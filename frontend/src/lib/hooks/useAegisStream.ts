"use client";

import { useCallback, useRef, useState } from "react";
import { makeSafe } from "@/lib/redact";

/**
 * Drives one playground request end to end: POST the chat completion, parse the
 * SSE stream, and expose the pieces each panel needs.
 *
 * Security: every string that lands in state goes through `makeSafe` first. The
 * original prompt is redacted the moment the `aegis.scan` frame gives us offsets,
 * and re-redacted by shape immediately on submit so there is no window where a
 * raw secret sits in state waiting for the server to answer.
 */

export interface Stage {
  stage: string;
  status: "pass" | "flagged" | "blocked" | "skipped";
  duration_ms: number | null;
  metadata?: Record<string, unknown>;
}

export interface SafeDetection {
  category: string;
  placeholder: string | null;
  start: number;
  end: number;
  confidence: number;
  message_index: number;
  secret: boolean;
  preview: string;
}

export interface ScanFrame {
  action: string;
  error_code: string | null;
  stages: Array<{ name: string; status: Stage["status"]; duration_ms?: number; detail?: string }>;
  detections: SafeDetection[];
  sanitized_messages: Array<{ role: string; content: string }> | null;
  had_secrets: boolean;
}

export interface TelemetryFrame {
  request_id?: string;
  provider_used?: string;
  primary_provider?: string;
  failover_used?: boolean;
  cache_hit?: boolean;
  response_length?: number;
  error?: string | null;
  grounding_status?: string | null;
  grounding_score?: number | null;
  stages?: Array<{ name: string; status: Stage["status"]; duration_ms?: number; detail?: string }>;
}

export interface GroundingFrame {
  status?: string;
  score?: number | null;
  final_text?: string;
  rehydrated?: boolean;
}

export interface StreamState {
  status: "idle" | "scanning" | "streaming" | "done" | "blocked" | "error";
  originalPrompt: string;
  sanitizedPrompt: string | null;
  detections: SafeDetection[];
  hadSecrets: boolean;
  stages: Stage[];
  /** Index of the stage that blocked; everything after it is greyed out. */
  blockedAt: number | null;
  responseText: string;
  telemetry: TelemetryFrame | null;
  grounding: GroundingFrame | null;
  error: string | null;
}

const INITIAL: StreamState = {
  status: "idle",
  originalPrompt: "",
  sanitizedPrompt: null,
  detections: [],
  hadSecrets: false,
  stages: [],
  blockedAt: null,
  responseText: "",
  telemetry: null,
  grounding: null,
  error: null,
};

function toStages(
  raw: Array<{ name: string; status: Stage["status"]; duration_ms?: number; detail?: string }> | undefined,
): Stage[] {
  if (!raw) return [];
  return raw.map((s) => ({
    stage: s.name,
    status: s.status,
    // A stage that reported no duration shows "—". Never substitute a number.
    duration_ms: typeof s.duration_ms === "number" && Number.isFinite(s.duration_ms) ? s.duration_ms : null,
    metadata: s.detail ? { detail: s.detail } : undefined,
  }));
}

function firstBlocked(stages: Stage[]): number | null {
  const i = stages.findIndex((s) => s.status === "blocked");
  return i === -1 ? null : i;
}

export function useAegisStream() {
  const [state, setState] = useState<StreamState>(INITIAL);
  const abortRef = useRef<AbortController | null>(null);

  const reset = useCallback(() => {
    abortRef.current?.abort();
    setState(INITIAL);
  }, []);

  const send = useCallback(
    async (opts: { prompt: string; confidential: boolean; strict: boolean; referenceDocs: string }) => {
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      // Shape-scrub immediately: the prompt must not sit in state raw even for
      // the few hundred ms before the engine answers with offsets.
      setState({ ...INITIAL, status: "scanning", originalPrompt: makeSafe(opts.prompt) });

      const headers: Record<string, string> = {
        "content-type": "application/json",
        accept: "text/event-stream",
        "x-aegis-mode": opts.strict ? "strict" : "sanitize",
      };
      if (opts.confidential) headers["x-aegis-confidential"] = "true";
      const docs = opts.referenceDocs
        .split(/\n{2,}/)
        .map((d) => d.trim())
        .filter(Boolean);
      if (docs.length > 0) headers["x-aegis-reference-docs"] = JSON.stringify(docs);

      let res: Response;
      try {
        res = await fetch("/api/v1/chat/completions", {
          method: "POST",
          headers,
          signal: controller.signal,
          body: JSON.stringify({
            model: "aegis-auto",
            stream: true,
            messages: [{ role: "user", content: opts.prompt }],
          }),
        });
      } catch (e) {
        if (controller.signal.aborted) return;
        setState((s) => ({ ...s, status: "error", error: e instanceof Error ? e.message : "Network error" }));
        return;
      }

      // A blocked request comes back as JSON, not a stream.
      if (!res.ok || !res.headers.get("content-type")?.includes("text/event-stream")) {
        let message = `Request failed (${res.status})`;
        let scan: ScanFrame | null = null;
        try {
          const body = await res.json();
          message = body?.error?.message ?? message;
          scan = body?.aegis ?? null;
        } catch {
          /* non-JSON error body — keep the status message */
        }
        const stages = toStages(scan?.stages);
        setState((s) => ({
          ...s,
          status: "blocked",
          error: message,
          stages,
          blockedAt: firstBlocked(stages),
          detections: scan?.detections ?? [],
          hadSecrets: scan?.had_secrets ?? false,
          originalPrompt: makeSafe(opts.prompt, scan?.detections ?? [], 0),
          sanitizedPrompt: scan?.sanitized_messages?.[0]?.content ?? null,
        }));
        return;
      }

      if (!res.body) {
        setState((s) => ({ ...s, status: "error", error: "Empty response stream" }));
        return;
      }

      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = "";

      const handleFrame = (eventName: string | null, data: string) => {
        if (data === "[DONE]") return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(data);
        } catch {
          return;
        }

        if (eventName === "aegis.scan") {
          const scan = parsed as ScanFrame;
          const stages = toStages(scan.stages);
          setState((s) => ({
            ...s,
            status: "streaming",
            stages,
            blockedAt: firstBlocked(stages),
            detections: scan.detections ?? [],
            hadSecrets: scan.had_secrets ?? false,
            // Now we have offsets — redact the local copy of the prompt properly.
            originalPrompt: makeSafe(opts.prompt, scan.detections ?? [], 0),
            sanitizedPrompt: scan.sanitized_messages?.[0]?.content ?? null,
          }));
          return;
        }

        if (eventName === "aegis.telemetry") {
          const t = parsed as TelemetryFrame;
          setState((s) => {
            const stages = t.stages && t.stages.length > 0 ? toStages(t.stages) : s.stages;
            return { ...s, telemetry: t, stages, blockedAt: firstBlocked(stages) };
          });
          return;
        }

        if (eventName === "aegis.grounding") {
          const g = parsed as GroundingFrame;
          setState((s) => ({
            ...s,
            grounding: g,
            // Verification is unavoidably post-stream; reconcile what we showed.
            responseText: g.final_text ? makeSafe(g.final_text) : s.responseText,
          }));
          return;
        }

        // Unnamed frames are OpenAI chat.completion.chunk deltas.
        const chunk = parsed as { choices?: Array<{ delta?: { content?: string } }> };
        const delta = chunk.choices?.[0]?.delta?.content;
        if (delta) {
          setState((s) => ({ ...s, status: "streaming", responseText: s.responseText + delta }));
        }
      };

      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += value;

          let sep: number;
          while ((sep = buffer.indexOf("\n\n")) !== -1) {
            const raw = buffer.slice(0, sep);
            buffer = buffer.slice(sep + 2);

            let eventName: string | null = null;
            const dataLines: string[] = [];
            for (const line of raw.split("\n")) {
              if (line.startsWith("event:")) eventName = line.slice(6).trim();
              else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
            }
            if (dataLines.length > 0) handleFrame(eventName, dataLines.join("\n"));
          }
        }
        setState((s) => ({ ...s, status: s.status === "error" ? s.status : "done" }));
      } catch (e) {
        if (controller.signal.aborted) return;
        setState((s) => ({ ...s, status: "error", error: e instanceof Error ? e.message : "Stream failed" }));
      }
    },
    [],
  );

  return { state, send, reset, cancel: () => abortRef.current?.abort() };
}
