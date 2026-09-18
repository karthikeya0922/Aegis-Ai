"use client";

import { useState } from "react";
import { useAegisStream } from "@/lib/hooks/useAegisStream";
import { Panel, PanelHeader } from "@/components/ui/Panel";
import { EgressPanel } from "./EgressPanel";
import { Inspector } from "./Inspector";
import { SanitizationDiff } from "./SanitizationDiff";

function Toggle({
  label, hint, checked, onChange,
}: { label: string; hint: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className="flex cursor-pointer items-center gap-8 rounded-full px-11 py-7 text-left transition-colors duration-200"
      style={{
        border: `1px solid ${checked ? "var(--aegis-border-focus)" : "var(--aegis-border)"}`,
        background: checked ? "var(--aegis-surface-toggle)" : "transparent",
      }}
      title={hint}
    >
      <span
        className="relative shrink-0 rounded-full transition-colors duration-200"
        style={{ width: 30, height: 17, background: checked ? "var(--aegis-blue)" : "var(--aegis-surface-track)" }}
      >
        <span
          className="absolute top-1/2 rounded-circle transition-all duration-200 ease-out-expo"
          style={{ width: 13, height: 13, background: "#fff", transform: "translateY(-50%)", left: checked ? 15 : 2 }}
        />
      </span>
      <span className="text-base" style={{ color: checked ? "var(--aegis-text)" : "var(--aegis-text-58)" }}>
        {label}
      </span>
    </button>
  );
}

export function Playground() {
  const [prompt, setPrompt] = useState("");
  const [referenceDocs, setReferenceDocs] = useState("");
  const [confidential, setConfidential] = useState(false);
  const [strict, setStrict] = useState(false);
  const { state, send, reset } = useAegisStream();

  const busy = state.status === "scanning" || state.status === "streaming";

  function submit() {
    if (!prompt.trim() || busy) return;
    void send({ prompt, confidential, strict, referenceDocs });
  }

  return (
    <div className="grid gap-14" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))", alignItems: "start" }}>
      <Panel glow="rgba(1,117,255,0.35)">
        <PanelHeader
          title="Playground"
          subtitle="Send a prompt through the live gateway"
          action={
            state.status !== "idle" && (
              <button
                onClick={reset}
                className="cursor-pointer rounded-full px-13 py-7 font-sans text-base text-aegis-text-85 transition-colors hover:text-aegis-text"
                style={{ border: "1px solid var(--aegis-border-strong)", background: "transparent" }}
              >
                Clear
              </button>
            )
          }
        />

        <label className="sr-only" htmlFor="aegis-prompt">Prompt</label>
        <textarea
          id="aegis-prompt"
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) submit();
          }}
          rows={6}
          placeholder="Ask anything. Include an email, a card number or an API key to watch the guardrails fire…"
          className="w-full resize-y rounded-md px-13 py-11 font-mono text-base-plus leading-mono text-aegis-text outline-none transition-colors duration-200 focus:border-aegis-border-focus"
          style={{ border: "1px solid var(--aegis-border)", background: "var(--aegis-surface-input)" }}
        />

        <div className="mt-11 flex flex-col gap-8">
          <label className="text-xs uppercase tracking-caps-tight text-aegis-text-45" htmlFor="aegis-docs">
            Reference documents
          </label>
          <textarea
            id="aegis-docs"
            value={referenceDocs}
            onChange={(e) => setReferenceDocs(e.target.value)}
            rows={3}
            placeholder="Optional. Blank line between documents — the answer is graded against these."
            className="w-full resize-y rounded-md px-13 py-11 font-mono text-sm-plus leading-mono text-aegis-text outline-none transition-colors duration-200 focus:border-aegis-border-focus"
            style={{ border: "1px solid var(--aegis-border)", background: "var(--aegis-surface-input)" }}
          />
        </div>

        <div className="mt-11 flex flex-wrap items-center gap-8">
          <Toggle label="Confidential Mode" hint="Sends x-aegis-confidential" checked={confidential} onChange={setConfidential} />
          <Toggle label="Strict Mode" hint="Sends x-aegis-mode: strict — prefer blocking over sanitizing" checked={strict} onChange={setStrict} />

          <button
            onClick={submit}
            disabled={!prompt.trim() || busy}
            className="ml-auto cursor-pointer rounded-full px-17 py-9 font-sans text-md-plus font-semibold transition-all duration-300 ease-out-expo disabled:cursor-not-allowed disabled:opacity-40"
            style={{
              border: "1px solid var(--aegis-border-cta)",
              background: "#000",
              boxShadow: busy ? "none" : "var(--shadow-cta)",
            }}
          >
            {busy ? "Running…" : "Send"}
          </button>
        </div>
      </Panel>

      <Panel glow="rgba(123,63,242,0.3)">
        <PanelHeader title="Live Inspector" subtitle="Every guardrail, in the order it ran" />
        <Inspector stages={state.stages} blockedAt={state.blockedAt} isLoading={state.status === "scanning"} />
      </Panel>

      <Panel span glow="rgba(255,138,0,0.28)">
        <PanelHeader title="Sanitization" subtitle="What you wrote vs. what the provider received" />
        <SanitizationDiff
          original={state.originalPrompt}
          sanitized={state.sanitizedPrompt}
          detections={state.detections}
          hadSecrets={state.hadSecrets}
        />
      </Panel>

      <Panel span glow="rgba(34,197,94,0.25)">
        <PanelHeader title="Response" subtitle="Streamed from the provider, checked on the way out" />
        <EgressPanel state={state} onRetry={submit} />
      </Panel>
    </div>
  );
}
