/**
 * Mock of Person 1's Aegis security engine.
 *
 * Implements the full /internal/* contract from `lib/types/aegis.ts` with realistic
 * fake data so frontend work is never blocked on the real Python engine. Point the
 * frontend at this via `AEGIS_ENGINE_URL=http://localhost:8001`.
 *
 * Run:
 *   npm install
 *   npm run dev      # or: npm start
 */

import cors from "cors";
import express, { type NextFunction, type Request, type Response } from "express";
import { randomUUID } from "node:crypto";

import type {
  AegisAction,
  AegisErrorCode,
  AegisMessage,
  AegisPolicy,
  AuditLogEntry,
  AuditLogRequest,
  AuditLogResponse,
  AuditQueryResponse,
  Detection,
  DetectionCategory,
  GroundingStatus,
  HealthResponse,
  PipelineStage,
  PoliciesResponse,
  ScanRequest,
  ScanResponse,
  UpdatePoliciesRequest,
  VerifyRequest,
  VerifyResponse,
} from "../../lib/types/aegis";

const PORT = Number(process.env.PORT ?? 8001);
const START_TIME = Date.now();
const ENGINE_VERSION = "0.1.0-mock";

// ---------------------------------------------------------------------------
// In-memory state (mock only — the real engine persists this properly)
// ---------------------------------------------------------------------------

let policy: AegisPolicy = {
  pii_detection_enabled: true,
  secret_detection_enabled: true,
  prompt_injection_detection_enabled: true,
  hallucination_check_enabled: true,
  faithfulness_threshold: 0.75,
  block_on_pii: false,
};
let policyUpdatedAt = new Date().toISOString();

const auditLog: AuditLogEntry[] = [];

/**
 * Seed the audit log with a plausible 30 days of traffic.
 *
 * MOCK-ONLY dev fixture. The frontend ships no mock data at all — it renders
 * empty states when the engine has nothing. This exists so `npm run dev` shows a
 * populated dashboard without having to hand-drive hundreds of requests first.
 * Set `AEGIS_MOCK_SEED=0` to start empty and exercise those empty states.
 */
function seedAuditLog(): void {
  if (process.env.AEGIS_MOCK_SEED === "0") return;

  const providers = ["groq", "glm-free", "ollama-local", "openai"];
  const rules: DetectionCategory[] = [
    "PII_EMAIL", "PII_PHONE", "PII_CREDIT_CARD", "PII_PERSON_NAME",
    "SECRET_AWS_ACCESS_KEY", "SECRET_API_KEY", "SECRET_JWT",
    "PROMPT_INJECTION",
  ];

  // Deterministic PRNG so restarts don't reshuffle the charts underfoot.
  let seed = 1337;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  const pick = <T,>(xs: T[]): T => xs[Math.floor(rnd() * xs.length)];

  const now = Date.now();
  const DAYS = 30;

  for (let d = DAYS; d >= 0; d--) {
    // Busier during the working day, quieter at night and at the weekend.
    const dayStart = now - d * 86_400_000;
    const weekend = [0, 6].includes(new Date(dayStart).getDay());
    const perDay = Math.floor((weekend ? 30 : 90) * (0.6 + rnd() * 0.8));

    for (let i = 0; i < perDay; i++) {
      // Spread across the calendar day this iteration represents, weighted
      // towards working hours. Anything in the future is skipped so the newest
      // bucket is never half-empty for the wrong reason.
      const hour = Math.floor(rnd() * 24);
      const busy = hour >= 9 && hour <= 18;
      if (!busy && rnd() > 0.35) continue;

      const midnight = new Date(dayStart);
      midnight.setHours(0, 0, 0, 0);
      const tsMs = midnight.getTime() + hour * 3_600_000 + Math.floor(rnd() * 3_600_000);
      if (tsMs > now) continue;
      const ts = new Date(tsMs);
      const roll = rnd();
      const action: AegisAction = roll > 0.93 ? "block" : roll > 0.66 ? "sanitize" : roll > 0.6 ? "warn" : "allow";

      const triggers: DetectionCategory[] = [];
      if (action === "block") triggers.push(rnd() > 0.5 ? "PROMPT_INJECTION" : "SECRET_AWS_ACCESS_KEY");
      else if (action === "sanitize") {
        const n = 1 + Math.floor(rnd() * 3);
        for (let k = 0; k < n; k++) triggers.push(pick(rules.filter((r) => r !== "PROMPT_INJECTION")));
      }

      const cacheHit = action !== "block" && rnd() > 0.62;
      const provider = action === "block" ? null : cacheHit ? null : pick(providers);
      const latency = action === "block" ? 40 + Math.floor(rnd() * 60)
        : cacheHit ? 18 + Math.floor(rnd() * 40)
        : 220 + Math.floor(rnd() * 900);
      const cost = provider === null ? 0 : Number((0.0004 + rnd() * 0.004).toFixed(5));

      auditLog.push({
        id: randomUUID(),
        timestamp: ts.toISOString(),
        request_id: `req_${Math.floor(rnd() * 1e9).toString(36)}`,
        model_used: provider === null ? null : `${provider}/chat`,
        tokens_consumed: provider === null ? null : 120 + Math.floor(rnd() * 1800),
        latency_ms: latency,
        scrubbed_entity_count: triggers.length,
        rule_triggers: triggers,
        action,
        error_code: action === "block"
          ? (triggers[0] === "PROMPT_INJECTION" ? "PROMPT_INJECTION_BLOCKED" : "CREDENTIAL_LEAK_PREVENTED")
          : null,
        provider_used: provider,
        cache_hit: cacheHit,
        failover_used: provider !== null && rnd() > 0.9,
        grounding_status: action === "block" ? null : rnd() > 0.88 ? "warn" : "pass",
        grounding_score: action === "block" ? null : Number((0.7 + rnd() * 0.3).toFixed(2)),
        estimated_cost_usd: cost,
        estimated_savings_usd: cacheHit ? Number((0.0008 + rnd() * 0.006).toFixed(5)) : null,
        estimated_carbon_g: Number((cost * 900).toFixed(3)),
      });
    }
  }
}

seedAuditLog();

/**
 * The redaction vault (Phase 4): when `/internal/scan` sanitizes, it stores the
 * placeholder → original mapping here keyed by a `vault_token`, instead of ever
 * handing raw entities back to the gateway. `/internal/verify` is the only place
 * that reads from it, and only for non-secret categories (secrets are never
 * rehydrated, no matter what the caller asks for — defense in depth beyond the
 * gateway's own `rehydrate` gating).
 */
interface VaultEntry {
  placeholder: string;
  original: string;
  category: DetectionCategory;
}
const vault = new Map<string, VaultEntry[]>();

function isSecretCategory(category: DetectionCategory): boolean {
  return category.startsWith("SECRET_");
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

const AWS_ACCESS_KEY_RE = /AKIA[0-9A-Z]{16}/g;
const DB_CONNECTION_STRING_RE = /postgres:\/\/\S+/g;
const INJECTION_RE = /ignore previous instructions/gi;
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
// Two capitalized words in a row, e.g. "John Smith" — a deliberately simple heuristic for the mock.
const FULL_NAME_RE = /\b[A-Z][a-z]+ [A-Z][a-z]+\b/g;

function findAll(
  content: string,
  regex: RegExp,
  category: DetectionCategory,
  messageIndex: number,
  confidence: number,
  placeholderPrefix: string | null,
): Detection[] {
  const detections: Detection[] = [];
  let counter = 1;
  for (const match of content.matchAll(regex)) {
    const start = match.index ?? 0;
    detections.push({
      category,
      match: match[0],
      placeholder: placeholderPrefix ? `[${placeholderPrefix}_${counter}]` : null,
      start,
      end: start + match[0].length,
      confidence,
      message_index: messageIndex,
    });
    counter += 1;
  }
  return detections;
}

function stage(name: string, status: PipelineStage["status"], duration_ms: number, detail?: string): PipelineStage {
  return { name, status, duration_ms, detail };
}

function jitter(base: number, spread: number): number {
  return Math.round(base + Math.random() * spread);
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const app = express();
app.use(cors());
app.use(express.json());

// ---- POST /internal/scan ---------------------------------------------------

app.post("/internal/scan", (req: Request, res: Response) => {
  const body = req.body as ScanRequest;
  const messages: AegisMessage[] = body.messages ?? [];
  const stages: PipelineStage[] = [];

  let allDetections: Detection[] = [];
  messages.forEach((message, index) => {
    allDetections = allDetections.concat(
      findAll(message.content, AWS_ACCESS_KEY_RE, "SECRET_AWS_ACCESS_KEY", index, 0.99, null),
      findAll(message.content, DB_CONNECTION_STRING_RE, "SECRET_DB_CONNECTION_STRING", index, 0.97, null),
      findAll(message.content, INJECTION_RE, "PROMPT_INJECTION", index, 0.95, null),
      findAll(message.content, EMAIL_RE, "PII_EMAIL", index, 0.92, "EMAIL"),
      findAll(message.content, FULL_NAME_RE, "PII_PERSON_NAME", index, 0.68, "PERSON"),
    );
  });

  stages.push(stage("pii_secret_scan", "pass", jitter(8, 6)));

  const credentialLeaks = allDetections.filter(
    (d) => d.category === "SECRET_AWS_ACCESS_KEY" || d.category === "SECRET_DB_CONNECTION_STRING",
  );
  const injectionHits = allDetections.filter((d) => d.category === "PROMPT_INJECTION");
  const sanitizableHits = allDetections.filter(
    (d) => d.category === "PII_EMAIL" || d.category === "PII_PERSON_NAME",
  );

  let action: AegisAction = "allow";
  let error_code: AegisErrorCode = null;
  let sanitized_messages: AegisMessage[] | null = null;
  let vault_token: string | null = null;

  if (credentialLeaks.length > 0) {
    stages.push(stage("credential_leak_check", "blocked", jitter(3, 3), `${credentialLeaks.length} secret(s) found`));
    stages.push(stage("prompt_injection_check", "skipped", 0));
    stages.push(stage("sanitize", "skipped", 0));
    action = "block";
    error_code = "CREDENTIAL_LEAK_PREVENTED";
  } else if (injectionHits.length > 0) {
    stages.push(stage("credential_leak_check", "pass", jitter(3, 3)));
    stages.push(
      stage("prompt_injection_check", "blocked", jitter(12, 8), `${injectionHits.length} injection pattern(s) found`),
    );
    stages.push(stage("sanitize", "skipped", 0));
    action = "block";
    error_code = "PROMPT_INJECTION_BLOCKED";
  } else if (sanitizableHits.length > 0) {
    stages.push(stage("credential_leak_check", "pass", jitter(3, 3)));
    stages.push(stage("prompt_injection_check", "pass", jitter(12, 8)));
    sanitized_messages = messages.map((message, index) => {
      let content = message.content;
      for (const detection of sanitizableHits.filter((d) => d.message_index === index)) {
        if (detection.placeholder) {
          content = content.split(detection.match).join(detection.placeholder);
        }
      }
      return { ...message, content };
    });
    stages.push(
      stage("sanitize", "flagged", jitter(5, 4), `${sanitizableHits.length} entit(y/ies) redacted`),
    );
    action = "sanitize";
    error_code = null;

    vault_token = `vault_${randomUUID()}`;
    vault.set(
      vault_token,
      sanitizableHits
        .filter((d) => d.placeholder !== null)
        .map((d) => ({ placeholder: d.placeholder as string, original: d.match, category: d.category })),
    );
  } else {
    stages.push(stage("credential_leak_check", "pass", jitter(3, 3)));
    stages.push(stage("prompt_injection_check", "pass", jitter(12, 8)));
    stages.push(stage("sanitize", "skipped", 0));
  }

  const response: ScanResponse = {
    request_id: body.request_id ?? randomUUID(),
    action,
    error_code,
    detections: allDetections,
    sanitized_messages,
    vault_token,
    stages,
    processed_at: new Date().toISOString(),
  };

  res.json(response);
});

// ---- POST /internal/verify --------------------------------------------------

app.post("/internal/verify", (req: Request, res: Response) => {
  const body = req.body as VerifyRequest;
  const threshold = policy.faithfulness_threshold;
  const request_id = body.request_id ?? randomUUID();

  const stages: PipelineStage[] = [];

  // --- Rehydration: engine-side only, never for secret categories, and only when
  // the gateway both asked for it AND handed back a vault_token that has entries. ---
  let final_text = body.response_text;
  let rehydrated = false;
  if (body.rehydrate && body.vault_token) {
    const entries = vault.get(body.vault_token) ?? [];
    const rehydratable = entries.filter((e) => !isSecretCategory(e.category));
    if (rehydratable.length > 0) {
      for (const entry of rehydratable) {
        final_text = final_text.split(entry.placeholder).join(entry.original);
      }
      rehydrated = true;
      stages.push(stage("rehydration", "flagged", jitter(4, 3), `${rehydratable.length} placeholder(s) restored`));
    } else {
      stages.push(stage("rehydration", "skipped", 0, "no rehydratable vault entries"));
    }
  } else {
    stages.push(stage("rehydration", "skipped", 0, body.rehydrate ? "no vault_token" : "rehydrate not requested"));
  }

  // --- Grounding: skipped (trivially "pass") when there's nothing to ground against. ---
  let status: GroundingStatus = "pass";
  let score = 1;
  let unsupported_claims: string[] = [];

  if (body.reference_documents.length === 0) {
    stages.push(stage("nli_cross_check", "skipped", 0, "no reference documents supplied"));
  } else {
    stages.push(stage("context_embedding", "pass", jitter(15, 10)));
    stages.push(stage("claim_extraction", "pass", jitter(20, 15)));

    // Mock heuristic: faithfulness drops if the answer shares little vocabulary with the
    // reference docs, and a touch of randomness keeps demos looking alive.
    const contextText = body.reference_documents.join(" ").toLowerCase();
    const answerWords = final_text.toLowerCase().split(/\W+/).filter((w) => w.length > 4);
    const supported = answerWords.filter((w) => contextText.includes(w));
    const overlapRatio = answerWords.length > 0 ? supported.length / answerWords.length : 1;
    score = Math.max(0, Math.min(1, Number((overlapRatio * 0.6 + 0.35).toFixed(2))));
    unsupported_claims =
      answerWords.length > 0 && overlapRatio < 1
        ? [final_text.split(/(?<=[.!?])\s+/)[0] ?? final_text]
        : [];

    if (score < threshold) {
      stages.push(stage("nli_cross_check", "blocked", jitter(30, 20), `score ${score} < threshold ${threshold}`));
      status = "block";
    } else {
      stages.push(stage("nli_cross_check", "pass", jitter(30, 20)));
    }
  }

  const response: VerifyResponse = {
    request_id,
    final_text,
    rehydrated,
    grounding: { status, score, unsupported_claims },
    stages,
    processed_at: new Date().toISOString(),
  };

  res.json(response);
});

// ---- /internal/audit (POST write, GET query) --------------------------------

app.post("/internal/audit", (req: Request, res: Response) => {
  const body = req.body as AuditLogRequest;
  const entry: AuditLogEntry = {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    ...body.entry,
  };
  auditLog.push(entry);

  const response: AuditLogResponse = { entry };
  res.status(201).json(response);
});

app.get("/internal/audit", (req: Request, res: Response) => {
  const { from, to, limit } = req.query;
  let entries = auditLog;

  if (typeof from === "string") entries = entries.filter((e) => e.timestamp >= from);
  if (typeof to === "string") entries = entries.filter((e) => e.timestamp < to);

  const total = entries.length;
  if (typeof limit === "string") entries = entries.slice(-Number(limit));

  const response: AuditQueryResponse = { entries, total };
  res.json(response);
});


// ---- /internal/audit/events (filtered, paginated) ---------------------------
//
// The dashboard's audit table and /api/metrics both read this. Kept separate from
// the plain GET /internal/audit above so the richer filter set doesn't change that
// endpoint's contract.

app.get("/internal/audit/events", (req: Request, res: Response) => {
  const { from, to, provider, action, cache_hit, has_detections, limit, offset } = req.query;

  let entries = auditLog;
  if (typeof from === "string") entries = entries.filter((e) => e.timestamp >= from);
  if (typeof to === "string") entries = entries.filter((e) => e.timestamp < to);
  if (typeof provider === "string" && provider) entries = entries.filter((e) => e.provider_used === provider);
  if (typeof action === "string" && action) entries = entries.filter((e) => e.action === action);
  if (cache_hit === "true" || cache_hit === "false") {
    entries = entries.filter((e) => e.cache_hit === (cache_hit === "true"));
  }
  if (has_detections === "true" || has_detections === "false") {
    const want = has_detections === "true";
    entries = entries.filter((e) => (e.rule_triggers.length > 0) === want);
  }

  // Newest first, which is what a log reader expects.
  entries = [...entries].sort((a, b) => b.timestamp.localeCompare(a.timestamp));

  const total = entries.length;
  const start = Number(offset ?? 0) || 0;
  const size = Number(limit ?? 25) || 25;

  res.json({ entries: entries.slice(start, start + size), total });
});

// ---- /internal/audit/report (PDF export) ------------------------------------
//
// A minimal but genuinely valid single-page PDF, so the download path (streaming
// proxy, content-disposition, filename) can be exercised end to end without
// pulling a PDF library into the mock.

app.get("/internal/audit/report", (req: Request, res: Response) => {
  const from = typeof req.query.from === "string" ? req.query.from : "";
  const to = typeof req.query.to === "string" ? req.query.to : "";

  let entries = auditLog;
  if (from) entries = entries.filter((e) => e.timestamp >= from);
  if (to) entries = entries.filter((e) => e.timestamp < to);

  const blocked = entries.filter((e) => e.action === "block").length;
  const scrubbed = entries.reduce((a, e) => a + e.scrubbed_entity_count, 0);

  const lines = [
    "Aegis Audit Report (mock engine)",
    `Window: ${from || "-"} to ${to || "-"}`,
    `Requests: ${entries.length}`,
    `Blocked: ${blocked}`,
    `Entities scrubbed: ${scrubbed}`,
    `Generated: ${new Date().toISOString()}`,
  ];

  const esc = (t: string) => t.replace(/([\\()])/g, "\\$1");
  const text = lines.map((l, i) => `BT /F1 12 Tf 60 ${720 - i * 22} Td (${esc(l)}) Tj ET`).join("\n");

  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
    `<< /Length ${text.length} >>\nstream\n${text}\nendstream`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
  ];

  let pdf = "%PDF-1.4\n";
  const offsets: number[] = [];
  objects.forEach((o, i) => {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xref = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) pdf += `${String(off).padStart(10, "0")} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;

  res.setHeader("content-type", "application/pdf");
  res.send(Buffer.from(pdf, "latin1"));
});

// ---- /internal/policies (GET, PUT) ------------------------------------------

app.get("/internal/policies", (_req: Request, res: Response) => {
  const response: PoliciesResponse = { policy, updated_at: policyUpdatedAt };
  res.json(response);
});

app.put("/internal/policies", (req: Request, res: Response) => {
  const body = req.body as UpdatePoliciesRequest;
  policy = { ...policy, ...body.policy };
  policyUpdatedAt = new Date().toISOString();

  const response: PoliciesResponse = { policy, updated_at: policyUpdatedAt };
  res.json(response);
});

// ---- GET /internal/health ----------------------------------------------------

app.get("/internal/health", (_req: Request, res: Response) => {
  const response: HealthResponse = {
    status: "ok",
    engine: "mock",
    version: ENGINE_VERSION,
    uptime_s: Math.round((Date.now() - START_TIME) / 1000),
  };
  res.json(response);
});

// ---- Error handling -----------------------------------------------------------

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const message = err instanceof Error ? err.message : "Unknown error";
  res.status(400).json({ error: message });
});

app.listen(PORT, () => {
  console.log(`[aegis-mock-engine] listening on http://localhost:${PORT}`);
});
