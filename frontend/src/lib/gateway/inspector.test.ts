import { describe, expect, it } from "vitest";
import { isSecretCategory, makeClientSafe, redactSecrets, scrubSecretShapes, toInspectorPayload, REDACTED } from "./inspector";

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

describe("isSecretCategory", () => {
  it("treats every SECRET_ category as secret", () => {
    for (const c of ["SECRET_AWS_ACCESS_KEY", "SECRET_AWS_SECRET_KEY", "SECRET_DB_CONNECTION_STRING", "SECRET_JWT", "SECRET_API_KEY"]) {
      expect(isSecretCategory(c)).toBe(true);
    }
  });

  it("does not treat PII as secret — PII is placeholdered, not withheld", () => {
    expect(isSecretCategory("PII_EMAIL")).toBe(false);
    expect(isSecretCategory("PROMPT_INJECTION")).toBe(false);
  });

  it("errs towards secrecy for unknown SECRET_-prefixed categories", () => {
    expect(isSecretCategory("SECRET_SOMETHING_NEW")).toBe(true);
  });
});

describe("redactSecrets", () => {
  it("replaces a secret span and leaves non-secret spans alone", () => {
    const text = `email a@b.com key ${AWS_KEY} end`;
    const out = redactSecrets(text, [
      { category: "PII_EMAIL", start: 6, end: 13 },
      { category: "SECRET_AWS_ACCESS_KEY", start: 18, end: 18 + AWS_KEY.length },
    ]);
    expect(out).not.toContain(AWS_KEY);
    expect(out).toContain(REDACTED);
    expect(out).toContain("a@b.com");
  });

  it("handles multiple secrets without corrupting later offsets", () => {
    const text = `${AWS_KEY} and ${AWS_KEY}`;
    const out = redactSecrets(text, [
      { category: "SECRET_AWS_ACCESS_KEY", start: 0, end: 20 },
      { category: "SECRET_AWS_ACCESS_KEY", start: 25, end: 45 },
    ]);
    expect(out).toBe(`${REDACTED} and ${REDACTED}`);
  });

  it("skips out-of-range offsets rather than mangling the string", () => {
    const text = "short";
    expect(redactSecrets(text, [{ category: "SECRET_JWT", start: 0, end: 999 }])).toBe(text);
  });
});

describe("scrubSecretShapes", () => {
  it("catches secrets that arrived with no detection offsets", () => {
    expect(scrubSecretShapes(`use ${AWS_KEY}`)).not.toContain(AWS_KEY);
    expect(scrubSecretShapes("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27u")).toContain(REDACTED);
    expect(scrubSecretShapes("postgres://user:hunter2@db.internal:5432/app")).toContain(REDACTED);
    expect(scrubSecretShapes("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----")).toBe(REDACTED);
  });

  it("leaves ordinary prose untouched", () => {
    const text = "Please summarise the quarterly report for the board.";
    expect(scrubSecretShapes(text)).toBe(text);
  });
});

describe("toInspectorPayload", () => {
  const base = {
    action: "sanitize",
    error_code: null,
    sanitized_messages: [{ role: "user" as const, content: `key ${AWS_KEY} for [EMAIL_1]` }],
    stages: [{ name: "pii_secret_scan", status: "pass", duration_ms: 11 }],
  };

  it("never emits a raw secret in any field", () => {
    const payload = toInspectorPayload({
      ...base,
      detections: [
        { category: "SECRET_AWS_ACCESS_KEY", match: AWS_KEY, placeholder: null, start: 4, end: 24, confidence: 0.99, message_index: 0 },
      ],
    });

    expect(JSON.stringify(payload)).not.toContain(AWS_KEY);
    expect(payload.detections[0].preview).toBe(REDACTED);
    expect(payload.detections[0].secret).toBe(true);
    expect(payload.had_secrets).toBe(true);
    expect(payload.sanitized_messages?.[0].content).not.toContain(AWS_KEY);
  });

  it("keeps non-secret previews, which is what makes the diff useful", () => {
    const payload = toInspectorPayload({
      ...base,
      sanitized_messages: [{ role: "user", content: "mail [EMAIL_1]" }],
      detections: [
        { category: "PII_EMAIL", match: "john@acme.com", placeholder: "[EMAIL_1]", start: 5, end: 18, confidence: 0.92, message_index: 0 },
      ],
    });

    expect(payload.detections[0].preview).toBe("john@acme.com");
    expect(payload.detections[0].secret).toBe(false);
    expect(payload.had_secrets).toBe(false);
  });

  it("reports a stage with no duration as null, never as 0", () => {
    const payload = toInspectorPayload({
      ...base,
      detections: [],
      stages: [
        { name: "a", status: "pass", duration_ms: 12 },
        { name: "b", status: "skipped" },
        { name: "c", status: "pass", duration_ms: "fast" },
      ],
    });

    expect(payload.stages.map((s) => s.duration_ms)).toEqual([12, null, null]);
  });

  it("drops malformed stages and defaults an unknown status to skipped", () => {
    const payload = toInspectorPayload({
      ...base,
      detections: [],
      stages: [null, 42, { noName: true }, { name: "ok", status: "weird" }],
    });

    expect(payload.stages).toEqual([{ name: "ok", status: "skipped", duration_ms: null }]);
  });
});

describe("makeClientSafe", () => {
  it("applies offsets first, then the shape sweep, so both nets catch", () => {
    const text = `a ${AWS_KEY} b sk-abcdefghijklmnopqrstuvwx`;
    const out = makeClientSafe(text, [{ category: "SECRET_AWS_ACCESS_KEY", start: 2, end: 22 }]);
    expect(out).not.toContain(AWS_KEY);
    expect(out).not.toContain("sk-abcdefghijklmnopqrstuvwx");
  });
});
