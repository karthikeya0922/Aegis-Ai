/**
 * Gateway authentication (Phase 7A fix for the "no authentication at all" finding).
 *
 * The gateway holds every configured provider's API key, so an unauthenticated
 * `/v1/chat/completions` is an open relay for those credentials. It is also the
 * thing that makes cross-tenant cache reads remotely reachable — the semantic
 * cache is scoped by the `tenant` this module returns (see
 * `lib/cache/semantic-cache.ts`), and the rate limiter is keyed off it (see the
 * route handler). So this is the root of both fixes, not just a login check.
 *
 * Keys come from `AEGIS_API_KEYS`, a comma-separated list of `secret:tenant`
 * pairs, e.g.
 *
 *     AEGIS_API_KEYS=sk-aegis-live-abc...:acme,sk-aegis-live-def...:globex
 *
 * The presented key is hashed before it is used to look anything up, so the
 * comparison is against a fixed-length digest and does not leak the secret's
 * prefix through timing. Digests are compared with `timingSafeEqual`.
 *
 * Fail-closed rule: if `AEGIS_API_KEYS` is missing or unparseable in
 * production, every request is refused with a misconfiguration error. There is
 * no "allow anonymous in production" path. Outside production an unset
 * `AEGIS_API_KEYS` falls back to a single `dev-local` tenant so local work and
 * tests keep functioning, and that fallback logs a warning every time it is
 * taken.
 */

import { createHash, timingSafeEqual } from "node:crypto";

/** The authenticated caller. `tenant` is the cache/rate-limit isolation boundary. */
export interface Principal {
  /** Stable tenant identifier from `AEGIS_API_KEYS`. Never client-supplied. */
  tenant: string;
  /**
   * Short, non-secret label for the key that authenticated this request, safe to
   * put in logs and audit records. This is a truncated digest, never the key.
   */
  key_id: string;
  /** True when this is the non-production `dev-local` fallback, not a real key. */
  dev_fallback: boolean;
}

export type AuthOutcome =
  | { ok: true; principal: Principal }
  | { ok: false; status: 401 | 500; code: "unauthorized" | "server_misconfigured"; message: string };

const DEV_FALLBACK_TENANT = "dev-local";

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/** Non-secret, log-safe identifier derived from a key. */
function keyIdFor(digest: Buffer): string {
  return "key_" + digest.toString("hex").slice(0, 12);
}

interface KeyTable {
  /** hex(sha256(secret)) -> tenant. */
  byDigest: Map<string, string>;
}

let cachedTable: { raw: string | undefined; table: KeyTable } | null = null;

/**
 * Parses `AEGIS_API_KEYS`. Entries are `secret:tenant`; a secret containing `:`
 * is not supported (the LAST colon separates tenant, so secrets may contain
 * colons but tenants may not). Blank and malformed entries are skipped rather
 * than silently widening access, and an entry with an empty secret or tenant is
 * treated as malformed.
 */
export function parseApiKeys(raw: string | undefined): KeyTable {
  const byDigest = new Map<string, string>();
  if (!raw) return { byDigest };

  for (const entry of raw.split(",")) {
    const trimmed = entry.trim();
    if (trimmed.length === 0) continue;
    const separator = trimmed.lastIndexOf(":");
    if (separator <= 0 || separator === trimmed.length - 1) continue;
    const secret = trimmed.slice(0, separator).trim();
    const tenant = trimmed.slice(separator + 1).trim();
    if (secret.length === 0 || tenant.length === 0) continue;
    byDigest.set(sha256(secret).toString("hex"), tenant);
  }

  return { byDigest };
}

function keyTable(env: NodeJS.ProcessEnv): KeyTable {
  const raw = env.AEGIS_API_KEYS;
  if (cachedTable && cachedTable.raw === raw) return cachedTable.table;
  const table = parseApiKeys(raw);
  cachedTable = { raw, table };
  return table;
}

/** Test-only escape hatch so a changed `AEGIS_API_KEYS` is re-read. */
export function resetApiKeyTableForTests(): void {
  cachedTable = null;
}

/** Extracts the presented secret from `Authorization: Bearer ...` or `x-api-key`. */
function presentedKey(headers: Headers): string | null {
  const authorization = headers.get("authorization");
  if (authorization) {
    const match = /^Bearer\s+(.+)$/i.exec(authorization.trim());
    if (match) return match[1].trim();
  }
  const apiKey = headers.get("x-api-key");
  if (apiKey && apiKey.trim().length > 0) return apiKey.trim();
  return null;
}

/**
 * Constant-time lookup of a presented secret. The secret is hashed first, so the
 * value actually compared is a fixed-length digest; `timingSafeEqual` then
 * compares candidate digests without an early exit.
 */
function lookupTenant(table: KeyTable, secret: string): { tenant: string; digest: Buffer } | null {
  const digest = sha256(secret);
  let found: string | null = null;
  for (const [candidateHex, tenant] of table.byDigest) {
    const candidate = Buffer.from(candidateHex, "hex");
    // Equal-length digests, so this never throws. The loop deliberately runs to
    // completion instead of breaking on the first hit, so the time taken does
    // not reveal which entry matched.
    const equal = timingSafeEqual(candidate, digest);
    if (equal && found === null) found = tenant;
  }
  return found === null ? null : { tenant: found, digest };
}

/**
 * Authenticates a request. Returns the `Principal` used for cache scoping and
 * rate limiting, or a refusal. Never reads a tenant from a client-supplied
 * header — the tenant comes only from the server-side key table.
 */
export function authenticate(headers: Headers, env: NodeJS.ProcessEnv = process.env): AuthOutcome {
  const table = keyTable(env);
  const isProduction = env.NODE_ENV === "production";

  if (table.byDigest.size === 0) {
    if (isProduction) {
      // Fail closed: an unconfigured key table in production must not mean "open".
      return {
        ok: false,
        status: 500,
        code: "server_misconfigured",
        message: "The gateway is not configured for authentication.",
      };
    }
    console.warn(
      "[aegis-gateway] AEGIS_API_KEYS is not set — falling back to the " +
        `"${DEV_FALLBACK_TENANT}" tenant. This is refused when NODE_ENV=production.`,
    );
    return {
      ok: true,
      principal: { tenant: DEV_FALLBACK_TENANT, key_id: "key_dev_fallback", dev_fallback: true },
    };
  }

  const secret = presentedKey(headers);
  if (secret === null) {
    return {
      ok: false,
      status: 401,
      code: "unauthorized",
      message: "An API key is required. Send it as `Authorization: Bearer <key>` or `x-api-key`.",
    };
  }

  const match = lookupTenant(table, secret);
  if (match === null) {
    return { ok: false, status: 401, code: "unauthorized", message: "The supplied API key is not valid." };
  }

  return {
    ok: true,
    principal: { tenant: match.tenant, key_id: keyIdFor(match.digest), dev_fallback: false },
  };
}
