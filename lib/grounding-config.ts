/**
 * Loader for `config/grounding.yaml` (Phase 4: response-path grounding & rehydration).
 * Same lazy fs-read-once pattern as `lib/cost.ts` / `lib/cache/semantic-cache.ts`'s
 * config loaders, so it works whether `process.cwd()` is the repo root or `frontend/`.
 */

import fs from "fs";
import path from "path";
import yaml from "yaml";

interface GroundingConfig {
  fallback_text: string;
  verify_timeout_ms: number;
}

const DEFAULT_FALLBACK_TEXT = "I cannot verify this claim against verified documentation.";
const DEFAULT_VERIFY_TIMEOUT_MS = 5_000;

let configCache: GroundingConfig | null = null;

function loadConfig(): GroundingConfig {
  if (configCache) return configCache;
  let targetPath = path.join(process.cwd(), "config", "grounding.yaml");
  if (!fs.existsSync(targetPath)) {
    targetPath = path.join(process.cwd(), "..", "config", "grounding.yaml");
  }
  const file = fs.readFileSync(targetPath, "utf8");
  configCache = yaml.parse(file) as GroundingConfig;
  return configCache;
}

/** The text the gateway substitutes for the response body on `grounding.status === "block"`. */
export function getGroundingFallbackText(): string {
  try {
    return loadConfig().fallback_text.trim() || DEFAULT_FALLBACK_TEXT;
  } catch {
    return DEFAULT_FALLBACK_TEXT;
  }
}

/** Deadline (ms) for `POST /internal/verify` before the gateway marks grounding "unverified". */
export function getVerifyTimeoutMs(): number {
  try {
    const parsed = loadConfig().verify_timeout_ms;
    return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_VERIFY_TIMEOUT_MS;
  } catch {
    return DEFAULT_VERIFY_TIMEOUT_MS;
  }
}

/** Test-only escape hatch to force a fresh config read. */
export function resetGroundingConfigForTests(): void {
  configCache = null;
}
