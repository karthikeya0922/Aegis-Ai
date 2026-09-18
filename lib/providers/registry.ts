/**
 * Provider registry — loads `config/providers.yaml` and builds the configured
 * `LLMProvider` instances, so the rest of the app never constructs an adapter
 * directly. Swapping/adding a provider is a config change, not a code change.
 *
 * The SSRF allowlist (`allowed_hosts`) can be extended (never replaced) via the
 * `AEGIS_PROVIDER_HOST_ALLOWLIST` env var (comma-separated hostnames) — useful for a
 * self-hosted OpenAI-compatible endpoint without editing the checked-in config.
 * `AEGIS_PROVIDER_ALLOW_PRIVATE_IPS=true` opts into private/loopback IPs (needed for
 * `ollama-local`'s default `http://localhost:11434`).
 */

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as yaml from "js-yaml";

import { type LLMProvider } from "./base";
import { CircuitBreaker, loadCircuitBreakerConfigFromEnv } from "./circuit-breaker";
import type { FailoverGroupMember } from "./failover";
import { OllamaProvider } from "./ollama";
import { OpenAICompatibleProvider } from "./openai-compatible";

export type ProviderKind = "openai_compatible" | "ollama";

export interface RawProviderEntry {
  name: string;
  kind: ProviderKind;
  base_url: string;
  api_key_env?: string;
  default_model?: string;
  extra_headers?: Record<string, string>;
}

interface RawProvidersConfig {
  allowed_hosts?: unknown;
  default_provider?: unknown;
  failover_chain?: unknown;
  providers?: unknown;
}

export class ProviderConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProviderConfigError";
  }
}

/**
 * Every provider gets its own default_model and a long-lived `CircuitBreaker`
 * attached alongside the interface. The breaker MUST outlive a single request —
 * it's created once here, when the registry (a module-level singleton, see
 * `frontend/src/lib/gateway/provider.ts`) is built.
 */
export interface RegisteredProvider {
  provider: LLMProvider;
  defaultModel: string | null;
  breaker: CircuitBreaker;
}

export class ProviderRegistry {
  private readonly providers = new Map<string, RegisteredProvider>();
  private readonly defaultProviderName: string | null;
  private readonly failoverChain: string[];

  constructor(providers: Map<string, RegisteredProvider>, defaultProviderName: string | null, failoverChain: string[]) {
    this.providers = providers;
    this.defaultProviderName = defaultProviderName;
    this.failoverChain = failoverChain;
  }

  get(name: string): RegisteredProvider {
    const entry = this.providers.get(name);
    if (!entry) {
      throw new ProviderConfigError(`Unknown provider "${name}". Configured providers: ${[...this.providers.keys()].join(", ") || "(none)"}`);
    }
    return entry;
  }

  getDefault(): RegisteredProvider {
    if (!this.defaultProviderName) {
      throw new ProviderConfigError("No default_provider configured in config/providers.yaml");
    }
    return this.get(this.defaultProviderName);
  }

  list(): string[] {
    return [...this.providers.keys()];
  }

  /**
   * The ordered chain `chatWithFailover`/`streamWithFailover` should try:
   * `config/providers.yaml`'s `failover_chain` if set, otherwise just the
   * `default_provider` on its own (no failover, since no secondary is configured).
   */
  getFailoverGroup(): FailoverGroupMember[] {
    const names = this.failoverChain.length > 0 ? this.failoverChain : this.defaultProviderName ? [this.defaultProviderName] : [];
    if (names.length === 0) {
      throw new ProviderConfigError("No failover_chain and no default_provider configured in config/providers.yaml");
    }
    return names.map((name) => {
      const entry = this.get(name);
      return { provider: entry.provider, breaker: entry.breaker };
    });
  }

  getFailoverGroupFor(route: { provider: string; failover?: string[] }): FailoverGroupMember[] {
    const failoverList = route.failover ?? this.failoverChain;
    const names = Array.from(new Set([route.provider, ...failoverList]));
    return names.map((name) => {
      const entry = this.get(name);
      return { provider: entry.provider, breaker: entry.breaker };
    });
  }
}

function parseEnvHostList(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((h) => h.trim())
    .filter((h) => h.length > 0);
}

function assertString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ProviderConfigError(`config/providers.yaml: expected non-empty string for "${field}", got ${JSON.stringify(value)}`);
  }
  return value;
}

function assertOptionalString(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined;
  return assertString(value, field);
}

function parseProviderEntry(raw: unknown, index: number): RawProviderEntry {
  if (typeof raw !== "object" || raw === null) {
    throw new ProviderConfigError(`config/providers.yaml: providers[${index}] must be an object`);
  }
  const entry = raw as Record<string, unknown>;
  const kind = assertString(entry.kind, `providers[${index}].kind`);
  if (kind !== "openai_compatible" && kind !== "ollama") {
    throw new ProviderConfigError(`config/providers.yaml: providers[${index}].kind must be "openai_compatible" or "ollama", got "${kind}"`);
  }
  const extraHeaders = entry.extra_headers;
  if (extraHeaders !== undefined && (typeof extraHeaders !== "object" || extraHeaders === null || Array.isArray(extraHeaders))) {
    throw new ProviderConfigError(`config/providers.yaml: providers[${index}].extra_headers must be a map of strings`);
  }

  return {
    name: assertString(entry.name, `providers[${index}].name`),
    kind,
    base_url: assertString(entry.base_url, `providers[${index}].base_url`),
    api_key_env: assertOptionalString(entry.api_key_env, `providers[${index}].api_key_env`),
    default_model: assertOptionalString(entry.default_model, `providers[${index}].default_model`),
    extra_headers: extraHeaders as Record<string, string> | undefined,
  };
}

function parseConfig(raw: unknown): {
  allowedHosts: string[];
  defaultProvider: string | null;
  failoverChain: string[];
  entries: RawProviderEntry[];
} {
  if (typeof raw !== "object" || raw === null) {
    throw new ProviderConfigError("config/providers.yaml: root must be a YAML mapping");
  }
  const config = raw as RawProvidersConfig;

  const allowedHostsRaw = config.allowed_hosts;
  if (allowedHostsRaw !== undefined && !Array.isArray(allowedHostsRaw)) {
    throw new ProviderConfigError('config/providers.yaml: "allowed_hosts" must be a list of strings');
  }
  const allowedHosts = ((allowedHostsRaw as unknown[] | undefined) ?? []).map((h, i) => assertString(h, `allowed_hosts[${i}]`));

  const defaultProvider = config.default_provider !== undefined ? assertString(config.default_provider, "default_provider") : null;

  const failoverChainRaw = config.failover_chain;
  if (failoverChainRaw !== undefined && !Array.isArray(failoverChainRaw)) {
    throw new ProviderConfigError('config/providers.yaml: "failover_chain" must be a list of provider names');
  }
  const failoverChain = ((failoverChainRaw as unknown[] | undefined) ?? []).map((n, i) => assertString(n, `failover_chain[${i}]`));

  if (!Array.isArray(config.providers)) {
    throw new ProviderConfigError('config/providers.yaml: "providers" must be a list');
  }
  const entries = config.providers.map(parseProviderEntry);

  const seen = new Set<string>();
  for (const entry of entries) {
    if (seen.has(entry.name)) {
      throw new ProviderConfigError(`config/providers.yaml: duplicate provider name "${entry.name}"`);
    }
    seen.add(entry.name);
  }

  return { allowedHosts, defaultProvider, failoverChain, entries };
}

function buildProvider(entry: RawProviderEntry, allowedHosts: string[], allowPrivateIps: boolean): LLMProvider {
  const ssrf = { allowedHosts, allowPrivateIps };
  if (entry.kind === "ollama") {
    return new OllamaProvider({ name: entry.name, baseUrl: entry.base_url, ssrf });
  }
  return new OpenAICompatibleProvider({
    name: entry.name,
    baseUrl: entry.base_url,
    apiKeyEnvVar: entry.api_key_env,
    extraHeaders: entry.extra_headers,
    ssrf,
  });
}

export interface LoadProviderRegistryOptions {
  /**
   * Overrides the config path. Falls back to `AEGIS_PROVIDERS_CONFIG_PATH` (useful for
   * pointing at a throwaway config in manual/e2e testing without touching the checked-in
   * file), then to `config/providers.yaml` at the repo root.
   */
  configPath?: string;
  /** Injectable for tests; defaults to `process.env`. */
  env?: NodeJS.ProcessEnv;
}

function defaultConfigPath(): string {
  // This file lives at `lib/providers/registry.ts`; the config lives at `<repo root>/config/providers.yaml`.
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "..", "..", "config", "providers.yaml");
}

/** Loads and validates `config/providers.yaml`, returning a ready-to-use `ProviderRegistry`. */
export async function loadProviderRegistry(options: LoadProviderRegistryOptions = {}): Promise<ProviderRegistry> {
  const env = options.env ?? process.env;
  const configPath = options.configPath || env.AEGIS_PROVIDERS_CONFIG_PATH || defaultConfigPath(); // blank (as in .env.example) means unset

  let raw: string;
  try {
    raw = await readFile(/* turbopackIgnore: true */ configPath, "utf-8");
  } catch (err) {
    throw new ProviderConfigError(`Could not read provider config at ${configPath}: ${err instanceof Error ? err.message : String(err)}`);
  }

  let parsedYaml: unknown;
  try {
    // js-yaml v4's `load()` uses DEFAULT_SCHEMA (safe) — it does not support the
    // arbitrary-type-construction tags that make PyYAML's `yaml.load` dangerous.
    parsedYaml = yaml.load(raw);
  } catch (err) {
    throw new ProviderConfigError(`Could not parse ${configPath} as YAML: ${err instanceof Error ? err.message : String(err)}`);
  }

  const { allowedHosts: configuredHosts, defaultProvider, failoverChain, entries } = parseConfig(parsedYaml);
  const allowedHosts = [...new Set([...configuredHosts, ...parseEnvHostList(env.AEGIS_PROVIDER_HOST_ALLOWLIST)])];
  const allowPrivateIps = env.AEGIS_PROVIDER_ALLOW_PRIVATE_IPS === "true";
  const breakerConfig = loadCircuitBreakerConfigFromEnv(env);

  const providers = new Map<string, RegisteredProvider>();
  for (const entry of entries) {
    providers.set(entry.name, {
      provider: buildProvider(entry, allowedHosts, allowPrivateIps),
      defaultModel: entry.default_model ?? null,
      // One breaker per provider, created once here — see `RegisteredProvider`'s doc comment.
      breaker: new CircuitBreaker(breakerConfig),
    });
  }

  if (defaultProvider && !providers.has(defaultProvider)) {
    throw new ProviderConfigError(`config/providers.yaml: default_provider "${defaultProvider}" is not a configured provider`);
  }
  for (const name of failoverChain) {
    if (!providers.has(name)) {
      throw new ProviderConfigError(`config/providers.yaml: failover_chain entry "${name}" is not a configured provider`);
    }
  }

  return new ProviderRegistry(providers, defaultProvider, failoverChain);
}
