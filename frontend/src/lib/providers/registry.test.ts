import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadProviderRegistry, ProviderConfigError } from "@aegis/providers/registry";
import { OllamaProvider } from "@aegis/providers/ollama";
import { OpenAICompatibleProvider } from "@aegis/providers/openai-compatible";

let tmpDir: string | null = null;
afterEach(async () => {
  if (tmpDir) {
    await rm(tmpDir, { recursive: true, force: true });
    tmpDir = null;
  }
});

async function writeConfig(yamlText: string): Promise<string> {
  tmpDir = await mkdtemp(path.join(tmpdir(), "aegis-providers-"));
  const configPath = path.join(tmpDir, "providers.yaml");
  await writeFile(configPath, yamlText, "utf-8");
  return configPath;
}

const BASE_CONFIG = `
allowed_hosts:
  - api.example.com
  - localhost
default_provider: main
providers:
  - name: main
    kind: openai_compatible
    base_url: https://api.example.com/v1
    api_key_env: TEST_KEY
    default_model: some-model
  - name: local
    kind: ollama
    base_url: http://localhost:11434
    default_model: llama3.1
`;

describe("loadProviderRegistry", () => {
  it("builds providers of the right adapter kind and exposes the default", async () => {
    const configPath = await writeConfig(BASE_CONFIG);
    const registry = await loadProviderRegistry({ configPath, env: { NODE_ENV: "test" } });

    expect(registry.list().sort()).toEqual(["local", "main"]);
    expect(registry.get("main").provider).toBeInstanceOf(OpenAICompatibleProvider);
    expect(registry.get("local").provider).toBeInstanceOf(OllamaProvider);
    expect(registry.get("main").defaultModel).toBe("some-model");
    expect(registry.getDefault().provider.name).toBe("main");
  });

  it("rejects an unknown provider name", async () => {
    const configPath = await writeConfig(BASE_CONFIG);
    const registry = await loadProviderRegistry({ configPath, env: { NODE_ENV: "test" } });
    expect(() => registry.get("does-not-exist")).toThrow(ProviderConfigError);
  });

  it("rejects a default_provider that isn't defined", async () => {
    const configPath = await writeConfig(BASE_CONFIG.replace("default_provider: main", "default_provider: ghost"));
    await expect(loadProviderRegistry({ configPath, env: { NODE_ENV: "test" } })).rejects.toThrow(ProviderConfigError);
  });

  it("rejects a duplicate provider name", async () => {
    const dup = `
providers:
  - name: dup
    kind: openai_compatible
    base_url: https://api.example.com/v1
  - name: dup
    kind: openai_compatible
    base_url: https://api.example.com/v1
`;
    const configPath = await writeConfig(dup);
    await expect(loadProviderRegistry({ configPath, env: { NODE_ENV: "test" } })).rejects.toThrow(/duplicate/);
  });

  it("rejects an invalid provider kind", async () => {
    const bad = `
providers:
  - name: bad
    kind: not_a_real_kind
    base_url: https://api.example.com/v1
`;
    const configPath = await writeConfig(bad);
    await expect(loadProviderRegistry({ configPath, env: { NODE_ENV: "test" } })).rejects.toThrow(ProviderConfigError);
  });

  it("extends (not replaces) allowed_hosts from AEGIS_PROVIDER_HOST_ALLOWLIST", async () => {
    const configPath = await writeConfig(BASE_CONFIG);
    // Both providers' hosts (api.example.com, localhost) are already in the YAML allowlist;
    // this just verifies the env var doesn't blow up config loading and merges additively.
    const registry = await loadProviderRegistry({ configPath, env: { NODE_ENV: "test", AEGIS_PROVIDER_HOST_ALLOWLIST: "extra.example.com, another.example.com" } });
    expect(registry.list().sort()).toEqual(["local", "main"]);
  });

  it("wraps a missing config file in ProviderConfigError", async () => {
    await expect(loadProviderRegistry({ configPath: "/nonexistent/path/providers.yaml", env: { NODE_ENV: "test" } })).rejects.toThrow(ProviderConfigError);
  });
});
