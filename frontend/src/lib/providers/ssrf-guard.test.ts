import { describe, expect, it } from "vitest";
import { assertProviderUrlAllowed, SsrfGuardError } from "@aegis/providers/ssrf-guard";

const ALLOWED = ["api.openai.com", "localhost", "127.0.0.1", "evil.example.com"];

function lookupOf(address: string, family: 4 | 6 = 4) {
  return async () => [{ address, family }];
}

describe("assertProviderUrlAllowed", () => {
  it("allows a public host resolving to a public IP", async () => {
    await expect(
      assertProviderUrlAllowed("https://api.openai.com/v1", {
        allowedHosts: ALLOWED,
        allowPrivateIps: false,
        lookupImpl: lookupOf("140.82.112.3"),
      }),
    ).resolves.toBeUndefined();
  });

  it("rejects a host not on the allowlist", async () => {
    await expect(
      assertProviderUrlAllowed("https://not-allowed.example.com/v1", {
        allowedHosts: ALLOWED,
        allowPrivateIps: true,
        lookupImpl: lookupOf("140.82.112.3"),
      }),
    ).rejects.toBeInstanceOf(SsrfGuardError);
  });

  it("rejects a loopback literal IP even if the hostname alone is allowlisted", async () => {
    await expect(
      assertProviderUrlAllowed("http://127.0.0.1:11434", {
        allowedHosts: ALLOWED,
        allowPrivateIps: false,
      }),
    ).rejects.toThrow(/private\/reserved/);
  });

  it("allows a loopback IP when allowPrivateIps is explicitly true", async () => {
    await expect(
      assertProviderUrlAllowed("http://127.0.0.1:11434", {
        allowedHosts: ALLOWED,
        allowPrivateIps: true,
      }),
    ).resolves.toBeUndefined();
  });

  it("rejects a hostname that resolves to a private IP (DNS-rebinding style)", async () => {
    await expect(
      assertProviderUrlAllowed("http://evil.example.com", {
        allowedHosts: ALLOWED,
        allowPrivateIps: false,
        lookupImpl: lookupOf("10.0.0.5"),
      }),
    ).rejects.toBeInstanceOf(SsrfGuardError);
  });

  it("rejects a 169.254.x.x link-local resolution (cloud metadata endpoint range)", async () => {
    await expect(
      assertProviderUrlAllowed("http://evil.example.com", {
        allowedHosts: ALLOWED,
        allowPrivateIps: false,
        lookupImpl: lookupOf("169.254.169.254"),
      }),
    ).rejects.toBeInstanceOf(SsrfGuardError);
  });

  it("rejects a non-http(s) protocol", async () => {
    await expect(
      assertProviderUrlAllowed("file:///etc/passwd", {
        allowedHosts: ALLOWED,
        allowPrivateIps: true,
      }),
    ).rejects.toBeInstanceOf(SsrfGuardError);
  });

  it("rejects an IPv6 loopback and unique-local address unless allowed", async () => {
    await expect(
      assertProviderUrlAllowed("http://[::1]:11434", {
        allowedHosts: ["::1"],
        allowPrivateIps: false,
      }),
    ).rejects.toBeInstanceOf(SsrfGuardError);

    await expect(
      assertProviderUrlAllowed("http://evil.example.com", {
        allowedHosts: ALLOWED,
        allowPrivateIps: false,
        lookupImpl: lookupOf("fd00::1", 6),
      }),
    ).rejects.toBeInstanceOf(SsrfGuardError);
  });
});
