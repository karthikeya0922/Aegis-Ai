/**
 * SSRF guard for outbound provider calls.
 *
 * Every adapter (`openai-compatible.ts`, `ollama.ts`) and every other outbound
 * fetch that carries user prompt text (`lib/cache/semantic-cache.ts`'s embedding
 * call) must:
 *
 *  1. call `assertProviderUrlAllowed` with its configured `base_url` immediately
 *     before each `fetch` — not just once at construction — and
 *  2. pass `guardedDispatcher(options)` as the request's `dispatcher`, so the
 *     private-IP check runs again at TCP-connect time against the address the
 *     socket actually connects to.
 *
 * Step 2 is what genuinely closes the DNS-rebinding window. Step 1 alone is
 * check-then-use: it resolves the hostname, and `fetch` then resolves it a
 * second time independently, so a record that flips between the two resolutions
 * would slip through. The dispatcher's `connect.lookup` hook is the last point
 * before the socket is opened, so a rebind cannot land after it.
 *
 * Two independent checks, both enforced in both places:
 *  1. Hostname allowlist — the host must be one of `allowedHosts` (from
 *     `config/providers.yaml`'s top-level `allowed_hosts`, plus the
 *     `AEGIS_PROVIDER_HOST_ALLOWLIST` env var). Deny by default.
 *  2. Private/reserved IP check — every IP the hostname resolves to must be a
 *     public address, unless `allowPrivateIps` is true
 *     (`AEGIS_PROVIDER_ALLOW_PRIVATE_IPS=true`). This is what makes local Ollama
 *     usable while keeping the check meaningful for everything else: `localhost`
 *     can be allowlisted by name, but the loopback IP it resolves to is still
 *     blocked until the env opt-in is set explicitly.
 */

import { isIP } from "node:net";
import type { LookupAddress } from "node:dns";
import { lookup as dnsLookup } from "node:dns/promises";
import { Agent, type Dispatcher } from "undici";

export class SsrfGuardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfGuardError";
  }
}

export interface SsrfGuardOptions {
  /** Allowed hostnames (case-insensitive, no ports/paths), e.g. ["api.openai.com", "localhost"]. */
  allowedHosts: readonly string[];
  /** Explicit opt-in (env-driven) to allow the resolved IP(s) to be private/loopback/link-local. */
  allowPrivateIps: boolean;
  /** Injectable for tests. Defaults to `dns.promises.lookup`. */
  lookupImpl?: (hostname: string) => Promise<LookupAddress[]>;
}

function defaultLookup(hostname: string): Promise<LookupAddress[]> {
  return dnsLookup(hostname, { all: true });
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

/** Parses "a.b.c.d" into a 32-bit unsigned int, or null if malformed. */
function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    out = (out << 8) | n;
  }
  return out >>> 0;
}

function ipv4InCidr(ip: string, base: string, bits: number): boolean {
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

/** RFC 1918/5735/6598 private, loopback, link-local, CGNAT, and "this network" ranges. */
const PRIVATE_V4_CIDRS: [string, number][] = [
  ["0.0.0.0", 8], // "this" network
  ["10.0.0.0", 8], // RFC 1918
  ["100.64.0.0", 10], // CGNAT (RFC 6598)
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local (incl. the cloud metadata address 169.254.169.254)
  ["172.16.0.0", 12], // RFC 1918
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // TEST-NET-1
  ["192.88.99.0", 24], // deprecated 6to4 relay anycast
  ["192.168.0.0", 16], // RFC 1918
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // TEST-NET-2
  ["203.0.113.0", 24], // TEST-NET-3
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved
];

function isPrivateOrReservedIpv4(ip: string): boolean {
  return PRIVATE_V4_CIDRS.some(([base, bits]) => ipv4InCidr(ip, base, bits));
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

/**
 * Expands any valid IPv6 textual form (including `::` compression and a trailing
 * embedded IPv4 literal) into its 16 bytes. Returns null if it cannot be parsed,
 * which callers treat as "unclassifiable" and therefore blocked.
 *
 * Doing real byte math is the point: matching textual prefixes instead meant
 * `::ffff:7f00:1` — loopback, written in hex rather than dotted form — was
 * classified as a public address.
 */
export function ipv6ToBytes(ip: string): Uint8Array | null {
  let text = ip.toLowerCase().trim();
  // Strip an RFC 6874 zone index ("fe80::1%eth0") — it does not affect the address.
  const zone = text.indexOf("%");
  if (zone !== -1) text = text.slice(0, zone);
  if (text.length === 0) return null;

  // A trailing dotted-quad ("::ffff:127.0.0.1", "64:ff9b::192.0.2.1") occupies the
  // last 4 bytes; replace it with the two equivalent hextets before splitting.
  const dotted = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(text);
  if (dotted) {
    const embedded = ipv4ToInt(dotted[1]);
    if (embedded === null) return null;
    const high = ((embedded >>> 16) & 0xffff).toString(16);
    const low = (embedded & 0xffff).toString(16);
    text = text.slice(0, dotted.index) + high + ":" + low;
  }

  const doubleColon = text.indexOf("::");
  let head: string[];
  let tail: string[];
  if (doubleColon === -1) {
    head = text.split(":");
    tail = [];
  } else {
    if (text.indexOf("::", doubleColon + 1) !== -1) return null; // only one "::" allowed
    const headText = text.slice(0, doubleColon);
    const tailText = text.slice(doubleColon + 2);
    head = headText.length === 0 ? [] : headText.split(":");
    tail = tailText.length === 0 ? [] : tailText.split(":");
  }

  if (head.length + tail.length > 8) return null;
  if (doubleColon === -1 && head.length !== 8) return null;

  const hextets = new Array<number>(8).fill(0);
  for (let i = 0; i < head.length; i++) {
    if (!/^[0-9a-f]{1,4}$/.test(head[i])) return null;
    hextets[i] = parseInt(head[i], 16);
  }
  for (let i = 0; i < tail.length; i++) {
    if (!/^[0-9a-f]{1,4}$/.test(tail[i])) return null;
    hextets[8 - tail.length + i] = parseInt(tail[i], 16);
  }

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = (hextets[i] >>> 8) & 0xff;
    bytes[i * 2 + 1] = hextets[i] & 0xff;
  }
  return bytes;
}

function bytesInPrefix(bytes: Uint8Array, prefix: readonly number[], prefixLength: number): boolean {
  const fullBytes = Math.floor(prefixLength / 8);
  for (let i = 0; i < fullBytes; i++) {
    if (bytes[i] !== (prefix[i] ?? 0)) return false;
  }
  const remainder = prefixLength % 8;
  if (remainder !== 0) {
    const mask = (0xff << (8 - remainder)) & 0xff;
    if ((bytes[fullBytes] & mask) !== ((prefix[fullBytes] ?? 0) & mask)) return false;
  }
  return true;
}

/** IPv6 ranges that must never be reachable as a provider endpoint. */
const PRIVATE_V6_PREFIXES: { prefix: readonly number[]; length: number; label: string }[] = [
  // Reached only after the v4-mapped / v4-compatible / NAT64 branches above have
  // returned, so this does not blanket-block a legitimate ::ffff:<public v4>.
  { prefix: [0x00], length: 8, label: "::/8 reserved" },
  { prefix: [0x01, 0x00], length: 16, label: "100::/16 discard-only" },
  { prefix: [0xfe, 0x80], length: 10, label: "fe80::/10 link-local" },
  { prefix: [0xfc], length: 7, label: "fc00::/7 unique-local" },
  { prefix: [0xff], length: 8, label: "ff00::/8 multicast" },
  { prefix: [0x20, 0x01, 0x0d, 0xb8], length: 32, label: "2001:db8::/32 documentation" },
  { prefix: [0x20, 0x01, 0x00, 0x00], length: 32, label: "2001::/32 Teredo" },
  { prefix: [0x20, 0x01, 0x00, 0x02], length: 48, label: "2001:2::/48 benchmarking" },
];

function isPrivateOrReservedIpv6(ip: string): boolean {
  const bytes = ipv6ToBytes(ip);
  if (bytes === null) return true; // unparseable — fail closed

  // ::/96 (v4-compatible), ::ffff:0:0/96 (v4-mapped) and 64:ff9b::/32 (NAT64) all
  // embed an IPv4 address in the last four bytes. Classify by that address, so
  // ::ffff:8.8.8.8 stays usable while ::ffff:127.0.0.1 and its hex spelling
  // ::ffff:7f00:1 are both blocked.
  const isV4Mapped = bytesInPrefix(bytes, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff], 96);
  const isV4Compatible = bytesInPrefix(bytes, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 96);
  const isNat64 = bytesInPrefix(bytes, [0x00, 0x64, 0xff, 0x9b], 32);
  if (isV4Mapped || isV4Compatible || isNat64) {
    // `::` and `::1` land in ::/96 with a zero high half — reserved either way.
    if (isV4Compatible && bytes[12] === 0 && bytes[13] === 0) return true;
    return isPrivateOrReservedIpv4(`${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`);
  }

  // 6to4 (2002::/16) embeds an IPv4 address in bytes 2..5.
  if (bytesInPrefix(bytes, [0x20, 0x02], 16)) {
    return isPrivateOrReservedIpv4(`${bytes[2]}.${bytes[3]}.${bytes[4]}.${bytes[5]}`);
  }

  return PRIVATE_V6_PREFIXES.some(({ prefix, length }) => bytesInPrefix(bytes, prefix, length));
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return isPrivateOrReservedIpv4(ip);
  if (version === 6) return isPrivateOrReservedIpv6(ip);
  return true; // couldn't classify — fail closed
}

function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}

/**
 * Validates `rawUrl` against the host allowlist and (unless explicitly allowed) rejects
 * hosts that resolve to a private/loopback/link-local/reserved IP. Throws `SsrfGuardError`
 * on any violation. Call this immediately before every outbound `fetch`, and pass
 * `guardedDispatcher` on that fetch so the IP check is repeated at connect time.
 */
export async function assertProviderUrlAllowed(rawUrl: string, options: SsrfGuardOptions): Promise<void> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new SsrfGuardError(`Provider base_url is not a valid URL: ${rawUrl}`);
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new SsrfGuardError(`Provider base_url must be http(s), got "${url.protocol}" in ${rawUrl}`);
  }

  const host = normalizeHost(url.hostname);
  const allowed = new Set(options.allowedHosts.map(normalizeHost));
  if (!allowed.has(host)) {
    throw new SsrfGuardError(
      `Provider host "${host}" is not in the allowlist. Add it to config/providers.yaml's ` +
        `allowed_hosts or the AEGIS_PROVIDER_HOST_ALLOWLIST env var if this is intentional.`,
    );
  }

  const lookupImpl = options.lookupImpl ?? defaultLookup;
  let records: LookupAddress[];
  // `URL.hostname` hands back a bracketed IPv6 literal as "[::1]".
  const literalHost = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  const literalVersion = isIP(literalHost);
  if (literalVersion) {
    records = [{ address: literalHost, family: literalVersion }];
  } else {
    try {
      records = await lookupImpl(host);
    } catch (err) {
      throw new SsrfGuardError(`Could not resolve provider host "${host}": ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  if (records.length === 0) {
    throw new SsrfGuardError(`Provider host "${host}" resolved to no addresses`);
  }

  if (!options.allowPrivateIps) {
    for (const record of records) {
      if (isPrivateOrReservedIp(record.address)) {
        throw new SsrfGuardError(
          `Provider host "${host}" resolves to a private/reserved IP (${record.address}). ` +
            `Set AEGIS_PROVIDER_ALLOW_PRIVATE_IPS=true to allow this explicitly (e.g. for local Ollama).`,
        );
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Connect-time enforcement (closes the check-then-use window)
// ---------------------------------------------------------------------------

type NodeLookup = (
  hostname: string,
  options: { all?: boolean } & Record<string, unknown>,
  callback: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void,
) => void;

/**
 * A `dns.lookup`-shaped function that re-runs the private-IP check on the
 * addresses the socket is about to connect to, and fails the connection if any
 * of them is private/reserved.
 */
function validatingLookup(allowPrivateIps: boolean): NodeLookup {
  return (hostname, options, callback) => {
    dnsLookup(hostname, { all: true }).then(
      (records) => {
        if (!allowPrivateIps) {
          const offending = records.find((r) => isPrivateOrReservedIp(r.address));
          if (offending) {
            const err: NodeJS.ErrnoException = new SsrfGuardError(
              `Blocked connection to "${hostname}": it resolved to a private/reserved IP (${offending.address}) at connect time.`,
            );
            err.code = "EACCES";
            callback(err, []);
            return;
          }
        }
        if (records.length === 0) {
          const err: NodeJS.ErrnoException = new SsrfGuardError(`"${hostname}" resolved to no addresses at connect time.`);
          err.code = "ENOTFOUND";
          callback(err, []);
          return;
        }
        if (options.all) callback(null, records);
        else callback(null, records[0].address, records[0].family);
      },
      (err: NodeJS.ErrnoException) => callback(err, []),
    );
  };
}

// One Agent per distinct policy, reused across requests so connection pooling
// still works. There are only two possible policies today.
const dispatcherCache = new Map<boolean, Agent>();

/**
 * The `dispatcher` every guarded outbound fetch must pass. Re-validates the
 * resolved address inside `connect`, immediately before the socket is opened.
 */
export function guardedDispatcher(options: Pick<SsrfGuardOptions, "allowPrivateIps">): Dispatcher {
  const cached = dispatcherCache.get(options.allowPrivateIps);
  if (cached) return cached;
  const agent = new Agent({
    connect: { lookup: validatingLookup(options.allowPrivateIps) as never },
  });
  dispatcherCache.set(options.allowPrivateIps, agent);
  return agent;
}

/**
 * Builds the `RequestInit` for a guarded outbound fetch: the caller's init, the
 * resolved headers, and the connect-time-validating `dispatcher`. Every adapter
 * uses this so no call site can forget the dispatcher half of the guard.
 */
export function withGuardedDispatcher(
  init: RequestInit & { signal: AbortSignal },
  headers: Record<string, string>,
  options: Pick<SsrfGuardOptions, "allowPrivateIps">,
): RequestInit & { signal: AbortSignal } {
  return { ...init, headers, dispatcher: guardedDispatcher(options) } as RequestInit & {
    signal: AbortSignal;
  };
}

/** Test-only: drops the cached Agents so a new policy takes effect. */
export function resetGuardedDispatchersForTests(): void {
  for (const agent of dispatcherCache.values()) void agent.close();
  dispatcherCache.clear();
}
