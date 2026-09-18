// Aegis Guard -- service worker.
//
// All network calls to the Inspector happen here, from the extension origin,
// so the Inspector needs no CORS entry for chat sites and the page never
// learns the Inspector's address. Content scripts and the popup send
// messages; this answers them.

const DEFAULTS = {
  engineUrl: "http://localhost:8000",
  mode: "sanitize",          // sanitize | strict
  failOpen: false,           // Inspector unreachable -> block by default
  pasteMinChars: 200,
  sites: { chatgpt: true, claude: true, gemini: true },
};

async function settings() {
  const stored = await chrome.storage.sync.get("settings");
  return { ...DEFAULTS, ...(stored.settings || {}), sites: { ...DEFAULTS.sites, ...((stored.settings || {}).sites || {}) } };
}

async function engineFetch(path, init = {}, timeoutMs = 3000) {
  const s = await settings();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(s.engineUrl.replace(/\/+$/, "") + path, { ...init, signal: ctrl.signal });
    const body = await res.json().catch(() => null);
    return { ok: res.ok, status: res.status, body };
  } finally {
    clearTimeout(timer);
  }
}

function newId(prefix) {
  return prefix + "_" + Array.from(crypto.getRandomValues(new Uint8Array(9)), (b) => b.toString(16).padStart(2, "0")).join("");
}

// Per-tab counters for the popup's "this page" tab. Session storage: gone when
// the browser closes, never written to disk.
async function bump(tabId, key, extra) {
  const k = "tab:" + tabId;
  const cur = (await chrome.storage.session.get(k))[k] || { scans: 0, sanitized: 0, blocked: 0, pastesBlocked: 0, last: null };
  cur[key] = (cur[key] || 0) + 1;
  if (extra) cur.last = extra;
  await chrome.storage.session.set({ [k]: cur });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    const tabId = sender.tab ? sender.tab.id : msg.tabId;
    switch (msg.type) {
      case "settings":
        return sendResponse(await settings());

      case "scan": {
        const s = await settings();
        const sessionKey = "session_id";
        let sid = (await chrome.storage.local.get(sessionKey))[sessionKey];
        if (!sid) { sid = newId("sess_ext"); await chrome.storage.local.set({ [sessionKey]: sid }); }
        try {
          const r = await engineFetch("/internal/scan", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              request_id: newId("req_ext"), session_id: sid, mode: s.mode,
              messages: [{ role: "user", content: msg.text }],
              metadata: { client: "aegis-guard-extension", site: msg.site || "unknown", kind: msg.kind || "send" },
            }),
          });
          if (!r.ok || !r.body) return sendResponse({ error: "engine_error", status: r.status, failOpen: s.failOpen });
          const b = r.body;
          // Strip raw values before anything leaves this worker: the content
          // script only ever needs categories, placeholders and offsets.
          const detections = (b.detections || []).map((d) => ({
            category: d.category, placeholder: d.placeholder, start: d.start, end: d.end,
            confidence: d.confidence, secret: String(d.category || "").startsWith("SECRET_"),
            rule: d.category === "PROMPT_INJECTION" ? d.match : undefined,
          }));
          const verdict = {
            request_id: b.request_id, action: b.action, error_code: b.error_code, detections,
            sanitized: b.sanitized_messages ? b.sanitized_messages[0].content : null,
            stages: (b.stages || []).map((st) => ({ name: st.name, status: st.status, duration_ms: st.duration_ms, detail: st.detail })),
            explanation: b.explanation,
          };
          if (tabId != null) {
            const key = b.action === "block" ? "blocked" : b.action === "sanitize" ? "sanitized" : "scans";
            await bump(tabId, "scans");
            if (key !== "scans") await bump(tabId, key);
            if (msg.kind === "paste" && b.action === "block") await bump(tabId, "pastesBlocked");
            await bump(tabId, "_", { action: b.action, error_code: b.error_code, categories: [...new Set(detections.map((d) => d.category))], stages: verdict.stages, at: Date.now() });
          }
          return sendResponse({ verdict });
        } catch (e) {
          return sendResponse({ error: "unreachable", failOpen: s.failOpen });
        }
      }

      case "health": {
        try { return sendResponse(await engineFetch("/internal/health", {}, 2500)); }
        catch { return sendResponse({ ok: false, status: 0, body: null }); }
      }

      case "deployment": {
        const out = {};
        for (const [k, p] of Object.entries({ metrics: "/api/metrics", security: "/api/metrics/security", sustainability: "/api/metrics/sustainability", providers: "/api/metrics/providers", reviews: "/api/reviews?status=PENDING", fairness: "/api/fairness/report" })) {
          try { const r = await engineFetch(p, {}, 4000); out[k] = r.ok ? r.body : null; } catch { out[k] = null; }
        }
        return sendResponse(out);
      }

      case "tabstats": {
        const k = "tab:" + tabId;
        return sendResponse((await chrome.storage.session.get(k))[k] || null);
      }

      default:
        return sendResponse({ error: "unknown message" });
    }
  })();
  return true; // async sendResponse
});
