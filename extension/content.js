// Aegis Guard -- content script.
//
// E1: intercept the send (Enter or the send button), scan through the
//     Inspector, then allow / sanitise-in-place / warn / block.
// E2: intercept a large paste, scan it alone, and hold it back when it
//     carries prompt-injection instructions.
//
// The verdict is the Gateway's own semantics (see frontend scan-gate.ts):
//   allow    -> send as typed
//   sanitize -> composer now holds placeholders; the user presses send again
//   warn     -> send as typed, toast
//   block    -> nothing is sent; card explains, values are never shown
// Fail closed by default when the Inspector is unreachable.

(function () {
  const A = window.__aegisAdapters.pick();
  let settingsCache = null;
  let enabledOnThisSite = true;
  let approvedText = null;       // text the user (or the verdict) approved for one send
  let inFlight = false;

  const send = (msg) => new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));

  async function settings() {
    if (!settingsCache) {
      settingsCache = await send({ type: "settings" });
      enabledOnThisSite = !settingsCache.sites || settingsCache.sites[A.id] !== false;
    }
    return settingsCache;
  }
  chrome.storage.onChanged.addListener(() => { settingsCache = null; });
  settings();

  // ---------------------------------------------------------------------------
  // UI
  // ---------------------------------------------------------------------------

  function card({ title, body, tone, actions = [], ttl = 0 }) {
    document.querySelectorAll(".aegis-card").forEach((n) => n.remove());
    const el = document.createElement("div");
    el.className = "aegis-card aegis-" + tone;
    el.setAttribute("role", "alert");
    const h = document.createElement("div"); h.className = "aegis-title"; h.textContent = title;
    const b = document.createElement("div"); b.className = "aegis-body"; b.textContent = body;
    el.append(h, b);
    if (actions.length) {
      const row = document.createElement("div"); row.className = "aegis-actions";
      for (const a of actions) {
        const btn = document.createElement("button"); btn.type = "button"; btn.textContent = a.label;
        btn.className = "aegis-btn" + (a.primary ? " aegis-primary" : "");
        btn.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); el.remove(); a.onClick && a.onClick(); });
        row.append(btn);
      }
      el.append(row);
    }
    const x = document.createElement("button"); x.className = "aegis-x"; x.textContent = "×"; x.title = "dismiss";
    x.addEventListener("click", () => el.remove());
    el.append(x);
    const foot = document.createElement("div"); foot.className = "aegis-foot";
    foot.textContent = "Aegis Guard · heuristic detection, can miss and can over-flag";
    el.append(foot);
    document.body.append(el);
    if (ttl) setTimeout(() => el.remove(), ttl);
    return el;
  }

  function summarise(detections) {
    const cats = [...new Set(detections.map((d) => d.category))];
    return cats.map((c) => c.replace(/^PII_|^SECRET_/, "").replace(/_/g, " ").toLowerCase()).join(", ");
  }

  function flashPlaceholders(el) {
    el.classList.add("aegis-flash");
    setTimeout(() => el.classList.remove("aegis-flash"), 1500);
  }

  // ---------------------------------------------------------------------------
  // E1: send interception
  // ---------------------------------------------------------------------------

  async function gate(triggerSend) {
    if (!enabledOnThisSite) return triggerSend();
    const el = A.composer();
    if (!el) return triggerSend();
    const text = A.read(el).trim();
    if (!text) return triggerSend();
    if (approvedText !== null && text === approvedText) { approvedText = null; return triggerSend(); }
    if (inFlight) return;
    inFlight = true;
    const s = await settings();
    const res = await send({ type: "scan", text, site: A.id, kind: "send" });
    inFlight = false;

    if (res.error) {
      if (s.failOpen) {
        card({ title: "Aegis unavailable — sent unscanned", body: "The Inspector could not be reached; fail-open is on in options.", tone: "warn", ttl: 5000 });
        approvedText = text; return triggerSend();
      }
      card({
        title: "Aegis unavailable — not sent", tone: "block",
        body: `The Inspector at the configured address did not answer (${res.error}). Nothing was sent.`,
        actions: [{ label: "Send anyway", onClick: () => { approvedText = text; triggerSend(); } }],
      });
      return;
    }
    const v = res.verdict;
    switch (v.action) {
      case "allow":
        approvedText = text; return triggerSend();
      case "warn":
        card({ title: "Sent with a warning", body: `Aegis recorded: ${summarise(v.detections) || v.explanation || "policy warning"}.`, tone: "warn", ttl: 6000 });
        approvedText = text; return triggerSend();
      case "sanitize": {
        const original = text;
        A.write(el, v.sanitized || text);
        flashPlaceholders(el);
        approvedText = A.read(el).trim();  // next send goes through as-is
        const n = v.detections.filter((d) => !d.secret).length;
        card({
          title: `${n} item${n === 1 ? "" : "s"} masked — press send again`, tone: "sanitize",
          body: `Replaced with placeholders: ${summarise(v.detections)}. The site never receives the original values; your Gateway can rehydrate them in the reply.`,
          actions: [
            { label: "Send masked", primary: true, onClick: () => { const btn = A.sendButton(); btn ? btn.click() : triggerSend(); } },
            { label: "Undo (send original)", onClick: () => { A.write(el, original); approvedText = original; } },
          ],
        });
        return;
      }
      case "block":
      default:
        card({
          title: v.error_code === "CREDENTIAL_LEAK_PREVENTED" ? "Blocked: credential in your message"
               : v.error_code === "PROMPT_INJECTION_BLOCKED" ? "Blocked: prompt-injection pattern"
               : "Blocked by policy", tone: "block",
          body: `${summarise(v.detections) || v.error_code || "policy"}. Nothing was sent. Remove it and try again; a blocked request can be appealed to a reviewer (request ${v.request_id}).`,
        });
        return;
    }
  }

  // Capture phase, so we run before the site's own handlers.
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
    const el = A.composer();
    if (!el || !el.contains(e.target)) return;
    const text = A.read(el).trim();
    if (!text || (approvedText !== null && text === approvedText)) { approvedText = null; return; }
    e.preventDefault(); e.stopImmediatePropagation();
    gate(() => {
      // Re-dispatch: prefer the site's send button; fall back to a synthetic Enter.
      const btn = A.sendButton();
      if (btn) btn.click();
      else el.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", code: "Enter", bubbles: true }));
    });
  }, true);

  document.addEventListener("click", (e) => {
    const btn = A.sendButton();
    if (!btn || !(e.target === btn || btn.contains(e.target))) return;
    const el = A.composer();
    if (!el) return;
    const text = A.read(el).trim();
    if (!text || (approvedText !== null && text === approvedText)) { approvedText = null; return; }
    e.preventDefault(); e.stopImmediatePropagation();
    gate(() => btn.click());
  }, true);

  // ---------------------------------------------------------------------------
  // E2: paste screening
  // ---------------------------------------------------------------------------

  document.addEventListener("paste", async (e) => {
    const el = A.composer();
    if (!el || !el.contains(e.target)) return;
    const pasted = (e.clipboardData && e.clipboardData.getData("text/plain")) || "";
    const s = await settings();
    if (!enabledOnThisSite) return;
    if (pasted.length < (s.pasteMinChars || 200)) return;
    e.preventDefault(); e.stopImmediatePropagation();
    const insert = () => document.execCommand("insertText", false, pasted);
    const res = await send({ type: "scan", text: pasted, site: A.id, kind: "paste" });
    if (res.error) {
      if (s.failOpen) return insert();
      card({ title: "Aegis unavailable — paste held", body: "Could not screen the pasted text.", tone: "block",
             actions: [{ label: "Paste anyway", onClick: insert }, { label: "Discard" }] });
      return;
    }
    const v = res.verdict;
    const inj = v.detections.filter((d) => d.category === "PROMPT_INJECTION");
    if (inj.length) {
      card({
        title: "Pasted text contains instructions aimed at the model", tone: "block",
        body: `Prompt-injection pattern (rule: ${inj.map((d) => d.rule).filter(Boolean).join(", ") || "unnamed"}). Pasting it would let that text steer the assistant. Heuristic match — review before pasting.`,
        actions: [{ label: "Paste anyway", onClick: insert }, { label: "Discard", primary: true }],
      });
      return;
    }
    const secrets = v.detections.filter((d) => d.secret);
    if (secrets.length) {
      card({ title: "Pasted text contains a credential", tone: "block",
             body: `${summarise(secrets)}. Held back; paste without it or send will be blocked.`,
             actions: [{ label: "Paste anyway", onClick: insert }, { label: "Discard", primary: true }] });
      return;
    }
    insert();
    if (v.detections.length) {
      card({ title: "Pasted text contains personal data", body: `${summarise(v.detections)} — it will be masked on send.`, tone: "warn", ttl: 5000 });
    }
  }, true);
})();
