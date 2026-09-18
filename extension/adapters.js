// Aegis Guard -- site adapters.
//
// All DOM knowledge lives here and nowhere else. These sites change their
// markup without notice; when one breaks, fix it in one place. Each adapter
// exposes: id, match(url), composer(), sendButton(), read(el), write(el, text).
// The generic fallback handles any focused composer inside a form.

(function () {
  function readEditable(el) {
    if (!el) return "";
    if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") return el.value;
    // ProseMirror / Quill: paragraphs -> lines
    const ps = el.querySelectorAll("p");
    if (ps.length) return Array.from(ps).map((p) => p.textContent).join("\n");
    return el.innerText || el.textContent || "";
  }

  function writeEditable(el, text) {
    if (!el) return;
    if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
      const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
      setter.call(el, text);
      el.dispatchEvent(new Event("input", { bubbles: true }));
      return;
    }
    el.focus();
    // Replace the whole contenteditable content through the editing API so
    // ProseMirror/Quill see a normal edit rather than a foreign DOM mutation.
    const sel = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(el);
    sel.removeAllRanges();
    sel.addRange(range);
    if (!document.execCommand("insertText", false, text)) {
      el.textContent = text;
      el.dispatchEvent(new Event("input", { bubbles: true }));
    }
  }

  const adapters = [
    {
      id: "chatgpt",
      match: (u) => /(^|\.)chatgpt\.com$|(^|\.)chat\.openai\.com$/.test(u.hostname),
      composer: () => document.querySelector("#prompt-textarea") || document.querySelector("form textarea"),
      sendButton: () => document.querySelector('button[data-testid="send-button"]') || document.querySelector('form button[type="submit"]'),
    },
    {
      id: "claude",
      match: (u) => /(^|\.)claude\.ai$/.test(u.hostname),
      composer: () => document.querySelector('div[contenteditable="true"].ProseMirror') || document.querySelector('div[contenteditable="true"]'),
      sendButton: () => document.querySelector('button[aria-label="Send message"]') || document.querySelector('button[aria-label*="Send"]'),
    },
    {
      id: "gemini",
      match: (u) => /(^|\.)gemini\.google\.com$/.test(u.hostname),
      composer: () => document.querySelector('div.ql-editor[contenteditable="true"]') || document.querySelector('div[contenteditable="true"]'),
      sendButton: () => document.querySelector('button[aria-label="Send message"]') || document.querySelector('button.send-button'),
    },
  ];

  const generic = {
    id: "generic",
    match: () => true,
    composer: () => {
      const a = document.activeElement;
      if (a && (a.tagName === "TEXTAREA" || a.isContentEditable)) return a;
      return document.querySelector('textarea, div[contenteditable="true"]');
    },
    sendButton: () => document.querySelector('button[type="submit"]'),
  };

  window.__aegisAdapters = {
    pick() {
      const u = new URL(location.href);
      const a = adapters.find((x) => x.match(u)) || generic;
      return { ...a, read: readEditable, write: writeEditable };
    },
  };
})();
