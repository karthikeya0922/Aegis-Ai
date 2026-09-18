const $ = (id) => document.getElementById(id);

async function load() {
  const s = await new Promise((r) => chrome.runtime.sendMessage({ type: "settings" }, r));
  $("engineUrl").value = s.engineUrl; $("mode").value = s.mode; $("failOpen").checked = !!s.failOpen;
  $("pasteMinChars").value = s.pasteMinChars;
  for (const k of ["chatgpt", "claude", "gemini"]) $("site-" + k).checked = s.sites[k] !== false;
}

$("save").addEventListener("click", async () => {
  const settings = {
    engineUrl: $("engineUrl").value.trim() || "http://localhost:8000",
    mode: $("mode").value, failOpen: $("failOpen").checked,
    pasteMinChars: Math.max(0, Number($("pasteMinChars").value) || 0),
    sites: { chatgpt: $("site-chatgpt").checked, claude: $("site-claude").checked, gemini: $("site-gemini").checked },
  };
  await chrome.storage.sync.set({ settings });
  $("saved").textContent = "saved"; setTimeout(() => ($("saved").textContent = ""), 1500);
});

load();
