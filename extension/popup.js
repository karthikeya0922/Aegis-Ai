// Aegis Guard -- popup. A thin client over the Inspector's read APIs.
// The Deployment tab shows what YOUR Gateway measured: cache, routing, cost
// and fairness numbers come from there, never from the third-party site.

const $ = (id) => document.getElementById(id);
const send = (msg) => new Promise((r) => chrome.runtime.sendMessage(msg, r));
const esc = (s) => String(s ?? "–").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const row = (k, v) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`;
const pct = (x) => (x == null ? "–" : (x * 100).toFixed(1) + "%");

document.querySelectorAll("nav button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll("nav button, section").forEach((n) => n.classList.remove("on"));
  b.classList.add("on"); $(b.dataset.tab).classList.add("on");
}));
$("opts").addEventListener("click", (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); });

async function health() {
  const h = await send({ type: "health" });
  const dot = $("dot");
  if (!h || !h.ok || !h.body) { dot.className = "dot down"; $("health").textContent = "Inspector unreachable"; return; }
  dot.className = "dot " + (h.body.status === "ok" ? "ok" : "degraded");
  const deg = (h.body.degraded || []).join(", ");
  $("health").textContent = `inspector ${h.body.status} · v${h.body.version}` + (deg ? ` (${deg})` : "");
}

async function page() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  try { $("site").textContent = new URL(tab.url).hostname; } catch { $("site").textContent = "–"; }
  const st = await send({ type: "tabstats", tabId: tab.id });
  if (!st) return;
  $("scans").textContent = st.scans || 0; $("sanitized").textContent = st.sanitized || 0;
  $("blocked").textContent = st.blocked || 0; $("pastes").textContent = st.pastesBlocked || 0;
  if (st.last) {
    $("last").textContent = `${st.last.action}${st.last.error_code ? " · " + st.last.error_code : ""}` +
      (st.last.categories.length ? ` · ${st.last.categories.join(", ")}` : "");
    $("stages").innerHTML = (st.last.stages || []).map((s) =>
      `<div class="stage"><span class="s ${esc(s.status)}">${s.status === "pass" ? "ok" : s.status === "flagged" ? "!!" : s.status === "blocked" ? "XX" : "--"}</span>` +
      `<span>${esc(s.name)}</span><span class="d">${typeof s.duration_ms === "number" ? s.duration_ms.toFixed(1) + " ms" : ""}</span></div>`).join("");
  }
}

async function deployment() {
  const d = await send({ type: "deployment" });
  const m = d.metrics, s = d.security, su = d.sustainability, p = d.providers, f = d.fairness;
  if (!m) { $("deploy-body").textContent = "Inspector metrics unavailable."; return; }
  const cost = m.cost || {}, lat = m.latency || {};
  let html = `<h4>traffic (last ${esc(m.window_hours)}h)</h4><table>` +
    row("requests", m.total_requests) + row("blocked / sanitised", `${m.blocked_requests} / ${m.sanitized_requests}`) +
    row("latency p50 / p95", `${lat.p50_ms ?? "–"} / ${lat.p95_ms ?? "–"} ms`) +
    row("inspector overhead p50", `${lat.inspector_overhead_p50_ms ?? "–"} ms`) + `</table>`;
  if (s) html += `<h4>security</h4><table>` + row("PII detections", s.pii_detections) + row("secret detections", s.secret_detections) +
    row("credential blocks", s.credential_blocks) + row("injection blocks", s.injection_blocks) + row("egress flags", s.egress_flags) + `</table>`;
  if (su) html += `<h4>cache &amp; sustainability (estimates)</h4><table>` +
    row("cache hit rate", `${pct(su.cache_hit_rate)} (${su.cache_hits} / ${su.cache_hits + su.cache_misses})`) +
    row("estimated spend / saved", `$${cost.estimated_spend_usd ?? "–"} / $${cost.estimated_saved_usd ?? "–"}`) +
    row("estimated energy", `${su.estimated_energy_wh} Wh · ${su.estimated_co2_g} g CO2`) + `</table>` +
    `<div class="basis">${esc(cost.basis || "")}</div><div class="basis">${esc((su.basis || "").slice(0, 220))}</div>`;
  if (p) html += `<h4>providers</h4><table>` + (p.providers || []).map((r) => row(r.provider, `${r.requests} req · ${r.failures} fail · failover ${r.failover_in}/${r.failover_out}`)).join("") +
    row("failover events", p.failover_events) + `</table>`;
  if (f) {
    const cur = f.current;
    html += `<h4>fairness (PERSON recall)</h4>`;
    html += cur ? `<table>` + (cur.groups || []).map((g) => row(g.group, g.recall.toFixed(3))).join("") + row("worst-best gap", cur.recall_gap?.toFixed(3)) + `</table>`
                : `<div class="basis">no run recorded (POST /api/fairness/run)</div>`;
    html += `<div class="basis">${esc((f.disclaimer || "").slice(0, 200))}</div>`;
  }
  $("deploy-body").innerHTML = html;
}

async function reviews() {
  const d = await send({ type: "deployment" });
  const r = d.reviews;
  if (!r) { $("reviews-body").textContent = "unavailable"; return; }
  const items = r.items || [];
  $("reviews-body").innerHTML = `<table>${row("pending", r.total)}</table>` +
    (items.length ? `<table>` + items.slice(0, 8).map((it) => row(it.id, `${it.original_decision} · ${esc((it.user_justification || "").slice(0, 60))}`)).join("") + `</table>` : "") +
    `<div class="basis">Decide in the dashboard or with <code>aegis reviews decide</code>. Appeals need a reviewer token when the Inspector has one set.</div>`;
}

health(); page(); deployment(); reviews();
setInterval(() => { health(); page(); }, 5000);
setInterval(() => { deployment(); reviews(); }, 15000);
