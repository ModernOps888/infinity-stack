"use strict";

const api = {
  async req(method, path, body) {
    const opts = { method, headers: {}, credentials: "same-origin" };
    if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    const res = await fetch(path, opts);
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = { raw: text }; }
    if (!res.ok) throw new Error((data && (data.error_description || data.error)) || `HTTP ${res.status}`);
    return data;
  },
  get: (p) => api.req("GET", p), post: (p, b) => api.req("POST", p, b), del: (p) => api.req("DELETE", p),
};
const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const qs = (o) => Object.entries(o).filter(([,v]) => v !== undefined && v !== null && v !== "").map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
let ME = null;
let tailTimer = null;

function toast(msg, kind = "ok") { const t = $("#toast"); t.textContent = msg; t.className = `toast show ${kind}`; setTimeout(() => { t.className = "toast"; }, 3200); }
function can(perm) { const [rr, ra] = perm.split(":"); return (ME?.permissions || []).some((g) => { const [gr, ga] = g.split(":"); return (gr === "*" || gr === rr) && (ga === "*" || ga === ra); }); }

async function boot() { try { ME = await api.get("/auth/me"); showApp(); } catch (_) { showLogin(); } }
function showLogin() { $("#app-view").classList.add("hidden"); $("#login-view").classList.remove("hidden"); }
function showApp() { $("#login-view").classList.add("hidden"); $("#app-view").classList.remove("hidden"); $("#who").innerHTML = `<b>${esc(ME.email)}</b><br><span class="tag">${esc(ME.role)}</span>`; navigate("overview"); }

$("#login-form").addEventListener("submit", async (e) => { e.preventDefault(); $("#login-error").textContent = ""; try { const r = await api.post("/auth/login", { email: $("#login-email").value.trim(), password: $("#login-password").value }); ME = r.user; showApp(); } catch (err) { $("#login-error").textContent = err.message; } });
$("#logout").addEventListener("click", async () => { try { await api.post("/auth/logout", {}); } catch (_) {} ME = null; showLogin(); });

document.querySelectorAll(".nav-item").forEach((n) => n.addEventListener("click", () => navigate(n.dataset.view)));
const TITLES = { overview: "Overview", logs: "Logs", metrics: "Metrics", traces: "Traces", alerts: "Alerts", settings: "Settings" };
function navigate(view) { if (tailTimer) { clearInterval(tailTimer); tailTimer = null; } document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === view)); $("#view-title").textContent = TITLES[view] || view; const root = $("#view-root"); root.innerHTML = `<div class="muted">Loading?</div>`; ({ overview:viewOverview, logs:viewLogs, metrics:viewMetrics, traces:viewTraces, alerts:viewAlerts, settings:viewSettings }[view] || viewOverview)(root).catch((e) => { root.innerHTML = `<div class="panel"><h2>Error</h2><p class="error">${esc(e.message)}</p></div>`; }); }

async function viewOverview(root) {
  const [stats, alerts] = await Promise.all([api.get("/v1/stats"), api.get("/v1/alerts?limit=5").catch(() => ({alerts:[]}))]);
  const s = stats.stats;
  root.innerHTML = `<div class="cards">
    <div class="stat"><div class="num">${s.logs}</div><div class="lbl">Logs</div></div>
    <div class="stat"><div class="num">${s.metrics}</div><div class="lbl">Metric points</div></div>
    <div class="stat"><div class="num">${s.spans}</div><div class="lbl">Spans</div></div>
    <div class="stat"><div class="num">${s.ingest_events_last_hour}</div><div class="lbl">Ingest last hour</div></div>
    <div class="stat"><div class="num">${s.active_alerts}</div><div class="lbl">Active alerts</div></div>
    <div class="stat"><div class="num">${s.services}</div><div class="lbl">Services</div></div>
  </div><div class="panel"><div class="panel-head"><h2>Recent alerts</h2><button id="refresh-overview" class="btn ghost sm">Refresh</button></div>${alertsTable(alerts.alerts)}</div>`;
  $("#refresh-overview").addEventListener("click", () => viewOverview(root));
}

async function viewLogs(root) {
  if (!can("logs:read")) return denied(root);
  root.innerHTML = `<div class="panel"><h2>Search logs</h2><div class="form-row">
    <input id="log-q" placeholder="search message tokens" /><input id="log-service" placeholder="service" />
    <select id="log-level"><option value="">any level</option><option>INFO</option><option>WARN</option><option>ERROR</option><option>DEBUG</option></select>
    <input id="log-since" placeholder="since RFC3339 (optional)" />
    <button id="log-search" class="btn primary">Search</button><button id="log-tail" class="btn ghost">Tail</button>
  </div></div><div class="panel"><div class="panel-head"><h2>Results</h2><span id="log-count" class="muted"></span></div><div id="log-results"></div></div>`;
  const run = async () => { const p = qs({ q: $("#log-q").value, service: $("#log-service").value, level: $("#log-level").value, since: $("#log-since").value, limit: 100 }); const {logs} = await api.get(`/v1/logs?${p}`); $("#log-count").textContent = `${logs.length} rows`; $("#log-results").innerHTML = logsTable(logs); };
  $("#log-search").addEventListener("click", () => run().catch(e => toast(e.message, "err")));
  $("#log-tail").addEventListener("click", () => { if (tailTimer) { clearInterval(tailTimer); tailTimer = null; toast("Tail stopped"); } else { run(); tailTimer = setInterval(run, 3000); toast("Tail started"); } });
  await run();
}
function logsTable(logs) { return `<table><thead><tr><th>Time</th><th>Level</th><th>Service</th><th>Message</th></tr></thead><tbody>${logs.map((l) => `<tr><td class="mono muted small">${esc(l.timestamp)}</td><td><span class="tag">${esc(l.level)}</span></td><td>${esc(l.service)}</td><td>${esc(l.message)}<br><span class="muted mono small">${esc(l.attributes)}</span></td></tr>`).join("")}</tbody></table>`; }

async function viewMetrics(root) {
  if (!can("metrics:read")) return denied(root);
  const {names} = await api.get("/v1/metrics/names");
  root.innerHTML = `<div class="panel"><h2>Metric explorer</h2><div class="form-row"><select id="metric-name">${names.map(n => `<option>${esc(n)}</option>`).join("")}</select><input id="metric-since" placeholder="since RFC3339 (optional)" /><button id="metric-load" class="btn primary">Load</button></div></div><div id="metric-body"></div>`;
  const load = async () => { const name = $("#metric-name").value; if (!name) { $("#metric-body").innerHTML = `<div class="panel muted">No metrics yet.</div>`; return; } const [summary, series] = await Promise.all([api.get(`/v1/metrics/summary?${qs({name})}`), api.get(`/v1/metrics/series?${qs({name, since: $("#metric-since").value})}`)]); renderMetric(name, summary.summary, series.series); };
  $("#metric-load").addEventListener("click", () => load().catch(e => toast(e.message, "err")));
  await load();
}
function renderMetric(name, s, series) { $("#metric-body").innerHTML = `<div class="cards"><div class="stat"><div class="num">${s?.count ?? 0}</div><div class="lbl">Count</div></div><div class="stat"><div class="num">${fmt(s?.avg)}</div><div class="lbl">Avg</div></div><div class="stat"><div class="num">${fmt(s?.p50)}</div><div class="lbl">p50</div></div><div class="stat"><div class="num">${fmt(s?.p90)}</div><div class="lbl">p90</div></div><div class="stat"><div class="num">${fmt(s?.p95)}</div><div class="lbl">p95</div></div><div class="stat"><div class="num">${fmt(s?.p99)}</div><div class="lbl">p99</div></div></div><div class="panel"><div class="panel-head"><h2>${esc(name)}</h2><span class="muted">${series.length} points</span></div>${sparkline(series.map(x => x.value))}<table><thead><tr><th>Time</th><th>Value</th><th>Tags</th></tr></thead><tbody>${series.slice(-30).reverse().map(x => `<tr><td class="mono muted small">${esc(x.timestamp)}</td><td>${fmt(x.value)}</td><td class="mono muted small">${esc(x.tags)}</td></tr>`).join("")}</tbody></table></div>`; }
function sparkline(vals) { if (!vals.length) return `<div class="muted">No points</div>`; const min = Math.min(...vals), max = Math.max(...vals), span = (max - min) || 1; const pts = vals.map((v,i) => `${(i / Math.max(vals.length - 1, 1)) * 100},${80 - ((v - min) / span) * 70}`).join(" "); return `<svg class="spark" viewBox="0 0 100 90" preserveAspectRatio="none"><polyline fill="none" stroke="#12d9a5" stroke-width="2" points="${pts}"></polyline></svg>`; }
function fmt(v) { return Number.isFinite(v) ? Number(v).toFixed(2) : "?"; }

async function viewTraces(root) {
  if (!can("traces:read")) return denied(root);
  const {traces} = await api.get("/v1/traces?limit=50");
  root.innerHTML = `<div class="panel"><div class="panel-head"><h2>Recent traces</h2><button id="tr-refresh" class="btn ghost sm">Refresh</button></div><table><thead><tr><th>Trace</th><th>Service</th><th>Spans</th><th>Duration</th><th>Status</th></tr></thead><tbody>${traces.map(t => `<tr data-trace="${esc(t.trace_id)}"><td class="mono">${esc(t.trace_id)}</td><td>${esc(t.service)}</td><td>${t.span_count}</td><td>${fmt(t.duration_ms)} ms</td><td>${esc(t.status || "OK")}</td></tr>`).join("")}</tbody></table></div><div id="trace-detail"></div>`;
  $("#tr-refresh").addEventListener("click", () => viewTraces(root));
  root.querySelectorAll("[data-trace]").forEach(r => r.addEventListener("click", async () => renderTrace(r.dataset.trace)));
}
async function renderTrace(id) { const {spans} = await api.get(`/v1/traces/${encodeURIComponent(id)}`); const min = Math.min(...spans.map(s => Date.parse(s.start_time))); const maxDur = Math.max(...spans.map(s => s.duration_ms), 1); $("#trace-detail").innerHTML = `<div class="panel"><h2>Trace ${esc(id)}</h2><table><thead><tr><th>Span</th><th>Service</th><th>Waterfall</th><th>Duration</th></tr></thead><tbody>${spans.map(s => { const off = ((Date.parse(s.start_time) - min) / Math.max(maxDur, 1)) * 100; const w = Math.max((s.duration_ms / maxDur) * 100, 2); return `<tr><td>${esc(s.name)}<br><span class="mono muted small">${esc(s.span_id)}</span></td><td>${esc(s.service)}</td><td><div class="bar-wrap"><div class="bar" style="left:${Math.min(off,95)}%;width:${Math.min(w,100)}%"></div></div></td><td>${fmt(s.duration_ms)} ms</td></tr>`; }).join("")}</tbody></table></div>`; }

async function viewAlerts(root) {
  if (!can("alerts:read")) return denied(root);
  const [rules, alerts] = await Promise.all([api.get("/v1/alerts/rules"), api.get("/v1/alerts?limit=100")]);
  root.innerHTML = `${can("alerts:create") ? `<div class="panel"><h2>Create alert rule</h2><div class="form-row"><input id="ar-name" placeholder="name" /><select id="ar-kind"><option value="error_log_count">error log count &gt; N</option><option value="metric_p99">metric p99 &gt; threshold</option></select><input id="ar-target" placeholder="service or metric name (blank = all errors)" /><input id="ar-threshold" type="number" placeholder="threshold" /><input id="ar-window" type="number" placeholder="window seconds" value="300" /><button id="ar-create" class="btn primary">Create</button></div></div>` : ""}<div class="panel"><h2>Rules</h2>${rulesTable(rules.rules)}</div><div class="panel"><h2>Fired alerts</h2>${alertsTable(alerts.alerts)}</div>`;
  if (can("alerts:create")) $("#ar-create").addEventListener("click", async () => { try { await api.post("/v1/alerts/rules", { name: $("#ar-name").value, kind: $("#ar-kind").value, target: $("#ar-target").value, threshold: Number($("#ar-threshold").value), window_secs: Number($("#ar-window").value) }); toast("Rule created"); viewAlerts(root); } catch(e) { toast(e.message, "err"); } });
  root.querySelectorAll("[data-del-rule]").forEach(b => b.addEventListener("click", async () => { if (!confirm("Delete rule?")) return; await api.del(`/v1/alerts/rules/${b.dataset.delRule}`); toast("Rule deleted"); viewAlerts(root); }));
}
function rulesTable(rules) { return `<table><thead><tr><th>Name</th><th>Kind</th><th>Target</th><th>Threshold</th><th></th></tr></thead><tbody>${rules.map(r => `<tr><td>${esc(r.name)}</td><td><span class="tag">${esc(r.kind)}</span></td><td>${esc(r.target || "*")}</td><td>${fmt(r.threshold)} / ${r.window_secs}s</td><td>${can("alerts:delete") ? `<button class="btn danger sm" data-del-rule="${esc(r.id)}">Delete</button>` : ""}</td></tr>`).join("")}</tbody></table>`; }
function alertsTable(alerts) { if (!alerts.length) return `<p class="muted">No alerts fired.</p>`; return `<table><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Message</th></tr></thead><tbody>${alerts.map(a => `<tr><td class="mono muted small">${esc(a.fired_at)}</td><td><span class="tag">${esc(a.severity)}</span></td><td>${esc(a.rule_name)}</td><td>${esc(a.message)}</td></tr>`).join("")}</tbody></table>`; }

async function viewSettings(root) {
  if (!can("keys:read")) return denied(root);
  const {keys} = await api.get("/v1/keys");
  root.innerHTML = `${can("keys:create") ? `<div class="panel"><h2>Create ingest API key</h2><div class="form-row tight"><input id="key-name" placeholder="name" value="agent" /><button id="key-create" class="btn primary">Create key</button></div><div id="key-result"></div></div>` : ""}<div class="panel"><h2>Ingest keys</h2><table><thead><tr><th>Name</th><th>Prefix</th><th>Created</th><th>Last used</th><th>Status</th><th></th></tr></thead><tbody>${keys.map(k => `<tr><td>${esc(k.name)}</td><td class="mono">${esc(k.prefix)}</td><td class="mono muted small">${esc(k.created_at)}</td><td class="mono muted small">${esc(k.last_used_at || "never")}</td><td>${k.revoked_at ? `<span class="pill-danger">revoked</span>` : `<span class="pill-ok">active</span>`}</td><td>${can("keys:delete") && !k.revoked_at ? `<button class="btn danger sm" data-revoke="${esc(k.id)}">Revoke</button>` : ""}</td></tr>`).join("")}</tbody></table></div>`;
  if (can("keys:create")) $("#key-create").addEventListener("click", async () => { try { const r = await api.post("/v1/keys", { name: $("#key-name").value }); $("#key-result").innerHTML = `<div class="codebox">${esc(r.token)}\n\n${esc(r.note)}</div>`; toast("Key created"); } catch(e) { toast(e.message, "err"); } });
  root.querySelectorAll("[data-revoke]").forEach(b => b.addEventListener("click", async () => { if (!confirm("Revoke this key?")) return; await api.del(`/v1/keys/${b.dataset.revoke}`); toast("Key revoked"); viewSettings(root); }));
}
function denied(root) { root.innerHTML = `<div class="panel"><h2>Access denied</h2><p class="muted">Your role does not grant access to this section.</p></div>`; }

boot();
