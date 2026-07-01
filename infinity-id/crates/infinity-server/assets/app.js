"use strict";

// ---------------------------------------------------------------------------
// Tiny API helper
// ---------------------------------------------------------------------------
const api = {
  async req(method, path, body) {
    const opts = { method, headers: {}, credentials: "same-origin" };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = { raw: text }; }
    if (!res.ok) {
      const msg = (data && (data.error_description || data.error)) || `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return data;
  },
  get: (p) => api.req("GET", p),
  post: (p, b) => api.req("POST", p, b),
  patch: (p, b) => api.req("PATCH", p, b),
  del: (p) => api.req("DELETE", p),
  put: (p, b) => api.req("PUT", p, b),
};

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------
const $ = (sel) => document.querySelector(sel);
const el = (html) => { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstChild; };
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function toast(msg, kind = "ok") {
  const t = $("#toast");
  t.textContent = msg;
  t.className = `toast show ${kind}`;
  setTimeout(() => { t.className = "toast"; }, 3200);
}

let ME = null;
const can = (perm) => {
  if (!ME) return false;
  const [rr, ra] = perm.split(":");
  return (ME.permissions || []).some((g) => {
    const [gr, ga] = g.split(":");
    return (gr === "*" || gr === rr) && (ga === "*" || ga === ra);
  });
};

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
async function boot() {
  try {
    ME = await api.get("/auth/me");
    showApp();
  } catch (_) {
    showLogin();
  }
}

function showLogin() {
  $("#app-view").classList.add("hidden");
  $("#login-view").classList.remove("hidden");
}

function showApp() {
  $("#login-view").classList.add("hidden");
  $("#app-view").classList.remove("hidden");
  $("#who").innerHTML = `<b>${esc(ME.username)}</b><br>${esc(ME.email)}<br>${(ME.roles || []).map((r) => `<span class="tag">${esc(r)}</span>`).join("")}`;
  navigate("overview");
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-error").textContent = "";
  try {
    const r = await api.post("/auth/login", {
      email: $("#login-email").value.trim(),
      password: $("#login-password").value,
      otp: $("#login-otp").value.trim() || null,
    });
    ME = r.user;
    showApp();
  } catch (err) {
    $("#login-error").textContent = err.message;
  }
});

$("#logout").addEventListener("click", async () => {
  try { await api.post("/auth/logout", {}); } catch (_) {}
  ME = null;
  showLogin();
});

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
const TITLES = { overview: "Overview", users: "Users", clients: "Applications", roles: "Roles", audit: "Audit log", security: "My security" };

document.querySelectorAll(".nav-item").forEach((n) =>
  n.addEventListener("click", () => navigate(n.dataset.view))
);

function navigate(view) {
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === view));
  $("#view-title").textContent = TITLES[view] || view;
  const root = $("#view-root");
  root.innerHTML = `<div class="muted">Loading…</div>`;
  ({ overview: viewOverview, users: viewUsers, clients: viewClients, roles: viewRoles, audit: viewAudit, security: viewSecurity }[view] || viewOverview)(root);
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------
async function viewOverview(root) {
  let users = [], clients = [], roles = [];
  try { if (can("users:read")) users = (await api.get("/admin/users")).users; } catch (_) {}
  try { if (can("clients:read")) clients = (await api.get("/admin/clients")).clients; } catch (_) {}
  try { if (can("roles:read")) roles = (await api.get("/admin/roles")).roles; } catch (_) {}
  const mfaOn = users.filter((u) => u.mfa_enabled).length;
  root.innerHTML = `
    <div class="cards">
      <div class="stat"><div class="num">${users.length}</div><div class="lbl">Users</div></div>
      <div class="stat"><div class="num">${clients.length}</div><div class="lbl">Applications</div></div>
      <div class="stat"><div class="num">${roles.length}</div><div class="lbl">Roles</div></div>
      <div class="stat"><div class="num">${mfaOn}</div><div class="lbl">Users with MFA</div></div>
    </div>
    <div class="panel">
      <h2>Welcome to Infinity ID</h2>
      <p class="muted">A secure-by-design identity provider written in Rust — OIDC/OAuth2, TOTP MFA, and RBAC in a single fast binary. Use the navigation to manage users, applications and roles. Endpoints:</p>
      <div class="codebox">GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json
POST /oauth/token
GET  /oauth/authorize
GET  /userinfo</div>
    </div>`;
}

async function viewUsers(root) {
  if (!can("users:read")) return denied(root);
  const { users } = await api.get("/admin/users");
  const rolesResp = can("roles:read") ? await api.get("/admin/roles").catch(() => ({ roles: [] })) : { roles: [] };
  const allRoles = rolesResp.roles.map((r) => r.name);

  root.innerHTML = `
    ${can("users:create") ? `<div class="panel">
      <h2>Create user</h2>
      <div class="form-row">
        <input id="nu-email" placeholder="email" />
        <input id="nu-username" placeholder="username" />
        <input id="nu-name" placeholder="display name" />
        <input id="nu-pass" type="password" placeholder="password (min 8)" />
        <select id="nu-role">${allRoles.map((r) => `<option>${esc(r)}</option>`).join("")}</select>
        <button id="nu-create" class="btn primary">Add user</button>
      </div>
    </div>` : ""}
    <div class="panel">
      <div class="panel-head"><h2>Users</h2><span class="muted">${users.length} total</span></div>
      <table><thead><tr><th>User</th><th>Roles</th><th>MFA</th><th>Status</th><th></th></tr></thead>
      <tbody>${users.map(userRow).join("")}</tbody></table>
    </div>`;

  if (can("users:create")) $("#nu-create").addEventListener("click", async () => {
    try {
      await api.post("/admin/users", {
        email: $("#nu-email").value.trim(),
        username: $("#nu-username").value.trim(),
        display_name: $("#nu-name").value.trim() || null,
        password: $("#nu-pass").value,
        roles: [$("#nu-role").value],
      });
      toast("User created");
      viewUsers(root);
    } catch (e) { toast(e.message, "err"); }
  });

  root.querySelectorAll("[data-toggle]").forEach((b) => b.addEventListener("click", async () => {
    try { await api.patch(`/admin/users/${b.dataset.toggle}`, { disabled: b.dataset.disabled === "false" }); toast("Updated"); viewUsers(root); }
    catch (e) { toast(e.message, "err"); }
  }));
  root.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
    if (!confirm("Delete this user?")) return;
    try { await api.del(`/admin/users/${b.dataset.del}`); toast("User deleted"); viewUsers(root); }
    catch (e) { toast(e.message, "err"); }
  }));
}

function userRow(u) {
  const roles = (u.roles || []).map((r) => `<span class="tag">${esc(r)}</span>`).join("") || "—";
  const mfa = u.mfa_enabled ? `<span class="pill-ok">● on</span>` : `<span class="pill-off">○ off</span>`;
  const status = u.disabled ? `<span class="pill-danger">disabled</span>` : `<span class="pill-ok">active</span>`;
  const actions = [];
  if (can("users:update")) actions.push(`<button class="btn ghost sm" data-toggle="${u.id}" data-disabled="${u.disabled}">${u.disabled ? "Enable" : "Disable"}</button>`);
  if (can("users:delete")) actions.push(`<button class="btn danger sm" data-del="${u.id}">Delete</button>`);
  return `<tr>
    <td><b>${esc(u.username)}</b><br><span class="muted">${esc(u.email)}</span></td>
    <td>${roles}</td><td>${mfa}</td><td>${status}</td>
    <td style="text-align:right">${actions.join(" ")}</td></tr>`;
}

async function viewClients(root) {
  if (!can("clients:read")) return denied(root);
  const { clients } = await api.get("/admin/clients");
  root.innerHTML = `
    ${can("clients:create") ? `<div class="panel">
      <h2>Register application</h2>
      <div class="form-row">
        <input id="nc-name" placeholder="App name" />
        <input id="nc-redirect" placeholder="redirect URI (comma separated)" />
        <input id="nc-scopes" placeholder="scopes (space separated)" value="openid profile email" />
        <label class="chk"><input type="checkbox" id="nc-public" /> Public (SPA/native, PKCE)</label>
        <button id="nc-create" class="btn primary">Create</button>
      </div>
      <div id="nc-result"></div>
    </div>` : ""}
    <div class="panel">
      <div class="panel-head"><h2>Applications</h2><span class="muted">${clients.length} total</span></div>
      <table><thead><tr><th>Name</th><th>Client ID</th><th>Type</th><th>Grants</th><th></th></tr></thead>
      <tbody>${clients.map(clientRow).join("")}</tbody></table>
    </div>`;

  if (can("clients:create")) $("#nc-create").addEventListener("click", async () => {
    try {
      const r = await api.post("/admin/clients", {
        name: $("#nc-name").value.trim(),
        redirect_uris: $("#nc-redirect").value.split(",").map((s) => s.trim()).filter(Boolean),
        scopes: $("#nc-scopes").value.split(" ").map((s) => s.trim()).filter(Boolean),
        public: $("#nc-public").checked,
      });
      $("#nc-result").innerHTML = `<div class="codebox">client_id: ${esc(r.client_id)}${r.client_secret ? `\nclient_secret: ${esc(r.client_secret)}\n\n⚠ ${esc(r.note)}` : "\n(public client — no secret)"}</div>`;
      toast("Application created");
      const list = (await api.get("/admin/clients")).clients;
      root.querySelector("tbody").innerHTML = list.map(clientRow).join("");
      bindClientDeletes(root);
    } catch (e) { toast(e.message, "err"); }
  });
  bindClientDeletes(root);
}

function clientRow(c) {
  const del = can("clients:delete") ? `<button class="btn danger sm" data-delc="${c.client_id}">Delete</button>` : "";
  return `<tr>
    <td><b>${esc(c.name)}</b></td>
    <td><span class="mono">${esc(c.client_id)}</span></td>
    <td>${c.public ? `<span class="tag">public</span>` : `<span class="tag">confidential</span>`}</td>
    <td>${(c.grant_types || []).map((g) => `<span class="tag">${esc(g)}</span>`).join("")}</td>
    <td style="text-align:right">${del}</td></tr>`;
}
function bindClientDeletes(root) {
  root.querySelectorAll("[data-delc]").forEach((b) => b.addEventListener("click", async () => {
    if (!confirm("Delete this application?")) return;
    try { await api.del(`/admin/clients/${b.dataset.delc}`); toast("Application deleted"); viewClients(root); }
    catch (e) { toast(e.message, "err"); }
  }));
}

async function viewRoles(root) {
  if (!can("roles:read")) return denied(root);
  const { roles } = await api.get("/admin/roles");
  root.innerHTML = `<div class="panel">
    <div class="panel-head"><h2>Roles &amp; permissions</h2><span class="muted">${roles.length} roles</span></div>
    <table><thead><tr><th>Role</th><th>Description</th><th>Permissions</th></tr></thead>
    <tbody>${roles.map((r) => `<tr>
      <td><b>${esc(r.name)}</b></td>
      <td class="muted">${esc(r.description)}</td>
      <td>${(r.permissions || []).map((p) => `<span class="tag">${esc(p)}</span>`).join("")}</td>
    </tr>`).join("")}</tbody></table>
  </div>`;
}

async function viewAudit(root) {
  if (!can("audit:read")) return denied(root);
  const { events } = await api.get("/admin/audit");
  root.innerHTML = `<div class="panel">
    <div class="panel-head"><h2>Audit log</h2><span class="muted">latest ${events.length}</span></div>
    <table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead>
    <tbody>${events.map((e) => `<tr>
      <td class="muted mono">${esc(e.created_at)}</td>
      <td class="mono">${esc((e.actor || "").slice(0, 8))}</td>
      <td><span class="tag">${esc(e.action)}</span></td>
      <td class="mono">${esc(e.target || "—")}</td>
      <td class="muted">${esc(e.detail || "")}</td>
    </tr>`).join("")}</tbody></table>
  </div>`;
}

async function viewSecurity(root) {
  const mfaOn = ME.mfa_enabled;
  root.innerHTML = `<div class="panel">
    <h2>Multi-factor authentication</h2>
    <p class="muted">Status: ${mfaOn ? `<span class="pill-ok">● enabled</span>` : `<span class="pill-off">○ disabled</span>`}</p>
    <div id="mfa-actions"></div>
    <div id="mfa-body"></div>
  </div>`;
  const actions = $("#mfa-actions");
  if (mfaOn) {
    actions.innerHTML = `<button id="mfa-disable" class="btn danger">Disable MFA</button>`;
    $("#mfa-disable").addEventListener("click", async () => {
      if (!confirm("Disable MFA for your account?")) return;
      try { await api.post("/mfa/disable", {}); ME.mfa_enabled = false; toast("MFA disabled"); viewSecurity(root); }
      catch (e) { toast(e.message, "err"); }
    });
  } else {
    actions.innerHTML = `<button id="mfa-enroll" class="btn primary">Set up authenticator app</button>`;
    $("#mfa-enroll").addEventListener("click", async () => {
      try {
        const r = await api.post("/mfa/enroll", {});
        $("#mfa-body").innerHTML = `
          <p class="muted" style="margin-top:16px">1. Add this secret to your authenticator (Google Authenticator, 1Password, Authy):</p>
          <div class="codebox">${esc(r.secret)}</div>
          <p class="muted">otpauth URI:</p>
          <div class="codebox">${esc(r.otpauth_uri)}</div>
          <p class="muted">2. Save these one-time recovery codes somewhere safe:</p>
          <div class="rec-codes">${r.recovery_codes.map((c) => `<span class="mono">${esc(c)}</span>`).join("")}</div>
          <p class="muted" style="margin-top:16px">3. Enter the current 6-digit code to activate:</p>
          <div class="form-row" style="max-width:320px">
            <input id="mfa-code" placeholder="123456" inputmode="numeric" />
            <button id="mfa-activate" class="btn primary">Activate</button>
          </div>`;
        $("#mfa-activate").addEventListener("click", async () => {
          try { await api.post("/mfa/activate", { code: $("#mfa-code").value.trim() }); ME.mfa_enabled = true; toast("MFA enabled"); viewSecurity(root); }
          catch (e) { toast(e.message, "err"); }
        });
      } catch (e) { toast(e.message, "err"); }
    });
  }
}

function denied(root) {
  root.innerHTML = `<div class="panel"><h2>Access denied</h2><p class="muted">Your role does not grant access to this section.</p></div>`;
}

boot();
