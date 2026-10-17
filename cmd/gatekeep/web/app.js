// Demo OIDC client: authorization code flow + PKCE, then calls through the proxy.
(() => {
  "use strict";
  const BASE = location.origin + location.pathname.replace(/[^/]*$/, "");
  const ISSUER = BASE + "idp";
  const CLIENT_ID = "demo-web";
  const REDIRECT = BASE;
  const $ = (id) => document.getElementById(id);

  // ---------- small helpers ----------
  const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const randomString = () => b64url(crypto.getRandomValues(new Uint8Array(32)));
  async function challengeFor(verifier) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return b64url(new Uint8Array(digest));
  }
  function decodePart(part) {
    const s = part.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(decodeURIComponent(escape(atob(s + "===".slice((s.length + 3) % 4)))));
  }
  const decode = (jwt) => ({ header: decodePart(jwt.split(".")[0]), claims: decodePart(jwt.split(".")[1]) });

  // Tokens live in sessionStorage so a reload keeps the demo going; a real
  // app would keep them in memory or behind a backend-for-frontend.
  const store = {
    get: () => JSON.parse(sessionStorage.getItem("gk.tokens") || "null"),
    set: (t) => sessionStorage.setItem("gk.tokens", JSON.stringify(t)),
    clear: () => sessionStorage.removeItem("gk.tokens"),
  };

  // ---------- activity log (textContent only: never inject server data as HTML) ----------
  function log(title, status, body, note) {
    $("empty").hidden = true;
    const li = document.createElement("li");
    li.className = status >= 200 && status < 300 ? "ok" : "bad";
    const head = document.createElement("div");
    head.className = "title";
    const badge = document.createElement("span");
    badge.className = "status";
    badge.textContent = status;
    const t = document.createElement("b");
    t.textContent = title;
    head.append(badge, t);
    li.append(head);
    if (note) {
      const p = document.createElement("p");
      p.className = "note";
      p.textContent = note;
      li.append(p);
    }
    if (body !== undefined && body !== "") {
      const pre = document.createElement("pre");
      pre.textContent = typeof body === "string" ? body : JSON.stringify(body, null, 2);
      li.append(pre);
    }
    $("log").prepend(li);
  }

  async function readBody(res) {
    const text = await res.text();
    try { return JSON.parse(text); } catch { return text; }
  }

  async function tokenRequest(params) {
    const res = await fetch(ISSUER + "/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: CLIENT_ID, ...params }),
    });
    return { res, body: await readBody(res) };
  }

  // ---------- sign in ----------
  async function login() {
    const verifier = randomString();
    const state = randomString();
    const nonce = randomString();
    sessionStorage.setItem("gk.pkce", JSON.stringify({ verifier, state, nonce }));
    const q = new URLSearchParams({
      response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT, scope: "openid profile email",
      state, nonce, code_challenge: await challengeFor(verifier), code_challenge_method: "S256",
    });
    location.assign(ISSUER + "/authorize?" + q);
  }

  async function finishLogin(params) {
    history.replaceState(null, "", location.pathname); // keep the code out of history and screenshots
    const saved = JSON.parse(sessionStorage.getItem("gk.pkce") || "null");
    sessionStorage.removeItem("gk.pkce");
    if (params.get("error")) return log("Sign-in failed", 400, params.get("error"));
    if (!saved || params.get("state") !== saved.state) return log("Sign-in rejected", 400, "state mismatch (possible CSRF)");
    if (params.get("iss") !== ISSUER) return log("Sign-in rejected", 400, "unexpected issuer (possible mix-up attack)");

    const { res, body } = await tokenRequest({
      grant_type: "authorization_code", code: params.get("code"), redirect_uri: REDIRECT, code_verifier: saved.verifier,
    });
    if (!res.ok) return log("Code exchange failed", res.status, body);
    if (decode(body.id_token).claims.nonce !== saved.nonce) return log("Sign-in rejected", 400, "nonce mismatch");
    store.set({ access: body.access_token, refresh: body.refresh_token, id: body.id_token, oldRefresh: null });
    log("Signed in: code exchanged with PKCE", res.status, { token_type: body.token_type, expires_in: body.expires_in, scope: body.scope });
    render();
  }

  // ---------- API calls through the proxy ----------
  async function callAPI(path, token, title, extraHeaders = {}) {
    const headers = { ...extraHeaders };
    if (token) headers.Authorization = "Bearer " + token;
    const res = await fetch(BASE + "api/" + path, { headers });
    const body = await readBody(res);
    const www = res.headers.get("WWW-Authenticate");
    log(title, res.status, body, www ? "WWW-Authenticate: " + www : "");
    return res;
  }

  function tampered(jwt) {
    const [h, p, s] = jwt.split(".");
    const claims = decodePart(p);
    claims.roles = ["user", "admin"]; // try to grant ourselves admin
    const forged = b64url(new TextEncoder().encode(JSON.stringify(claims)));
    return [h, forged, s].join(".");
  }

  function algNone(jwt) {
    const p = jwt.split(".")[1];
    const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "none", typ: "JWT" })));
    return header + "." + p + ".x";
  }

  const calls = {
    hello: (t) => callAPI("hello", t.access, "GET /api/hello"),
    admin: (t) => callAPI("admin", t.access, "GET /api/admin"),
    none: () => callAPI("hello", null, "GET /api/hello without a token"),
    tamper: (t) => callAPI("admin", tampered(t.access), "Edited the token to add the admin role"),
    algnone: (t) => callAPI("hello", algNone(t.access), 'Token re-signed with alg "none"'),
    spoof: (t) => callAPI("hello", t.access, "Sent X-Auth-User: bob as a header", { "X-Auth-User": "bob", "X-Auth-Roles": "admin" }),
  };

  // ---------- lifecycle ----------
  async function refresh() {
    const t = store.get();
    const { res, body } = await tokenRequest({ grant_type: "refresh_token", refresh_token: t.refresh });
    if (!res.ok) return log("Refresh failed", res.status, body);
    store.set({ ...t, access: body.access_token, refresh: body.refresh_token, oldRefresh: t.refresh });
    log("Refreshed: new access token and a new refresh token", res.status, { expires_in: body.expires_in },
      "The refresh token you just used is now spent. Try replaying it.");
    render();
  }

  async function replay() {
    const t = store.get();
    if (!t.oldRefresh) return log("Nothing to replay yet", 400, "", "Press “Refresh tokens” first, then replay the old one.");
    const first = await tokenRequest({ grant_type: "refresh_token", refresh_token: t.oldRefresh });
    log("Replayed an already-used refresh token", first.res.status, first.body);
    const second = await tokenRequest({ grant_type: "refresh_token", refresh_token: t.refresh });
    log("Then tried the current refresh token", second.res.status, second.body,
      "Reuse detection revoked the whole session, including tokens the real user still held.");
    setTimeout(() => callAPI("hello", t.access, "Access token after the session was revoked"), 3500);
  }

  async function rotate() {
    const res = await fetch(BASE + "demo/rotate", { method: "POST" });
    const body = await readBody(res);
    log("Rotated the signing key", res.status, body,
      res.ok ? "New tokens get the new key. Your current token still verifies: its key stays in the JWKS for the grace period." : "");
    if (res.ok) await calls.hello(store.get());
  }

  async function revokeAccess() {
    const t = store.get();
    const res = await fetch(ISSUER + "/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: CLIENT_ID, token: t.access }),
    });
    log("Revoked the access token (RFC 7009)", res.status, "", "The proxy pulls the revocation list every 3 seconds. Calling the API again in 3.5 s…");
    setTimeout(() => callAPI("hello", t.access, "GET /api/hello with the revoked token"), 3500);
  }

  function logout() {
    const t = store.get();
    if (t) {
      fetch(ISSUER + "/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: CLIENT_ID, token: t.refresh }),
      });
    }
    store.clear();
    log("Signed out; refresh token revoked", 200, "");
    render();
  }

  // ---------- view ----------
  let timer;
  function render() {
    const t = store.get();
    $("signed-out").hidden = !!t;
    $("signed-in").hidden = !t;
    $("api").hidden = !t;
    $("life").hidden = !t;
    clearInterval(timer);
    if (!t) return;
    const { header, claims } = decode(t.access);
    $("who-name").textContent = claims.name + " (" + claims.sub + ")";
    $("who-roles").textContent = (claims.roles || []).join(", ");
    $("kid").textContent = header.kid;
    $("claims").textContent = JSON.stringify({ header, claims }, null, 2);
    const tick = () => {
      const left = claims.exp - Math.floor(Date.now() / 1000);
      $("ttl").textContent = left > 0 ? Math.floor(left / 60) + "m " + (left % 60) + "s" : "expired: press Refresh";
    };
    tick();
    timer = setInterval(tick, 1000);
  }

  // ---------- wiring ----------
  $("login").addEventListener("click", login);
  $("logout").addEventListener("click", logout);
  $("refresh").addEventListener("click", refresh);
  $("replay").addEventListener("click", replay);
  $("rotate").addEventListener("click", rotate);
  $("revoke").addEventListener("click", revokeAccess);
  document.querySelectorAll("[data-call]").forEach((b) =>
    b.addEventListener("click", () => calls[b.dataset.call](store.get())));

  const params = new URLSearchParams(location.search);
  if (params.has("code") || params.has("error")) finishLogin(params);
  else render();
})();
