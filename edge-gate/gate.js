// The team sign-in as a Cloudflare Worker, for a static team site: copy this file into the site.
// The contract is in Sustenaut/auth's README ("A Worker gate for static sites"). The check is
// access_check.py's, at the edge. No dependencies, and no timers: it asks Keycloak only because a
// request arrived, so a site nobody is using asks nothing.
//
//   import { gate } from "./gate.js";
//   export default gate({ role: "pub" });
//
// Environment: REALM_URL and CLIENT_ID as plain variables, CLIENT_SECRET and SESSION_KEY (at least
// 32 characters) as Worker secrets, and the site's files as the assets binding ASSETS with
// run_worker_first, so nothing is served without passing here. Missing any of them fails closed.
//
// The session is a cookie encrypted with AES-GCM, so a forged or altered one is refused and the
// refresh token in it stays unreadable to the browser. It holds the hash and roles of the last full
// check, so a Worker keeps nothing about anyone between requests.

const HASH_TTL_MS = 2000;
const FULL_EVERY_MS = 5 * 60 * 1000;
const SESSION_MAX_MS = 7 * 24 * 3600 * 1000;
const FLOW_MAX_MS = 10 * 60 * 1000;
const JWKS_TTL_MS = 3600 * 1000;
const TIMEOUT_MS = 3000;
const SESSION_COOKIE = "__Host-sustenaut-gate";
const FLOW_COOKIE = "__Host-sustenaut-gate-flow";
const LAST_HASH_KEY = "https://gate.invalid/last-hash";

const bytes = (text) => new TextEncoder().encode(text);
const b64url = (data) => btoa(String.fromCharCode(...new Uint8Array(data))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
const unb64url = (text) => Uint8Array.from(atob(text.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
const random = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));

async function aesKey(secret) {
  return crypto.subtle.importKey("raw", await crypto.subtle.digest("SHA-256", bytes(secret)), "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function seal(value, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(secret), bytes(JSON.stringify(value)));
  return `${b64url(iv)}.${b64url(sealed)}`;
}

async function unseal(text, secret) {
  try {
    const [iv, sealed] = text.split(".");
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64url(iv) }, await aesKey(secret), unb64url(sealed));
    return JSON.parse(new TextDecoder().decode(plain));
  } catch {
    return null; // forged, altered, or made with another key
  }
}

function cookies(request) {
  const out = {};
  for (const part of (request.headers.get("Cookie") || "").split(";")) {
    const at = part.indexOf("=");
    if (at > 0) out[part.slice(0, at).trim()] = part.slice(at + 1).trim();
  }
  return out;
}

const setCookie = (name, value, maxSeconds) =>
  `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.max(0, Math.floor(maxSeconds))}`;
const clearCookie = (name) => setCookie(name, "", 0);

/** A path on this site to come back to; anything else is the home page (no open redirect). */
function safePath(path) {
  return typeof path === "string" && /^\/(?![/\\])/.test(path) && !/[\r\n]/.test(path) ? path : "/";
}

function page(status, title, text, headers = {}) {
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  return new Response(
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)}</title><body style="font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem"><h1 style="font-size:1.4rem">${esc(title)}</h1><p>${esc(text)}</p><p><a href="/oauth2/sign_out">Sign out</a></p>`,
    { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...headers } });
}

function redirect(location, setCookies = []) {
  const response = new Response(null, { status: 303, headers: { Location: location, "Cache-Control": "no-store" } });
  for (const cookie of setCookies) response.headers.append("Set-Cookie", cookie);
  return response;
}

/**
 * Makes the fetch handler. options: role (required); handler, the site's own answer to a request that
 * has passed the check, (request, env, person) with person { email, roles, reading }, where reading says
 * Keycloak could not be reached, and null to serve the file from ASSETS; headers, a function from a path to
 * headers to set on what is served there; and for tests fetch, now, cache.
 */
export function gate(options) {
  if (!options || !options.role) throw new Error("gate: a role is required");
  const now = options.now || (() => Date.now());
  const httpFetch = options.fetch || ((...args) => fetch(...args));
  const cache = "cache" in options ? options.cache : (typeof caches === "undefined" ? null : caches.default);
  let known = null; // the last hash Keycloak gave, in this isolate
  let fetched = null;
  let jwks = null;

  const ask = (url, init = {}) => httpFetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS), redirect: "manual" });
  const basic = (env) => `Basic ${btoa(`${encodeURIComponent(env.CLIENT_ID)}:${encodeURIComponent(env.CLIENT_SECRET)}`)}`;

  /** The current hash, fetched at most every 2 seconds; null if Keycloak cannot say. */
  async function currentHash(env) {
    if (fetched !== null && now() - fetched < HASH_TTL_MS) return known;
    let fresh = null;
    try {
      const url = `${env.REALM_URL}/app-registration/${encodeURIComponent(env.CLIENT_ID)}/access-state`;
      const response = await ask(url, { headers: { Authorization: basic(env), Accept: "application/json" } });
      if (response.status === 200) fresh = (await response.json()).hash || null;
    } catch {
      fresh = null;
    }
    if (!fresh) {
      fetched = null;
      return null;
    }
    if (fresh !== known) await rememberHash(fresh);
    known = fresh;
    fetched = now();
    return fresh;
  }

  // A new isolate starts knowing nothing, so the last hash also goes in the colo's cache: it is
  // what a session is compared with while Keycloak is down.
  async function rememberHash(hash) {
    try {
      if (cache) await cache.put(LAST_HASH_KEY, new Response(hash, { headers: { "Cache-Control": "max-age=604800" } }));
    } catch { /* only a fallback */ }
  }

  async function lastKnownHash() {
    if (known) return known;
    try {
      const hit = cache ? await cache.match(LAST_HASH_KEY) : null;
      return hit ? await hit.text() : null;
    } catch {
      return null;
    }
  }

  async function signingKey(env, kid) {
    if (!jwks || now() - jwks.at > JWKS_TTL_MS || !jwks.keys.some((k) => k.kid === kid)) {
      const response = await ask(`${env.REALM_URL}/protocol/openid-connect/certs`, { headers: { Accept: "application/json" } });
      if (response.status !== 200) throw new Error("no signing keys");
      jwks = { at: now(), keys: (await response.json()).keys };
    }
    const jwk = jwks.keys.find((k) => k.kid === kid && k.kty === "RSA");
    if (!jwk) throw new Error("unknown signing key");
    return crypto.subtle.importKey("jwk", { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  }

  /** The claims of an ID token: RS256 by the realm's key, this realm, this client, in date; else it throws. */
  async function verifyIdToken(env, token) {
    const [head, body, signature] = (token || "").split(".");
    const header = JSON.parse(new TextDecoder().decode(unb64url(head)));
    if (header.alg !== "RS256") throw new Error("not RS256");
    const key = await signingKey(env, header.kid);
    const good = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, unb64url(signature), bytes(`${head}.${body}`));
    if (!good) throw new Error("bad signature");
    const claims = JSON.parse(new TextDecoder().decode(unb64url(body)));
    const audience = [].concat(claims.aud);
    if (claims.iss !== env.REALM_URL || !audience.includes(env.CLIENT_ID) || (claims.azp && claims.azp !== env.CLIENT_ID)
        || !(claims.exp * 1000 > now())) {
      throw new Error("claims not for this site");
    }
    return claims;
  }

  async function token(env, form) {
    return ask(`${env.REALM_URL}/protocol/openid-connect/token`, {
      method: "POST",
      headers: { Authorization: basic(env), "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams(form).toString(),
    });
  }

  /** Userinfo: the claims; false if the token is refused; null if Keycloak cannot say. */
  async function userinfo(env, accessToken) {
    const response = await ask(`${env.REALM_URL}/protocol/openid-connect/userinfo`,
      { headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" } });
    if (response.status === 200) return response.json();
    return response.status === 401 || response.status === 403 ? false : null;
  }

  async function start(request, env) {
    const url = new URL(request.url);
    const flow = { state: random(), nonce: random(), verifier: random(48), rd: safePath(url.searchParams.get("rd")), at: now() };
    const challenge = b64url(await crypto.subtle.digest("SHA-256", bytes(flow.verifier)));
    const auth = new URL(`${env.REALM_URL}/protocol/openid-connect/auth`);
    auth.search = new URLSearchParams({
      client_id: env.CLIENT_ID, response_type: "code", scope: "openid email", redirect_uri: `${url.origin}/oauth2/callback`,
      state: flow.state, nonce: flow.nonce, code_challenge: challenge, code_challenge_method: "S256",
    }).toString();
    return redirect(auth.toString(), [setCookie(FLOW_COOKIE, await seal(flow, env.SESSION_KEY), FLOW_MAX_MS / 1000)]);
  }

  async function callback(request, env) {
    const url = new URL(request.url);
    const again = () => page(400, "Sign-in did not finish", "That sign-in has expired or was already used. Open the site again to start over.",
      { "Set-Cookie": clearCookie(FLOW_COOKIE) });
    const flow = await unseal(cookies(request)[FLOW_COOKIE] || "", env.SESSION_KEY);
    if (!flow || flow.state !== url.searchParams.get("state") || now() - flow.at > FLOW_MAX_MS || !url.searchParams.get("code")) {
      return again();
    }
    let response;
    try {
      response = await token(env, { grant_type: "authorization_code", code: url.searchParams.get("code"),
        redirect_uri: `${url.origin}/oauth2/callback`, code_verifier: flow.verifier });
    } catch {
      return unavailable();
    }
    if (response.status >= 500) return unavailable();
    if (response.status !== 200) return again();
    const tokens = await response.json();
    let claims;
    try {
      claims = await verifyIdToken(env, tokens.id_token);
      if (claims.nonce !== flow.nonce) throw new Error("wrong nonce");
    } catch {
      return again();
    }
    const hash = await currentHash(env);
    let info;
    try {
      info = await userinfo(env, tokens.access_token);
    } catch {
      info = null;
    }
    if (!hash || info === null) return unavailable();
    if (info === false || info.sub !== claims.sub) return again();
    const session = { sub: claims.sub, email: claims.email || info.email || "", rt: tokens.refresh_token,
      hash, roles: rolesOf(info), checked: now(), exp: now() + SESSION_MAX_MS };
    return redirect(flow.rd, [setCookie(SESSION_COOKIE, await seal(session, env.SESSION_KEY), SESSION_MAX_MS / 1000), clearCookie(FLOW_COOKIE)]);
  }

  const rolesOf = (info) => (Array.isArray(info.access) ? info.access.filter((r) => typeof r === "string") : []);

  const unavailable = () => page(503, "Sign-in can't be reached", "The sign-in service can't be reached just now, so this can't be checked. Try again in a moment.",
    { "Retry-After": "30" });

  function signOut(env) {
    const logout = new URL(`${env.REALM_URL}/protocol/openid-connect/logout`);
    logout.search = new URLSearchParams({ client_id: env.CLIENT_ID }).toString();
    return redirect(logout.toString(), [clearCookie(SESSION_COOKIE), clearCookie(FLOW_COOKIE)]);
  }

  function signIn(request, extra = []) {
    const url = new URL(request.url);
    if (request.method !== "GET" && request.method !== "HEAD") {
      return page(401, "Sign in again", "Your sign-in has ended. Open the site again to sign in.",
        extra.length ? { "Set-Cookie": extra[0] } : {});
    }
    return redirect(`/oauth2/start?rd=${encodeURIComponent(url.pathname + url.search)}`, extra);
  }

  function decide(request, env, session, fresh, degraded = false) {
    if (!session.roles.includes(options.role)) {
      return page(403, "No access to this site", `${session.email || "This account"} doesn't have access to this site. Ask a controller to give it the role ${options.role}.`,
        fresh ? { "Set-Cookie": fresh } : {});
    }
    return serve(request, env, session, fresh, degraded);
  }

  async function serve(request, env, session, fresh, degraded) {
    const person = { email: session.email, roles: session.roles, reading: degraded };
    const answer = (options.handler && await options.handler(request, env, person)) || await env.ASSETS.fetch(request);
    const response = new Response(answer.body, answer);
    if (options.headers) {
      for (const [name, value] of Object.entries(options.headers(new URL(request.url).pathname))) response.headers.set(name, value);
    }
    // Behind a sign-in: only this browser may keep it, however the files are marked.
    const cacheControl = response.headers.get("Cache-Control");
    response.headers.set("Cache-Control", cacheControl ? cacheControl.replace(/\bpublic\b/g, "private") : "private, no-cache");
    if (fresh) response.headers.append("Set-Cookie", fresh);
    return response;
  }

  /** Keycloak cannot say: a session whose hash is the last one known keeps reading; nothing else. */
  async function onTheLastAnswer(request, env, session) {
    const last = await lastKnownHash();
    const reading = request.method === "GET" || request.method === "HEAD";
    if (!reading || (last && session.hash !== last)) return unavailable();
    return decide(request, env, session, null, true);
  }

  async function check(request, env) {
    const session = await unseal(cookies(request)[SESSION_COOKIE] || "", env.SESSION_KEY);
    if (!session || !(session.exp > now())) return signIn(request, session ? [clearCookie(SESSION_COOKIE)] : []);
    const hash = await currentHash(env);
    if (hash === null) return onTheLastAnswer(request, env, session);
    if (session.hash === hash && now() - session.checked < FULL_EVERY_MS) return decide(request, env, session, null);

    // The hash asked for before the full check: a change between the two is seen next time.
    let response;
    try {
      response = await token(env, { grant_type: "refresh_token", refresh_token: session.rt });
    } catch {
      return onTheLastAnswer(request, env, session);
    }
    if (response.status === 400 || response.status === 401) return signIn(request, [clearCookie(SESSION_COOKIE)]);
    if (response.status !== 200) return onTheLastAnswer(request, env, session);
    const tokens = await response.json();
    let info;
    try {
      info = await userinfo(env, tokens.access_token);
    } catch {
      info = null;
    }
    if (info === null) return onTheLastAnswer(request, env, session);
    if (info === false || info.sub !== session.sub) return signIn(request, [clearCookie(SESSION_COOKIE)]);
    const next = { ...session, rt: tokens.refresh_token || session.rt, hash, roles: rolesOf(info), checked: now() };
    const fresh = setCookie(SESSION_COOKIE, await seal(next, env.SESSION_KEY), (session.exp - now()) / 1000);
    return decide(request, env, next, fresh);
  }

  return {
    async fetch(request, env) {
      const missing = ["REALM_URL", "CLIENT_ID", "CLIENT_SECRET", "SESSION_KEY"].filter((name) => !env[name]);
      if (missing.length || env.SESSION_KEY.length < 32 || !env.ASSETS) {
        console.error(`gate: not set up: ${missing.join(", ") || "SESSION_KEY too short, or no ASSETS"}`);
        return page(500, "Not set up", "This site's sign-in is not set up.");
      }
      const { pathname } = new URL(request.url);
      if (pathname === "/healthz") return new Response("ok\n", { headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" } });
      if (pathname === "/oauth2/start") return start(request, env);
      if (pathname === "/oauth2/callback") return callback(request, env);
      if (pathname === "/oauth2/sign_out") return signOut(env);
      return check(request, env);
    },
  };
}
