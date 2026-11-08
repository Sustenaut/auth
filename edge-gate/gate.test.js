// The gate against a made-up Keycloak: node --test edge-gate/
// (dev/prove_team.py runs these, then the gate against a real one under wrangler dev.)
import assert from "node:assert/strict";
import { generateKeyPairSync, createSign } from "node:crypto";
import { test } from "node:test";
import { gate } from "./gate.js";

const REALM = "https://auth.example/realms/team";
const SITE = "https://pub.example";
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
const b64 = (value) => Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");

function jwt(claims, key = privateKey) {
  const body = `${b64({ alg: "RS256", kid: "k1" })}.${b64(claims)}`;
  return `${body}.${createSign("RSA-SHA256").update(body).sign(key).toString("base64url")}`;
}

class FakeKeycloak {
  constructor(clock) {
    Object.assign(this, { clock, hash: "h1", roles: ["pub"], up: true, alive: true, calls: [], codes: {}, idClaims: {}, idKey: privateKey, hashStatus: 200 });
  }

  fetch = async (url, init = {}) => {
    const { pathname } = new URL(url);
    const kind = pathname.split("/").at(-1);
    this.calls.push(kind);
    if (!this.up) throw new TypeError("connection refused");
    const json = (status, value) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
    if (kind === "access-state") {
      this.lastBasic = init.headers.Authorization;
      return json(this.hashStatus, { hash: this.hash });
    }
    if (kind === "certs") return json(200, { keys: [{ ...publicKey.export({ format: "jwk" }), kid: "k1" }] });
    if (kind === "userinfo") return this.alive ? json(200, { sub: "u1", email: "anna@example.org", access: this.roles }) : json(401, {});
    if (kind === "token") {
      const form = new URLSearchParams(init.body);
      if (form.get("grant_type") === "refresh_token" && !this.alive) return json(400, { error: "invalid_grant" });
      this.tokenForm = form;
      return json(200, { access_token: "at", refresh_token: "rt2", id_token: jwt({ iss: REALM, aud: "sustenaut.eu", azp: "sustenaut.eu", sub: "u1",
        email: "anna@example.org", nonce: this.nonce, exp: Math.floor(this.clock() / 1000) + 300, ...this.idClaims }, this.idKey) });
    }
    return json(404, {});
  };

  count(kind) {
    return this.calls.filter((c) => c === kind).length;
  }
}

function setup(role = "pub") {
  const time = { now: 1_800_000_000_000 };
  const clock = () => time.now;
  const keycloak = new FakeKeycloak(clock);
  const store = new Map();
  const cache = { put: async (key, value) => store.set(key, await value.text()), match: async (key) => (store.has(key) ? new Response(store.get(key)) : undefined) };
  const make = (more = {}) => gate({ role, fetch: keycloak.fetch, now: clock, cache, ...more });
  const site = make();
  const env = { REALM_URL: REALM, CLIENT_ID: "sustenaut.eu", CLIENT_SECRET: "se/cret", SESSION_KEY: "k".repeat(40),
    ASSETS: { fetch: async () => new Response("the page", { headers: { "Cache-Control": "public, max-age=60" } }) } };
  const browser = { jar: {} };
  async function go(path, init = {}, on = site) {
    const headers = { Cookie: Object.entries(browser.jar).map(([k, v]) => `${k}=${v}`).join("; "), ...(init.headers || {}) };
    const response = await on.fetch(new Request(`${SITE}${path}`, { ...init, headers }), env);
    for (const line of response.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const at = pair.indexOf("=");
      if (/Max-Age=0\b/.test(line)) delete browser.jar[pair.slice(0, at)];
      else browser.jar[pair.slice(0, at)] = pair.slice(at + 1);
    }
    return response;
  }
  async function signIn(path = "/page") {
    const first = await go(path);
    assert.equal(first.status, 303);
    const started = await go(first.headers.get("Location"));
    const auth = new URL(started.headers.get("Location"));
    keycloak.nonce = auth.searchParams.get("nonce");
    return go(`/oauth2/callback?code=c1&state=${auth.searchParams.get("state")}`);
  }
  return { time, keycloak, site, env, browser, go, signIn, make, store };
}

test("signing in: code flow with PKCE and the client secret, back to the page asked for", async () => {
  const { go, signIn, keycloak, browser } = setup();
  const first = await go("/some/page?x=1");
  assert.equal(first.status, 303);
  const started = await go(first.headers.get("Location"));
  const auth = new URL(started.headers.get("Location"));
  assert.equal(`${auth.origin}${auth.pathname}`, `${REALM}/protocol/openid-connect/auth`);
  assert.equal(auth.searchParams.get("code_challenge_method"), "S256");
  assert.equal(auth.searchParams.get("redirect_uri"), `${SITE}/oauth2/callback`);
  const line = started.headers.getSetCookie()[0];
  for (const attribute of ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"]) assert.ok(line.includes(attribute), line);
  browser.jar = {};
  const back = await signIn("/some/page?x=1");
  assert.equal(back.status, 303);
  assert.equal(back.headers.get("Location"), "/some/page?x=1");
  assert.ok(keycloak.tokenForm.get("code_verifier"));
  const session = back.headers.getSetCookie().find((c) => c.startsWith("__Host-sustenaut-gate="));
  for (const attribute of ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"]) assert.ok(session.includes(attribute), session);
  const shown = await go("/some/page?x=1");
  assert.equal(shown.status, 200);
  assert.equal(await shown.text(), "the page");
  assert.ok(!session.includes("rt2"), "the refresh token is not readable in the cookie");
});

test("the cookie cannot be read or changed", async () => {
  const { go, signIn, browser } = setup();
  await signIn();
  const real = browser.jar["__Host-sustenaut-gate"];
  const [iv, sealed] = real.split(".");
  assert.ok(!Buffer.from(sealed, "base64url").toString().includes("anna"));
  const flipped = `${iv}.${sealed.slice(0, -2)}${sealed.endsWith("A") ? "B" : "A"}A`;
  for (const forged of [flipped, "garbage", `${iv}.`, b64({ roles: ["pub"], exp: 9e15, hash: "h1", checked: 9e15 })]) {
    browser.jar["__Host-sustenaut-gate"] = forged;
    const response = await go("/page");
    assert.equal(response.status, 303, forged);
    assert.match(response.headers.get("Location"), /^\/oauth2\/start/);
  }
});

test("a cookie made with another key is refused", async () => {
  const { go, signIn, browser, env } = setup();
  await signIn();
  env.SESSION_KEY = "z".repeat(40);
  void browser;
  assert.equal((await go("/page")).status, 303);
});

test("an unchanged hash asks userinfo nothing, and the hash is fetched once in 2 seconds", async () => {
  const { go, signIn, keycloak, time } = setup();
  await signIn();
  const userinfo = keycloak.count("userinfo");
  time.now += 3000;
  const hashes = keycloak.count("access-state");
  for (let i = 0; i < 5; i += 1) assert.equal((await go("/page")).status, 200);
  assert.equal(keycloak.count("userinfo"), userinfo);
  assert.equal(keycloak.count("access-state"), hashes + 1);
});

test("the site's secret reaches the hash URL-encoded", async () => {
  const { signIn, keycloak } = setup();
  await signIn();
  assert.equal(keycloak.lastBasic, `Basic ${btoa("sustenaut.eu:se%2Fcret")}`);
});

test("no requests, no calls: nothing runs by itself", async () => {
  const { make, keycloak } = setup();
  make();
  await new Promise((resolve) => { setImmediate(resolve); });
  assert.deepEqual(keycloak.calls, []);
});

test("the role is required, from userinfo", async () => {
  const { go, signIn, keycloak, time } = setup();
  keycloak.roles = ["release"];
  await signIn();
  const refused = await go("/page");
  assert.equal(refused.status, 403);
  assert.ok(!(await refused.text()).includes("the page"));
  keycloak.roles = ["pub"];
  keycloak.hash = "h2";
  time.now += 3000;
  assert.equal((await go("/page")).status, 200);
});

test("a role taken away is refused at the next request, the session going on", async () => {
  const { go, signIn, keycloak, time } = setup();
  await signIn();
  assert.equal((await go("/page")).status, 200);
  keycloak.roles = ["plan"];
  keycloak.hash = "h2";
  time.now += 3000;
  assert.equal((await go("/page")).status, 403);
  const calls = keycloak.count("userinfo");
  assert.equal((await go("/page")).status, 403);
  assert.equal(keycloak.count("userinfo"), calls, "the new answer is kept in the cookie");
});

test("removed from all: refused at the next request, cookie gone", async () => {
  const { go, signIn, keycloak, time, browser } = setup();
  await signIn();
  keycloak.alive = false;
  keycloak.hash = "h2";
  time.now += 3000;
  const gone = await go("/page");
  assert.equal(gone.status, 303);
  assert.match(gone.headers.get("Location"), /^\/oauth2\/start/);
  assert.equal(browser.jar["__Host-sustenaut-gate"], undefined);
});

test("a full check after 5 minutes even with the hash unchanged", async () => {
  const { go, signIn, keycloak, time } = setup();
  await signIn();
  const calls = keycloak.count("userinfo");
  time.now += 299_000;
  assert.equal((await go("/page")).status, 200);
  assert.equal(keycloak.count("userinfo"), calls);
  time.now += 2_000;
  assert.equal((await go("/page")).status, 200);
  assert.equal(keycloak.count("userinfo"), calls + 1);
});

test("Keycloak down: reads go on, changes are refused, an out-of-date session is refused, sign-in waits", async () => {
  const { go, signIn, keycloak, time, browser, make } = setup();
  await signIn();
  keycloak.up = false;
  time.now += 3000;
  assert.equal((await go("/page")).status, 200);
  assert.equal((await go("/page", { method: "POST" })).status, 503);
  // A new isolate knows the last hash from the cache.
  const fresh = make();
  assert.equal((await go("/page", {}, fresh)).status, 200);

  keycloak.up = true;
  const old = browser.jar["__Host-sustenaut-gate"];
  keycloak.hash = "h2";
  keycloak.roles = ["pub"];
  time.now += 3000;
  assert.equal((await go("/page")).status, 200); // this one moves on to h2
  keycloak.up = false;
  time.now += 3000;
  browser.jar["__Host-sustenaut-gate"] = old; // a session from before the change
  assert.equal((await go("/page")).status, 503);

  const stranger = setup();
  stranger.keycloak.up = false;
  const start = await stranger.go("/page");
  assert.equal(start.status, 303); // the browser is sent to the realm, which is down: sign-in waits
});

test("the hash endpoint not set up counts as Keycloak unreachable", async () => {
  const { go, signIn, keycloak, time } = setup();
  await signIn();
  keycloak.hashStatus = 503;
  time.now += 3000;
  assert.equal((await go("/page")).status, 200);
  assert.equal((await go("/page", { method: "POST" })).status, 503);
});

test("an expired session signs in again", async () => {
  const { go, signIn, time } = setup();
  await signIn();
  time.now += 8 * 24 * 3600 * 1000;
  assert.equal((await go("/page")).status, 303);
});

test("ID tokens: wrong nonce, audience, issuer, signer or date are refused", async () => {
  for (const [what, change] of Object.entries({
    audience: (k) => { k.idClaims = { aud: "other", azp: "other" }; },
    issuer: (k) => { k.idClaims = { iss: "https://evil.example/realms/team" }; },
    date: (k) => { k.idClaims = { exp: 1000 }; },
    nonce: (k) => { k.idClaims = { nonce: "wrong" }; },
    signer: (k) => { k.idKey = other.privateKey; },
  })) {
    const { signIn, keycloak, browser } = setup();
    change(keycloak);
    const back = await signIn();
    assert.equal(back.status, 400, what);
    assert.equal(browser.jar["__Host-sustenaut-gate"], undefined, what);
  }
});

test("a callback without the flow's state signs nobody in", async () => {
  const { go, browser } = setup();
  const response = await go("/oauth2/callback?code=c1&state=guess");
  assert.equal(response.status, 400);
  assert.equal(browser.jar["__Host-sustenaut-gate"], undefined);
});

test("no open redirect back from sign-in", async () => {
  for (const rd of ["//evil.example/", "https://evil.example/", "/\\evil.example", "evil", "/x\r\nSet-Cookie: a=b"]) {
    const { go, keycloak } = setup();
    const started = await go(`/oauth2/start?rd=${encodeURIComponent(rd)}`);
    const auth = new URL(started.headers.get("Location"));
    keycloak.nonce = auth.searchParams.get("nonce");
    const back = await go(`/oauth2/callback?code=c1&state=${auth.searchParams.get("state")}`);
    assert.equal(back.headers.get("Location"), "/", rd);
  }
});

test("behind the gate nothing may be kept by a shared cache", async () => {
  const { go, signIn } = setup();
  await signIn();
  assert.equal((await go("/page")).headers.get("Cache-Control"), "private, max-age=60");
});

test("a site's own headers go on what it serves, and a public mark still becomes private", async () => {
  const { go, signIn, make } = setup();
  await signIn();
  const site = make({ headers: (path) => ({ "X-Frame-Options": "DENY", "X-Path": path, "Cache-Control": "public, max-age=9" }) });
  const response = await go("/page", {}, site);
  assert.equal(response.headers.get("X-Frame-Options"), "DENY");
  assert.equal(response.headers.get("X-Path"), "/page");
  assert.equal(response.headers.get("Cache-Control"), "private, max-age=9");
});

test("a site's own handler answers past the check, null means the file, and it never runs before the check", async () => {
  const { go, signIn, make, keycloak, time } = setup();
  const seen = [];
  const site = make({
    headers: () => ({ "X-Site": "yes" }),
    handler: (request, env, person) => {
      seen.push(person);
      if (new URL(request.url).pathname === "/own") {
        return new Response("my page", { headers: { "Cache-Control": "public, max-age=9" } });
      }
      return null;
    },
  });
  assert.equal((await go("/own", {}, site)).status, 303);
  assert.deepEqual(seen, [], "signed out: not called");
  await signIn();
  const own = await go("/own", {}, site);
  assert.equal(await own.text(), "my page");
  assert.equal(own.headers.get("X-Site"), "yes");
  assert.equal(own.headers.get("Cache-Control"), "private, max-age=9");
  assert.equal(await (await go("/file", {}, site)).text(), "the page");
  assert.deepEqual(seen[0], { email: "anna@example.org", roles: ["pub"], reading: false });
  keycloak.up = false;
  time.now += 3000;
  assert.equal((await go("/own", {}, site)).status, 200);
  assert.equal(seen.at(-1).reading, true, "the handler is told Keycloak can't be reached");
  keycloak.up = true;
  keycloak.roles = ["plan"];
  keycloak.hash = "h2";
  time.now += 3000;
  const before = seen.length;
  assert.equal((await go("/own", {}, site)).status, 403);
  assert.equal(seen.length, before, "no role: not called");
});

test("fails closed without its settings; only /healthz is open", async () => {
  for (const name of ["REALM_URL", "CLIENT_ID", "CLIENT_SECRET", "SESSION_KEY", "ASSETS"]) {
    const { env, go } = setup();
    delete env[name];
    assert.equal((await go("/page")).status, 500, name);
  }
  const { env, go } = setup();
  env.SESSION_KEY = "short";
  assert.equal((await go("/page")).status, 500);
  env.SESSION_KEY = "k".repeat(40);
  assert.equal((await go("/healthz")).status, 200);
  assert.throws(() => gate({}), /role/);
});
