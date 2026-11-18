// The gate against a made-up Keycloak: cd edge-gate && npx cucumber-js
// (dev/prove_team.py runs these, then the gate against a real one under wrangler dev.)
// pubtest's steps send the requests and check the answers; these build the world and keep the browser.
import assert from "node:assert/strict";
import { generateKeyPairSync, createSign } from "node:crypto";
import * as cucumber from "@cucumber/cucumber";
import { register } from "@sustenaut/pubtest";
import { Answer } from "@sustenaut/pubtest/http";
import { gate } from "./gate.js";

const { Given, When, Then } = cucumber;

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
  const world = { on: site };
  async function go(path, init = {}, on = world.on) {
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
    const first = await go(path, {}, site);
    assert.equal(first.status, 303);
    return callback(await go(first.headers.get("Location"), {}, site));
  }
  async function callback(started) {
    const auth = new URL(started.headers.get("Location"));
    keycloak.nonce = auth.searchParams.get("nonce");
    return go(`/oauth2/callback?code=c1&state=${auth.searchParams.get("state")}`, {}, site);
  }
  return { time, keycloak, site, env, browser, go, signIn, callback, make, store, world };
}


const SESSION = "__Host-sustenaut-gate";

/** A Set-Cookie line's attributes, Max-Age without its number. */
const attributes = (line) => line.split("; ").slice(1).map((a) => (a.startsWith("Max-Age=") ? "Max-Age" : a));

async function answered(response) {
  return new Answer(response.status, Object.fromEntries(response.headers.entries()), await response.text());
}

register(cucumber, {
  // Each request goes to the site the scenario is on, with the browser's cookies.
  client: (world) => async (method, path, headers, body) =>
    answered(await world.gate.go(path, { method, headers, body: body ?? undefined })),
});

/** The forged cookies a browser might send in place of the real one. */
const FORGED = {
  "its sealed part with a byte changed": (iv, sealed) => `${iv}.${sealed.slice(0, -2)}${sealed.endsWith("A") ? "B" : "A"}A`,
  garbage: () => "garbage",
  "its iv alone": (iv) => `${iv}.`,
  "unsealed claims": () => b64({ roles: ["pub"], exp: 9e15, hash: "h1", checked: 9e15 }),
};

/** Where a sign-in may be asked to go back to, none of them on the site. */
const ELSEWHERE = {
  "another host": "//evil.example/",
  "an absolute URL": "https://evil.example/",
  "a host after a backslash": "/\\evil.example",
  "a relative path": "evil",
  "a header of its own": "/x\r\nSet-Cookie: a=b",
};

/** ID tokens Keycloak should not have signed. */
const WRONG = {
  audience: (k) => { k.idClaims = { aud: "other", azp: "other" }; },
  issuer: (k) => { k.idClaims = { iss: "https://evil.example/realms/team" }; },
  date: (k) => { k.idClaims = { exp: 1000 }; },
  nonce: (k) => { k.idClaims = { nonce: "wrong" }; },
  signer: (k) => { k.idKey = other.privateKey; },
};

Given("a site behind the gate for the role {string}", function (role) {
  this.gate = setup(role);
});

Given("I have signed in at {string}", async function (path) {
  await this.gate.signIn(path);
});

Given("I have opened {string}", async function (path) {
  await this.gate.go(path);
});

Given("{int} second(s) pass", function (seconds) {
  this.gate.time.now += seconds * 1000;
});

Given("{int} day(s) pass", function (days) {
  this.gate.time.now += days * 24 * 3600 * 1000;
});

Given("Keycloak gives the role {string}", function (role) {
  this.gate.keycloak.roles = [role];
});

Given("Keycloak's access hash changes to {string}", function (hash) {
  this.gate.keycloak.hash = hash;
});

Given("Keycloak cannot be reached", function () {
  this.gate.keycloak.up = false;
});

Given("the account is removed from Keycloak", function () {
  this.gate.keycloak.alive = false;
});

Given("the hash endpoint answers {int}", function (status) {
  this.gate.keycloak.hashStatus = status;
});

Given("Keycloak's ID tokens have the wrong {word}", function (what) {
  WRONG[what](this.gate.keycloak);
});

Given("Keycloak's calls are counted from here", function () {
  this.gate.keycloak.calls = [];
});

Given("the setting {string} is {string}", function (name, value) {
  this.gate.env[name] = value;
});

Given("the setting {string} is missing", function (name) {
  delete this.gate.env[name];
});

Given(/^the session cookie is (its sealed part with a byte changed|garbage|its iv alone|unsealed claims)$/, function (forged) {
  const [iv, sealed] = this.gate.browser.jar[SESSION].split(".");
  this.gate.browser.jar[SESSION] = FORGED[forged](iv, sealed);
});

Given("the session cookie is kept aside", function () {
  this.aside = this.gate.browser.jar[SESSION];
});

Given("the session cookie kept aside is put back", function () {
  this.gate.browser.jar[SESSION] = this.aside;
});

Given("a new isolate of the gate", function () {
  this.gate.world.on = this.gate.make();
});

Given("the site sets its own headers", function () {
  this.gate.world.on = this.gate.make({
    headers: (path) => ({ "X-Frame-Options": "DENY", "X-Path": path, "Cache-Control": "public, max-age=9" }),
  });
});

Given("the site has its own handler for {string}", function (own) {
  this.seen = [];
  this.gate.world.on = this.gate.make({
    headers: () => ({ "X-Site": "yes" }),
    handler: (request, env, person) => {
      this.seen.push(person);
      if (new URL(request.url).pathname === own) {
        return new Response("my page", { headers: { "Cache-Control": "public, max-age=9" } });
      }
      return null;
    },
  });
});

When("the sign-in starts from {string}", function (path) {
  return this.attempt(async () => {
    const first = await this.gate.go(path);
    const started = await this.gate.go(first.headers.get("Location"));
    const auth = new URL(started.headers.get("Location"));
    return {
      authorize: `${auth.origin}${auth.pathname}`,
      code_challenge_method: auth.searchParams.get("code_challenge_method"),
      redirect_uri: auth.searchParams.get("redirect_uri"),
      cookie: attributes(started.headers.getSetCookie()[0]),
    };
  });
});

When("I sign in from {string}", function (path) {
  return this.attempt(async () => {
    const back = await this.gate.signIn(path);
    const session = back.headers.getSetCookie().find((c) => c.startsWith(`${SESSION}=`));
    this.pubtest.answer = await answered(back);
    const sealed = this.gate.browser.jar[SESSION]?.split(".")[1];
    return {
      "code_verifier sent": Boolean(this.gate.keycloak.tokenForm?.get("code_verifier")),
      "session cookie": session && attributes(session),
      "refresh token in the cookie": Boolean(session?.includes("rt2")),
      "name in the sealed cookie": sealed === undefined ? null : Buffer.from(sealed, "base64url").toString().includes("anna"),
    };
  });
});

When(/^I sign in from the gate's start, asked to go back to (.+)$/, function (where) {
  return this.attempt(async () => {
    const started = await this.gate.go(`/oauth2/start?rd=${encodeURIComponent(ELSEWHERE[where])}`);
    this.pubtest.answer = await answered(await this.gate.callback(started));
    return this.pubtest.answer;
  });
});

When("I GET {string} {int} times", function (path, times) {
  return this.attempt(async () => {
    const statuses = [];
    for (let i = 0; i < times; i += 1) statuses.push((await this.gate.go(path)).status);
    return statuses;
  });
});

When("the gate is made, and left alone", function () {
  return this.attempt(async () => {
    this.gate.make();
    await new Promise((resolve) => { setImmediate(resolve); });
  });
});

When("the gate is made with no settings", function () {
  return this.attempt(() => gate({}));
});

Then("Keycloak was asked for {string} {int} time(s)", function (kind, times) {
  assert.equal(this.gate.keycloak.count(kind), times, JSON.stringify(this.gate.keycloak.calls));
});

Then("Keycloak was asked nothing", function () {
  assert.deepEqual(this.gate.keycloak.calls, []);
});

Then("Keycloak was last asked for the hash with the header {string} set to {string}", function (name, value) {
  assert.equal(name, "Authorization");
  assert.equal(this.gate.keycloak.lastBasic, value);
});

Then("the browser keeps no session cookie", function () {
  assert.equal(this.gate.browser.jar[SESSION], undefined);
});

Then("the site's handler was told:", function (docstring) {
  assert.deepEqual(this.seen, JSON.parse(docstring));
});
