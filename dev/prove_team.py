# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.27", "playwright>=1.50", "pyyaml>=6"]
# ///
"""End-to-end proof of the team realm (realm/team.json) against the local compose stack.

In the order the service goes live:

1. invite-team.sh brings the realm in line with a team list (TEAM_EMAILS standing in for
   Terraform's var.team) and the registrant (TEAM_REGISTRANT): accounts, invitations.
2. register-app.py (what business-plan/opportunity-site/register-client.sh runs on the server) registers
   sustenaut.eu for the opportunity site: the registrant signs in with the device flow
   (emailed code), the record goes to the compose stack's nameserver (ns1, which signs
   sustenaut.eu; the team realm trusts that key), and the next run collects the client; a
   run for a second site adds its redirect URI to the same client.
3. A member sets up a passkey from the invitation and signs in with it; another signs in
   with an emailed code; someone not invited gets the same page, no email, no account; no
   page has a password field and no password is accepted; no account console, no
   self-registration or reset.
4. oauth2-proxy, with the args of opportunity-site's k8s/oauth2-proxy.yaml (issuer and
   addresses made local), in front of a stub app: a member with the role gets in and the app
   sees their email in X-Forwarded-Email (not the one the browser sent); the registrant, who
   has an account but no role, is turned away.
5. invite-team.sh with a member taken out of the list disables the account and signs it
   out (the passkey no longer works); put back, it is switched on and invited again.
6. The access that replaces var.team (TeamAccess, AccessPage), checked along the way:
   import-team-access.sh before sustenaut.eu has registered (roles waiting on a placeholder the
   registration takes over), sites declaring roles with register-app.py --role, the access claim
   (that client's roles; a controller all of them and "controller"), the page at /realms/team/access
   (a controller only; members and the registrant refused; CSRF), ticks and "Remove from all"
   (sessions end, switched off, kept and restored, deleted after 30 days), invitations from the
   page, history, oauth2-proxy admitting by role, access_check.py and the hash it compares
   (a change by any route seen at the next request, an unchanged hash asking userinfo nothing, only
   the client itself reading its hash, Keycloak down), the Worker gate (edge-gate/gate.js under
   wrangler dev: sign-in, the role, a forged cookie, a change and a removal at the next request,
   Keycloak down), a new registration and the realm job keeping it all.

  uv run dev/prove_team.py     # stack must be up: podman compose up -d (podman, for oauth2-proxy)
"""

import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from contextlib import contextmanager
from pathlib import Path

import httpx
import yaml
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import access_check
import prove_family as pf  # its helpers: checks, mailpit, the nameserver's zones
from prove_family import check, jwt_claims, mails_to, no_password_field, wait_for_mail

HERE = pf.HERE
KC = pf.KC
REALM = f"{KC}/realms/team"
DOMAIN = "sustenaut.eu"
RECORD = f"_sustenaut-auth.{DOMAIN}"
CALLBACK = "https://opportunity.sustenaut.eu/oauth2/callback"
REGISTRANT = "admin@sustenaut.eu"
ANNA, BOB = "anna.team@example.org", "bob.team@example.org"
STRANGER = "nobody.team@example.org"
CONTROLLER = "controller@example.org"  # import-team-access.sh's ACCESS_CONTROLLER, in the local stack's mailpit only
CARL, DANA = "carl.team@example.org", "dana.team@example.org"
ACCESS = f"{REALM}/access"
SERVICE_ROLES = {"opportunity", "release", "notebooks", "plan", "pub", "estimate", "review"}
THIRTY_ONE_DAYS = 31 * 24 * 3600
OUT = HERE / ".pki" / "proof-team"
# The oauth2-proxy Deployment the team sites run (opportunity-site's
# k8s/oauth2-proxy.yaml), kept here so the proof runs without
# that checkout; AUTH_PROOF_PROXY_YAML points at another copy.
PROXY_YAML = Path(os.environ.get("AUTH_PROOF_PROXY_YAML", HERE / "oauth2-proxy.yaml"))
PROXY_PORT = int(os.environ.get("AUTH_PROOF_PROXY_PORT", "4180"))
STUB_PORT = int(os.environ.get("AUTH_PROOF_STUB_PORT", "8099"))
GATE_PORT = int(os.environ.get("AUTH_PROOF_GATE_PORT", "8787"))
GATE = f"http://localhost:{GATE_PORT}"
GATE_DIR = HERE / "edge-gate"
WRANGLER = "wrangler@4.156.0"
ERIN = "erin.team@example.org"
CLIENT: dict = {}


def admin() -> httpx.Client:
    return httpx.Client(base_url=f"{KC}/admin/realms/team", auth=pf._AdminToken())


def user(api: httpx.Client, email: str) -> dict:
    return (api.get("/users", params={"email": email, "exact": "true"}).json() or [{}])[0]


def invite_team(*members: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(HERE.parent / "invite-team.sh")],
        env={**pf.LOCAL_ENV, "KEYCLOAK_ADMIN_URL": pf.KC_ADMIN,
             "AUTH_CONFIG_CLIENT_SECRET": pf.ENV["KC_ADMIN_PASSWORD"],
             "TEAM_EMAILS": ",".join(members), "TEAM_REGISTRANT": REGISTRANT},
        capture_output=True, text=True, check=False)


def import_access(*members: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(HERE.parent / "import-team-access.sh")],
        env={**pf.LOCAL_ENV, "KEYCLOAK_ADMIN_URL": pf.KC_ADMIN,
             "AUTH_CONFIG_CLIENT_SECRET": pf.ENV["KC_ADMIN_PASSWORD"],
             "TEAM_EMAILS": ",".join(members), "TEAM_REGISTRANT": REGISTRANT,
             "ACCESS_CONTROLLER": CONTROLLER},
        capture_output=True, text=True, check=False)


def roles_of(api: httpx.Client, email: str) -> set[str]:
    """The roles a person holds directly on sustenaut.eu's client."""
    mappings = api.get(f"/users/{user(api, email)['id']}/role-mappings").json()
    return {r["name"] for r in mappings.get("clientMappings", {}).get(DOMAIN, {}).get("mappings", [])}


def code_in(page, email: str) -> bool:
    """On the team sign-in page: ask for a code by email and enter it. False if none came."""
    before = len([m for m in mails_to(email) if m["Subject"].startswith(pf.SIGN_IN_MAIL)])
    page.fill("input[name=username]", email)
    page.click("#kc-login")
    page.wait_for_selector("input[name=code]")
    mail = wait_for_mail(email, pf.SIGN_IN_MAIL, before, timeout=8)
    if mail is None:
        return False
    page.fill("input[name=code]", pf.link_and_code(mail)[1])
    page.click("#kc-login")
    return True


def status_of(state: Path) -> tuple[int, dict]:
    """register-app.py --status, with a step's arguments, as pubkit's deploy walk asks it."""
    run = subprocess.run(
        [sys.executable, "-I", str(HERE.parent / "register-app.py"), "--state-dir", str(state), "--auth", REALM,
         "--domain", DOMAIN, "--redirect", CALLBACK, "--status"], capture_output=True, text=True, timeout=30)
    return run.returncode, json.loads(run.stdout or "{}")


def register(browser, state: Path, redirect: str, roles: tuple[str, ...] = ()) -> tuple[int, dict]:
    """One run of register-app.py; when it prints a sign-in link, the registrant signs in."""
    run = subprocess.Popen(
        [sys.executable, "-I", str(HERE.parent / "register-app.py"), "--state-dir", str(state), "--auth", REALM,
         "--domain", DOMAIN, "--name", "sustenaut.eu team sites", "--redirect", redirect,
         "--logout", redirect.replace("/oauth2/callback", "/"), *[f"--role={r}" for r in roles]],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in run.stderr:
        if line.strip().startswith("open"):
            page = browser.new_context().new_page()
            page.goto(line.split()[1])
            code_in(page, REGISTRANT)
            page.click("[name=accept]")  # Keycloak asks: grant this device access? Yes.
            page.wait_for_load_state()
            page.context.close()
    out, _ = run.communicate(timeout=120)
    return run.returncode, json.loads(out or "{}")


def declared_first(api: httpx.Client) -> None:
    """The import before sustenaut.eu has registered: roles wait on a switched-off placeholder."""
    run = import_access(ANNA, BOB, REGISTRANT)
    rep = pf.client_rep(api, DOMAIN) or {}
    check("import-team-access.sh, no client yet: the roles wait on a switched-off placeholder with the domain's id",
          run.returncode == 0 and rep.get("enabled") is False
          and rep.get("attributes", {}).get("sustenaut.app.state") == "declared"
          and {r["name"] for r in api.get(f"/clients/{rep.get('id')}/roles").json()} == SERVICE_ROLES,
          (run.stdout + run.stderr).strip().replace("\n", " | ")[:300])
    check("...everyone in the list holds every role, and the registrant none",
          roles_of(api, ANNA) == SERVICE_ROLES and roles_of(api, BOB) == SERVICE_ROLES
          and roles_of(api, REGISTRANT) == set())
    controller = user(api, CONTROLLER)
    realm_roles = {r["name"] for r in api.get(f"/users/{controller.get('id')}/role-mappings/realm").json()}
    check("...the controller has an account, an invitation and controller", "controller" in realm_roles
          and wait_for_mail(CONTROLLER, "Your invitation", 0) is not None)
    again = import_access(ANNA, BOB, REGISTRANT)
    check("...running it again creates and sends nothing", again.returncode == 0 and "Created" not in again.stdout + again.stderr
          and "Sent" not in again.stdout + again.stderr and len(mails_to(CONTROLLER)) == 1, again.stdout.strip()[:200])
    check("...only the listed roles: the realm's own are all still there",
          {r["name"] for r in api.get("/roles").json()} >= {"controller", "offline_access", "uma_authorization", "default-roles-team"})


def registration(api: httpx.Client, browser) -> None:
    pf.publish({})
    state = Path(tempfile.mkdtemp(prefix="team-registration-"))
    code, none = status_of(state / "not-made")
    check("register-app.py --status, no state: none, and the directory is not made",
          code == 0 and none == {"status": "none"} and not (state / "not-made").exists(), json.dumps(none))
    code, first = register(browser, state, CALLBACK, ("opportunity", "opportunity:site"))
    check("register-app.py: the registrant signs in (device flow, emailed code) and gets the record to publish",
          code == 3 and first.get("status") == "waiting" and first["record"]["name"] == RECORD
          and re.fullmatch(r"sa1=[0-9a-f]{64}", first["record"]["value"]) is not None, json.dumps(first)[:160])
    code, early = register(browser, state, CALLBACK)
    check("...before the record is published: still waiting", code == 3 and early.get("status") == "waiting")
    code, asked = status_of(state)
    check("...--status says waiting, with the record, signing nobody in",
          code == 0 and asked == {"status": "waiting", "record": first["record"]}, json.dumps(asked)[:160])
    pf.publish({RECORD: [first["record"]["value"]]})
    CLIENT["record"] = first["record"]["value"]
    code, done = register(browser, state, CALLBACK)
    CLIENT.update(json.loads((state / "client.json").read_text()) if (state / "client.json").exists() else {})
    check("...with the record published (DNSSEC-validated): the client sustenaut.eu is issued and kept",
          code == 0 and done.get("status") == "registered" and CLIENT.get("client_id") == DOMAIN
          and len(CLIENT.get("client_secret", "")) > 20, json.dumps(done))
    code, asked = status_of(state)
    check("...--status says registered, with the client's id and not its secret",
          code == 0 and asked == {"status": "registered", "client_id": DOMAIN}, json.dumps(asked)[:160])
    rep = pf.client_rep(api, DOMAIN) or {}
    check("the registration takes over the placeholder: active, switched on, every role, the mapper",
          rep.get("enabled") is True and rep.get("attributes", {}).get("sustenaut.app.state") == "active"
          and {r["name"] for r in api.get(f"/clients/{rep.get('id')}/roles").json()} == SERVICE_ROLES | {"opportunity:site"}
          and [m["protocolMapper"] for m in rep.get("protocolMappers", [])] == ["sustenaut-access"])
    check("...and who holds them: anna and bob still hold every role they were given",
          roles_of(api, ANNA) == SERVICE_ROLES and roles_of(api, BOB) == SERVICE_ROLES)
    check("the state directory is private (0700, client.json 0600)",
          (state.stat().st_mode & 0o777) == 0o700 and ((state / "client.json").stat().st_mode & 0o777) == 0o600)
    code, more = register(browser, state, "https://plan.sustenaut.eu/oauth2/callback", ("plan", "plan:editor"))
    rep = pf.client_rep(api, DOMAIN) or {}
    check("a site declares its roles when it registers: new ones added, ones there already left alone",
          code == 0 and {r["name"] for r in api.get(f"/clients/{rep.get('id')}/roles").json()}
          == SERVICE_ROLES | {"opportunity:site", "plan:editor"} and roles_of(api, ANNA) == SERVICE_ROLES)
    CLIENT.update(json.loads((state / "client.json").read_text()))
    basic = (CLIENT["client_id"], CLIENT["client_secret"])
    declare = f"{REALM}/app-registration/{DOMAIN}/roles"
    refusals = {
        "another secret": httpx.post(declare, auth=(DOMAIN, "wrong"), json={"roles": ["x"]}).status_code == 401,
        "no credentials": httpx.post(declare, json={"roles": ["x"]}).status_code == 401,
        "controller": httpx.post(declare, auth=basic, json={"roles": ["controller"]}).status_code == 400,
        "a bad name": httpx.post(declare, auth=basic, json={"roles": ["Not A Role"]}).status_code == 400,
        "the family realm": httpx.post(f"{KC}/realms/family/app-registration/{DOMAIN}/roles", auth=basic,
                                       json={"roles": ["x"]}).status_code == 404,
    }
    check("declaring roles refused: " + ", ".join(refusals), all(refusals.values()), json.dumps(refusals))
    answer = httpx.post(declare, auth=basic, json={"roles": ["plan"]})
    check("declaring a role that is there changes nothing", answer.status_code == 200 and "plan" in answer.json()["roles"])
    roles_before = api.get(f"/clients/{rep.get('id')}/roles").json()
    tampered = dict(rep, protocolMappers=[{"name": "x", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
                                           "config": {"claim.name": "access", "claim.value": "controller"}}])
    reg = json.loads((state / "client.json").read_text())
    client_uri = f"{REALM}/clients-registrations/default/{DOMAIN}"
    view = httpx.get(client_uri, headers={"Authorization": f"Bearer {reg['registration_access_token']}"})
    forged = httpx.put(client_uri, json=tampered,
                       headers={"Authorization": f"Bearer {view.json().get('registrationAccessToken', reg['registration_access_token'])}"})
    check("the app's registration token cannot add a mapper of its own (it could forge the claim)",
          forged.status_code >= 400 and len(api.get(f"/clients/{rep.get('id')}/roles").json()) == len(roles_before),
          f"HTTP {forged.status_code}")
    check("a second team site adds its redirect URI to the same client, no new sign-in",
          code == 0 and more.get("status") == "ok"
          and set(rep.get("redirectUris", [])) == {CALLBACK, "https://plan.sustenaut.eu/oauth2/callback"},
          json.dumps(rep.get("redirectUris")))
    check("the client: confidential, code flow + PKCE S256 only, email scope, no password grant",
          rep.get("enabled") is True and rep.get("publicClient") is False and not rep.get("directAccessGrantsEnabled")
          and not rep.get("implicitFlowEnabled") and not rep.get("serviceAccountsEnabled")
          and rep.get("attributes", {}).get("pkce.code.challenge.method") == "S256"
          and "email" in rep.get("defaultClientScopes", []))

    start = httpx.post(f"{REALM}/protocol/openid-connect/auth/device", data={"client_id": "app-registration"}).json()
    page = browser.new_context().new_page()
    page.goto(start["verification_uri_complete"])
    code_in(page, BOB)
    page.click("[name=accept]")
    page.wait_for_load_state()
    token = None
    for _ in range(12):
        time.sleep(start.get("interval", 5) + 0.5)
        answer = httpx.post(f"{REALM}/protocol/openid-connect/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "client_id": "app-registration",
            "device_code": start["device_code"]})
        if answer.status_code == 200:
            token = answer.json()["access_token"]
            break
    wrong = httpx.post(f"{REALM}/app-registration", headers={"Authorization": f"Bearer {token}"},
                       json={"domain": DOMAIN, "redirect_uris": [CALLBACK]})
    check("a team member not at the domain cannot register sustenaut.eu (403)", wrong.status_code == 403, wrong.text[:120])
    other = httpx.post(f"{REALM}/app-registration", headers={"Authorization": f"Bearer {token}"},
                       json={"domain": "example.net", "redirect_uris": ["https://share.example.net/oauth2/callback"]})
    check("the team realm registers sustenaut.eu only (example.net refused)", other.status_code == 400, other.text[:120])


class Opportunity:
    """The opportunity site's side of the code flow (its callback), inside a browser context."""

    def __init__(self, context):
        self.landed = self.state = None
        context.on("request", self._seen)

    def _seen(self, request):
        # Only this sign-in's: an earlier one's request can still be on its way here.
        if request.url.startswith(CALLBACK) and urllib.parse.parse_qs(urllib.parse.urlparse(request.url).query).get("state") == [self.state]:
            self.landed = request.url

    def start(self, page) -> None:
        self.landed = None
        self.state = secrets.token_urlsafe(8)
        self.verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).rstrip(b"=").decode()
        try:
            page.goto(f"{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode({
                "client_id": DOMAIN, "response_type": "code", "scope": "openid email", "redirect_uri": CALLBACK,
                "state": self.state, "code_challenge": challenge, "code_challenge_method": "S256"}))
        except PlaywrightError as error:  # a session goes straight to the callback, a host Chrome is told is not there
            if "ERR_NAME_NOT_RESOLVED" not in str(error):
                raise

    def tokens(self, page, wait: float = 20) -> dict | None:
        for _ in range(int(wait * 4)):
            if self.landed:
                break
            page.wait_for_timeout(250)
        if not self.landed:
            return None
        code = urllib.parse.parse_qs(urllib.parse.urlparse(self.landed).query)["code"][0]
        return httpx.post(f"{REALM}/protocol/openid-connect/token", data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": CALLBACK, "client_id": DOMAIN,
            "client_secret": CLIENT["client_secret"], "code_verifier": self.verifier}).raise_for_status().json()


def phone(browser):
    """A browser context with a platform passkey authenticator (Chrome's virtual one)."""
    context = browser.new_context()
    site = Opportunity(context)
    page = context.new_page()
    page.on("dialog", lambda d: d.accept("Anna's phone"))
    cdp = context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
    return context, site, page


def sign_ins(api: httpx.Client, browser) -> object:
    anna = user(api, ANNA)
    invite = wait_for_mail(ANNA, "Your invitation", 0)
    link = re.search("(" + re.escape(KC) + r"/realms/team/login-actions/action-token\S+)", invite["Text"]).group(1) if invite else ""
    check("the invitation arrives from noreply@sustenaut.eu, in the team's words, with a setup link",
          bool(link) and invite["From"]["Address"] == "noreply@sustenaut.eu"
          and "Sustenaut's team sites" in invite["Text"] and "Example family" not in invite["Text"],
          f"subject={invite and invite['Subject']!r}")

    context, site, page = phone(browser)
    page.goto(link)
    page.click("text=Start")
    page.wait_for_selector("#registerWebAuthn")
    page.screenshot(path=OUT / "1-passkey-setup.png")
    no_password_field(page, "team passkey setup page")
    page.click("#registerWebAuthn")
    page.wait_for_selector("text=Your passkey is ready", timeout=20000)
    creds = api.get(f"/users/{anna.get('id')}/credentials").json()
    check("the setup link registers a passkey, and only that",
          [c["type"] for c in creds] == ["webauthn-passwordless"], json.dumps([c["type"] for c in creds]))

    context.clear_cookies()
    site.start(page)
    tokens = site.tokens(page)
    idt = jwt_claims(tokens["id_token"]) if tokens else {}
    check("signing in with the passkey reaches the opportunity site's client, email verified in the ID token",
          idt.get("sub") == anna.get("id") and idt.get("email") == ANNA and idt.get("email_verified") is True
          and idt.get("iss") == REALM and idt.get("azp") == DOMAIN,
          json.dumps({k: idt.get(k) for k in ("email", "email_verified", "azp", "iss")}))

    other = browser.new_context()
    bob_site = Opportunity(other)
    page2 = other.new_page()
    bob_site.start(page2)
    page2.wait_for_selector("#kc-login")
    page2.screenshot(path=OUT / "2-login-page.png")
    no_password_field(page2, "team login page")
    check("the login page: the email field (a passkey offered in it, no passkey button) and an emailed link and "
          "code, no registration or reset link, team wording",
          page2.locator("#authenticateWebAuthnButton").count() == 0 and page2.locator("#webauth").count() == 1
          and "Email me a sign-in link" in page2.locator("#kc-login").inner_text()
          and page2.locator("a[href*=registrations], a[href*=reset-credentials]").count() == 0
          and "Sustenaut team only" in page2.content() and "family" not in page2.locator("#family-invite-only").inner_text())
    check("no wallet buttons on the team page", page2.locator("[id^=social-oid4vp], #sk-plugin-source").count() == 0)
    sent = code_in(page2, BOB)
    bob_tokens = bob_site.tokens(page2) if sent else None
    check("signing in with an emailed code reaches the client, as bob",
          bob_tokens is not None and jwt_claims(bob_tokens["id_token"]).get("email") == BOB)
    no_password_field(page2, "team code page")

    stranger = browser.new_context()
    s_site = Opportunity(stranger)
    page3 = stranger.new_page()
    s_site.start(page3)
    page3.fill("input[name=username]", STRANGER)
    page3.click("#kc-login")
    page3.wait_for_selector("input[name=code]")
    same = f"If {STRANGER} has been invited" in page3.content()
    time.sleep(3)
    page3.fill("input[name=code]", "123456")
    page3.click("#kc-login")
    page3.wait_for_selector("input[name=code]")
    check("someone not invited sees the same 'we sent a code' page, gets no email and no way in",
          same and mails_to(STRANGER) == [] and s_site.landed is None and "not right" in page3.content())

    pw_try = browser.new_context()
    pw_site = Opportunity(pw_try)
    page4 = pw_try.new_page()
    pw_site.start(page4)
    action = page4.locator("#kc-form-login").get_attribute("action")
    with page4.expect_navigation():
        page4.evaluate("""([action, email]) => {
            const f = document.createElement('form'); f.method = 'post'; f.action = action;
            for (const [k, v] of [['username', email], ['password', 'hunter2'], ['login', 'x']]) {
                const i = document.createElement('input'); i.name = k; i.value = v; f.appendChild(i); }
            document.body.appendChild(f); f.submit(); }""", [action, ANNA])
    check("a username and password posted to the login form do not sign in (a code page instead)",
          pw_site.landed is None and page4.locator("input[name=code]").count() == 1)
    grant = httpx.post(f"{REALM}/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": DOMAIN, "client_secret": CLIENT["client_secret"],
        "username": ANNA, "password": "x"})
    check("the client refuses the password grant", grant.status_code in (400, 401), grant.text[:120])
    return context, site, page


class _Stub(http.server.BaseHTTPRequestHandler):
    """Stands in for the opportunity app: answers with the identity header it was given."""

    seen: list = []  # noqa: RUF012

    def do_GET(self):
        _Stub.seen.append(self.headers.get("X-Forwarded-Email"))
        body = json.dumps({"x-forwarded-email": self.headers.get("X-Forwarded-Email"),
                           "x-forwarded-groups": self.headers.get("X-Forwarded-Groups"),
                           "access-token": bool(self.headers.get("X-Forwarded-Access-Token"))}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def proxy_args(cookie_refresh: str | None = None) -> tuple[str, list[str]]:
    """The image and args of opportunity-site's k8s/oauth2-proxy.yaml, with local addresses."""
    docs = [d for d in yaml.safe_load_all(PROXY_YAML.read_text()) if d and d["kind"] == "Deployment"]
    container = docs[0]["spec"]["template"]["spec"]["containers"][0]
    local = {"--oidc-issuer-url": REALM, "--redirect-url": f"http://localhost:{PROXY_PORT}/oauth2/callback",
             "--upstream": f"http://127.0.0.1:{STUB_PORT}/", "--cookie-secure": "false",
             "--http-address": f"127.0.0.1:{PROXY_PORT}"}
    if cookie_refresh:
        local["--cookie-refresh"] = cookie_refresh
    args = []
    for arg in container["args"]:
        name = arg.split("=", 1)[0]
        args.append(f"{name}={local[name]}" if name in local else arg)
    return container["image"], args


@contextmanager
def proxy_running(api: httpx.Client, args: list[str]):
    """oauth2-proxy with these args in front of the stub app, its callback allowed for the while; yields "is it up?"."""
    rep = pf.client_rep(api, DOMAIN)
    local_cb = f"http://localhost:{PROXY_PORT}/oauth2/callback"
    rep["redirectUris"] = rep["redirectUris"] + [local_cb]  # test only: the admin API, not the app's rules
    api.put(f"/clients/{rep['id']}", json=rep).raise_for_status()
    image, _ = proxy_args()
    stub = http.server.HTTPServer(("127.0.0.1", STUB_PORT), _Stub)
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    name = f"prove-team-proxy-{os.getpid()}"
    subprocess.run(["podman", "run", "-d", "--rm", "--name", name, "--network", "host",
                    "-e", f"OAUTH2_PROXY_CLIENT_ID={DOMAIN}", "-e", f"OAUTH2_PROXY_CLIENT_SECRET={CLIENT['client_secret']}",
                    "-e", f"OAUTH2_PROXY_COOKIE_SECRET={secrets.token_hex(16)}", image, *args],
                   check=True, capture_output=True)

    def up() -> bool:
        try:
            return httpx.get(f"http://localhost:{PROXY_PORT}/ping").status_code == 200
        except httpx.TransportError:
            return False

    try:
        if not pf.wait_until(up, timeout=40):
            check("oauth2-proxy starts", False, " ".join(args)[:200])
        yield up
    finally:
        logs = subprocess.run(["podman", "logs", name], capture_output=True, text=True, check=False).stderr
        with (OUT / "oauth2-proxy.log").open("a") as log:
            log.write(logs)
        subprocess.run(["podman", "rm", "-f", name], capture_output=True, check=False)
        stub.shutdown()
        stub.server_close()
        rep = pf.client_rep(api, DOMAIN)
        rep["redirectUris"] = [u for u in rep["redirectUris"] if u != local_cb]
        api.put(f"/clients/{rep['id']}", json=rep).raise_for_status()


def through_proxy(api: httpx.Client, browser) -> None:
    _, args = proxy_args()
    check("oauth2-proxy.yaml signs in with the team realm (keycloak-oidc, PKCE S256) and admits by the role, no emails file",
          "--provider=keycloak-oidc" in args and "--code-challenge-method=S256" in args
          and {"--oidc-groups-claim=access", "--allowed-group=opportunity", "--email-domain=*"} <= set(args)
          and not any("authenticated-emails" in a or "google" in a for a in args), " ".join(args)[:200])
    check("...passes the access token on, and refreshes in time for it to be valid at userinfo (it lasts 5 minutes)",
          {"--pass-access-token=true", "--pass-user-headers=true", "--cookie-refresh=4m"} <= set(args)
          and api.get("").json().get("accessTokenLifespan") == 300, str(api.get("").json().get("accessTokenLifespan")))
    with proxy_running(api, args) as up:
        check("oauth2-proxy starts with those args against the team realm's discovery document", up())
        check("/healthz is open without sign-in (passed to the app)",
              httpx.get(f"http://localhost:{PROXY_PORT}/healthz").status_code == 200)
        context = browser.new_context(extra_http_headers={"X-Forwarded-Email": "eve@example.org"})
        page = context.new_page()
        page.goto(f"http://localhost:{PROXY_PORT}/")
        page.wait_for_selector("input[name=username]")
        code_in(page, BOB)
        page.wait_for_url(f"http://localhost:{PROXY_PORT}/**", timeout=20000)
        page.wait_for_load_state()
        body = page.inner_text("body")
        check("a member signs in through oauth2-proxy; the app gets their email in X-Forwarded-Email, "
              "not the one the browser sent", f'"x-forwarded-email": "{BOB}"' in body, body[:160])
        _Stub.seen.clear()
        outsider = browser.new_context().new_page()
        outsider.goto(f"http://localhost:{PROXY_PORT}/")
        outsider.wait_for_selector("input[name=username]")
        code_in(outsider, REGISTRANT)
        outsider.wait_for_url(f"http://localhost:{PROXY_PORT}/**", timeout=20000)
        outsider.wait_for_load_state()
        text = outsider.inner_text("body")
        outsider.screenshot(path=OUT / "3-proxy-refuses-registrant.png")
        check("the registrant (an account, but no role) is refused; the app never sees them",
              _Stub.seen == [] and ("403" in text or "Forbidden" in text or "not authorized" in text.lower()), text[:160])


def claims_of(context) -> tuple[dict, dict]:
    """A fresh token through the opportunity site's client, in this browser's session: the ID token's claims, the tokens."""
    site = Opportunity(context)
    page = context.new_page()
    site.start(page)
    tokens = site.tokens(page) or {}
    page.close()
    return jwt_claims(tokens["id_token"]) if tokens else {}, tokens


def refreshed(tokens: dict) -> httpx.Response:
    return httpx.post(f"{REALM}/protocol/openid-connect/token", data={
        "grant_type": "refresh_token", "client_id": DOMAIN, "client_secret": CLIENT["client_secret"],
        "refresh_token": tokens["refresh_token"]})


def page_as(browser, email: str):
    """A browser signing in to the access page with an emailed code; its context and page."""
    context = browser.new_context()
    page = context.new_page()
    answer = page.goto(ACCESS)
    page.wait_for_selector("input[name=username]")
    assert answer is not None
    code_in(page, email)
    page.wait_for_url(f"{ACCESS}*", timeout=20000)
    page.wait_for_load_state()
    return context, page


def act(page, selector: str) -> str:
    """Clicks a button on the access page; what the page then says."""
    page.click(selector)
    page.wait_for_selector("#access-done")
    return page.inner_text("#access-done")


def row(email: str) -> str:
    return f'tr[data-email="{email}"]'


def action_button(email: str, action: str) -> str:
    return f'tr[data-history="{email}"] button[data-action="{action}"]'


def role_button(email: str, role: str) -> str:
    return f'{row(email)} button[data-role="{role}"]'


def the_claim(api: httpx.Client, browser) -> tuple:
    """The access claim, with the page's controller signed in (the tokens to refresh later)."""
    all_roles = {r["name"] for r in api.get(f"/clients/{pf.client_rep(api, DOMAIN)['id']}/roles").json()}
    before = invite_team(ANNA, BOB, CONTROLLER)
    check("the controller is on the team list (put back by invite-team.sh with their roles)", before.returncode == 0
          and user(api, CONTROLLER).get("enabled") is True, before.stdout.strip()[:200])
    d_context, d_page = page_as(browser, CONTROLLER)
    idt, tokens = claims_of(d_context)
    check("a controller's claim: every role of this client, and the word controller",
          set(idt.get("access", [])) == all_roles | {"controller"}, json.dumps(idt.get("access")))
    access = jwt_claims(tokens["access_token"]).get("access") if tokens else None
    info = httpx.get(f"{REALM}/protocol/openid-connect/userinfo", headers={"Authorization": f"Bearer {tokens.get('access_token')}"})
    check("...the same in the access token and userinfo", set(access or []) == set(idt.get("access", []))
          and set(info.json().get("access", [])) == set(idt.get("access", [])))
    extra = api.get("/clients", params={"clientId": "app-registration"}).json()[0]
    api.post(f"/clients/{extra['id']}/roles", json={"name": "elsewhere"}).raise_for_status()
    other = api.get(f"/clients/{extra['id']}/roles/elsewhere").json()
    bob = user(api, BOB)
    api.post(f"/users/{bob['id']}/role-mappings/clients/{extra['id']}", json=[other]).raise_for_status()
    b_context = browser.new_context()
    b_site = Opportunity(b_context)
    b_page = b_context.new_page()
    b_site.start(b_page)
    code_in(b_page, BOB)
    b_tokens = b_site.tokens(b_page) or {}
    b_idt = jwt_claims(b_tokens["id_token"]) if b_tokens else {}
    check("a member's claim: exactly the roles held on THIS client, not another client's, not the word controller",
          set(b_idt.get("access", [])) == SERVICE_ROLES, json.dumps(b_idt.get("access")))
    api.delete(f"/clients/{extra['id']}/roles/elsewhere").raise_for_status()
    r_context = browser.new_context()
    r_site = Opportunity(r_context)
    r_page = r_context.new_page()
    r_site.start(r_page)
    code_in(r_page, REGISTRANT)
    r_tokens = r_site.tokens(r_page) or {}
    check("the registrant's claim is empty", r_tokens and jwt_claims(r_tokens["id_token"]).get("access") == [])
    return d_context, d_page, b_context, b_page, b_tokens


def the_page(api: httpx.Client, browser, anna_phone) -> tuple:
    d_context, d_page, b_context, b_page, b_tokens = the_claim(api, browser)
    anna_context, anna_site, anna_page = anna_phone

    # Who sees it.
    anon = httpx.get(ACCESS)
    check("the page, signed out: to the realm's own sign-in, through team-access",
          anon.status_code == 303 and "/protocol/openid-connect/auth?" in anon.headers["location"]
          and "client_id=team-access" in anon.headers["location"], anon.headers.get("location", "")[:120])
    check("the page does not exist in the other realms",
          httpx.get(f"{KC}/realms/family/access").status_code == 404 and httpx.get(f"{KC}/realms/sustenaut/access").status_code == 404)
    d_page.screenshot(path=OUT / "5-access-page.png", full_page=True)
    no_password_field(d_page, "access page")
    head = d_page.locator("#access-table thead").inner_text()
    check("a controller sees the table: people by service roles, status per person, in the team theme",
          all(r in head for r in SERVICE_ROLES) and d_page.locator(row(ANNA)).count() == 1
          and d_page.locator(row(ANNA)).get_attribute("data-status") == "active"
          and "sustenaut.css" in d_page.content(), head.replace("\n", " ")[:160])
    check("the registrant is listed apart, with no ticks", d_page.locator(row(REGISTRANT)).count() == 0
          and REGISTRANT in d_page.inner_text("#access-registrants"))
    check("a page signed out has no table", "access-table" not in anon.text)
    csrf = d_page.get_attribute("#access-invite input[name=csrf]", "value")
    anna = user(api, ANNA)
    grant_form = {"csrf": csrf, "user": anna["id"], "role": "sustenaut.eu/opportunity:site"}

    b_answer = b_context.new_page()
    response = b_answer.goto(ACCESS)  # bob's session, from signing in to the site
    check("a member is refused the page (403), and it shows nothing of the list",
          response.status == 403 and b_answer.locator("#access-refused").count() == 1 and ANNA not in b_answer.content())
    b_answer.screenshot(path=OUT / "6-access-refused.png")
    no_password_field(b_answer, "access refusal")
    forged = b_context.request.post(f"{ACCESS}/grant", form=grant_form, max_redirects=0)
    check("a member's change is refused (403), even with a controller's token", forged.status == 403
          and "opportunity:site" not in roles_of(api, ANNA))
    r_context, r_page = page_as(browser, REGISTRANT)
    check("the registrant is refused the page too", r_page.locator("#access-refused").count() == 1)
    r_context.close()
    signed_out = httpx.post(f"{ACCESS}/grant", data=grant_form)
    check("a change without a session goes to the sign-in and changes nothing",
          signed_out.status_code == 303 and "opportunity:site" not in roles_of(api, ANNA))

    # CSRF: this session's token, and this server's origin.
    no_token = d_context.request.post(f"{ACCESS}/grant", form={k: v for k, v in grant_form.items() if k != "csrf"}, max_redirects=0)
    wrong_token = d_context.request.post(f"{ACCESS}/grant", form={**grant_form, "csrf": "0" * 64}, max_redirects=0)
    other_origin = d_context.request.post(f"{ACCESS}/grant", form=grant_form, max_redirects=0,
                                          headers={"Origin": "https://evil.example"})
    check("CSRF: a controller's change without the token, with another token, or from another origin is refused",
          no_token.status == 403 and wrong_token.status == 403 and other_origin.status == 403
          and "opportunity:site" not in roles_of(api, ANNA), f"{no_token.status} {wrong_token.status} {other_origin.status}")
    answer = d_context.request.get(ACCESS)
    check("the page is not cached, and frames are refused", "no-store" in answer.headers.get("cache-control", "")
          and "frame-ancestors" in answer.headers.get("content-security-policy", ""))

    # Grant and revoke: one service, nothing else.
    done = act(d_page, role_button(ANNA, "release"))
    check("taking one service away takes only that role", roles_of(api, ANNA) == SERVICE_ROLES - {"release"}, done)
    anna_site.start(anna_page)
    anna_tokens = anna_site.tokens(anna_page) or {}
    check("...the person stays signed in, and the next token lacks it",
          set(jwt_claims(anna_tokens["id_token"]).get("access", [])) == SERVICE_ROLES - {"release"} if anna_tokens else False)
    act(d_page, role_button(BOB, "review"))
    again = refreshed(b_tokens)
    check("...a token refresh is enough to see it (sessions go on)", again.status_code == 200
          and "review" not in jwt_claims(again.json()["id_token"]).get("access", []))
    act(d_page, role_button(ANNA, "release"))
    fresh = refreshed(anna_tokens)
    check("ticking it again gives it back at the next refresh", fresh.status_code == 200
          and "release" in jwt_claims(fresh.json()["id_token"]).get("access", []))
    act(d_page, role_button(ANNA, "opportunity:site"))
    check("a role only a site declared has a column and a tick too", "opportunity:site" in roles_of(api, ANNA))
    act(d_page, role_button(ANNA, "opportunity:site"))
    registrant = user(api, REGISTRANT)
    token = d_page.get_attribute("#access-invite input[name=csrf]", "value")
    d_context.request.post(f"{ACCESS}/grant", form={"csrf": token, "user": registrant["id"], "role": "sustenaut.eu/opportunity"}, max_redirects=0)
    check("the registrant cannot be given a service role", roles_of(api, REGISTRANT) == set())

    # A controller cannot lock themself out; another controller can be made and unmade.
    controller = user(api, CONTROLLER)
    gone = d_context.request.post(f"{ACCESS}/remove", form={"csrf": token, "user": controller["id"]}, max_redirects=0)
    self_off = d_context.request.post(f"{ACCESS}/revoke", form={"csrf": token, "user": controller["id"], "role": "controller"}, max_redirects=0)
    check("a controller cannot remove themself or take controller from themself",
          "notYourself" in gone.headers.get("location", "") and "notYourself" in self_off.headers.get("location", "")
          and user(api, CONTROLLER).get("enabled") is True and "controller" in pf.jwt_claims(claims_of(d_context)[1]["id_token"]).get("access", []))
    act(d_page, role_button(BOB, "controller"))
    b_refused_no_more = b_context.new_page()
    check("controller given on the page: the person can open it", b_refused_no_more.goto(ACCESS).status == 200)
    act(d_page, role_button(BOB, "controller"))
    check("...and taken away: refused again", b_refused_no_more.goto(ACCESS).status == 403)
    b_refused_no_more.close()

    # Invite.
    d_page.fill("#access-invite input[name=email]", CARL.upper())
    d_page.fill("#access-invite input[name=first_name]", "Carl")
    d_page.fill("#access-invite input[name=last_name]", "Example")
    d_page.check('#access-invite input[value="sustenaut.eu/opportunity"]')
    done = act(d_page, "#access-invite button")
    carl = user(api, CARL)
    mail = wait_for_mail(CARL, "Your invitation", 0)
    link = re.search("(" + re.escape(KC) + r"/realms/team/login-actions/action-token\S+)", mail["Text"]).group(1) if mail else ""
    check("invite from the page: account (lower case, verified, the name), only the ticked role, the invitation email",
          carl.get("username") == CARL and carl.get("emailVerified") and carl.get("firstName") == "Carl"
          and roles_of(api, CARL) == {"opportunity"} and bool(link) and mail["From"]["Address"] == "noreply@sustenaut.eu"
          and "7 days" in mail["Text"], done)
    check("...status invited", d_page.locator(row(CARL)).get_attribute("data-status") == "invited")
    c_context = browser.new_context()
    c_page = c_context.new_page()
    c_page.goto(link)
    c_page.click("text=Start")
    c_page.wait_for_selector("#registerWebAuthn")
    check("...the link sets up a passkey, as invite-team.sh's does", c_page.locator("#registerWebAuthn").count() == 1)
    c_context.close()
    c_context = browser.new_context()
    c_site = Opportunity(c_context)
    c_page = c_context.new_page()
    c_site.start(c_page)
    code_in(c_page, CARL)
    c_tokens = c_site.tokens(c_page) or {}
    check("...they sign in; the claim has only what was ticked",
          bool(c_tokens) and jwt_claims(c_tokens["id_token"]).get("access") == ["opportunity"])
    d_page.reload()
    check("...status active, after signing in", d_page.locator(row(CARL)).get_attribute("data-status") == "active")
    bad = act_invite(d_page, "not-an-address@example")
    check("an address that is not one is refused", "does not look like" in bad and user(api, "not-an-address@example") == {})

    # Declare a service that has not registered.
    d_page.fill("#access-declare input[name=name]", "later-site")
    act(d_page, "#access-declare button")
    idt, _ = claims_of(d_context)
    check("declaring a service on the page adds a column; a controller has it at once, a member not until ticked",
          "later-site" in d_page.locator("#access-table thead").inner_text() and "later-site" in idt.get("access", [])
          and "later-site" not in roles_of(api, ANNA))

    # History.
    text = d_page.locator(f'tr[data-history="{ANNA}"]').text_content()
    check("history per person: what changed, by whom, when (the page's and the import's through the admin API)",
          f"took release away ({CONTROLLER})" in text and f"gave release ({CONTROLLER})" in text and "UTC" in text
          and "(an admin)" in text and "opportunity" in text, " ".join(text.split())[:240])

    # Remove from all.
    anna_site.start(anna_page)
    before = anna_site.tokens(anna_page) or {}
    check("before: anna is signed in, with a refresh token", refreshed(before).status_code == 200)
    done = act(d_page, action_button(ANNA, "remove"))
    d_page.screenshot(path=OUT / "7-access-removed.png", full_page=True)
    after = user(api, ANNA)
    stamp = int((after.get("attributes") or {}).get("sustenaut.removedAt", ["0"])[0])
    check("remove from all: every role off, the account off and stamped", after.get("enabled") is False
          and roles_of(api, ANNA) == set() and abs(time.time() - stamp) < 120, done)
    check("...all sessions end: her refresh token is dead and her browser no longer passes",
          refreshed(before).status_code == 400 and api.get(f"/users/{after['id']}/sessions").json() == [])
    anna_site.start(anna_page)
    check("...her browser's session no longer lets her in", anna_site.tokens(anna_page, wait=6) is None)
    anna_context.clear_cookies()
    anna_site.start(anna_page)
    check("...and her passkey no longer works", anna_site.tokens(anna_page, wait=8) is None)
    state = d_page.locator(row(ANNA))
    check("...the page shows her removed, the date she goes, no ticks",
          state.get_attribute("data-status") == "removed" and "deleted on" in state.inner_text()
          and state.locator("button[data-role]").count() == 0)
    check("...the passkey is kept", [c["type"] for c in api.get(f"/users/{after['id']}/credentials").json()] == ["webauthn-passwordless"])
    before_mails = len([m for m in mails_to(ANNA) if m["Subject"].startswith("Your invitation")])
    done = act(d_page, action_button(ANNA, "restore"))
    back = user(api, ANNA)
    check("put back: on again, no stamp, no roles, invited again", back.get("enabled") is True
          and "sustenaut.removedAt" not in (back.get("attributes") or {}) and roles_of(api, ANNA) == set()
          and wait_for_mail(ANNA, "Your invitation", before_mails) is not None, done)
    anna_context.clear_cookies()
    anna_site.start(anna_page)
    tokens = anna_site.tokens(anna_page) or {}
    check("...her passkey works as before; the claim is empty until she is ticked",
          bool(tokens) and jwt_claims(tokens["id_token"]).get("access") == [])
    act(d_page, role_button(ANNA, "opportunity"))

    # Removed for 30 days: gone.
    act(d_page, action_button(CARL, "remove"))
    carl = user(api, CARL)
    check("a removed account within the 30 days is kept", carl.get("enabled") is False
          and pf.wait_until(lambda: user(api, CARL) != {}, timeout=1))
    time.sleep(7)  # the daily job, every 5 s here, leaves it alone
    check("...through the daily job", user(api, CARL) != {})
    carl["attributes"]["sustenaut.removedAt"] = [str(int(time.time()) - THIRTY_ONE_DAYS)]
    api.put(f"/users/{carl['id']}", json=carl).raise_for_status()
    check("...and deleted once 30 days have passed", pf.wait_until(lambda: user(api, CARL) == {}, timeout=30))
    d_page.reload()
    b_context.close()
    return d_context, d_page


def act_invite(page, email: str) -> str:
    page.fill("#access-invite input[name=email]", email)
    page.evaluate("document.querySelector('#access-invite').noValidate = true")
    return act(page, "#access-invite button")


def by_role(api: httpx.Client, browser, d_context, d_page) -> None:
    """oauth2-proxy admitting by the claim, as the sites do: who is refused, forged headers, a refresh."""
    token = d_page.get_attribute("#access-invite input[name=csrf]", "value")
    d_page.fill("#access-invite input[name=email]", DANA)
    d_page.check('#access-invite input[value="sustenaut.eu/release"]')
    act(d_page, "#access-invite button")
    assert token
    _, args = proxy_args(cookie_refresh="3s")  # the site's args, refreshing sooner for the proof
    with proxy_running(api, args):
        def through(email: str, context=None) -> tuple[str, object]:
            page = (context or browser.new_context()).new_page()
            page.goto(f"http://localhost:{PROXY_PORT}/")
            if page.locator("input[name=username]").count():
                code_in(page, email)
            page.wait_for_url(f"http://localhost:{PROXY_PORT}/**", timeout=20000)
            page.wait_for_load_state()
            return page.inner_text("body"), page
        _Stub.seen.clear()
        forger = browser.new_context(extra_http_headers={"X-Forwarded-Groups": "controller"})
        body, _ = through(ANNA, forger)
        check("oauth2-proxy with --allowed-group=opportunity: someone holding it is admitted, with their roles in X-Forwarded-Groups "
              "(not the ones the browser sent), and their access token for the app",
              f'"x-forwarded-email": "{ANNA}"' in body and '"x-forwarded-groups": "opportunity"' in body
              and '"access-token": true' in body, body[:200])
        act(d_page, role_button(ANNA, "opportunity"))
        time.sleep(4)
        _Stub.seen.clear()
        body, _ = through(ANNA, forger)
        check("...the role taken away: refused at the first request after --cookie-refresh, the session going on, "
              "whatever the browser sends", _Stub.seen == [] and ("403" in body or "Forbidden" in body), body[:160])
        act(d_page, role_button(ANNA, "opportunity"))
        time.sleep(4)
        body, _ = through(ANNA, forger)
        check("...given back: admitted again at the next refresh", '"x-forwarded-groups": "opportunity"' in body, body[:160])
        _Stub.seen.clear()
        body, page = through(DANA)
        page.screenshot(path=OUT / "8-proxy-refuses-by-role.png")
        check("...someone holding only another service's role is refused; the app never sees them",
              _Stub.seen == [] and ("403" in body or "Forbidden" in body or "not authorized" in body.lower()), body[:160])
        _Stub.seen.clear()
        body, _ = through(REGISTRANT)
        check("...so is the registrant", _Stub.seen == [])
        body, _ = through(CONTROLLER, d_context)
        check("...a controller is admitted, with controller in X-Forwarded-Groups for the apps' edit rights",
              "controller" in body and "opportunity" in body, body[:200])


class CountingCheck(access_check.AccessCheck):
    """access_check.py as a site runs it, with its requests to Keycloak counted."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls: list[str] = []

    def _get(self, url, headers):
        self.calls.append("userinfo" if url.endswith("/userinfo") else "hash")
        return super()._get(url, headers)

    def count(self, kind: str) -> int:
        return self.calls.count(kind)


def signed_in_token(browser, email: str) -> str:
    context = browser.new_context()
    site = Opportunity(context)
    page = context.new_page()
    site.start(page)
    code_in(page, email)
    return (site.tokens(page) or {}).get("access_token", "")


def the_hash(api: httpx.Client, browser, d_page) -> None:
    url = f"{REALM}/app-registration/{DOMAIN}/access-state"
    basic = (CLIENT["client_id"], CLIENT["client_secret"])
    first = httpx.get(url, auth=basic)
    check("the access state: the client gets a keyed hash and nothing else, not to be cached",
          first.status_code == 200 and re.fullmatch("[0-9a-f]{64}", first.json().get("hash", "")) is not None
          and list(first.json()) == ["hash"] and first.headers.get("cache-control") == "no-store", first.text[:100])
    other = {"clientId": "other.example", "secret": "other-secret-for-the-proof", "enabled": True, "protocol": "openid-connect",
             "publicClient": False, "attributes": {"sustenaut.app.state": "active", "sustenaut.app.domain": "other.example"}}
    api.post("/clients", json=other).raise_for_status()
    refused = {
        "no credentials": httpx.get(url).status_code,
        "another secret": httpx.get(url, auth=(DOMAIN, "wrong")).status_code,
        "another registered client": httpx.get(url, auth=(other["clientId"], other["secret"])).status_code,
        "team-access": httpx.get(url, auth=("team-access", "")).status_code,
    }
    own = httpx.get(f"{REALM}/app-registration/other.example/access-state", auth=(other["clientId"], other["secret"]))
    api.delete(f"/clients/{pf.client_rep(api, 'other.example')['id']}").raise_for_status()
    check("...no other client can read it, and each has its own", set(refused.values()) == {401}
          and own.status_code == 200 and own.json()["hash"] != first.json()["hash"], json.dumps(refused))
    check("...not in the family realm", httpx.get(f"{KC}/realms/family/app-registration/{DOMAIN}/access-state", auth=basic).status_code == 404)

    def site(**kwargs) -> CountingCheck:
        return CountingCheck(REALM, DOMAIN, CLIENT["client_secret"], role="opportunity", **{"hash_ttl": 0, **kwargs})

    bob_token = signed_in_token(browser, BOB)
    bob = site()
    decision = bob.check(BOB, bob_token)
    check("a first request: one full check at userinfo, with the person's roles",
          decision.allowed and "opportunity" in decision.roles and bob.count("userinfo") == 1, str(decision))
    for _ in range(3):
        decision = bob.check(BOB, bob_token)
    check("an unchanged hash: no userinfo call, however many requests", decision.allowed and bob.count("userinfo") == 1
          and bob.count("hash") == 4, str(bob.calls))
    signed_in_token(browser, DANA)
    bob.check(BOB, bob_token)
    check("someone else signing in changes nothing", bob.count("userinfo") == 1
          and httpx.get(url, auth=basic).json()["hash"] == bob._known)
    cached = site(hash_ttl=2)
    for _ in range(3):
        cached.check(BOB, bob_token)
    check("the hash is fetched once in its 2 seconds, not per request", cached.count("hash") == 1, str(cached.calls))
    quiet = site(hash_ttl=2)
    time.sleep(0.1)
    check("a site with no requests asks nothing: there is no timer", quiet.calls == [])

    held = "plan" in bob.check(BOB, bob_token).roles
    rep = pf.client_rep(api, DOMAIN)
    role = api.get(f"/clients/{rep['id']}/roles/plan").json()
    bob_id = user(api, BOB)["id"]
    api.request("DELETE", f"/users/{bob_id}/role-mappings/clients/{rep['id']}", json=[role]).raise_for_status()
    decision = bob.check(BOB, bob_token)
    check("a role taken away through the admin API: the hash changes, one full check, gone at the next request",
          held and decision.allowed and "plan" not in decision.roles and bob.count("userinfo") == 2, str(decision))
    bob.check(BOB, bob_token)
    check("...and then quiet again", bob.count("userinfo") == 2)
    d_page.reload()
    act(d_page, role_button(BOB, "opportunity"))
    decision = bob.check(BOB, bob_token)
    check("the site's own role taken away on the page: refused at the next request, without new sign-in",
          not decision.allowed and decision.reason == access_check.NO_ROLE and "opportunity" not in decision.roles, str(decision))
    act(d_page, role_button(BOB, "opportunity"))
    check("...ticked again: allowed at the next request", bob.check(BOB, bob_token).allowed)
    act(d_page, action_button(BOB, "remove"))
    decision = bob.check(BOB, bob_token)
    check("removed from all: refused at the next request, told to sign in", not decision.allowed
          and decision.reason == access_check.SIGN_IN and decision.roles == frozenset(), str(decision))
    check("...and it stays refused", not bob.check(BOB, bob_token).allowed)

    now = [0.0]
    anna_token = signed_in_token(browser, ANNA)
    anna = site(clock=lambda: now[0], full_every=300)
    anna.check(ANNA, anna_token)
    now[0] = 299.0
    anna.check(ANNA, anna_token)
    before = anna.count("userinfo")
    now[0] = 301.0
    check("the hash unchanged, a full check all the same after N minutes", anna.check(ANNA, anna_token).allowed
          and before == 1 and anna.count("userinfo") == 2, str(anna.calls))

    down = site()
    dana_token = signed_in_token(browser, DANA)
    down.check(ANNA, anna_token)
    live = down.realm_url
    down.realm_url = "http://127.0.0.1:9/realms/team"  # nothing listens there: Keycloak unreachable
    reading = down.check(ANNA, anna_token)
    writing = down.check(ANNA, anna_token, write=True)
    stranger = down.check(CONTROLLER, "some-token")
    check("Keycloak down: reads go on with the last roles, changes are refused, someone not vouched for is refused",
          reading.allowed and reading.reason == access_check.DEGRADED and "opportunity" in reading.roles
          and not writing.allowed and writing.reason == access_check.UNAVAILABLE
          and not stranger.allowed and stranger.reason == access_check.UNAVAILABLE,
          f"{reading} {writing} {stranger}")
    down.realm_url = live
    check("...and back: as before", down.check(ANNA, anna_token, write=True).allowed)
    d_page.reload()
    act(d_page, role_button(ANNA, "release"))
    down.check(DANA, dana_token)  # the new hash reaches the site; anna has not been checked under it
    down.realm_url = "http://127.0.0.1:9/realms/team"
    missed = down.check(ANNA, anna_token)
    check("...someone whose stored hash is out of date when Keycloak goes is refused, even to read",
          not missed.allowed and missed.reason == access_check.UNAVAILABLE, str(missed))
    down.realm_url = live
    act(d_page, role_button(ANNA, "release"))


@contextmanager
def gate_worker(realm_url: str, persist: Path):
    """edge-gate/gate.js under wrangler dev, in front of dev/edge-gate/site, asking this realm."""
    (GATE_DIR / ".dev.vars").write_text(f'REALM_URL="{realm_url}"\nCLIENT_ID="{DOMAIN}"\n'
                                        f'CLIENT_SECRET="{CLIENT["client_secret"]}"\nSESSION_KEY="{"proof-session-key-" * 3}"\n')
    with (OUT / "wrangler.log").open("a") as log:
        run = subprocess.Popen(["npx", "--yes", WRANGLER, "dev", "--config", str(GATE_DIR / "wrangler.toml"), "--ip", "127.0.0.1",
                                "--port", str(GATE_PORT), "--persist-to", str(persist), "--show-interactive-dev-session=false"],
                               cwd=GATE_DIR, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True,
                               env={**os.environ, "WRANGLER_SEND_METRICS": "false"})

    def up() -> bool:
        try:
            return httpx.get(f"{GATE}/healthz", timeout=2).status_code == 200
        except httpx.TransportError:
            return False

    try:
        if not pf.wait_until(up, timeout=120):
            raise RuntimeError(f"wrangler dev did not start; see {OUT / 'wrangler.log'}")
        yield
    finally:
        os.killpg(run.pid, signal.SIGTERM)
        run.wait(timeout=20)
        (GATE_DIR / ".dev.vars").unlink(missing_ok=True)
        pf.wait_until(lambda: not up(), timeout=20)


def gate_session(browser, email: str):
    """A browser signing in at the gate; its context and the sign-in's last response body."""
    context = browser.new_context()
    page = context.new_page()
    page.goto(f"{GATE}/")
    page.wait_for_selector("input[name=username]")
    code_in(page, email)
    page.wait_for_url(f"{GATE}/**", timeout=20000)
    page.wait_for_load_state()
    return context, page.inner_text("body")


def at_gate(context, method: str = "get"):
    """One request at the gate in this browser's session, redirects not followed."""
    return getattr(context.request, method)(f"{GATE}/", max_redirects=0)


def the_gate(api: httpx.Client, browser, d_page) -> None:
    unit = subprocess.run(["node", "--test", str(HERE.parent / "edge-gate" / "gate.test.js")], capture_output=True, text=True, check=False)
    passed = re.search(r"^# pass (\d+)", unit.stdout, re.M)
    check("the gate's own tests, against a made-up Keycloak", unit.returncode == 0, f"{passed and passed.group(1)} passed")
    rep = pf.client_rep(api, DOMAIN)
    callback = f"{GATE}/oauth2/callback"
    rep["redirectUris"] = rep["redirectUris"] + [callback]  # test only: the admin API, not register-app.py
    api.put(f"/clients/{rep['id']}", json=rep).raise_for_status()
    persist = Path(tempfile.mkdtemp(prefix="team-gate-"))
    dead = "http://127.0.0.1:9/realms/team"  # nothing listens there: Keycloak unreachable
    try:
        with gate_worker(REALM, persist):
            signed_out = httpx.get(f"{GATE}/", follow_redirects=False)
            started = httpx.get(f"{GATE}{signed_out.headers.get('location', '')}", follow_redirects=False)
            check("the gate, signed out: the page is not served, and the browser goes to the team realm (PKCE)",
                  signed_out.status_code == 303 and "Behind the gate" not in signed_out.text
                  and started.headers.get("location", "").startswith(f"{REALM}/protocol/openid-connect/auth?")
                  and "code_challenge_method=S256" in started.headers.get("location", ""), started.headers.get("location", "")[:120])
            check("...only /healthz is open", httpx.get(f"{GATE}/healthz").text.strip() == "ok")
            anna, body = gate_session(browser, ANNA)
            check("someone with the role signs in with the realm and gets the page", "Behind the gate" in body, body[:120])
            cookie = next((c for c in anna.cookies() if c["name"] == "__Host-sustenaut-gate"), {})
            check("...the session cookie: HttpOnly, Secure, SameSite=Lax, under a cookie's size limit, nothing readable in it",
                  cookie.get("httpOnly") and cookie.get("secure") and cookie.get("sameSite") == "Lax" and 0 < len(cookie.get("value", "")) < 4000
                  and ANNA not in str(base64.urlsafe_b64decode(cookie["value"].split(".")[1] + "==")), f"{len(cookie.get('value', ''))} characters")
            check("...it stays signed in", at_gate(anna).status == 200)
            dana, body = gate_session(browser, DANA)
            check("someone with another service's role is refused the page", "Behind the gate" not in body and at_gate(dana).status == 403, body[:120])
            registrant, body = gate_session(browser, REGISTRANT)
            check("...and so is the registrant, with no roles", "Behind the gate" not in body and at_gate(registrant).status == 403)

            forger = browser.new_context()
            real = cookie["value"]
            flipped = real[:-3] + ("AAA" if not real.endswith("AAA") else "BBB")
            base = {"name": "__Host-sustenaut-gate", "domain": "localhost", "path": "/", "secure": True, "httpOnly": True, "sameSite": "Lax"}
            results = {}
            for name, value in {"altered": flipped, "made up": "e30.e30", "plain": "{}"}.items():
                forger.clear_cookies()
                forger.add_cookies([{**base, "value": value}])
                response = at_gate(forger)
                results[name] = response.status == 303 and "/oauth2/start" in response.headers.get("location", "")
            check("a forged or altered cookie is refused: sign in", all(results.values()), json.dumps(results))

            d_page.reload()
            act(d_page, role_button(ANNA, "opportunity"))
            time.sleep(2.2)
            check("the role taken away on the access page: refused at the next request, no new sign-in", at_gate(anna).status == 403)
            act(d_page, role_button(ANNA, "opportunity"))
            time.sleep(2.2)
            check("...ticked again: the page at the next request", at_gate(anna).status == 200)

            d_page.fill("#access-invite input[name=email]", ERIN)
            d_page.check('#access-invite input[value="sustenaut.eu/opportunity"]')
            act(d_page, "#access-invite button")
            erin, body = gate_session(browser, ERIN)
            allowed = "Behind the gate" in body
            act(d_page, action_button(ERIN, "remove"))
            time.sleep(2.2)
            gone = at_gate(erin)
            check("removed from all: refused at the next request, told to sign in, the cookie gone", allowed and gone.status == 303
                  and "/oauth2/start" in gone.headers.get("location", "")
                  and not [c for c in erin.cookies() if c["name"] == "__Host-sustenaut-gate"], f"{gone.status} {gone.headers.get('location', '')[:80]}")
            at_gate(anna)  # the last hash the gate knows, for Keycloak going away

        with gate_worker(dead, persist):
            reading, changing = at_gate(anna), at_gate(anna, "post")
            check("Keycloak down: someone signed in goes on reading, on the last hash; changes are refused",
                  reading.status == 200 and "Behind the gate" in reading.text() and changing.status == 503, f"{reading.status} {changing.status}")
            new = browser.new_context()
            first = at_gate(new)
            check("...someone new is sent to sign in, which waits for Keycloak; the page is not served",
                  first.status == 303 and "Behind the gate" not in first.text())

        with gate_worker(REALM, persist):
            d_page.reload()
            act(d_page, role_button(ANNA, "plan"))
            time.sleep(2.2)
            at_gate(dana)  # the gate learns the new hash from someone else; anna's session has not been checked under it
        with gate_worker(dead, persist):
            stale = at_gate(anna)
            check("...a session whose hash is out of date when Keycloak goes is refused, even to read", stale.status == 503, str(stale.status))
        d_page.reload()
        act(d_page, role_button(ANNA, "plan"))
    finally:
        rep = pf.client_rep(api, DOMAIN)
        rep["redirectUris"] = [u for u in rep["redirectUris"] if u != callback]
        api.put(f"/clients/{rep['id']}", json=rep).raise_for_status()


def what_survives(api: httpx.Client, browser, d_page) -> None:
    """A new registration and the realm job leave the list alone; the placeholder from the page."""
    def held() -> tuple[set, set]:
        return roles_of(api, ANNA), roles_of(api, DANA)

    rerun = os.environ.get("REALM_RERUN")
    wanted = held()
    if rerun:
        ran = subprocess.run(rerun, shell=True, cwd=HERE.parent, capture_output=True, text=True, check=False)
        realm_roles = {r["name"] for r in api.get("/roles").json()}
        controller = {r["name"] for r in api.get(f"/users/{user(api, CONTROLLER)['id']}/role-mappings/realm").json()}
        check("the realm job (run again as in production) leaves the roles, who holds them, and the mapper alone",
              ran.returncode == 0 and held() == wanted and "controller" in realm_roles and "controller" in controller
              and {"offline_access", "uma_authorization"} <= realm_roles
              and [m["protocolMapper"] for m in pf.client_rep(api, DOMAIN).get("protocolMappers", [])] == ["sustenaut-access"],
              f"exit {ran.returncode}; {ran.stderr[-200:] if ran.returncode else ''}")
    else:
        print("INFO REALM_RERUN not set: realm-job rerun not checked")

    def register_anew(keep: list[str]) -> tuple[int, dict, dict]:
        """A registration from nothing, its record published beside the values in keep."""
        state = Path(tempfile.mkdtemp(prefix="team-reregistration-"))
        _, first = register(browser, state, CALLBACK)
        pf.publish({RECORD: [*keep, first["record"]["value"]]})
        code, done = register(browser, state, CALLBACK)
        newer = json.loads((state / "client.json").read_text()) if (state / "client.json").exists() else {}
        CLIENT.update(newer, record=first["record"]["value"])
        return code, done, newer

    old_secret = CLIENT["client_secret"]
    code, done, newer = register_anew([CLIENT["record"]])
    check("a new registration replaces the client (the old one revoked), and the list goes with it",
          code == 0 and newer.get("client_secret") not in (None, old_secret)
          and held() == wanted and bool(wanted[0]) and bool(pf.by_state(api, "revoked")),
          f"{json.dumps(done)}; before {wanted}, after {held()}")

    pf.publish({})
    check("the record gone: the re-check revokes the client", pf.wait_until(
        lambda: (pf.client_rep(api, DOMAIN) or {}).get("id") is None, timeout=40))
    code, done, newer = register_anew([])
    rep = pf.client_rep(api, DOMAIN) or {}
    check("registering again after that: the list comes back from the revoked client, with the mapper",
          code == 0 and held() == wanted and bool(wanted[0])
          and [m["protocolMapper"] for m in rep.get("protocolMappers", [])] == ["sustenaut-access"],
          f"{json.dumps(done)}; before {wanted}, after {held()}")

    api.delete(f"/clients/{pf.client_rep(api, DOMAIN)['id']}").raise_for_status()
    d_page.reload()
    d_page.fill("#access-declare input[name=name]", "first-site")
    act(d_page, "#access-declare button")
    rep = pf.client_rep(api, DOMAIN) or {}
    check("no client at all: declaring on the page makes the switched-off placeholder, with the mapper",
          rep.get("enabled") is False and rep.get("attributes", {}).get("sustenaut.app.state") == "declared"
          and [m["protocolMapper"] for m in rep.get("protocolMappers", [])] == ["sustenaut-access"]
          and "first-site" in d_page.locator("#access-table thead").inner_text())


def removal(api: httpx.Client, browser, anna_phone) -> None:
    context, site, page = anna_phone
    site.start(page)  # anna still has a Keycloak session here: straight through
    check("before: anna's browser goes straight through on her session", site.tokens(page) is not None)
    run = invite_team(BOB)
    anna = user(api, ANNA)
    check("invite-team.sh with anna out of the list disables her account", run.returncode == 0
          and anna.get("enabled") is False and "Disabled the account of " + ANNA in run.stdout,
          (run.stdout + run.stderr).strip().replace("\n", " | ")[:300])
    check("...and keeps the registrant and bob", user(api, REGISTRANT).get("enabled") is True
          and user(api, BOB).get("enabled") is True)
    site.start(page)
    check("...and signs her out everywhere: her session no longer lets her in", site.tokens(page, wait=6) is None)
    context.clear_cookies()
    site.start(page)
    check("...and her passkey no longer works", site.tokens(page, wait=8) is None)
    page.screenshot(path=OUT / "4-disabled-passkey.png")
    before = len(mails_to(ANNA))
    run = invite_team(ANNA, BOB)
    check("put back in the list, her account is switched on and invited again", run.returncode == 0
          and user(api, ANNA).get("enabled") is True and wait_for_mail(ANNA, "Your invitation", 1) is not None
          and len(mails_to(ANNA)) > before, run.stdout.strip().replace("\n", " | ")[:200])
    context.clear_cookies()
    site.start(page)
    check("...and her passkey works again", site.tokens(page) is not None)


def main() -> int:
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)
    api = admin()
    for old in api.get("/users", params={"max": 1000}).json():  # start clean
        api.delete(f"/users/{old['id']}").raise_for_status()
    for old in [c for c in api.get("/clients").json() if c.get("attributes", {}).get("sustenaut.app.state")]:
        api.delete(f"/clients/{old['id']}").raise_for_status()
    httpx.delete(f"{pf.MAILPIT}/messages").raise_for_status()

    # 1. Invite, before any client exists (as on go-live: the registrant needs an account).
    run = invite_team(ANNA.upper(), BOB, f" {BOB} ")
    accounts = {u["email"]: u for u in api.get("/users").json()}
    check("invite-team.sh creates the members' accounts and the registrant's, nothing else", run.returncode == 0
          and set(accounts) == {ANNA, BOB, REGISTRANT}, (run.stdout + run.stderr).strip().replace("\n", " | ")[:300])
    check("the accounts: username = email (lower case), verified, enabled, no credentials",
          all(u["username"] == e and u["emailVerified"] and u["enabled"]
              and api.get(f"/users/{u['id']}/credentials").json() == [] for e, u in accounts.items()))
    again = invite_team(ANNA, BOB)
    check("running it again changes nothing and sends nothing new", again.returncode == 0
          and len([m for m in mails_to(ANNA) if m["Subject"].startswith("Your invitation")]) == 1
          and "Created" not in again.stdout and "Sent" not in again.stdout, again.stdout.strip()[:200])
    empty = invite_team()
    check("an empty team list is refused (it would disable everyone)", empty.returncode != 0
          and all(u["enabled"] for u in api.get("/users").json()))

    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel=os.environ.get("PW_CHANNEL", "chrome"),
                                     args=["--host-resolver-rules=MAP opportunity.sustenaut.eu ~NOTFOUND, MAP plan.sustenaut.eu ~NOTFOUND"])
        # 1b. The access list imported before anything has registered.
        declared_first(admin())
        # 2. sustenaut.eu registers for sign-in, for the opportunity site.
        registration(admin(), browser)
        # 3. Sign-in: passkey, emailed code, refusals.
        anna_phone = sign_ins(admin(), browser)
        # 4. oauth2-proxy as the opportunity site runs it.
        through_proxy(admin(), browser)
        # 5. Taken out of var.team, and put back.
        removal(admin(), browser, anna_phone)
        # 6. The access page, oauth2-proxy by role, and what survives a new registration or the realm job.
        d_context, d_page = the_page(admin(), browser, anna_phone)
        by_role(admin(), browser, d_context, d_page)
        the_hash(admin(), browser, d_page)
        the_gate(admin(), browser, d_page)
        what_survives(admin(), browser, d_page)
        browser.close()

    api = admin()
    check("no account for the address that was not invited", user(api, STRANGER) == {})
    signup = httpx.get(f"{REALM}/protocol/openid-connect/registrations", params={
        "client_id": DOMAIN, "response_type": "code", "scope": "openid", "redirect_uri": CALLBACK})
    reset = httpx.get(f"{REALM}/login-actions/reset-credentials", params={"client_id": DOMAIN})
    check("no self-registration and no reset flow", signup.status_code == 400 and reset.status_code == 400,
          f"registrations {signup.status_code}, reset-credentials {reset.status_code}")
    check("account console is switched off", httpx.get(f"{REALM}/account/").status_code != 200)
    family = httpx.get(f"{KC}/realms/family/.well-known/openid-configuration")
    check("the family realm is still there beside it", family.status_code == 200)
    results = pf.results
    print(f"\n{sum(ok for _, ok, _ in results)}/{len(results)} checks passed; screenshots in {OUT}")
    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
