# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.27", "playwright>=1.50"]
# ///
"""End-to-end proof of the family realm (realm/family.json) against the local compose stack.

First example.net registers for sign-in the way a tenant's setup script does (app-registration):
registrant@example.net signs in with the device flow, asks, publishes the record at the compose
stack's nameserver (ns1, which signs example.net: DNSSEC from a local trust anchor), verifies; with the refusals around it, a replacement
registration revoking the first client, and the realm job run again. Then the domain stores
its settings (name, home page, words) and invites a friend with its own credentials; the
invitation (from mailpit) is in its words; invite-family.sh, the admin fallback, in neutral
ones. The domain looks its people up (none, invited, active: signed in at least once,
any method, the invitation's own sign-in included; only those it invited), and is told of
each one's first sign-in at its notify_url (signed with its client secret; once; only its
own people; nothing while it has no notify_url). The invitation
signs the friend in; the passkey offer that follows sets up a passkey in Chrome with a
virtual authenticator; then the friend signs in to the share-portal client with the
passkey and, in a browser without it, by email (link and code: in the browser that asked,
on another device, once, expiring).
Every passkey added emails a notice: the first (Set up in the offer that follows the
invitation's sign-in) and one added later on
another device (an app asking for it with kc_action), in the domain's words; someone no
domain invited gets it in neutral words.
Checks that an address without an account gets neither a code nor an account, that no
page has a password field and no password is accepted, that the ID token carries the
email, and that the sustenaut realm's wallet page and the family page stay apart.

Then removal: the domain removes people (/remove; only its own, the same answer for
anyone), sessions end, the last domain switches the account off and stamps it, another
domain keeps it, "moved" changes the email's words, an invitation switches a removed
account on again (not one an admin locked), people leave themselves ("Remove my access",
kc_action=sustenaut-leave: cancel and confirm), remove-family.sh (the admin fallback), and
the daily job (every 5 s here) deletes accounts removed 30 or more days ago.

Last, the weekly check (every 5 s here): no definite answer (answers that don't
validate, or no answers at all) revokes nothing; the record gone at both, twice in a
row, revokes the client and emails the registrant; putting it back does not undo that; a
revoked client is deleted after 30 days. Then the domain registers again and deregisters
(DELETE): revoked at once, and when its client is deleted its people lose access.

The share-portal redirect (https://share.example.net/oauth2/callback) is read from the
browser's requests; Chrome is told the host does not exist, so nothing reaches it.

  uv run dev/prove_family.py     # stack must be up: podman compose up -d


REALM_RERUN, if set, is a command that runs the realm job again as production does
(remote state on); the proof checks the registered client survives it, e.g.
  REALM_RERUN="podman compose run --rm -e IMPORT_REMOTESTATE_ENABLED=true \
    -e IMPORT_MANAGED_CLIENT=full -e IMPORT_FILES_LOCATIONS=/config/family.json realm"
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

import httpx
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
# The compose stack's addresses; AUTH_KC, AUTH_KC_ADMIN, AUTH_MAILPIT and AUTH_NS1 point the
# proof at a second stack (other ports and subnet, e.g. beside another checkout's).
KC = os.environ.get("AUTH_KC", "http://localhost:8080")
KC_ADMIN = os.environ.get("AUTH_KC_ADMIN", "http://localhost:8180")
# The admin scripts run with this environment: never SUSTENAUT_SERVER, so they act on the
# local stack (KEYCLOAK_ADMIN_URL) or stop; never the live server (admin-api.sh).
LOCAL_ENV = {k: v for k, v in os.environ.items() if k != "SUSTENAUT_SERVER"}
NS1 = os.environ.get("AUTH_NS1", "10.89.77.11")
REALM = f"{KC}/realms/family"
MAILPIT = os.environ.get("AUTH_MAILPIT", "http://localhost:8025") + "/api/v1"
HOOKS = os.environ.get("AUTH_HOOKS", "http://localhost:8035")  # compose's hooks (dev/hooks.py)
NOTIFY_URL = "https://hooks.example.net/hooks/auth"  # the domain's notify_url: hooks, in the stack
CALLBACK = "https://share.example.net/oauth2/callback"
LEFT = "https://share.example.net/left"  # where the portal's "Remove my access" comes back (not oauth2-proxy)
OUT = HERE / ".pki" / "proof-family"
ENV = dict(
    line.split("=", 1)
    for line in (HERE.parent / ".env").read_text().splitlines()
    if "=" in line and not line.startswith("#")
)
REGISTER = f"{REALM}/app-registration"
ZONES = HERE / "dns" / "zones"
CLIENT: dict = {}  # the domain's client (id example.net, what share-portal uses), from the registration
FRIEND = "anna.example@example.org"
FALLBACK = "fallback.example@example.org"
CODER = "ben.example@example.org"  # invited, signs in only with emailed codes (no passkey)
TENANT = {  # what the domain's own repository's auth-tenant.json holds
    "display_name": "The Example family",
    "home_url": "https://share.example.net/",
    "invite_intro": "The Example family has invited you to see the photos they share with you.",
    "help_contact": "the person who invited you",
}
STRANGER = "nobody@example.org"
LINKED = "cleo.example@example.org"  # signs in by emailed link and code, never sets up a passkey
SIGN_IN_MAIL = "Your sign-in link"
THIRTY_DAYS = 30 * 24 * 3600

results = []


def check(name: str, ok: bool, detail: str = "") -> None:
    ok = bool(ok)
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail else ""), flush=True)


def jwt_claims(token: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))


class _AdminToken(httpx.Auth):
    """The master admin's token, fetched again before it expires (it lives a minute)."""

    def __init__(self):
        self.token, self.fetched = None, 0.0

    def auth_flow(self, request):
        if time.time() - self.fetched > 45:
            self.token = httpx.post(
                f"{KC}/realms/master/protocol/openid-connect/token",
                data={"grant_type": "password", "client_id": "admin-cli", "username": "admin",
                      "password": ENV["KC_ADMIN_PASSWORD"]},
            ).raise_for_status().json()["access_token"]
            self.fetched = time.time()
        request.headers["Authorization"] = f"Bearer {self.token}"
        yield request


def admin() -> httpx.Client:
    return httpx.Client(base_url=f"{KC}/admin/realms/family", auth=_AdminToken())


def mails_to(address: str) -> list[dict]:
    found = httpx.get(f"{MAILPIT}/search", params={"query": f"to:{address}"}).raise_for_status().json()
    return found["messages"]


def wait_for_mail(address: str, subject: str, after: int, timeout: float = 20) -> dict | None:
    """The newest mail to address with subject, once more than `after` mails have arrived."""
    end = time.time() + timeout
    while time.time() < end:
        mails = [m for m in mails_to(address) if m["Subject"].startswith(subject)]
        if len(mails) > after:
            return httpx.get(f"{MAILPIT}/message/{mails[0]['ID']}").raise_for_status().json()
        time.sleep(0.5)
    return None


_serial = [int(time.time()) - 1_700_000_000]
DOMAIN = "example.net"
RECORD = f"_sustenaut-auth.{DOMAIN}"
REGISTRANT = f"registrant@{DOMAIN}"
OUTSIDER = "eve@sustenaut.eu"


def publish(records: dict[str, list[str]], ns: str = "ns1") -> None:
    """Writes the zones the local nameserver serves: {fqdn: [TXT values]}. It signs both
    on the fly (DNSSEC); this realm trusts example.net's key only."""
    _serial[0] += 1
    for zone in ("example.net", "sustenaut.eu"):
        lines = [f"$ORIGIN {zone}.", f"@ 300 IN SOA ns1.{zone}. admin.{zone}. {_serial[0]} 7200 3600 1209600 5",
                 "@ 300 IN NS ns1", f"ns1 300 IN A {NS1}"]
        for name, values in records.items():
            if name == zone or name.endswith("." + zone):
                lines += [f'{name}. 5 IN TXT "{v}"' for v in values]
        (ZONES / ns / f"{zone}.zone").write_text("\n".join(lines) + "\n")
    time.sleep(2.5)  # CoreDNS reloads every second


def set_realm(api: httpx.Client, **attributes: str) -> None:
    rep = api.get("").json()
    rep["attributes"].update({f"sustenaut.appRegistration.{k}": v for k, v in attributes.items()})
    api.put("", json={"attributes": rep["attributes"]}).raise_for_status()


def device_token(browser, email: str) -> str:
    """The registrant signs in with the device flow of app-registration, as a tenant's setup script
    has them do: open the link, an emailed code (no passkey on this browser)."""
    start = httpx.post(f"{REALM}/protocol/openid-connect/auth/device", data={"client_id": "app-registration"}).json()
    page = browser.new_context().new_page()
    page.goto(start["verification_uri_complete"])
    before = len([m for m in mails_to(email) if m["Subject"].startswith(SIGN_IN_MAIL)])
    page.fill("input[name=username]", email)
    page.click("#kc-login")
    page.wait_for_selector("input[name=code]")
    mail = wait_for_mail(email, SIGN_IN_MAIL, before, timeout=10)
    page.fill("input[name=code]", link_and_code(mail)[1])
    page.click("#kc-login")
    page.click("[name=accept]")  # Keycloak asks: grant this device access? Yes.
    page.wait_for_load_state()
    for _ in range(12):
        time.sleep(start.get("interval", 5) + 0.5)
        answer = httpx.post(f"{REALM}/protocol/openid-connect/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "client_id": "app-registration",
            "device_code": start["device_code"]})
        if answer.status_code == 200:
            return answer.json()["access_token"]
    raise RuntimeError(f"device flow did not finish: {answer.text}; page: {page.inner_text('body')[:300]}")


def ask(token: str | None, domain: str, redirects: list[str], logouts: list[str] | None = None) -> httpx.Response:
    return httpx.post(REGISTER, headers={"Authorization": f"Bearer {token}"} if token else {},
                      json={"domain": domain, "redirect_uris": redirects, "post_logout_redirect_uris": logouts or []})


def verify(token: str, request: dict, tries: int = 1) -> httpx.Response:
    """Verify; with tries > 1, asks again after a 409 as an app would (a nameserver reload can lag)."""
    for attempt in range(tries):
        answer = httpx.post(request["verify_url"], headers={"Authorization": f"Bearer {token}"})
        if answer.status_code != 409 or attempt == tries - 1:
            return answer
        time.sleep(2)
    return answer


def client_rep(api: httpx.Client, client_id: str) -> dict | None:
    found = api.get("/clients", params={"clientId": client_id}).json()
    return found[0] if found else None


def by_state(api: httpx.Client, state: str) -> list[dict]:
    return [c for c in api.get("/clients").json() if c.get("attributes", {}).get("sustenaut.app.state") == state]


def set_family_attribute(api: httpx.Client, name: str, value: str) -> None:
    """A realm attribute of the family sign-in (blank: its default)."""
    rep = api.get("").json()
    rep["attributes"][name] = value
    api.put("", json={"attributes": rep["attributes"]}).raise_for_status()


def wait_until(test, timeout: float = 30) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if test():
            return True
        time.sleep(1)
    return False


def notices_for(email: str) -> list[dict]:
    """The first-sign-in notices hooks took for email: {"path", "headers", "body"} each."""
    return [n for n in httpx.get(f"{HOOKS}/received").raise_for_status().json()
            if json.loads(n["body"] or "{}").get("email") == email]


def wait_for_notice(email: str, count: int = 1, timeout: float = 15) -> list[dict]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        found = notices_for(email)
        if len(found) >= count:
            return found
        time.sleep(0.5)
    return notices_for(email)


def notice_ok(notice: dict, secret: str) -> bool:
    """Signed as SignInNotice says: sha256=HMAC(secret, timestamp + "." + body), timestamp now-ish."""
    stamp = notice["headers"].get("x-sustenaut-timestamp", "")
    want = "sha256=" + hmac.new(secret.encode(), f"{stamp}.{notice['body']}".encode(), hashlib.sha256).hexdigest()
    return (stamp.isdigit() and abs(time.time() - int(stamp)) < 300
            and hmac.compare_digest(notice["headers"].get("x-sustenaut-signature", ""), want))


def person(email: str, auth=None) -> httpx.Response:
    """GET {domain}/people: where someone the domain invited stands (none, invited, active)."""
    return httpx.get(f"{REGISTER}/{DOMAIN}/people", params={"email": email},
                     auth=auth or (CLIENT["client_id"], CLIENT["client_secret"]))


def status_of(email: str) -> str | None:
    answer = person(email)
    return answer.json().get("status") if answer.status_code == 200 else f"HTTP {answer.status_code}"


def make_user(api: httpx.Client, email: str) -> None:
    for old in api.get("/users", params={"email": email, "exact": "true"}).json():
        api.delete(f"/users/{old['id']}").raise_for_status()
    api.post("/users", json={"username": email, "email": email, "emailVerified": True, "enabled": True}).raise_for_status()


def register(api: httpx.Client) -> None:
    """The portal's domain registers for sign-in, as a tenant's setup script does; the refusals around it."""
    for old in [c for c in api.get("/clients").json() if c.get("attributes", {}).get("sustenaut.app.state")]:
        api.delete(f"/clients/{old['id']}").raise_for_status()
    for email in (REGISTRANT, OUTSIDER):
        make_user(api, email)
    publish({})
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel=os.environ.get("PW_CHANNEL", "chrome"))
        token = device_token(browser, REGISTRANT)
        outsider = device_token(browser, OUTSIDER)
        browser.close()
    check("the registrant signs in with the device flow (passkey or emailed code): token for app-registration",
          jwt_claims(token).get("azp") == "app-registration" and jwt_claims(token).get("email") == REGISTRANT)

    share = [CALLBACK]
    check("registration refused without signing in", ask(None, DOMAIN, share).status_code == 401)
    wrong = ask(outsider, DOMAIN, share)
    check("registration refused for an email address not at the domain (eve@sustenaut.eu for example.net)",
          wrong.status_code == 403, wrong.text[:120])
    bad = {
        "a domain not on the realm's list": ask(token, "example.org", ["https://example.org/cb"]),
        "a subdomain as the domain": ask(token, "share.example.net", share),
        "a redirect outside the domain": ask(token, DOMAIN, ["https://evil.example/cb"]),
        "a lookalike host": ask(token, DOMAIN, ["https://share.example.net.evil.example/cb"]),
        "plain http": ask(token, DOMAIN, ["http://share.example.net/cb"]),
        "a wildcard": ask(token, DOMAIN, ["https://share.example.net/*"]),
    }
    for what, response in bad.items():
        check(f"registration request refused: {what}", response.status_code == 400,
              f"{response.status_code} {response.text[:100]}")

    asked = ask(token, DOMAIN, [CALLBACK, "https://recipes.example.net/oauth2/callback"], ["https://share.example.net/"])
    req = asked.json()
    check("the request (two hosts under the domain) gets the TXT record for the domain and a verify URL",
          asked.status_code == 201 and req["record"]["name"] == RECORD
          and re.fullmatch(r"sa1=[0-9a-f]{64}", req["record"]["value"]) is not None, json.dumps(req.get("record")))
    pending = client_rep(api, "pending-" + req["id"])
    check("until verified, the request is a disabled client keeping the registrant, not the token",
          pending is not None and pending["enabled"] is False
          and pending["attributes"].get("sustenaut.app.registrant") == REGISTRANT
          and req["record"]["value"][4:] not in json.dumps(pending))

    check("verify by someone else: refused", verify(outsider, req).status_code == 404)
    early = verify(token, req)
    check("verify before the record exists: 409, try again later", early.status_code == 409, early.text[:100])
    publish({RECORD: ["sa1=" + "0" * 64]})
    check("a record with another token: still 409", verify(token, req).status_code == 409)

    anchors = api.get("").json()["attributes"]["sustenaut.appRegistration.trustAnchors"]
    set_realm(api, trustAnchors="example.net. IN DS 1 13 2 " + "00" * 32)
    publish({RECORD: [req["record"]["value"]]})
    bogus = verify(token, req)
    check("the record is there but does not validate (wrong trust anchor): 409, nothing issued",
          bogus.status_code == 409, bogus.json().get("message", "")[:140])
    set_realm(api, trustAnchors=anchors)
    done = verify(token, req, tries=3)
    CLIENT.clear()
    CLIENT.update(done.json() if done.status_code == 200 else {}, record=req["record"]["value"])
    check("the record is there and validates (DNSSEC): the client (id = the domain) is issued",
          done.status_code == 200 and CLIENT.get("client_id") == DOMAIN and len(CLIENT.get("client_secret", "")) > 20
          and CLIENT.get("registration_access_token"), done.text[:120])
    rep = client_rep(api, DOMAIN) or {}
    attrs = rep.get("attributes", {})
    check("the issued client: enabled, confidential, code flow + PKCE S256 only, openid/email/profile",
          rep.get("enabled") is True and rep.get("publicClient") is False and rep.get("standardFlowEnabled") is True
          and not rep.get("implicitFlowEnabled") and not rep.get("directAccessGrantsEnabled")
          and not rep.get("serviceAccountsEnabled") and rep.get("fullScopeAllowed") is False
          and attrs.get("pkce.code.challenge.method") == "S256"
          and set(rep.get("defaultClientScopes", [])) == {"basic", "email", "profile", "web-origins", "acr"}
          and set(rep.get("redirectUris", [])) == {CALLBACK, "https://recipes.example.net/oauth2/callback"},
          json.dumps({k: rep.get(k) for k in ("enabled", "redirectUris", "defaultClientScopes")}))
    check("the credentials are given once: verify again is refused", verify(token, req).status_code == 404)

    unsigned = ask(outsider, "sustenaut.eu", ["https://app.sustenaut.eu/oauth2/callback"]).json()
    publish({RECORD: [req["record"]["value"]], "_sustenaut-auth.sustenaut.eu": [unsigned["record"]["value"]]})
    plain = verify(outsider, unsigned, tries=2)
    check("a domain the realm can't validate (sustenaut.eu here: no trust anchor for it) can't register (409)",
          plain.status_code == 409 and client_rep(api, "sustenaut.eu") is None, plain.json().get("message", "")[:140])
    publish({RECORD: [req["record"]["value"]]})

    expired = ask(token, DOMAIN, share).json()
    late = client_rep(api, "pending-" + expired["id"])
    late["attributes"]["sustenaut.app.expires"] = str(int(time.time()) - 1)
    api.put(f"/clients/{late['id']}", json=late).raise_for_status()
    publish({RECORD: [req["record"]["value"], expired["record"]["value"]]})
    gone = verify(token, expired)
    # 410 if verify comes first, 404 if the re-check already removed it.
    check("an expired request cannot be verified, even with its record published, and is removed",
          gone.status_code in (404, 410) and client_rep(api, "pending-" + expired["id"]) is None, gone.text[:80])
    publish({RECORD: [req["record"]["value"]]})

    direct = httpx.post(f"{REALM}/clients-registrations/default", json={
        "clientId": "sneaky", "redirectUris": ["https://share.example.net/x"],
        "attributes": {"pkce.code.challenge.method": "S256"}})
    check("Keycloak's own registration endpoint refuses new clients (DNS approval only)",
          direct.status_code in (400, 401, 403) and client_rep(api, "sneaky") is None, f"{direct.status_code}")
    uri = CLIENT.get("registration_client_uri", "")
    own = httpx.get(uri, headers={"Authorization": f"Bearer {CLIENT.get('registration_access_token')}"})
    check("the registrant's app can read its client with the registration access token", own.status_code == 200,
          own.text[:80])
    if own.status_code == 200:
        rat = own.json().get("registrationAccessToken", CLIENT["registration_access_token"])
        added = dict(own.json(), redirectUris=[CALLBACK, "https://photos.example.net/oauth2/callback"])
        ok = httpx.put(uri, headers={"Authorization": f"Bearer {rat}"}, json=added)
        rat = ok.json().get("registrationAccessToken", rat) if ok.status_code == 200 else rat
        check("...and add another service under the domain (photos.example.net)", ok.status_code == 200, ok.text[:100])
        moved = dict(own.json(), redirectUris=["https://evil.example/oauth2/callback"])
        refused = httpx.put(uri, headers={"Authorization": f"Bearer {rat}"}, json=moved)
        check("...but not a redirect outside the domain", refused.status_code in (400, 403)
              and "https://evil.example/oauth2/callback" not in (client_rep(api, DOMAIN) or {}).get("redirectUris", []),
              refused.text[:100])
        CLIENT["registration_access_token"] = rat

    # A new verified registration of the domain replaces (revokes) the old client.
    before = len([m for m in mails_to(REGISTRANT) if "revoked" in m["Subject"]])
    again = ask(token, DOMAIN, share, ["https://share.example.net/"]).json()
    publish({RECORD: [again["record"]["value"]]})
    renewed = verify(token, again, tries=3)
    old_id = rep.get("id")
    old = next((c for c in api.get("/clients").json() if c["id"] == old_id), {})
    mail = wait_for_mail(REGISTRANT, "Sign-in for example.net", before, timeout=10)
    check("a new verified registration of the domain revokes the old client (off, renamed, kept) and tells the registrant",
          renewed.status_code == 200 and old.get("enabled") is False and old.get("clientId", "").startswith("revoked-example.net-")
          and old.get("attributes", {}).get("sustenaut.app.state") == "revoked" and mail is not None
          and "replaced" in mail["Text"], f"{renewed.status_code} {old.get('clientId')}")
    CLIENT.clear()
    CLIENT.update(renewed.json(), record=again["record"]["value"], old_secret=rep.get("secret"))
    stale = httpx.post(f"{REALM}/protocol/openid-connect/token", data={
        "grant_type": "client_credentials", "client_id": old.get("clientId"), "client_secret": "x"})
    check("...whose credentials no longer work", stale.status_code in (400, 401))

    rerun = os.environ.get("REALM_RERUN")
    if rerun:
        ran = subprocess.run(rerun, shell=True, cwd=HERE.parent, capture_output=True, text=True, check=False)
        after = client_rep(admin(), DOMAIN) or {}
        check("the realm job (run again as in production) leaves the registered client alone",
              ran.returncode == 0 and after.get("enabled") is True and after.get("secret") == CLIENT["client_secret"],
              f"exit {ran.returncode}")
    else:
        print("INFO REALM_RERUN not set: realm-job rerun not checked")


def recheck(api: httpx.Client) -> None:
    """The weekly check, here every few seconds (a miss asked again after 3 s, not an hour)."""
    record = CLIENT["record"]
    enabled = lambda: (client_rep(api, DOMAIN) or {}).get("enabled") is True  # noqa: E731
    anchors = api.get("").json()["attributes"]["sustenaut.appRegistration.trustAnchors"]
    set_realm(api, trustAnchors="example.net. IN DS 1 13 2 " + "00" * 32)
    publish({})  # gone, but nothing validates: no definite answer
    time.sleep(15)
    check("record gone but the answers don't validate (wrong trust anchor): nothing is revoked", enabled())
    set_realm(api, trustAnchors=anchors, dnsServer=NS1.rsplit(".", 1)[0] + ".99:53")
    time.sleep(20)
    check("record gone but DNS doesn't answer (dead resolver, timeouts): nothing is revoked", enabled())
    set_realm(api, dnsServer=f"{NS1}:53")
    publish({RECORD: [record]})
    time.sleep(8)

    before = len([m for m in mails_to(REGISTRANT) if "revoked" in m["Subject"]])
    publish({})
    revoked = wait_until(lambda: client_rep(api, DOMAIN) is None, timeout=40)
    mail = wait_for_mail(REGISTRANT, "Sign-in for example.net", before, timeout=15)
    gone = by_state(api, "revoked")
    check("record gone at every nameserver, twice in a row: the client is revoked (off, renamed, kept)",
          revoked and any(c["enabled"] is False and c["secret"] == CLIENT["client_secret"] for c in gone))
    check("...and the registrant is told the TXT record is gone and a new registration is required",
          mail is not None and "_sustenaut-auth.example.net" in mail["Text"] and "no longer exists" in mail["Text"]
          and "new registration is required" in mail["Text"], mail and mail["Subject"])
    stopped = httpx.get(f"{REALM}/protocol/openid-connect/auth", params={
        "client_id": DOMAIN, "response_type": "code", "scope": "openid", "redirect_uri": CALLBACK,
        "code_challenge": "x" * 43, "code_challenge_method": "S256"})
    check("...so nobody can sign in through it", stopped.status_code >= 400, f"{stopped.status_code}")
    publish({RECORD: [record]})
    time.sleep(12)
    check("putting the record back does not switch it on again (a new registration is needed)",
          client_rep(api, DOMAIN) is None and all(c["enabled"] is False for c in by_state(api, "revoked")))

    target = next(c for c in by_state(api, "revoked") if c["secret"] == CLIENT["client_secret"])
    target["attributes"]["sustenaut.app.revoked"] = f"{int(time.time()) - 31 * 24 * 3600} test"
    api.put(f"/clients/{target['id']}", json=target).raise_for_status()
    check("a revoked client is deleted after 30 days",
          wait_until(lambda: all(c["id"] != target["id"] for c in api.get("/clients").json()), timeout=15))


def no_password_field(page, where: str) -> None:
    check(f"no password field on the {where}", page.locator("input[type=password]").count() == 0)


class Portal:
    """The share-portal's side of the code flow, inside the browser context."""

    def __init__(self, context):
        self.landed = None
        self.home = None  # a request to the domain's home page (TENANT home_url)
        self.left = None  # the leave flow's way back (LEFT)
        self.offered = False
        context.on("request", self._seen)

    def _seen(self, request):
        if request.url.startswith(CALLBACK):
            self.landed = request.url
        elif request.url == TENANT["home_url"]:
            self.home = request.url
        elif request.url.startswith(LEFT):
            self.left = request.url

    def start(self, page, redirect: str = CALLBACK, **extra: str) -> str:
        self.landed = self.home = self.left = None
        self.offered = False
        self.verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).rstrip(b"=").decode()
        url = f"{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode({
            "client_id": CLIENT["client_id"], "response_type": "code", "scope": "openid email",
            "redirect_uri": redirect, "state": secrets.token_urlsafe(8),
            "code_challenge": challenge, "code_challenge_method": "S256", **extra})
        try:
            page.goto(url)
        except PlaywrightError as e:  # the last redirect's error page (no share.example.net here) still loading
            if "interrupted by another navigation" not in str(e):
                raise
            page.wait_for_timeout(500)
            page.goto(url)

    def tokens(self, page) -> dict:
        """The code from the callback, exchanged; says "Not now" if the passkey offer comes first."""
        for _ in range(80):
            if self.landed:
                break
            if not self.offered and page.locator("#family-passkey-offer").count():
                self.offered = True
                page.click("#family-passkey-not-now")
            page.wait_for_timeout(250)
        if not self.landed:
            raise RuntimeError(f"never reached the callback; page: {page.inner_text('body')[:300]!r}")
        code = urllib.parse.parse_qs(urllib.parse.urlparse(self.landed).query)["code"][0]
        return httpx.post(f"{REALM}/protocol/openid-connect/token", data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": CALLBACK,
            "client_id": CLIENT["client_id"], "client_secret": CLIENT["client_secret"],
            "code_verifier": self.verifier}).raise_for_status().json()


def link_and_code(mail: dict) -> tuple[str, str]:
    link = re.search(r"(https?://\S+/login-actions/action-token\S+)", mail["Text"])
    code = re.search(r"^\s*(\d{6})\s*$", mail["Text"], re.MULTILINE)
    return (link.group(1) if link else ""), (code.group(1) if code else "")


def cookie(context, name: str) -> dict | None:
    return next((c for c in context.cookies() if c["name"] == name), None)


def remembered(context) -> float:
    """Days the Keycloak sign-in cookie lives (0: a browser-session cookie, or none)."""
    identity = cookie(context, "KEYCLOAK_IDENTITY")
    return max(0.0, (identity["expires"] - time.time()) / 86400) if identity else 0.0


def ask_for_email(context, email: str) -> tuple[object, "Portal", str, str]:
    """Starts the portal's sign-in in this browser and asks for the email; its link and code."""
    portal = Portal(context)
    page = context.new_page()
    before = len([m for m in mails_to(email) if m["Subject"].startswith(SIGN_IN_MAIL)])
    portal.start(page)
    page.fill("input[name=username]", email)
    page.click("#kc-login")
    page.wait_for_selector("input[name=code]")
    mail = wait_for_mail(email, SIGN_IN_MAIL, before, timeout=10)
    link, code = link_and_code(mail) if mail else ("", "")
    return page, portal, link, code


def signed_out(context) -> None:
    """Ends Keycloak's session in this browser, keeping other cookies (the passkey answer)."""
    for name in ("KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"):
        context.clear_cookies(name=name)


friend_portal_offered = [False]  # whether code_sign_in's sign-in met the passkey offer


def code_sign_in(browser, email: str, label: str, wrong_first: bool = False) -> tuple[dict | None, object]:
    context = browser.new_context()
    portal = Portal(context)
    page = context.new_page()
    before = len([m for m in mails_to(email) if m["Subject"].startswith(SIGN_IN_MAIL)])
    portal.start(page)
    page.wait_for_selector("#kc-login")
    if label == "4-friend":
        page.screenshot(path=OUT / "3-login-page.png")
        no_password_field(page, "login page")
        check("the login page: one email field and 'Email me a sign-in link', no registration or reset link",
              "Email me a sign-in link" in page.locator("#kc-login").inner_text()
              and page.locator("input:visible").count() == 1
              and page.locator("a[href*=registrations], a[href*=reset-credentials]").count() == 0)
        check("no passkey button and no passkey dialog, but the browser still offers a passkey in the email field "
              "(conditional UI)",
              page.locator("#authenticateWebAuthnButton").count() == 0 and "Sign in with a passkey" not in page.content()
              and page.locator("#webauth").count() == 1
              and "webauthn" in (page.locator("input[name=username]").get_attribute("autocomplete") or "")
              and '"conditional"' in page.content())
        invite_only = page.locator("#family-invite-only").inner_text()
        check("the page no longer says a passkey is needed", "passkey" not in invite_only.lower(), invite_only)
        check("the sign-in page speaks for the domain: 'Sign in to <its name>', its help contact",
              f"Sign in to {TENANT['display_name']}" in page.content() and TENANT["help_contact"] in page.content())
        check("the family page has no wallet buttons (sustenaut theme kept apart)",
              page.locator("[id^=social-oid4vp], #sk-plugin-source").count() == 0)
    page.fill("input[name=username]", email)
    page.click("#kc-login")
    page.wait_for_selector("input[name=code]")
    page.screenshot(path=OUT / f"{label}-code-page.png")
    mail = wait_for_mail(email, SIGN_IN_MAIL, before, timeout=8)
    if mail is None:
        return None, page
    if label == "4-friend":
        check("the sign-in email is in the domain's name (sender and subject)",
              mail["From"]["Name"] == TENANT["display_name"]
              and mail["Subject"] == f"{SIGN_IN_MAIL} for {TENANT['display_name']}"
              and TENANT["display_name"] in mail["Text"], f"{mail['From']} {mail['Subject']!r}")
        link, code = link_and_code(mail)
        check("one email carries both a 'Sign me in' button (the link) and the 6-digit code",
              bool(link) and bool(code) and "Sign me in" in mail["HTML"] and "action-token" in mail["HTML"])
        (OUT / "4-sign-in-email.txt").write_text(mail["Text"])
    code = link_and_code(mail)[1]
    if wrong_first:
        page.fill("input[name=code]", f"{(int(code) + 1) % 1_000_000:06d}")
        page.click("#kc-login")
        page.wait_for_selector("input[name=code]")
        check("a wrong code is refused, with a message, and the page stays",
              "not right" in page.content() and portal.landed is None)
    page.fill("input[name=code]", code)
    page.click("#kc-login")
    tokens = portal.tokens(page)
    friend_portal_offered[0] = portal.offered
    return tokens, page


def account(api: httpx.Client, email: str) -> dict:
    """The account as the admin API shows it ({} if there is none)."""
    return (api.get("/users", params={"email": email, "exact": "true"}).json() or [{}])[0]


def marks(user: dict) -> list[str]:
    return user.get("attributes", {}).get("sustenaut.invitedBy", [])


def removed_at(user: dict) -> int | None:
    value = user.get("attributes", {}).get("sustenaut.removedAt")
    return int(value[0]) if value else None


def set_account(api: httpx.Client, email: str, **changes) -> None:
    """Changes an account as an admin would: the whole representation back, attributes merged."""
    user = account(api, email)
    attributes = dict(user.get("attributes", {}))
    for key, value in changes.pop("attributes", {}).items():
        if value is None:
            attributes.pop(key, None)
        else:
            attributes[key] = value
    user.pop("access", None)
    api.put(f"/users/{user['id']}", json={**user, **changes, "attributes": attributes}).raise_for_status()


def remove(email: str, auth=None, **extra) -> httpx.Response:
    return httpx.post(f"{REGISTER}/{DOMAIN}/remove", json={"email": email, **extra},
                      auth=auth or (CLIENT["client_id"], CLIENT["client_secret"]))


def invite(email: str, **extra) -> httpx.Response:
    return httpx.post(f"{REGISTER}/{DOMAIN}/invite", json={"email": email, **extra},
                      auth=(CLIENT["client_id"], CLIENT["client_secret"]))


def refreshes(tokens: dict) -> bool:
    """Whether the sign-in's refresh token still works (its session is still there)."""
    return httpx.post(f"{REALM}/protocol/openid-connect/token", data={
        "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
        "client_id": CLIENT["client_id"], "client_secret": CLIENT["client_secret"]}).status_code == 200


REMOVED = "rita.example@example.org"     # invited by example.net only; removed, then invited again
TWO = "tove.example@example.org"         # invited by example.net and sustenaut.eu
OTHERS = "olga.example@example.org"      # invited by sustenaut.eu only
MOVER = "mats.example@example.org"       # removed with reason "moved"
LOCKED = "lars.example@example.org"      # an admin locked the account
LEAVER = "liis.example@example.org"      # leaves example.net herself
SCRIPTED = "sven.example@example.org"    # remove-family.sh
ADMIN_MARKED = "ada.example@example.org"  # invite-family.sh --domain example.net, then leaves
REMOVAL_PEOPLE = (ADMIN_MARKED, REMOVED, TWO, OTHERS, MOVER, LOCKED, LEAVER, SCRIPTED)


def removal(api: httpx.Client, browser) -> None:
    """A domain lets people go, people leave, the admin fallback, and the daily deletion."""
    name = TENANT["display_name"]
    for email in (REMOVED, TWO, MOVER, LEAVER, SCRIPTED):
        invite(email).raise_for_status()
    make_user(api, OTHERS)
    set_account(api, OTHERS, attributes={"sustenaut.invitedBy": ["sustenaut.eu"]})
    set_account(api, TWO, attributes={"sustenaut.invitedBy": [DOMAIN, "sustenaut.eu"]})

    check("removing someone needs the domain's credentials (none or a wrong secret: 401)",
          httpx.post(f"{REGISTER}/{DOMAIN}/remove", json={"email": REMOVED}).status_code == 401
          and remove(REMOVED, auth=(DOMAIN, "nope")).status_code == 401)
    check("removing through another domain's path with this domain's credentials: 401",
          httpx.post(f"{REGISTER}/sustenaut.eu/remove", json={"email": OTHERS},
                     auth=(CLIENT["client_id"], CLIENT["client_secret"])).status_code == 401)
    check("a reason other than removed or moved: 400", remove(REMOVED, reason="left").status_code == 400)

    # Removed by the domain while signed in: the session ends, the account is switched off.
    tokens, _ = code_sign_in(browser, REMOVED, "r1-removed")
    check("before removal, the person's sign-in session works (refresh token)", tokens is not None and refreshes(tokens))
    before = len(mails_to(REMOVED))
    answer = remove(REMOVED.upper())
    user = account(api, REMOVED)
    check("the domain removes someone it invited: 202 {status: removed, email}",
          answer.status_code == 202 and answer.json() == {"status": "removed", "email": REMOVED}, answer.text[:120])
    check("...their last domain: the account is switched off and stamped removedAt, the mark gone, passkeys kept",
          user.get("enabled") is False and removed_at(user) is not None
          and abs(removed_at(user) - time.time()) < 60 and marks(user) == [], json.dumps(user.get("attributes")))
    check("...every session of theirs has ended (the refresh token no longer works, no sessions left)",
          tokens is not None and not refreshes(tokens) and api.get(f"/users/{user.get('id')}/sessions").json() == [])
    mail = wait_for_mail(REMOVED, "Your access to", 0)
    check("...and they are told in the domain's words: no longer access, the account deleted in 30 days",
          mail is not None and mail["Subject"] == f"Your access to {name}" and mail["From"]["Name"] == name
          and f"You no longer have access to {name}." in mail["Text"] and "deleted in 30 days" in mail["Text"],
          mail and mail["Text"][:160])
    check("...and they read as none", status_of(REMOVED) == "none", status_of(REMOVED))
    check("...and they can no longer sign in (a code sign-in gets no code)",
          code_sign_in(browser, REMOVED, "r1-after")[0] is None and len(mails_to(REMOVED)) == before + 1)

    # Someone the domain did not invite, and an unknown address: the same answer, nothing changes.
    others_before = account(api, OTHERS)
    answer = remove(OTHERS)
    others = account(api, OTHERS)
    check("a domain cannot remove someone it did not invite: the same 202, the account unchanged, no email",
          answer.status_code == 202 and answer.json() == {"status": "removed", "email": OTHERS}
          and others.get("enabled") is True and marks(others) == ["sustenaut.eu"] and removed_at(others) is None
          and others.get("attributes") == others_before.get("attributes") and mails_to(OTHERS) == [], answer.text[:120])
    answer = remove(STRANGER)
    check("an unknown address gets the same 202, and no account", answer.status_code == 202
          and answer.json() == {"status": "removed", "email": STRANGER} and account(api, STRANGER) == {})

    # Invited by two domains: one lets them go, the account stays for the other.
    answer = remove(TWO)
    two = account(api, TWO)
    mail = wait_for_mail(TWO, "Your access to", 0)
    check("someone two domains invited keeps the account when one removes them (still on, the other mark kept)",
          answer.status_code == 202 and two.get("enabled") is True and marks(two) == ["sustenaut.eu"]
          and removed_at(two) is None, json.dumps(two.get("attributes")))
    check("...and their email says only that this access ends (no deletion)",
          mail is not None and "You no longer have access to" in mail["Text"] and "deleted" not in mail["Text"],
          mail and mail["Text"][:160])

    # "moved": the words change, nothing else.
    answer = remove(MOVER, reason="moved")
    mail = wait_for_mail(MOVER, "Your access to", 0)
    check("reason moved: the shares moved to a new address (not named), ask the domain's help contact",
          answer.status_code == 202 and account(api, MOVER).get("enabled") is False and mail is not None
          and "moved to a new address" in mail["Text"] and TENANT["help_contact"] in mail["Text"]
          and "@" not in mail["Text"].split("moved to a new address")[1].split(".")[0], mail and mail["Text"][:200])

    # An invitation switches a removed account on again; not one an admin locked.
    before = len([m for m in mails_to(REMOVED) if m["Subject"].startswith("Your invitation")])
    invite(REMOVED).raise_for_status()
    user = account(api, REMOVED)
    check("invited again, a removed account is switched on, removedAt cleared, the mark back, an invitation sent",
          user.get("enabled") is True and removed_at(user) is None and marks(user) == [DOMAIN]
          and wait_for_mail(REMOVED, "Your invitation", before) is not None, json.dumps(user.get("attributes")))
    make_user(api, LOCKED)
    set_account(api, LOCKED, enabled=False)
    invite(LOCKED).raise_for_status()
    locked = account(api, LOCKED)
    check("an account an admin locked (off, no removedAt) stays locked when invited, and gets no invitation",
          locked.get("enabled") is False and removed_at(locked) is None and mails_to(LOCKED) == [])

    # Self-service: "Remove my access" (kc_action=sustenaut-leave), cancel and confirm. The
    # portal sends it back to a page of its own, /left, outside oauth2-proxy (which can't take a
    # sign-in it did not start): register.py adds that redirect with the registration token.
    uri = CLIENT["registration_client_uri"]
    own = httpx.get(uri, headers={"Authorization": f"Bearer {CLIENT['registration_access_token']}"})
    rat = own.json().get("registrationAccessToken", CLIENT["registration_access_token"])
    added = httpx.put(uri, headers={"Authorization": f"Bearer {rat}"},
                      json=dict(own.json(), redirectUris=sorted(set(own.json()["redirectUris"]) | {LEFT})))
    CLIENT["registration_access_token"] = added.json().get("registrationAccessToken", rat) if added.status_code == 200 else rat
    check("the domain adds its leave page (share.example.net/left) as a redirect URI with its registration token",
          added.status_code == 200 and LEFT in (client_rep(api, DOMAIN) or {}).get("redirectUris", []), added.text[:100])

    context = browser.new_context()
    portal = Portal(context)
    page = context.new_page()

    def leave_page(email: str, wait_for: str = "#family-leave-confirm") -> None:
        sent = len([m for m in mails_to(email) if m["Subject"].startswith(SIGN_IN_MAIL)])
        portal.start(page, redirect=LEFT, kc_action="sustenaut-leave", max_age="300")
        page.fill("input[name=username]", email)
        page.click("#kc-login")
        page.wait_for_selector("input[name=code]")
        mail = wait_for_mail(email, SIGN_IN_MAIL, sent, timeout=8)
        page.fill("input[name=code]", link_and_code(mail)[1])
        page.click("#kc-login")
        page.wait_for_selector(wait_for)

    def back() -> dict:
        for _ in range(40):
            if portal.left:
                break
            page.wait_for_timeout(250)
        return urllib.parse.parse_qs(urllib.parse.urlparse(portal.left or "").query)

    leave_page(LEAVER)
    page.screenshot(path=OUT / "6-leave-page.png")
    no_password_field(page, "leave page")
    check("Remove my access: after a fresh sign-in, a page names the domain and says the account goes in 30 days",
          f"Remove my access to {name}" in page.content() and "deleted in 30 days" in page.inner_text("body"),
          page.inner_text("body")[:200])
    page.click("#family-leave-cancel")
    query = back()
    leaver = account(api, LEAVER)
    check("...cancel goes back to the app's leave page (kc_action_status=cancelled), never oauth2-proxy, nothing changed",
          query.get("kc_action_status") == ["cancelled"] and portal.landed is None
          and leaver.get("enabled") is True and marks(leaver) == [DOMAIN], portal.left)
    context.clear_cookies()
    leave_page(LEAVER)
    page.click("#family-leave-confirm")
    query = back()
    leaver = account(api, LEAVER)
    mail = wait_for_mail(LEAVER, "Your access to", 0)
    check("...confirm: back to the leave page with kc_action_status=success and the app's state, no code;"
          " the account is off and stamped, no sessions left",
          query.get("kc_action_status") == ["success"] and "state" in query and "code" not in query
          and portal.landed is None and leaver.get("enabled") is False and removed_at(leaver) is not None
          and api.get(f"/users/{leaver.get('id')}/sessions").json() == [], portal.left)
    check("...and the email says they asked for it", mail is not None and "you asked to remove it" in mail["Text"],
          mail and mail["Text"][:160])

    # Signed in, but not one of the domain's people (OTHERS: only sustenaut.eu's mark): told so.
    context.clear_cookies()
    others_before = account(api, OTHERS)
    leave_page(OTHERS, wait_for="#family-leave-nothing")
    page.screenshot(path=OUT / "6b-leave-nothing.png")
    nothing = page.inner_text("body")
    page.click("#family-leave-cancel")
    query = back()
    others = account(api, OTHERS)
    check("someone the domain did not invite is told there is nothing to remove here (no silent skip),"
          " and Back changes nothing (kc_action_status=cancelled)",
          f"not invited by {name}" in nothing and page.locator("#family-leave-confirm").count() == 0
          and query.get("kc_action_status") == ["cancelled"] and others.get("enabled") is True
          and marks(others) == marks(others_before) and removed_at(others) is None, nothing[:160])

    # Invited by the admin, for the domain (invite-family.sh --domain): one of its people, can leave.
    run = subprocess.run([str(HERE.parent / "invite-family.sh"), "--domain", DOMAIN, ADMIN_MARKED],
                         env={**LOCAL_ENV, "KEYCLOAK_ADMIN_URL": KC_ADMIN, "AUTH_CONFIG_CLIENT_SECRET": ENV["KC_ADMIN_PASSWORD"]},
                         capture_output=True, text=True, check=False)
    marked = account(api, ADMIN_MARKED)
    check("invite-family.sh --domain marks the account as the domain's (sustenaut.invitedBy), no warning",
          run.returncode == 0 and marks(marked) == [DOMAIN] and "belongs to no domain" not in run.stderr,
          (run.stdout + run.stderr).strip().replace("\n", " | ")[:200])
    context.clear_cookies()
    leave_page(ADMIN_MARKED)
    page.click("#family-leave-confirm")
    query = back()
    marked = account(api, ADMIN_MARKED)
    check("...so they can leave it themselves: Remove my access works (account off, stamped)",
          query.get("kc_action_status") == ["success"] and marked.get("enabled") is False
          and removed_at(marked) is not None, portal.left)
    context.close()

    # The admin scripts never reach the live server unless asked by name (SUSTENAUT_SERVER).
    run = subprocess.run([str(HERE.parent / "remove-family.sh"), SCRIPTED, DOMAIN],
                         env={**LOCAL_ENV, "KEYCLOAK_ADMIN_URL": "http://127.0.0.1:9",
                              "AUTH_CONFIG_CLIENT_SECRET": "x", "REMOVE_FAMILY_YES": "1"},
                         capture_output=True, text=True, check=False, timeout=60)
    check("remove-family.sh with nothing answering at its admin URL stops: no tunnel without SUSTENAUT_SERVER",
          run.returncode != 0 and "Nothing answers" in run.stderr and "Opening the admin tunnel" not in run.stderr,
          run.stderr.strip()[:160])

    # remove-family.sh, the admin fallback: with a domain (the mark), without (the account).
    env = {**LOCAL_ENV, "KEYCLOAK_ADMIN_URL": KC_ADMIN,
           "AUTH_CONFIG_CLIENT_SECRET": ENV["KC_ADMIN_PASSWORD"], "REMOVE_FAMILY_YES": "1"}
    script = str(HERE.parent / "remove-family.sh")
    run = subprocess.run([script, SCRIPTED, DOMAIN], env=env, capture_output=True, text=True, check=False)
    scripted = account(api, SCRIPTED)
    check("remove-family.sh EMAIL DOMAIN: the mark off, the account off and stamped, names kept, a reminder about Immich",
          run.returncode == 0 and scripted.get("enabled") is False and marks(scripted) == []
          and removed_at(scripted) is not None and scripted.get("email") == SCRIPTED and "for:" in run.stdout,
          (run.stdout + run.stderr).strip().replace("\n", " | ")[:240])
    run = subprocess.run([script, TWO], env=env, capture_output=True, text=True, check=False)
    check("remove-family.sh EMAIL (no domain): the account is deleted now",
          run.returncode == 0 and account(api, TWO) == {}, (run.stdout + run.stderr).strip().replace("\n", " | ")[:200])

    # The daily job (every 5 s here): removed 30 or more days ago goes; 29 days, and locked, stay.
    day = 24 * 3600
    set_account(api, LEAVER, attributes={"sustenaut.removedAt": [str(int(time.time()) - 31 * day)]})
    set_account(api, MOVER, attributes={"sustenaut.removedAt": [str(int(time.time()) - 29 * day)]})
    check("the daily job deletes an account removed 30 or more days ago",
          wait_until(lambda: account(api, LEAVER) == {}, timeout=20))
    time.sleep(6)
    check("...but not one removed 29 days ago, nor one an admin locked (no removedAt)",
          account(api, MOVER).get("enabled") is False and account(api, LOCKED).get("enabled") is False)

    for email in REMOVAL_PEOPLE:
        for old in api.get("/users", params={"email": email, "exact": "true"}).json():
            api.delete(f"/users/{old['id']}").raise_for_status()


GONE = "gita.example@example.org"  # invited by the registration that deregisters


def deregister(api: httpx.Client) -> None:
    """The domain registers again, invites someone, and deregisters (DELETE {domain})."""
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel=os.environ.get("PW_CHANNEL", "chrome"))
        token = device_token(browser, REGISTRANT)
        browser.close()
    asked = ask(token, DOMAIN, [CALLBACK], ["https://share.example.net/"]).json()
    publish({RECORD: [asked["record"]["value"]]})
    done = verify(token, asked, tries=3)
    CLIENT.clear()
    CLIENT.update(done.json() if done.status_code == 200 else {})
    check("the domain registers again (after its revoked client was deleted)", done.status_code == 200, done.text[:100])
    for old in api.get("/users", params={"email": GONE, "exact": "true"}).json():
        api.delete(f"/users/{old['id']}").raise_for_status()
    invite(GONE).raise_for_status()

    check("deregistering needs the domain's credentials (none or a wrong secret: 401)",
          httpx.delete(f"{REGISTER}/{DOMAIN}").status_code == 401
          and httpx.delete(f"{REGISTER}/{DOMAIN}", auth=(DOMAIN, "nope")).status_code == 401)
    before = len([m for m in mails_to(REGISTRANT) if "revoked" in m["Subject"]])
    answer = httpx.delete(f"{REGISTER}/{DOMAIN}", auth=(CLIENT["client_id"], CLIENT["client_secret"]))
    revoked = next((c for c in by_state(api, "revoked") if c["secret"] == CLIENT.get("client_secret")), {})
    mail = wait_for_mail(REGISTRANT, "Sign-in for example.net", before, timeout=10)
    check("DELETE {domain} with its credentials revokes the client at once (off, renamed) and tells the registrant",
          answer.status_code == 200 and answer.json().get("status") == "revoked" and client_rep(api, DOMAIN) is None
          and revoked.get("enabled") is False and mail is not None and "end its registration" in mail["Text"],
          answer.text[:120])
    check("...its credentials no longer work",
          httpx.post(f"{REGISTER}/{DOMAIN}/invite", json={"email": GONE},
                     auth=(CLIENT["client_id"], CLIENT["client_secret"])).status_code == 401)
    check("...the people it invited keep their accounts for now (30 days)", account(api, GONE).get("enabled") is True)

    revoked["attributes"]["sustenaut.app.revoked"] = f"{int(time.time()) - 31 * 24 * 3600} test"
    api.put(f"/clients/{revoked['id']}", json=revoked).raise_for_status()
    deleted = wait_until(lambda: all(c["id"] != revoked["id"] for c in api.get("/clients").json()), timeout=15)
    gone = account(api, GONE)
    mail = wait_for_mail(GONE, "Your access to", 0)
    check("when the revoked client is deleted (30 days), its people lose access first: off, stamped, the mark gone",
          deleted and gone.get("enabled") is False and removed_at(gone) is not None and marks(gone) == [],
          json.dumps(gone.get("attributes")))
    check("...and are told the domain no longer uses this sign-in",
          mail is not None and "no longer uses this sign-in" in mail["Text"], mail and mail["Text"][:160])
    for old in api.get("/users", params={"email": GONE, "exact": "true"}).json():
        api.delete(f"/users/{old['id']}").raise_for_status()


def authenticator(context, page, label: str) -> None:
    """Chrome's virtual authenticator in this browser context (a phone's or laptop's passkey store)."""
    page.on("dialog", lambda d: d.accept(label))
    cdp = context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})


def add_passkey(browser, email: str, label: str) -> bool:
    """Another device: an app asks Keycloak to add a passkey (kc_action); the person signs in
    there with an emailed code, then sets the passkey up (no offer: the app asked already).
    True if the app was reached."""
    context = browser.new_context()
    portal = Portal(context)
    page = context.new_page()
    authenticator(context, page, label)
    before = len([m for m in mails_to(email) if m["Subject"].startswith(SIGN_IN_MAIL)])
    portal.start(page, kc_action="webauthn-register-passwordless")
    page.fill("input[name=username]", email)
    page.click("#kc-login")
    page.wait_for_selector("input[name=code]")
    mail = wait_for_mail(email, SIGN_IN_MAIL, before, timeout=8)
    page.fill("input[name=code]", link_and_code(mail)[1])
    page.click("#kc-login")
    page.wait_for_selector("#registerWebAuthn")
    page.screenshot(path=OUT / f"{label}-add-passkey.png")
    page.click("#registerWebAuthn")
    for _ in range(80):
        if portal.landed or page.locator("#family-passkey-offer").count():
            break
        page.wait_for_timeout(250)
    context.close()
    return portal.landed is not None


def passkey_notices(address: str) -> list[dict]:
    return [m for m in mails_to(address) if m["Subject"].startswith("A new passkey")]


def main() -> int:
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)
    api = admin()
    for address in (FRIEND, STRANGER, FALLBACK, LINKED, CODER, GONE, *REMOVAL_PEOPLE):  # start clean: a re-run invites anew
        for old in api.get("/users", params={"email": address, "exact": "true"}).json():
            api.delete(f"/users/{old['id']}").raise_for_status()
    httpx.delete(f"{MAILPIT}/messages").raise_for_status()
    httpx.delete(f"{HOOKS}/received").raise_for_status()
    # 0. The portal's domain registers for sign-in; approval is the DNS record.
    register(api)
    users_before = api.get("/users/count").json()

    # 1. The domain's own settings and invitations, with its client's id and secret.
    basic = (CLIENT["client_id"], CLIENT["client_secret"])
    settings_url = f"{REGISTER}/{DOMAIN}/settings"
    refused = {
        "a wrong secret": httpx.put(settings_url, auth=(DOMAIN, "nope"), json=TENANT),
        "another domain's path": httpx.put(f"{REGISTER}/sustenaut.eu/settings", auth=basic, json=TENANT),
        "markup in the text": httpx.put(settings_url, auth=basic, json=dict(TENANT, display_name="<b>Hi</b>")),
        "braces in the text": httpx.put(settings_url, auth=basic, json=dict(TENANT, invite_intro="{0} hello")),
        "a home page outside the domain": httpx.put(settings_url, auth=basic, json=dict(TENANT, home_url="https://evil.example/")),
        "a name too long": httpx.put(settings_url, auth=basic, json=dict(TENANT, display_name="x" * 81)),
        "a notify URL outside the domain": httpx.put(settings_url, auth=basic, json=dict(TENANT, notify_url="https://evil.example/hook")),
        "a notify URL over plain http": httpx.put(settings_url, auth=basic, json=dict(TENANT, notify_url="http://hooks.example.net/hook")),
    }
    for what, answer in refused.items():
        check(f"domain settings refused: {what}", answer.status_code in (400, 401), f"{answer.status_code} {answer.text[:80]}")
    stored = httpx.put(settings_url, auth=basic, json=TENANT)
    rep = client_rep(api, DOMAIN) or {}
    check("the domain stores its settings with its own credentials (name, home page, words)",
          stored.status_code == 200 and rep.get("name") == TENANT["display_name"]
          and rep.get("baseUrl") == TENANT["home_url"]
          and rep.get("attributes", {}).get("sustenaut.tenant.inviteIntro") == TENANT["invite_intro"], stored.text[:120])

    check("an invitation needs the domain's credentials",
          httpx.post(f"{REGISTER}/{DOMAIN}/invite", auth=(DOMAIN, "nope"), json={"email": FRIEND}).status_code == 401)
    sent = httpx.post(f"{REGISTER}/{DOMAIN}/invite", auth=basic,
                      json={"email": FRIEND.upper(), "first_name": "Anna", "last_name": "Example"})
    check("the domain invites a friend (account created, the same answer whether it existed or not)",
          sent.status_code == 202 and sent.json().get("status") == "sent", sent.text[:120])
    user = (api.get("/users", params={"email": FRIEND, "exact": "true"}).json() or [{}])[0]
    check("the account: username = email (lower case), email verified, no credentials, marked with the domain",
          user.get("username") == FRIEND and user.get("email") == FRIEND and user.get("emailVerified") is True
          and api.get(f"/users/{user.get('id')}/credentials").json() == []
          and user.get("attributes", {}).get("sustenaut.invitedBy") == [DOMAIN],
          json.dumps({k: user.get(k) for k in ("username", "email", "emailVerified", "firstName", "attributes")}))

    # The domain looks up its people (email change and removal use this).
    listeners = api.get("").json().get("eventsListeners", [])
    check("the family realm sends sign-in events to sustenaut-sign-in (and still jboss-logging)",
          set(listeners) >= {"jboss-logging", "sustenaut-sign-in"}, json.dumps(listeners))
    no_auth = httpx.get(f"{REGISTER}/{DOMAIN}/people", params={"email": FRIEND})
    check("looking someone up needs the domain's credentials (none: 401, a wrong secret: 401)",
          no_auth.status_code == 401 and person(FRIEND, auth=(DOMAIN, "nope")).status_code == 401,
          f"{no_auth.status_code}")
    check("looking up through another domain's path with this domain's credentials: 401",
          httpx.get(f"{REGISTER}/sustenaut.eu/people", params={"email": FRIEND},
                    auth=(CLIENT["client_id"], CLIENT["client_secret"])).status_code == 401)
    check("looking up something that is not an address: 400", person("not-an-address").status_code == 400)
    found = person(FRIEND.upper())
    check("an invited friend who never signed in reads as invited, with their names (address in any case)",
          found.status_code == 200 and found.json() == {"email": FRIEND, "status": "invited",
                                                     "first_name": "Anna", "last_name": "Example"}, found.text[:120])
    check("the account remembers which domain gave the names", account(api, FRIEND).get("attributes", {})
          .get("sustenaut.namesBy") == [DOMAIN])
    set_account(api, FRIEND, attributes={"sustenaut.namesBy": ["sustenaut.eu"]})
    hidden = person(FRIEND)
    check("names another domain gave stay with that domain (status only)",
          hidden.status_code == 200 and hidden.json() == {"email": FRIEND, "status": "invited"}, hidden.text[:120])
    set_account(api, FRIEND, attributes={"sustenaut.namesBy": [DOMAIN]})
    check("an unknown address reads as none", status_of(STRANGER) == "none", status_of(STRANGER))
    sent = httpx.post(f"{REGISTER}/{DOMAIN}/invite", auth=basic, json={"email": CODER, "first_name": "Ben"})
    check("the domain invites a second friend (who will only use emailed codes)", sent.status_code == 202, sent.text[:120])

    invite = wait_for_mail(FRIEND, "Your invitation", 0)
    link = re.search("(" + re.escape(KC) + r"/realms/family/login-actions/action-token\S+)", invite["Text"]).group(1) if invite else ""
    check("the invitation is in the domain's words: its name as sender and subject, its intro and home page",
          bool(link) and invite["From"]["Address"] == "noreply@sustenaut.eu"
          and invite["From"]["Name"] == TENANT["display_name"]
          and invite["Subject"] == f"Your invitation from {TENANT['display_name']}"
          and TENANT["invite_intro"] in invite["Text"] and TENANT["home_url"] in invite["Text"],
          f"from={invite and invite['From']} subject={invite and invite['Subject']!r}")

    # The admin fallback, invite-family.sh: neutral words, no domain's.
    run = subprocess.run(
        [str(HERE.parent / "invite-family.sh"), FALLBACK],
        env={**LOCAL_ENV, "KEYCLOAK_ADMIN_URL": KC_ADMIN,
             "AUTH_CONFIG_CLIENT_SECRET": ENV["KC_ADMIN_PASSWORD"]},
        capture_output=True, text=True, check=False)
    plain = wait_for_mail(FALLBACK, "Your invitation", 0)
    check("invite-family.sh without --domain warns that the person belongs to no domain (none can remove them)",
          "belongs to no domain" in run.stderr, run.stderr.strip()[:160])
    check("invite-family.sh (admin fallback) still invites, in the realm's neutral words",
          run.returncode == 0 and plain is not None and plain["Subject"] == "Your invitation to sign in"
          and plain["From"]["Name"] == "auth.sustenaut.eu" and "Example family" not in plain["Text"],
          (run.stdout + run.stderr).strip().replace("\n", " | ")[:200])
    plain_link = re.search(rf"({re.escape(REALM)}/login-actions/action-token\S+)", plain["Text"]).group(1) if plain else ""
    (OUT / "1-invitation-email.txt").write_text(invite["Text"] if invite else "")

    # An emailed link must not do anything by being fetched (mail scanners open links).
    scanned = httpx.get(link)
    check("fetching the invitation link (as a mail scanner does) signs nobody in and uses nothing up: "
          "it asks 'Sign me in'", scanned.status_code == 200 and "Sign me in" in scanned.text
          and "KEYCLOAK_IDENTITY" not in scanned.headers.get("set-cookie", ""), f"{scanned.status_code}")
    check("someone the domain did not invite (invite-family.sh, the realm admin's) reads as none",
          status_of(FALLBACK) == "none", status_of(FALLBACK))

    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel=os.environ.get("PW_CHANNEL", "chrome"),
                                     args=["--host-resolver-rules=MAP share.example.net ~NOTFOUND"])

        # 2. The invitation signs in: one click, then the domain's home page (whose own sign-in
        # passes straight through). Then, once on this device, the passkey offer: Set up,
        # with Chrome's virtual authenticator (a phone's passkey).
        phone = browser.new_context()
        portal = Portal(phone)
        page = phone.new_page()
        page.on("dialog", lambda d: d.accept("Anna's phone"))
        cdp = phone.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
        page.goto(link)
        page.screenshot(path=OUT / "1-invitation.png")
        no_password_field(page, "invitation page")
        page.click("text=Sign me in")
        for _ in range(40):
            if portal.home:
                break
            page.wait_for_timeout(250)
        anna = api.get(f"/users/{user.get('id')}").json()
        check("the invitation signs in without a passkey: one click, then the domain's home page; "
              "address verified, nothing set up, a remembered session",
              portal.home == TENANT["home_url"] and anna.get("emailVerified") is True
              and api.get(f"/users/{user.get('id')}/credentials").json() == [] and remembered(phone) > 29,
              f"home={portal.home} remembered={remembered(phone):.1f} days")
        check("the invitation's sign-in counts: the friend reads as active (no passkey needed)",
              status_of(FRIEND) == "active", status_of(FRIEND))
        used = httpx.get(link)
        check("the invitation link works once", "no longer works" in used.text, f"{used.status_code}")
        if plain_link:
            elsewhere = browser.new_context()
            other = elsewhere.new_page()
            other.goto(plain_link)
            other.click("text=Sign me in")
            other.wait_for_selector("text=You are signed in")
            check("invite-family.sh's invitation (no domain) signs in too, and says so",
                  remembered(elsewhere) > 29, f"remembered={remembered(elsewhere):.1f} days")
            elsewhere.close()

        portal.start(page)  # the portal's own sign-in, as after its home page
        page.wait_for_selector("#family-passkey-offer")
        page.screenshot(path=OUT / "2-passkey-offer.png")
        check("the domain's sign-in after the invitation passes straight through to the passkey offer: "
              "'Skip the email next time on this device?' with Set up and Not now",
              "Skip the email next time on this device?" in page.content()
              and page.locator("#family-passkey-setup").count() == 1 and page.locator("#family-passkey-not-now").count() == 1
              and page.locator("input[name=username]").count() == 0)
        page.click("#family-passkey-setup")
        page.wait_for_selector("#registerWebAuthn")
        page.screenshot(path=OUT / "2-passkey-setup.png")
        no_password_field(page, "passkey setup page")
        page.click("#registerWebAuthn")
        setup_tokens = portal.tokens(page)
        creds = api.get(f"/users/{user.get('id')}/credentials").json()
        check("Set up registers a passkey, and only that, then goes on to the app",
              [c["type"] for c in creds] == ["webauthn-passwordless"]
              and jwt_claims(setup_tokens["id_token"]).get("sub") == user.get("id"), json.dumps([c["type"] for c in creds]))

        # 3. Sign in with the passkey (fresh cookies, same device). The browser offers the
        # passkey in the email field (conditional UI); the virtual authenticator, like a
        # person tapping it, takes it at once, so no click is needed.
        phone.clear_cookies()
        portal.start(page)
        passkey_tokens = portal.tokens(page)
        idt = jwt_claims(passkey_tokens["id_token"])
        check("signing in with the passkey reaches share-portal, with no passkey offer (asked only after email)",
              idt.get("sub") == user.get("id") and not portal.offered, f"sub={idt.get('sub')} offered={portal.offered}")
        check("after signing in (with the passkey) the friend reads as active", status_of(FRIEND) == "active",
              status_of(FRIEND))
        check("share-portal's ID token carries the email, verified",
              idt.get("email") == FRIEND and idt.get("email_verified") is True and idt.get("azp") == CLIENT["client_id"],
              json.dumps({k: idt.get(k) for k in ("email", "email_verified", "azp", "iss")}))

        # 3b. Every passkey added sends a notice, in the domain's words: the first (Set up in the
        # offer after the invitation) and a second one, added on another device because an app
        # asked for it.
        first = wait_for_mail(FRIEND, "A new passkey", 0)
        check("the first passkey (Set up in the offer after the invitation) sends a notice in the domain's words",
              first is not None and first["Subject"] == f"A new passkey for {TENANT['display_name']}"
              and TENANT["help_contact"] in first["Text"], f"{first and first['Subject']!r}")
        added = add_passkey(browser, FRIEND, "anna-laptop")
        creds = api.get(f"/users/{user.get('id')}/credentials").json()
        notice = wait_for_mail(FRIEND, "A new passkey", 1)
        check("a second passkey can be added on another device (app-initiated, after an emailed code)",
              added and [c["type"] for c in creds] == ["webauthn-passwordless"] * 2, json.dumps([c["type"] for c in creds]))
        check("the second passkey emails a notice in the domain's words: its name, its help contact",
              notice is not None and notice["From"]["Name"] == TENANT["display_name"]
              and notice["Subject"] == f"A new passkey for {TENANT['display_name']}"
              and TENANT["help_contact"] in notice["Text"] and TENANT["display_name"] in notice["Text"],
              f"{notice and notice['From']} {notice and notice['Subject']!r}")
        check("the notice says when (UTC and readable) and roughly on what device",
              notice is not None and re.search(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", notice["Text"]) is not None
              and " UTC" in notice["Text"] and "Chrome on Linux" in notice["Text"]
              and "If it was not you, contact" in notice["Text"],
              (notice or {}).get("Text", "")[:300].replace("\n", " | "))
        check("exactly one notice per passkey added (two)", len(passkey_notices(FRIEND)) == 2)

        # 3c. Someone no domain invited (invite-family.sh): the notice in neutral words.
        add_passkey(browser, FALLBACK, "fallback-phone")
        first_neutral = wait_for_mail(FALLBACK, "A new passkey", 0)
        added = add_passkey(browser, FALLBACK, "fallback-laptop")
        neutral = wait_for_mail(FALLBACK, "A new passkey", 1)
        check("without a domain: a notice for each passkey (two), in neutral words",
              first_neutral is not None and added and neutral is not None and len(passkey_notices(FALLBACK)) == 2
              and neutral["Subject"] == "A new passkey was added to your account"
              and neutral["From"]["Name"] == "auth.sustenaut.eu" and "the person who invited you" in neutral["Text"]
              and "Example family" not in neutral["Text"],
              f"{neutral and neutral['From']} {neutral and neutral['Subject']!r}")
        for extra in api.get("/users", params={"email": FALLBACK, "exact": "true"}).json():
            api.delete(f"/users/{extra['id']}").raise_for_status()

        # 4. Sign in with a code sent by email, in a browser without the passkey.
        code_tokens, page = code_sign_in(browser, FRIEND, "4-friend", wrong_first=True)
        no_password_field(page, "code page")
        check("signing in with an emailed code reaches share-portal, same account and email",
              code_tokens is not None and jwt_claims(code_tokens["id_token"]).get("sub") == user.get("id")
              and jwt_claims(code_tokens["id_token"]).get("email") == FRIEND)
        check("the passkey offer is per device: someone with a passkey on their phone is asked on this browser",
              friend_portal_offered[0])

        # 4b. The email's link, for someone who never sets up a passkey (one device, "cleo").
        make_user(api, LINKED)
        cleo = api.get("/users", params={"email": LINKED, "exact": "true"}).json()[0]
        device = browser.new_context()
        page, cleo_portal, link1, _ = ask_for_email(device, LINKED)
        page.screenshot(path=OUT / "4b-code-page.png")
        page.goto(link1)  # opened in the browser that asked (as from the mail app, same browser)
        page.wait_for_selector("#family-passkey-offer")
        page.screenshot(path=OUT / "4b-passkey-offer.png")
        check("after an emailed sign-in, someone without a passkey is offered one", "Skip the email" in page.content())
        page.click("#family-passkey-not-now")
        linked = cleo_portal.tokens(page)
        check("the link signs in, in the browser that asked: share-portal gets the account",
              jwt_claims(linked["id_token"]).get("sub") == cleo["id"])
        asked = cookie(device, "FAMILY_PASSKEY_ASKED")
        check("'Not now' is kept on the device: a cookie on the realm's path, for about 400 days",
              asked is not None and asked["path"].endswith("/realms/family") and asked["httpOnly"]
              and (asked["expires"] - time.time()) / 86400 > 390, json.dumps(asked))
        check("the sign-in is remembered for 30 days (the Keycloak cookie survives a browser restart)",
              29 < remembered(device) <= 30.01, f"{remembered(device):.2f} days")
        again = device.new_page()
        again.goto(link1)
        check("the link works once: opened again in the same browser, it says it no longer works",
              again.locator("#family-link-used").count() == 1, again.inner_text("body")[:120])
        late = browser.new_context()
        late_page = late.new_page()
        late_page.goto(link1)
        check("...and in another browser", late_page.locator("#family-link-used").count() == 1)
        late.close()

        signed_out(device)
        page, cleo_portal, link2, code2 = ask_for_email(device, LINKED)
        phone_b = browser.new_context()  # where the email was read: another device
        phone_portal = Portal(phone_b)
        other = phone_b.new_page()
        other.goto(link2)
        other.wait_for_selector("#family-link-code")
        other.screenshot(path=OUT / "4b-link-elsewhere.png")
        check("the link opened on another device shows the code in large digits: 'type this on the screen where "
              "you started'", other.inner_text("#family-link-code").strip() == code2
              and "Type this code on the screen where you started" in other.content(), other.inner_text("body")[:160])
        check("...and does not sign that device in", cookie(phone_b, "KEYCLOAK_IDENTITY") is None
              and phone_portal.landed is None)
        page.fill("input[name=code]", code2)
        page.click("#kc-login")
        by_code = cleo_portal.tokens(page)
        check("the code still works (shown there, typed here), and 'Not now' is remembered: no offer this time",
              jwt_claims(by_code["id_token"]).get("sub") == cleo["id"] and not cleo_portal.offered)
        other.goto(link2)
        check("once the code is used, the link is dead (even on the device that showed its code)",
              other.locator("#family-link-used").count() == 1 and cookie(phone_b, "KEYCLOAK_IDENTITY") is None)
        phone_b.close()

        set_family_attribute(api, "sustenaut.family.codeSeconds", "3")
        try:
            signed_out(device)
            page, cleo_portal, link3, code3 = ask_for_email(device, LINKED)
            time.sleep(6)
            page.fill("input[name=code]", code3)
            page.click("#kc-login")
            page.wait_for_selector("input[name=code]")
            code_expired = "has expired" in page.content()
            page.goto(link3)
            page.wait_for_load_state()
            check("link and code expire (3 seconds here, 10 minutes for real): neither signs in",
                  code_expired and ("expired" in page.content() or page.locator("#family-link-used").count() == 1)
                  and cleo_portal.landed is None,
                  page.inner_text("body")[:160])
        finally:
            set_family_attribute(api, "sustenaut.family.codeSeconds", "")
        device.close()

        # A passkey setup that fails (WebAuthn error) never traps anyone: "Not now" there too.
        laptop = browser.new_context()
        page, cleo_portal, _, code4 = ask_for_email(laptop, LINKED)
        page.fill("input[name=code]", code4)
        page.click("#kc-login")
        page.wait_for_selector("#family-passkey-offer")
        page.click("#family-passkey-setup")
        page.wait_for_selector("#registerWebAuthn")
        setup_skip = page.locator("#family-passkey-not-now").count() == 1
        page.evaluate("""() => { document.getElementById('error').value = 'NotAllowedError';
                                 document.getElementById('register').requestSubmit(); }""")
        page.wait_for_selector("#family-passkey-not-now")
        page.screenshot(path=OUT / "4b-passkey-failed.png")
        failed_page = "kc-try-again" in page.content()
        page.click("#family-passkey-not-now")
        skipped = cleo_portal.tokens(page)
        check("a failed passkey setup (reached from the offer) has 'Not now', as does the setup page: on to the app, "
              "nothing registered, the device not asked again",
              setup_skip and failed_page and jwt_claims(skipped["id_token"]).get("sub") == cleo["id"]
              and api.get(f"/users/{cleo['id']}/credentials").json() == [] and cookie(laptop, "FAMILY_PASSKEY_ASKED") is not None
              and passkey_notices(LINKED) == [])
        laptop.close()
        api.delete(f"/users/{cleo['id']}").raise_for_status()

        # First-sign-in notices. Until now the domain had no notify_url: nothing was sent.
        check("while the domain has no notify_url, a first sign-in (the friend's) sends it nothing",
              notices_for(FRIEND) == [], json.dumps(notices_for(FRIEND))[:200])
        stored = httpx.put(settings_url, auth=basic, json=dict(TENANT, notify_url=NOTIFY_URL))
        check("the domain sets a notify_url (https under it) in its settings",
              stored.status_code == 200 and stored.json().get("notify_url") == NOTIFY_URL, stored.text[:160])

        # The second friend never sets up a passkey: signing in once with a code makes them active.
        check("the second friend, invited, no passkey, never signed in, reads as invited",
              status_of(CODER) == "invited", status_of(CODER))
        coder_tokens, _ = code_sign_in(browser, CODER, "4b-coder")
        coder = (api.get("/users", params={"email": CODER, "exact": "true"}).json() or [{}])[0]
        check("after signing in with an emailed code the second friend reads as active (no credential needed)",
              coder_tokens is not None and status_of(CODER) == "active"
              and api.get(f"/users/{coder.get('id')}/credentials").json() == [], status_of(CODER))
        coder_notices = wait_for_notice(CODER)
        notice = coder_notices[0] if len(coder_notices) == 1 else None
        body = json.loads(notice["body"]) if notice else {}
        check("their first sign-in is POSTed to the domain's notify_url, signed with its client secret"
              " (X-Sustenaut-Timestamp, X-Sustenaut-Signature: sha256=HMAC over timestamp.body)",
              notice is not None and notice["path"] == "/hooks/auth" and notice_ok(notice, CLIENT["client_secret"])
              and notice["headers"].get("content-type", "").startswith("application/json")
              and body.get("event") == "first_sign_in" and body.get("domain") == DOMAIN and body.get("email") == CODER
              and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", body.get("at", "")) is not None,
              json.dumps(notice)[:300])
        check("...and the signature does not hold with another key or another body",
              notice is not None and not notice_ok(notice, "not-the-secret")
              and not notice_ok(dict(notice, body=notice["body"].replace(CODER, FRIEND)), CLIENT["client_secret"]))
        again, _ = code_sign_in(browser, CODER, "4b-coder-again")
        time.sleep(3)
        check("signing in again sends nothing (first sign-in only)",
              again is not None and len(notices_for(CODER)) == 1, f"{len(notices_for(CODER))} notices")
        api.put(f"/users/{coder.get('id')}", json={"enabled": False}).raise_for_status()
        check("a disabled account reads as none, without names", person(CODER).json() == {"email": CODER, "status": "none"},
              person(CODER).text[:120])
        api.put(f"/users/{coder.get('id')}", json={"enabled": True}).raise_for_status()

        # 5. An address without an account: the same page, no email, no account, no way in.
        stranger = browser.new_context()
        stranger_portal = Portal(stranger)
        page = stranger.new_page()
        stranger_portal.start(page)
        page.fill("input[name=username]", STRANGER)
        page.click("#kc-login")
        page.wait_for_selector("input[name=code]")
        same_page = f"If {STRANGER} has been invited" in page.content()
        time.sleep(3)
        page.fill("input[name=code]", "123456")
        page.click("#kc-login")
        page.wait_for_selector("input[name=code]")
        page.screenshot(path=OUT / "5-stranger.png")
        check("an unknown address sees the same 'we sent you an email' page (no hint who is invited)", same_page)
        check("an unknown address gets no email (no link, no code) and cannot sign in",
              mails_to(STRANGER) == [] and stranger_portal.landed is None and "not right" in page.content())
        for _ in range(5):
            page.fill("input[name=code]", "654321")
            page.click("#kc-login")
            page.wait_for_selector("input[name=code]")
        check("after five wrong codes the code is dead: a new one must be sent", "has expired" in page.content())

        # 6. Passwords are not a way in.
        pw_try = browser.new_context()
        pw_portal = Portal(pw_try)
        page = pw_try.new_page()
        pw_portal.start(page)
        action = page.locator("#kc-form-login").get_attribute("action")
        with page.expect_navigation():
            page.evaluate("""([action, email]) => {
                const f = document.createElement('form'); f.method = 'post'; f.action = action;
                for (const [k, v] of [['username', email], ['password', 'hunter2'], ['login', 'x']]) {
                    const i = document.createElement('input'); i.name = k; i.value = v; f.appendChild(i); }
                document.body.appendChild(f); f.submit(); }""", [action, FRIEND])
        check("a username and password posted to the login form do not sign in (a code page instead)",
              pw_portal.landed is None and page.locator("input[name=code]").count() == 1)
        grant = httpx.post(f"{REALM}/protocol/openid-connect/token", data={
            "grant_type": "password", "client_id": CLIENT["client_id"],
            "client_secret": CLIENT["client_secret"], "username": FRIEND, "password": "x"})
        check("share-portal refuses the password grant", grant.status_code in (400, 401), grant.text[:120])

        # 7. Removal: by the domain, by the person, by the admin; the daily deletion.
        removal(admin(), browser)
        check("a first sign-in of someone the domain did not invite (only sustenaut.eu's) sends the domain nothing,"
              " while one of its own people's does",
              notices_for(OTHERS) == [] and len(wait_for_notice(REMOVED)) >= 1,
              f"others {len(notices_for(OTHERS))}, removed {len(notices_for(REMOVED))}")

        # 8. The sustenaut realm keeps its own wallet-only page.
        sus = browser.new_page()
        sus.goto(f"{KC}/realms/sustenaut/protocol/openid-connect/auth?" + urllib.parse.urlencode({
            "client_id": "test-app", "response_type": "code", "scope": "openid",
            "redirect_uri": "http://localhost:8099/callback", "code_challenge_method": "S256",
            "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(b"x").digest()).rstrip(b"=").decode()}))
        sus.wait_for_selector("#social-oid4vp-wallet-eu-pid")
        check("the sustenaut login page is unchanged: wallet only, no email field, no family text",
              sus.locator("input[name=username], #authenticateWebAuthnButton").count() == 0
              and "Email me a sign-in link" not in sus.content())
        browser.close()

    # 9. The weekly check, made quick: the record goes away, then comes back.
    recheck(admin())
    # 10. The domain registers again and deregisters.
    deregister(admin())

    api = admin()
    users_after = api.get("/users/count").json()
    check("exactly two accounts were made (the invited friends')", users_after - users_before == 2,
          f"{users_before} -> {users_after}")
    check("no account for the unknown address",
          api.get("/users", params={"email": STRANGER, "exact": "true"}).json() == [])
    signup = httpx.get(f"{REALM}/protocol/openid-connect/registrations", params={
        "client_id": "share-portal", "response_type": "code", "scope": "openid", "redirect_uri": CALLBACK})
    reset = httpx.get(f"{REALM}/login-actions/reset-credentials", params={"client_id": "share-portal"})
    check("no self-registration and no reset flow", signup.status_code == 400 and reset.status_code == 400,
          f"registrations {signup.status_code}, reset-credentials {reset.status_code}")
    check("account console is switched off", httpx.get(f"{REALM}/account/").status_code != 200)
    realm = api.get("").json()
    check("sessions: remembered, 30 days idle and 30 days at most",
          realm.get("rememberMe") is True and all(realm.get(k) == THIRTY_DAYS for k in (
              "ssoSessionIdleTimeout", "ssoSessionMaxLifespan", "ssoSessionIdleTimeoutRememberMe",
              "ssoSessionMaxLifespanRememberMe")), json.dumps({k: v for k, v in realm.items() if "ssoSession" in k}))
    print(f"\n{sum(ok for _, ok, _ in results)}/{len(results)} checks passed; screenshots in {OUT}")
    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
