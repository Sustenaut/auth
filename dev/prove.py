# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography>=44", "httpx>=0.27", "playwright>=1.50", "zxing-cpp>=2.2", "pillow>=10"]
# ///
"""End-to-end proof of wallet-only sign-in against the local compose stack.

Drives a real browser through the standard OpenID Connect code flow of the
test-app client: the wallet-only login page, the QR code (decoded and handed
to the scripted wallet in dev/wallet.py, as a phone would scan it), the page
completing by itself once the wallet has answered, and the code exchanged for
tokens. Then checks account creation, the member credential issued into the
wallet after a PID sign-in and signing in with it, a lost wallet, single
sign-on into a second app, and that untrusted or forged credentials are refused.

  uv run dev/prove.py            # stack must be up: podman compose up -d
"""

import base64
import http.server
import threading
import hashlib
import json
import os
import secrets
import shutil
import sys
import urllib.parse
from pathlib import Path

import io
import httpx
import zxingcpp
from PIL import Image
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wallet import Person, Wallet, claims_of, forge_member  # noqa: E402

KC = os.environ.get("AUTH_KC", "http://localhost:8080")  # and AUTH_KC_ADMIN: another stack's ports
KC_ADMIN = os.environ.get("AUTH_KC_ADMIN", "http://localhost:8180")
REALM = f"{KC}/realms/sustenaut"
OUT = Path(__file__).resolve().parent / ".pki" / "proof"
ENV = dict(
    line.split("=", 1)
    for line in (Path(__file__).resolve().parent.parent / ".env").read_text().splitlines()
    if "=" in line and not line.startswith("#")
)

MARI = Person("EE-38001010000", "Mari", "Maasikas")
JAAN = Person("EE-37502020000", "Jaan", "Tamm")

results = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail else ""), flush=True)


def jwt_claims(token: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def auth_url(client_id: str, redirect: str, challenge: str) -> str:
    return f"{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "scope": "openid",
            "redirect_uri": redirect,
            "state": secrets.token_urlsafe(8),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )


def decode_qr(data_url: str) -> str:
    image = Image.open(io.BytesIO(base64.b64decode(data_url.split(",", 1)[1])))
    found = zxingcpp.read_barcodes(image)
    if not found:
        raise RuntimeError("QR code not decodable")
    return found[0].text


class _Callback(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.path.startswith("/callback"):
            self.send_error(404)  # e.g. the browser asking for /favicon.ico
            return
        LANDED[self.server.server_port] = f"http://localhost:{self.server.server_port}{self.path}"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<p>back at the app</p>")

    def log_message(self, *args):
        pass


LANDED: dict[int, str] = {}
for _port in (8099, 8098):  # test-app, test-app-2 redirect URIs
    _server = http.server.ThreadingHTTPServer(("127.0.0.1", _port), _Callback)
    threading.Thread(target=_server.serve_forever, daemon=True).start()


MEMBER_VCT = "https://sustenaut.eu/credentials/member/v1"


def sign_in(browser, wallet: Wallet, label: str, profile: str = "eu-pid", context=None) -> dict:
    """One wallet sign-in in test-app with the given wallet profile; returns the tokens, or
    {'error': ...}. If Keycloak offers the member credential, the wallet takes it
    (tokens['offered'] is then the credential) and the login continues."""
    context = context or browser.new_context()
    LANDED.pop(8099, None)
    page = context.new_page()
    verifier, challenge = pkce()
    page.goto(auth_url("test-app", "http://localhost:8099/callback", challenge))
    page.screenshot(path=OUT / f"{label}-1-login.png")
    if label == "first":
        check("login page offers the wallet only, no password field",
              page.locator("input[type=password]").count() == 0
              and page.locator("input[name=username]").count() == 0
              and page.locator("#social-oid4vp-wallet-member").count() == 1
              and page.locator("#social-oid4vp-wallet-eu-pid").count() == 1)
        check("login page links to the patched plugin's source",
              httpx.get(KC + page.locator("#sk-plugin-source a").get_attribute("href")).status_code == 200)
    page.click(f"#social-oid4vp-wallet-{profile}")
    qr = page.locator("#kc-oid4vp-qrcode")
    qr.wait_for()
    page.screenshot(path=OUT / f"{label}-2-qr.png")
    reply = wallet.present(decode_qr(qr.get_attribute("src")))
    if reply["status"] != 200:
        if reply["status"] is None:
            return {"error": reply, "context": context}
        message = page.locator("#sk-wallet-refused")
        message.wait_for(timeout=15000)
        page.screenshot(path=OUT / f"{label}-3-refused.png")
        return {"error": reply, "context": context, "message_shown": message.is_visible()}

    offered = None
    page.wait_for_function(
        "() => location.href.startsWith('http://localhost:8099/') || document.getElementById('credential-offer-uri-link')",
        timeout=20000)
    if not page.url.startswith("http://localhost:8099/"):
        page.screenshot(path=OUT / f"{label}-3-offer.png")
        offered = wallet.accept_offer(page.locator("#credential-offer-uri-link").get_attribute("href"))
        page.click("#continue-vc-offer")

    page.wait_for_url("http://localhost:8099/**", timeout=20000)
    code = urllib.parse.parse_qs(urllib.parse.urlparse(LANDED[8099]).query)["code"][0]
    tokens = httpx.post(
        f"{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:8099/callback",
            "client_id": "test-app",
            "client_secret": ENV["SUSTENAUT_TEST_CLIENT_SECRET"],
            "code_verifier": verifier,
        },
    ).raise_for_status().json()
    tokens["context"] = context
    tokens["disclosed"] = reply["disclosed"]
    tokens["offered"] = offered
    return tokens


def sub_of(result: dict):
    return jwt_claims(result["id_token"]).get("sub") if "id_token" in result else None


def admin() -> httpx.Client:
    token = httpx.post(
        f"{KC}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli", "username": "admin",
              "password": ENV["KC_ADMIN_PASSWORD"]},
    ).raise_for_status().json()["access_token"]
    return httpx.Client(base_url=f"{KC}/admin/realms/sustenaut", headers={"Authorization": f"Bearer {token}"})


def main() -> int:
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)
    api = admin()
    before = api.get("/users/count").json()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel=os.environ.get("PW_CHANNEL", "chrome"))

        # First time: the PID creates the account, then Keycloak offers the member credential.
        mari_wallet = Wallet(MARI)
        first = sign_in(browser, mari_wallet, "first")
        ok = "id_token" in first
        idt = jwt_claims(first["id_token"]) if ok else {}
        member = claims_of(first["offered"]) if first.get("offered") else {}
        check("first sign-in completes the OIDC code flow", ok, json.dumps(first.get("error", ""))[:300])
        check("first sign-in creates an account from the PID", ok and idt.get("given_name") == "Mari"
              and idt.get("family_name") == "Maasikas", f"sub={idt.get('sub')} name={idt.get('name')}")
        check("username is random, not the PID identifier",
              ok and idt.get("preferred_username", "").startswith("u-"), idt.get("preferred_username", ""))
        check("wallet disclosed only the requested PID attributes", ok and "birthdate" not in first["disclosed"],
              ", ".join(first.get("disclosed", [])))
        check("after the PID sign-in, the wallet receives a member credential for this account",
              member.get("vct") == MEMBER_VCT and member.get("sub") == idt.get("sub")
              and member.get("iss") == REALM and "cnf" in member,
              f"vct={member.get('vct')} sub={member.get('sub')} iss={member.get('iss')}")
        check("the member credential holds no PID data",
              bool(member) and not {"personal_administrative_number", "given_name", "family_name",
                                    "birthdate"} & set(member), ", ".join(sorted(member)))

        if ok:
            # Single sign-on: a second app in the same browser gets a code without any login page.
            ctx = first["context"]
            page = ctx.new_page()
            _, challenge = pkce()
            page.goto(auth_url("test-app-2", "http://localhost:8098/callback", challenge))
            page.wait_for_url("http://localhost:8098/**", timeout=10000)
            check("second app signs in without a second wallet prompt",
                  "code=" in LANDED.get(8098, ""), LANDED.get(8098, "")[:80])

        # Later sign-ins: the member credential alone, from a new browser; no offer this time.
        again = sign_in(browser, mari_wallet, "member", profile="member")
        check("signing in with the member credential lands on the same account",
              sub_of(again) == idt.get("sub"), f"sub={sub_of(again)} {again.get('error', '')}")
        check("a member-credential sign-in asks no PID and offers nothing",
              "id_token" in again and again["disclosed"] == ["sub"] and again.get("offered") is None,
              ", ".join(again.get("disclosed", [])))

        # Lost wallet: a new device with a freshly issued PID and no member credential.
        new_device = Wallet(MARI)
        lost = sign_in(browser, new_device, "lost-wallet")
        check("lost wallet: the PID signs in to the same account and a new member credential is issued",
              sub_of(lost) == idt.get("sub") and lost.get("offered")
              and claims_of(lost["offered"]).get("sub") == idt.get("sub"), f"sub={sub_of(lost)}")
        new_device.remove_pid()
        after_lost = sign_in(browser, new_device, "new-member", profile="member")
        check("the new device's member credential signs in to the same account",
              sub_of(after_lost) == idt.get("sub"), f"sub={sub_of(after_lost)} {after_lost.get('error', '')}")

        # Not a check, a fact to know: credentials are not revoked when a new one is issued.
        old = sign_in(browser, mari_wallet, "old-member", profile="member")
        print("INFO the lost wallet's old member credential still signs in:", sub_of(old) == idt.get("sub"))

        other_wallet = Wallet(JAAN)
        other = sign_in(browser, other_wallet, "other")
        check("a different person gets a different account and their own member credential",
              sub_of(other) not in (None, idt.get("sub"))
              and claims_of(other["offered"]).get("sub") == sub_of(other), f"sub={sub_of(other)}")

        no_member = sign_in(browser, Wallet(MARI), "no-member", profile="member")
        check("the member button needs a member credential (a PID alone is not offered)",
              "error" in no_member, str(no_member.get("error", ""))[:120])

        forger = Wallet()
        forger.add(*forge_member(idt.get("sub", "x"), MEMBER_VCT, REALM))
        forged_member = sign_in(browser, forger, "forged-member", profile="member")
        check("a forged member credential for Mari's account is refused, with a message",
              "error" in forged_member and forged_member.get("message_shown") is True,
              json.dumps(forged_member.get("error", {}))[:160])

        rogue = sign_in(browser, Wallet(MARI, issuer="rogue-issuer", iss="ROGUE-PID-PROVIDER"), "rogue")
        check("PID issuer not on the trust list is refused, with a message",
              "error" in rogue and rogue.get("message_shown") is True, json.dumps(rogue.get("error", {}))[:160])

        # The admin console lives on its own address (on the server: an SSH tunnel
        # over the tailnet), and so does the master realm's sign-in.
        admin_page = browser.new_page()
        admin_page.goto(f"{KC_ADMIN}/admin/master/console/")
        admin_page.wait_for_selector("input[name=username]", timeout=30000)
        login_on_admin_address = admin_page.url.startswith(f"{KC_ADMIN}/realms/master/")
        admin_page.fill("input[name=username]", "admin")
        admin_page.fill("input[name=password]", ENV["KC_ADMIN_PASSWORD"])
        admin_page.press("input[name=password]", "Enter")
        admin_page.wait_for_url(f"{KC_ADMIN}/admin/master/console/**", timeout=30000)
        check("admin sign-in and console stay on the admin address", login_on_admin_address,
              admin_page.url[:60])

        forged = sign_in(browser, Wallet(MARI, issuer="rogue-issuer"), "forged")
        check("untrusted key claiming the trusted PID issuer's name is refused", "error" in forged,
              json.dumps(forged.get("error", {}))[:160])
        browser.close()

    api = admin()  # the first admin token has expired by now
    after = api.get("/users/count").json()
    check("exactly two accounts: Mari's and Jaan's", after - before == 2, f"{before} -> {after}")
    if idt.get("sub"):
        user = api.get(f"/users/{idt['sub']}").json()
        links = api.get(f"/users/{idt['sub']}/federated-identity").json()
        print("account:", json.dumps({k: user.get(k) for k in ("username", "firstName", "lastName", "email",
                                                               "attributes")}))
        print("federated link:", json.dumps(links))
        check("account carries no password", not any(
            c.get("type") == "password" for c in api.get(f"/users/{idt['sub']}/credentials").json()))
    check("account console is switched off", httpx.get(f"{REALM}/account/").status_code != 200)

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed; screenshots in {OUT}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
