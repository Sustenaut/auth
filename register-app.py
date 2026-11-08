"""Registers a domain's sites for sign-in with auth.sustenaut.eu (app registration, README).

Standard library only, so it runs where the client is kept: on the Sustenaut k3s server,
for sustenaut.eu's team sites (business-plan/opportunity-site/register-client.sh pipes it to python3
there). One registration, one client, per domain and realm: the client's id is the
domain, and each site on the domain adds its own redirect URIs to it. The state lives in
--state-dir:

  registration.json  a request waiting for its DNS record (id, the record)
  client.json        the issued client: client_id, client_secret, registration access token

Addresses come from --auth and --domain, never from those files, so a changed file cannot send
a token elsewhere.

Asking and verifying need the registrant signed in: someone with a verified address at
the domain, with an account in the realm (the team realm: var.team_registrant, given one
by invite-team.sh). This prints a link and a code (OAuth device flow) on stderr and
waits for them to sign in there.

Each run moves one step:
  no state      sign in, ask for the client; the TXT record to publish     -> "waiting"
  waiting       sign in, verify; once auth.sustenaut.eu sees the record
                (DNSSEC-validated), store the client                      -> "registered"
                (not yet -> "waiting" again; expired -> a new request)
  registered    check the client still answers to its registration token,
                add this site's redirect URIs if it lacks them, and
                declare its --role service roles (idempotent)             -> "ok"

Prints one JSON object on stdout: {"status": ..., "record": {"name", "value"}?, "message"?}.
Exit 0 for ok/registered, 3 for waiting, 1 for anything else.

--status moves nothing: it reads --state-dir only, never signs in, calls nothing and creates
nothing, and says which step is next: {"status": "registered", "client_id"} when client.json
is there, {"status": "waiting", "record"} when registration.json is, else {"status": "none"};
exit 0 for each. The other arguments are taken as for a step, so the same command line asks
(pubkit's deploy walk checks auth.sign-in-client so).
"""

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def call(method: str, url: str, body: dict | None = None, token: str | None = None,
         form: dict | None = None, basic: tuple[str, str] | None = None) -> tuple[int, dict]:
    if form is not None:
        data, kind = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
    elif body is not None:
        data, kind = json.dumps(body).encode(), "application/json"
    else:
        data, kind = None, None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if kind:
        request.add_header("Content-Type", kind)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    if basic:
        request.add_header("Authorization", "Basic " + base64.b64encode(":".join(basic).encode()).decode())
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read() or b"{}")
        except ValueError:
            return error.code, {}


def save(path: Path, value: dict) -> None:
    old = os.umask(0o077)
    try:
        path.write_text(json.dumps(value, indent=2) + "\n")
    finally:
        os.umask(old)


def say(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def sign_in(auth: str, domain: str) -> str:
    """The registrant signs in (device flow of the client app-registration); their access token."""
    status, start = call("POST", f"{auth}/protocol/openid-connect/auth/device", form={"client_id": "app-registration"})
    if status != 200:
        raise RuntimeError(f"the device sign-in could not start (HTTP {status}: {start})")
    say(f"\n  Sign in as the registrant of {domain} (an address @{domain}, invited to {auth}):")
    say(f"    open   {start['verification_uri_complete']}")
    say(f"    (or {start['verification_uri']} and enter the code {start['user_code']})")
    say("  then confirm. Waiting...")
    interval = start.get("interval", 5)
    deadline = time.time() + start.get("expires_in", 600)
    while time.time() < deadline:
        time.sleep(interval)
        status, answer = call("POST", f"{auth}/protocol/openid-connect/token", form={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "client_id": "app-registration",
            "device_code": start["device_code"]})
        if status == 200:
            say("  Signed in.")
            return answer["access_token"]
        if answer.get("error") == "slow_down":
            interval += 5
        elif answer.get("error") != "authorization_pending":
            raise RuntimeError(f"the sign-in was not completed ({answer.get('error')})")
    raise RuntimeError("the sign-in timed out")


def add_site(client_uri: str, client: dict, rep: dict, redirects: list[str], logouts: list[str]) -> str:
    """Adds the site's URIs to the client if it lacks them; "" or what went wrong."""
    have = rep.get("redirectUris") or []
    attributes = rep.get("attributes") or {}
    have_logouts = [u for u in (attributes.get("post.logout.redirect.uris") or "").split("##") if u]
    if all(u in have for u in redirects) and all(u in have_logouts for u in logouts):
        return ""
    rep["redirectUris"] = have + [u for u in redirects if u not in have]
    attributes["post.logout.redirect.uris"] = "##".join(have_logouts + [u for u in logouts if u not in have_logouts])
    rep["attributes"] = attributes
    token = rep.get("registrationAccessToken") or client["registration_access_token"]
    status, answer = call("PUT", client_uri, body=rep, token=token)
    if status != 200:
        return f"adding {', '.join(redirects)} to the client answered HTTP {status}: {answer}"
    if answer.get("registrationAccessToken"):
        client["registration_access_token"] = answer["registrationAccessToken"]
    say(f"  Added {', '.join(redirects)} to the client {client['client_id']}.")
    return ""


def declare(auth: str, domain: str, client: dict, roles: list[str]) -> str:
    """Declares the site's service roles on the client (in a realm that has them); "" or what went wrong."""
    if not roles:
        return ""
    status, answer = call("POST", f"{auth}/app-registration/{domain}/roles", body={"roles": roles},
                          basic=(client["client_id"], client["client_secret"]))
    return "" if status == 200 else f"declaring the roles {', '.join(roles)} answered HTTP {status}: {answer}"


def state_dir(given: str) -> Path:
    """--state-dir, which must be an absolute path without "..", resolved."""
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", given) or ".." in given.split("/"):
        raise SystemExit(f"--state-dir must be an absolute path without '..', not {given!r}")
    return Path(os.path.realpath(given))


def status(state: Path) -> dict:
    """Which step is next, from the state directory alone."""
    client_file, waiting_file = state / "client.json", state / "registration.json"
    if client_file.exists():
        return {"status": "registered", "client_id": json.loads(client_file.read_text())["client_id"]}
    if waiting_file.exists():
        return {"status": "waiting", "record": json.loads(waiting_file.read_text())["record"]}
    return {"status": "none"}


def step(state: Path, auth: str, domain: str, name: str, redirects: list[str], logouts: list[str],
         roles: list[str]) -> tuple[int, dict]:
    client_file, waiting_file = state / "client.json", state / "registration.json"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)

    if client_file.exists():
        client = json.loads(client_file.read_text())
        client_uri = f"{auth}/clients-registrations/default/{domain}"
        status, rep = call("GET", client_uri, token=client["registration_access_token"])
        if status != 200:
            return 1, {"status": "error", "message": f"the client {client['client_id']} does not answer to its "
                       f"registration token (HTTP {status}): it was revoked (the TXT record _sustenaut-auth.{domain} "
                       "went missing or changed; the registrant was emailed), replaced by a newer registration, or "
                       f"deleted. To register anew, remove {client_file} and run again."}
        if rep.get("registrationAccessToken"):  # Keycloak may hand out a new one
            client["registration_access_token"] = rep["registrationAccessToken"]
        problem = declare(auth, domain, client, roles) or add_site(client_uri, client, rep, redirects, logouts)
        save(client_file, client)
        if problem:
            return 1, {"status": "error", "message": problem}
        return 0, {"status": "ok", "client_id": client["client_id"]}

    try:
        token = sign_in(auth, domain)
    except RuntimeError as error:
        return 1, {"status": "error", "message": str(error)}

    if waiting_file.exists():
        waiting = json.loads(waiting_file.read_text())
        request_id = waiting.get("id", "")
        if not re.fullmatch("[0-9a-f]{32}", request_id):
            return 1, {"status": "error", "message": f"{waiting_file} has no request id; remove it and run again"}
        status, answer = call("POST", f"{auth}/app-registration/{request_id}/verify", token=token)
        if status == 200:
            save(client_file, answer)
            waiting_file.unlink()
            problem = declare(auth, domain, answer, roles)  # a later run may name more than the request did
            if problem:
                return 1, {"status": "error", "message": problem}
            return 0, {"status": "registered", "client_id": answer["client_id"]}
        if status == 409:
            return 3, {"status": "waiting", "record": waiting["record"], "message": answer.get("message", "")}
        if status not in (404, 410):
            return 1, {"status": "error", "message": f"verify answered HTTP {status}: {answer}"}
        waiting_file.unlink()  # expired, or asked by someone else: ask again

    body = {"domain": domain, "display_name": name, "redirect_uris": redirects, "post_logout_redirect_uris": logouts}
    if roles:
        body["roles"] = roles
    status, answer = call("POST", f"{auth}/app-registration", token=token, body=body)
    if status != 201:
        return 1, {"status": "error", "message": f"the registration request answered HTTP {status}: "
                   f"{answer.get('error_description', answer)}"}
    save(waiting_file, answer)
    return 3, {"status": "waiting", "record": answer["record"], "message": "publish this record"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--auth", required=True, help="the realm, e.g. https://auth.sustenaut.eu/realms/team")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--name", help="the client's display name (default: the domain)")
    parser.add_argument("--redirect", action="append", required=True, help="a redirect URI of this site (repeatable)")
    parser.add_argument("--logout", action="append", default=[], help="a post-logout redirect URI (repeatable)")
    parser.add_argument("--role", action="append", default=[],
                        help="a service role this site understands (repeatable; realms with service roles)")
    parser.add_argument("--status", action="store_true",
                        help="say which step is next, from --state-dir alone, and change nothing")
    args = parser.parse_args()
    if args.status:
        print(json.dumps(status(state_dir(args.state_dir))))
        return 0
    code, result = step(state_dir(args.state_dir), args.auth.rstrip("/"), args.domain, args.name or args.domain,
                        args.redirect, args.logout, args.role)
    print(json.dumps(result))
    return code


if __name__ == "__main__":
    sys.exit(main())
