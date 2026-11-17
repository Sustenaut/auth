"""register-app.py --site-status, against a stand-in for auth.sustenaut.eu: one test per outcome."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from pytest_bdd import scenarios, then

scenarios("register-app.feature")

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("register_app", ROOT / "register-app.py")
app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(app)

AUTH, DOMAIN = "https://auth.example/realms/team", "example.org"
SITE = "https://site.example.org"


class Keycloak:
    """The registration endpoint and the roles endpoint, as the client sees them."""

    def __init__(self, redirects, logouts, roles, rotate=False, answers=200):
        self.redirects, self.logouts, self.roles, self.rotate, self.answers = redirects, logouts, roles, rotate, answers
        self.asked = []

    def __call__(self, method, url, body=None, token=None, form=None, basic=None):
        self.asked.append((method, url, body, token))
        if url.endswith(f"/clients-registrations/default/{DOMAIN}"):
            if self.answers != 200:
                return self.answers, {}
            rep = {"redirectUris": self.redirects,
                   "attributes": {"post.logout.redirect.uris": "##".join(self.logouts)}}
            if self.rotate:
                rep["registrationAccessToken"] = "token-2"
            return 200, rep
        if url.endswith(f"/app-registration/{DOMAIN}/roles"):
            assert body == {"roles": []}, "site-status declares no role"
            return 200, {"roles": self.roles}
        raise AssertionError(url)


@pytest.fixture
def state(tmp_path):
    (tmp_path / "client.json").write_text(json.dumps(
        {"client_id": DOMAIN, "client_secret": "secret-1", "registration_access_token": "token-1"}))
    return tmp_path


def run(monkeypatch, state, keycloak):
    monkeypatch.setattr(app, "call", keycloak)
    return app.site_status(state, AUTH, DOMAIN, [f"{SITE}/oauth2/callback"], [f"{SITE}/"], ["site"])


@then("a site whose uris and role are on the client is present")
def a_site_whose_uris_and_role_are_on_the_client_is_present(monkeypatch, state):
    code, lines = run(monkeypatch, state, Keycloak([f"{SITE}/oauth2/callback"], [f"{SITE}/"], ["other", "site"]))
    assert code == 0
    assert lines == [f"redirect {SITE}/oauth2/callback: present", f"logout {SITE}/: present", "role site: present"]


@then("a missing redirect is said")
def a_missing_redirect_is_said(monkeypatch, state):
    code, lines = run(monkeypatch, state, Keycloak(["https://other.example.org/oauth2/callback"], [f"{SITE}/"], ["site"]))
    assert code == 1 and f"redirect {SITE}/oauth2/callback: missing" in lines


@then("a missing role is said")
def a_missing_role_is_said(monkeypatch, state):
    code, lines = run(monkeypatch, state, Keycloak([f"{SITE}/oauth2/callback"], [f"{SITE}/"], ["other"]))
    assert code == 1 and "role site: missing" in lines


@then("no state file is unreadable")
def no_state_file_is_unreadable(monkeypatch, tmp_path):
    code, lines = run(monkeypatch, tmp_path, Keycloak([], [], []))
    assert code == 2 and lines[0].startswith("no registration:")


@then("a client that does not answer its token is unreadable")
def a_client_that_does_not_answer_its_token_is_unreadable(monkeypatch, state):
    code, lines = run(monkeypatch, state, Keycloak([], [], [], answers=401))
    assert code == 2 and "HTTP 401" in lines[0]


@then("a new registration token is kept and none is printed")
def a_new_registration_token_is_kept_and_none_is_printed(monkeypatch, state, capsys):
    run(monkeypatch, state, Keycloak([f"{SITE}/oauth2/callback"], [f"{SITE}/"], ["site"], rotate=True))
    assert json.loads((state / "client.json").read_text())["registration_access_token"] == "token-2"
    assert sorted(p.name for p in state.iterdir()) == ["client.json"]
    assert oct((state / "client.json").stat().st_mode & 0o777) == "0o600"
    out = capsys.readouterr()
    assert "token" not in out.out and "secret" not in out.out
