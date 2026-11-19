"""register-app.py --site-status, against a stand-in for auth.sustenaut.eu: one scenario per outcome."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

from pytest_bdd import parsers, scenarios, then, when

scenarios("register-app.feature")

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("register_app", ROOT / "register-app.py")
app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(app)

SITE = "https://site.example.org"


@when(parsers.parse('the site\'s status is asked of the "{name}" service'))
def site_status(ctx, monkeypatch, name):
    """register-app.py's main, in-process, the realm at the stand-in's address."""
    auth = os.environ[f"{name.upper()}_URL"] + "/realms/team"
    monkeypatch.setattr(sys, "argv", [
        "register-app.py", "--site-status", "--state-dir", str(ctx.directory / "state"), "--auth", auth,
        "--domain", "example.org", "--redirect", f"{SITE}/oauth2/callback", "--logout", f"{SITE}/", "--role", "site",
    ])
    ctx.attempt(lambda: sys.exit(app.main()))


@then(parsers.parse('the file "{path}" is readable and writable by its owner alone'))
def owner_alone(ctx, path):
    mode = (ctx.directory / path).stat().st_mode & 0o777
    assert mode == 0o600, oct(mode)
