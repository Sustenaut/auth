"""The team access check, for a site's server: has this person's access changed? Copy this file
into the site; standard library only. The contract, for other languages, is in the README
("Checking access on each request").

A site asks on each request it gets, never in the background: nothing here runs on a timer, so a
site nobody is using asks nothing, and an idle browser tab costs nothing. On a request it fetches
the realm's hash of its client's access state (or uses one fetched within hash_ttl seconds). If
that differs from the hash stored for this person, or their last full check is older than
full_every seconds, it does one full check at userinfo with their access token (session alive,
their roles now) and stores the answer. So an unchanged list costs Keycloak one small request every
hash_ttl seconds at most, however many people are reading.

If Keycloak cannot be reached, someone whose stored hash is still the last one known keeps reading
with their last roles; changes are refused, and so is anyone who cannot be vouched for.

    check = AccessCheck("https://auth.sustenaut.eu/realms/team", client_id, client_secret, role="opportunity")
    decision = check.check(email, access_token, write=request.method != "GET")
    if not decision.allowed: ...  # decision.reason says which: no_role, sign_in or unavailable
    decision.roles               # the person's access claim, "controller" included if they are one
"""
from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

OK = "ok"
DEGRADED = "degraded"  # allowed, on the last answer, while Keycloak cannot be reached
NO_ROLE = "no_role"  # signed in, without the site's role: refuse
SIGN_IN = "sign_in"  # the session has ended, or the account was removed: send them to sign in
UNAVAILABLE = "unavailable"  # Keycloak cannot be reached and this cannot be vouched for: refuse, try later


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    roles: frozenset[str] = frozenset()


@dataclass(frozen=True)
class _Stored:
    hash: str
    roles: frozenset[str]
    checked: float


class AccessCheck:
    def __init__(self, realm_url: str, client_id: str, client_secret: str, role: str | None = None,
                 hash_ttl: float = 2, full_every: float = 300, max_people: int = 1000, timeout: float = 3,
                 clock: Callable[[], float] = time.monotonic):
        self.realm_url = realm_url.rstrip("/")
        self.client_id, self.client_secret = client_id, client_secret
        self.role, self.hash_ttl, self.full_every = role, hash_ttl, full_every
        self.max_people, self.timeout, self.clock = max_people, timeout, clock
        self._lock = threading.Lock()
        self._people: dict[str, _Stored] = {}
        self._known: str | None = None  # the last hash Keycloak gave
        self._fetched: float | None = None

    def check(self, person: str, access_token: str | None, write: bool = False) -> Decision:
        """Whether this request of this person may go on. write: it changes something."""
        with self._lock:
            stored = self._people.get(person)
        current = self._hash()
        if current is None:
            return self._on_the_last_answer(stored, write)
        if stored and stored.hash == current and self.clock() - stored.checked < self.full_every:
            return self._decide(stored.roles, OK)
        if not access_token:
            self._forget(person)
            return Decision(False, SIGN_IN)
        answer = self._userinfo(access_token)
        if answer is None:
            return self._on_the_last_answer(stored, write)
        if answer is False:
            self._forget(person)
            return Decision(False, SIGN_IN)
        # The hash asked for before the full check: a change between the two is seen next time.
        roles = frozenset(r for r in answer.get("access") or [] if isinstance(r, str))
        with self._lock:
            self._people[person] = _Stored(current, roles, self.clock())
            while len(self._people) > self.max_people:
                self._people.pop(next(iter(self._people)))
        return self._decide(roles, OK)

    def _decide(self, roles: frozenset[str], reason: str) -> Decision:
        if self.role is not None and self.role not in roles:
            return Decision(False, NO_ROLE, roles)
        return Decision(True, reason, roles)

    def _on_the_last_answer(self, stored: _Stored | None, write: bool) -> Decision:
        with self._lock:
            known = self._known
        if write or stored is None or stored.hash != known:
            return Decision(False, UNAVAILABLE)
        return self._decide(stored.roles, DEGRADED)

    def _forget(self, person: str) -> None:
        with self._lock:
            self._people.pop(person, None)

    def _hash(self) -> str | None:
        """The current hash (fetched at most every hash_ttl seconds); None if Keycloak cannot say."""
        with self._lock:
            if self._fetched is not None and self.clock() - self._fetched < self.hash_ttl:
                return self._known
        client_id = urllib.parse.quote(self.client_id, safe="")
        secret = urllib.parse.quote(self.client_secret, safe="")
        basic = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
        status, body = self._get(f"{self.realm_url}/app-registration/{client_id}/access-state",
                                 {"Authorization": f"Basic {basic}"})
        fresh = body.get("hash") if status == 200 and isinstance(body, dict) else None
        with self._lock:
            if fresh:
                self._known, self._fetched = fresh, self.clock()
            else:
                self._fetched = None
        return fresh

    def _userinfo(self, access_token: str):
        """Userinfo's answer; False if the token is refused (session over); None if Keycloak cannot say."""
        status, body = self._get(f"{self.realm_url}/protocol/openid-connect/userinfo",
                                 {"Authorization": f"Bearer {access_token}"})
        if status == 200 and isinstance(body, dict):
            return body
        return False if status in (401, 403) else None

    def _get(self, url: str, headers: dict[str, str]) -> tuple[int, object]:
        request = urllib.request.Request(url, headers={"Accept": "application/json", **headers})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, {}
        except (OSError, ValueError):
            return 0, {}
