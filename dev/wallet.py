"""A scripted test wallet, plus the test PID provider that fills it. Local development only.

It stands in for the EU reference wallet until a real one can reach this
machine: the test PID provider (dev/.pki/issuer.*, on the local trust list)
issues an SD-JWT VC PID of type urn:eudi:pid:1 bound to a fresh holder key,
and the wallet presents it over OpenID4VP (DCQL, direct_post) with a
key-binding JWT, the way a real wallet does. It also accepts credential
offers over OpenID4VCI (pre-authorized code, JWT key proof), which is how
Keycloak issues the Sustenaut member credential into it, and presents
whichever of its credentials a request asks for.

What it does not do: verify the verifier's request-object signature and
access certificate, encrypt the response (direct_post.jwt), or keep keys in a
secure element.
"""

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

PKI = Path(__file__).resolve().parent / ".pki"
PID_VCT = "urn:eudi:pid:1"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_json(obj) -> str:
    return b64u(json.dumps(obj, separators=(",", ":")).encode())


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def es256(signing_input: str, key: ec.EllipticCurvePrivateKey) -> str:
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def jws(header: dict, payload: dict, key) -> str:
    signing_input = b64u_json(header) + "." + b64u_json(payload)
    return signing_input + "." + es256(signing_input, key)


def public_jwk(key: ec.EllipticCurvePrivateKey) -> dict:
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}


def load_issuer(name: str):
    key = serialization.load_pem_private_key((PKI / f"{name}.key").read_bytes(), None)
    cert = x509.load_pem_x509_certificate((PKI / f"{name}.pem").read_bytes())
    return key, base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


@dataclass
class Person:
    personal_administrative_number: str
    given_name: str
    family_name: str


def issue_pid(person: Person, holder_key, issuer: str = "issuer", iss: str = "SUSTENAUT-TEST-PID-PROVIDER") -> str:
    """The test PID provider's SD-JWT VC, every attribute selectively disclosable."""
    key, cert_b64 = load_issuer(issuer)
    disclosures = [
        b64u_json([b64u(secrets.token_bytes(16)), name, value])
        for name, value in (
            ("personal_administrative_number", person.personal_administrative_number),
            ("given_name", person.given_name),
            ("family_name", person.family_name),
            ("birthdate", "1990-01-01"),
            ("issuing_country", "EE"),
        )
    ]
    now = int(time.time())
    payload = {
        "iss": iss,
        "vct": PID_VCT,
        "iat": now,
        "exp": now + 86400,
        "_sd_alg": "sha-256",
        "_sd": sorted(b64u(hashlib.sha256(d.encode()).digest()) for d in disclosures),
        "cnf": {"jwk": public_jwk(holder_key)},
    }
    header = {"alg": "ES256", "typ": "dc+sd-jwt", "x5c": [cert_b64]}
    return jws(header, payload, key) + "~" + "~".join(disclosures) + "~"


class Wallet:
    """Holds credentials (each SD-JWT VC with its own holder key) and answers requests with them."""

    def __init__(self, person: Person | None = None, issuer: str = "issuer",
                 iss: str = "SUSTENAUT-TEST-PID-PROVIDER"):
        self.http = httpx.Client(timeout=20)
        self.credentials: list[tuple[str, ec.EllipticCurvePrivateKey]] = []  # a new device each time
        if person is not None:
            holder_key = ec.generate_private_key(ec.SECP256R1())
            self.credentials.append((issue_pid(person, holder_key, issuer, iss), holder_key))

    def add(self, credential: str, holder_key) -> None:
        self.credentials.append((credential, holder_key))

    def remove_pid(self) -> None:
        self.credentials = [c for c in self.credentials if vct_of(c[0]) != PID_VCT]

    def find(self, vct: str):
        """The newest credential of this type."""
        matches = [c for c in self.credentials if vct_of(c[0]) == vct]
        return matches[-1] if matches else None

    def accept_offer(self, offer_link: str) -> str:
        """Take an openid-credential-offer:// link (QR content) and fetch the credential it offers."""
        query = urllib.parse.parse_qs(urllib.parse.urlparse(offer_link).query)
        if "credential_offer_uri" in query:
            offer = self.http.get(query["credential_offer_uri"][0]).raise_for_status().json()
        else:
            offer = json.loads(query["credential_offer"][0])
        issuer = offer["credential_issuer"]
        config_id = offer["credential_configuration_ids"][0]
        grant = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]

        meta = self.http.get(f"{issuer}/.well-known/openid-credential-issuer").raise_for_status().json()
        auth_server = (meta.get("authorization_servers") or [issuer])[0]
        as_meta = self.http.get(f"{auth_server}/.well-known/openid-configuration").raise_for_status().json()
        token = self.http.post(as_meta["token_endpoint"], data={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": grant["pre-authorized_code"],
        }).raise_for_status().json()
        nonce = self.http.post(meta["nonce_endpoint"]).raise_for_status().json()["c_nonce"]

        holder_key = ec.generate_private_key(ec.SECP256R1())
        proof = jws({"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": public_jwk(holder_key)},
                    {"aud": issuer, "iat": int(time.time()), "nonce": nonce}, holder_key)
        body = {"proofs": {"jwt": [proof]}}
        details = token.get("authorization_details") or []
        ids = [i for d in details for i in d.get("credential_identifiers", [])]
        if ids:
            body["credential_identifier"] = ids[0]
        else:
            body["credential_configuration_id"] = config_id
        reply = self.http.post(meta["credential_endpoint"], json=body,
                               headers={"Authorization": f"Bearer {token['access_token']}"})
        if reply.status_code != 200:
            raise RuntimeError(f"credential request failed: {reply.status_code} {reply.text}")
        credential = reply.json()["credentials"][0]["credential"]
        self.add(credential, holder_key)
        return credential

    def present(self, authorization_request: str) -> dict:
        """Take an openid4vp:// link (QR content), answer it, return the verifier's reply."""
        query = urllib.parse.parse_qs(urllib.parse.urlparse(authorization_request).query)
        request_jwt = self.http.get(query["request_uri"][0]).raise_for_status().text
        request = json.loads(unb64u(request_jwt.split(".")[1]))
        assert request["client_id"] == query["client_id"][0], "client_id in link and request differ"

        wanted = request["dcql_query"]["credentials"][0]
        assert wanted["format"] == "dc+sd-jwt"
        held = next((self.find(v) for v in wanted["meta"]["vct_values"] if self.find(v)), None)
        if held is None:
            return {"status": None, "body": "no matching credential in the wallet", "disclosed": []}
        credential, holder_key = held
        wanted_claims = {c["path"][0] for c in wanted["claims"]}

        # Disclose only what was asked for (claims that are not selectively disclosable are always shown).
        jwt, *disclosures = credential.rstrip("~").split("~")
        shown = [d for d in disclosures if json.loads(unb64u(d))[1] in wanted_claims]
        sd_jwt = jwt + "~" + "".join(d + "~" for d in shown)
        kb = jws(
            {"alg": "ES256", "typ": "kb+jwt"},
            {
                "iat": int(time.time()),
                "aud": request["client_id"],
                "nonce": request["nonce"],
                "sd_hash": b64u(hashlib.sha256(sd_jwt.encode()).digest()),
            },
            holder_key,
        )
        form = {"vp_token": json.dumps({wanted["id"]: [sd_jwt + kb]}), "state": request["state"]}
        reply = self.http.post(request["response_uri"], data=form)
        return {"status": reply.status_code, "body": reply.text, "disclosed": sorted(wanted_claims)}


def vct_of(credential: str) -> str:
    return json.loads(unb64u(credential.split("~")[0].split(".")[1])).get("vct")


def claims_of(credential: str) -> dict:
    jwt, *disclosures = credential.rstrip("~").split("~")
    claims = json.loads(unb64u(jwt.split(".")[1]))
    for d in disclosures:
        _, name, value = json.loads(unb64u(d))
        claims[name] = value
    return claims


def forge_member(sub: str, vct: str, realm_issuer: str) -> tuple[str, ec.EllipticCurvePrivateKey]:
    """A member credential for someone else's account, signed with a key that is not the realm's."""
    key = ec.generate_private_key(ec.SECP256R1())
    holder_key = ec.generate_private_key(ec.SECP256R1())
    now = int(time.time())
    payload = {"iss": realm_issuer, "vct": vct, "sub": sub, "iat": now, "exp": now + 3600,
               "_sd_alg": "sha-256", "_sd": [], "cnf": {"jwk": public_jwk(holder_key)}}
    return jws({"alg": "ES256", "typ": "dc+sd-jwt"}, payload, key) + "~", holder_key


if __name__ == "__main__":
    import sys

    # Manual use: python wallet.py 'openid4vp://...' [pan] [given] [family]
    link = sys.argv[1]
    person = Person(*(sys.argv[2:5] or ["EE-38001010000", "Mari", "Maasikas"]))
    print(json.dumps(Wallet(person, os.environ.get("ISSUER", "issuer")).present(link), indent=2))
