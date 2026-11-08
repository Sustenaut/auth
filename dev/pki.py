# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography>=44"]
# ///
"""Create the test trust material for local development, and only for that.

Writes to dev/.pki/ (git-ignored):

  ca.pem / ca.key            a test CA standing in for an EU PID provider's issuing CA,
                             and also signing the TLS certificate of the local trust-list host
  issuer.pem / issuer.key    the test PID provider's signing certificate (leaf, signed by ca)
  rogue-ca.pem, rogue-issuer.pem / .key
                             a second, untrusted provider, to prove rejection
  lote-signer.pem / .key     the key that signs the trust list (in production: the
                             European Commission's / member state's list operator)
  trustlist.pem / .key       TLS server certificate for https://trustlist:8443
  pid-providers.jwt          the signed ETSI TS 119 602 PID-provider list (LoTE),
                             naming only the trusted test provider

and prints the values the realm import needs, as lines for the .env file.
Run it again to refresh the list (it expires after 30 days).
"""

import base64
import datetime as dt
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parent / ".pki"
PROVIDER_ID = "SUSTENAUT-TEST-PID-PROVIDER"
ROGUE_ID = "ROGUE-PID-PROVIDER"
LOTE_TYPE = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList"
PID_ISSUANCE = "http://uri.etsi.org/19602/SvcType/PID/Issuance"
NOW = dt.datetime.now(dt.timezone.utc)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def der_b64(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def load_or_make_key(name: str) -> ec.EllipticCurvePrivateKey:
    path = OUT / f"{name}.key"
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), None)
    key = ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return key


def cert(name, key, subject_cn, issuer_cert=None, issuer_key=None, ca=False, san=None, days=365):
    path = OUT / f"{name}.pem"
    if path.exists():
        return x509.load_pem_x509_certificate(path.read_bytes())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=days))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True
        )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False)
    if issuer_cert:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
        )
    c = builder.sign(issuer_key or key, hashes.SHA256())
    path.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    return c


def es256_jws(header: dict, payload: dict, key: ec.EllipticCurvePrivateKey) -> str:
    signing_input = b64u(json.dumps(header).encode()) + "." + b64u(json.dumps(payload).encode())
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def provider_entry(provider_id: str, ca_cert: x509.Certificate) -> dict:
    return {
        "TrustedEntityInformation": {
            "TEName": [{"lang": "en", "value": provider_id}],
            "TETradeName": [{"lang": "en", "value": provider_id}],
        },
        "TrustedEntityServices": [
            {
                "ServiceInformation": {
                    "ServiceTypeIdentifier": PID_ISSUANCE,
                    "ServiceName": [{"lang": "en", "value": "PID issuance"}],
                    "ServiceDigitalIdentity": {"X509Certificates": [{"val": der_b64(ca_cert)}]},
                }
            }
        ],
    }


def main() -> None:
    OUT.mkdir(exist_ok=True)

    ca_key = load_or_make_key("ca")
    ca = cert("ca", ca_key, "Sustenaut test PID provider CA", ca=True, days=3650)
    issuer_key = load_or_make_key("issuer")
    cert("issuer", issuer_key, "Sustenaut test PID provider", ca, ca_key)

    rogue_ca_key = load_or_make_key("rogue-ca")
    rogue_ca = cert("rogue-ca", rogue_ca_key, "Rogue PID provider CA", ca=True, days=3650)
    rogue_issuer_key = load_or_make_key("rogue-issuer")
    cert("rogue-issuer", rogue_issuer_key, "Rogue PID provider", rogue_ca, rogue_ca_key)

    tls_key = load_or_make_key("trustlist")
    cert("trustlist", tls_key, "trustlist", ca, ca_key, san=["trustlist", "localhost"])
    # The family proof's stand-in for a domain's notify_url (dev/hooks.py, compose: hooks).
    hooks_key = load_or_make_key("hooks")
    cert("hooks", hooks_key, "hooks.example.net", ca, ca_key, san=["hooks.example.net"])

    lote_key = load_or_make_key("lote-signer")
    lote_cert = cert("lote-signer", lote_key, "Sustenaut test LoTE operator")

    # Only the trusted provider is on the list; the rogue one is not.
    lote = {
        "LoTE": {
            "ListAndSchemeInformation": {
                "LoTEType": LOTE_TYPE,
                "ListIssueDateTime": (NOW - dt.timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
                "NextUpdate": (NOW + dt.timedelta(days=30)).isoformat().replace("+00:00", "Z"),
            },
            "TrustedEntitiesList": [provider_entry(PROVIDER_ID, ca)],
        }
    }
    header = {"alg": "ES256", "typ": "trustlist+jwt", "x5c": [der_b64(lote_cert)]}
    (OUT / "pid-providers.jwt").write_text(es256_jws(header, lote, lote_key))
    del rogue_ca  # only its leaf is used, by the wallet

    print(f"SUSTENAUT_TRUST_LIST_SIGNING_CERT={der_b64(lote_cert)}")
    print(f"SUSTENAUT_PID_ISSUER={PROVIDER_ID}")
    print(f"wrote {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
