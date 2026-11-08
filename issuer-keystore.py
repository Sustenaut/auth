# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography>=44"]
# ///
"""Make the key that signs Sustenaut member credentials, as a PKCS#12 keystore.

Keycloak follows HAIP: a credential's signing certificate must not be self-signed. So
this makes a small CA ("Sustenaut member credentials CA") and an ES256 issuer key with a
certificate from it, and packs key and chain into a PKCS#12 keystore (alias
member-issuer) under a random password. Only our own sign-in trusts these credentials
(the plugin's self trust uses the realm's keys), so our own CA is enough.

Prints two lines to put in Bitwarden (production: secrets auth-issuer-keystore and
auth-issuer-keystore-password) or in .env (local):

  SUSTENAUT_ISSUER_KEYSTORE_B64=...       the keystore, base64
  SUSTENAUT_ISSUER_KEYSTORE_PASSWORD=...

The CA's private key is discarded: the issuer certificate is valid for 5 years; make a
new keystore before then. Usage: uv run issuer-keystore.py [common-name-suffix]
"""

import base64
import datetime as dt
import secrets
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


def name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sustenaut"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def main() -> None:
    suffix = f" ({sys.argv[1]})" if len(sys.argv) > 1 else ""
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(name("Sustenaut member credentials CA" + suffix))
        .issuer_name(name("Sustenaut member credentials CA" + suffix))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name("Sustenaut member credentials" + suffix))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    password = secrets.token_hex(24)
    p12 = pkcs12.serialize_key_and_certificates(
        b"member-issuer", key, leaf, [ca],
        serialization.BestAvailableEncryption(password.encode()),
    )
    print(f"SUSTENAUT_ISSUER_KEYSTORE_B64={base64.b64encode(p12).decode()}")
    print(f"SUSTENAUT_ISSUER_KEYSTORE_PASSWORD={password}")


if __name__ == "__main__":
    main()
