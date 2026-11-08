# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography>=44"]
# ///
"""Local only: the DNSSEC keys the compose stack's nameserver (ns1) signs example.net and
sustenaut.eu with, and the trust anchors Keycloak validates them from: example.net's for the
family realm, sustenaut.eu's for the team realm (their trustAnchors).

Writes dev/.pki/dns/K<zone>.key and .private (BIND format, as CoreDNS's dnssec plugin
reads them) and prints the .env lines:

  uv run dev/dnskeys.py >> .env

Each realm trusts only its own zone's key, so to the family realm sustenaut.eu is a domain
it cannot validate, which shows that such a domain can't register.
"""

import base64
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

ZONES = {"example.net": "FAMILY_DNSSEC_TRUST_ANCHORS", "sustenaut.eu": "TEAM_DNSSEC_TRUST_ANCHORS"}
OUT = Path(__file__).resolve().parent / ".pki" / "dns"


def key_tag(rdata: bytes) -> int:
    """RFC 4034, appendix B."""
    total = sum(b << 8 if i % 2 == 0 else b for i, b in enumerate(rdata))
    return (total + (total >> 16)) & 0xFFFF


def make_key(zone: str) -> str:
    """Writes the zone's key files; the DNSKEY record that is its trust anchor."""
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    public = numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    flags, protocol, algorithm = 257, 3, 13  # key-signing key, DNSSEC, ECDSAP256SHA256
    tag = key_tag(struct.pack("!HBB", flags, protocol, algorithm) + public)
    dnskey = f"{zone}. IN DNSKEY {flags} {protocol} {algorithm} {base64.b64encode(public).decode()}"
    (OUT / f"K{zone}.key").write_text(f"; key tag {tag}\n{dnskey}\n")
    private = key.private_numbers().private_value.to_bytes(32, "big")
    (OUT / f"K{zone}.private").write_text(
        "Private-key-format: v1.3\nAlgorithm: 13 (ECDSAP256SHA256)\n"
        f"PrivateKey: {base64.b64encode(private).decode()}\n")
    (OUT / f"K{zone}.private").chmod(0o644)  # read by CoreDNS in its container; a throwaway test key
    return dnskey


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for zone, variable in ZONES.items():
        print(f"{variable}={make_key(zone)}")

if __name__ == "__main__":
    main()
