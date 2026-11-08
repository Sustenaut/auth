#!/bin/bash
# Writes the member-credential issuer keystore (issuer-keystore.py) from the environment
# into the realm's keystore folder, where the realm's java-keystore key provider reads it,
# then starts Keycloak. The keystore never goes into the image.
set -euo pipefail
if [[ -n "${SUSTENAUT_ISSUER_KEYSTORE_B64:-}" ]]; then
    mkdir -p /opt/keycloak/data/sustenaut
    base64 -d <<<"$SUSTENAUT_ISSUER_KEYSTORE_B64" > /opt/keycloak/data/sustenaut/member-issuer.p12
    unset SUSTENAUT_ISSUER_KEYSTORE_B64
fi
exec /opt/keycloak/bin/kc.sh "$@"
