#!/usr/bin/env bash
# Once, before the first deploy walk: keeps the access-hash key auth already uses.
#
#   ./scripts/go-live-access-hash-key.sh
#
# Until the walk, the key of the team realm's access-state hash lived only in the Secret
# auth-secrets (push-secrets.sh made it there). The walk keeps it in Bitwarden as
# auth-access-hash-key, and makes a new one when Bitwarden has none, which costs every site
# one full access check per person and restarts Keycloak. This copies the cluster's key into
# Bitwarden instead, so the walk finds it ready and leaves auth-secrets as it is.
#
# Signed in to Sustenaut's tailnet. It asks, at a hidden prompt, for a Bitwarden access
# token that may write to the project Sustenaut, and keeps it only in its process. The key
# travels in the SSH stream and in memory: never on a command line, never in a file.
# Run it again and it writes the same value. Delete this script once the walk is all ready.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's|.*/releases/download/v\([0-9][0-9.]*\)/pubkit-.*|\1|p' pubkit | head -n 1)
[[ -n "$version" ]] || { echo "go-live: no pubkit version in ./pubkit" >&2; exit 1; }

exec uvx --from "https://github.com/Sustenaut/pubkit/releases/download/v$version/pubkit-$version-py3-none-any.whl" \
  python -c '
import base64, re, subprocess, sys
from pubkit.deploy import BitwardenWriter
from pubkit.github_app import ask_hidden

ran = subprocess.run(["ssh", "root@sustenaut", "k3s kubectl -n auth get secret auth-secrets"
                      " -o jsonpath={.data.access-hash-key} --ignore-not-found"],
                     capture_output=True, text=True, check=False)
if ran.returncode != 0:
    sys.exit(f"go-live: could not read auth-secrets: {ran.stderr.strip()}")
if not ran.stdout.strip():
    sys.exit("go-live: auth-secrets has no access-hash-key: nothing to keep, so let the walk make one")
key = base64.b64decode(ran.stdout.strip()).decode()
if not re.fullmatch(r"[0-9a-f]{64}", key):
    sys.exit("go-live: the access-hash-key in auth-secrets is not 64 hex digits: let the walk make one")
token = ask_hidden("Bitwarden access token with write access to Sustenaut (hidden, and not kept): ")
if not token:
    sys.exit("go-live: no token, nothing written")
BitwardenWriter(token, "Sustenaut").write("auth-access-hash-key", key, "copied from auth-secrets, as hex-32")
print("go-live: auth-access-hash-key is in Bitwarden: 64 bytes, the key auth-secrets holds")
'
