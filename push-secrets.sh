#!/usr/bin/env bash
# Puts the auth app's secrets into the cluster on the Sustenaut k3s server, as the
# Secret auth-secrets in namespace auth. Run it from the repository root through
# with-secrets, after the first terraform apply and whenever a secret changes:
#
#   ./with-secrets ./push-secrets.sh
#
# The values come from Bitwarden (auth-db-password, auth-admin-password,
# auth-config-client-secret, auth-issuer-keystore, auth-issuer-keystore-password,
# auth-review-client-secret (the review app's Keycloak client),
# auth-smtp-login and auth-smtp-password (the mailbox.org login and app password
# the family and team realms send their emails with), and auth-backup-gcs-key (the backup
# writer's key, base64-encoded, made by ./pubkit service-account-key create), which with-secrets
# exports in upper case. One is made here and kept nowhere else: access-hash-key,
# the key of the team realm's access-state hash. It is random, kept from the Secret when it is
# there, and made once when it is not; losing it costs each site one full check per person.
# They travel to the server inside the SSH connection, never on a command line.
# Keycloak reads them at start, the realm job when it runs: after a change, restart
# Keycloak with
#   ssh root@sustenaut k3s kubectl -n auth rollout restart deployment/keycloak
# and run the auth workflow again (the realm job puts the SMTP login into the
# family realm).
set -euo pipefail
root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
# The server's name is a Terraform output of shared-infra's infra/: a checkout of it
# beside this one, or SHARED_INFRA=its path.
infra="${SHARED_INFRA:-$root/../shared-infra}/infra"
[ -d "$infra" ] || { echo "no shared-infra checkout at ${infra%/infra}: clone it beside this repository or set SHARED_INFRA" >&2; exit 1; }

for name in AUTH_DB_PASSWORD AUTH_ADMIN_PASSWORD AUTH_CONFIG_CLIENT_SECRET AUTH_ISSUER_KEYSTORE AUTH_ISSUER_KEYSTORE_PASSWORD AUTH_REVIEW_CLIENT_SECRET \
  AUTH_SMTP_LOGIN AUTH_SMTP_PASSWORD \
  AUTH_BACKUP_GCS_KEY; do
  if [ -z "${!name:-}" ]; then
    echo "$name is not set: run this through ./with-secrets, and check the secret is in Bitwarden." >&2
    exit 1
  fi
done

# SSH reaches the server over Sustenaut's tailnet only (be signed in to it).
server=$(terraform -chdir="$infra" output -json sustenaut_server | jq -r .ssh_host)
b64() { printf '%s' "$1" | base64 -w0; }
# shellcheck disable=SC2029 # the query is this machine's on purpose
access_hash_key=$(ssh "root@$server" "k3s kubectl -n auth get secret auth-secrets -o jsonpath='{.data.access-hash-key}' --ignore-not-found")
[[ -n "$access_hash_key" ]] || access_hash_key=$(b64 "$(openssl rand -hex 32)")

# shellcheck disable=SC2087 # expanded here on purpose: the values go in the SSH stream
ssh "root@$server" 'k3s kubectl apply -f -' <<YAML
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: auth-secrets
  namespace: auth
data:
  db-password: $(b64 "$AUTH_DB_PASSWORD")
  admin-password: $(b64 "$AUTH_ADMIN_PASSWORD")
  config-client-secret: $(b64 "$AUTH_CONFIG_CLIENT_SECRET")
  issuer-keystore: $(b64 "$AUTH_ISSUER_KEYSTORE")
  issuer-keystore-password: $(b64 "$AUTH_ISSUER_KEYSTORE_PASSWORD")
  review-client-secret: $(b64 "$AUTH_REVIEW_CLIENT_SECRET")
  mailbox-smtp-login: $(b64 "$AUTH_SMTP_LOGIN")
  mailbox-smtp-password: $(b64 "$AUTH_SMTP_PASSWORD")
  backup-gcs-key: $AUTH_BACKUP_GCS_KEY
  access-hash-key: $access_hash_key
YAML
