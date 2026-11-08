# shellcheck shell=bash
# Sourced by invite-family.sh, invite-team.sh and remove-family.sh: a Keycloak admin API,
# signed in as the realm job's admin client (AUTH_CONFIG_CLIENT_SECRET). Defines `api`
# (curl with the token) and `admin` (the base URL).
#
# Production only when asked for by name: with KEYCLOAK_ADMIN_URL unset and
# SUSTENAUT_SERVER=sustenaut, the SSH tunnel to that server's admin console is opened for the
# run (README) if http://localhost:8180 does not answer. A KEYCLOAK_ADMIN_URL that was given
# and does not answer is an error, and so is no SUSTENAUT_SERVER: a local stack that is
# down, or on other ports, can never send a run to the live server.
#   Production: SUSTENAUT_SERVER=sustenaut ./with-secrets ./<script> ...
#   Locally, against compose: KEYCLOAK_ADMIN_URL=http://localhost:8180
#   AUTH_CONFIG_CLIENT_SECRET=<KC_ADMIN_PASSWORD from .env> <script> ...

: "${AUTH_CONFIG_CLIENT_SECRET:?run this through ./with-secrets (or set it, locally)}"
admin=${KEYCLOAK_ADMIN_URL:-http://localhost:8180}

# The tunnel to the real server only when no address was given: an address that was
# given (a local stack, a proof) and does not answer is an error, never production.
if ! curl -fsS -o /dev/null "$admin/realms/master"; then
  if [ -n "${KEYCLOAK_ADMIN_URL:-}" ]; then
    echo "Nothing answers at $admin (KEYCLOAK_ADMIN_URL); not opening the tunnel to the server." >&2
    exit 1
  fi
  server=${SUSTENAUT_SERVER:-}
  if [ -z "$server" ]; then
    echo "Nothing answers at $admin. For the live server, set SUSTENAUT_SERVER=sustenaut" >&2
    echo "(opens the admin tunnel); locally, KEYCLOAK_ADMIN_URL=<your stack's admin URL>." >&2
    exit 1
  fi
  echo "Opening the admin tunnel to $server (port 8180) for this run." >&2
  ssh -o ExitOnForwardFailure=yes -f -N -M -S "/tmp/auth-admin-$$.sock" \
    -L 8180:127.0.0.1:30180 "root@$server"
  trap 'ssh -S "/tmp/auth-admin-$$.sock" -O exit "root@$server" 2>/dev/null' EXIT
  admin=http://localhost:8180
fi

# The secret goes on stdin and the token in a header file, never on a command line.
token=$(printf 'grant_type=client_credentials&client_id=sustenaut-config&client_secret=%s' \
          "$(jq -rn --arg s "$AUTH_CONFIG_CLIENT_SECRET" '$s|@uri')" |
        curl -fsS --data @- "$admin/realms/master/protocol/openid-connect/token" | jq -r .access_token)
api() { curl -fsS -H @<(printf 'Authorization: Bearer %s\n' "$token") -H 'Content-Type: application/json' "$@"; }
uri() { jq -rn --arg v "$1" '$v|@uri'; }
