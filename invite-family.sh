#!/usr/bin/env bash
# Admin fallback: invites someone to the family realm directly. Registered domains invite
# their own people with their own client credentials (/realms/family/app-registration/
# <domain>/invite, usually from a script of its own), in their
# own words. This one creates the account,
# username = email, email marked verified (you know it is theirs), and sends them the
# invitation email, whose link (valid 7 days, once) signs them in. Inviting an address
# that already has an account just sends the email again (a way back in, e.g. on a new
# phone). Run it from the repository root, signed in to Sustenaut's tailnet:
#
#   SUSTENAUT_SERVER=sustenaut ./with-secrets ./invite-family.sh --domain example.net anna@example.org Anna Example
#
# --domain DOMAIN (or INVITE_CLIENT=DOMAIN) marks the account as that registered domain's
# person (sustenaut.invitedBy), as the domain's own invitation does, and lands them on its home
# page once signed in. Only a marked person can be removed by the domain or leave it themselves
# ("Remove my access"); without a domain the script says so.
#
# It talks to the admin API as admin-api.sh says (locally, against compose: see there).
set -euo pipefail

domain=${INVITE_CLIENT:-}
if [ "${1:-}" = --domain ]; then
  domain=${2:-}
  shift 2 || true
fi
if [ $# -lt 1 ] || [ $# -gt 3 ]; then
  echo "usage: $0 [--domain DOMAIN] EMAIL [FIRST_NAME] [LAST_NAME]" >&2
  exit 2
fi
domain=$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]')
case "$domain" in
  ''|*.*) ;;
  *) echo "$domain does not look like a domain (example.net, say)." >&2; exit 2 ;;
esac
email=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
first=${2:-}
last=${3:-}
case "$email" in
  *@*.*) ;;
  *) echo "$1 does not look like an email address." >&2; exit 2 ;;
esac
lifespan=$((7 * 24 * 3600))
# shellcheck source=admin-api.sh
. "$(dirname "$0")/admin-api.sh"
realm="$admin/admin/realms/family"

query=$(jq -rn --arg e "$email" '$e|@uri')
id=$(api "$realm/users?email=$query&exact=true" | jq -r '.[0].id // empty')
if [ -z "$id" ]; then
  jq -n --arg e "$email" --arg f "$first" --arg l "$last" \
     '{username: $e, email: $e, emailVerified: true, enabled: true}
      + (if $f != "" then {firstName: $f} else {} end)
      + (if $l != "" then {lastName: $l} else {} end)' |
    api -X POST --data @- "$realm/users"
  id=$(api "$realm/users?email=$query&exact=true" | jq -r '.[0].id')
  echo "Created the account for $email."
else
  echo "$email has an account already; sending the invitation again."
fi

if [ -n "$domain" ]; then
  # The whole account goes back as it was read, with the domain added to its marks.
  user=$(api "$realm/users/$id")
  if jq -e --arg d "$domain" '.attributes["sustenaut.invitedBy"] // [] | index($d)' <<<"$user" >/dev/null; then
    echo "$email is already marked as invited by $domain."
  else
    jq -c --arg d "$domain" '.attributes["sustenaut.invitedBy"] = ((.attributes["sustenaut.invitedBy"] // []) + [$d])
                             | del(.access)' <<<"$user" | api -X PUT --data @- "$realm/users/$id"
    echo "Marked $email as invited by $domain."
  fi
fi

# The email is in the realm's neutral words. With a domain (its client id) they land on that
# domain's home page once signed in; without one they are told they are signed in.
query="lifespan=$lifespan"
[ -z "$domain" ] || query="$query&client_id=$(jq -rn --arg c "$domain" '$c|@uri')"
api -X PUT --data '["family-invite-sign-in"]' "$realm/users/$id/execute-actions-email?$query"
echo "Sent the invitation to $email (the link works for 7 days)."
if [ -z "$domain" ]; then
  echo "Warning: no --domain, so $email belongs to no domain: no domain can remove them, and they" >&2
  echo "can't leave one themselves (\"Remove my access\" says there is nothing to remove there)." >&2
  echo "Run again with --domain example.net (say) to fix that." >&2
fi
echo "Usually a registered domain invites its own people instead."
