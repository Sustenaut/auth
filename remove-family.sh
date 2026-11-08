#!/usr/bin/env bash
# Admin fallback: takes someone's access away in the family realm directly. Registered
# domains remove their own people with their own client credentials (/realms/family/
# app-registration/<domain>/remove, usually from a script of its own),
# which also emails them in the domain's words. This one emails nobody.
#
#   SUSTENAUT_SERVER=sustenaut ./with-secrets ./remove-family.sh anna@example.org example.net
#   SUSTENAUT_SERVER=sustenaut ./with-secrets ./remove-family.sh anna@example.org
#
# With DOMAIN: that domain's mark comes off the account and all the person's sessions end;
# if no domain is left, the account is switched off and stamped sustenaut.removedAt (deleted
# after 30 days by Keycloak's daily job; an invitation before then switches it on again).
# Without DOMAIN: the account is deleted now, passkeys and all, after you confirm.
#
# It talks to the admin API as admin-api.sh says: the live server only with
# SUSTENAUT_SERVER=sustenaut (locally, against compose: see there).
# (REMOVE_FAMILY_YES=1 skips the confirmation, for the proof.)
set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: $0 EMAIL [DOMAIN]" >&2
  exit 2
fi
email=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
domain=$(printf '%s' "${2:-}" | tr '[:upper:]' '[:lower:]')
case "$email" in
  *@*.*) ;;
  *) echo "$1 does not look like an email address." >&2; exit 2 ;;
esac
# shellcheck source=admin-api.sh
. "$(dirname "$0")/admin-api.sh"
realm="$admin/admin/realms/family"

query=$(jq -rn --arg e "$email" '$e|@uri')
user=$(api "$realm/users?email=$query&exact=true" | jq -c '.[0] // empty')
if [ -z "$user" ]; then
  echo "$email has no account in the family realm; nothing to do."
  exit 0
fi
id=$(jq -r .id <<<"$user")

if [ -z "$domain" ]; then
  marks=$(jq -r '.attributes["sustenaut.invitedBy"] // [] | join(", ")' <<<"$user")
  echo "Deleting the account of $email for good (passkeys too), now. Invited by: ${marks:-nobody}."
  if [ "${REMOVE_FAMILY_YES:-}" != 1 ]; then
    read -r -p "Type the address again to confirm: " typed
    if [ "$(printf '%s' "$typed" | tr '[:upper:]' '[:lower:]')" != "$email" ]; then
      echo "Not the same address; nothing deleted." >&2
      exit 1
    fi
  fi
  api -X DELETE "$realm/users/$id"
  echo "Deleted the account of $email."
else
  if ! jq -e --arg d "$domain" '.attributes["sustenaut.invitedBy"] // [] | index($d)' <<<"$user" >/dev/null; then
    echo "$email is not marked as invited by $domain; nothing changed."
    exit 0
  fi
  # The whole account goes back as it was read, with the mark off (and switched off and
  # stamped if no domain is left; an account an admin locked stays as it is, unstamped).
  rep=$(jq -c --arg d "$domain" --arg now "$(date +%s)" '
    (.attributes["sustenaut.invitedBy"] - [$d]) as $left
    | .attributes["sustenaut.invitedBy"] = $left
    | if ($left | length) == 0 then del(.attributes["sustenaut.invitedBy"]) else . end
    | if ($left | length) == 0 and .enabled then .enabled = false | .attributes["sustenaut.removedAt"] = [$now] else . end
    | del(.access)' <<<"$user")
  api -X PUT --data "$rep" "$realm/users/$id"
  api -X POST "$realm/users/$id/logout"
  if [ "$(jq -r '.attributes["sustenaut.invitedBy"] // [] | length' <<<"$rep")" = 0 ]; then
    echo "Took $domain off $email; no domain is left, so the account is switched off (deleted in 30 days; an account already locked stays locked)."
  else
    echo "Took $domain off $email; the account stays for $(jq -r '.attributes["sustenaut.invitedBy"] | join(", ")' <<<"$rep")."
  fi
  echo "Their sessions have ended. Nobody was emailed: tell them yourself if they should know."
fi
echo "Reminder: Immich shared links name people on their \"for:\" lines; the domain's"
echo "The domain's own removal (its POST /remove) cleans those up."
