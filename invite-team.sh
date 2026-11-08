#!/usr/bin/env bash
# Brings the team realm (the team's sign-in, e.g. opportunity.sustenaut.eu) in line
# with Terraform's var.team, the list review and plan use, so there is no second list:
#
# - an address in var.team without an account gets one (username = email, email
#   marked verified) and the invitation email, whose link (valid 7 days) sets up a
#   passkey; a disabled account that is back in the list is switched on and invited;
# - an account whose address is no longer in the list is disabled and signed out
#   everywhere (kept, so putting the address back restores it);
# - the registrant (var.team_registrant, an address @sustenaut.eu that registers the
#   team's apps for sign-in) gets an account too, but is not a team member: the apps
#   still check var.team themselves.
#
# Run it from the repository root, signed in to Sustenaut's tailnet, after each
# change to var.team (terraform apply first, so its output has the list):
#
#   SUSTENAUT_SERVER=sustenaut ./with-secrets ./invite-team.sh
#   SUSTENAUT_SERVER=sustenaut ./with-secrets ./invite-team.sh --resend anna@example.org   # a new phone, say
#
# It talks to the admin API as admin-api.sh says (locally, against compose: see
# there). Locally, TEAM_EMAILS (comma-separated) and TEAM_REGISTRANT stand in for the
# Terraform output.
set -euo pipefail

resend=""
case "${1:-}" in
  "") ;;
  --resend) resend=$(printf '%s' "${2:?usage: $0 [--resend EMAIL]}" | tr '[:upper:]' '[:lower:]') ;;
  *) echo "usage: $0 [--resend EMAIL]" >&2; exit 2 ;;
esac

root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
if [ -n "${TEAM_EMAILS+set}" ]; then
  members=$(tr -s ', ' '\n' <<<"$TEAM_EMAILS")
  registrant=${TEAM_REGISTRANT:-}
else
  infra="${SHARED_INFRA:-$root/../shared-infra}/infra"   # var.team is shared-infra's
  out=$(terraform -chdir="$infra" output -json auth_team)
  members=$(jq -r '.members[]' <<<"$out")
  registrant=$(jq -r '.registrant // empty' <<<"$out")
fi
members=$(printf '%s\n' "$members" | tr '[:upper:]' '[:lower:]' | sed '/^$/d' | sort -u)
registrant=$(printf '%s' "$registrant" | tr '[:upper:]' '[:lower:]')
wanted=$(printf '%s\n' "$members" "$registrant" | sed '/^$/d' | sort -u)
for email in $wanted; do
  case "$email" in
    *@*.*) ;;
    *) echo "$email does not look like an email address." >&2; exit 2 ;;
  esac
done
if [ -z "$members" ]; then
  echo "The team list is empty; refusing to disable every account." >&2
  exit 1
fi
if [ -n "$resend" ] && ! grep -qxF "$resend" <<<"$wanted"; then
  echo "$resend is not in var.team (or the registrant): nothing to resend." >&2
  exit 2
fi

lifespan=$((7 * 24 * 3600))
# shellcheck source=admin-api.sh
. "$(dirname "$0")/admin-api.sh"
realm="$admin/admin/realms/team"
# The link's "back to" page is the app of INVITE_CLIENT (default sustenaut.eu: the
# client sustenaut.eu's team sites registered). Before that client exists (the
# registrant is invited first), the link is issued for app-registration, which has no
# such page (dev/prove_team.py sets up passkeys from links like that).
client=${INVITE_CLIENT:-sustenaut.eu}

invite() { # user id, email
  if ! api -X PUT --data '["webauthn-register-passwordless"]' \
       "$realm/users/$1/execute-actions-email?client_id=$(uri "$client")&lifespan=$lifespan" 2>/dev/null; then
    api -X PUT --data '["webauthn-register-passwordless"]' \
      "$realm/users/$1/execute-actions-email?client_id=app-registration&lifespan=$lifespan"
  fi
  echo "Sent the invitation to $2 (the link works for 7 days)."
}

for email in $wanted; do
  user=$(api "$realm/users?email=$(uri "$email")&exact=true" | jq -c '.[0] // empty')
  if [ -z "$user" ]; then
    jq -n --arg e "$email" '{username: $e, email: $e, emailVerified: true, enabled: true}' |
      api -X POST --data @- "$realm/users"
    id=$(api "$realm/users?email=$(uri "$email")&exact=true" | jq -r '.[0].id')
    echo "Created the account for $email."
    invite "$id" "$email"
  elif [ "$(jq -r .enabled <<<"$user")" != true ]; then
    id=$(jq -r .id <<<"$user")
    api -X PUT --data '{"enabled": true}' "$realm/users/$id"
    echo "Switched the account of $email on again."
    invite "$id" "$email"
  elif [ "$email" = "$resend" ]; then
    invite "$(jq -r .id <<<"$user")" "$email"
  fi
done

# Everyone else is switched off. Pages of 100, until one comes back short.
first=0
while :; do
  page=$(api "$realm/users?briefRepresentation=true&first=$first&max=100")
  jq -c '.[] | select(.enabled) | {id, email: ((.email // .username) | ascii_downcase)}' <<<"$page" |
    while read -r user; do
      email=$(jq -r .email <<<"$user")
      if ! grep -qxF "$email" <<<"$wanted"; then
        id=$(jq -r .id <<<"$user")
        api -X PUT --data '{"enabled": false}' "$realm/users/$id"
        api -X POST "$realm/users/$id/logout"
        echo "Disabled the account of $email (not in var.team) and signed it out."
      fi
    done
  [ "$(jq length <<<"$page")" -lt 100 ] && break
  first=$((first + 100))
done
echo "The team realm matches var.team ($(wc -w <<<"$members") members$([ -n "$registrant" ] && echo ", and the registrant $registrant"))."
