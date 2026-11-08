#!/usr/bin/env bash
# One time, when the access page (/realms/team/access, README) replaces Terraform's var.team as
# the list of who may use which team service. Everyone in var.team gets every current service
# role and the controller (ACCESS_CONTROLLER) gets controller, so nobody loses anything on the day and the page has someone
# who can open it. After this the page is the list.
#
# - The roles: TEAM_SERVICE_ROLES (spaces between; default below) are declared on the domain's
#   client; before it registers they wait on a switched-off placeholder a registration takes over.
#   Every role the client then holds, the site's own included, goes to everyone in the list.
# - A member or controller without an account gets one and the invitation; a switched-off account
#   is left off (and said so). The registrant (var.team_registrant) gets no service role.
# - Running it again adds nothing new, but gives back what the page has taken from someone in the
#   list: it is for the first day, not for later.
#
#   SUSTENAUT_SERVER=sustenaut ./with-secrets ./import-team-access.sh
#
# ACCESS_CONTROLLER is the controller's email address: configuration, not code. with-secrets
# exports it from the Bitwarden secret access-controller; locally, set it yourself.
#
# It talks to the admin API as admin-api.sh says, so it reaches production only when asked to by
# name. Locally, TEAM_EMAILS (comma-separated) and TEAM_REGISTRANT stand in for the Terraform output.
set -euo pipefail

domain=${ACCESS_DOMAIN:-sustenaut.eu}
controller=${ACCESS_CONTROLLER:?set ACCESS_CONTROLLER to the controller's email address (Bitwarden: access-controller)}
declared=${TEAM_SERVICE_ROLES:-opportunity release notebooks plan pub estimate review}

root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
if [[ -n "${TEAM_EMAILS+set}" ]]; then
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
controller=$(printf '%s' "$controller" | tr '[:upper:]' '[:lower:]')
if [[ -z "$members" ]]; then
  echo "The team list is empty; nothing to import." >&2
  exit 1
fi

lifespan=$((7 * 24 * 3600))
# shellcheck source=admin-api.sh
. "$(dirname "$0")/admin-api.sh"
realm="$admin/admin/realms/team"

if ! role=$(api "$realm/roles/controller" 2>/dev/null); then
  echo "The team realm has no role controller yet: deploy this version first (the realm job)." >&2
  exit 1
fi

# The domain's client, or the placeholder that holds its roles until it registers (TeamAccess).
client=$(api "$realm/clients?clientId=$(uri "$domain")" | jq -c '.[0] // empty')
if [[ -z "$client" ]]; then
  jq -n --arg d "$domain" '{clientId: $d, name: $d, enabled: false, protocol: "openid-connect",
      fullScopeAllowed: false,
      attributes: {"sustenaut.app.state": "declared", "sustenaut.app.domain": $d}}' |
    api -X POST --data @- "$realm/clients"
  client=$(api "$realm/clients?clientId=$(uri "$domain")" | jq -c '.[0]')
  echo "No client for $domain yet: its roles wait on a placeholder until it registers."
fi
cid=$(jq -r .id <<<"$client")
if ! api "$realm/clients/$cid/protocol-mappers/models" | jq -e 'any(.[]; .protocolMapper == "sustenaut-access")' >/dev/null; then
  api -X POST --data '{"name": "access", "protocol": "openid-connect", "protocolMapper": "sustenaut-access",
      "config": {"id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true", "introspection.token.claim": "true"}}' \
    "$realm/clients/$cid/protocol-mappers/models"
fi
for name in $declared; do
  if ! api "$realm/clients/$cid/roles" | jq -e --arg n "$name" 'any(.[]; .name == $n)' >/dev/null; then
    jq -n --arg n "$name" '{name: $n}' | api -X POST --data @- "$realm/clients/$cid/roles"
    echo "Declared the role $name."
  fi
done
roles=$(api "$realm/clients/$cid/roles")

# The account of an address (made and invited if there is none); its id, or nothing if it is off.
account() {
  local user id
  user=$(api "$realm/users?email=$(uri "$1")&exact=true" | jq -c '.[0] // empty')
  if [[ -z "$user" ]]; then
    jq -n --arg e "$1" '{username: $e, email: $e, emailVerified: true, enabled: true}' |
      api -X POST --data @- "$realm/users"
    id=$(api "$realm/users?email=$(uri "$1")&exact=true" | jq -r '.[0].id')
    echo "Created the account for $1." >&2
    if ! api -X PUT --data '["webauthn-register-passwordless"]' \
         "$realm/users/$id/execute-actions-email?client_id=$(uri "$domain")&lifespan=$lifespan" 2>/dev/null; then
      api -X PUT --data '["webauthn-register-passwordless"]' \
        "$realm/users/$id/execute-actions-email?client_id=app-registration&lifespan=$lifespan"
    fi
    echo "Sent the invitation to $1 (the link works for 7 days)." >&2
    printf '%s' "$id"
  elif [[ "$(jq -r .enabled <<<"$user")" = true ]]; then
    jq -r .id <<<"$user"
  else
    echo "$1 is switched off: left off, with no roles. Put them back on the page." >&2
  fi
}

count=0
for email in $members; do
  if [[ "$email" = "$registrant" ]]; then
    echo "$email is the registrant: no service roles."
    continue
  fi
  id=$(account "$email")
  [[ -n "$id" ]] || continue
  api -X POST --data "$roles" "$realm/users/$id/role-mappings/clients/$cid"
  count=$((count + 1))
done

id=$(account "$controller")
if [[ -z "$id" ]]; then
  echo "The controller $controller is switched off: nobody can open the page." >&2
  exit 1
fi
jq -c '[.]' <<<"$role" | api -X POST --data @- "$realm/users/$id/role-mappings/realm"
echo "$controller holds controller; $count people hold every service role of $domain: $(jq -r '[.[].name] | sort | join(", ")' <<<"$roles")."
