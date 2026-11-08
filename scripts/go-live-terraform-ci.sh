#!/usr/bin/env bash
# Brings up Terraform from CI for this repository (.github/workflows/terraform.yml):
# main's pushes to infra/ are applied by GitHub Actions, as the account terraform-auth,
# which Sustenaut/shared-infra makes (its infra/terraform-ci.tf, brought up by its own
# scripts/go-live-terraform-ci.sh first). Run it from this repository's root, with gh
# signed in as an admin of Sustenaut/auth and gcloud signed in:
#
#   scripts/go-live-terraform-ci.sh
#
#   1. the environment terraform, which only main may deploy to; it holds no secret
#   2. that main has the workflow, and shared-infra has made terraform-auth
#   3. the variable TERRAFORM_CI on
#   4. one run of the workflow, which must find nothing to change
#
# Each step says what it does and asks first; a step already done is skipped, and the
# first error stops it. Step 1 can run before the pull request merges; it stops at 2
# until it has. It prints no secret.
set -euo pipefail
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
repo=Sustenaut/auth
env=terraform
account=terraform-auth@sustenaut.iam.gserviceaccount.com

step() { printf '\n== %s\n' "$*"; }
skip() { echo "   already done: $*"; }
ask() {
  local answer
  read -r -p "   $1 Type yes to go on: " answer </dev/tty
  [[ $answer == yes ]] || { echo "Stopped; run scripts/go-live-terraform-ci.sh again to go on."; exit 1; }
}

step "Checking the tools and the logins"
for tool in gh gcloud git; do command -v "$tool" >/dev/null || { echo "$tool is not installed" >&2; exit 1; }; done
[[ $(gh api "repos/$repo" --jq .permissions.admin) == true ]] || { echo "gh is not signed in as an admin of $repo" >&2; exit 1; }
echo "   ok"

step "1. The environment $env, which only main may deploy to"
policies=$(gh api "repos/$repo/environments/$env/deployment-branch-policies" --jq '[.branch_policies[] | "\(.type) \(.name)"] | sort | join(",")' 2>/dev/null || true)
if [[ $policies == "branch main" ]]; then skip "$env exists, and takes main only"; else
  ask "Make $env (or set it) to take deployments from main only?"
  gh api -X PUT "repos/$repo/environments/$env" --input - >/dev/null <<<'{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}'
  while read -r id; do
    [[ -n $id ]] && gh api -X DELETE "repos/$repo/environments/$env/deployment-branch-policies/$id" >/dev/null
  done < <(gh api "repos/$repo/environments/$env/deployment-branch-policies" --jq '.branch_policies[] | select(.type != "branch" or .name != "main") | .id')
  if ! gh api "repos/$repo/environments/$env/deployment-branch-policies" --jq '.branch_policies[] | "\(.type) \(.name)"' | grep -qx "branch main"; then
    gh api -X POST "repos/$repo/environments/$env/deployment-branch-policies" -f name=main -f type=branch >/dev/null
  fi
  echo "   ok: $env takes main only"
fi

step "2. main has the workflow, and shared-infra has made $account"
git fetch -q origin main
git cat-file -e origin/main:.github/workflows/terraform.yml 2>/dev/null ||
  { echo "   main has no .github/workflows/terraform.yml yet: merge the pull request, then run this again"; exit 1; }
gcloud iam service-accounts describe "$account" --project=sustenaut --format='value(email)' >/dev/null 2>&1 ||
  { echo "   no $account yet: run Sustenaut/shared-infra's scripts/go-live-terraform-ci.sh first"; exit 1; }
echo "   ok"

step "3. The variable TERRAFORM_CI on"
if [[ $(gh variable list -R "$repo" --json name,value --jq '.[] | select(.name == "TERRAFORM_CI") | .value') == on ]]; then skip "TERRAFORM_CI is on"; else
  ask "Turn it on? From then on every push to main is applied."
  gh variable set TERRAFORM_CI -R "$repo" --body on
fi

step "4. One run of the workflow terraform, on main"
ask "Start it?"
gh workflow run terraform -R "$repo" --ref main
sleep 5
gh run list -R "$repo" --workflow terraform --limit 1 --json url --jq '"   " + .[0].url'
cat <<'DONE'

== Open the run above. Its plan, in the job's summary, must say "No changes." Then this
   repository is live: each merge to main is applied by it.
DONE
