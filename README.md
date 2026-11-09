# auth: shared sign-in (local proof)

Keycloak 26.8.0 with the [ADORSYS OpenID4VP plugin](https://github.com/ADORSYS-GIS/keycloak-oid4vp-plugin)
(AGPL-3.0, with the two small patches in `plugin-patches/`). In the realm `sustenaut`, people sign in only with an
EU Digital Identity Wallet, by presenting their PID (person identification data).
There are no passwords, no registration form and no reset flow. Design:
https://claude.ai/artifact/98qGJbseKXhGYJy4BsoDoS

A second realm, `family`, is for invited friends and family who view what a registered
domain shares with them (in these docs, the example tenant example.net and its portal
share.example.net; the real one is the `FAMILY_TENANT_DOMAIN` Actions variable): an emailed sign-in link (or its code), or a
passkey if they set one up; no passwords there either, and no wallet needed ([below](#the-family-realm-registered-domains-sign-in)).
A third, `team`, is the same kind of realm for the Sustenaut team's sites
(opportunity.sustenaut.eu first): invite only, and who may use which service is on its access
page ([below](#the-access-page-who-may-use-which-service)).

Runs locally with compose (below) and, for real, in namespace `auth` on the
Sustenaut k3s server at Hetzner (`shared-infra/infra/hetzner.tf`), deployed by
`.github/workflows/auth.yml`.

## Run it

```sh
cp .env.example .env            # then fill it in as the comments in .env.example say
uv run dev/pki.py >> .env       # test PID provider, trust list, TLS cert in dev/.pki/
uv run issuer-keystore.py local >> .env   # the key that signs member credentials
uv run dev/dnskeys.py >> .env   # local DNSSEC keys for example.net (the example tenant) and sustenaut.eu (family, team proofs)
podman compose up -d --build    # or docker compose; podman needs a compose provider (uvx podman-compose)
uv run dev/prove.py             # end-to-end checks in a headless Chrome
uv run dev/prove_family.py      # the family realm's checks (invitation, email link and code, passkey)
uv run dev/prove_team.py        # the team realm's checks (invite-team.sh, registration, access page, oauth2-proxy)
```

An `.env` made before the team realm lacks `TEAM_DNSSEC_TRUST_ANCHORS`: run
`dev/dnskeys.py` again, drop the old `FAMILY_DNSSEC_TRUST_ANCHORS` line, and recreate ns1.

Keycloak: http://localhost:8080 (admin console user `admin`, password from `.env`).
The family and team realms' emails land in mailpit: http://localhost:8025.
After editing `realm/`, apply it again with `podman compose up realm`.
To start again from an empty database: `podman compose down -v`.
Pull requests touching this repository run the same steps and all three proofs in CI
(`.github/workflows/auth-proofs.yml`, check `auth-proofs`), with throwaway keys and no secrets.
A second stack beside another checkout's: a copy of `compose.yaml` with its own `name:`,
host ports and subnet (`-f` that copy), and the proofs pointed at it with `AUTH_KC`,
`AUTH_KC_ADMIN`, `AUTH_MAILPIT`, `AUTH_NS1` and `AUTH_HOOKS` (the `hooks` service's port,
default `http://localhost:8035`; prove_team.py also `AUTH_PROOF_PROXY_PORT`,
`AUTH_PROOF_STUB_PORT`, `AUTH_PROOF_GATE_PORT`; it needs Node.js for the Worker gate). prove.py's callback ports 8099 and 8098 are fixed (the test
clients' redirect URIs), so run it in one checkout at a time.

## What is here

| Path | What |
|---|---|
| `Dockerfile` | Keycloak 26.8.0 + the plugin built from a pinned commit with `plugin-patches/` applied + our providers (`extension/`) + dnsjava (pinned, checksum), `kc.sh build`, runs `start --optimized`. |
| `plugin-patches/` | Our changes to the AGPL plugin, also served from the login page (AGPL section 13): 0001 runs required actions after a wallet sign-in; 0002 records which profile (PID or member credential) the wallet answered. |
| `issuer-keystore.py` | Makes the PKCS#12 keystore with the key that signs member credentials (an ES256 key with a certificate from our own small CA: Keycloak's HAIP check refuses self-signed signing certificates). |
| `docker-entrypoint.sh` | Writes that keystore from the environment into the realm's keystore folder, then starts Keycloak. |
| `extension/` | Our Keycloak providers (Java, Apache-licensed APIs only): `sustenaut-wallet-page` (the login page, never a password step), `sustenaut-random-username` (imported accounts get `u-…` usernames, not the PID number), `sustenaut-member-credential` (below), `family-sign-in` (the family realm's page: an emailed link and code, passkeys in the email field) with `family-sign-in-link` (the link), `family-invite-sign-in` (the invitation signs in) and `family-passkey-offer` (once per device), `sustenaut-leave` (a person leaves a domain: "Remove my access"), `app-registration` (domains registering for sign-in, approved by a DNSSEC-validated record, and the weekly re-check; inviting, looking up and removing their people; declaring service roles) with `family-client-rules` (what Keycloak's own registration endpoints allow there), `access` (the team realm's access page) with `sustenaut-access` (the `access` claim), and `sustenaut-passkey-notice` (an event listener: emails the person when a passkey is added). |
| `compose.yaml` | Local only: PostgreSQL 16, Keycloak in `start-dev`, `trustlist` (an HTTPS host serving the test trust list), `mailpit` (catches the family realm's emails), `hooks` (stands in for a domain's `notify_url`, https://hooks.example.net, dev/hooks.py), `ns1` (CoreDNS: the domains' nameserver, signing example.net, with the records the family proof writes to `dev/dns/zones/ns1/`), and `realm`, which applies `realm/` and exits. |
| `realm/sustenaut.json` | The realm as code, applied with keycloak-config-cli (`realm/Dockerfile`; on the server the `auth-realm` job): wallet-only browser flow, the `oid4vp auth` flow and its verifier settings, the hidden import provider and its mappers, two wallet profiles (member credential, PID), the `sustenaut-member` credential type (OpenID4VCI) and the `sustenaut-wallet` client wallets redeem offers with, the member-credential required action, user profile with email optional, key providers (including the issuer keystore), account console off. `$(env:NAME)` placeholders come from the environment. |
| `realm/family.json` | The family realm: invite only, an emailed link and code (or a passkey), 30-day remembered sessions, domain registration by DNS (allowed domains, re-check interval, alert address, DNSSEC trust anchors), the device-flow client `app-registration`, client registration policies, SMTP through mailbox.org, account console off. No app clients of its own: domains register theirs. |
| `invite-family.sh` | Admin fallback: invites someone to the family realm directly, in neutral words (domains invite their own people). |
| `remove-family.sh` | Admin fallback: takes a domain's mark off someone (switching the account off if none is left), or deletes the account outright (domains remove their own people). |
| `realm/team.json` | The team realm: the family realm's settings (invite only, passkeys or an emailed code, account console off, domain registration by DNS) for sustenaut.eu only, its own theme, mail from `noreply@sustenaut.eu`; the role `controller`, the client `team-access` and admin events for the access page. |
| `import-team-access.sh` | One time: everyone in `var.team` gets every service role, the controller (`ACCESS_CONTROLLER`) gets `controller` ([below](#the-access-page-who-may-use-which-service)). |
| `invite-team.sh` | Until the consumer repositories have switched to the access page, then retired: brings the team realm in line with Terraform's `var.team`: accounts and invitations for new addresses, disabled (and signed out) for removed ones, plus the registrant (`var.team_registrant`). |
| `admin-api.sh` | Sourced by the invite and import scripts and `remove-family.sh`: the admin client's token, and the admin tunnel to the live server only when `KEYCLOAK_ADMIN_URL` is unset and `SUSTENAUT_SERVER=sustenaut` is set (a given address that does not answer is an error; so a local run or a proof never reaches production). |
| `edge-gate/` | For a static site's Cloudflare Worker, to copy: the same sign-in and check at the edge ([below](#a-worker-gate-for-static-sites)). `dev/edge-gate/` runs it in `dev/prove_team.py`. |
| `access_check.py` | For a site's server, to copy: asks on each request whether the person's access has changed ([below](#checking-access-on-each-request)). |
| `register-app.py` | Registers a domain's sites for sign-in (the steps below) and declares their service roles (`--role`), standard library only; `--status` says which step is next from the state directory alone, changing nothing (pubkit's deploy walk asks it); `business-plan/opportunity-site/register-client.sh` runs it on the server for sustenaut.eu. |
| `k8s/` | The app on the k3s server (kustomize): PostgreSQL 16 (Keycloak's only), Keycloak (memory-capped), the ingress for auth.sustenaut.eu, the realm job (re-run on each deploy), the nightly backup CronJob, and `trust-list.env` (which PID-provider list is trusted). |
| `backups/` | Backups by [Sustenaut/pg-backup](https://github.com/Sustenaut/pg-backup): `pg-backup`, which runs its pinned release, and `pg-backup.json`, auth's settings. Its [README](backups/README.md) says when to run which command. |
| `realm/master.json`, `realm/apply-realm.sh` | Moves the master realm (admin sign-in) to the admin console's address, which is not public; applied in a run of its own after `sustenaut.json`. |
| `realm/dev-clients.json` | Local only: test clients `test-app` and `test-app-2`, and `review-local` for the review service run locally. |
| `themes/sustenaut/` | Login theme: wallet buttons only, and our QR page with a message when a presentation is refused. |
| `themes/family/` | The family realm's login theme (email field, code page, the link's code page, passkey offer) and email theme (invitation, sign-in link and code). The pages look like the Sustenaut apps (the recipe site, `@sustenaut/ui`): `resources/css/sustenaut.css` puts the `ui/src/theme.css` tokens (cream ground, Canopy and Sprout greens, Nunito, rounded panel and controls, light and dark) over keycloak.v2's PatternFly, with the mark from `brand/logo/` and the fonts served by the theme itself. Shares nothing with `themes/sustenaut`. |
| `themes/team/` | The team realm's themes: `themes/family`'s pages, look and emails (`parent=family`), with the team's wording, and the access page (`team-access.ftl`). |
| `dev/pki.py` | Test trust material: a PID provider CA and signing cert, a rogue provider, the signed ETSI TS 119 602 PID-provider list (LoTE). |
| `dev/wallet.py` | Scripted test wallet and test PID provider: issues an SD-JWT VC PID (`urn:eudi:pid:1`) bound to a fresh holder key, answers OpenID4VP requests (DCQL, `direct_post`, key-binding JWT), disclosing only the requested claims. It also accepts OpenID4VCI credential offers (pre-authorized code, JWT key proof), which is how it gets the member credential. |
| `dev/dnskeys.py`, `dev/dns/` | The local DNSSEC keys and CoreDNS setup (ns1 signs example.net and sustenaut.eu; the family realm trusts the first key, the team realm the second) for the proofs. |
| `dev/prove_family.py` | The family realm's proof (150 checks): example.net registering for sign-in (device-flow registrant, refusals, 409 before the record and for records that don't validate, a domain it cannot validate refused, credentials once, a new registration revoking the old client, the realm job run again leaving it alone), the domain's settings (refusals: wrong secret, another domain, markup, braces, a home page elsewhere, too long) and its invitation in its words (sender, subject, intro, home page), `invite-family.sh` in neutral words, a fetched invitation link signing nobody in, the invitation signing in (once, without a passkey, landing on the home page), the passkey offer after it and Set up (Chrome's virtual authenticator), the passkey used (no offer after it), the offer per device, "Not now" after a failed setup, sign-in with an emailed code, the email's link (signs in in the browser that asked; elsewhere shows the code and signs nothing in; once; dead after the code; expiry), "Not now" remembered on the device, no passkey button, 30-day remembered sessions, an unknown address gets no email and no account, a new-passkey notice for each passkey (the domain's words, or neutral ones; the first from the offer's Set up), no password field or password path, `email` in the ID token, the sustenaut page unchanged; the weekly check: no revocation on answers that don't validate or don't come, revocation and the registrant's email on a validated miss twice, no switching back on, deletion after 30 days. Removal: by the domain (only its own people, the same answer for anyone, sessions end, the account off and stamped or kept for another domain, "moved" wording), invited again (on again; not when an admin locked it), "Remove my access" (cancel and confirm), `remove-family.sh`, the daily deletion after 30 days, and deregistering (revoked at once; its people lose access when the client is deleted). The people lookup: none, invited, active once signed in by any means (the invitation's sign-in included). |
| `dev/prove_team.py` | The team realm's proof: `invite-team.sh` from a team list (accounts, invitations, idempotent, an empty list refused), sustenaut.eu registering through `register-app.py` (device-flow sign-in, record, client, a second site's redirect added; a member not at the domain and another domain refused), passkey and emailed-code sign-in, someone not invited gets no code and no account, no password path, oauth2-proxy run with opportunity-site's `k8s/oauth2-proxy.yaml` args (a member with the role admitted, their email in `X-Forwarded-Email`, not the browser's; the registrant refused), a member taken out of the list disabled and signed out (passkey refused), put back and invited again; and the access list: the import before anything has registered (the placeholder a registration takes over), roles declared by a site, refused, and only ever added, the `access` claim (that client's roles only; a controller all of them and `controller`; empty for the registrant; a mapper of an app's own refused), the page (signed out, member, registrant refused; not in the other realms; CSRF token and origin), ticks (one service only, the session goes on, seen at the next refresh), controller given and taken (not by oneself), invitation from the page (status invited, then active), a service declared on the page, history, "Remove from all" (roles off, sessions and refresh tokens dead, account off and stamped, passkey refused and kept, put back, deleted after 30 days), oauth2-proxy admitting by role (the browser's own `X-Forwarded-Groups` replaced, the access token passed on, a role taken away seen at the refresh), `access_check.py` and the hash (only the client itself can read it, an unchanged hash asks userinfo nothing, sign-ins change nothing, a role taken away and a full removal refused at the next request, a full check after N minutes, Keycloak down), the Worker gate under `wrangler dev` (its own tests, sign-in, the role, cookie attributes, forged cookies, a role taken away and a removal at the next request, Keycloak down), and a new registration and the realm job leaving the list alone. |
| `dev/prove.py` | The proof (22 checks): OIDC code flow in a browser, QR decoded and handed to the wallet, account creation from the PID, the member credential issued and then used to sign in, a lost wallet, single sign-on, untrusted or forged credentials refused with a message, no passwords, no account console. |

## How the plugin decides whom to trust

The primary credential's `trust` policy is `eudi_pid_trust_list`. Keycloak
downloads the signed PID-provider list (`trustListUrl`, HTTPS only), checks its
signature against the pinned `trustListSigningCertificate`, takes the
certificates of the one provider named in `issuer`, and checks the PID's `x5c`
chain against those certificates only. The PID's signed `iss` must equal that
provider identifier. The list is cached for up to 15 minutes (capped by its
`NextUpdate`). Other policies: `x5c` (pinned CA anchors, mdoc only for
external import) and `self` (credentials this Keycloak issued).

## How accounts are created and matched

First sign-in: a verified PID from a trusted provider whose identity is unknown
creates an account (`importUnknownUsers=true`), with first and last name from
the PID, and a federated link to the hidden `oid4vp-import` provider. The link
id is a hash of the provider identifier and `personal_administrative_number`
(`subjectClaim`). Later sign-ins, from any device, find the account through that
link. Usernames and emails never match or merge accounts.

This needs upstream PR #210 (open, not yet released); the released v1.4.0 only
signs in accounts that already exist.

A PID must carry `personal_administrative_number`. The plugin asks for it and
refuses a credential without an identity, so a wallet whose PID lacks it cannot
sign in at all (not every member state fills it).

## The member credential: our own key, in the wallet

Two buttons on the login page, two wallet profiles:

- **"EU ID (first time, or a new wallet)"** asks for the PID. The first time, it
  creates the account. After every PID sign-in, Keycloak then offers a
  **Sustenaut member credential** for the wallet (its own OpenID4VCI offer page:
  QR code or same-device link, pre-authorized code). The credential is an SD-JWT VC
  of type `https://sustenaut.eu/credentials/member/v1` holding only the account id
  (`sub`), bound to a key the wallet makes, valid for a year, signed by the key in
  the issuer keystore.
- **"Sustenaut membership in your wallet"** asks for that credential only (plugin
  "self" trust: Keycloak checks its own signature, the wallet's key binding, and
  finds the account by `sub`). No PID data is requested.

Lost wallet: sign in with the PID on the new device; it lands on the same account
(the PID's identifier is linked to it) and a new member credential is offered.
The old credential is not revoked: it keeps working until it expires (one year).
Revoking it needs Keycloak's token status list, not set up yet.

Skipping the offer (Cancel) is fine: it is offered again at the next PID sign-in.
Profiles can combine both credentials (member primary, PID supporting, as in the
plugin's German-wallet guide) for actions that need fresh proof of identity; no app
needs that yet.

## Deploying

The Sustenaut k3s server (`shared-infra/infra/hetzner.tf`): a Hetzner cx33 in Helsinki in
Sustenaut's own Hetzner project, k3s with Traefik as the one ingress for every
Sustenaut app (Let's Encrypt certificates), one namespace per app. k3s's state and
the apps' volumes are on a separate Hetzner volume; the IPs are kept across
rebuilds. Keycloak's database has two layers of backups off the server ("Backups", below).

What is public, and what is not:

- Public (Hetzner firewall: 80, 443): auth.sustenaut.eu, and on it only
  `/realms/sustenaut`, `/realms/family`, `/realms/team`, `/resources` and `/.well-known`
  (`k8s/ingress.yaml`).
- Sustenaut's tailnet only: SSH (the firewall has no port 22; the server joins the
  tailnet at first boot as `sustenaut`, tag `tag:sustenaut-server`), and with it
  the admin console and the master realm, served as http://localhost:8180 through
  an SSH tunnel (Keycloak's admin console needs a secure browser context, which
  localhost is):

  ```sh
  ssh -L 8180:127.0.0.1:30180 root@sustenaut    # then open http://localhost:8180/admin/
  ```

Deploys: `.github/workflows/auth.yml` pushes the images to GitHub's container
registry on each merge to main, and, once `DEPLOY_AUTH` is `on`, joins the tailnet as
`tag:ci` and sends the rendered `k8s/` manifests over SSH; the deploy key can only run
`sustenaut-deploy`, which applies them in namespace `auth`, re-runs the realm job and
waits for both.

pubkit.json's `deploy` block lists everything else the deployment needs, and pubkit's
deploy walk checks each need and makes what it can. `pg.database` is
[Sustenaut/pg-backup](https://github.com/Sustenaut/pg-backup)'s type: `deploy.providers`
pins its release, and `./pubkit` runs with it. To bring auth live, or back in step, from a
checkout of this repository with Sustenaut/shared-infra checked out beside it, on a machine
on the admin tailnet, signed in to `gh` and `gcloud`:

```sh
./with-secrets ./pubdeploy walk --fulfil --server sustenaut --zones ../shared-infra/pubkit.json
```

It checks every need, prints the plan, and waits for a typed `yes`; then it makes each
missing need it can, over the admin channel (`ssh root@sustenaut`), and checks it again.
Every run can run again: what is ready is left alone. In order:

| Need | What the walk does |
|---|---|
| the namespace `auth` | the server's `sustenaut-app`, which makes it and its deploy identity |
| `bitwarden.generated` `auth-access-hash-key` | the key of the team realm's access-state hash: a new one (`hex-32`), written to Bitwarden, when it is missing or misshapen. A new key costs each site one full access check per person, no more |
| `gcp.service-account-key` `auth-backup-gcs-key` | the nightly dump's key for `sustenaut-auth-backup` (`infra/`'s account): made and written to Bitwarden when it is missing or not one of the account's live keys |
| the Secret `auth-secrets` | made from the eight values below, the access-hash key and the backup key; Keycloak restarted |
| `pg.database` | the WAL archive's two keys in Bitwarden and the Secret `auth-wal`, as `./backups/pg-backup setup-secrets` makes them; then PostgreSQL, the archive and the last base backup checked |
| `DEPLOY_AUTH` and the rollout | the gate on, once everything before it is ready, and `auth.yml` run and waited for |
| `service.health` | `https://auth.sustenaut.eu/realms/team/.well-known/openid-configuration` answers 200, and the CronJob `backup` (the nightly dump) succeeded in the last 24 hours; when it has not, a Job is run from it |

A new access-hash key, backup key or archive key wants a Bitwarden token that may write:
the walk asks for it once, at a hidden prompt, and keeps it only in its process.

Some needs it only checks, and says what a person does:

- **The values in Bitwarden** (project Sustenaut): `auth-db-password` and
  `auth-admin-password` (random, and kept: PostgreSQL and Keycloak hold them),
  `auth-config-client-secret` (the realm job's client), `auth-issuer-keystore` and
  `auth-issuer-keystore-password` (from `uv run issuer-keystore.py`: the values after
  `SUSTENAUT_ISSUER_KEYSTORE_B64=` and `SUSTENAUT_ISSUER_KEYSTORE_PASSWORD=`),
  `auth-review-client-secret` (the `review` client's, below), and `auth-smtp-login` and
  `auth-smtp-password` (the mailbox.org login and app password the family and team realms
  send their emails with).
- **The DNS record** for `auth.sustenaut.eu`, in shared-infra's hosting block.
- **The backup drill** (`pg.database`): `./backups/pg-backup drill --wait` ("Backups",
  below), until pg-backup records the drill where the walk can read it.

`./pubdeploy walk` without `--fulfil` (or `pubdeploy check`) changes nothing, and
`./pubdeploy walk --offline` checks only the files. `.github/workflows/deploy-check.yml`
walks the deployment every 30 minutes, read-only, with the deploy key, and writes the walk
to storage's `plane` tenant; it fails when a need is missing, drift or blocked.

Going live on a new server, once, before the walk:

1. Tailscale (Sustenaut's tailnet, admin console):
   - Access controls: add the tags and rules below, and remove the default rule
     that lets every device reach every other.
   - Settings, OAuth clients (also called trust credentials): create one for
     Terraform (scope Auth Keys, write; tag `tag:sustenaut-server`) and one for
     GitHub Actions (scope Auth Keys, write; tag `tag:ci`).
   - DNS: keep MagicDNS on (it resolves `sustenaut`).

   Paste the whole file, braces included (it replaces Tailscale's starter policy):

   ```jsonc
   {
     "tagOwners": {
       "tag:sustenaut-server": ["autogroup:admin"],
       "tag:ci":               ["autogroup:admin"],
     },
     "grants": [
       // Admins: everything on the server (SSH, the admin console tunnel).
       {"src": ["autogroup:admin"], "dst": ["tag:sustenaut-server"], "ip": ["*"]},
       // GitHub Actions: SSH to the server only (the deploy key's forced command).
       {"src": ["tag:ci"], "dst": ["tag:sustenaut-server"], "ip": ["tcp:22"]},
     ],
   }
   ```
2. Hetzner: a Cloud project "Sustenaut" and a Read & Write API token for it.
3. Bitwarden, project Sustenaut: the values the walk checks (above), and
   - `HCLOUD_TOKEN` (or `hcloud-token`): the Hetzner token;
   - `TS_TF_OAUTH_CLIENT_ID`, `TS_TF_OAUTH_SECRET`: the Terraform OAuth client.
     `shared-infra/infra/tailscale-aliases.json` has ./with-secrets also export them as the
     names the Tailscale provider reads (needs pubkit 0.11.1). Do not also keep a
     `TAILSCALE_API_KEY` in the project: the provider refuses both at once.
4. `terraform -chdir=infra init -upgrade` (new providers: hcloud, tls, tailscale),
   then `./with-secrets terraform -chdir=infra plan` and `apply`.
5. DNS: the sustenaut.eu zone moves into Sustenaut's Hetzner project, and
   `shared-infra/infra/dns.tf` manages its records, auth.sustenaut.eu included (from the
   server's IP). Have the zone's old project forget its records (without deleting
   them), transfer the zone in the Hetzner console (zone "⋯",
   Transfer to Project, Sustenaut), then `./with-secrets terraform -chdir=infra
   apply` here again: 13 imports of the existing records and the new auth record.
6. GitHub, repository settings:
   - secrets `SUSTENAUT_DEPLOY_SSH_KEY`
     (`terraform -chdir=infra output -raw sustenaut_deploy_ssh_key | gh secret set SUSTENAUT_DEPLOY_SSH_KEY`),
     `TS_GH_OAUTH_CLIENT_ID` and `TS_GH_OAUTH_SECRET` (the GitHub Actions OAuth client);
   - variables `SUSTENAUT_SERVER` = `sustenaut` and `SUSTENAUT_KNOWN_HOSTS` (the
     `known_hosts` output), and `FAMILY_TENANT_DOMAIN` (the domain the family realm lets
     register for sign-in beside sustenaut.eu; the workflow refuses to render without it).
     `DEPLOY_AUTH` is the walk's to set.
   Configuration that names people stays out of the code: the family tenant's domain is that
   variable, and the access page's first controller is the Bitwarden secret
   `access-controller` (`ACCESS_CONTROLLER`, for `import-team-access.sh`).
7. The walk, above. After the images' first build, make the packages
   `sustenaut-auth` and `sustenaut-auth-realm` public (they hold no
   secrets; the workflow stops before deploying while one isn't, and says which), or
   the server cannot pull them, and run the walk again.

Application clients in the sustenaut realm: `review` (review.sustenaut.eu, review-site/;
its secret is Bitwarden `auth-review-client-secret`, which reaches the cluster
through the walk's `auth-secrets` and the review service through Secret Manager). On the server:
`ssh root@sustenaut`, then `k3s kubectl -n auth get pods`.

### Backups

Two layers, both off the server and in Finland:

| Layer | What | Kept | Where |
|---|---|---|---|
| Every change | PostgreSQL's write-ahead log, archived by WAL-G at least once a minute while anything changes, and a base backup each night (`k8s/postgres.yaml`, with Sustenaut/pg-backup's image) | 14 days, to any moment | `gs://sustenaut-auth-wal` |
| Nightly | A `pg_dump`, which needs neither WAL-G nor this PostgreSQL version (`k8s/backup.yaml`) | 30 days | `gs://sustenaut-auth-backups` |

- **Encryption:** WAL-G encrypts everything before it leaves the server, with `auth-wal-key` in
  Bitwarden. Without that key the archive can't be read, so keep it.
- **Append-only:** each bucket's account may add and read, never replace or delete; the buckets
  delete by age (`infra/main.tf`). The one exception: WAL-G uploads in chunks and may delete
  those, by a grant limited to names with `_chunks/` in them.
- **Status:** the `wal-g` container prints one line of JSON every 5 minutes: when the last segment
  was archived, failures, the size of `pg_wal`, and the last base backup. To see it:
  `ssh root@sustenaut k3s kubectl -n auth logs statefulset/postgres -c wal-g --tail=3`.
  If uploads fail, PostgreSQL keeps the WAL in `pg_wal` until they work, which is the one way
  this can fill the server's data volume.

**Setting up, restoring and the drill:** the scripts in [`backups/`](backups/README.md), and
its README for when to run which and what their results mean.

**Putting a restore back** is a separate, deliberate step:

- **From WAL:** `./backups/pg-backup promote auth-restore-<the namespace>`, after a restore
  to the moment you want ([backups/README.md](backups/README.md)).
- **From a dump**, with Keycloak scaled to 0: copy it from `sustenaut-auth-backups`, then run
  `k3s kubectl -n auth exec -i statefulset/postgres -c postgres -- pg_restore -U keycloak -d keycloak --clean < keycloak-….dump`.

## The family realm (registered domains' sign-in)

Sign-in for people who are not Sustenaut users, on behalf of domains registered here
(below), such as example.net, whose portal at share.example.net (in the tenant's own
repository) signs friends and family in through the confidential client
`example.net` and lists the Immich shared links meant for them. Apps trust the `email`
claim, so the email is set by whoever invited the person and nobody else: the user
profile lets only admins edit it, and the account console is off.

**Everything about a domain lives on the domain's side.** The realm itself is neutral
(it calls itself auth.sustenaut.eu); a registered domain brings its own name, home
page and words, and invites its own people, with its own client id and secret:

- `PUT /realms/family/app-registration/<domain>/settings` (HTTP Basic: client id and
  secret): `{"display_name", "home_url", "invite_intro", "help_contact", "notify_url"?}`,
  plain text (no markup, braces or control characters; 80/300/80 characters), the home
  page and `notify_url` https under the domain. Stored on the domain's client (`sustenaut.tenant.*`). The sign-in
  pages then say "Sign in to <display name>" with its help contact, and its
  invitations and codes carry its name as the sender's name and in the subject, its
  intro and its home page. example.net keeps them in its own repository
  (an `auth-tenant.json`, say), and its setup script sends them on every run.
- `POST /realms/family/app-registration/<domain>/invite` (same credentials):
  `{"email", "first_name"?, "last_name"?}`. Creates the account if there is none
  (username = email, verified: the domain vouches for it), marks it with the domain
  (`sustenaut.invitedBy`), and sends the invitation in the domain's words. Same answer
  whether the account existed or not; 50 an hour per domain. An account switched off
  because its last domain let it go (`sustenaut.removedAt`) is switched on again; one an
  admin locked gets nothing. A tenant usually wraps this in a script of its own.
- `GET /realms/family/app-registration/<domain>/people?email=...` (same credentials):
  `{"email", "status", "first_name"?, "last_name"?}` (names unless `none`), where `status` is `active` (has signed in at least once, by any
  method: the event listener `sustenaut-sign-in` records the first sign-in as
  `sustenaut.signedInAt`), `invited` (never signed in), or
  `none` (no account, a disabled one, or one this domain did not invite: a domain sees
  only its own people). 300 an hour per domain. example.net's email change
  waits on it before letting the old address go.
- **First-sign-in notices** (`SignInNotice`), for a domain whose settings have a
  `notify_url`: when one of its people (`sustenaut.invitedBy`) signs in for the first
  time, by any method, Keycloak POSTs to it

  ```
  Content-Type: application/json
  X-Sustenaut-Timestamp: 1793180000          (Unix seconds, when it was sent)
  X-Sustenaut-Signature: sha256=<hex HMAC-SHA256(client secret, timestamp + "." + body)>

  {"event": "first_sign_in", "domain": "example.net", "email": "anna@example.org", "at": "2026-10-28T12:00:00Z"}
  ```

  The key is the domain's client secret. A receiver checks the signature over the exact
  body, refuses a timestamp more than 5 minutes from its clock, and refuses a signature it
  has already seen in those 5 minutes (a replay). Sent once the sign-in has committed, from
  a pool of its own (3 s to connect, 5 s to answer, no retry, no redirects), so a sign-in
  never waits on a domain; a domain that was down misses it and should also ask `people`
  now and then. Nothing for later sign-ins, for domains that did not invite the person, or
  for a domain without `notify_url`. example.net: `/hooks/auth` on share.example.net, which
  finishes a pending email change at once.
- `POST /realms/family/app-registration/<domain>/remove` (same credentials):
  `{"email", "reason"?}`, reason `removed` (the default) or `moved`. Only people the domain
  invited are touched; the answer is `202 {"status": "removed", "email"}` for anyone
  (unknown, someone else's, already gone). See "Taking access away" below. 50 an hour per
  domain. A tenant usually wraps this in a script of its own.
- `DELETE /realms/family/app-registration/<domain>` (same credentials): the domain
  deregisters. Its client is revoked at once, as a failed re-check would (below); its
  people lose access when the revoked client is deleted 30 days later.
  A tenant usually wraps this in a script of its own.
- Email goes out from the service's own address, `noreply@sustenaut.eu` (realm job,
  `FAMILY_MAIL_FROM`), with the domain's name as the sender's name.

- **Invite only.** No registration, no reset flow. A registered domain invites people
  (above); `invite-family.sh` is the admin fallback, in neutral words.
- **The invitation signs in.** Its link (Keycloak's execute-actions email with our
  required action `family-invite-sign-in`, valid 7 days, once) asks "Sign me in?" once
  (a mail scanner opening links signs nobody in), marks the address verified, starts
  the session and lands on the domain's home page, whose sign-in then passes straight
  through. Nothing to set up first.
- **Email first.** "Email me a sign-in link" sends one email with a "Sign me in"
  button and a 6-digit code (both valid 10 minutes, once; the code 5 tries; a new
  email at most every 30 seconds). The link is an action token (`FamilyLinkToken`)
  with a random secret, kept hashed in the sign-in's authentication session; the code
  is derived from that secret. Opened in the browser that asked, the link signs in;
  opened on another device or browser it shows the code in large digits, "type this
  on the screen where you started", and signs nothing in there. Using the link or the
  code ends both. An address without an account gets the same "if it has been
  invited, we sent an email" page, but no email, and nothing can match: the page tells
  nobody who is invited, and never creates an account.
- **Passkeys optional.** After a sign-in by email (link, code or invitation), each
  device is asked once "Skip the email next time on this device?", whether or not the
  person has a passkey elsewhere (never after a passkey sign-in). Set up runs Keycloak's
  `webauthn-register-passwordless` with a "Not now" on its page and its error page, so a
  failed passkey never traps anyone; Not now goes on to the app. The answer is kept in a
  cookie on auth.sustenaut.eu (`FAMILY_PASSKEY_ASKED`, 400 days), so that device is not
  asked again. On the sign-in page the browser offers a passkey in the email field
  (conditional UI); there is no passkey button and no passkey dialog.
- **Long sessions.** Every sign-in is remembered (remember-me): the session lasts 30
  days idle and 30 days at most, across browser restarts, so people rarely see the
  sign-in page. share.example.net's own cookie (oauth2-proxy, 7 days, refreshed hourly)
  goes back to this session when it runs out, without a sign-in page.
- **A notice for every passkey added.** When a passkey is added to an account (the offer
  after an email sign-in or an invitation, or an app asking for it with
  `kc_action`, on another device), the event listener `sustenaut-passkey-notice` (`PasskeyNotice`, in the
  realm's `eventsListeners`; Keycloak's `UPDATE_CREDENTIAL` event with
  `credential_type` `webauthn-passwordless`) emails the account's address: when (UTC),
  roughly on what (browser and system, from the User-Agent), and whom to contact if
  it was not them. That is the inviting domain's `help_contact`, in its name, when it
  has settings (the domain the passkey was added through first, if it invited the
  person); else neutral words ("the person who invited you"). `PasskeyNotice.NOTICE_FROM`
  (1) is the switch: 2 would skip the first passkey.
- **No passwords.** The only authenticator is `family-sign-in` (`extension/`,
  `FamilySignInForm`): it extends Keycloak's username form for its passkey support
  and replaces its password step. Password-related required actions are off, and
  no app client has a direct-access (password) grant.
- **Email:** sent with mailbox.org (`smtp.mailbox.org:587`, STARTTLS; Hetzner blocks
  outgoing 25 and 465) from `noreply@sustenaut.eu`, an alias of the account in
  `auth-smtp-login`.

Why our own link and code and not Phase Two's keycloak-magic-link: that extension is
under the Elastic License 2.0 (every release, checked October 2026), not an open
source licence. Ours is small and uses only Keycloak's Apache-licensed APIs.

The admin fallback, inviting someone directly (signed in to Sustenaut's tailnet;
`SUSTENAUT_SERVER=sustenaut` opens the admin tunnel for the run). `--domain <domain>`
(or `INVITE_CLIENT=<domain>`) marks them as that domain's person, as its own invitation
does, and lands them on its home page once signed in. Without it they belong to no domain:
none can remove them and "Remove my access" has nothing to remove, and the script warns.

```sh
SUSTENAUT_SERVER=sustenaut ./with-secrets ./invite-family.sh --domain example.net anna@example.org Anna Example
```

Running it again for the same address resends the invitation (a way back in on a new
phone, say). Remove a lost passkey in the admin console (realm `family`, Credentials).

### Taking access away

An account is marked with every domain that invited it (`sustenaut.invitedBy`). Access to
a domain ends in four ways, all through `FamilyRemoval.leave`: the domain removes the
person (`/remove` above), the person leaves (below), the domain's revoked client is
deleted (30 days after deregistering or a failed re-check, unless the domain has
registered again), or the admin runs `remove-family.sh`. Each time:

- the domain's mark comes off and **all the person's sessions end**, offline ones too
  (tokens issued before then stop working);
- if **no domain is left**, the account is switched off and stamped
  `sustenaut.removedAt`; its passkeys are kept. A daily job (beside the re-check;
  `sustenaut.appRegistration.removalSeconds`) **deletes it 30 days later**. Invited again
  before then, by any domain, it is switched on as it was. An account switched off
  without the stamp (an admin locked it) stays locked when invited and is never deleted
  by the job;
- the person is emailed in the domain's words: "you no longer have access to <name>",
  plus "your account will be deleted in 30 days" when it was the last domain. `moved`
  says instead that what the domain shares has moved to a new address (not named) and
  whom to ask (its `help_contact`); leaving says they asked for it; a deleted client says
  the domain no longer uses this sign-in. Keycloak logs one line (domain, how, account
  kept or disabled), never the address. `remove-family.sh` emails nobody.

**"Remove my access"** is the required action `sustenaut-leave`, used only as an
application-initiated action: the app links to the realm's auth URL with its own
`client_id`, `kc_action=sustenaut-leave`, `max_age=300` (a fresh sign-in) and a redirect
URI of its own that reads the outcome (example.net: `https://share.example.net/left`, served
by the portal outside oauth2-proxy, which can't take a sign-in it did not start). The
domain is the client signed in to (an active registered domain). A page
(`themes/family/login/family-leave.ftl`) says what goes; Remove calls `leave` and goes back
with the app's `state` and `kc_action_status=success` but no code (the session is gone);
Cancel goes back as Keycloak does (a code, `kc_action_status=cancelled`), nothing changed.
Someone the domain did not invite (no mark: an admin's invitation without `--domain`) is
told there is nothing to remove here, with only Back (cancelled). Every skip is logged in
one line without the address (`leave: …`: which check failed); an action switched off in
the realm is skipped by Keycloak itself (`kc_action_status=error`, logged at debug only).
example.net links it from the portal's footer and help.

The admin fallback (no email; the domain's own cleanup, such as Immich shared links'
`for:` lines, is still its own `remove.sh`):

```sh
SUSTENAUT_SERVER=sustenaut ./with-secrets ./remove-family.sh anna@example.org example.net   # that mark
SUSTENAUT_SERVER=sustenaut ./with-secrets ./remove-family.sh anna@example.org              # delete now
```

The realm's user profile lets admins edit unmanaged attributes (`ADMIN_EDIT`; users
still can't), so that script and the admin console can change the marks.

### Domains register for sign-in; a DNSSEC-signed record approves them

No client secret is shared between projects. A domain registers itself, the way ACME's
dns-01 challenge works (`extension/…/AppRegistration*.java`). One registration, one
client, per domain; which services on the domain use it is the domain owner's business.

1. **The registrant signs in**: someone with a verified email address exactly at the
   domain (`registrant@example.net` for `example.net`), invited to this realm like anyone else
   (`invite-family.sh`). Apps do it with the device flow of the public client
   `app-registration`: they show a link and a code, the registrant opens it, signs in
   (emailed link or code, or a passkey) and confirms. Later: a wallet-backed Sustenaut account.
2. **They ask**: `POST https://auth.sustenaut.eu/realms/family/app-registration` with that
   access token and `{"domain": "example.net", "redirect_uris": [...],
   "post_logout_redirect_uris": [...]}`. The domain must be on the realm's list
   (`sustenaut.appRegistration.domains`: example.net, sustenaut.eu); the URLs plain https on
   any host under it. The answer: the record to publish, `_sustenaut-auth.<domain> TXT
   "sa1=<token>"`, and a `verify_url`. The request waits, as a disabled client, 7 days.
3. **Approving = publishing that record** in the domain's DNS (example.net's records are in
   the tenant's repository `dns.tf`, sustenaut.eu's in shared-infra's `infra/dns.tf`).
4. **Verify** (same registrant, signed in): Keycloak looks the record up **with DNSSEC
   validation**, from IANA's root keys (dnsjava's validating resolver over the server's
   resolver). Only a validated answer with the token counts: an unsigned domain can't
   register. Not there yet: 409, try again. There: the client, **id = the domain**, is
   switched on and `client_id`, `client_secret`, `registration_access_token` and
   `registration_client_uri` are returned, **once**. A client the domain had before is
   revoked (and its registrant told).
5. **Weekly re-check** (`sustenaut.appRegistration.checkSeconds`). A validated "no" (the
   record gone or changed) is checked again an hour later; a second one in a row **revokes**
   the client: switched off for good (putting the record back doesn't undo it), renamed
   `revoked-<domain>-<time>`, deleted after 30 days, and the registrant emailed that the
   TXT record required to use auth.sustenaut.eu no longer exists and a new registration
   is required (a copy to the operator, `alerts@sustenaut.eu`). Anything not definite (no answer, a
   validation failure) changes nothing and is asked again an hour later.

What every domain's client gets, whatever it asks: confidential, authorization code flow
with PKCE (S256), the `basic`, `email`, `profile`, `web-origins` and `acr` scopes (so
`email` is in the ID token), no service account, no password, implicit, device or other
grant, no protocol mappers (the team realm adds its `access` claim's, the only one allowed there), no full scope. With its registration access token the app can
read and change its client at `registration_client_uri` (add another service's redirect
URI, say) within those limits and under its domain (`FamilyClientRules`); Keycloak's own
registration endpoints create nothing.

Both example.net and sustenaut.eu must be DNSSEC-signed before this can approve anything
(the move to Cloudflare + deSEC, a separate change). Limits: 20 waiting requests at
most, 10 an hour per registrant. One Keycloak instance runs the re-check (not
cluster-coordinated). Locally, CoreDNS signs example.net and sustenaut.eu with keys from
`dev/dnskeys.py`, which the realms trust as their anchors (`FAMILY_DNSSEC_TRUST_ANCHORS`,
`TEAM_DNSSEC_TRUST_ANCHORS`);
the decisions are unit-tested in `extension/` (`LIVE_DNS=1` also against real signed,
unsigned and deliberately broken domains).

Going live, once (after the steps above are done for the sustenaut realm):

1. mailbox.org: the alias `noreply@sustenaut.eu` on the account, and an app
   password limited to SMTP (All settings, Security, Email app-passwords; in the
   classic interface Settings, mailbox.org, Email App Passwords) just for Keycloak.
2. Bitwarden, project Sustenaut: `auth-smtp-login` (that account's login address,
   not the alias) and `auth-smtp-password` (the new app password). Other projects'
   SMTP secrets are different app passwords; this repository's `./with-secrets` does not
   read them.
3. The deploy walk ("Deploying", above), which puts the two into `auth-secrets` and runs the `auth` workflow: the image gets the family theme, sign-in step and app registration, and
   the realm job creates the realm.
4. DNSSEC for example.net (and sustenaut.eu): the DNS move must be live first.
5. Set the Actions variable `FAMILY_TENANT_DOMAIN` to the tenant's domain (the realm job
   refuses to run without it), and invite the registrant, an address at that domain:
   `SUSTENAUT_SERVER=sustenaut ./with-secrets ./invite-family.sh --domain example.net registrant@example.net`
   (and open its link: that signs you in).
6. The tenant registers (device sign-in as registrant@example.net, [below](#domains-register-for-sign-in-a-dnssec-signed-record-approves-them))
   and publishes the DNS record it is given, then asks again to verify.
7. Invite yourself as a friend too, if you like, and try both ways in.

Not in this first version (follow-ups):

- **EUDI wallet as an optional way in.** An invited account would need a "link my
  wallet" step after signing in by email or passkey: the wallet plugin must never
  create accounts in this realm (`importUnknownUsers` off), only find linked ones.
- **Sign-in notices:** an email to the person when a new passkey is added.
- **Registrants with a wallet-backed Sustenaut account** instead of a family-realm
  invitation.

## The team realm (sustenaut.eu's team sites)

For the Sustenaut team's own sites, opportunity.sustenaut.eu first, in place of Google
sign-in. It is the family realm again (`realm/team.json`; the same sign-in step,
`FamilySignInForm`, and the team's wording over the family theme): **invite only**,
**passkeys first** (with an email notice for each passkey added), an **emailed 6-digit code** as the fallback, **no passwords**, the
email set by the controller and nobody else, no account console. The `sustenaut` realm stays
wallet-only and has nothing to do with it.

- **One list.** [The access page](#the-access-page-who-may-use-which-service) replaces
  Terraform's `var.team` as the list of who may use which service.
- **`invite-team.sh`, until the consumer repositories have switched, then retired.** It reads
  `var.team` (`terraform output auth_team`) and brings the realm in line: a new address gets an
  account and the invitation email (a passkey setup link, 7 days); an address taken out of the
  list has its account disabled and signed out everywhere (kept: put back, it is switched on and
  invited again); `--resend EMAIL` sends someone's invitation again. **Once people are invited on
  the page, it would switch off anyone not in `var.team`** and bring back anyone removed who still
  is: do not run it after the import unless `var.team` says the same as the page.
- **The registrant** (`var.team_registrant`, default `admin@sustenaut.eu`) registers
  sustenaut.eu's sites for sign-in, the way `registrant@example.net` does for example.net in the
  family realm (above). It has an account but is not a team member: the page lists it apart with
  no service roles (`sustenaut.access.registrant`, `TEAM_REGISTRANT` on the realm job for another
  address). Until they switch, the sites check `var.team` themselves (oauth2-proxy's emails file
  and the app's `TEAM`).
- **The sites' client.** sustenaut.eu registers once, `client_id` = `sustenaut.eu`, for all
  its team sites; each adds its redirect URIs with the registration access token.
  `business-plan/opportunity-site/register-client.sh` does it for the opportunity site: it runs
  `register-app.py` on the k3s server, which keeps the client there
  (`/root/.config/sustenaut-auth/team-sustenaut.eu/`) and puts its id and secret in the
  Secret `opportunity-oidc`; the approval record goes in `shared-infra/infra/auth-approvals.json`, which
  `shared-infra/infra/dns.tf` publishes at `_sustenaut-auth.sustenaut.eu` (Cloudflare and deSEC). No
  client secret is made by hand or kept in Bitwarden.
- **Email** from `noreply@sustenaut.eu` (an alias on the same mailbox.org account and app
  password as the family realm's); alerts about revoked clients to `alerts@sustenaut.eu`.

Going live, once (the family realm's steps 1 to 3 done, so the SMTP secrets and the
`noreply@sustenaut.eu` alias are in):

1. `./with-secrets terraform -chdir=infra apply` (the `auth_team` output, and later the
   approval record), then run the `auth` workflow (or merge): the image gets the team
   theme and the realm job creates the realm.
2. `SUSTENAUT_SERVER=sustenaut ./with-secrets ./invite-team.sh`: everyone in `var.team` and the
   registrant get their invitation. Set up the registrant's passkey (or use a code).
3. The opportunity site's sign-in: `business-plan/opportunity-site/README.md`, "Going live".
4. The access page: `SUSTENAUT_SERVER=sustenaut ./with-secrets ./import-team-access.sh`, once.

### The access page: who may use which service

`https://auth.sustenaut.eu/realms/team/access` is the one list: a table of people by service
roles (`extension/`, `AccessPage`; `themes/team/login/team-access.ftl`; no script). It signs in
through the realm's own passkey or emailed code. Only a `controller` sees it; anyone else
signed in is refused, and it does not exist in the other realms. A change needs no Terraform, no secrets
pushed and no restarts.

- **Service roles** are client roles on the domain's sign-in client, one per service (`opportunity`,
  `release`, `notebooks`, `plan`, `pub`, `estimate`, `review`; lower case, an optional `:level`). Each
  is a column. A site declares its own: `register-app.py --role opportunity` when it registers and
  on any later run, or `POST /realms/team/app-registration/<domain>/roles` `{"roles": [...]}` with the
  client's id and secret (HTTP Basic); adding a role that is there changes nothing, and neither can
  give one to anyone or take one away. A controller can declare one on the page, for a service that has not
  registered. With no client for the domain at all, roles wait on a switched-off placeholder with the
  domain's id (state `declared`, no secret, nothing can sign in to it), which the registration takes
  over. A new registration keeps the roles and who holds them, whether it replaces the old client or follows its revocation (30 days).
- **`controller`** is a realm role: it holds every service role of every client and alone can change
  the page. A controller can give it to someone else, but not take it from themself or remove
  themself, so there is always one left.
- **The `access` claim.** The ID token, access token and userinfo of a domain's client carry `access`:
  that person's roles on THAT client, nothing of any other client's. A controller's is all of the
  client's roles and the word `controller`, which the release app reads as edit rights. Someone with no
  roles gets `[]`. A protocol mapper does this (`AccessClaimMapper`), on every domain client in this realm
  only; `FamilyClientRules` lets an app's registration token keep it but add no other. For oauth2-proxy, in place of
  `--authenticated-emails-file`:

  ```
  --email-domain=* --oidc-groups-claim=access --allowed-group=opportunity
  ```

  It hands the app the claim in `X-Forwarded-Groups` (with `--pass-user-headers=true`).
- **A tick** takes effect at the person's next sign-in or token refresh; a site's cookie keeps its
  old answer until then, so an oauth2-proxy site needs `--cookie-refresh` to see one taken away sooner
  (or [checks on each request](#checking-access-on-each-request), which sees it at once). Taking a tick away changes nothing else about the person.
- **Invite**: email, name, ticks. An account (verified: the controller vouches) and the existing
  invitation email, whose 7-day link sets up a passkey. Status: `invited`, `active` (signed in once
  or has a passkey), `removed`.
- **Remove from all** takes every role, ends all their sessions (tokens and refresh tokens stop working
  at once) and switches the account off, stamped `sustenaut.removedAt`: the same 30 days and daily job as
  family removal. **Put back** before then restores the account, passkeys too, with no roles, and invites them
  again. Nobody is emailed about a removal.
- **History per person**: the realm's admin events, kept a year. The page's changes say who made them; the
  admin API's (the console, the import) say "an admin".
- **Every change** is a POST with a token tied to the user session and, as browsers send it, an `Origin`
  of this server. Without them, 403 and nothing changed.

### Checking access on each request

A cookie or token says what was true when it was made. So that a change reaches a site at once, a
site's server asks one question on each request it gets: has this client's access state changed?
`access_check.py` does it (Python, standard library only; copy the file into the site).

There is no timer anywhere. A site fetches the hash only because a request arrived, so a site nobody is using
asks nothing, and an idle browser tab costs nothing. The browser never sees the hash.

The contract, for a site in another language (the release app):

1. **The hash.** `GET /realms/team/app-registration/<domain>/access-state` with the client's id and secret
   (HTTP Basic, each URL-encoded) answers `{"hash": "<hex>"}`, not to be cached by anything between. Compare it,
   never read it. It is an HMAC of that client's access state, worked out from Keycloak's state on each call so a
   change by any route counts (page, admin console, scripts): for everyone holding something on the client or
   switched off, their id, on or off, when their sessions were last ended by force, and their claim. Signing in
   does not change it. Each client has its own and only it can read it (401 otherwise; 503 until the key
   `SUSTENAUT_ACCESS_HASH_KEY` is set; 404 in other realms).
2. **Fetch only when a request arrives.** Keep it about 2 seconds, so a burst of requests makes one fetch. Do not poll.
3. **Per person, on the server** (never in a cookie the browser could replay): store the hash they last passed under, their
   roles, and when. If the fetched hash is the stored one and the check is under 5 minutes old, go on with the stored
   roles, with no other call. Otherwise do one full check, and store the hash fetched *before* it, so a change in between shows next time.
4. **The full check.** `GET /realms/team/protocol/openid-connect/userinfo` with the person's access token (oauth2-proxy:
   `--pass-access-token=true`, read `X-Forwarded-Access-Token`; `--cookie-refresh=4m` keeps it valid, as they last 5 minutes).
   200: `access` is their roles now. 401 or 403: the session is over or the account removed, so forget them and send
   them to sign in (a change is refused, without losing what they typed). Anything else: as below.
5. **Keycloak cannot be reached.** Someone whose stored hash is the last one known keeps reading with their stored
   roles. Changes are refused, and so is anyone else: no stored hash, or one that is out of date.

So a person with a role taken away, or removed from all, is refused at their next request, within the 2 seconds the hash is
kept. A page already open stays on the screen; the next click fails. An unchanged list costs Keycloak one small request every
2 seconds at most, per site, and only while someone is using it. Every change costs each active person one call to userinfo.

### A Worker gate for static sites

A static team site has no server to run `access_check.py` on, so `edge-gate/gate.js` does the same check in a Cloudflare
Worker that also serves the site's files (Workers static assets). No dependencies; copy the file into the site. Its
tests are `node --test edge-gate/gate.test.js`, and `dev/prove_team.py` runs it under `wrangler dev` against the realm.

```js
import { gate } from "./gate.js";
export default gate({ role: "pub" });
// optional: headers, a function from a path to headers for what is served there;
// handler, (request, env, { email, roles, reading }), the site's own answer past the check, or null to serve the file
```

```toml
[vars]
REALM_URL = "https://auth.sustenaut.eu/realms/team"
CLIENT_ID = "sustenaut.eu"

[assets]
directory = "./site"
binding = "ASSETS"
run_worker_first = true   # nothing is served without passing the gate
```

`CLIENT_SECRET` and `SESSION_KEY` (32 characters or more, one per site) are Worker secrets. Without any of these it fails
closed. Register the site's address like any other: `register-app.py --redirect https://<site>/oauth2/callback --role <role>`.

- **Sign-in.** `/oauth2/start` runs the code flow with the realm (PKCE, with the client secret), and `/oauth2/callback`
  checks the ID token against the realm's JWKS (RS256, issuer, audience, date, nonce; the keys cached an hour) and the `state`. `/oauth2/sign_out` signs
  out. `/healthz` is the only other open path.
- **The session** is a cookie (`__Host-sustenaut-gate`: HttpOnly, Secure, SameSite=Lax, 7 days at most) encrypted with AES-GCM, so a
  forged or altered one is refused, and the refresh token in it can't be read by the browser. It holds the hash and roles of the last full check, because a Worker keeps nothing between requests.
- **On each request**, exactly the [contract above](#checking-access-on-each-request): fetch the hash only because a request arrived, keep it 2 seconds,
  and do a full check (a refresh, then userinfo) when it differs from the session's or after 5 minutes. The role is required, from userinfo. A
  role taken away is refused at the next request; a removal sends the person to sign in. There are no timers.
- **Keycloak can't be reached.** A session whose hash is the last one known keeps reading (that hash is also kept in the Cloudflare location's cache, for a new
  isolate); anything else that isn't a read is refused, as is a session already out of date. New sign-ins wait. If no location knows a last hash at
  all, a session in date keeps reading: the session's 7 days are the limit.
- **Behind the gate**, `public` in a file's `Cache-Control` becomes `private`, so no shared cache keeps a page.
- **What Cloudflare sees:** it serves these pages, so their traffic. That is accepted for static team pages; server sites stay on Hetzner behind oauth2-proxy.

The switch, once this version is deployed:

1. `SUSTENAUT_SERVER=sustenaut ./with-secrets ./import-team-access.sh` declares the roles above
   (`TEAM_SERVICE_ROLES`), gives every role on the client to everyone in `var.team` (not the registrant), and
   `controller` to `ACCESS_CONTROLLER` (Bitwarden: `access-controller`). A member with no account gets one and the invitation.
   Run again, it gives back what the page has taken from anyone in the list, so it is for the first day.
2. The consumer repositories switch to the claim (phase 2), then `invite-team.sh` and the `auth_team`
   output go. The Google IAP sites become columns when they move behind this realm; `var.team` goes with the last.

Not in this first version, as for the family realm: **"link my wallet"**. Once wallets are
issued, a team member signed in with a passkey or code would add their wallet with a
required action after `family-sign-in` (the wallet plugin must never create accounts here,
`importUnknownUsers` off, only find linked ones).

## Licence

Apache-2.0: see [`LICENSE`](LICENSE). The image also carries the ADORSYS OpenID4VP plugin, which
keeps its own licence (AGPL-3.0); its source and the patches in `plugin-patches/` are served
with it (`plugin-source/`).
