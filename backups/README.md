# Backups: pg-backup

Keycloak's database is backed up by [Sustenaut/pg-backup](https://github.com/Sustenaut/pg-backup),
pinned to one release in [`pg-backup`](pg-backup) (the same as `infra/`'s module ref and
`k8s/kustomization.yaml`'s image). This folder holds only what is auth's:
[`pg-backup.json`](pg-backup.json), which says where the database runs, where its archive is, what
to stop while a restore goes back, and that a restore must have the realms family, sustenaut and
team. Every command checks it against the release's schema before it touches the server.

Run each from `~/git/auth` after `git latest`, signed in to Sustenaut's tailnet:

| When | Command |
|---|---|
| Monthly, and after any change to the backups or PostgreSQL (right after a merge: `drill --wait`) | `./backups/pg-backup drill` |
| To look at, or get back, the database as it was at a moment | `./backups/pg-backup restore --to "2026-11-05 14:32:00+00"` (or `--to latest`) |
| To put that restore back as the live database, after you've looked at it | `./backups/pg-backup promote auth-restore-<the namespace>` |
| To delete a scratch restore | `./backups/pg-backup clean auth-restore-<the namespace>` |
| Once, and again after a rebuild of the server | the deploy walk (`pg.database`, the README's "Deploying"), or `./backups/pg-backup setup-secrets` |

- **drill** exits 0 with `DRILL PASSED … in N s` (under 15 minutes), 2 with `DRILL NOT RUN` when
  there's no base backup that old yet (it says when to try again), and 1 with `DRILL FAILED`.
- **restore** never touches namespace `auth`. It exits 3 when there's no base backup from before
  the moment.
- **promote** runs only at a terminal, after you type `promote <namespace>`. It runs the nightly
  dump job once first, stops Keycloak (sign-in is down for about a minute), and replaces the live
  database in one transaction, so a failure leaves live as it was.
- **setup-secrets** makes `auth-wal-gcs-key` and `auth-wal-key` in Bitwarden if they aren't there,
  and puts them in the cluster as the Secret `auth-wal`. **Losing `auth-wal-key` makes the archive
  unreadable.**

pg-backup's README says what each does in full. The archive is `gs://sustenaut-auth-wal`: WAL kept
16 days and base backups 15, so a restore reaches any moment in the last 14 days. The nightly
`pg_dump` (`k8s/backup.yaml`) is kept 30 days in `gs://sustenaut-auth-backups`.
