# Where the shared sign-in's nightly database dumps go: a bucket in Finland, kept 30
# days, written by an account that can create objects and nothing else. Keycloak itself
# runs on the Sustenaut k3s server, whose Terraform, like auth's DNS record, is
# Sustenaut/shared-infra's. This stack does not read that state.
#
# The account's key is not here, so no state holds it: the deploy walk
# (`./pubdeploy walk --fulfil`) makes it, puts it in Bitwarden as auth-backup-gcs-key,
# and gives it to the cluster in the Secret auth-secrets.

locals {
  gcp = jsondecode(file("${path.module}/../pubkit.json")).hosting.providers["google-cloud"]
}

module "backups" {
  source = "github.com/Sustenaut/pubkit//terraform/backup-bucket?ref=v0.26.0"

  bucket  = "${local.gcp.project}-auth-backups"
  project = local.gcp.project
  region  = local.gcp.region

  account_id           = "sustenaut-auth-backup"
  account_display_name = "Sustenaut auth backups"
  account_description  = "Writes Keycloak's nightly PostgreSQL dumps from the Hetzner k3s server into the auth-backups bucket."
  create_key           = false
}

# Where every change to Keycloak's database goes, as it is made: PostgreSQL's write-ahead
# log, archived by WAL-G within a minute (k8s/postgres.yaml), with a base backup each night,
# so the database can be restored to any moment in the last 14 days. The nightly dumps above
# stay as a second copy that does not depend on PostgreSQL's version or on WAL-G.
# Sustenaut/pg-backup's module: the bucket, its add-and-read account (which may delete only
# its own upload chunks), and deletion by age. backups/pg-backup setup-secrets makes the keys.
module "wal" {
  source = "github.com/Sustenaut/pg-backup//terraform/wal-archive?ref=v0.2.0"

  project              = local.gcp.project
  region               = local.gcp.region
  bucket               = "${local.gcp.project}-auth-wal"
  prefix               = "keycloak"
  account_id           = "sustenaut-auth-wal"
  account_display_name = "Sustenaut auth WAL archive"
  account_description  = "WAL-G on the Hetzner k3s server: archives Keycloak's write-ahead log and nightly base backups into the auth-wal bucket. Creates and reads; deletes only its own upload chunks."
  role_id              = "walChunkDelete"
}

# Where these were before the module.
moved {
  from = google_storage_bucket.wal
  to   = module.wal.google_storage_bucket.wal
}
moved {
  from = google_service_account.wal
  to   = module.wal.google_service_account.wal
}
moved {
  from = google_storage_bucket_iam_member.wal
  to   = module.wal.google_storage_bucket_iam_member.wal
}
moved {
  from = google_project_iam_custom_role.wal_chunk_delete
  to   = module.wal.google_project_iam_custom_role.wal_chunk_delete
}
moved {
  from = time_sleep.wal_chunk_delete_role
  to   = module.wal.time_sleep.wal_chunk_delete_role
}
moved {
  from = google_storage_bucket_iam_member.wal_chunk_delete
  to   = module.wal.google_storage_bucket_iam_member.wal_chunk_delete
}
