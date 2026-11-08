output "backups" {
  description = "The backup bucket, and the account that writes to it."
  value = {
    bucket  = module.backups.bucket
    account = module.backups.account
  }
}

output "wal" {
  description = "The WAL archive's bucket, and the account WAL-G writes to it as."
  value = {
    bucket  = module.wal.bucket
    account = module.wal.account
  }
}
