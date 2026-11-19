Feature: PostgreSQL reaches its WAL archive with no key
  The database and its wal-g sidecar read the external_account credential in
  k8s/wal-google-credential.yaml, which trades the pod's projected token for
  sustenaut-auth-wal through Workload Identity. A mismatch between the provider,
  the token's audience and the credential's fails only at run time, as Google's
  STS refusing the token, so the manifests are held to one another here: the
  ConfigMap, the StatefulSet in k8s/postgres.yaml, k8s/service-accounts.yaml and
  the wal block of backups/pg-backup.json.

  Scenario: The credential acts as the archive's account, at the provider's audience
    When the WAL archive's manifests are read
    Then the result's "credential.type" is "external_account"
    And the result's "credential.audience" is "//iam.googleapis.com/projects/948171295184/locations/global/workloadIdentityPools/services/providers/sustenaut-k3s"
    And the result's "credential.service_account_impersonation_url" is "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sustenaut-auth-wal@sustenaut.iam.gserviceaccount.com:generateAccessToken"

  Scenario: pg-backup.json names that account, its read-only restore account, the ServiceAccount and the ConfigMap
    When the WAL archive's manifests are read
    Then the result's "settings.account" is "sustenaut-auth-wal@sustenaut.iam.gserviceaccount.com"
    And the result's "settings.restore_account" is "sustenaut-auth-wal-read@sustenaut.iam.gserviceaccount.com"
    And the result's "settings.serviceaccount" is "postgres"
    And the result's "pod.serviceAccountName" is "postgres"
    And the result's "settings.credential" is "wal-google-credential"
    And the result's "configmap" is "wal-google-credential"
    # The whole wal block: no gcs_key_secret, the key it had before Workload Identity.
    And the result's "settings" is "{"secret": "auth-wal", "bucket": "sustenaut-auth-wal", "prefix": "keycloak", "account": "sustenaut-auth-wal@sustenaut.iam.gserviceaccount.com", "restore_account": "sustenaut-auth-wal-read@sustenaut.iam.gserviceaccount.com", "serviceaccount": "postgres", "credential": "wal-google-credential", "encryption_key_secret": "auth-wal-key"}"

  Scenario: The restore account is the one infra/main.tf makes
    infra/main.tf's restore_account_id, which shared-infra's restore mapping grants.

    When the WAL archive's manifests are read
    Then the file "../infra/main.tf" includes "restore_account_id = "sustenaut-auth-wal-read""

  Scenario: The StatefulSet runs as postgres, with no API token and no key
    When the WAL archive's manifests are read
    Then the result's "pod.automountServiceAccountToken" is "false"
    And the result's "account.automountServiceAccountToken" is "false"
    And the result's "token.volumes" is "1"
    And the result's "token.sources" is "1"
    And the result's "token.audience" is "//iam.googleapis.com/projects/948171295184/locations/global/workloadIdentityPools/services/providers/sustenaut-k3s"
    And the result's "volumes holding the key file" is "[]"

  Scenario Outline: Each container reads the token and the credential where they are
    When the WAL archive's manifests are read
    Then the result's "containers.<container>.token file" is "/var/run/secrets/google/token"
    And the result's "credential.credential_source.file" is "/var/run/secrets/google/token"
    And the result's "containers.<container>.GOOGLE_APPLICATION_CREDENTIALS" is "/etc/wal-google/credential.json"
    And the result's "containers.<container>.credential file" is "/etc/wal-google/credential.json"
    And the result's "credential volumes" is "1"

    Examples:
      | container |
      | postgres  |
      | wal-g     |
