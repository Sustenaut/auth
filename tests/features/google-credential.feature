Feature: The backup's Google credential
  The external_account credential the backup reads names one audience: the projected token's and the services pool's provider.
  The manifests are k8s/google-credential.yaml (the credential), k8s/service-accounts.yaml and k8s/backup.yaml
  (the CronJob whose one container uploads the backup).

  Scenario: The backup's token, its credential and the provider name one audience
    When the backup's credential and CronJob are read from the manifests
    Then the result's "credential.type" is "external_account"
    And the result's "credential.audience" is "//iam.googleapis.com/projects/948171295184/locations/global/workloadIdentityPools/services/providers/sustenaut-k3s"
    And the result's "token.audience" is "//iam.googleapis.com/projects/948171295184/locations/global/workloadIdentityPools/services/providers/sustenaut-k3s"
    And the result's "credential.service_account_impersonation_url" is "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sustenaut-auth-backup@sustenaut.iam.gserviceaccount.com:generateAccessToken"

  Scenario: The backup runs as its own account with no API token
    When the backup's credential and CronJob are read from the manifests
    Then the result's "account.automountServiceAccountToken" is "false"
    And the result's "pod.serviceAccountName" is "backup"
    And the result's "pod.automountServiceAccountToken" is "false"
    And the result's "token.volumes" is "1"
    And the result's "token.sources" is "1"
    And the result's "pod.containers" is "1"

  Scenario: The upload reads the token where the credential does, and no key
    When the backup's credential and CronJob are read from the manifests
    Then the result's "token.file" is "/var/run/secrets/google/token"
    And the result's "credential.credential_source.file" is "/var/run/secrets/google/token"
    And the result's "upload.CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE" is "/etc/google/credential.json"
    And the result's "upload.credential file" is "/etc/google/credential.json"
    And the result's "upload.key file in the command" is "false"
