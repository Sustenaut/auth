Feature: PostgreSQL reaches its WAL archive with no key
  The database and its wal-g sidecar read the external_account credential in
  k8s/wal-google-credential.yaml, which trades the pod's projected token for
  sustenaut-auth-wal through Workload Identity. A mismatch between the provider,
  the token's audience and the credential's fails only at run time, as Google's
  STS refusing the token, so the manifests are held to one another here.

  Background:
    Given the manifests in k8s and backups/pg-backup.json

  Scenario: The credential acts as the archive's account, at the provider's audience
    Then the credential in wal-google-credential.yaml acts as sustenaut-auth-wal, audience the provider's
    And pg-backup.json names that account, its read-only restore account, the ServiceAccount and the ConfigMap

  Scenario: The StatefulSet runs as postgres, with no API token and no key
    Then the StatefulSet runs as postgres, which mounts no API token
    And its projected token has the provider's audience
    And no volume of it is the WAL Secret's key

  Scenario Outline: Each container reads the token and the credential where they are
    Then the <container> container finds the token where the credential reads it
    And its GOOGLE_APPLICATION_CREDENTIALS is the ConfigMap's credential.json

    Examples:
      | container |
      | postgres  |
      | wal-g     |
