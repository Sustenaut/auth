"""The backup reaches Cloud Storage with no key: the Cloud SDK reads the external_account
credential in k8s/google-credential.yaml, whose audience must be the projected
token's and the services pool's provider. A mismatch fails only at run time, as
Google's STS refusing the token."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from pytest_bdd import scenarios, then

scenarios("google-credential.feature")

ROOT = Path(__file__).resolve().parents[2]
PROVIDER = ("//iam.googleapis.com/projects/948171295184/locations/global/workloadIdentityPools/services/"
            "providers/sustenaut-k3s")


@then("the backup's token, its credential and the provider name one audience")
def the_backups_token_its_credential_and_the_provider_name_one_audience():
    configmap = yaml.safe_load((ROOT / "k8s" / "google-credential.yaml").read_text(encoding="utf-8"))
    credential = json.loads(configmap["data"]["credential.json"])
    assert credential["type"] == "external_account" and credential["audience"] == PROVIDER
    assert credential["service_account_impersonation_url"].endswith(
        "/sustenaut-auth-backup@sustenaut.iam.gserviceaccount.com:generateAccessToken")
    accounts = {d["metadata"]["name"]: d for d in yaml.safe_load_all(
        (ROOT / "k8s" / "service-accounts.yaml").read_text(encoding="utf-8")) if d}
    assert accounts["backup"]["automountServiceAccountToken"] is False
    cronjob = yaml.safe_load((ROOT / "k8s" / "backup.yaml").read_text(encoding="utf-8"))
    spec = cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    assert spec["serviceAccountName"] == "backup" and spec["automountServiceAccountToken"] is False
    (volume,) = [v for v in spec["volumes"] if v["name"] == "google-token"]
    (source,) = volume["projected"]["sources"]
    assert source["serviceAccountToken"]["audience"] == PROVIDER
    (upload,) = spec["containers"]
    mounts = {m["name"]: m["mountPath"] for m in upload["volumeMounts"]}
    assert f"{mounts['google-token']}/{source['serviceAccountToken']['path']}" == credential["credential_source"]["file"]
    env = {e["name"]: e.get("value") for e in upload["env"]}
    assert env["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"] == f"{mounts['google-credential']}/credential.json"
    assert "--key-file" not in " ".join(upload["command"])
