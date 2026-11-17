"""Steps for features/wal-credential.feature: the WAL archive's keyless credential."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from pytest_bdd import given, parsers, scenarios, then

ROOT = Path(__file__).resolve().parents[2]
PROVIDER = ("//iam.googleapis.com/projects/948171295184/locations/global/workloadIdentityPools/services/"
            "providers/sustenaut-k3s")

scenarios("../features/wal-credential.feature")


@given("the manifests in k8s and backups/pg-backup.json", target_fixture="wal")
def wal() -> dict:
    configmap = yaml.safe_load((ROOT / "k8s" / "wal-google-credential.yaml").read_text(encoding="utf-8"))
    statefulset = next(d for d in yaml.safe_load_all((ROOT / "k8s" / "postgres.yaml").read_text(encoding="utf-8"))
                       if d and d["kind"] == "StatefulSet")
    accounts = {d["metadata"]["name"]: d for d in yaml.safe_load_all(
        (ROOT / "k8s" / "service-accounts.yaml").read_text(encoding="utf-8")) if d}
    return {"configmap": configmap, "credential": json.loads(configmap["data"]["credential.json"]),
            "spec": statefulset["spec"]["template"]["spec"], "accounts": accounts,
            "settings": json.loads((ROOT / "backups" / "pg-backup.json").read_text(encoding="utf-8"))["wal"]}


def token_volume(wal: dict) -> dict:
    (volume,) = [v for v in wal["spec"]["volumes"] if "projected" in v]
    (source,) = volume["projected"]["sources"]
    return {"name": volume["name"], **source["serviceAccountToken"]}


@then("the credential in wal-google-credential.yaml acts as sustenaut-auth-wal, audience the provider's")
def credential_acts(wal: dict) -> None:
    credential = wal["credential"]
    assert credential["type"] == "external_account" and credential["audience"] == PROVIDER
    assert credential["service_account_impersonation_url"].endswith(
        "/sustenaut-auth-wal@sustenaut.iam.gserviceaccount.com:generateAccessToken")


@then("pg-backup.json names that account, its read-only restore account, the ServiceAccount and the ConfigMap")
def settings_agree(wal: dict) -> None:
    settings = wal["settings"]
    assert settings["account"] == "sustenaut-auth-wal@sustenaut.iam.gserviceaccount.com"
    # infra/main.tf's restore_account_id, which shared-infra's restore mapping grants.
    assert settings["restore_account"] == "sustenaut-auth-wal-read@sustenaut.iam.gserviceaccount.com"
    restore_id = settings["restore_account"].split("@")[0]
    assert f'restore_account_id = "{restore_id}"' in (ROOT / "infra" / "main.tf").read_text(encoding="utf-8")
    assert settings["serviceaccount"] == wal["spec"]["serviceAccountName"]
    assert settings["credential"] == wal["configmap"]["metadata"]["name"]
    assert "gcs_key_secret" not in settings


@then("the StatefulSet runs as postgres, which mounts no API token")
def runs_as_postgres(wal: dict) -> None:
    assert wal["spec"]["serviceAccountName"] == "postgres" and wal["spec"]["automountServiceAccountToken"] is False
    assert wal["accounts"]["postgres"]["automountServiceAccountToken"] is False


@then("its projected token has the provider's audience")
def token_audience(wal: dict) -> None:
    assert token_volume(wal)["audience"] == PROVIDER


@then("no volume of it is the WAL Secret's key")
def no_key(wal: dict) -> None:
    for volume in wal["spec"]["volumes"]:
        items = (volume.get("secret") or {}).get("items") or []
        assert not any(i.get("key") == "gcs-key.json" for i in items), volume


@then(parsers.parse("the {name} container finds the token where the credential reads it"), target_fixture="container")
def finds_token(wal: dict, name: str) -> dict:
    container = next(c for c in wal["spec"]["containers"] if c["name"] == name)
    token = token_volume(wal)
    mounts = {m["name"]: m["mountPath"] for m in container["volumeMounts"]}
    assert f"{mounts[token['name']]}/{token['path']}" == wal["credential"]["credential_source"]["file"]
    return container


@then("its GOOGLE_APPLICATION_CREDENTIALS is the ConfigMap's credential.json")
def env_names_credential(wal: dict, container: dict) -> None:
    (volume,) = [v for v in wal["spec"]["volumes"] if (v.get("configMap") or {}).get("name") == "wal-google-credential"]
    mounts = {m["name"]: m["mountPath"] for m in container["volumeMounts"]}
    env = {e["name"]: e.get("value") for e in container["env"]}
    assert env["GOOGLE_APPLICATION_CREDENTIALS"] == f"{mounts[volume['name']]}/credential.json"
