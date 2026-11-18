"""The backup reaches Cloud Storage with no key: the Cloud SDK reads the external_account
credential in k8s/google-credential.yaml, whose audience must be the projected
token's and the services pool's provider. A mismatch fails only at run time, as
Google's STS refusing the token."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from pytest_bdd import scenarios, when

scenarios("google-credential.feature")

ROOT = Path(__file__).resolve().parents[2]


def read(name: str):
    return (ROOT / "k8s" / name).read_text(encoding="utf-8")


def manifests() -> dict:
    """The credential, the backup's ServiceAccount, the CronJob's pod, its projected token and its upload container."""
    credential = json.loads(yaml.safe_load(read("google-credential.yaml"))["data"]["credential.json"])
    accounts = {d["metadata"]["name"]: d for d in yaml.safe_load_all(read("service-accounts.yaml")) if d}
    spec = yaml.safe_load(read("backup.yaml"))["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    volumes = [v for v in spec["volumes"] if v["name"] == "google-token"]
    sources = volumes[0]["projected"]["sources"]
    token = sources[0]["serviceAccountToken"]
    upload = spec["containers"][0]
    mounts = {m["name"]: m["mountPath"] for m in upload["volumeMounts"]}
    env = {e["name"]: e.get("value") for e in upload["env"]}
    return {
        "credential": credential,
        "account": {"automountServiceAccountToken": accounts["backup"]["automountServiceAccountToken"]},
        "pod": {"serviceAccountName": spec["serviceAccountName"],
                "automountServiceAccountToken": spec["automountServiceAccountToken"],
                "containers": len(spec["containers"])},
        "token": {"volumes": len(volumes), "sources": len(sources), "audience": token["audience"],
                  "file": f"{mounts['google-token']}/{token['path']}"},
        "upload": {"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": env["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"],
                   "credential file": f"{mounts['google-credential']}/credential.json",
                   "key file in the command": "--key-file" in " ".join(upload["command"])},
    }


@when("the backup's credential and CronJob are read from the manifests")
def read_manifests(ctx):
    ctx.attempt(manifests)
