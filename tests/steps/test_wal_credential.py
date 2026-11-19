"""Steps for features/wal-credential.feature: the WAL archive's keyless credential."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from pytest_bdd import scenarios, when

ROOT = Path(__file__).resolve().parents[2]

scenarios("../features/wal-credential.feature")


def manifests() -> dict:
    """The credential, pg-backup.json's wal block, the StatefulSet's pod, its projected token and each container's
    token file and credential."""
    configmap = yaml.safe_load((ROOT / "k8s" / "wal-google-credential.yaml").read_text(encoding="utf-8"))
    statefulset = next(d for d in yaml.safe_load_all((ROOT / "k8s" / "postgres.yaml").read_text(encoding="utf-8"))
                       if d and d["kind"] == "StatefulSet")
    accounts = {d["metadata"]["name"]: d for d in yaml.safe_load_all(
        (ROOT / "k8s" / "service-accounts.yaml").read_text(encoding="utf-8")) if d}
    spec = statefulset["spec"]["template"]["spec"]
    volumes = [v for v in spec["volumes"] if "projected" in v]
    sources = volumes[0]["projected"]["sources"]
    token = {"name": volumes[0]["name"], **sources[0]["serviceAccountToken"]}
    credential_volumes = [v for v in spec["volumes"]
                          if (v.get("configMap") or {}).get("name") == "wal-google-credential"]
    containers = {}
    for container in spec["containers"]:
        mounts = {m["name"]: m["mountPath"] for m in container["volumeMounts"]}
        env = {e["name"]: e.get("value") for e in container["env"]}
        containers[container["name"]] = {
            "token file": f"{mounts[token['name']]}/{token['path']}",
            "GOOGLE_APPLICATION_CREDENTIALS": env["GOOGLE_APPLICATION_CREDENTIALS"],
            "credential file": f"{mounts[credential_volumes[0]['name']]}/credential.json",
        }
    return {
        "credential": json.loads(configmap["data"]["credential.json"]),
        "configmap": configmap["metadata"]["name"],
        "settings": json.loads((ROOT / "backups" / "pg-backup.json").read_text(encoding="utf-8"))["wal"],
        "pod": {k: spec[k] for k in ("serviceAccountName", "automountServiceAccountToken")},
        "account": {"automountServiceAccountToken": accounts["postgres"]["automountServiceAccountToken"]},
        "token": {"volumes": len(volumes), "sources": len(sources), "audience": token["audience"]},
        # The WAL Secret's key, gcs-key.json, from before Workload Identity.
        "volumes holding the key file": [
            v["name"] for v in spec["volumes"]
            if any(i.get("key") == "gcs-key.json" for i in (v.get("secret") or {}).get("items") or [])
        ],
        "credential volumes": len(credential_volumes),
        "containers": containers,
    }


@when("the WAL archive's manifests are read")
def read_manifests(ctx):
    ctx.attempt(manifests)
