#!/usr/bin/env python3
"""Reference CFHS materializer v0.1.

Deliberately deterministic and non-agentic. It creates a filesystem representation
from a validated CDM and refuses apparent inline secrets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

VERSION = "0.1"
ROOT_DIRS = [
    "bin", "boot", "dev", "etc", "home", "lib", "mnt", "opt", "proc",
    "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var",
]
SUBDIRS = [
    "etc/company", "etc/identity", "etc/groups", "etc/policy",
    "etc/capabilities", "etc/approvals", "etc/budgets", "etc/devices",
    "etc/mounts", "etc/services", "etc/schedules",
    "home/humans", "home/agents", "usr/skills",
    "var/lib", "var/log/kernel", "var/log/process", "var/log/device",
    "var/log/security", "var/log/audit", "var/log/agent",
    "var/spool/jobs", "var/spool/approvals", "var/spool/dead-letter",
    "var/checkpoint", "var/archive",
    "run/pids", "run/sockets", "run/locks", "run/leases", "run/sessions",
    "run/approvals", "run/heartbeats", "run/ipc",
    "sys/kernel", "sys/identity", "sys/capabilities", "sys/policy",
    "sys/resources", "sys/cgroups", "sys/models", "sys/scheduler",
    "sys/devices", "sys/health",
]

SECRET_FIELD_RE = re.compile(
    r"(^|_)(password|passwd|token|api[_-]?key|private[_-]?key|client[_-]?secret|"
    r"access[_-]?key|secret[_-]?key|credential|bearer)($|_)", re.I
)
SAFE_SECRET_PREFIX = "secret://"
SAFE_PLACEHOLDERS = {"", "REDACTED", "REPLACE_ME", "PLACEHOLDER", "NONE", "NULL"}


def _load(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    if yaml is None:
        raise RuntimeError("PyYAML is required for YAML input")
    return yaml.safe_load(text)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _safe_id(value: Any, fallback: str) -> str:
    raw = str(value or fallback).strip().lower()
    raw = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-.")
    return raw or fallback


def _check_no_inline_secrets(node: Any, path: str = "$") -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            p = f"{path}.{k}"
            if SECRET_FIELD_RE.search(str(k)) and isinstance(v, str):
                upper = v.strip().upper()
                if v.startswith(SAFE_SECRET_PREFIX) or upper in SAFE_PLACEHOLDERS:
                    pass
                elif len(v.strip()) > 0:
                    raise ValueError(f"inline secret-like value rejected at {p}")
            _check_no_inline_secrets(v, p)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _check_no_inline_secrets(v, f"{path}[{i}]")


def _write_json(root: Path, rel: str, value: Any, generated: list[str]) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    generated.append(rel)


def _listify(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        # Permit map-style registries.
        out = []
        for k, v in value.items():
            if isinstance(v, dict):
                item = dict(v)
                item.setdefault("id", k)
            else:
                item = {"id": k, "value": v}
            out.append(item)
        return out
    return [value]


def materialize(cdm: dict[str, Any], target: Path, cfhs_version: str = "0.1") -> dict[str, Any]:
    if not isinstance(cdm, dict):
        raise ValueError("CDM root must be an object")
    _check_no_inline_secrets(cdm)

    generated: list[str] = []
    warnings: list[str] = []
    recognized: set[str] = set()

    parent = target.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{target.name}.stage-", dir=str(parent)))
    try:
        for d in ROOT_DIRS + SUBDIRS:
            (stage / d).mkdir(parents=True, exist_ok=True)

        # Boot metadata
        source_id = (cdm.get("cdm") or cdm.get("manifest") or {}).get("id") if isinstance(cdm.get("cdm") or cdm.get("manifest"), dict) else None
        boot = {
            "cfhs_version": cfhs_version,
            "materializer_version": VERSION,
            "source_cdm_id": source_id,
            "source_digest_sha256": _digest(cdm),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_json(stage, "boot/materialization.json", boot, generated)

        simple_mappings = {
            "company": "etc/company/company.json",
            "authority": "etc/capabilities/authority.json",
            "policies": "etc/policy/policies.json",
            "schedules": "etc/schedules/schedules.json",
            "processes": "var/lib/process-catalog/processes.json",
            "events": "var/lib/event-catalog/events.json",
            "metrics": "var/lib/metrics/definitions.json",
            "documents": "var/lib/document-catalog/documents.json",
            "media": "var/lib/assets/media.json",
        }
        for section, rel in simple_mappings.items():
            if section in cdm:
                recognized.add(section)
                _write_json(stage, rel, cdm[section], generated)

        # Principals + home identity views.
        principals = _listify(cdm.get("principals"))
        if principals:
            recognized.add("principals")
            _write_json(stage, "etc/identity/principals.json", principals, generated)
            for idx, p in enumerate(principals):
                if not isinstance(p, dict):
                    continue
                pid = _safe_id(p.get("principal_id") or p.get("id") or p.get("uid"), f"principal-{idx+1}")
                kind = str(p.get("type", "human")).lower()
                home_kind = "agents" if kind == "agent" else "humans"
                _write_json(stage, f"home/{home_kind}/{pid}/.identity.json", p, generated)

        groups = cdm.get("groups")
        if groups is None and isinstance(cdm.get("organization"), dict):
            groups = cdm["organization"].get("groups") or cdm["organization"].get("teams")
        if groups is not None:
            recognized.add("groups")
            recognized.add("organization")
            _write_json(stage, "etc/groups/groups.json", groups, generated)

        resources = cdm.get("resources")
        if resources is not None:
            recognized.add("resources")
            _write_json(stage, "etc/budgets/resources.json", resources, generated)
            _write_json(stage, "sys/resources/resources.json", resources, generated)

        systems = _listify(cdm.get("systems"))
        if systems:
            recognized.add("systems")
            _write_json(stage, "etc/devices/systems.json", systems, generated)
            for idx, s in enumerate(systems):
                if not isinstance(s, dict):
                    continue
                sid = _safe_id(s.get("system_id") or s.get("id") or s.get("name"), f"system-{idx+1}")
                cat = _safe_id(s.get("category"), "other")
                _write_json(stage, f"dev/{cat}/{sid}.json", s, generated)

        repos = _listify(cdm.get("repositories"))
        if repos:
            recognized.add("repositories")
            _write_json(stage, "etc/mounts/repositories.json", repos, generated)
            for idx, r in enumerate(repos):
                if not isinstance(r, dict):
                    continue
                rid = _safe_id(r.get("repository_id") or r.get("id") or r.get("name"), f"repo-{idx+1}")
                _write_json(stage, f"mnt/{rid}/.mount.json", r, generated)

        apps = _listify(cdm.get("applications"))
        if apps:
            recognized.add("applications")
            for idx, a in enumerate(apps):
                if not isinstance(a, dict):
                    continue
                aid = _safe_id(a.get("application_id") or a.get("id") or a.get("name"), f"app-{idx+1}")
                _write_json(stage, f"opt/{aid}/manifest.json", a, generated)

        caps = _listify(cdm.get("capabilities"))
        if caps:
            recognized.add("capabilities")
            for idx, c in enumerate(caps):
                if not isinstance(c, dict):
                    continue
                cid = _safe_id(c.get("capability_id") or c.get("id") or c.get("name"), f"cap-{idx+1}")
                _write_json(stage, f"usr/skills/{cid}/manifest.json", c, generated)

        # Persist the entire source CDM for provenance, but never as a substitute for mappings.
        _write_json(stage, "var/archive/cdm-source.json", cdm, generated)

        operational_sections = set(cdm.keys()) - {"cdm", "manifest", "discovery", "modules", "unknowns", "conflicts", "certification"}
        unmapped = sorted(operational_sections - recognized)
        if unmapped:
            warnings.append("unmapped CDM sections preserved in source archive: " + ", ".join(unmapped))

        manifest = {
            "materializer_version": VERSION,
            "cfhs_version": cfhs_version,
            "source_cdm_id": source_id,
            "source_digest_sha256": _digest(cdm),
            "generated_files": sorted(generated),
            "unmapped_sections": unmapped,
            "warnings": warnings,
            "verification": "PASS",
        }
        _write_json(stage, ".cfhs-manifest.json", manifest, generated)

        # Atomic-ish directory activation: target must not already exist in v0.1.
        if target.exists():
            raise FileExistsError(f"target already exists: {target}")
        os.replace(stage, target)
        return manifest
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cdm")
    ap.add_argument("target")
    ap.add_argument("--cfhs-version", default="0.1")
    args = ap.parse_args()
    cdm = _load(Path(args.cdm))
    manifest = materialize(cdm, Path(args.target), args.cfhs_version)
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
