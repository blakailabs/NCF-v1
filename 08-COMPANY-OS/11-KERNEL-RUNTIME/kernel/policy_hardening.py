from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .hardening import HardeningError
from .trust import PolicyPackageSigner, canonical_json, sha256_hex


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PersistentRollbackProtectedPolicyStore:
    """Signed restrictive policies with durable active contents and rollback protection."""

    def __init__(self, conn: sqlite3.Connection, trusted_keys: dict[str, bytes]):
        self.conn = conn
        self.trusted_keys = dict(trusted_keys)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS signed_policy_packages_v04(
                package_id TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                package_digest TEXT NOT NULL,
                key_id TEXT NOT NULL,
                package_json TEXT NOT NULL,
                installed_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    @staticmethod
    def _semver(version: str) -> tuple[int, int, int]:
        parts = version.split(".")
        if len(parts) != 3 or not all(part.isdigit() for part in parts):
            raise HardeningError("CFHS_INVALID_POLICY", "Policy version must be strict numeric MAJOR.MINOR.PATCH")
        return int(parts[0]), int(parts[1]), int(parts[2])

    def _verify(self, envelope: dict[str, Any]) -> tuple[dict[str, Any], str, str]:
        package = envelope.get("package")
        signature = envelope.get("signature") or {}
        if not isinstance(package, dict):
            raise HardeningError("CFHS_INVALID_POLICY", "Signed policy package missing")
        if signature.get("algorithm") != PolicyPackageSigner.ALG:
            raise HardeningError("CFHS_INVALID_POLICY", "Unsupported reference policy signature algorithm")
        key_id = str(signature.get("key_id", ""))
        key = self.trusted_keys.get(key_id)
        if not key:
            raise HardeningError("CFHS_POLICY_DENIED", "Policy signing key is not trusted")
        expected = hmac.new(key, canonical_json(package), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(signature.get("value", "")), expected):
            raise HardeningError("CFHS_POLICY_DENIED", "Policy signature verification failed")
        package_id = str(package.get("id", "")).strip()
        version = str(package.get("version", "")).strip()
        policies = package.get("policies")
        if not package_id or not isinstance(policies, list):
            raise HardeningError("CFHS_INVALID_POLICY", "Policy package requires id and policy list")
        self._semver(version)
        for policy in policies:
            if policy.get("effect") not in {"DENY", "ELEVATION_REQUIRED"}:
                raise HardeningError("CFHS_INVALID_POLICY", "Policy packages are restrictive-only")
        return package, key_id, sha256_hex(package)

    def install_atomic(self, envelopes: list[dict[str, Any]]) -> dict[str, Any]:
        verified = [self._verify(envelope) for envelope in envelopes]
        ids = [package["id"] for package, _key, _digest in verified]
        if len(ids) != len(set(ids)):
            raise HardeningError("CFHS_CONFLICT", "Duplicate package id in one activation set")

        for package, _key_id, digest in verified:
            row = self.conn.execute(
                "SELECT version,package_digest FROM signed_policy_packages_v04 WHERE package_id=?",
                (package["id"],),
            ).fetchone()
            if not row:
                continue
            old_version = self._semver(row["version"])
            new_version = self._semver(package["version"])
            if new_version < old_version:
                raise HardeningError(
                    "CFHS_POLICY_DENIED",
                    "Signed policy rollback rejected",
                    {"package_id": package["id"], "installed": row["version"], "requested": package["version"]},
                )
            if new_version == old_version and row["package_digest"] != digest:
                raise HardeningError("CFHS_CONFLICT", "Same policy version cannot be replaced with different content")

        installed_at = now_iso()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            for package, key_id, digest in verified:
                self.conn.execute(
                    """
                    INSERT INTO signed_policy_packages_v04(package_id,version,package_digest,key_id,package_json,installed_at)
                    VALUES(?,?,?,?,?,?)
                    ON CONFLICT(package_id) DO UPDATE SET
                        version=excluded.version,
                        package_digest=excluded.package_digest,
                        key_id=excluded.key_id,
                        package_json=excluded.package_json,
                        installed_at=excluded.installed_at
                    """,
                    (
                        package["id"],
                        package["version"],
                        digest,
                        key_id,
                        json.dumps(package, sort_keys=True),
                        installed_at,
                    ),
                )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        return {"installed": sorted(ids), "package_count": len(ids), "installed_at": installed_at}

    def packages(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT package_json FROM signed_policy_packages_v04 ORDER BY package_id"
        ).fetchall()
        return [json.loads(row["package_json"]) for row in rows]

    def active_policies(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for package in self.packages():
            for policy in package["policies"]:
                item = dict(policy)
                item["package_id"] = package["id"]
                item["package_version"] = package["version"]
                output.append(item)
        return output

    def state(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT package_id,version,package_digest,key_id,installed_at FROM signed_policy_packages_v04 ORDER BY package_id"
        ).fetchall()
        return [dict(row) for row in rows]
