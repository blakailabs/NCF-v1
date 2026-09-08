from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Any, Callable

from .hardening import HardeningError


GOOGLE_SPANNER_TRANSPORT_CONTRACT = "company-kernel-google-spanner-transport/v0.9.1"


@dataclass(frozen=True)
class GoogleSpannerTransportConfig:
    project_id: str
    instance_id: str
    database_id: str
    emulator_host: str | None = None

    def validate(self) -> None:
        for name, value in (("project_id", self.project_id), ("instance_id", self.instance_id), ("database_id", self.database_id)):
            if not value or any(c.isspace() for c in value):
                raise HardeningError("CFHS_SPANNER_GOOGLE_CONFIG_INVALID", f"{name} must be a non-empty identifier")
        if self.emulator_host:
            raise HardeningError("CFHS_SPANNER_EMULATOR_LIVE_DENIED", "Google transport for certification cannot target the emulator")


class GoogleSpannerTransportV091:
    """Concrete google-cloud-spanner boundary, intentionally lazy and ADC-only.

    The class imports the provider SDK only when `connect()` is called. It never
    accepts credential JSON, keys, tokens, or arbitrary credential objects. Auth
    therefore remains outside the repository and is supplied by ADC/WIF at runtime.
    """

    def __init__(self, config: GoogleSpannerTransportConfig, module_loader: Callable[[str], Any] = import_module):
        config.validate()
        self.config = config
        self._module_loader = module_loader
        self._database: Any | None = None

    @property
    def connected(self) -> bool:
        return self._database is not None

    def connect(self) -> None:
        if self.connected:
            return
        try:
            spanner = self._module_loader("google.cloud.spanner")
        except Exception as exc:
            raise HardeningError("CFHS_SPANNER_SDK_UNAVAILABLE", "google-cloud-spanner is unavailable") from exc
        client = spanner.Client(project=self.config.project_id)
        instance = client.instance(self.config.instance_id)
        self._database = instance.database(self.config.database_id)

    def _db(self) -> Any:
        if not self.connected:
            raise HardeningError("CFHS_SPANNER_TRANSPORT_NOT_CONNECTED", "Google Spanner transport is not connected")
        return self._database

    def strong_read(self, object_key: str) -> dict[str, Any]:
        db = self._db()
        with db.snapshot() as snapshot:
            rows = list(snapshot.execute_sql(
                "SELECT object_version, commit_ts FROM cfhs_shared_objects WHERE object_key=@object_key",
                params={"object_key": object_key},
                param_types={"object_key": "STRING"},
            ))
            read_timestamp = getattr(snapshot, "read_timestamp", None)
        return {
            "read_consistency": "strong",
            "observed_commit_timestamp": str(read_timestamp) if read_timestamp is not None else None,
            "row_count": len(rows),
            "object_version": rows[0][0] if rows else None,
            "object_commit_timestamp": str(rows[0][1]) if rows and rows[0][1] is not None else None,
        }

    def run_read_write(self, operation: str, request: dict[str, Any]) -> dict[str, Any]:
        db = self._db()
        if operation not in {"stale_cas_probe", "fenced_cas_journal", "acquire_fence"}:
            raise HardeningError("CFHS_SPANNER_GOOGLE_OPERATION_DENIED", f"Unsupported Google Spanner operation: {operation}")
        attempts = {"count": 0}

        def unit_of_work(txn: Any) -> dict[str, Any]:
            attempts["count"] += 1
            if operation == "stale_cas_probe":
                return self._stale_cas(txn, request)
            if operation == "acquire_fence":
                return self._acquire_fence(txn, request)
            return self._fenced_cas_journal(txn, request)

        try:
            observed = db.run_in_transaction(unit_of_work)
        except Exception as exc:
            code = getattr(exc, "code", None)
            code_name = code.name if hasattr(code, "name") else str(code or exc.__class__.__name__).upper()
            return {"committed": False, "provider_code": code_name, "attempts": max(attempts["count"], 1)}
        observed = dict(observed)
        observed.setdefault("attempts", max(attempts["count"], 1))
        observed.setdefault("provider_code", "OK")
        observed.setdefault("committed", True)
        return observed

    def _stale_cas(self, txn: Any, request: dict[str, Any]) -> dict[str, Any]:
        rows = list(txn.execute_sql(
            "SELECT object_version FROM cfhs_shared_objects WHERE object_key=@object_key",
            params={"object_key": request["object_key"]}, param_types={"object_key": "STRING"},
        ))
        current = rows[0][0] if rows else None
        stale = request["stale_expected_version"]
        return {"stale_expected_version": stale, "observed_current_version": current, "mutation_applied": False, "journal_appended": False}

    def _acquire_fence(self, txn: Any, request: dict[str, Any]) -> dict[str, Any]:
        rows = list(txn.execute_sql(
            "SELECT fence_token FROM cfhs_shared_fences WHERE fence_key=@fence_key",
            params={"fence_key": request["fence_key"]}, param_types={"fence_key": "STRING"},
        ))
        current = rows[0][0] if rows else 0
        if current != request["previous_token"]:
            raise HardeningError("CFHS_SPANNER_FENCE_COMPARE_FAILED", "Observed fence token differs from expected previous token")
        next_token = current + 1
        txn.execute_update(
            "UPDATE cfhs_shared_fences SET fence_token=@next_token, commit_ts=PENDING_COMMIT_TIMESTAMP() WHERE fence_key=@fence_key",
            params={"next_token": next_token, "fence_key": request["fence_key"]},
            param_types={"next_token": "INT64", "fence_key": "STRING"},
        )
        return {"fence_token": next_token, "commit_timestamp": "PENDING_COMMIT_TIMESTAMP"}

    def _fenced_cas_journal(self, txn: Any, request: dict[str, Any]) -> dict[str, Any]:
        # The live implementation verifies exact rows and obtains the final server
        # commit timestamp after transaction commit. Until a real database exists,
        # this method intentionally refuses to synthesize final certification evidence.
        raise HardeningError("CFHS_SPANNER_LIVE_RESULT_BINDING_REQUIRED", "Real Spanner commit result binding is required before live mutation evidence can pass")
