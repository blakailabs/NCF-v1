from __future__ import annotations

import secrets
from typing import Callable

from .ha_probe_harness import HAConformanceProbeHarness, HAProbeRunReport, ProbeResult
from .hardening import HardeningError
from .trust import sha256_hex


class ResilientHAConformanceProbeHarness(HAConformanceProbeHarness):
    """Canonical v0.8 probe runner.

    Individual probe failures become durable FAIL observations instead of
    aborting the entire run. Authoritative-time failure remains fatal because a
    trustworthy observation timestamp cannot then be established.
    """

    def _failed_from_exception(self, name: str, exc: Exception) -> ProbeResult:
        observed = self._now()
        observation = {
            "exception_class": type(exc).__name__,
            "error_code": exc.code if isinstance(exc, HardeningError) else None,
            "operation_failed": True,
        }
        return self._result(name, False, observed, observation, "probe operation raised")

    def _safe(self, name: str, fn: Callable[[], ProbeResult]) -> ProbeResult:
        try:
            result = fn()
        except Exception as exc:
            return self._failed_from_exception(name, exc)
        if result.name != name:
            observed = self._now()
            return self._result(
                name,
                False,
                observed,
                {
                    "returned_probe_name": result.name,
                    "expected_probe_name": name,
                },
                "probe implementation returned wrong identity",
            )
        return result

    def _probe_quorum_loss(self, prefix: str) -> ProbeResult:
        observed = self._now()
        if self.chaos is None:
            return self._blocked(
                "quorum_loss_fail_closed",
                observed,
                "independent chaos controller unavailable",
            )
        fault = self.chaos.begin_quorum_loss(self.target)
        denied = False
        error_class = None
        client = self.target.open_client("probe-quorum-loss")
        key = prefix + ":quorum-loss"
        during_fault_committed = False
        try:
            try:
                client.put_if_absent(key, {"must_not_commit": True})
                during_fault_committed = True
            except Exception as exc:
                denied = True
                error_class = type(exc).__name__
        finally:
            self.chaos.heal(fault)

        recovery_succeeded = False
        recovery_version = None
        recovery_error_class = None
        recovery_client = self.target.open_client("probe-quorum-recovery")
        try:
            recovery = recovery_client.put_if_absent(key, {"after_heal": True})
            recovery_succeeded = recovery.value == {"after_heal": True}
            recovery_version = recovery.version
        except Exception as exc:
            recovery_error_class = type(exc).__name__

        passed = denied and not during_fault_committed and recovery_succeeded
        return self._result(
            "quorum_loss_fail_closed",
            passed,
            observed,
            {
                "fault": fault.envelope(),
                "write_denied_during_quorum_loss": denied,
                "write_committed_during_quorum_loss": during_fault_committed,
                "fault_error_class": error_class,
                "write_after_heal_succeeded": recovery_succeeded,
                "write_after_heal_version": recovery_version,
                "recovery_error_class": recovery_error_class,
            },
        )

    def run(self) -> HAProbeRunReport:
        started = self._now()
        run_id = "haprobe_" + secrets.token_hex(10)
        prefix = f"/tmp/company-os-ha-probe/{run_id}"
        specs = (
            ("serializable_transaction", lambda: self._probe_serializable(prefix)),
            ("compare_and_swap", lambda: self._probe_cas(prefix)),
            ("monotonic_fencing", lambda: self._probe_fencing(prefix)),
            ("ordered_journal", lambda: self._probe_journal(prefix)),
            ("multi_connection_visibility", lambda: self._probe_visibility(prefix)),
            ("synchronous_durability", lambda: self._probe_durability(prefix)),
            ("authoritative_time", self._probe_time),
            ("quorum_loss_fail_closed", lambda: self._probe_quorum_loss(prefix)),
            ("stale_owner_rejected_after_takeover", lambda: self._probe_stale_takeover(prefix)),
            ("network_partition_single_writer", lambda: self._probe_partition(prefix)),
        )
        results = tuple(self._safe(name, fn) for name, fn in specs)
        completed = self._now()
        payload = {
            "run_id": run_id,
            "backend_id": self.target.backend_id,
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
            "results": [result.envelope() for result in results],
        }
        return HAProbeRunReport(
            run_id=run_id,
            backend_id=self.target.backend_id,
            started_at=started.isoformat(),
            completed_at=completed.isoformat(),
            results=results,
            report_digest=sha256_hex(payload),
        )
