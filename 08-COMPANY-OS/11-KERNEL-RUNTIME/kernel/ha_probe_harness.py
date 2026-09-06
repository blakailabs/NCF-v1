from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .ha_persistence import HAProbeEvidence, REQUIRED_PROBES
from .hardening import HardeningError
from .shared_state_backend import SharedFence
from .trust import sha256_hex


def _aware(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise HardeningError("CFHS_INVALID_EVIDENCE", f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class SerializableConflictObservation:
    initial_value: int
    transaction_a_read: int
    transaction_b_read: int
    transaction_a_result: str
    transaction_b_result: str
    final_value: int
    trace: tuple[dict[str, Any], ...]

    def envelope(self) -> dict[str, Any]:
        return {
            "initial_value": self.initial_value,
            "transaction_a_read": self.transaction_a_read,
            "transaction_b_read": self.transaction_b_read,
            "transaction_a_result": self.transaction_a_result,
            "transaction_b_result": self.transaction_b_result,
            "final_value": self.final_value,
            "trace": list(self.trace),
        }


@dataclass(frozen=True)
class DurabilityObservation:
    acknowledged: bool
    value_digest: str
    reconnect_value_digest: str | None
    failover_value_digest: str | None
    trace: tuple[dict[str, Any], ...]

    def envelope(self) -> dict[str, Any]:
        return {
            "acknowledged": self.acknowledged,
            "value_digest": self.value_digest,
            "reconnect_value_digest": self.reconnect_value_digest,
            "failover_value_digest": self.failover_value_digest,
            "trace": list(self.trace),
        }


@dataclass(frozen=True)
class FaultLease:
    fault_id: str
    fault_type: str
    started_at: str
    details: dict[str, Any]

    def envelope(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProbeResult:
    name: str
    status: str
    observed_at: str
    observation_digest: str
    observation: dict[str, Any]
    reason: str | None = None

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    def evidence(self) -> HAProbeEvidence | None:
        if self.status == "BLOCKED":
            return None
        return HAProbeEvidence(
            name=self.name,
            passed=self.passed,
            observed_at=self.observed_at,
            evidence_digest=self.observation_digest,
        )

    def envelope(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "observed_at": self.observed_at,
            "observation_digest": self.observation_digest,
            "observation": self.observation,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class HAProbeRunReport:
    run_id: str
    backend_id: str
    started_at: str
    completed_at: str
    results: tuple[ProbeResult, ...]
    report_digest: str

    def evidence(self) -> tuple[HAProbeEvidence, ...]:
        return tuple(e for result in self.results if (e := result.evidence()) is not None)

    def blocked(self) -> tuple[str, ...]:
        return tuple(result.name for result in self.results if result.status == "BLOCKED")

    def failed(self) -> tuple[str, ...]:
        return tuple(result.name for result in self.results if result.status == "FAIL")

    def complete(self) -> bool:
        names = {result.name for result in self.results if result.status != "BLOCKED"}
        return set(REQUIRED_PROBES).issubset(names) and not self.blocked()

    def envelope(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "backend_id": self.backend_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "results": [result.envelope() for result in self.results],
            "report_digest": self.report_digest,
        }


class HAProbeClient(Protocol):
    def read(self, object_key: str): ...
    def put_if_absent(self, object_key: str, value: dict[str, Any]): ...
    def compare_and_swap(self, object_key: str, expected_version: int, value: dict[str, Any]): ...
    def acquire_fence(self, resource_key: str, owner_id: str, ttl_seconds: int) -> SharedFence: ...
    def assert_fence(self, fence: SharedFence) -> None: ...
    def release_fence(self, fence: SharedFence) -> None: ...
    def append_event(self, stream_key: str, expected_version: int, event: dict[str, Any]) -> dict[str, Any]: ...
    def stream_version(self, stream_key: str) -> int: ...
    def journal(self, stream_key: str) -> list[dict[str, Any]]: ...


class HAProbeTarget(Protocol):
    @property
    def backend_id(self) -> str: ...
    def member_ids(self) -> tuple[str, ...]: ...
    def open_client(self, client_id: str, member_id: str | None = None) -> HAProbeClient: ...
    def authoritative_now(self) -> datetime: ...
    def wait_until_authoritative(self, instant: datetime) -> datetime: ...
    def run_serializable_conflict(self, probe_key: str) -> SerializableConflictObservation: ...
    def run_durability_roundtrip(self, probe_key: str, value: dict[str, Any]) -> DurabilityObservation: ...


class HAChaosController(Protocol):
    """Independent fault-control boundary.

    This interface must be implemented outside the storage client's ordinary
    success path. Production evidence must not let a backend self-assert that a
    partition or quorum loss occurred.
    """

    def begin_quorum_loss(self, target: HAProbeTarget) -> FaultLease: ...
    def begin_partition(
        self,
        target: HAProbeTarget,
        groups: tuple[tuple[str, ...], ...],
    ) -> FaultLease: ...
    def heal(self, fault: FaultLease) -> None: ...


class HAConformanceProbeHarness:
    """Generates HAProbeEvidence from observed behavior.

    Ordinary probes actively exercise independent clients. Fault probes require
    a separate chaos controller; if it is absent, those probes are BLOCKED and
    no positive HAProbeEvidence is emitted for them.
    """

    def __init__(
        self,
        target: HAProbeTarget,
        chaos: HAChaosController | None = None,
        *,
        fence_ttl_seconds: int = 1,
    ):
        if isinstance(fence_ttl_seconds, bool) or not isinstance(fence_ttl_seconds, int) or fence_ttl_seconds < 1:
            raise HardeningError("CFHS_INVALID_POLICY", "Probe fence TTL must be a positive integer")
        self.target = target
        self.chaos = chaos
        self.fence_ttl_seconds = fence_ttl_seconds

    def _now(self) -> datetime:
        return _aware(self.target.authoritative_now(), "authoritative probe time")

    @staticmethod
    def _result(name: str, passed: bool, observed_at: datetime, observation: dict[str, Any], reason: str | None = None) -> ProbeResult:
        status = "PASS" if passed else "FAIL"
        payload = {"name": name, "status": status, "observed_at": observed_at.isoformat(), "observation": observation}
        return ProbeResult(name, status, observed_at.isoformat(), sha256_hex(payload), observation, reason)

    def _blocked(self, name: str, observed_at: datetime, reason: str) -> ProbeResult:
        observation = {"blocked": True, "reason": reason}
        payload = {"name": name, "status": "BLOCKED", "observed_at": observed_at.isoformat(), "observation": observation}
        return ProbeResult(name, "BLOCKED", observed_at.isoformat(), sha256_hex(payload), observation, reason)

    def _probe_serializable(self, prefix: str) -> ProbeResult:
        observed = self._now()
        obs = self.target.run_serializable_conflict(prefix + ":serializable")
        same_snapshot = (
            obs.transaction_a_read == obs.initial_value
            and obs.transaction_b_read == obs.initial_value
        )
        results = {obs.transaction_a_result, obs.transaction_b_result}
        allowed_results = {"COMMITTED", "SERIALIZATION_FAILURE", "ABORTED"}
        committed = sum(result == "COMMITTED" for result in (obs.transaction_a_result, obs.transaction_b_result))
        # In the controlled stale-snapshot schedule, both transactions read the
        # same initial value before either commit. A serializable engine must
        # not allow both stale writes to commit successfully.
        passed = (
            same_snapshot
            and results.issubset(allowed_results)
            and committed == 1
            and obs.final_value == obs.initial_value + 1
        )
        envelope = obs.envelope()
        envelope["controlled_same_snapshot"] = same_snapshot
        envelope["stale_snapshot_commit_count"] = committed
        return self._result("serializable_transaction", passed, observed, envelope)

    def _probe_cas(self, prefix: str) -> ProbeResult:
        observed = self._now()
        a = self.target.open_client("probe-cas-a")
        b = self.target.open_client("probe-cas-b")
        key = prefix + ":cas"
        created = a.put_if_absent(key, {"value": 0})
        first = a.compare_and_swap(key, created.version, {"value": 1})
        stale_rejected = False
        stale_error = None
        try:
            b.compare_and_swap(key, created.version, {"value": 2})
        except Exception as exc:
            stale_rejected = True
            stale_error = type(exc).__name__
        final = b.read(key)
        passed = stale_rejected and final is not None and final.version == first.version and final.value == {"value": 1}
        return self._result(
            "compare_and_swap",
            passed,
            observed,
            {
                "initial_version": created.version,
                "committed_version": first.version,
                "stale_rejected": stale_rejected,
                "stale_error_class": stale_error,
                "final_version": final.version if final else None,
                "final_digest": final.value_digest if final else None,
            },
        )

    def _probe_fencing(self, prefix: str) -> ProbeResult:
        observed = self._now()
        a = self.target.open_client("probe-fence-a")
        b = self.target.open_client("probe-fence-b")
        resource = prefix + ":fence"
        first = a.acquire_fence(resource, "probe-owner-a", self.fence_ttl_seconds)
        first_expiry = datetime.fromisoformat(first.expires_at)
        if first_expiry.tzinfo is None:
            first_expiry = first_expiry.replace(tzinfo=timezone.utc)
        self.target.wait_until_authoritative(first_expiry + timedelta(microseconds=1))
        second = b.acquire_fence(resource, "probe-owner-b", self.fence_ttl_seconds)
        stale_rejected = False
        try:
            a.assert_fence(first)
        except Exception:
            stale_rejected = True
        passed = second.fence_token > first.fence_token and stale_rejected
        try:
            b.release_fence(second)
        except Exception:
            pass
        return self._result(
            "monotonic_fencing",
            passed,
            observed,
            {
                "first_token": first.fence_token,
                "second_token": second.fence_token,
                "stale_owner_rejected": stale_rejected,
            },
        )

    def _probe_journal(self, prefix: str) -> ProbeResult:
        observed = self._now()
        a = self.target.open_client("probe-journal-a")
        b = self.target.open_client("probe-journal-b")
        stream = prefix + ":journal"
        one = a.append_event(stream, 0, {"step": 1})
        two = b.append_event(stream, 1, {"step": 2})
        stale_rejected = False
        try:
            a.append_event(stream, 1, {"step": "stale"})
        except Exception:
            stale_rejected = True
        journal = b.journal(stream)
        versions = [int(item["version"]) for item in journal]
        passed = one["version"] == 1 and two["version"] == 2 and versions == [1, 2] and stale_rejected
        return self._result(
            "ordered_journal",
            passed,
            observed,
            {"versions": versions, "stale_append_rejected": stale_rejected},
        )

    def _probe_visibility(self, prefix: str) -> ProbeResult:
        observed = self._now()
        a = self.target.open_client("probe-visibility-a")
        b = self.target.open_client("probe-visibility-b")
        key = prefix + ":visibility"
        value = {"nonce": secrets.token_hex(8)}
        created = a.put_if_absent(key, value)
        seen = b.read(key)
        passed = seen is not None and seen.version == created.version and seen.value_digest == created.value_digest and seen.value == value
        return self._result(
            "multi_connection_visibility",
            passed,
            observed,
            {
                "writer_version": created.version,
                "reader_version": seen.version if seen else None,
                "writer_digest": created.value_digest,
                "reader_digest": seen.value_digest if seen else None,
            },
        )

    def _probe_durability(self, prefix: str) -> ProbeResult:
        observed = self._now()
        value = {"nonce": secrets.token_hex(12), "kind": "durability-probe"}
        obs = self.target.run_durability_roundtrip(prefix + ":durability", value)
        expected = sha256_hex(value)
        passed = (
            obs.acknowledged
            and obs.value_digest == expected
            and obs.reconnect_value_digest == expected
            and obs.failover_value_digest == expected
        )
        envelope = obs.envelope()
        envelope["expected_value_digest"] = expected
        return self._result("synchronous_durability", passed, observed, envelope)

    def _probe_time(self) -> ProbeResult:
        first = self._now()
        second = self._now()
        passed = second >= first
        return self._result(
            "authoritative_time",
            passed,
            second,
            {
                "first": first.isoformat(),
                "second": second.isoformat(),
                "nondecreasing": passed,
            },
        )

    def _probe_stale_takeover(self, prefix: str) -> ProbeResult:
        observed = self._now()
        a = self.target.open_client("probe-takeover-a")
        b = self.target.open_client("probe-takeover-b")
        resource = prefix + ":takeover"
        first = a.acquire_fence(resource, "takeover-owner-a", self.fence_ttl_seconds)
        expiry = datetime.fromisoformat(first.expires_at)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        self.target.wait_until_authoritative(expiry + timedelta(microseconds=1))
        second = b.acquire_fence(resource, "takeover-owner-b", self.fence_ttl_seconds)
        stale_rejected = False
        try:
            a.assert_fence(first)
        except Exception:
            stale_rejected = True
        passed = stale_rejected and second.fence_token > first.fence_token
        try:
            b.release_fence(second)
        except Exception:
            pass
        return self._result(
            "stale_owner_rejected_after_takeover",
            passed,
            observed,
            {
                "old_token": first.fence_token,
                "new_token": second.fence_token,
                "stale_owner_rejected": stale_rejected,
            },
        )

    def _probe_quorum_loss(self, prefix: str) -> ProbeResult:
        observed = self._now()
        if self.chaos is None:
            return self._blocked("quorum_loss_fail_closed", observed, "independent chaos controller unavailable")
        fault = self.chaos.begin_quorum_loss(self.target)
        denied = False
        error_class = None
        client = self.target.open_client("probe-quorum-loss")
        key = prefix + ":quorum-loss"
        try:
            try:
                client.put_if_absent(key, {"must_not_commit": True})
            except Exception as exc:
                denied = True
                error_class = type(exc).__name__
        finally:
            self.chaos.heal(fault)
        recovery_client = self.target.open_client("probe-quorum-recovery")
        recovery = recovery_client.put_if_absent(key, {"after_heal": True})
        passed = denied and recovery.value == {"after_heal": True}
        return self._result(
            "quorum_loss_fail_closed",
            passed,
            observed,
            {
                "fault": fault.envelope(),
                "write_denied_during_quorum_loss": denied,
                "error_class": error_class,
                "write_after_heal_version": recovery.version,
            },
        )

    def _probe_partition(self, prefix: str) -> ProbeResult:
        observed = self._now()
        members = self.target.member_ids()
        if self.chaos is None:
            return self._blocked("network_partition_single_writer", observed, "independent chaos controller unavailable")
        if len(members) < 3:
            return self._blocked("network_partition_single_writer", observed, "at least three members are required for partition probe")
        majority = tuple(members[: len(members) // 2 + 1])
        minority = tuple(member for member in members if member not in majority)
        if not minority:
            return self._blocked("network_partition_single_writer", observed, "partition did not produce a minority group")

        setup = self.target.open_client("probe-partition-setup", majority[0])
        key = prefix + ":partition"
        created = setup.put_if_absent(key, {"value": 0})
        fault = self.chaos.begin_partition(self.target, (majority, minority))
        outcomes: dict[str, str] = {}
        try:
            for label, member, value in (
                ("majority", majority[0], 1),
                ("minority", minority[0], 2),
            ):
                client = self.target.open_client(f"probe-partition-{label}", member)
                try:
                    client.compare_and_swap(key, created.version, {"value": value})
                    outcomes[label] = "COMMITTED"
                except Exception:
                    outcomes[label] = "REJECTED"
        finally:
            self.chaos.heal(fault)
        final = self.target.open_client("probe-partition-final").read(key)
        committed = [label for label, outcome in outcomes.items() if outcome == "COMMITTED"]
        passed = committed == ["majority"] and final is not None and final.value == {"value": 1}
        return self._result(
            "network_partition_single_writer",
            passed,
            observed,
            {
                "fault": fault.envelope(),
                "majority_members": list(majority),
                "minority_members": list(minority),
                "outcomes": outcomes,
                "final_value": final.value if final else None,
            },
        )

    def run(self) -> HAProbeRunReport:
        started = self._now()
        run_id = "haprobe_" + secrets.token_hex(10)
        prefix = f"/tmp/company-os-ha-probe/{run_id}"
        results = (
            self._probe_serializable(prefix),
            self._probe_cas(prefix),
            self._probe_fencing(prefix),
            self._probe_journal(prefix),
            self._probe_visibility(prefix),
            self._probe_durability(prefix),
            self._probe_time(),
            self._probe_quorum_loss(prefix),
            self._probe_stale_takeover(prefix),
            self._probe_partition(prefix),
        )
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
