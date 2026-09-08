from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .hardening import HardeningError


SPANNER_TRANSACTION_SEMANTICS_CONTRACT = "company-kernel-spanner-transaction-semantics/v0.9.1"
RETRYABLE_ABORT_CODES = frozenset({"ABORTED"})


@dataclass(frozen=True)
class SpannerTransactionOutcome:
    committed: bool
    provider_code: str
    attempts: int
    commit_timestamp: str | None = None
    object_version: int | None = None
    fence_token: int | None = None
    journal_version: int | None = None

    @property
    def retryable(self) -> bool:
        return (not self.committed) and self.provider_code.upper() in RETRYABLE_ABORT_CODES


class SpannerTransactionSemanticsV091:
    """Kernel-owned validation for observations returned by a Spanner SDK adapter."""

    @staticmethod
    def require_strong_read(observation: Mapping[str, Any]) -> dict[str, Any]:
        if observation.get("read_consistency") != "strong":
            raise HardeningError("CFHS_SPANNER_STRONG_READ_REQUIRED", "Certification reads must be strong")
        if not observation.get("observed_commit_timestamp"):
            raise HardeningError("CFHS_SPANNER_READ_TIMESTAMP_REQUIRED", "Strong-read evidence requires observed commit timestamp")
        return dict(observation)

    @staticmethod
    def classify_outcome(observation: Mapping[str, Any]) -> SpannerTransactionOutcome:
        attempts = observation.get("attempts")
        if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 1:
            raise HardeningError("CFHS_SPANNER_TRANSACTION_ATTEMPTS_INVALID", "Transaction attempts must be a positive integer")
        committed = observation.get("committed")
        if not isinstance(committed, bool):
            raise HardeningError("CFHS_SPANNER_TRANSACTION_RESULT_INVALID", "Transaction committed flag must be boolean")
        code = str(observation.get("provider_code", "")).upper()
        if not code:
            raise HardeningError("CFHS_SPANNER_PROVIDER_CODE_REQUIRED", "Provider transaction code is required")
        commit_timestamp = observation.get("commit_timestamp")
        if committed and not commit_timestamp:
            raise HardeningError("CFHS_SPANNER_COMMIT_TIMESTAMP_REQUIRED", "Committed transactions require provider commit timestamp")
        if not committed and commit_timestamp:
            raise HardeningError("CFHS_SPANNER_ABORT_TIMESTAMP_FORBIDDEN", "Aborted transactions cannot claim a commit timestamp")
        return SpannerTransactionOutcome(
            committed=committed,
            provider_code=code,
            attempts=attempts,
            commit_timestamp=commit_timestamp,
            object_version=observation.get("object_version"),
            fence_token=observation.get("fence_token"),
            journal_version=observation.get("journal_version"),
        )

    @classmethod
    def require_committed_fenced_cas_journal(cls, observation: Mapping[str, Any]) -> SpannerTransactionOutcome:
        outcome = cls.classify_outcome(observation)
        if not outcome.committed:
            raise HardeningError("CFHS_SPANNER_ATOMIC_MUTATION_NOT_COMMITTED", "Atomic fenced CAS+journal mutation did not commit")
        if observation.get("single_read_write_transaction") is not True:
            raise HardeningError("CFHS_SPANNER_ATOMIC_TRANSACTION_REQUIRED", "Fence assertion, object CAS and journal append must share one read-write transaction")
        if observation.get("fence_asserted") is not True or observation.get("object_cas_applied") is not True or observation.get("journal_appended") is not True:
            raise HardeningError("CFHS_SPANNER_ATOMIC_COMPONENT_MISSING", "Committed evidence must include fence assertion, object CAS and journal append")
        for name, value in (
            ("object_version", outcome.object_version),
            ("fence_token", outcome.fence_token),
            ("journal_version", outcome.journal_version),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise HardeningError("CFHS_SPANNER_VERSION_EVIDENCE_INVALID", f"{name} must be a positive integer")
        if observation.get("journal_object_version") != outcome.object_version:
            raise HardeningError("CFHS_SPANNER_JOURNAL_OBJECT_VERSION_MISMATCH", "Journal must bind the committed object version")
        if observation.get("journal_fence_token") != outcome.fence_token:
            raise HardeningError("CFHS_SPANNER_JOURNAL_FENCE_MISMATCH", "Journal must bind the committed fence token")
        if observation.get("journal_commit_timestamp") != outcome.commit_timestamp:
            raise HardeningError("CFHS_SPANNER_JOURNAL_TIMESTAMP_MISMATCH", "Journal and object mutation must bind the same commit timestamp")
        return outcome

    @staticmethod
    def require_monotonic_fence(previous_token: int, next_token: int) -> int:
        if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in (previous_token, next_token)):
            raise HardeningError("CFHS_SPANNER_FENCE_TOKEN_INVALID", "Fence tokens must be nonnegative integers")
        if next_token <= previous_token:
            raise HardeningError("CFHS_SPANNER_FENCE_NOT_MONOTONIC", "New fence token must be strictly greater than previous token")
        return next_token

    @staticmethod
    def require_stale_cas_rejected(observation: Mapping[str, Any]) -> dict[str, Any]:
        if observation.get("stale_expected_version") is None:
            raise HardeningError("CFHS_SPANNER_STALE_CAS_EVIDENCE_INCOMPLETE", "Stale CAS evidence requires expected version")
        if observation.get("mutation_applied") is not False:
            raise HardeningError("CFHS_SPANNER_STALE_CAS_ACCEPTED", "Stale CAS must not apply a mutation")
        if observation.get("journal_appended") is not False:
            raise HardeningError("CFHS_SPANNER_STALE_CAS_JOURNALED", "Rejected stale CAS must not append a journal event")
        return dict(observation)
