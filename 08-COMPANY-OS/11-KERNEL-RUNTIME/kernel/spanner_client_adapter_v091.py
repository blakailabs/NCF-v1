from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .hardening import HardeningError
from .spanner_transaction_semantics_v091 import SpannerTransactionSemanticsV091 as Semantics


SPANNER_CLIENT_ADAPTER_CONTRACT = "company-kernel-spanner-client-adapter/v0.9.1"


class SpannerTransport(Protocol):
    """Narrow transport implemented later by google-cloud-spanner.

    Repository tests inject a fake. This contract never discovers credentials.
    """
    def strong_read(self, object_key: str) -> dict[str, Any]: ...
    def run_read_write(self, operation: str, request: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class SpannerClientAdapterV091:
    transport: SpannerTransport
    network_enabled: bool = False
    mutations_enabled: bool = False

    def _require_network(self) -> None:
        if not self.network_enabled:
            raise HardeningError("CFHS_SPANNER_NETWORK_DISABLED", "Spanner network transport is disabled")

    def _require_mutations(self) -> None:
        self._require_network()
        if not self.mutations_enabled:
            raise HardeningError("CFHS_SPANNER_MUTATIONS_DISABLED", "Spanner mutation transport is disabled")

    def strong_read(self, object_key: str) -> dict[str, Any]:
        self._require_network()
        if not object_key or not object_key.startswith("/"):
            raise HardeningError("CFHS_SPANNER_OBJECT_KEY_INVALID", "Object key must be an absolute CFHS path")
        return Semantics.require_strong_read(self.transport.strong_read(object_key))

    def stale_cas_probe(self, object_key: str, stale_expected_version: int) -> dict[str, Any]:
        self._require_mutations()
        observed = self.transport.run_read_write("stale_cas_probe", {
            "object_key": object_key, "stale_expected_version": stale_expected_version,
        })
        return Semantics.require_stale_cas_rejected(observed)

    def fenced_cas_journal(self, *, object_key: str, expected_version: int, fence_token: int,
                           journal_stream: str, expected_journal_version: int,
                           payload_digest: str) -> dict[str, Any]:
        self._require_mutations()
        for name, value in (("expected_version", expected_version), ("fence_token", fence_token), ("expected_journal_version", expected_journal_version)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise HardeningError("CFHS_SPANNER_REQUEST_VERSION_INVALID", f"{name} must be a nonnegative integer")
        if not object_key.startswith("/") or not journal_stream or not payload_digest:
            raise HardeningError("CFHS_SPANNER_MUTATION_REQUEST_INVALID", "Mutation identity fields are required")
        observed = self.transport.run_read_write("fenced_cas_journal", {
            "object_key": object_key,
            "expected_version": expected_version,
            "fence_token": fence_token,
            "journal_stream": journal_stream,
            "expected_journal_version": expected_journal_version,
            "payload_digest": payload_digest,
        })
        outcome = Semantics.require_committed_fenced_cas_journal(observed)
        return {
            "contract": SPANNER_CLIENT_ADAPTER_CONTRACT,
            "commit_timestamp": outcome.commit_timestamp,
            "object_version": outcome.object_version,
            "fence_token": outcome.fence_token,
            "journal_version": outcome.journal_version,
            "attempts": outcome.attempts,
        }

    def acquire_fence(self, fence_key: str, previous_token: int) -> dict[str, Any]:
        self._require_mutations()
        observed = self.transport.run_read_write("acquire_fence", {"fence_key": fence_key, "previous_token": previous_token})
        outcome = Semantics.classify_outcome(observed)
        if not outcome.committed:
            raise HardeningError("CFHS_SPANNER_FENCE_ACQUIRE_NOT_COMMITTED", "Fence acquisition did not commit")
        next_token = Semantics.require_monotonic_fence(previous_token, outcome.fence_token)
        return {"fence_token": next_token, "commit_timestamp": outcome.commit_timestamp, "attempts": outcome.attempts}
