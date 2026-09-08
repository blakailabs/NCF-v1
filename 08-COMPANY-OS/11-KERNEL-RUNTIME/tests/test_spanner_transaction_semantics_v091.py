import unittest

from kernel.hardening import HardeningError
from kernel.spanner_transaction_semantics_v091 import SpannerTransactionSemanticsV091 as S


def atomic_observation():
    return {
        "committed": True, "provider_code": "OK", "attempts": 1,
        "commit_timestamp": "2026-09-08T20:00:00.000001Z",
        "single_read_write_transaction": True,
        "fence_asserted": True, "object_cas_applied": True, "journal_appended": True,
        "object_version": 8, "fence_token": 13, "journal_version": 21,
        "journal_object_version": 8, "journal_fence_token": 13,
        "journal_commit_timestamp": "2026-09-08T20:00:00.000001Z",
    }


class SpannerTransactionSemanticsV091Tests(unittest.TestCase):
    def test_strong_read_required(self):
        with self.assertRaises(HardeningError): S.require_strong_read({"read_consistency": "stale", "observed_commit_timestamp": "t"})

    def test_strong_read_requires_timestamp(self):
        with self.assertRaises(HardeningError): S.require_strong_read({"read_consistency": "strong"})

    def test_aborted_is_retryable(self):
        out = S.classify_outcome({"committed": False, "provider_code": "ABORTED", "attempts": 1})
        self.assertTrue(out.retryable)

    def test_non_aborted_failure_not_retryable(self):
        out = S.classify_outcome({"committed": False, "provider_code": "FAILED_PRECONDITION", "attempts": 1})
        self.assertFalse(out.retryable)

    def test_committed_requires_timestamp(self):
        with self.assertRaises(HardeningError): S.classify_outcome({"committed": True, "provider_code": "OK", "attempts": 1})

    def test_abort_cannot_claim_timestamp(self):
        with self.assertRaises(HardeningError): S.classify_outcome({"committed": False, "provider_code": "ABORTED", "attempts": 1, "commit_timestamp": "fake"})

    def test_attempts_must_be_positive_integer(self):
        with self.assertRaises(HardeningError): S.classify_outcome({"committed": False, "provider_code": "ABORTED", "attempts": 0})

    def test_atomic_fenced_cas_journal_positive(self):
        out = S.require_committed_fenced_cas_journal(atomic_observation())
        self.assertEqual((out.object_version, out.fence_token, out.journal_version), (8, 13, 21))

    def test_atomic_requires_single_transaction(self):
        o = atomic_observation(); o["single_read_write_transaction"] = False
        with self.assertRaises(HardeningError): S.require_committed_fenced_cas_journal(o)

    def test_atomic_requires_all_components(self):
        o = atomic_observation(); o["journal_appended"] = False
        with self.assertRaises(HardeningError): S.require_committed_fenced_cas_journal(o)

    def test_journal_must_bind_object_version(self):
        o = atomic_observation(); o["journal_object_version"] = 7
        with self.assertRaises(HardeningError): S.require_committed_fenced_cas_journal(o)

    def test_journal_must_bind_fence(self):
        o = atomic_observation(); o["journal_fence_token"] = 12
        with self.assertRaises(HardeningError): S.require_committed_fenced_cas_journal(o)

    def test_journal_must_bind_commit_timestamp(self):
        o = atomic_observation(); o["journal_commit_timestamp"] = "other"
        with self.assertRaises(HardeningError): S.require_committed_fenced_cas_journal(o)

    def test_fence_must_increase(self):
        self.assertEqual(S.require_monotonic_fence(13, 14), 14)
        with self.assertRaises(HardeningError): S.require_monotonic_fence(13, 13)

    def test_stale_cas_must_reject_without_journal(self):
        result = S.require_stale_cas_rejected({"stale_expected_version": 7, "mutation_applied": False, "journal_appended": False})
        self.assertFalse(result["mutation_applied"])

    def test_stale_cas_cannot_mutate(self):
        with self.assertRaises(HardeningError): S.require_stale_cas_rejected({"stale_expected_version": 7, "mutation_applied": True, "journal_appended": False})


if __name__ == "__main__": unittest.main()
