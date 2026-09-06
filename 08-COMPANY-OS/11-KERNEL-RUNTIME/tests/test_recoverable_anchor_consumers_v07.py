import sqlite3
import tempfile
import unittest
from pathlib import Path

from kernel.hardening import HardeningError, TamperEvidentAuditChain
from kernel.recoverable_anchor_consumers import (
    RecoverableAnchoredProviderActionAudit,
    RecoverableAnchoredProviderAuthorizationEvidenceLedger,
)


class FailOnceAnchor:
    def __init__(self):
        self.calls = []
        self.failed = False

    def anchor(self, head_hash, metadata=None):
        self.calls.append((head_hash, dict(metadata or {})))
        if not self.failed:
            self.failed = True
            raise HardeningError(
                "CFHS_AUDIT_ANCHOR_FAILED",
                "quorum unavailable",
                {"anchor_request_id": "anchorq_test_recovery", "confirmed_count": 1},
            )
        return {
            "receipt_id": "recovered:" + head_hash[:16],
            "audit_head_hash": head_hash,
            "recovered": True,
        }


class AlwaysAnchor:
    def __init__(self):
        self.calls = []

    def anchor(self, head_hash, metadata=None):
        self.calls.append((head_hash, dict(metadata or {})))
        return {"receipt_id": "ok:" + head_hash[:16], "audit_head_hash": head_hash}


class RecoverableAnchorConsumersV07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.conn = sqlite3.connect(self.root / "kernel.db")
        self.conn.row_factory = sqlite3.Row

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    @staticmethod
    def line_count(path: Path) -> int:
        if not path.exists():
            return 0
        return len([line for line in path.read_text().splitlines() if line.strip()])

    def test_provider_action_retry_reuses_original_chain_head_without_second_append(self):
        chain_path = self.root / "action-chain.jsonl"
        chain = TamperEvidentAuditChain(chain_path)
        anchor = FailOnceAnchor()
        audit = RecoverableAnchoredProviderActionAudit(self.conn, chain, anchor)
        intent = "a" * 64
        with self.assertRaises(HardeningError) as cm:
            audit.prepare(intent, "sandbox-payments", "idem-action-1", {"sandbox": True})
        self.assertEqual(cm.exception.code, "CFHS_AUDIT_ANCHOR_FAILED")
        self.assertEqual(cm.exception.details["anchor_request_id"], "anchorq_test_recovery")
        self.assertEqual(self.line_count(chain_path), 1)
        pending = audit.pending_checkpoints("PENDING")
        self.assertEqual(len(pending), 1)
        original_head = pending[0]["audit_head_hash"]

        prepared = audit.prepare(intent, "sandbox-payments", "idem-action-1", {"sandbox": True})
        self.assertEqual(self.line_count(chain_path), 1)
        self.assertEqual(prepared["anchor"]["audit_head_hash"], original_head)
        self.assertEqual(anchor.calls[0][0], anchor.calls[1][0])
        self.assertEqual(audit.pending_checkpoints("PENDING"), [])
        self.assertEqual(len(audit.receipts(prepared["audit_id"])), 1)

    def test_provider_action_pending_checkpoint_survives_consumer_recreation(self):
        chain_path = self.root / "action-restart-chain.jsonl"
        chain = TamperEvidentAuditChain(chain_path)
        failing = FailOnceAnchor()
        audit = RecoverableAnchoredProviderActionAudit(self.conn, chain, failing)
        intent = "b" * 64
        with self.assertRaises(HardeningError):
            audit.prepare(intent, "sandbox-payments", "idem-action-restart", {"sandbox": True})
        pending = audit.pending_checkpoints("PENDING")[0]
        original_head = pending["audit_head_hash"]
        self.assertEqual(self.line_count(chain_path), 1)

        recovered_anchor = AlwaysAnchor()
        recreated = RecoverableAnchoredProviderActionAudit(self.conn, chain, recovered_anchor)
        prepared = recreated.prepare(intent, "sandbox-payments", "idem-action-restart", {"sandbox": True})
        self.assertEqual(self.line_count(chain_path), 1)
        self.assertEqual(recovered_anchor.calls[0][0], original_head)
        self.assertEqual(prepared["anchor"]["audit_head_hash"], original_head)

    def test_provider_action_retry_after_success_is_fully_idempotent(self):
        chain_path = self.root / "action-idempotent-chain.jsonl"
        chain = TamperEvidentAuditChain(chain_path)
        anchor = AlwaysAnchor()
        audit = RecoverableAnchoredProviderActionAudit(self.conn, chain, anchor)
        intent = "c" * 64
        first = audit.prepare(intent, "sandbox-payments", "idem-action-ok", {"sandbox": True})
        second = audit.prepare(intent, "sandbox-payments", "idem-action-ok", {"sandbox": True})
        self.assertEqual(first["anchor"]["receipt_key"], second["anchor"]["receipt_key"])
        self.assertEqual(len(anchor.calls), 1)
        self.assertEqual(self.line_count(chain_path), 1)

    def test_authorization_retry_reuses_original_chain_head_without_second_append(self):
        chain_path = self.root / "auth-chain.jsonl"
        chain = TamperEvidentAuditChain(chain_path)
        anchor = FailOnceAnchor()
        ledger = RecoverableAnchoredProviderAuthorizationEvidenceLedger(self.conn, chain, anchor)
        intent = "d" * 64
        decision = {"decision": "ALLOW", "matched_policies": ["cap-refund"], "constraints": {}}
        with self.assertRaises(HardeningError) as cm:
            ledger.bind_and_anchor(intent, "agent:ops", "proc:ops", decision)
        self.assertEqual(cm.exception.details["anchor_request_id"], "anchorq_test_recovery")
        self.assertEqual(self.line_count(chain_path), 1)
        pending = ledger.pending_checkpoints("PENDING")[0]
        original_head = pending["audit_head_hash"]

        result = ledger.bind_and_anchor(intent, "agent:ops", "proc:ops", decision)
        self.assertEqual(self.line_count(chain_path), 1)
        self.assertEqual(result["anchor"]["audit_head_hash"], original_head)
        self.assertEqual(anchor.calls[0][0], anchor.calls[1][0])
        self.assertEqual(ledger.pending_checkpoints("PENDING"), [])

    def test_authorization_pending_checkpoint_survives_consumer_recreation(self):
        chain_path = self.root / "auth-restart-chain.jsonl"
        chain = TamperEvidentAuditChain(chain_path)
        failing = FailOnceAnchor()
        ledger = RecoverableAnchoredProviderAuthorizationEvidenceLedger(self.conn, chain, failing)
        intent = "e" * 64
        decision = {"decision": "ALLOW", "matched_policies": ["cap-refund"], "constraints": {}}
        with self.assertRaises(HardeningError):
            ledger.bind_and_anchor(intent, "agent:ops", "proc:ops", decision)
        original_head = ledger.pending_checkpoints("PENDING")[0]["audit_head_hash"]

        recovered_anchor = AlwaysAnchor()
        recreated = RecoverableAnchoredProviderAuthorizationEvidenceLedger(self.conn, chain, recovered_anchor)
        result = recreated.bind_and_anchor(intent, "agent:ops", "proc:ops", decision)
        self.assertEqual(self.line_count(chain_path), 1)
        self.assertEqual(recovered_anchor.calls[0][0], original_head)
        self.assertEqual(result["anchor"]["audit_head_hash"], original_head)

    def test_authorization_retry_after_success_does_not_reanchor_or_reappend(self):
        chain_path = self.root / "auth-idempotent-chain.jsonl"
        chain = TamperEvidentAuditChain(chain_path)
        anchor = AlwaysAnchor()
        ledger = RecoverableAnchoredProviderAuthorizationEvidenceLedger(self.conn, chain, anchor)
        intent = "f" * 64
        decision = {"decision": "ALLOW", "matched_policies": ["cap-refund"], "constraints": {}}
        first = ledger.bind_and_anchor(intent, "agent:ops", "proc:ops", decision)
        second = ledger.bind_and_anchor(intent, "agent:ops", "proc:ops", decision)
        self.assertEqual(first["anchor"]["audit_head_hash"], second["anchor"]["audit_head_hash"])
        self.assertEqual(len(anchor.calls), 1)
        self.assertEqual(self.line_count(chain_path), 1)

    def test_pending_checkpoint_failure_preserves_structured_quorum_cause(self):
        chain = TamperEvidentAuditChain(self.root / "structured-chain.jsonl")
        anchor = FailOnceAnchor()
        audit = RecoverableAnchoredProviderActionAudit(self.conn, chain, anchor)
        with self.assertRaises(HardeningError) as cm:
            audit.prepare("7" * 64, "sandbox-payments", "idem-structured", {"sandbox": True})
        self.assertEqual(cm.exception.details["cause_code"], "CFHS_AUDIT_ANCHOR_FAILED")
        self.assertEqual(cm.exception.details["anchor_request_id"], "anchorq_test_recovery")
        self.assertEqual(cm.exception.details["cause_details"]["confirmed_count"], 1)


if __name__ == "__main__":
    unittest.main()
