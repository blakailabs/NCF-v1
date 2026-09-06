import sqlite3
import tempfile
import unittest
from pathlib import Path

from kernel.action_safety import MultiPartyApprovalLedger
from kernel.anchored_provider_audit import AnchoredProviderActionAudit
from kernel.approval_provenance import (
    ApprovalProvenanceLedger,
    ApprovalSessionResolver,
    SessionIdentityProvenanceLedger,
)
from kernel.hardening import HardeningError, SessionManager, TamperEvidentAuditChain
from kernel.trust import FileAuditAnchorProvider


class RejectingAnchor:
    def anchor(self, head_hash, metadata=None):
        raise RuntimeError("anchor unavailable")


class LyingAnchor:
    def anchor(self, head_hash, metadata=None):
        return {"receipt_id": "bad", "audit_head_hash": "wrong"}


class V06TrustBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "v06-trust.db"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.sessions = SessionManager(self.conn)
        self.identity = SessionIdentityProvenanceLedger(self.conn)
        self.resolver = ApprovalSessionResolver(self.conn, self.identity)
        self.approval_provenance = ApprovalProvenanceLedger(self.conn)
        self.approvals = MultiPartyApprovalLedger(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_approval_provenance_requires_live_matching_session(self):
        session = self.sessions.issue("human:risk", 3600)
        evidence = self.resolver.resolve(session["bearer_token"], "human:risk")
        self.assertEqual(evidence.session_id, session["session_id"])
        self.assertEqual(evidence.authentication_class, "kernel_session")
        with self.assertRaises(HardeningError):
            self.resolver.resolve(session["bearer_token"], "human:finance")

    def test_revoked_session_cannot_supply_approval_evidence(self):
        session = self.sessions.issue("human:risk", 3600)
        self.sessions.revoke(session["session_id"])
        with self.assertRaises(HardeningError) as cm:
            self.resolver.resolve(session["bearer_token"], "human:risk")
        self.assertEqual(cm.exception.code, "CFHS_UNAUTHENTICATED")

    def test_expired_session_cannot_supply_approval_evidence(self):
        session = self.sessions.issue("human:risk", 3600)
        self.conn.execute(
            "UPDATE kernel_sessions SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?",
            (session["session_id"],),
        )
        self.conn.commit()
        with self.assertRaises(HardeningError):
            self.resolver.resolve(session["bearer_token"], "human:risk")

    def test_verified_external_identity_is_bound_without_storing_token(self):
        session = self.sessions.issue("human:risk", 3600)
        bound = self.identity.bind_verified_identity(
            session["session_id"],
            "human:risk",
            "oidc:workforce",
            "https://id.example.test",
            "subject-123",
            {"amr": ["pwd", "mfa"], "acr": "urn:mfa"},
        )
        evidence = self.resolver.resolve(session["bearer_token"], "human:risk")
        self.assertEqual(evidence.authentication_class, "verified_external_identity")
        self.assertEqual(evidence.external_provider_id, "oidc:workforce")
        self.assertEqual(evidence.external_identity_digest, bound["evidence_digest"])

    def test_external_identity_provenance_is_immutable_per_session(self):
        session = self.sessions.issue("human:risk", 3600)
        self.identity.bind_verified_identity(
            session["session_id"], "human:risk", "oidc:workforce", "https://id.example.test", "subject-123"
        )
        with self.assertRaises(HardeningError):
            self.identity.bind_verified_identity(
                session["session_id"], "human:risk", "oidc:other", "https://other.example.test", "subject-999"
            )

    def test_every_counted_approval_requires_session_provenance(self):
        request = self.approvals.create(
            "intent-digest",
            "agent:ops",
            2,
            900,
            ["human:risk", "human:finance"],
        )
        risk_session = self.sessions.issue("human:risk", 3600)
        finance_session = self.sessions.issue("human:finance", 3600)
        self.approvals.approve(request["request_id"], "human:risk")
        self.approval_provenance.record(
            request["request_id"],
            "human:risk",
            self.resolver.resolve(risk_session["bearer_token"], "human:risk"),
        )
        self.approvals.approve(request["request_id"], "human:finance")
        with self.assertRaises(HardeningError) as cm:
            self.approval_provenance.require_complete(request["request_id"])
        self.assertEqual(cm.exception.code, "CFHS_ELEVATION_REQUIRED")

        self.approval_provenance.record(
            request["request_id"],
            "human:finance",
            self.resolver.resolve(finance_session["bearer_token"], "human:finance"),
        )
        complete = self.approval_provenance.require_complete(request["request_id"])
        self.assertEqual(complete["approval_count"], 2)
        self.assertEqual(complete["provenance_count"], 2)
        self.assertTrue(complete["provenance_digest"])

    def test_approval_provenance_cannot_be_replaced_by_other_session(self):
        request = self.approvals.create("intent-digest-2", "agent:ops", 1, 900, ["human:risk"])
        first = self.sessions.issue("human:risk", 3600)
        second = self.sessions.issue("human:risk", 3600)
        self.approvals.approve(request["request_id"], "human:risk")
        self.approval_provenance.record(
            request["request_id"], "human:risk", self.resolver.resolve(first["bearer_token"], "human:risk")
        )
        with self.assertRaises(HardeningError):
            self.approval_provenance.record(
                request["request_id"], "human:risk", self.resolver.resolve(second["bearer_token"], "human:risk")
            )

    def test_provider_prepare_and_commit_are_chained_and_anchored(self):
        chain = TamperEvidentAuditChain(Path(self.tmp.name) / "audit.jsonl")
        anchors = FileAuditAnchorProvider(Path(self.tmp.name) / "anchors.jsonl")
        audit = AnchoredProviderActionAudit(self.conn, chain, anchors)
        prepared = audit.prepare(
            "abc1234567890defabc1234567890def",
            "sandbox-payments",
            "idem-1",
            {"actor_id": "agent:ops", "operation": "payments.refund"},
        )
        self.assertEqual(prepared["status"], "PREPARED")
        committed = audit.set_status(prepared["audit_id"], "COMMITTED", "provider-action-1", {"ok": True})
        self.assertEqual(committed["status"], "COMMITTED")
        self.assertTrue(chain.verify()["valid"])
        self.assertTrue(anchors.verify()["valid"])
        receipts = audit.receipts(prepared["audit_id"])
        self.assertEqual(len(receipts), 2)
        self.assertEqual([r["transition_status"] for r in receipts], ["PREPARED", "COMMITTED"])

    def test_repeated_prepare_does_not_duplicate_anchor_receipt(self):
        chain = TamperEvidentAuditChain(Path(self.tmp.name) / "audit-repeat.jsonl")
        anchors = FileAuditAnchorProvider(Path(self.tmp.name) / "anchors-repeat.jsonl")
        audit = AnchoredProviderActionAudit(self.conn, chain, anchors)
        first = audit.prepare("f" * 64, "sandbox-payments", "idem-repeat", {"operation": "payments.refund"})
        second = audit.prepare("f" * 64, "sandbox-payments", "idem-repeat", {"operation": "payments.refund"})
        self.assertEqual(first["audit_id"], second["audit_id"])
        self.assertEqual(len(audit.receipts(first["audit_id"])), 1)
        self.assertEqual(chain.verify()["count"], 1)
        self.assertEqual(anchors.verify()["count"], 1)

    def test_prepare_fails_closed_when_anchor_unavailable(self):
        chain = TamperEvidentAuditChain(Path(self.tmp.name) / "audit-reject.jsonl")
        audit = AnchoredProviderActionAudit(self.conn, chain, RejectingAnchor())
        with self.assertRaises(HardeningError) as cm:
            audit.prepare("e" * 64, "sandbox-payments", "idem-reject", {"operation": "payments.refund"})
        self.assertEqual(cm.exception.code, "CFHS_AUDIT_ANCHOR_FAILED")
        self.assertEqual(chain.verify()["count"], 1)

    def test_anchor_receipt_must_confirm_exact_chain_head(self):
        chain = TamperEvidentAuditChain(Path(self.tmp.name) / "audit-lie.jsonl")
        audit = AnchoredProviderActionAudit(self.conn, chain, LyingAnchor())
        with self.assertRaises(HardeningError) as cm:
            audit.prepare("d" * 64, "sandbox-payments", "idem-lie", {"operation": "payments.refund"})
        self.assertEqual(cm.exception.code, "CFHS_AUDIT_ANCHOR_FAILED")


if __name__ == "__main__":
    unittest.main()
