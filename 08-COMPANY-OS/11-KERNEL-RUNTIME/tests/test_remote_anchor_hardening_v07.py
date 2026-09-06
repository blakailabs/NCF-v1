import sqlite3
import tempfile
import unittest
from pathlib import Path

from kernel.anchored_provider_audit import AnchoredProviderActionAudit
from kernel.anchored_provider_authorization import AnchoredProviderAuthorizationEvidenceLedger
from kernel.hardening import HardeningError, TamperEvidentAuditChain
from kernel.remote_anchor_endpoint_strict import StrictSQLiteSignedAnchorEndpoint
from kernel.remote_anchor_hardening import (
    AnchorEndpointBinding,
    AnchorRequestAuthenticator,
    QuorumAuditAnchorProvider,
    SignedAnchorReceiptVerifier,
)
from kernel.trust import sha256_hex


class RemoteAnchorHardeningV07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.conn = sqlite3.connect(self.root / "anchor.db")
        self.conn.row_factory = sqlite3.Row
        self.request_key = b"reference-request-key-v07"
        self.request_auth = AnchorRequestAuthenticator("request-key-v1", self.request_key)
        self.receipt_keys = {
            "anchor-a": b"reference-anchor-a-key-v07",
            "anchor-b": b"reference-anchor-b-key-v07",
            "anchor-c": b"reference-anchor-c-key-v07",
        }

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def endpoint(self, endpoint_id, verifier_key=None):
        key = self.receipt_keys[endpoint_id]
        provider = StrictSQLiteSignedAnchorEndpoint(
            self.conn,
            endpoint_id,
            f"{endpoint_id}-receipt-key-v1",
            key,
            {"request-key-v1": self.request_key},
        )
        verifier = SignedAnchorReceiptVerifier(
            endpoint_id,
            {f"{endpoint_id}-receipt-key-v1": key if verifier_key is None else verifier_key},
        )
        return provider, AnchorEndpointBinding(endpoint_id, provider, verifier)

    def quorum(self, required=2, verifier_overrides=None):
        providers = {}
        bindings = []
        for endpoint_id in ("anchor-a", "anchor-b", "anchor-c"):
            provider, binding = self.endpoint(
                endpoint_id,
                (verifier_overrides or {}).get(endpoint_id),
            )
            providers[endpoint_id] = provider
            bindings.append(binding)
        return QuorumAuditAnchorProvider(self.conn, bindings, required, self.request_auth), providers

    def signed_metadata(self, head_hash, metadata):
        metadata_digest = sha256_hex(metadata)
        request_digest = sha256_hex(
            {
                "contract": "audit-anchor-quorum/v0.7",
                "audit_head_hash": head_hash,
                "metadata_digest": metadata_digest,
            }
        )
        request_id = "anchorq_" + request_digest[:32]
        return {
            **metadata,
            "anchor_request_id": request_id,
            "anchor_request_digest": request_digest,
            "anchor_request_auth": self.request_auth.sign(request_id, request_digest),
        }

    def test_strict_endpoint_rejects_tampered_metadata_even_with_valid_digest_signature(self):
        provider, _binding = self.endpoint("anchor-a")
        head = "a" * 64
        signed = self.signed_metadata(head, {"kind": "authorization", "intent": "one"})
        signed["intent"] = "tampered"
        with self.assertRaises(HardeningError) as cm:
            provider.anchor(head, signed)
        self.assertEqual(cm.exception.code, "CFHS_AUDIT_ANCHOR_FAILED")

    def test_reference_endpoint_rejects_missing_request_authentication(self):
        provider, _binding = self.endpoint("anchor-a")
        head = "b" * 64
        metadata = self.signed_metadata(head, {"kind": "audit"})
        metadata.pop("anchor_request_auth")
        with self.assertRaises(HardeningError) as cm:
            provider.anchor(head, metadata)
        self.assertEqual(cm.exception.code, "CFHS_AUDIT_ANCHOR_FAILED")

    def test_two_of_three_quorum_succeeds_when_one_endpoint_is_unavailable(self):
        quorum, providers = self.quorum(2)
        providers["anchor-c"].mode = "unavailable"
        receipt = quorum.anchor("c" * 64, {"kind": "provider_action", "event": "prepare"})
        self.assertTrue(receipt["quorum_confirmed"])
        self.assertEqual(receipt["confirmed_count"], 2)
        self.assertEqual(receipt["confirmed_endpoint_ids"], ["anchor-a", "anchor-b"])

    def test_insufficient_quorum_fails_closed_but_retains_verified_partial_receipt(self):
        quorum, providers = self.quorum(2)
        providers["anchor-b"].mode = "unavailable"
        providers["anchor-c"].mode = "unavailable"
        with self.assertRaises(HardeningError) as cm:
            quorum.anchor("d" * 64, {"kind": "provider_action", "event": "prepare"})
        self.assertEqual(cm.exception.code, "CFHS_AUDIT_ANCHOR_FAILED")
        request_id = cm.exception.details["anchor_request_id"]
        state = quorum.request_status(request_id)
        self.assertEqual(state["status"], "PARTIAL")
        self.assertEqual(state["aggregate"]["confirmed_count"], 1)
        self.assertEqual(state["receipts"][0]["endpoint_id"], "anchor-a")

    def test_reconciliation_reaches_quorum_after_missing_endpoint_recovers(self):
        quorum, providers = self.quorum(2)
        providers["anchor-b"].mode = "unavailable"
        providers["anchor-c"].mode = "unavailable"
        with self.assertRaises(HardeningError) as cm:
            quorum.anchor("e" * 64, {"kind": "authorization", "intent": "refund-1"})
        request_id = cm.exception.details["anchor_request_id"]
        providers["anchor-b"].mode = "success"
        reconciled = quorum.reconcile(request_id)
        self.assertTrue(reconciled["quorum_confirmed"])
        self.assertEqual(reconciled["confirmed_endpoint_ids"], ["anchor-a", "anchor-b"])
        self.assertEqual(len(quorum.request_status(request_id)["receipts"]), 2)

    def test_repeating_same_semantic_anchor_request_is_idempotent(self):
        quorum, providers = self.quorum(2)
        providers["anchor-c"].mode = "unavailable"
        first = quorum.anchor("f" * 64, {"kind": "authorization", "intent": "refund-2"})
        providers["anchor-a"].mode = "unavailable"
        providers["anchor-b"].mode = "unavailable"
        second = quorum.anchor("f" * 64, {"kind": "authorization", "intent": "refund-2"})
        self.assertEqual(first["anchor_request_id"], second["anchor_request_id"])
        self.assertEqual(first["receipt_set_digest"], second["receipt_set_digest"])
        self.assertEqual(len(quorum.request_status(first["anchor_request_id"])["receipts"]), 2)

    def test_same_head_with_different_metadata_creates_different_request_identity(self):
        quorum, providers = self.quorum(2)
        providers["anchor-c"].mode = "unavailable"
        one = quorum.anchor("1" * 64, {"kind": "authorization", "intent": "one"})
        two = quorum.anchor("1" * 64, {"kind": "authorization", "intent": "two"})
        self.assertNotEqual(one["anchor_request_id"], two["anchor_request_id"])
        self.assertNotEqual(one["anchor_request_digest"], two["anchor_request_digest"])

    def test_bad_signature_receipt_is_not_counted_toward_quorum(self):
        quorum, providers = self.quorum(2)
        providers["anchor-b"].mode = "bad_signature"
        providers["anchor-c"].mode = "unavailable"
        with self.assertRaises(HardeningError) as cm:
            quorum.anchor("2" * 64, {"kind": "audit", "event": "commit"})
        self.assertEqual(cm.exception.details["confirmed_count"], 1)
        self.assertEqual(cm.exception.details["confirmed_endpoint_ids"], ["anchor-a"])

    def test_wrong_head_receipt_is_not_counted_toward_quorum(self):
        quorum, providers = self.quorum(2)
        providers["anchor-b"].mode = "wrong_head"
        providers["anchor-c"].mode = "unavailable"
        with self.assertRaises(HardeningError) as cm:
            quorum.anchor("3" * 64, {"kind": "audit", "event": "commit"})
        self.assertEqual(cm.exception.details["confirmed_count"], 1)

    def test_untrusted_endpoint_receipt_key_is_not_counted(self):
        quorum, providers = self.quorum(2, {"anchor-b": b"wrong-verifier-key"})
        providers["anchor-c"].mode = "unavailable"
        with self.assertRaises(HardeningError) as cm:
            quorum.anchor("4" * 64, {"kind": "audit", "event": "commit"})
        self.assertEqual(cm.exception.details["confirmed_count"], 1)

    def test_quorum_policy_rejects_duplicate_endpoint_ids(self):
        provider, binding = self.endpoint("anchor-a")
        duplicate = AnchorEndpointBinding("anchor-a", provider, binding.verifier)
        with self.assertRaises(HardeningError) as cm:
            QuorumAuditAnchorProvider(self.conn, [binding, duplicate], 1, self.request_auth)
        self.assertEqual(cm.exception.code, "CFHS_INVALID_POLICY")

    def test_existing_authorization_ledger_accepts_quorum_anchor_provider(self):
        quorum, providers = self.quorum(2)
        providers["anchor-c"].mode = "unavailable"
        chain = TamperEvidentAuditChain(self.root / "authorization-chain.jsonl")
        ledger = AnchoredProviderAuthorizationEvidenceLedger(self.conn, chain, quorum)
        result = ledger.bind_and_anchor(
            "5" * 64,
            "agent:ops",
            "proc:ops",
            {"decision": "ALLOW", "matched_policies": ["cap-refund"], "constraints": {}},
        )
        aggregate = result["anchor"]["anchor_receipt"]
        self.assertTrue(aggregate["quorum_confirmed"])
        self.assertEqual(aggregate["confirmed_count"], 2)
        self.assertEqual(aggregate["audit_head_hash"], result["anchor"]["audit_head_hash"])

    def test_existing_provider_action_audit_accepts_quorum_anchor_provider(self):
        quorum, providers = self.quorum(2)
        providers["anchor-c"].mode = "unavailable"
        chain = TamperEvidentAuditChain(self.root / "provider-chain.jsonl")
        audit = AnchoredProviderActionAudit(self.conn, chain, quorum)
        prepared = audit.prepare(
            "6" * 64,
            "sandbox-payments",
            "provider-idempotency-key",
            {"sandbox": True},
        )
        aggregate = prepared["anchor"]["anchor_receipt"]
        self.assertTrue(aggregate["quorum_confirmed"])
        self.assertEqual(aggregate["confirmed_count"], 2)
        committed = audit.set_status(prepared["audit_id"], "COMMITTED", "provider-action-1", {"ok": True})
        self.assertTrue(committed["anchor"]["anchor_receipt"]["quorum_confirmed"])


if __name__ == "__main__":
    unittest.main()
