import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kernel.distributed_safety import (
    BusinessIdentityContract,
    BusinessIdentityLedger,
    DistributedActionGuard,
    ProviderFenceGuard,
    SQLiteFenceStore,
)
from kernel.hardening import HardeningError


class DistributedSafetyV07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = sqlite3.connect(Path(self.tmp.name) / "v07.db")
        self.conn.row_factory = sqlite3.Row
        self.identities = BusinessIdentityLedger(self.conn)
        self.fences = SQLiteFenceStore(self.conn)
        self.provider_fences = ProviderFenceGuard(self.conn)
        self.guard = DistributedActionGuard(self.identities, self.fences)
        self.contract = BusinessIdentityContract(
            "payments.refund.target",
            1,
            "payments.refund",
            ("provider_account_id", "charge_id", "refund_reference"),
        )
        self.args = {
            "provider_account_id": "acct-test",
            "charge_id": "charge-123",
            "refund_reference": "case-456",
            "amount": "10.00",
        }
        self.t0 = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_identity_same_values_same_digest(self):
        a = self.contract.derive(dict(self.args))
        b = self.contract.derive(dict(reversed(list(self.args.items()))))
        self.assertEqual(a.identity_digest, b.identity_digest)
        self.assertEqual(a.component_digest, b.component_digest)

    def test_identity_changes_when_identity_component_changes(self):
        a = self.contract.derive(self.args)
        changed = dict(self.args)
        changed["charge_id"] = "charge-999"
        b = self.contract.derive(changed)
        self.assertNotEqual(a.identity_digest, b.identity_digest)

    def test_non_identity_argument_does_not_change_business_identity(self):
        a = self.contract.derive(self.args)
        changed = dict(self.args)
        changed["amount"] = "999.00"
        b = self.contract.derive(changed)
        self.assertEqual(a.identity_digest, b.identity_digest)

    def test_contract_version_changes_business_identity(self):
        a = self.contract.derive(self.args)
        v2 = BusinessIdentityContract(self.contract.contract_id, 2, self.contract.operation, self.contract.fields)
        self.assertNotEqual(a.identity_digest, v2.derive(self.args).identity_digest)

    def test_operation_changes_business_identity(self):
        a = self.contract.derive(self.args)
        other = BusinessIdentityContract(self.contract.contract_id, 1, "payments.capture", self.contract.fields)
        self.assertNotEqual(a.identity_digest, other.derive(self.args).identity_digest)

    def test_missing_identity_field_is_rejected(self):
        bad = dict(self.args)
        bad.pop("charge_id")
        with self.assertRaises(HardeningError) as cm:
            self.contract.derive(bad)
        self.assertEqual(cm.exception.code, "CFHS_INVALID_REQUEST")

    def test_null_identity_field_is_rejected(self):
        bad = dict(self.args)
        bad["charge_id"] = None
        with self.assertRaises(HardeningError):
            self.contract.derive(bad)

    def test_nonfinite_identity_number_is_rejected(self):
        contract = BusinessIdentityContract("numeric", 1, "inventory.reserve", ("sku", "batch"))
        with self.assertRaises(HardeningError):
            contract.derive({"sku": "sku-1", "batch": float("inf")})

    def test_dotted_identity_path_is_supported(self):
        contract = BusinessIdentityContract(
            "crm.contact.version",
            1,
            "crm.contact.update",
            ("contact.id", "contact.version"),
        )
        result = contract.derive({"contact": {"id": "c-1", "version": 7}, "name": "Example"})
        self.assertTrue(result.identity_digest)
        self.assertEqual(result.operation, "crm.contact.update")

    def test_duplicate_contract_fields_are_rejected(self):
        contract = BusinessIdentityContract("bad", 1, "x", ("id", "id"))
        with self.assertRaises(HardeningError) as cm:
            contract.derive({"id": "1"})
        self.assertEqual(cm.exception.code, "CFHS_INVALID_POLICY")

    def test_same_identity_same_semantic_bind_is_idempotent(self):
        identity = self.contract.derive(self.args)
        first = self.identities.bind(identity, "sandbox-payments", "intent-a")
        second = self.identities.bind(identity, "sandbox-payments", "intent-a")
        self.assertEqual(first["identity_digest"], second["identity_digest"])
        self.assertEqual(second["status"], "BOUND")

    def test_same_business_identity_cannot_bind_different_semantic_intent(self):
        identity = self.contract.derive(self.args)
        self.identities.bind(identity, "sandbox-payments", "intent-a")
        with self.assertRaises(HardeningError) as cm:
            self.identities.bind(identity, "sandbox-payments", "intent-b")
        self.assertEqual(cm.exception.code, "CFHS_BUSINESS_IDENTITY_CONFLICT")

    def test_same_semantic_intent_cannot_bind_different_business_identity(self):
        first = self.contract.derive(self.args)
        changed = dict(self.args)
        changed["refund_reference"] = "case-other"
        second = self.contract.derive(changed)
        self.identities.bind(first, "sandbox-payments", "intent-a")
        with self.assertRaises(HardeningError) as cm:
            self.identities.bind(second, "sandbox-payments", "intent-a")
        self.assertEqual(cm.exception.code, "CFHS_BUSINESS_IDENTITY_CONFLICT")

    def test_business_identity_valid_state_transition(self):
        identity = self.contract.derive(self.args)
        self.identities.bind(identity, "sandbox-payments", "intent-a")
        running = self.identities.transition(identity.identity_digest, "intent-a", "EXECUTING")
        committed = self.identities.transition(identity.identity_digest, "intent-a", "COMMITTED")
        self.assertEqual(running["status"], "EXECUTING")
        self.assertEqual(committed["status"], "COMMITTED")

    def test_business_identity_invalid_state_transition_fails_closed(self):
        identity = self.contract.derive(self.args)
        self.identities.bind(identity, "sandbox-payments", "intent-a")
        with self.assertRaises(HardeningError) as cm:
            self.identities.transition(identity.identity_digest, "intent-a", "COMMITTED")
        self.assertEqual(cm.exception.code, "CFHS_CONFLICT")

    def test_raw_business_identity_values_are_not_persisted(self):
        identity = self.contract.derive(self.args)
        self.identities.bind(identity, "sandbox-payments", "intent-a")
        row = dict(self.conn.execute("SELECT * FROM business_identity_bindings_v07").fetchone())
        serialized = json.dumps(row, sort_keys=True)
        self.assertNotIn("charge-123", serialized)
        self.assertNotIn("case-456", serialized)
        self.assertNotIn("acct-test", serialized)

    def test_first_fence_token_is_one(self):
        lease = self.fences.acquire("resource:x", "kernel:a", 30, self.t0)
        self.assertEqual(lease.fence_token, 1)

    def test_active_fence_blocks_competing_owner(self):
        self.fences.acquire("resource:x", "kernel:a", 30, self.t0)
        with self.assertRaises(HardeningError) as cm:
            self.fences.acquire("resource:x", "kernel:b", 30, self.t0 + timedelta(seconds=1))
        self.assertEqual(cm.exception.code, "CFHS_FENCE_BUSY")

    def test_fence_renewal_keeps_same_token_and_lease(self):
        lease = self.fences.acquire("resource:x", "kernel:a", 30, self.t0)
        renewed = self.fences.renew(lease, 60, self.t0 + timedelta(seconds=10))
        self.assertEqual(renewed.fence_token, lease.fence_token)
        self.assertEqual(renewed.lease_id, lease.lease_id)
        self.assertGreater(renewed.expires_at, lease.expires_at)

    def test_expired_fence_cannot_be_renewed(self):
        lease = self.fences.acquire("resource:x", "kernel:a", 10, self.t0)
        with self.assertRaises(HardeningError) as cm:
            self.fences.renew(lease, 30, self.t0 + timedelta(seconds=11))
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")

    def test_takeover_after_expiry_increments_fence_token(self):
        first = self.fences.acquire("resource:x", "kernel:a", 10, self.t0)
        second = self.fences.acquire("resource:x", "kernel:b", 30, self.t0 + timedelta(seconds=11))
        self.assertEqual(first.fence_token, 1)
        self.assertEqual(second.fence_token, 2)

    def test_stale_owner_cannot_assert_current_after_takeover(self):
        first = self.fences.acquire("resource:x", "kernel:a", 10, self.t0)
        self.fences.acquire("resource:x", "kernel:b", 30, self.t0 + timedelta(seconds=11))
        with self.assertRaises(HardeningError) as cm:
            self.fences.assert_current(first, self.t0 + timedelta(seconds=12))
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")

    def test_stale_owner_cannot_release_new_owners_fence(self):
        first = self.fences.acquire("resource:x", "kernel:a", 10, self.t0)
        second = self.fences.acquire("resource:x", "kernel:b", 30, self.t0 + timedelta(seconds=11))
        with self.assertRaises(HardeningError):
            self.fences.release(first, self.t0 + timedelta(seconds=12))
        self.fences.assert_current(second, self.t0 + timedelta(seconds=12))

    def test_release_then_reacquire_still_increments_token(self):
        first = self.fences.acquire("resource:x", "kernel:a", 30, self.t0)
        self.fences.release(first, self.t0 + timedelta(seconds=1))
        second = self.fences.acquire("resource:x", "kernel:b", 30, self.t0 + timedelta(seconds=2))
        self.assertEqual(second.fence_token, 2)

    def test_provider_guard_accepts_same_current_fence_epoch(self):
        first = self.provider_fences.accept("sandbox-payments", "business:x", 4)
        second = self.provider_fences.accept("sandbox-payments", "business:x", 4)
        self.assertEqual(first["accepted_token"], 4)
        self.assertEqual(second["accepted_token"], 4)

    def test_provider_guard_rejects_token_below_highest_observed_epoch(self):
        self.provider_fences.accept("sandbox-payments", "business:x", 5)
        with self.assertRaises(HardeningError) as cm:
            self.provider_fences.accept("sandbox-payments", "business:x", 4)
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")

    def test_distributed_action_guard_binds_identity_and_advances_with_current_fence(self):
        permit = self.guard.prepare(
            self.contract,
            self.args,
            "intent-a",
            "sandbox-payments",
            "kernel:a",
            30,
            self.t0,
        )
        self.assertEqual(permit.lease.fence_token, 1)
        state = self.guard.transition(permit, "EXECUTING", self.t0 + timedelta(seconds=1))
        self.assertEqual(state["status"], "EXECUTING")
        self.assertEqual(state["semantic_intent_digest"], "intent-a")

    def test_stale_distributed_action_permit_cannot_advance_after_takeover(self):
        first = self.guard.prepare(
            self.contract,
            self.args,
            "intent-a",
            "sandbox-payments",
            "kernel:a",
            10,
            self.t0,
        )
        second = self.guard.prepare(
            self.contract,
            self.args,
            "intent-a",
            "sandbox-payments",
            "kernel:b",
            30,
            self.t0 + timedelta(seconds=11),
        )
        self.assertEqual(second.lease.fence_token, 2)
        with self.assertRaises(HardeningError) as cm:
            self.guard.transition(first, "EXECUTING", self.t0 + timedelta(seconds=12))
        self.assertEqual(cm.exception.code, "CFHS_STALE_FENCE")


if __name__ == "__main__":
    unittest.main()
