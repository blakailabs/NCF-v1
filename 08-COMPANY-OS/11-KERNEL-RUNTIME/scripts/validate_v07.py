#!/usr/bin/env python3
from __future__ import annotations

import compileall
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TARGETED_TESTS = 246
TESTS = [
    # v0.5 regression surface
    "test_action_safety_v05",
    "test_action_crash_recovery_v05",
    "test_action_reconciliation_v05",
    "test_server_v05_integration",
    # v0.6 live-adapter safety surface
    "test_live_adapter_safety_v06",
    "test_v06_trust_bindings",
    "test_provider_action_hardening_v06",
    "test_server_v06_integration",
    "test_provider_execution_gate_v06",
    "test_provider_compensation_gate_v06",
    "test_provider_replay_restart_v06",
    # v0.7 distributed safety surface
    "test_distributed_safety_v07",
    "test_distributed_provider_gate_v07",
    "test_distributed_state_v07",
    "test_distributed_state_hardening_v07",
    "test_transactional_provider_gate_v07",
    "test_distributed_compensation_v07",
    "test_shared_state_backend_v07",
    "test_control_plane_fencing_v07",
    "test_exact_authority_v07",
    "test_production_identity_v07",
    "test_remote_anchor_hardening_v07",
]


def main() -> int:
    compile_ok = True
    for directory in ("kernel", "tests", "examples", "scripts"):
        compile_ok = compileall.compile_dir(str(ROOT / directory), quiet=1) and compile_ok

    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "tests"))

    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite()
    for module in TESTS:
        suite.addTests(loader.loadTestsFromName(module))

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    exact_test_count = result.testsRun == EXPECTED_TARGETED_TESTS
    successful = compile_ok and result.wasSuccessful() and exact_test_count
    summary = {
        "milestone": "Company Kernel Distributed / Production Safety v0.7",
        "compile_ok": compile_ok,
        "test_modules": TESTS,
        "expected_targeted_tests": EXPECTED_TARGETED_TESTS,
        "tests_run": result.testsRun,
        "exact_test_count": exact_test_count,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "successful": successful,
        "production_credentials_allowed": False,
        "distributed_primitives": [
            "business-object identity",
            "monotonic fencing",
            "provider stale-fence rejection",
            "fenced provider execution",
            "fenced reconciliation ownership",
            "atomic fenced exact-resource prepare",
            "versioned distributed transaction journal",
            "retryable safe abort",
            "pre-execution takeover after fence expiry",
            "transaction-coordinated provider lifecycle",
            "distributed compensation ownership epoch",
            "compensation provider idempotency",
            "compensation unknown-outcome reconciliation",
            "compensation reconciliation attempt history",
            "shared backend CAS contract",
            "shared backend monotonic fencing contract",
            "shared backend ordered journal contract",
            "atomic fenced shared mutation contract",
            "fenced approval mutation",
            "atomic approval plus session provenance",
            "versioned approval control-plane journal",
            "exact minor-unit financial authority",
            "exact-unit elevation scope",
            "trusted external identity policy",
            "MFA and ACR enforcement",
            "authentication freshness enforcement",
            "MFA-bound elevation approval",
            "S3 strong-provenance release",
            "authenticated audit-anchor request binding",
            "signed endpoint receipt verification",
            "N-of-M audit-anchor quorum",
            "durable partial anchor receipts",
            "replay-safe anchor reconciliation",
        ],
        "reference_backend_production_ready": False,
        "production_identity_policy_available": True,
        "reference_anchor_crypto_production_ready": False,
    }
    print("\nV0.7_VALIDATION_SUMMARY=" + json.dumps(summary, sort_keys=True))
    if not exact_test_count:
        print(
            f"V0.7_TEST_COUNT_MISMATCH expected={EXPECTED_TARGETED_TESTS} actual={result.testsRun}",
            file=sys.stderr,
        )
    return 0 if successful else 1


if __name__ == "__main__":
    raise SystemExit(main())
