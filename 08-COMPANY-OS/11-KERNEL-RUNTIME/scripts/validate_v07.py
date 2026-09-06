#!/usr/bin/env python3
from __future__ import annotations

import compileall
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TARGETED_TESTS = 164
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
        ],
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
