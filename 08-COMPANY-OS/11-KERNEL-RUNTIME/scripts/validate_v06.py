#!/usr/bin/env python3
from __future__ import annotations

import compileall
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTS = [
    # v0.5 regression surface
    "test_action_safety_v05",
    "test_action_crash_recovery_v05",
    "test_action_reconciliation_v05",
    "test_server_v05_integration",
    # v0.6 provider-realistic safety
    "test_live_adapter_safety_v06",
    "test_v06_trust_bindings",
    "test_provider_action_hardening_v06",
    "test_server_v06_integration",
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
    summary = {
        "milestone": "Company Kernel Live-Adapter Safety v0.6",
        "compile_ok": compile_ok,
        "test_modules": TESTS,
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "successful": compile_ok and result.wasSuccessful(),
        "sandbox_only": True,
        "production_credentials_allowed": False,
    }
    print("\nV0.6_VALIDATION_SUMMARY=" + json.dumps(summary, sort_keys=True))
    return 0 if summary["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
