#!/usr/bin/env python3
from __future__ import annotations

import compileall
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTS = [
    "test_action_safety_v05",
    "test_action_crash_recovery_v05",
    "test_action_reconciliation_v05",
    "test_server_v05_integration",
]


def main() -> int:
    compile_ok = compileall.compile_dir(str(ROOT / "kernel"), quiet=1)
    compile_ok = compileall.compile_dir(str(ROOT / "tests"), quiet=1) and compile_ok

    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "tests"))

    suite = unittest.TestSuite()
    loader = unittest.defaultTestLoader
    for module in TESTS:
        suite.addTests(loader.loadTestsFromName(module))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    summary = {
        "milestone": "Company Kernel Action Safety v0.5",
        "compile_ok": compile_ok,
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "successful": compile_ok and result.wasSuccessful(),
        "simulation_only": True,
    }
    print("\nV0.5_VALIDATION_SUMMARY=" + json.dumps(summary, sort_keys=True))
    return 0 if summary["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
