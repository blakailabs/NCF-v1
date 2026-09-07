#!/usr/bin/env python3
from __future__ import annotations

import compileall
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from validate_v08 import TESTS as V08_TESTS  # noqa: E402

EXPECTED_V08_BASELINE = 415
EXPECTED_TARGETED_TESTS = 427
TESTS = list(V08_TESTS) + ["test_production_infrastructure_v09"]


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
        "milestone": "Company Kernel Production Infrastructure v0.9",
        "compile_ok": compile_ok,
        "v08_frozen_baseline_tests": EXPECTED_V08_BASELINE,
        "expected_targeted_tests": EXPECTED_TARGETED_TESTS,
        "tests_run": result.testsRun,
        "exact_test_count": exact_test_count,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "successful": successful,
        "production_credentials_allowed": False,
        "production_write_providers_allowed": False,
        "real_production_infrastructure_connected": False,
        "v09_controls": [
            "provider-neutral production infrastructure evidence bundle",
            "exact deployment provider adapter backend cluster identity binding",
            "required HA capability claim surface",
            "required deployment evidence phase surface",
            "external verifier required",
            "provider self-certification forbidden",
            "external verifier independence required",
            "verifier receipt and trust-store provenance required",
            "credential source class constrained to external identity/secret systems",
            "secret-like material rejected from evidence metadata",
            "evidence freshness and expiry enforced",
            "positive authority generation required",
            "v0.8 exact 415-test baseline preserved",
        ],
    }
    print("\nV0.9_VALIDATION_SUMMARY=" + json.dumps(summary, sort_keys=True))
    if not exact_test_count:
        print(
            f"V0.9_TEST_COUNT_MISMATCH expected={EXPECTED_TARGETED_TESTS} actual={result.testsRun}",
            file=sys.stderr,
        )
    return 0 if successful else 1


if __name__ == "__main__":
    raise SystemExit(main())
