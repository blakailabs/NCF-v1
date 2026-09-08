#!/usr/bin/env python3
from __future__ import annotations
import compileall, json, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from validate_v08 import TESTS as V08_TESTS  # noqa: E402
EXPECTED_V08_BASELINE = 415
EXPECTED_TARGETED_TESTS = 493
TESTS = list(V08_TESTS) + [
    "test_production_infrastructure_v09", "test_spanner_backend_v091",
    "test_spanner_live_certification_v091", "test_spanner_pre_gcp_v091",
    "test_spanner_sdk_boundary_v091", "test_spanner_transaction_semantics_v091",
]
def main() -> int:
    compile_ok = True
    for directory in ("kernel", "tests", "examples", "scripts"):
        compile_ok = compileall.compile_dir(str(ROOT / directory), quiet=1) and compile_ok
    sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "tests"))
    loader = unittest.defaultTestLoader; suite = unittest.TestSuite()
    for module in TESTS: suite.addTests(loader.loadTestsFromName(module))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    exact_test_count = result.testsRun == EXPECTED_TARGETED_TESTS
    successful = compile_ok and result.wasSuccessful() and exact_test_count
    summary = {
        "milestone":"Company Kernel Production Infrastructure v0.9", "compile_ok":compile_ok,
        "v08_frozen_baseline_tests":EXPECTED_V08_BASELINE, "expected_targeted_tests":EXPECTED_TARGETED_TESTS,
        "tests_run":result.testsRun, "exact_test_count":exact_test_count, "failures":len(result.failures),
        "errors":len(result.errors), "skipped":len(result.skipped), "successful":successful,
        "production_credentials_allowed":False, "production_write_providers_allowed":False,
        "real_production_infrastructure_connected":False, "spanner_live_integration_enabled":False,
        "v09_controls":[
            "provider-neutral production infrastructure evidence bundle", "external verifier and trust provenance required",
            "provider self-certification forbidden", "Spanner deployment and schema identity binding",
            "Spanner emulator permanently excluded from production certification", "Spanner external credential references only",
            "Spanner live channels disabled by default", "fourteen ordered Spanner live certification phases",
            "PASS requires observed evidence", "FAIL and BLOCKED require explicit reason", "probe exceptions preserved as FAIL",
            "negative phase stops dependent later authority phases", "independent live probe driver required",
            "live report digest binds deployment and negative evidence", "fixed pre-GCP certification target identity",
            "live runtime requires complete keyless workload identity references", "secret-like runtime identity material denied",
            "certification artifact digest binds ordered phase evidence", "provider SDK isolated behind kernel-owned protocol",
            "network, mutation, fault and external-authority permissions independently gated",
            "provider observations cannot self-declare certification status", "provider evidence secret material denied",
            "S1-S14 mapped to concrete SDK boundary methods", "strong reads require observed commit timestamp",
            "ABORTED classified retryable without fabricating commit", "committed mutations require provider commit timestamp",
            "fence assertion object CAS and journal append require one read-write transaction",
            "journal binds object version fence token and commit timestamp", "monotonic fencing enforced",
            "stale CAS must reject without mutation or journal append", "v0.8 exact 415-test baseline preserved",
        ],
    }
    print("\nV0.9_VALIDATION_SUMMARY=" + json.dumps(summary, sort_keys=True))
    if not exact_test_count: print(f"V0.9_TEST_COUNT_MISMATCH expected={EXPECTED_TARGETED_TESTS} actual={result.testsRun}", file=sys.stderr)
    return 0 if successful else 1
if __name__ == "__main__": raise SystemExit(main())
