#!/usr/bin/env python3
from __future__ import annotations

import compileall
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TARGETED_TESTS = 415
TESTS = [
    "test_action_safety_v05","test_action_crash_recovery_v05","test_action_reconciliation_v05","test_server_v05_integration",
    "test_live_adapter_safety_v06","test_v06_trust_bindings","test_provider_action_hardening_v06","test_server_v06_integration",
    "test_provider_execution_gate_v06","test_provider_compensation_gate_v06","test_provider_replay_restart_v06",
    "test_distributed_safety_v07","test_distributed_provider_gate_v07","test_distributed_state_v07","test_distributed_state_hardening_v07",
    "test_transactional_provider_gate_v07","test_distributed_compensation_v07","test_shared_state_backend_v07","test_control_plane_fencing_v07",
    "test_exact_authority_v07","test_production_identity_v07","test_remote_anchor_hardening_v07","test_remote_anchor_config_v07",
    "test_recoverable_anchor_consumers_v07","test_server_v07_anchor_wiring",
    "test_ha_persistence_v08","test_ha_certification_runtime_v08","test_ha_probe_harness_v08","test_ha_evidence_pipeline_v08",
    "test_ha_bootstrap_authority_v08","test_ha_certification_handoff_v08","test_shared_certification_plane_v08",
    "test_certification_plane_attestation_v08","test_certification_plane_enrollment_v08","test_certification_plane_enrollment_authority_v08",
    "test_certification_plane_production_runtime_v08",
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
        "milestone":"Company Kernel HA Persistence Safety v0.8","compile_ok":compile_ok,"test_modules":TESTS,
        "expected_targeted_tests":EXPECTED_TARGETED_TESTS,"tests_run":result.testsRun,"exact_test_count":exact_test_count,
        "failures":len(result.failures),"errors":len(result.errors),"skipped":len(result.skipped),"successful":successful,
        "production_credentials_allowed":False,"production_write_providers_allowed":False,
        "ha_persistence_controls":[
            "capability contract separate from deployment certification","independent topology and behavioral evidence","trusted deployment attestation",
            "time-bounded certification lifecycle","bootstrap-to-steady-state handoff","permanent first-bootstrap closure",
            "provider-neutral shared certification-plane state machine","fenced certification-plane writers","atomic certification CAS plus ordered journal",
            "deployment-bound certification-plane adapter attestation","adapter implementation and backend capability digest binding",
            "adapter topology and probe evidence digest binding","adapter authority generation rollback protection","adapter attestation nonce replay protection",
            "durable reference adapter trust ledger restart recovery","production adapter readiness requires external verifier plus production trust store",
            "durable adapter enrollment bound to verified readiness","monotonic enrollment generation","backend-authoritative enrollment expiry",
            "runtime deployment identity revalidation on every guarded operation","cross-process enrollment revocation visibility",
            "adapter backend cluster capability topology and probe drift fail closed","restart-safe enrollment and revocation state",
            "independent production adapter enrollment authorization","exact readiness deployment attestation and provenance binding",
            "enrollment authority class and generation enforcement","enrollment authorization nonce replay protection",
            "authority-selected enrollment generation","reference enrollment authority cannot self-promote",
            "shared authority activation receipt required for production runtime","direct enrollment registry writes cannot unlock production runtime",
            "authority activation receipt generation and deployment binding","authority activation retry idempotency",
            "production runtime requires active enrollment plus matching authority receipt on every operation","activation receipt survives restart and is cross-process visible",
            "enrollment revocation overrides existing production activation"
        ],
        "sqlite_reference_production_ready":False,"real_ha_backend_enabled":False,"real_chaos_environment_enabled":False,
        "real_topology_control_plane_enabled":False,"production_bootstrap_authority_enabled":False,
        "production_shared_certification_plane_enabled":False,"production_adapter_attestation_authority_enabled":False,
        "production_adapter_enrollment_authority_enabled":False,"production_runtime_enabled":False,
    }
    print("\nV0.8_VALIDATION_SUMMARY=" + json.dumps(summary, sort_keys=True))
    if not exact_test_count: print(f"V0.8_TEST_COUNT_MISMATCH expected={EXPECTED_TARGETED_TESTS} actual={result.testsRun}", file=sys.stderr)
    return 0 if successful else 1

if __name__ == "__main__": raise SystemExit(main())
