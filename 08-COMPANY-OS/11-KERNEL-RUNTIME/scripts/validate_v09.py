#!/usr/bin/env python3
from __future__ import annotations
import compileall, json, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; SCRIPT_DIR=Path(__file__).resolve().parent
sys.path.insert(0,str(SCRIPT_DIR)); from validate_v08 import TESTS as V08_TESTS  # noqa:E402
EXPECTED_V08_BASELINE=415; EXPECTED_TARGETED_TESTS=521
TESTS=list(V08_TESTS)+[
 "test_production_infrastructure_v09","test_spanner_backend_v091","test_spanner_live_certification_v091",
 "test_spanner_pre_gcp_v091","test_spanner_sdk_boundary_v091","test_spanner_transaction_semantics_v091",
 "test_spanner_client_adapter_v091","test_google_spanner_transport_v091","test_spanner_cert_preflight_v091",
]
def main()->int:
 compile_ok=True
 for directory in ("kernel","tests","examples","scripts"): compile_ok=compileall.compile_dir(str(ROOT/directory),quiet=1) and compile_ok
 sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/"tests")); loader=unittest.defaultTestLoader; suite=unittest.TestSuite()
 for module in TESTS: suite.addTests(loader.loadTestsFromName(module))
 result=unittest.TextTestRunner(verbosity=2).run(suite); exact=result.testsRun==EXPECTED_TARGETED_TESTS; successful=compile_ok and result.wasSuccessful() and exact
 summary={"milestone":"Company Kernel Production Infrastructure v0.9","compile_ok":compile_ok,"v08_frozen_baseline_tests":EXPECTED_V08_BASELINE,"expected_targeted_tests":EXPECTED_TARGETED_TESTS,"tests_run":result.testsRun,"exact_test_count":exact,"failures":len(result.failures),"errors":len(result.errors),"skipped":len(result.skipped),"successful":successful,"production_credentials_allowed":False,"production_write_providers_allowed":False,"real_production_infrastructure_connected":False,"spanner_live_integration_enabled":False,"v09_controls":["provider-neutral production evidence","external verifier required","provider self-certification forbidden","Spanner emulator excluded","live channels disabled by default","S1-S14 observed evidence","keyless runtime references","SDK protocol boundary","independent network mutation fault and authority gates","strong read validation","ABORTED retry classification","provider commit timestamp required","atomic fence CAS journal transaction validation","journal version fence timestamp binding","monotonic fencing","stale CAS no-write/no-journal","injectable provider transport with no credential discovery","request validation before transport","kernel-shaped transaction results","lazy google-cloud-spanner import","ADC/WIF-only Google transport with no credential arguments","live emulator target denied","unsupported Google mutation operations denied","real commit result binding required before live mutation pass","cert preflight binds repository ref environment target and WIF readiness","manual GitHub WIF workflow separates preflight plan and apply","apply requires explicit APPLY-CERT-SPANNER confirmation","v0.8 exact 415-test baseline preserved"]}
 print("\nV0.9_VALIDATION_SUMMARY="+json.dumps(summary,sort_keys=True))
 if not exact: print(f"V0.9_TEST_COUNT_MISMATCH expected={EXPECTED_TARGETED_TESTS} actual={result.testsRun}",file=sys.stderr)
 return 0 if successful else 1
if __name__=="__main__": raise SystemExit(main())
