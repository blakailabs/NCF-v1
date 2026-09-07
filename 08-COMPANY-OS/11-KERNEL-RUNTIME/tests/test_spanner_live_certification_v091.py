import unittest

from kernel.hardening import HardeningError
from kernel.spanner_backend_v091 import SpannerDeploymentConfig, SpannerProductionAdapterV091
from kernel.spanner_live_certification_v091 import SPANNER_LIVE_PHASES, SpannerLiveCertificationOrchestrator


class Driver:
    def __init__(self, overrides=None): self.overrides = overrides or {}
    def execute(self, phase, adapter):
        value = self.overrides.get(phase)
        if isinstance(value, Exception): raise value
        if value is not None: return value
        return {"status": "PASS", "evidence": {"phase": phase, "backend": adapter.backend_id}}


def config(**kwargs):
    values = dict(
        deployment_id="spanner-live-01", project_id="p", instance_id="i", database_id="d",
        instance_config="regional-us-central1", database_dialect="GOOGLE_STANDARD_SQL",
        credential_reference="secret://gcp/workload-identity/spanner", live_reads_enabled=True, live_writes_enabled=True,
    )
    values.update(kwargs)
    return SpannerDeploymentConfig(**values)


class SpannerLiveCertificationTests(unittest.TestCase):
    def test_disabled_channels_block_before_driver(self):
        adapter = SpannerProductionAdapterV091(config(live_reads_enabled=False, live_writes_enabled=False))
        report = SpannerLiveCertificationOrchestrator(adapter).run(Driver())
        self.assertFalse(report.production_ready)
        self.assertEqual(report.results[0].status, "BLOCKED")

    def test_missing_driver_is_blocked(self):
        report = SpannerLiveCertificationOrchestrator(SpannerProductionAdapterV091(config())).run(None)
        self.assertEqual(report.results[0].reason, "independent_live_probe_driver_not_connected")

    def test_all_fourteen_observed_phases_are_required(self):
        report = SpannerLiveCertificationOrchestrator(SpannerProductionAdapterV091(config())).run(Driver())
        self.assertTrue(report.production_ready)
        self.assertEqual(tuple(r.phase for r in report.results), SPANNER_LIVE_PHASES)

    def test_pass_without_evidence_is_invalid(self):
        driver = Driver({SPANNER_LIVE_PHASES[0]: {"status": "PASS"}})
        with self.assertRaises(HardeningError) as cm:
            SpannerLiveCertificationOrchestrator(SpannerProductionAdapterV091(config())).run(driver)
        self.assertEqual(cm.exception.code, "CFHS_SPANNER_PROBE_INVALID")

    def test_fail_requires_reason(self):
        driver = Driver({SPANNER_LIVE_PHASES[0]: {"status": "FAIL"}})
        with self.assertRaises(HardeningError):
            SpannerLiveCertificationOrchestrator(SpannerProductionAdapterV091(config())).run(driver)

    def test_blocked_requires_reason(self):
        driver = Driver({SPANNER_LIVE_PHASES[0]: {"status": "BLOCKED"}})
        with self.assertRaises(HardeningError):
            SpannerLiveCertificationOrchestrator(SpannerProductionAdapterV091(config())).run(driver)

    def test_failure_stops_later_authority_phases(self):
        phase = SPANNER_LIVE_PHASES[4]
        report = SpannerLiveCertificationOrchestrator(SpannerProductionAdapterV091(config())).run(
            Driver({phase: {"status": "FAIL", "reason": "stale_cas_was_accepted"}})
        )
        self.assertFalse(report.production_ready)
        self.assertEqual(report.results[-1].phase, phase)
        self.assertEqual(len(report.results), 5)

    def test_blocked_fault_control_is_preserved_not_promoted(self):
        phase = "S12_FAULT_QUORUM_EVIDENCE"
        report = SpannerLiveCertificationOrchestrator(SpannerProductionAdapterV091(config())).run(
            Driver({phase: {"status": "BLOCKED", "reason": "independent_fault_controller_unavailable"}})
        )
        self.assertFalse(report.production_ready)
        self.assertEqual(report.results[-1].status, "BLOCKED")

    def test_driver_exception_becomes_fail_evidence(self):
        phase = SPANNER_LIVE_PHASES[2]
        report = SpannerLiveCertificationOrchestrator(SpannerProductionAdapterV091(config())).run(
            Driver({phase: RuntimeError("network")})
        )
        self.assertEqual(report.results[-1].status, "FAIL")
        self.assertIn("RuntimeError", report.results[-1].reason)

    def test_invalid_status_is_rejected(self):
        driver = Driver({SPANNER_LIVE_PHASES[0]: {"status": "UNKNOWN", "evidence": {"x": 1}}})
        with self.assertRaises(HardeningError):
            SpannerLiveCertificationOrchestrator(SpannerProductionAdapterV091(config())).run(driver)

    def test_report_digest_binds_negative_evidence(self):
        phase = SPANNER_LIVE_PHASES[1]
        a = SpannerLiveCertificationOrchestrator(SpannerProductionAdapterV091(config())).run(
            Driver({phase: {"status": "FAIL", "reason": "schema-a"}})
        )
        b = SpannerLiveCertificationOrchestrator(SpannerProductionAdapterV091(config())).run(
            Driver({phase: {"status": "FAIL", "reason": "schema-b"}})
        )
        self.assertNotEqual(a.digest(), b.digest())

    def test_report_digest_binds_deployment_identity(self):
        a = SpannerLiveCertificationOrchestrator(SpannerProductionAdapterV091(config(database_id="d1"))).run(Driver())
        b = SpannerLiveCertificationOrchestrator(SpannerProductionAdapterV091(config(database_id="d2"))).run(Driver())
        self.assertNotEqual(a.digest(), b.digest())


if __name__ == "__main__": unittest.main()
