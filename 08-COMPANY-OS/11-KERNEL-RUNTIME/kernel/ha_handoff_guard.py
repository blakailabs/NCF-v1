from __future__ import annotations

from .ha_bootstrap_authority import HABootstrapPermit, HACertificationBootstrapCoordinator
from .ha_certification_handoff import SQLiteHAHandoffLedger
from .ha_persistence import HADeploymentEvidence, HAPersistenceCertification
from .hardening import HardeningError


class HandoffAwareBootstrapCoordinator:
    """Bootstrap entry point that permanently denies first-bootstrap after handoff closure."""

    def __init__(
        self,
        bootstrap: HACertificationBootstrapCoordinator,
        handoff_ledger: SQLiteHAHandoffLedger,
    ):
        self.bootstrap = bootstrap
        self.handoff_ledger = handoff_ledger

    def initialize(
        self,
        certification: HAPersistenceCertification,
        evidence: HADeploymentEvidence,
        permit: HABootstrapPermit,
    ):
        state = self.handoff_ledger.get(evidence.backend_id)
        if state and state.status == "CLOSED":
            raise HardeningError(
                "CFHS_HA_BOOTSTRAP_CLOSED",
                "First-bootstrap authority is permanently closed for this backend lineage",
                {
                    "backend_id": evidence.backend_id,
                    "cluster_id": state.cluster_id,
                    "topology_epoch": state.topology_epoch,
                },
            )
        return self.bootstrap.initialize(certification, evidence, permit)
