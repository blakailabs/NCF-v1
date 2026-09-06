from __future__ import annotations

from .provider_compensation_hardening import TrustKernelV06FinalGate
from .provider_intent_replay_hardening import TrustKernelV06ReplaySafeGate


class TrustKernelV06ReleaseGate(TrustKernelV06FinalGate):
    """Canonical v0.6 sandbox release gate.

    Composition order:
      exact provider safety
      → semantic replay reservation before intent persistence
      → session-proven approvals
      → anchored authorization evidence
      → anchored provider PREPARE/result
      → reconciliation on uncertainty
      → separately governed S3 compensation
    """

    _durable_matches = TrustKernelV06ReplaySafeGate._durable_matches
    recover_unattached_provider_replays = TrustKernelV06ReplaySafeGate.recover_unattached_provider_replays
    _release_unattached_if_safe = TrustKernelV06ReplaySafeGate._release_unattached_if_safe
    create_provider_intent = TrustKernelV06ReplaySafeGate.create_provider_intent

    def __init__(self, hardened, trusted_policy_keys=None, provider_anchor=None):
        super().__init__(hardened, trusted_policy_keys or {}, provider_anchor)
        self.startup_provider_replay_recovery = self.recover_unattached_provider_replays()
