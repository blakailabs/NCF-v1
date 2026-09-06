from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .control_plane_fencing import TrustKernelV07ControlPlaneFinalGate
from .hardening import HardeningError
from .live_adapter_safety import ExactUnitPolicy
from .runtime import RequestContext, uid


class ExactFinancialAuthorityEvaluator:
    """Evaluates financial authority using the same exact units as accounting."""

    @staticmethod
    def policy_from_conditions(conditions: dict[str, Any]) -> dict[str, Any] | None:
        policy = conditions.get("exact_authority")
        if policy is None:
            return None
        if not isinstance(policy, dict):
            raise HardeningError("CFHS_INVALID_POLICY", "exact_authority must be an object")
        required = ("argument", "unit_kind", "max_units")
        for key in required:
            if key not in policy:
                raise HardeningError("CFHS_INVALID_POLICY", f"exact_authority is missing: {key}")
        max_units = policy["max_units"]
        if isinstance(max_units, bool) or not isinstance(max_units, int) or max_units < 1:
            raise HardeningError("CFHS_INVALID_POLICY", "exact_authority max_units must be a positive integer")
        unit_kind = str(policy["unit_kind"])
        if unit_kind not in {"currency_minor", "count"}:
            raise HardeningError("CFHS_INVALID_POLICY", "Unsupported exact authority unit kind")
        if unit_kind == "currency_minor" and not policy.get("currency"):
            raise HardeningError("CFHS_INVALID_POLICY", "Currency exact authority requires currency")
        return dict(policy)

    @staticmethod
    def units(policy: dict[str, Any], context: dict[str, Any]) -> int:
        converter = ExactUnitPolicy(
            pool_id="authority-only",
            argument=str(policy["argument"]),
            unit_kind=str(policy["unit_kind"]),
            minor_exponent=int(policy.get("minor_exponent", 0)),
            currency=policy.get("currency"),
        )
        return converter.to_units(context)

    @staticmethod
    def elevation_matches(policy: dict[str, Any], scope: dict[str, Any], requested_units: int) -> bool:
        elevated = scope.get("exact_authority")
        if not isinstance(elevated, dict):
            return False
        for key in ("argument", "unit_kind", "currency", "minor_exponent"):
            expected = policy.get(key)
            actual = elevated.get(key)
            if key == "minor_exponent":
                expected = int(expected or 0)
                actual = int(actual or 0)
            if actual != expected:
                return False
        max_units = elevated.get("max_units")
        if isinstance(max_units, bool) or not isinstance(max_units, int):
            return False
        return max_units >= requested_units


class TrustKernelV07ExactAuthorityFinalGate(TrustKernelV07ControlPlaneFinalGate):
    """Canonical candidate enforcing exact-unit financial authority thresholds."""

    def _active_exact_elevation(
        self,
        principal_id: str,
        action: str,
        resource: str,
        policy: dict[str, Any],
        requested_units: int,
    ) -> dict[str, Any] | None:
        rows = self.core.store.all(
            "SELECT * FROM elevation_requests WHERE principal_id=? AND action=? AND resource=? AND status='APPROVED'",
            (principal_id, action, resource),
        )
        now = datetime.now(timezone.utc)
        for row in rows:
            expires_at = datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None
            if expires_at and expires_at <= now:
                continue
            scope = json.loads(row["scope_json"])
            if ExactFinancialAuthorityEvaluator.elevation_matches(policy, scope, requested_units):
                return dict(row)
        return None

    def authorize(
        self,
        ctx: RequestContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        context = context or {}
        base = super().authorize(ctx, action, resource, context)
        principal = self.core._principal(ctx.actor_id)
        capability = self.core._match_capability(principal, action, resource)
        if capability is None:
            return base
        conditions = dict(capability.get("conditions", {}))
        policy = ExactFinancialAuthorityEvaluator.policy_from_conditions(conditions)
        if policy is None:
            return base

        requested_units = ExactFinancialAuthorityEvaluator.units(policy, context)
        max_units = int(policy["max_units"])
        exact = {
            "argument": policy["argument"],
            "unit_kind": policy["unit_kind"],
            "currency": policy.get("currency"),
            "minor_exponent": int(policy.get("minor_exponent", 0)),
            "requested_units": requested_units,
            "max_units": max_units,
        }

        # A hard denial for an unrelated policy/resource control is never
        # weakened by the exact-authority overlay.
        if base.get("decision") == "DENY":
            result = {**base, "exact_authority": exact}
            self.core.audit(ctx, "authorization.exact.v07", action, resource, "DENY", result)
            return result

        if requested_units <= max_units:
            # For capabilities carrying exact_authority, exact units are the
            # canonical financial threshold. A legacy float max_amount on the
            # same capability is retained only for backward regression paths.
            result = {
                **base,
                "decision": "ALLOW",
                "decision_id": uid("dec_exact"),
                "matched_policies": [capability.get("id", "capability"), "exact-authority-v07"],
                "exact_authority": exact,
            }
            self.core.audit(ctx, "authorization.exact.v07", action, resource, "ALLOW", result)
            return result

        elevation = self._active_exact_elevation(
            ctx.actor_id,
            action,
            resource,
            policy,
            requested_units,
        )
        if elevation:
            result = {
                **base,
                "decision": "ALLOW",
                "decision_id": uid("dec_exact"),
                "matched_policies": [
                    capability.get("id", "capability"),
                    "exact-authority-v07",
                    f"exact-elevation:{elevation['id']}",
                ],
                "exact_authority": {**exact, "elevation_id": elevation["id"]},
            }
            self.core.audit(ctx, "authorization.exact.v07", action, resource, "ALLOW", result)
            return result

        result = {
            **base,
            "decision": "ELEVATION_REQUIRED",
            "decision_id": uid("dec_exact"),
            "matched_policies": [capability.get("id", "capability"), "exact-authority-v07"],
            "exact_authority": exact,
        }
        self.core.audit(ctx, "authorization.exact.v07", action, resource, "ELEVATION_REQUIRED", result)
        return result
