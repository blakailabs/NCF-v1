from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .exact_authority import TrustKernelV07ExactAuthorityFinalGate
from .hardening import HardeningError
from .runtime import RequestContext, now_iso
from .trust import sha256_hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ProductionIdentityPolicy:
    mode: str
    allowed_provider_ids: tuple[str, ...]
    allowed_issuers: tuple[str, ...]
    required_amr: tuple[str, ...]
    allowed_acr: tuple[str, ...]
    max_auth_age_seconds: int
    max_future_skew_seconds: int

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "ProductionIdentityPolicy":
        raw = dict((config.get("security") or {}).get("production_identity") or {})
        mode = str(raw.get("mode", "sandbox"))
        if mode not in {"sandbox", "production"}:
            raise HardeningError("CFHS_INVALID_POLICY", "production_identity mode must be sandbox or production")
        allowed_provider_ids = tuple(str(x) for x in raw.get("allowed_provider_ids", []))
        allowed_issuers = tuple(str(x) for x in raw.get("allowed_issuers", []))
        required_amr = tuple(str(x) for x in raw.get("required_amr", ["mfa"]))
        allowed_acr = tuple(str(x) for x in raw.get("allowed_acr", []))
        max_auth_age_seconds = int(raw.get("max_auth_age_seconds", 900))
        max_future_skew_seconds = int(raw.get("max_future_skew_seconds", 60))
        if max_auth_age_seconds < 1 or max_auth_age_seconds > 86400:
            raise HardeningError("CFHS_INVALID_POLICY", "max_auth_age_seconds must be from 1 to 86400")
        if max_future_skew_seconds < 0 or max_future_skew_seconds > 300:
            raise HardeningError("CFHS_INVALID_POLICY", "max_future_skew_seconds must be from 0 to 300")
        if mode == "production":
            if not allowed_provider_ids:
                raise HardeningError("CFHS_INVALID_POLICY", "Production identity policy requires allowed_provider_ids")
            if not allowed_issuers:
                raise HardeningError("CFHS_INVALID_POLICY", "Production identity policy requires allowed_issuers")
            if not required_amr:
                raise HardeningError("CFHS_INVALID_POLICY", "Production identity policy requires at least one AMR factor")
        return cls(
            mode,
            allowed_provider_ids,
            allowed_issuers,
            required_amr,
            allowed_acr,
            max_auth_age_seconds,
            max_future_skew_seconds,
        )

    @property
    def production(self) -> bool:
        return self.mode == "production"

    def envelope(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "allowed_provider_ids": list(self.allowed_provider_ids),
            "allowed_issuers": list(self.allowed_issuers),
            "required_amr": list(self.required_amr),
            "allowed_acr": list(self.allowed_acr),
            "max_auth_age_seconds": self.max_auth_age_seconds,
            "max_future_skew_seconds": self.max_future_skew_seconds,
        }


class ProductionIdentityAssurance:
    """Evaluates trusted external identity provenance without storing raw tokens."""

    def __init__(self, kernel: "TrustKernelV07ProductionIdentityFinalGate", policy: ProductionIdentityPolicy):
        self.kernel = kernel
        self.policy = policy

    @staticmethod
    def _parse_auth_time(value: Any) -> datetime:
        if isinstance(value, bool):
            raise HardeningError("CFHS_AUTHENTICATION_CLASS_REQUIRED", "Identity auth_time is invalid")
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(float(value), tz=timezone.utc)
            except Exception as exc:
                raise HardeningError("CFHS_AUTHENTICATION_CLASS_REQUIRED", "Identity auth_time is invalid") from exc
        if isinstance(value, str):
            text = value.strip()
            if not text:
                raise HardeningError("CFHS_AUTHENTICATION_CLASS_REQUIRED", "Identity auth_time is missing")
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError as exc:
                raise HardeningError("CFHS_AUTHENTICATION_CLASS_REQUIRED", "Identity auth_time is invalid") from exc
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        raise HardeningError("CFHS_AUTHENTICATION_CLASS_REQUIRED", "Identity auth_time is missing")

    def require_bearer(
        self,
        bearer_token: str,
        expected_principal: str,
        purpose: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        evidence = self.kernel.approval_session_resolver.resolve(bearer_token, expected_principal)
        if not self.policy.production:
            return {
                "principal_id": expected_principal,
                "authentication_class": evidence.authentication_class,
                "purpose": purpose,
                "policy_mode": "sandbox",
                "session_evidence_digest": evidence.digest(),
            }
        external = self.kernel.session_identity_provenance.get(evidence.session_id)
        if not external or evidence.authentication_class != "verified_external_identity":
            raise HardeningError(
                "CFHS_AUTHENTICATION_CLASS_REQUIRED",
                "Production action requires verified external identity provenance",
                {"purpose": purpose, "required_class": "verified_external_identity"},
            )
        if external["provider_id"] not in self.policy.allowed_provider_ids:
            raise HardeningError(
                "CFHS_AUTHENTICATION_CLASS_REQUIRED",
                "External identity provider is not allowed for production action",
                {"purpose": purpose, "provider_id": external["provider_id"]},
            )
        if external["issuer"] not in self.policy.allowed_issuers:
            raise HardeningError(
                "CFHS_AUTHENTICATION_CLASS_REQUIRED",
                "External identity issuer is not allowed for production action",
                {"purpose": purpose},
            )
        auth_context = dict(external.get("auth_context") or {})
        amr_raw = auth_context.get("amr", [])
        amr = {str(x) for x in amr_raw} if isinstance(amr_raw, list) else set()
        missing_amr = [factor for factor in self.policy.required_amr if factor not in amr]
        if missing_amr:
            raise HardeningError(
                "CFHS_MFA_REQUIRED",
                "Production action requires stronger authentication factors",
                {"purpose": purpose, "missing_amr": missing_amr},
            )
        acr = str(auth_context.get("acr", ""))
        if self.policy.allowed_acr and acr not in self.policy.allowed_acr:
            raise HardeningError(
                "CFHS_MFA_REQUIRED",
                "Authentication context class is not strong enough for production action",
                {"purpose": purpose},
            )
        auth_time = self._parse_auth_time(auth_context.get("auth_time"))
        current = now or utcnow()
        age = (current - auth_time).total_seconds()
        if age < -self.policy.max_future_skew_seconds:
            raise HardeningError("CFHS_AUTHENTICATION_CLASS_REQUIRED", "Identity auth_time is unreasonably in the future")
        if age > self.policy.max_auth_age_seconds:
            raise HardeningError(
                "CFHS_REAUTHENTICATION_REQUIRED",
                "Production action requires recent authentication",
                {
                    "purpose": purpose,
                    "max_auth_age_seconds": self.policy.max_auth_age_seconds,
                    "observed_auth_age_seconds": int(age),
                },
            )
        result = {
            "principal_id": expected_principal,
            "authentication_class": "verified_external_identity+mfa",
            "provider_id": external["provider_id"],
            "issuer_digest": sha256_hex(external["issuer"]),
            "auth_context_digest": sha256_hex(auth_context),
            "external_identity_digest": external["evidence_digest"],
            "session_evidence_digest": evidence.digest(),
            "auth_age_seconds": max(0, int(age)),
            "purpose": purpose,
            "policy_mode": "production",
        }
        result["assurance_digest"] = sha256_hex(result)
        return result

    def require_request_provenance(self, request_id: str, purpose: str) -> dict[str, Any]:
        complete = self.kernel.approval_provenance.require_complete(request_id)
        if not self.policy.production:
            return {**complete, "policy_mode": "sandbox"}
        strong: list[dict[str, Any]] = []
        for approver in complete["approvers"]:
            session_id = approver["session_id"]
            session = self.kernel.core.store.one("SELECT * FROM kernel_sessions WHERE id=?", (session_id,))
            if not session:
                raise HardeningError("CFHS_AUTHENTICATION_CLASS_REQUIRED", "Approval session no longer exists")
            external = self.kernel.session_identity_provenance.get(session_id)
            if not external:
                raise HardeningError(
                    "CFHS_AUTHENTICATION_CLASS_REQUIRED",
                    "Every production approval must have verified external identity provenance",
                    {"request_id": request_id, "approver_id": approver["approver_id"]},
                )
            auth_context = dict(external.get("auth_context") or {})
            amr = {str(x) for x in auth_context.get("amr", [])} if isinstance(auth_context.get("amr", []), list) else set()
            if external["provider_id"] not in self.policy.allowed_provider_ids or external["issuer"] not in self.policy.allowed_issuers:
                raise HardeningError("CFHS_AUTHENTICATION_CLASS_REQUIRED", "Production approval identity source is not trusted")
            if any(factor not in amr for factor in self.policy.required_amr):
                raise HardeningError("CFHS_MFA_REQUIRED", "Production approval lacks required MFA evidence")
            acr = str(auth_context.get("acr", ""))
            if self.policy.allowed_acr and acr not in self.policy.allowed_acr:
                raise HardeningError("CFHS_MFA_REQUIRED", "Production approval ACR is insufficient")
            auth_time = self._parse_auth_time(auth_context.get("auth_time"))
            age = (utcnow() - auth_time).total_seconds()
            if age < -self.policy.max_future_skew_seconds:
                raise HardeningError("CFHS_AUTHENTICATION_CLASS_REQUIRED", "Production approval auth_time is invalid")
            if age > self.policy.max_auth_age_seconds:
                raise HardeningError("CFHS_REAUTHENTICATION_REQUIRED", "Production approval authentication is stale")
            strong.append(
                {
                    "approver_id": approver["approver_id"],
                    "session_id": session_id,
                    "provider_id": external["provider_id"],
                    "external_identity_digest": external["evidence_digest"],
                    "auth_context_digest": sha256_hex(auth_context),
                }
            )
        return {
            **complete,
            "policy_mode": "production",
            "strong_approvers": strong,
            "strong_provenance_digest": sha256_hex(strong),
            "purpose": purpose,
        }


class ElevationApprovalIdentityLedger:
    def __init__(self, conn):
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS elevation_approval_identity_v07(
                elevation_id TEXT PRIMARY KEY,
                approver_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                authentication_class TEXT NOT NULL,
                assurance_digest TEXT NOT NULL,
                external_identity_digest TEXT,
                approved_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def get(self, elevation_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM elevation_approval_identity_v07 WHERE elevation_id=?",
            (elevation_id,),
        ).fetchone()
        return dict(row) if row else None


class TrustKernelV07ProductionIdentityFinalGate(TrustKernelV07ExactAuthorityFinalGate):
    """Canonical candidate for production external-identity/MFA enforcement."""

    def __init__(self, hardened, trusted_policy_keys=None, provider_anchor=None, kernel_instance_id="kernel:reference-v07"):
        super().__init__(hardened, trusted_policy_keys or {}, provider_anchor, kernel_instance_id)
        self.production_identity_policy = ProductionIdentityPolicy.from_config(self.core.config)
        self.identity_assurance = ProductionIdentityAssurance(self, self.production_identity_policy)
        self.elevation_identity = ElevationApprovalIdentityLedger(self.core.store.conn)

    def approve_action_with_session(self, ctx: RequestContext, bearer_token: str, request_id: str) -> dict[str, Any]:
        assurance = self.identity_assurance.require_bearer(
            bearer_token,
            ctx.actor_id,
            "action_approval",
        )
        result = super().approve_action_with_session(ctx, bearer_token, request_id)
        safe = {**result, "identity_assurance": assurance}
        self.hardened._chain(ctx, "action.approval.identity.v07", safe)
        return safe

    def prepare_provider_action(
        self,
        ctx: RequestContext,
        intent_id: str,
        arguments: dict[str, Any],
        approval_request_id: str | None = None,
    ) -> dict[str, Any]:
        intent, _binding, _operation, _profile = self._bound_provider_context(intent_id)
        if self.production_identity_policy.production and intent.side_effect_class == "S3":
            if not approval_request_id:
                raise HardeningError("CFHS_ELEVATION_REQUIRED", "Production S3 PREPARE requires approved MFA provenance")
            strong = self.identity_assurance.require_request_provenance(
                approval_request_id,
                "s3_prepare_release",
            )
            self.hardened._chain(
                ctx,
                "provider.s3.identity.release.v07",
                {
                    "intent_id": intent_id,
                    "approval_request_id": approval_request_id,
                    "strong_provenance_digest": strong["strong_provenance_digest"],
                },
            )
        return super().prepare_provider_action(ctx, intent_id, arguments, approval_request_id)

    def request_provider_compensation_approval_with_session(
        self,
        ctx: RequestContext,
        bearer_token: str,
        intent_id: str,
        arguments: dict[str, Any],
        eligible_approvers: list[str],
        required_count: int | None = None,
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        assurance = self.identity_assurance.require_bearer(
            bearer_token,
            ctx.actor_id,
            "compensation_request",
        )
        result = super().request_provider_compensation_approval(
            ctx,
            intent_id,
            arguments,
            eligible_approvers,
            required_count,
            ttl_seconds,
        )
        self.hardened._chain(
            ctx,
            "provider.compensation.request.identity.v07",
            {
                "intent_id": intent_id,
                "compensation_intent_id": result["compensation_intent"]["compensation_intent_id"],
                "assurance_digest": assurance.get("assurance_digest", assurance["session_evidence_digest"]),
            },
        )
        return {**result, "requester_identity_assurance": assurance}

    def compensate_provider_action_with_session(
        self,
        ctx: RequestContext,
        bearer_token: str,
        intent_id: str,
        arguments: dict[str, Any],
        sandbox_mode: str = "success",
        compensation_intent_id: str | None = None,
        compensation_approval_request_id: str | None = None,
    ) -> dict[str, Any]:
        assurance = self.identity_assurance.require_bearer(
            bearer_token,
            ctx.actor_id,
            "compensation_execute",
        )
        if self.production_identity_policy.production and compensation_approval_request_id:
            self.identity_assurance.require_request_provenance(
                compensation_approval_request_id,
                "compensation_release",
            )
        result = super().compensate_provider_action(
            ctx,
            intent_id,
            arguments,
            sandbox_mode,
            compensation_intent_id,
            compensation_approval_request_id,
        )
        return {**result, "requester_identity_assurance": assurance}

    def approve_elevation_with_session(
        self,
        ctx: RequestContext,
        bearer_token: str,
        elevation_id: str,
        ttl_seconds: int = 600,
    ) -> dict[str, Any]:
        assurance = self.identity_assurance.require_bearer(
            bearer_token,
            ctx.actor_id,
            "elevation_approval",
        )
        principal = self.core._principal(ctx.actor_id)
        caps = json.loads(principal["capabilities_json"])
        if not any(c.get("action") in ("kernel.elevation.approve", "*") for c in caps):
            raise HardeningError("CFHS_POLICY_DENIED", "Principal cannot approve elevations")
        ttl = max(60, min(int(ttl_seconds), 3600))
        now = utcnow()
        expires_at = (now + timedelta(seconds=ttl)).isoformat()
        conn = self.core.store.conn
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM elevation_requests WHERE id=?", (elevation_id,)).fetchone()
            if not row or row["status"] != "PENDING":
                raise HardeningError("CFHS_NOT_FOUND", "Pending elevation request not found")
            existing = conn.execute(
                "SELECT * FROM elevation_approval_identity_v07 WHERE elevation_id=?",
                (elevation_id,),
            ).fetchone()
            if existing:
                raise HardeningError("CFHS_CONFLICT", "Elevation approval identity already exists")
            conn.execute(
                """
                INSERT INTO elevation_approval_identity_v07(
                    elevation_id,approver_id,session_id,authentication_class,
                    assurance_digest,external_identity_digest,approved_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    elevation_id,
                    ctx.actor_id,
                    self.approval_session_resolver.resolve(bearer_token, ctx.actor_id).session_id,
                    assurance["authentication_class"],
                    assurance.get("assurance_digest", assurance["session_evidence_digest"]),
                    assurance.get("external_identity_digest"),
                    now.isoformat(),
                ),
            )
            conn.execute(
                "UPDATE elevation_requests SET status='APPROVED',approved_by=?,approved_at=?,expires_at=? WHERE id=?",
                (ctx.actor_id, now.isoformat(), expires_at, elevation_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        result = {
            "elevation_id": elevation_id,
            "status": "APPROVED",
            "approved_by": ctx.actor_id,
            "expires_at": expires_at,
            "identity_assurance": assurance,
        }
        self.core.audit(ctx, "elevation.approved.identity.v07", row["action"], row["resource"], "ALLOW", result)
        self.hardened._chain(ctx, "elevation.approved.identity.v07", result)
        return result

    def authorize(
        self,
        ctx: RequestContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = super().authorize(ctx, action, resource, context)
        if not self.production_identity_policy.production:
            return result
        exact = result.get("exact_authority") or {}
        elevation_id = exact.get("elevation_id")
        if result.get("decision") == "ALLOW" and elevation_id:
            provenance = self.elevation_identity.get(elevation_id)
            if not provenance:
                denied = {
                    **result,
                    "decision": "ELEVATION_REQUIRED",
                    "matched_policies": list(result.get("matched_policies", [])) + ["production-identity-v07"],
                    "identity_requirement": "verified_external_identity+mfa",
                }
                self.core.audit(ctx, "authorization.identity.v07", action, resource, "ELEVATION_REQUIRED", denied)
                return denied
        return result

    def identity_policy_status(self) -> dict[str, Any]:
        policy = self.production_identity_policy.envelope()
        return {
            "mode": policy["mode"],
            "policy_digest": sha256_hex(policy),
            "production_enforced": self.production_identity_policy.production,
            "raw_identity_tokens_stored": False,
            "required_human_class": "verified_external_identity+mfa" if self.production_identity_policy.production else "kernel_session_or_stronger",
        }
