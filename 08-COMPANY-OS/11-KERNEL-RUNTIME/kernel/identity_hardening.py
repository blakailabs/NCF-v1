from __future__ import annotations

import hashlib
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from .hardening import HardeningError, SessionManager


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class VerifiedOIDCProvider(Protocol):
    """Provider boundary for cryptographically verified OIDC claims.

    Implementations must validate the token signature against issuer keys before
    returning claims. The Company Kernel broker does not parse or trust unsigned
    JWT payloads itself.
    """

    def verify_id_token(self, id_token: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class OIDCProviderConfig:
    provider_id: str
    issuer: str
    audience: str
    max_session_seconds: int = 3600


class OIDCIdentityBroker:
    """Maps verified external identities to Company Kernel principals."""

    def __init__(self, conn: sqlite3.Connection, sessions: SessionManager):
        self.conn = conn
        self.sessions = sessions
        if sessions.conn is not conn:
            raise HardeningError("CFHS_CONFLICT", "OIDC broker and session state must share one transaction database")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oidc_principal_mappings(
                provider_id TEXT NOT NULL,
                issuer TEXT NOT NULL,
                subject TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                PRIMARY KEY(provider_id,issuer,subject)
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oidc_login_nonces(
                nonce TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                consumed_at TEXT
            )
            """
        )
        self.conn.commit()

    def map_subject(self, config: OIDCProviderConfig, subject: str, principal_id: str) -> None:
        if not subject or not principal_id:
            raise HardeningError("CFHS_INVALID_REQUEST", "OIDC subject and principal are required")
        self.conn.execute(
            """
            INSERT INTO oidc_principal_mappings(provider_id,issuer,subject,principal_id,active,created_at)
            VALUES(?,?,?,?,1,?)
            ON CONFLICT(provider_id,issuer,subject) DO UPDATE SET principal_id=excluded.principal_id,active=1
            """,
            (config.provider_id, config.issuer, subject, principal_id, utcnow().isoformat()),
        )
        self.conn.commit()

    def disable_subject(self, config: OIDCProviderConfig, subject: str) -> None:
        self.conn.execute(
            "UPDATE oidc_principal_mappings SET active=0 WHERE provider_id=? AND issuer=? AND subject=?",
            (config.provider_id, config.issuer, subject),
        )
        self.conn.commit()

    def begin_login(self, config: OIDCProviderConfig) -> dict[str, Any]:
        nonce = "oidc_" + secrets.token_urlsafe(24)
        self.conn.execute(
            "INSERT INTO oidc_login_nonces(nonce,provider_id,created_at) VALUES(?,?,?)",
            (nonce, config.provider_id, utcnow().isoformat()),
        )
        self.conn.commit()
        return {"provider_id": config.provider_id, "nonce": nonce, "issuer": config.issuer, "audience": config.audience}

    @staticmethod
    def _audience_matches(claim: Any, expected: str) -> bool:
        if isinstance(claim, str):
            return claim == expected
        if isinstance(claim, list):
            return expected in claim
        return False

    def complete_login(
        self,
        config: OIDCProviderConfig,
        provider: VerifiedOIDCProvider,
        id_token: str,
        nonce: str,
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        claims = provider.verify_id_token(id_token)
        if claims.get("iss") != config.issuer:
            raise HardeningError("CFHS_UNAUTHENTICATED", "OIDC issuer mismatch")
        if not self._audience_matches(claims.get("aud"), config.audience):
            raise HardeningError("CFHS_UNAUTHENTICATED", "OIDC audience mismatch")
        if claims.get("nonce") != nonce:
            raise HardeningError("CFHS_UNAUTHENTICATED", "OIDC nonce mismatch")
        subject = str(claims.get("sub", ""))
        if not subject:
            raise HardeningError("CFHS_UNAUTHENTICATED", "OIDC subject missing")
        try:
            exp = datetime.fromtimestamp(float(claims.get("exp")), timezone.utc)
        except (TypeError, ValueError, OSError):
            raise HardeningError("CFHS_UNAUTHENTICATED", "OIDC expiration missing or invalid")
        if exp <= utcnow():
            raise HardeningError("CFHS_UNAUTHENTICATED", "OIDC token expired")

        requested = int(ttl_seconds or config.max_session_seconds)
        ttl = max(60, min(requested, config.max_session_seconds))
        session_token = "cks_" + secrets.token_urlsafe(32)
        session_id = "sess_" + secrets.token_hex(10)
        created = utcnow()
        expires = created + timedelta(seconds=ttl)

        try:
            self.conn.execute("BEGIN IMMEDIATE")
            nonce_row = self.conn.execute(
                "SELECT provider_id,consumed_at FROM oidc_login_nonces WHERE nonce=?",
                (nonce,),
            ).fetchone()
            if not nonce_row or nonce_row["provider_id"] != config.provider_id or nonce_row["consumed_at"]:
                raise HardeningError("CFHS_UNAUTHENTICATED", "OIDC nonce is unknown or already consumed")
            mapping = self.conn.execute(
                "SELECT principal_id,active FROM oidc_principal_mappings WHERE provider_id=? AND issuer=? AND subject=?",
                (config.provider_id, config.issuer, subject),
            ).fetchone()
            if not mapping or not mapping["active"]:
                raise HardeningError("CFHS_POLICY_DENIED", "External identity is not mapped to an active Company Kernel principal")
            self.conn.execute(
                "INSERT INTO kernel_sessions(id,principal_id,token_hash,created_at,expires_at) VALUES(?,?,?,?,?)",
                (session_id, mapping["principal_id"], token_hash(session_token), created.isoformat(), expires.isoformat()),
            )
            updated = self.conn.execute(
                "UPDATE oidc_login_nonces SET consumed_at=? WHERE nonce=? AND consumed_at IS NULL",
                (created.isoformat(), nonce),
            )
            if updated.rowcount != 1:
                raise HardeningError("CFHS_CONFLICT", "OIDC nonce consumption conflict")
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        return {
            "session_id": session_id,
            "principal_id": mapping["principal_id"],
            "bearer_token": session_token,
            "expires_at": expires.isoformat(),
            "external_identity": {
                "provider_id": config.provider_id,
                "issuer": config.issuer,
                "subject": subject,
            },
        }


class StaticVerifiedClaimsProvider:
    """Test-only provider; treats supplied claim dictionary as already verified."""

    def __init__(self, claims: dict[str, Any]):
        self.claims = dict(claims)

    def verify_id_token(self, _id_token: str) -> dict[str, Any]:
        return dict(self.claims)
