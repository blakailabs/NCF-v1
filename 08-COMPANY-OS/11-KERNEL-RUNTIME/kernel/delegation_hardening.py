from __future__ import annotations

import json
import sqlite3
from typing import Any

from .hardening import HardeningError
from .trust import CapabilityBoundingEngine, sha256_hex


class RecursiveDelegationVerifier:
    """Verifies durable delegation provenance from a process back to its root."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _process(self, process_id: str):
        row = self.conn.execute(
            "SELECT id,owner,parent_id,metadata_json FROM processes WHERE id=?",
            (process_id,),
        ).fetchone()
        if not row:
            raise HardeningError("CFHS_NOT_FOUND", "Delegation process not found", {"process_id": process_id})
        return row

    def _proof(self, child_process_id: str):
        return self.conn.execute(
            "SELECT * FROM delegation_proofs WHERE child_process_id=?",
            (child_process_id,),
        ).fetchone()

    @staticmethod
    def _proof_digest(row) -> str:
        proof_base = {
            "parent_process_id": row["parent_process_id"],
            "delegator_id": row["delegator_id"],
            "delegate_id": row["delegate_id"],
            "capabilities": json.loads(row["capabilities_json"]),
            "created_at": row["created_at"],
        }
        return sha256_hex(proof_base)

    def verify_chain(self, process_id: str, max_depth: int = 32) -> dict[str, Any]:
        visited: set[str] = set()
        chain: list[dict[str, Any]] = []
        current_id = process_id
        child_bounds: list[dict[str, Any]] | None = None

        for depth in range(max_depth + 1):
            if current_id in visited:
                raise HardeningError("CFHS_CONFLICT", "Delegation cycle detected", {"process_id": current_id})
            visited.add(current_id)
            process = self._process(current_id)
            metadata = json.loads(process["metadata_json"])
            current_bounds = metadata.get("capability_bounds")
            if current_bounds is not None and not isinstance(current_bounds, list):
                raise HardeningError("CFHS_CONFLICT", "Process capability bounds are malformed", {"process_id": current_id})

            parent_id = process["parent_id"]
            proof = self._proof(current_id)

            if parent_id is None:
                if proof:
                    raise HardeningError("CFHS_CONFLICT", "Root process unexpectedly has a delegation proof", {"process_id": current_id})
                chain.append({"process_id": current_id, "owner": process["owner"], "root": True})
                return {"valid": True, "depth": len(chain) - 1, "chain": list(reversed(chain))}

            if not proof:
                raise HardeningError("CFHS_CONFLICT", "Child process is missing delegation proof", {"process_id": current_id})
            if proof["parent_process_id"] != parent_id:
                raise HardeningError("CFHS_CONFLICT", "Delegation proof parent differs from process parent", {"process_id": current_id})
            if proof["delegate_id"] != process["owner"]:
                raise HardeningError("CFHS_CONFLICT", "Delegation proof delegate differs from process owner", {"process_id": current_id})

            claimed_digest = str(proof["proof_digest"])
            calculated_digest = self._proof_digest(proof)
            if claimed_digest != calculated_digest:
                raise HardeningError("CFHS_CONFLICT", "Delegation proof digest mismatch", {"process_id": current_id})
            if metadata.get("delegation_digest") != claimed_digest:
                raise HardeningError("CFHS_CONFLICT", "Process metadata delegation digest mismatch", {"process_id": current_id})

            proof_caps = json.loads(proof["capabilities_json"])
            if current_bounds != proof_caps:
                raise HardeningError("CFHS_CONFLICT", "Process bounds differ from delegation proof", {"process_id": current_id})

            if child_bounds is not None:
                CapabilityBoundingEngine.assert_bounded(current_bounds or [], child_bounds)

            parent = self._process(parent_id)
            parent_metadata = json.loads(parent["metadata_json"])
            parent_bounds = parent_metadata.get("capability_bounds")
            if parent_bounds is not None:
                CapabilityBoundingEngine.assert_bounded(parent_bounds, current_bounds or [])

            chain.append(
                {
                    "process_id": current_id,
                    "owner": process["owner"],
                    "parent_process_id": parent_id,
                    "proof_id": proof["id"],
                    "proof_digest": claimed_digest,
                    "capability_count": len(current_bounds or []),
                }
            )
            child_bounds = current_bounds or []
            current_id = parent_id

        raise HardeningError("CFHS_RESOURCE_EXHAUSTED", "Delegation chain exceeds maximum verification depth", {"max_depth": max_depth})
