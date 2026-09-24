from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any, Optional

from sia.config import resolve_env


class EvidenceStore:
    """
    Persistent evidence storage with HMAC signing.

    Stores verifications in JSONL format with cryptographic signatures
    to ensure integrity and prevent tampering.
    """

    def __init__(
        self,
        evidence_dir: Optional[str] = None,
        signing_key: Optional[str] = None,
    ):
        # D13: каталог настраивается через EVIDENCE_DIR (в проде — на томе)
        self.evidence_dir = Path(evidence_dir or os.getenv("EVIDENCE_DIR") or "evidence")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # Use environment/.env variable or provided key (resolve_env, как
        # у всех секретов проекта — сырой getenv молча игнорировал .env)
        resolved_key = signing_key or resolve_env("EVIDENCE_SIGNING_KEY")

        if not resolved_key:
            # Эфемерный ключ: подписи не переживут рестарт.
            resolved_key = secrets.token_hex(32)
            print(
                "WARNING: EVIDENCE_SIGNING_KEY not set — generated an ephemeral key; "
                "evidence signatures will not survive restarts. "
                "Set EVIDENCE_SIGNING_KEY in production."
            )
        self.signing_key: str = resolved_key

    def _sign(self, data: dict[str, Any]) -> str:
        """Generate HMAC-SHA256 signature for evidence."""
        # Create deterministic JSON string (sorted keys)
        json_str = json.dumps(data, sort_keys=True, separators=(",", ":"))

        # Generate HMAC
        signature = hmac.new(
            self.signing_key.encode("utf-8"),
            json_str.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return signature

    def _get_evidence_file(self, agent_id: str) -> Path:
        """Get JSONL file path for agent."""
        safe_agent_id = self._safe_agent_id(agent_id)
        return self.evidence_dir / f"evidence_{safe_agent_id}.jsonl"

    def _safe_agent_id(self, agent_id: str) -> str:
        """Sanitize agent_id for file system."""
        safe = "".join(
            c if c.isalnum() or c in "-_" else "_"
            for c in str(agent_id)
            if ord(c) >= 32 and c not in '<>:"/\\|?*' and c != chr(0)
        )
        return safe or "unknown_agent"

    def store(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """
        Store evidence with signature.

        Args:
            evidence: Evidence dict without signature

        Returns:
            Evidence dict with signature added
        """
        # Add signature
        signature = self._sign(evidence)
        evidence["signature"] = signature

        # Get file path
        agent_id = evidence.get("agent_id", "unknown")
        evidence_file = self._get_evidence_file(agent_id)

        # Append to JSONL
        with open(evidence_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(evidence, ensure_ascii=False) + "\n")

        return evidence

    def verify(self, evidence: dict[str, Any]) -> bool:
        """
        Verify evidence signature.

        Args:
            evidence: Evidence dict with signature

        Returns:
            True if signature is valid
        """
        if "signature" not in evidence:
            return False

        # Extract signature
        stored_signature = evidence.pop("signature")

        # Recompute signature
        computed_signature = self._sign(evidence)

        # Restore signature in dict
        evidence["signature"] = stored_signature

        # Compare
        return hmac.compare_digest(stored_signature, computed_signature)

    def get_by_id(
        self,
        evidence_id: str,
        tenant_id: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """
        Retrieve evidence by ID.

        Args:
            evidence_id: UUID of evidence
            tenant_id: If provided, the evidence must belong to this tenant
                (multitenancy isolation). ``None`` means no tenant filter and is
                reserved for platform-admin/verifier internal use.

        Returns:
            Evidence dict or None
        """
        # Search all evidence files
        for evidence_file in self.evidence_dir.glob("evidence_*.jsonl"):
            with open(evidence_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        evidence = json.loads(line)
                        if evidence.get("evidence_id") != evidence_id:
                            continue
                        # Tenant isolation: a tenant-scoped read must not
                        # return another tenant's evidence. A record with no
                        # tenant tag is treated as belonging to no tenant and
                        # is therefore hidden from tenant-scoped reads.
                        if (
                            tenant_id is not None
                            and evidence.get("tenant_id", None) != tenant_id
                        ):
                            continue
                        return evidence
                    except json.JSONDecodeError:
                        continue

        return None

    def get_by_agent(
        self,
        agent_id: str,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve evidence for agent.

        Args:
            agent_id: Agent identifier
            limit: Maximum number of records
            tenant_id: If provided, only evidence belonging to this tenant is
                returned (multitenancy isolation).

        Returns:
            List of evidence dicts (newest first)
        """
        evidence_file = self._get_evidence_file(agent_id)

        if not evidence_file.exists():
            return []

        results = []

        with open(evidence_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    evidence = json.loads(line)
                    if (
                        tenant_id is not None
                        and evidence.get("tenant_id", None) != tenant_id
                    ):
                        continue
                    results.append(evidence)
                except json.JSONDecodeError:
                    continue

        # Return newest first, limited
        return list(reversed(results[-limit:]))

    def get_all(
        self,
        limit: int = 100,
        approved_only: bool = False,
        tenant_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve all evidence.

        Args:
            limit: Maximum number of records
            approved_only: If True, return only approved verifications
            tenant_id: If provided, only evidence belonging to this tenant is
                returned (multitenancy isolation).

        Returns:
            List of evidence dicts (newest first)
        """
        results = []

        for evidence_file in self.evidence_dir.glob("evidence_*.jsonl"):
            with open(evidence_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        evidence = json.loads(line)

                        if tenant_id is not None and evidence.get(
                            "tenant_id", None
                        ) != tenant_id:
                            continue

                        if approved_only and not evidence.get("decision", {}).get("approved"):
                            continue

                        results.append(evidence)
                    except json.JSONDecodeError:
                        continue

        # Sort by created_at descending
        results.sort(key=lambda e: e.get("created_at", ""), reverse=True)

        return results[:limit]
