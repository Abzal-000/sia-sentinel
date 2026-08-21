from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any, Optional

from .evidence_store import EvidenceStore
from .github_client import GitHubClient, format_evidence_as_markdown
from .policy_engine import PolicyEngine


class WebhookHandler:
    """
    Handles GitHub webhook events for pull request verification.
    """

    def __init__(
        self,
        github_client: GitHubClient,
        evidence_store: EvidenceStore,
        policy_engine: PolicyEngine,
        webhook_secret: Optional[str] = None,
    ):
        self.github = github_client
        self.evidence_store = evidence_store
        self.policy_engine = policy_engine
        self.webhook_secret = webhook_secret or os.getenv("GITHUB_WEBHOOK_SECRET")

        # Import here to avoid circular dependency
        from .api import guard, _get_trust_manager
        self.guard = guard
        self._get_trust_manager = _get_trust_manager

    def verify_signature(
        self,
        payload_body: bytes,
        signature_header: Optional[str],
    ) -> bool:
        """
        Verify GitHub webhook signature.

        Args:
            payload_body: Raw request body
            signature_header: X-Hub-Signature-256 header value

        Returns:
            True if signature is valid
        """
        if not self.webhook_secret:
            # Fail-closed (H4): без настроенного секрета подлинность
            # отправителя проверить нельзя — отклоняем, а не пропускаем.
            return False

        if not signature_header:
            return False

        # Expected format: sha256=<hex>
        if not signature_header.startswith("sha256="):
            return False

        expected_signature = signature_header[7:]  # Remove "sha256=" prefix

        # Compute HMAC
        computed_signature = hmac.new(
            self.webhook_secret.encode("utf-8"),
            payload_body,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(expected_signature, computed_signature)

    def handle_pull_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Handle pull_request webhook event.

        Args:
            payload: GitHub webhook payload

        Returns:
            Processing result
        """
        action = payload.get("action")

        # Only process opened and synchronize events
        if action not in ("opened", "synchronize", "reopened"):
            return {"status": "skipped", "reason": f"action_{action}_not_processed"}

        pr = payload.get("pull_request", {})
        repo = payload.get("repository", {})

        owner = repo.get("owner", {}).get("login")
        repo_name = repo.get("name")
        pr_number = pr.get("number")
        sha = pr.get("head", {}).get("sha")

        if not all([owner, repo_name, pr_number, sha]):
            return {"status": "error", "reason": "missing_pr_data"}

        # Set pending status
        try:
            self.github.create_status(
                owner=owner,
                repo=repo_name,
                sha=sha,
                state="pending",
                description="SIA Sentinel is verifying changes...",
                context="SIA Sentinel",
            )
        except Exception as exc:
            return {"status": "error", "reason": f"status_update_failed: {exc}"}

        # Extract agent_id from PR metadata or use default
        agent_id = self._extract_agent_id(pr)

        # Get PR diff and extract code changes
        try:
            diff = self.github.get_pr_diff(owner, repo_name, pr_number)
        except Exception as exc:
            self._set_failure_status(owner, repo_name, sha, f"Failed to get diff: {exc}")
            return {"status": "error", "reason": f"diff_fetch_failed: {exc}"}

        # Parse diff and verify changes
        verification_results = self._verify_pr_changes(
            owner=owner,
            repo=repo_name,
            pr_number=pr_number,
            agent_id=agent_id,
            diff=diff,
        )

        # Determine overall status
        all_approved = all(r.get("approved") for r in verification_results)

        if all_approved:
            state = "success"
            description = "All changes verified and approved"
        else:
            state = "failure"
            description = "Some changes failed verification"

        # Update status
        try:
            self.github.create_status(
                owner=owner,
                repo=repo_name,
                sha=sha,
                state=state,
                description=description,
                context="SIA Sentinel",
            )
        except Exception as exc:
            return {"status": "error", "reason": f"final_status_failed: {exc}"}

        # Post summary comment
        try:
            summary = self._format_summary_comment(verification_results)
            self.github.post_comment(owner, repo_name, pr_number, summary)
        except Exception as exc:
            return {"status": "error", "reason": f"comment_post_failed: {exc}"}

        return {
            "status": "processed",
            "pr_number": pr_number,
            "files_checked": len(verification_results),
            "all_approved": all_approved,
        }

    def _extract_agent_id(self, pr: dict[str, Any]) -> str:
        """Extract agent_id from PR metadata or generate default."""
        # Try to get from PR body or labels
        body = pr.get("body", "") or ""

        # Look for pattern like "SIA-Agent: agent-123"
        match = re.search(r"SIA-Agent:\s*([a-zA-Z0-9_-]+)", body)
        if match:
            return match.group(1)

        # Default to PR author
        author = pr.get("user", {}).get("login", "unknown")
        return f"github-{author}"

    def _verify_pr_changes(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        agent_id: str,
        diff: str,
    ) -> list[dict[str, Any]]:
        """
        Verify code changes in PR diff.

        This is a simplified version that extracts Python files from diff.
        In production, you'd want more sophisticated diff parsing.
        """
        results = []

        # Simple diff parser: extract file paths and added lines
        file_pattern = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)
        files = file_pattern.findall(diff)

        for file_path in files:
            if not file_path.endswith(".py"):
                continue

            # Extract added lines (simplified)
            added_lines = self._extract_added_lines(diff, file_path)

            if not added_lines:
                continue

            # Create verification request
            current_code = ""  # In production, fetch from base branch
            proposed_code = "\n".join(added_lines)

            # Run verification
            try:
                result = self._verify_single_file(
                    agent_id=agent_id,
                    target_path=file_path,
                    current_code=current_code,
                    proposed_code=proposed_code,
                )

                results.append({
                    "file": file_path,
                    "approved": result.get("decision", {}).get("approved", False),
                    "evidence": result,
                })

                # Post individual comment for this file if failed
                if not result.get("decision", {}).get("approved"):
                    comment = format_evidence_as_markdown(result)
                    comment = f"### ⚠️ Verification failed for `{file_path}`\n\n{comment}"
                    # Don't post individual comments to avoid spam
                    # self.github.post_comment(owner, repo, pr_number, comment)

            except Exception as exc:
                results.append({
                    "file": file_path,
                    "approved": False,
                    "error": str(exc),
                })

        return results

    def _extract_added_lines(self, diff: str, file_path: str) -> list[str]:
        """Extract added lines from diff for a specific file."""
        lines: list[str] = []

        # Find the section for this file
        file_section_pattern = re.compile(
            rf"^\+\+\+ b/{re.escape(file_path)}\n(.*?)(?=^\+\+\+ b/|\Z)",
            re.MULTILINE | re.DOTALL,
        )

        match = file_section_pattern.search(diff)
        if not match:
            return lines

        section = match.group(1)

        # Extract lines starting with +
        for line in section.split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                lines.append(line[1:])  # Remove leading +

        return lines

    def _verify_single_file(
        self,
        agent_id: str,
        target_path: str,
        current_code: str,
        proposed_code: str,
    ) -> dict[str, Any]:
        """Verify a single file change."""
        import datetime
        import uuid

        from sia.models import Task

        trust_manager = self._get_trust_manager(agent_id)

        task = Task(
            description=f"PR change in {target_path}",
            target_path=target_path,
            current_code=current_code,
            allowed_paths=(target_path,),
        )

        # Trust decision
        trust_decision = trust_manager.can_modify(task)

        # Safety check
        safety_result = self.guard.check(proposed_code)
        safety_approved = bool(getattr(safety_result, "approved", False))
        violations = list(getattr(safety_result, "violations", []))
        warnings = list(getattr(safety_result, "warnings", []))

        # Policy assessment
        risk_assessment = self.policy_engine.assess_risk(
            agent_id=agent_id,
            target_path=target_path,
            current_code=current_code,
            proposed_code=proposed_code,
        )

        # Combine decisions
        approved = bool(
            trust_decision.allowed
            and safety_approved
            and risk_assessment.recommendation != "block"
        )

        reason = None
        if not trust_decision.allowed:
            reason = getattr(trust_decision, "reason", "trust_denied")
        elif not safety_approved:
            reason = "; ".join(violations) or "safety_violation"
        elif risk_assessment.recommendation == "block":
            reason = f"policy_blocked: {', '.join(risk_assessment.matched_rules)}"

        # Update trust
        if approved:
            trust_manager.record_success(task)
        else:
            trust_manager.record_failure(task, reason or "verification_failed")

        # Build evidence
        evidence = {
            "evidence_id": str(uuid.uuid4()),
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "agent_id": agent_id,
            "artifact_hashes": {
                "current_code_sha256": hashlib.sha256(current_code.encode("utf-8")).hexdigest(),
                "proposed_code_sha256": hashlib.sha256(proposed_code.encode("utf-8")).hexdigest(),
            },
            "trust": {
                "level": trust_manager.level.name,
                "allowed": bool(trust_decision.allowed),
                "reason": getattr(trust_decision, "reason", None),
                "success_streak": trust_manager.success_streak,
                "failure_streak": trust_manager.failure_streak,
            },
            "safety": {
                "approved": safety_approved,
                "violations": violations,
                "warnings": warnings,
            },
            "policy": {
                "risk_score": risk_assessment.risk_score,
                "risk_level": risk_assessment.risk_level,
                "matched_rules": risk_assessment.matched_rules,
                "warnings": risk_assessment.warnings,
                "requires_human_review": risk_assessment.requires_human_review,
                "recommendation": risk_assessment.recommendation,
            },
            "decision": {
                "approved": approved,
                "reason": reason,
            },
        }

        return self.evidence_store.store(evidence)

    def _format_summary_comment(
        self,
        results: list[dict[str, Any]],
    ) -> str:
        """Format summary comment for PR."""
        total = len(results)
        approved = sum(1 for r in results if r.get("approved"))
        failed = total - approved

        if failed == 0:
            emoji = "✅"
            status = "All checks passed"
        else:
            emoji = "❌"
            status = f"{failed} file(s) failed verification"

        lines = [
            f"## {emoji} SIA Sentinel Verification Summary",
            "",
            f"**Status:** {status}",
            f"**Files checked:** {total}",
            f"**Approved:** {approved}",
            f"**Failed:** {failed}",
            "",
        ]

        if failed > 0:
            lines.extend([
                "### ❌ Failed Files",
                "",
            ])

            for result in results:
                if not result.get("approved"):
                    file_path = result.get("file", "unknown")
                    evidence = result.get("evidence", {})
                    reason = evidence.get("decision", {}).get("reason", "Unknown reason")

                    lines.append(f"- **`{file_path}`**: {reason}")

            lines.extend([
                "",
                "<details>",
                "<summary>📋 Detailed Reports</summary>",
                "",
            ])

            for result in results:
                if not result.get("approved"):
                    evidence = result.get("evidence", {})
                    lines.append(format_evidence_as_markdown(evidence))
                    lines.append("\n---\n")

            lines.append("</details>")
        else:
            lines.extend([
                "### ✅ All Files Approved",
                "",
                "All code changes have passed safety, policy, and trust checks.",
            ])

        lines.extend([
            "",
            "---",
            "",
            "*Generated by SIA Sentinel — Proof-of-Savings Protocol*",
        ])

        return "\n".join(lines)

    def _set_failure_status(
        self,
        owner: str,
        repo: str,
        sha: str,
        description: str,
    ) -> None:
        """Set failure status on commit."""
        try:
            self.github.create_status(
                owner=owner,
                repo=repo,
                sha=sha,
                state="error",
                description=description[:140],
                context="SIA Sentinel",
            )
        except Exception:
            pass  # Ignore status update failures
