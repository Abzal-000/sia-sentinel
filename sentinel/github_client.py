from __future__ import annotations

import os
from typing import Any, Optional

import requests

# Таймаут по умолчанию для ВСЕХ вызовов GitHub API. Без него зависший
# TCP-коннект (молчащий прокси, сетевой чёрный дырой) блокирует поток
# воркера/обработчика вебхука бесконечно — доступность сервиса зависит от
# чужого API. (connect, read) — connect ограничивает установление соединения,
# read — ожидание ответа.
DEFAULT_TIMEOUT = (5.0, 15.0)


class GitHubClient:
    """
    GitHub API client for posting comments and status checks.

    Uses GitHub App installation token or personal access token.

    Every request carries an explicit timeout (DEFAULT_TIMEOUT) and retries
    transient failures (429/5xx/network) with bounded backoff, so a flaky or
    hanging GitHub never stalls the audit worker indefinitely.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        api_base: str = "https://api.github.com",
        timeout: tuple[float, float] = DEFAULT_TIMEOUT,
        max_retries: int = 2,
    ):
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))

        if not self.token:
            raise ValueError(
                "GitHub token not provided. Set GITHUB_TOKEN environment variable."
            )

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SIA-Sentinel/0.4.0",
        })

    def _request(
        self,
        method: str,
        url: str,
        *,
        retry: bool = True,
        **kwargs: Any,
    ) -> requests.Response:
        """HTTP-вызов с таймаутом и ограниченными повторами на 429/5xx/сети.

        Повторяются только идемпотентные по смыслу запросы (GET, и POST, который
        не меняет состояние дважды опасно); здесь retry=True используется для
        GET, а для POST оставлен один безопасный повтор на 5xx/429, где запрос
        скорее всего не был применён.
        """
        import time

        attempts = (self.max_retries + 1) if retry else 1
        last_exc: Optional[BaseException] = None

        for attempt in range(attempts):
            try:
                response = self.session.request(
                    method, url, timeout=self.timeout, **kwargs
                )
            except requests.RequestException as exc:
                # Сетевой сбой/таймаут — повторяем с задержкой.
                last_exc = exc
                if attempt == attempts - 1:
                    raise
                time.sleep(0.5 * (2**attempt))
                continue

            # 429/5xx и идемпотентный GET — безопасны к повтору.
            if response.status_code in (429, 500, 502, 503, 504):
                if attempt < attempts - 1:
                    retry_after = response.headers.get("Retry-After")
                    try:
                        delay = float(retry_after) if retry_after else 0.5 * (2**attempt)
                    except ValueError:
                        delay = 0.5 * (2**attempt)
                    time.sleep(min(delay, 5.0))
                    continue

            return response

        # Сюда попадаем только если все попытки исчерпаны исключением.
        if last_exc is not None:
            raise last_exc
        raise requests.RequestException("GitHub request failed")

    def post_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
    ) -> dict[str, Any]:
        """
        Post a comment on a pull request.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number
            body: Comment body (Markdown supported)

        Returns:
            Comment data from GitHub API
        """
        url = f"{self.api_base}/repos/{owner}/{repo}/issues/{pr_number}/comments"

        response = self._request("POST", url, json={"body": body})

        response.raise_for_status()
        return response.json()

    def create_status(
        self,
        owner: str,
        repo: str,
        sha: str,
        state: str,
        description: str,
        context: str = "SIA Sentinel",
        target_url: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Create a commit status check.

        Args:
            owner: Repository owner
            repo: Repository name
            sha: Commit SHA
            state: "pending", "success", "failure", or "error"
            description: Short description
            context: Status check name
            target_url: Optional URL for details

        Returns:
            Status data from GitHub API
        """
        url = f"{self.api_base}/repos/{owner}/{repo}/statuses/{sha}"

        payload = {
            "state": state,
            "description": description[:140],  # GitHub limit
            "context": context,
        }

        if target_url:
            payload["target_url"] = target_url

        response = self._request("POST", url, json=payload)
        response.raise_for_status()
        return response.json()

    def get_pr_diff(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> str:
        """
        Get pull request diff.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number

        Returns:
            Diff as string
        """
        url = f"{self.api_base}/repos/{owner}/{repo}/pulls/{pr_number}"

        response = self._request(
            "GET",
            url,
            headers={"Accept": "application/vnd.github.v3.diff"},
        )

        response.raise_for_status()
        return response.text

    def get_pr_info(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> dict[str, Any]:
        """
        Get pull request information.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number

        Returns:
            PR data from GitHub API
        """
        url = f"{self.api_base}/repos/{owner}/{repo}/pulls/{pr_number}"

        response = self._request("GET", url)
        response.raise_for_status()
        return response.json()


def format_evidence_as_markdown(evidence: dict[str, Any]) -> str:
    """
    Format evidence as GitHub-flavored Markdown comment.

    Args:
        evidence: Evidence dict from verification

    Returns:
        Markdown string
    """
    decision = evidence.get("decision", {})
    safety = evidence.get("safety", {})
    policy = evidence.get("policy", {})
    trust = evidence.get("trust", {})

    # Status emoji
    if decision.get("approved"):
        status_emoji = "✅"
        status_text = "APPROVED"
    else:
        status_emoji = "❌"
        status_text = "BLOCKED"

    # Risk level emoji
    risk_level = policy.get("risk_level", "unknown")
    risk_emoji = {
        "low": "🟢",
        "medium": "🟡",
        "high": "🟠",
        "critical": "🔴",
    }.get(risk_level, "⚪")

    # Build markdown
    lines = [
        f"## {status_emoji} SIA Sentinel: {status_text}",
        "",
        f"**Evidence ID:** `{evidence.get('evidence_id', 'N/A')}`",
        f"**Agent:** `{evidence.get('agent_id', 'N/A')}`",
        f"**Timestamp:** {evidence.get('created_at', 'N/A')}",
        "",
        "---",
        "",
        "### 🛡️ Safety Check",
        "",
        f"- **Status:** {'✅ Passed' if safety.get('approved') else '❌ Failed'}",
    ]

    violations = safety.get("violations", [])
    if violations:
        lines.append("- **Violations:**")
        for v in violations:
            lines.append(f"  - `{v}`")

    lines.extend([
        "",
        "### 📊 Policy Assessment",
        "",
        f"- **Risk Score:** {policy.get('risk_score', 0)}/100 {risk_emoji}",
        f"- **Risk Level:** `{risk_level}`",
        f"- **Recommendation:** `{policy.get('recommendation', 'N/A')}`",
    ])

    matched_rules = policy.get("matched_rules", [])
    if matched_rules:
        lines.append("- **Matched Rules:**")
        for rule in matched_rules:
            lines.append(f"  - `{rule}`")

    warnings = policy.get("warnings", [])
    if warnings:
        lines.append("- **Warnings:**")
        for w in warnings:
            lines.append(f"  - {w}")

    lines.extend([
        "",
        "### 🔐 Trust Level",
        "",
        f"- **Level:** `{trust.get('level', 'N/A')}`",
        f"- **Success Streak:** {trust.get('success_streak', 0)}",
        f"- **Failure Streak:** {trust.get('failure_streak', 0)}",
    ])

    if decision.get("reason"):
        lines.extend([
            "",
            "### 📝 Reason",
            "",
            "```",
            decision["reason"],
            "```",
        ])

    lines.extend([
        "",
        "---",
        "",
        "<details>",
        "<summary>🔍 Artifact Hashes</summary>",
        "",
        "```",
        f"Current Code SHA256:  {evidence.get('artifact_hashes', {}).get('current_code_sha256', 'N/A')}",
        f"Proposed Code SHA256: {evidence.get('artifact_hashes', {}).get('proposed_code_sha256', 'N/A')}",
        "```",
        "",
        "</details>",
        "",
        f"**Signature:** `{evidence.get('signature', 'N/A')[:32]}...`",
        "",
        "---",
        "",
        "*Generated by SIA Sentinel — Proof-of-Savings Protocol*",
    ])

    return "\n".join(lines)
