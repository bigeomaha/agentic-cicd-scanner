"""
Dockerfile lint agent.

Tool: Hadolint

Only runs when a Dockerfile is present in the repo root.
Catches common Dockerfile mistakes: running as root, using :latest tags,
insecure patterns, inefficient layer ordering, etc.
"""
import json
import logging
from pathlib import Path
from typing import Any

from scanner.base_agent import BaseAgent
from scanner import llm

logger = logging.getLogger(__name__)

HADOLINT_SEVERITY_MAP = {
    "error":   "high",
    "warning": "medium",
    "info":    "low",
    "style":   "info",
}


class DockerfileLintAgent(BaseAgent):
    agent_id = "dockerfile_lint"
    category = "quality"

    def _collect(self) -> tuple[Any, dict]:
        repo = Path(self.repo_path)

        # Find all Dockerfiles (including Dockerfile.dev, Dockerfile.prod, etc.)
        dockerfiles = (
            [str(repo / "Dockerfile")]
            + [str(p) for p in repo.glob("Dockerfile.*")]
            + [str(p) for p in repo.glob("**/Dockerfile") if p != repo / "Dockerfile"]
        )
        dockerfiles = [d for d in dockerfiles if Path(d).exists()]

        if not dockerfiles:
            return self._skipped_envelope("No Dockerfile found.")

        all_findings: list[dict] = []
        for df in dockerfiles:
            all_findings.extend(self._run_hadolint(df))

        return all_findings, {
            "tool":                  "hadolint",
            "files_scanned":         len(dockerfiles),
            "dockerfiles_found":     [Path(d).name for d in dockerfiles],
            "languages_scanned":     ["dockerfile"],
            "languages_unsupported": [],
        }

    def _interpret(self, raw_data: Any, metadata: dict) -> dict:
        if metadata.get("skipped"):
            return self._skipped_result(metadata.get("skip_reason", ""))

        if not raw_data:
            return {
                "findings": [],
                "summary":  "Dockerfile follows best practices. No issues detected by Hadolint.",
                "status":   "pass",
                "score":    100,
            }

        prompt = llm.build_findings_prompt(
            agent_name="Dockerfile Linter",
            tool_name="Hadolint",
            raw_findings=raw_data,
            extra_context=(
                "These are Dockerfile linting issues. Explain each in plain language, "
                "including WHY it matters (security, image size, reproducibility, or reliability). "
                "Key issues to highlight: running as root (security risk), "
                "using :latest tags (reproducibility risk), "
                "not using --no-install-recommends (bloated image), "
                "using ADD instead of COPY (unexpected behaviour), "
                "secrets passed as ENV or ARG (security risk)."
            ),
        )

        result = llm.interpret_as_json(prompt)
        return result if result else self._fallback(raw_data)

    # ── Tool runner ───────────────────────────────────────────────────────────

    def _run_hadolint(self, dockerfile_path: str) -> list[dict]:
        cmd = [
            "hadolint",
            "--format", "json",
            dockerfile_path,
        ]
        stdout, stderr, _ = self._run_tool(cmd, timeout=30, cwd=self.repo_path)

        if not stdout:
            logger.debug(f"[dockerfile_lint] Hadolint no output for {dockerfile_path}: {stderr[:100]}")
            return []

        try:
            issues = json.loads(stdout)
            rel_path = str(Path(dockerfile_path).relative_to(self.repo_path))
            return [
                {
                    "source":   "hadolint",
                    "rule":     i.get("code", ""),
                    "file":     rel_path,
                    "line":     i.get("line"),
                    "message":  i.get("message", ""),
                    "severity": HADOLINT_SEVERITY_MAP.get(i.get("level", "info"), "info"),
                }
                for i in issues
            ]
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(f"[dockerfile_lint] Hadolint parse error for {dockerfile_path}: {exc}")
            return []

    def _fallback(self, raw_data: list) -> dict:
        errors = sum(1 for f in raw_data if f.get("severity") in ("high", "critical"))
        return {
            "findings": [
                {"severity": f.get("severity", "medium"), "rule": f.get("rule", ""),
                 "file": f.get("file", "Dockerfile"), "line": f.get("line"),
                 "message": f.get("message", ""), "suggestion": "Consult Hadolint documentation for this rule."}
                for f in raw_data
            ],
            "summary": f"{len(raw_data)} Dockerfile issue(s) found ({errors} errors). Address errors before deployment.",
            "status":  "fail" if errors > 0 else "warn",
            "score":   max(50, 90 - errors * 15 - len(raw_data) * 2),
        }
