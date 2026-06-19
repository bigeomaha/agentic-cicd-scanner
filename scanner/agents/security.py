"""
Security agent — SAST scanning.

Tools:
  - Semgrep  : OWASP Top 10 rules, multi-language
  - Bandit   : Python-specific security AST analysis

The LLM interprets combined findings in plain language for non-developers.
"""
import json
import logging
from typing import Any

from scanner.base_agent import BaseAgent
from scanner import llm

logger = logging.getLogger(__name__)


class SecurityAgent(BaseAgent):
    agent_id = "security"
    category = "security"

    # Semgrep rule packs to run (pre-warmed in Docker image)
    SEMGREP_CONFIGS = [
        "p/owasp-top-ten",
        "p/secrets",         # belt-and-suspenders alongside gitleaks
        "p/python",
        "p/javascript",
        "p/typescript",
    ]

    def _collect(self) -> tuple[Any, dict]:
        languages  = self.context.get("languages", {})
        unsupported = self.context.get("semgrep_unsupported", [])

        # Only run if we have code Semgrep understands
        code_langs = [l for l in languages if l not in ("jupyter",)]
        if not code_langs:
            return self._skipped_envelope("No supported source files found.")

        semgrep_findings = self._run_semgrep()
        bandit_findings  = self._run_bandit() if "python" in languages else []

        all_findings = semgrep_findings + bandit_findings
        total_files = sum(languages.values())

        return all_findings, {
            "tool":                 "semgrep + bandit",
            "files_scanned":        total_files,
            "languages_scanned":    code_langs,
            "languages_unsupported": unsupported,
            "semgrep_count":        len(semgrep_findings),
            "bandit_count":         len(bandit_findings),
        }

    def _interpret(self, raw_data: Any, metadata: dict) -> dict:
        if metadata.get("skipped"):
            return self._skipped_result(metadata.get("skip_reason", ""))

        if not raw_data:
            return {
                "findings": [],
                "summary": "No security issues detected by Semgrep or Bandit. Good start!",
                "status": "pass",
                "score": 100,
            }

        unsupported = metadata.get("languages_unsupported", [])
        extra = ""
        if unsupported:
            extra = (
                f"Note: the following languages are present but not fully covered "
                f"by these tools: {', '.join(unsupported)}. "
                f"Flag this in your summary."
            )

        prompt = llm.build_findings_prompt(
            agent_name="Security (SAST)",
            tool_name="Semgrep + Bandit",
            raw_findings=raw_data[:60],   # cap at 60 findings to manage tokens
            extra_context=extra,
        )

        result = llm.interpret_as_json(prompt)
        return result if result else self._fallback(raw_data)

    # ── Tool runners ──────────────────────────────────────────────────────────

    def _run_semgrep(self) -> list[dict]:
        configs = " ".join(f"--config {c}" for c in self.SEMGREP_CONFIGS)
        cmd = [
            "semgrep",
            "--json",
            "--quiet",
            "--no-rewrite-rule-ids",
            *[item for c in self.SEMGREP_CONFIGS for item in ("--config", c)],
            self.repo_path,
        ]
        stdout, stderr, rc = self._run_tool(cmd, timeout=180)

        if not stdout:
            logger.debug(f"[security] Semgrep no output. stderr: {stderr[:200]}")
            return []

        try:
            data = json.loads(stdout)
            results = data.get("results", [])
            return [
                {
                    "source":   "semgrep",
                    "rule":     r.get("check_id", "unknown"),
                    "file":     r.get("path", ""),
                    "line":     r.get("start", {}).get("line"),
                    "message":  r.get("extra", {}).get("message", r.get("message", "")),
                    "severity": _semgrep_severity(r.get("extra", {}).get("severity", "INFO")),
                }
                for r in results
            ]
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(f"[security] Failed to parse Semgrep output: {exc}")
            return []

    def _run_bandit(self) -> list[dict]:
        cmd = [
            "bandit",
            "-r", self.repo_path,
            "-f", "json",
            "-q",
        ]
        stdout, stderr, rc = self._run_tool(cmd, timeout=120)

        # Bandit exits 1 when issues found — that's normal
        if not stdout:
            return []

        try:
            data = json.loads(stdout)
            return [
                {
                    "source":   "bandit",
                    "rule":     r.get("test_id", ""),
                    "file":     r.get("filename", "").replace(self.repo_path + "/", ""),
                    "line":     r.get("line_number"),
                    "message":  r.get("issue_text", ""),
                    "severity": r.get("issue_severity", "MEDIUM").lower(),
                }
                for r in data.get("results", [])
            ]
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(f"[security] Failed to parse Bandit output: {exc}")
            return []

    def _fallback(self, raw_data: list) -> dict:
        """Minimal result if LLM call fails."""
        count = len(raw_data)
        return {
            "findings": [
                {"severity": f.get("severity", "medium"), "rule": f.get("rule", ""),
                 "file": f.get("file", ""), "line": f.get("line"),
                 "message": f.get("message", ""), "suggestion": "Review this finding manually."}
                for f in raw_data[:20]
            ],
            "summary": f"{count} security finding(s) detected. LLM interpretation unavailable.",
            "status": "warn" if count > 0 else "pass",
            "score": max(0, 80 - count * 5),
        }


def _semgrep_severity(raw: str) -> str:
    return {"ERROR": "high", "WARNING": "medium", "INFO": "info"}.get(raw.upper(), "low")
