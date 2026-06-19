"""
Secrets agent — credential and secret detection.

Tools:
  - Gitleaks : pattern-based secret scanning across all file types
  - Semgrep  : p/secrets ruleset as a second pass

Scans every file regardless of language — secrets can appear anywhere.
"""
import json
import logging
import tempfile
import os
from typing import Any

from scanner.base_agent import BaseAgent
from scanner import llm

logger = logging.getLogger(__name__)


class SecretsAgent(BaseAgent):
    agent_id = "secrets"
    category = "security"

    def _collect(self) -> tuple[Any, dict]:
        gitleaks_findings = self._run_gitleaks()
        semgrep_findings  = self._run_semgrep_secrets()

        # Deduplicate by (file, line) — both tools may catch the same secret
        seen:    set[tuple] = set()
        merged:  list[dict] = []

        for f in gitleaks_findings + semgrep_findings:
            key = (f.get("file", ""), f.get("line"))
            if key not in seen:
                seen.add(key)
                merged.append(f)

        total_files = self.context.get("file_counts", {}).get("total", 0)

        return merged, {
            "tool":                  "gitleaks + semgrep/secrets",
            "files_scanned":         total_files,
            "languages_scanned":     ["all"],
            "languages_unsupported": [],
            "gitleaks_count":        len(gitleaks_findings),
            "semgrep_count":         len(semgrep_findings),
            "deduplicated_count":    len(merged),
        }

    def _interpret(self, raw_data: Any, metadata: dict) -> dict:
        if not raw_data:
            return {
                "findings": [],
                "summary":  "No secrets or credentials detected. Make sure to keep it that way — never commit API keys or passwords.",
                "status":   "pass",
                "score":    100,
            }

        prompt = llm.build_findings_prompt(
            agent_name="Secrets Detection",
            tool_name="Gitleaks + Semgrep",
            raw_findings=raw_data,
            extra_context=(
                "These are potential secrets, credentials, or API keys found in the codebase. "
                "Even if a key has been rotated, its presence in source control is a risk. "
                "Any critical or high finding here should be treated as urgent. "
                "Note: redact or summarise secret values in your output — do not reproduce them."
            ),
        )

        result = llm.interpret_as_json(prompt)
        return result if result else self._fallback(raw_data)

    # ── Tool runners ──────────────────────────────────────────────────────────

    def _run_gitleaks(self) -> list[dict]:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        try:
            cmd = [
                "gitleaks", "detect",
                "--source", self.repo_path,
                "--report-format", "json",
                "--report-path", report_path,
                "--no-git",     # scan files, not git history (history scan is slower)
                "--exit-code", "0",  # don't fail the process on findings
            ]
            self._run_tool(cmd, timeout=120)

            if not os.path.exists(report_path):
                return []

            with open(report_path) as f:
                data = json.load(f)

            if not isinstance(data, list):
                return []

            return [
                {
                    "source":      "gitleaks",
                    "rule":        item.get("RuleID", "unknown"),
                    "file":        item.get("File", ""),
                    "line":        item.get("StartLine"),
                    "message":     f"{item.get('Description', 'Secret detected')} — value redacted",
                    "severity":    "critical",
                }
                for item in data
            ]

        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(f"[secrets] Gitleaks parse error: {exc}")
            return []
        finally:
            if os.path.exists(report_path):
                os.unlink(report_path)

    def _run_semgrep_secrets(self) -> list[dict]:
        cmd = [
            "semgrep",
            "--config", "p/secrets",
            "--json",
            "--quiet",
            self.repo_path,
        ]
        stdout, _, _ = self._run_tool(cmd, timeout=120)

        if not stdout:
            return []

        try:
            data = json.loads(stdout)
            return [
                {
                    "source":   "semgrep",
                    "rule":     r.get("check_id", ""),
                    "file":     r.get("path", ""),
                    "line":     r.get("start", {}).get("line"),
                    "message":  r.get("extra", {}).get("message", "Potential secret"),
                    "severity": "high",
                }
                for r in data.get("results", [])
            ]
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(f"[secrets] Semgrep parse error: {exc}")
            return []

    def _fallback(self, raw_data: list) -> dict:
        count = len(raw_data)
        return {
            "findings": [
                {"severity": "critical", "rule": f.get("rule", "secret-detected"),
                 "file": f.get("file", ""), "line": f.get("line"),
                 "message": f.get("message", "Potential secret detected"),
                 "suggestion": "Remove this value from source code and rotate the credential immediately."}
                for f in raw_data
            ],
            "summary": f"{count} potential secret(s) found. These must be removed and rotated immediately.",
            "status": "fail",
            "score": 0,
        }
