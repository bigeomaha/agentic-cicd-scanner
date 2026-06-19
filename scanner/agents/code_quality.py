"""
Code quality agent.

Tools:
  - Ruff   : Python linting and formatting (fast, covers flake8 + isort + pyupgrade rules)
  - ESLint : JavaScript / TypeScript linting
"""
import json
import logging
from typing import Any

from scanner.base_agent import BaseAgent
from scanner import llm

logger = logging.getLogger(__name__)


class CodeQualityAgent(BaseAgent):
    agent_id = "code_quality"
    category = "quality"

    def _collect(self) -> tuple[Any, dict]:
        languages = self.context.get("languages", {})
        has_python = "python" in languages
        has_js_ts  = "javascript" in languages or "typescript" in languages

        if not has_python and not has_js_ts:
            return self._skipped_envelope("No Python or JavaScript/TypeScript files found.")

        findings:          list[dict] = []
        scanned_languages: list[str]  = []

        if has_python:
            ruff = self._run_ruff()
            findings.extend(ruff)
            scanned_languages.append("python")

        if has_js_ts:
            eslint = self._run_eslint()
            findings.extend(eslint)
            if "javascript" in languages:
                scanned_languages.append("javascript")
            if "typescript" in languages:
                scanned_languages.append("typescript")

        total_files = sum(
            languages.get(l, 0) for l in ("python", "javascript", "typescript")
        )

        return findings, {
            "tool":                  "ruff + eslint",
            "files_scanned":         total_files,
            "languages_scanned":     scanned_languages,
            "languages_unsupported": [],
        }

    def _interpret(self, raw_data: Any, metadata: dict) -> dict:
        if metadata.get("skipped"):
            return self._skipped_result(metadata.get("skip_reason", ""))

        if not raw_data:
            return {
                "findings": [],
                "summary":  "Code quality checks passed. No linting issues found.",
                "status":   "pass",
                "score":    100,
            }

        # Cap findings — linters can produce hundreds of style issues; focus on the worst
        capped = raw_data[:80]

        prompt = llm.build_findings_prompt(
            agent_name="Code Quality",
            tool_name="Ruff + ESLint",
            raw_findings=capped,
            extra_context=(
                "These are code quality and style issues. Group similar issues together. "
                "Focus your explanation on patterns that indicate real problems "
                "(unused variables, insecure patterns, dead code, complexity) "
                "rather than minor formatting nits. "
                f"Note: {len(raw_data)} total issues found; showing top {len(capped)}."
            ),
        )

        result = llm.interpret_as_json(prompt)
        return result if result else self._fallback(raw_data)

    # ── Tool runners ──────────────────────────────────────────────────────────

    def _run_ruff(self) -> list[dict]:
        cmd = [
            "ruff", "check",
            "--output-format", "json",
            "--quiet",
            self.repo_path,
        ]
        stdout, _, _ = self._run_tool(cmd, timeout=60)

        if not stdout:
            return []

        try:
            issues = json.loads(stdout)
            return [
                {
                    "source":   "ruff",
                    "rule":     i.get("code", ""),
                    "file":     i.get("filename", "").replace(self.repo_path + "/", ""),
                    "line":     i.get("location", {}).get("row"),
                    "message":  i.get("message", ""),
                    "severity": _ruff_severity(i.get("code", "")),
                }
                for i in issues
            ]
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(f"[code_quality] Ruff parse error: {exc}")
            return []

    def _run_eslint(self) -> list[dict]:
        cmd = [
            "eslint",
            "--format", "json",
            "--no-eslintrc",              # use built-in rules only (no config file needed)
            "--rule", '{"no-unused-vars": "warn", "no-undef": "warn", "no-eval": "error", '
                      '"no-implied-eval": "error", "no-new-func": "error"}',
            "--ext", ".js,.jsx,.ts,.tsx",
            self.repo_path,
        ]
        stdout, _, _ = self._run_tool(cmd, timeout=60)

        if not stdout:
            return []

        try:
            files = json.loads(stdout)
            findings = []
            for file_result in files:
                fp = file_result.get("filePath", "").replace(self.repo_path + "/", "")
                for msg in file_result.get("messages", []):
                    findings.append({
                        "source":   "eslint",
                        "rule":     msg.get("ruleId", ""),
                        "file":     fp,
                        "line":     msg.get("line"),
                        "message":  msg.get("message", ""),
                        "severity": "high" if msg.get("severity") == 2 else "low",
                    })
            return findings
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(f"[code_quality] ESLint parse error: {exc}")
            return []

    def _fallback(self, raw_data: list) -> dict:
        count  = len(raw_data)
        errors = sum(1 for f in raw_data if f.get("severity") in ("high", "critical"))
        return {
            "findings": [
                {"severity": f.get("severity", "low"), "rule": f.get("rule", ""),
                 "file": f.get("file", ""), "line": f.get("line"),
                 "message": f.get("message", ""), "suggestion": "Review and fix this issue."}
                for f in raw_data[:30]
            ],
            "summary": f"{count} code quality issues found ({errors} errors). Review and address the errors first.",
            "status": "fail" if errors > 10 else "warn",
            "score":  max(40, 90 - errors * 2 - (count // 10)),
        }


def _ruff_severity(code: str) -> str:
    """Map Ruff rule codes to severity levels."""
    if not code:
        return "info"
    prefix = code[:1].upper()
    # E = errors, W = warnings, F = pyflakes, S = security (bandit), B = bugbear
    return {
        "E": "medium", "W": "low", "F": "medium",
        "S": "high",   "B": "medium", "N": "info",
        "I": "info",   "UP": "info",  "C": "low",
    }.get(prefix, "info")
