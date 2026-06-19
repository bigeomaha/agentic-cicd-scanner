"""
Dependencies agent — CVE vulnerability scanning.

Tools:
  - Trivy    : scans requirements.txt, package.json, go.mod, etc.
  - pip-audit: targeted Python package CVE scan (OSV database)
"""
import json
import logging
from pathlib import Path
from typing import Any

from scanner.base_agent import BaseAgent
from scanner import llm

logger = logging.getLogger(__name__)

# Dependency manifest files that indicate there are packages to scan
MANIFEST_FILES = (
    "requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
    "pyproject.toml", "Pipfile", "Pipfile.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock",
    "composer.json",
)


class DependenciesAgent(BaseAgent):
    agent_id = "dependencies"
    category = "security"

    def _collect(self) -> tuple[Any, dict]:
        repo = Path(self.repo_path)
        manifests = [f for f in MANIFEST_FILES if (repo / f).exists()]

        if not manifests:
            return self._skipped_envelope("No dependency manifest files found.")

        trivy_findings  = self._run_trivy()
        pipaudit_findings = (
            self._run_pip_audit()
            if any(f.startswith("requirements") or f in ("pyproject.toml", "Pipfile")
                   for f in manifests)
            else []
        )

        # Deduplicate by CVE ID
        seen: set[str] = set()
        merged: list[dict] = []
        for f in trivy_findings + pipaudit_findings:
            cve = f.get("cve_id", f.get("rule", ""))
            if cve not in seen:
                seen.add(cve)
                merged.append(f)

        return merged, {
            "tool":                  "trivy + pip-audit",
            "files_scanned":         len(manifests),
            "manifests_found":       manifests,
            "languages_scanned":     list(self.context.get("languages", {}).keys()),
            "languages_unsupported": [],
            "trivy_count":           len(trivy_findings),
            "pipaudit_count":        len(pipaudit_findings),
        }

    def _interpret(self, raw_data: Any, metadata: dict) -> dict:
        if metadata.get("skipped"):
            return self._skipped_result(metadata.get("skip_reason", ""))

        if not raw_data:
            return {
                "findings": [],
                "summary":  "No known vulnerabilities found in dependencies. Keep dependencies updated regularly.",
                "status":   "pass",
                "score":    100,
            }

        prompt = llm.build_findings_prompt(
            agent_name="Dependency CVE Scanner",
            tool_name="Trivy + pip-audit",
            raw_findings=raw_data[:50],
            extra_context=(
                "These are known CVEs (Common Vulnerabilities and Exposures) in the project's dependencies. "
                "Explain each in plain language: what the vulnerability allows an attacker to do, "
                "and provide the exact package upgrade command to fix it. "
                "Prioritise: CRITICAL and HIGH severities must be fixed before deployment."
            ),
        )

        result = llm.interpret_as_json(prompt)
        return result if result else self._fallback(raw_data)

    # ── Tool runners ──────────────────────────────────────────────────────────

    def _run_trivy(self) -> list[dict]:
        cmd = [
            "trivy", "fs",
            "--scanners", "vuln",
            "--format", "json",
            "--quiet",
            self.repo_path,
        ]
        stdout, stderr, _ = self._run_tool(cmd, timeout=180)

        if not stdout:
            logger.debug(f"[dependencies] Trivy no output. stderr: {stderr[:200]}")
            return []

        try:
            data = json.loads(stdout)
            findings = []
            for result in data.get("Results", []):
                target = result.get("Target", "")
                for vuln in result.get("Vulnerabilities") or []:
                    findings.append({
                        "source":   "trivy",
                        "cve_id":   vuln.get("VulnerabilityID", ""),
                        "rule":     vuln.get("VulnerabilityID", ""),
                        "file":     target,
                        "line":     None,
                        "package":  vuln.get("PkgName", ""),
                        "installed_version": vuln.get("InstalledVersion", ""),
                        "fixed_version":     vuln.get("FixedVersion", "not yet fixed"),
                        "severity": vuln.get("Severity", "UNKNOWN").lower(),
                        "message":  vuln.get("Title") or vuln.get("Description", "")[:200],
                    })
            return findings
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(f"[dependencies] Trivy parse error: {exc}")
            return []

    def _run_pip_audit(self) -> list[dict]:
        cmd = [
            "pip-audit",
            "--format", "json",
            "--progress-spinner", "off",
        ]
        stdout, stderr, rc = self._run_tool(cmd, timeout=120)

        if not stdout:
            return []

        try:
            data = json.loads(stdout)
            findings = []
            for dep in data.get("dependencies", []):
                for vuln in dep.get("vulns", []):
                    findings.append({
                        "source":            "pip-audit",
                        "cve_id":            vuln.get("id", ""),
                        "rule":              vuln.get("id", ""),
                        "file":              "requirements",
                        "line":              None,
                        "package":           dep.get("name", ""),
                        "installed_version": dep.get("version", ""),
                        "fixed_version":     ", ".join(vuln.get("fix_versions", [])) or "unknown",
                        "severity":          "high",   # pip-audit doesn't expose CVSS severity
                        "message":           vuln.get("description", "")[:200],
                    })
            return findings
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(f"[dependencies] pip-audit parse error: {exc}")
            return []

    def _fallback(self, raw_data: list) -> dict:
        count = len(raw_data)
        crits = sum(1 for f in raw_data if f.get("severity") in ("critical", "high"))
        return {
            "findings": [
                {"severity": f.get("severity", "high"),
                 "rule": f.get("cve_id", f.get("rule", "")),
                 "file": f.get("file", ""), "line": None,
                 "message": f"{f.get('package', '')} {f.get('installed_version', '')} — {f.get('message', '')}",
                 "suggestion": f"Upgrade to {f.get('fixed_version', 'latest stable version')}"}
                for f in raw_data[:30]
            ],
            "summary": f"{count} vulnerabilities found ({crits} critical/high). Upgrade affected packages immediately.",
            "status": "fail" if crits > 0 else "warn",
            "score": max(0, 60 - crits * 15),
        }
