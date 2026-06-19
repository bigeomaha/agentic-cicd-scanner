"""
License compliance agent.

Tool: Trivy (license scanner mode)

Identifies dependency licenses and flags ones that may be incompatible
with commercial/proprietary use (e.g. GPL, AGPL, SSPL).
"""
import json
import logging
from pathlib import Path
from typing import Any

from scanner.base_agent import BaseAgent
from scanner import llm

logger = logging.getLogger(__name__)

MANIFEST_FILES = (
    "requirements.txt", "pyproject.toml", "Pipfile",
    "package.json", "go.mod",
)

# Licenses that raise concerns in corporate / proprietary projects
HIGH_RISK_LICENSES = {
    "GPL-2.0", "GPL-3.0", "AGPL-3.0", "AGPL-1.0",
    "SSPL-1.0", "EUPL-1.1", "EUPL-1.2", "CC-BY-SA-4.0",
}
MEDIUM_RISK_LICENSES = {
    "LGPL-2.0", "LGPL-2.1", "LGPL-3.0",
    "MPL-2.0", "EPL-1.0", "EPL-2.0",
    "CDDL-1.0",
}


class LicenseAgent(BaseAgent):
    agent_id = "license"
    category = "compliance"

    def _collect(self) -> tuple[Any, dict]:
        repo = Path(self.repo_path)
        manifests = [f for f in MANIFEST_FILES if (repo / f).exists()]

        if not manifests:
            return self._skipped_envelope("No dependency manifest files found.")

        findings = self._run_trivy_licenses()

        return findings, {
            "tool":                  "trivy (license)",
            "files_scanned":         len(manifests),
            "manifests_found":       manifests,
            "languages_scanned":     list(self.context.get("languages", {}).keys()),
            "languages_unsupported": [],
        }

    def _interpret(self, raw_data: Any, metadata: dict) -> dict:
        if metadata.get("skipped"):
            return self._skipped_result(metadata.get("skip_reason", ""))

        if not raw_data:
            return {
                "findings": [],
                "summary":  "No dependency licenses detected. Ensure dependency files are present and populated.",
                "status":   "pass",
                "score":    100,
            }

        # Flag risky licenses locally before sending to LLM
        flagged = [f for f in raw_data if f.get("license") in HIGH_RISK_LICENSES | MEDIUM_RISK_LICENSES]

        prompt = f"""You are reviewing software dependency licenses for a corporate AI application.

The following dependency licenses were detected:
{json.dumps(raw_data, indent=2)[:8000]}

Licenses to be especially careful about in proprietary/commercial projects:
- HIGH RISK (may require open-sourcing your code): {', '.join(sorted(HIGH_RISK_LICENSES))}
- MEDIUM RISK (review required): {', '.join(sorted(MEDIUM_RISK_LICENSES))}
- LOW RISK (generally safe): MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Python-2.0

For each problematic license:
- Explain what restriction it places on the project
- State the real business risk in plain language
- Suggest whether to seek legal advice or find an alternative package

Return JSON with this exact schema:
{{
  "findings": [
    {{
      "severity": "critical|high|medium|low|info",
      "rule": "license-risk",
      "file": "package_name",
      "line": null,
      "message": "Plain language description of the license risk",
      "suggestion": "What to do about it"
    }}
  ],
  "summary": "2-3 sentence plain-language summary of the license posture",
  "status": "pass|warn|fail",
  "score": 0-100,
  "false_positive_notes": "Notes on licenses that look risky but are probably fine in context"
}}"""

        result = llm.interpret_as_json(prompt)
        return result if result else self._fallback(flagged)

    # ── Tool runner ───────────────────────────────────────────────────────────

    def _run_trivy_licenses(self) -> list[dict]:
        cmd = [
            "trivy", "fs",
            "--scanners", "license",
            "--format", "json",
            "--quiet",
            self.repo_path,
        ]
        stdout, stderr, _ = self._run_tool(cmd, timeout=120)

        if not stdout:
            logger.debug(f"[license] Trivy no output. stderr: {stderr[:200]}")
            return []

        try:
            data = json.loads(stdout)
            findings = []
            for result in data.get("Results", []):
                for pkg in result.get("Packages") or []:
                    for lic in pkg.get("Licenses") or []:
                        findings.append({
                            "package": pkg.get("Name", ""),
                            "version": pkg.get("Version", ""),
                            "license": lic,
                            "file":    result.get("Target", ""),
                        })
            return findings
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(f"[license] Trivy parse error: {exc}")
            return []

    def _fallback(self, flagged: list) -> dict:
        count = len(flagged)
        return {
            "findings": [
                {"severity": "high" if f.get("license") in HIGH_RISK_LICENSES else "medium",
                 "rule": "license-risk",
                 "file": f.get("package", ""),
                 "line": None,
                 "message": f"{f.get('package', '')} uses {f.get('license', 'unknown')} license, which may restrict commercial use.",
                 "suggestion": "Consult your legal team before shipping this dependency in a commercial product."}
                for f in flagged
            ],
            "summary": f"{count} potentially problematic license(s) detected. Legal review recommended.",
            "status": "warn" if count > 0 else "pass",
            "score": max(50, 90 - count * 10),
        }
