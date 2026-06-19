"""
Report compiler.

Takes all agent results and produces:
  - scan-report.json  : full machine-readable report
  - scan-summary.md   : human-readable PR comment
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from scanner import llm

logger = logging.getLogger(__name__)

STATUS_EMOJI = {"pass": "✅", "warn": "⚠️", "fail": "❌", "error": "🔴", "skipped": "⏭️"}
SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def compile_report(
    agent_results: list[dict],
    repo_path: str,
    repo_context: dict,
    commit_sha: str = "",
    pr_number: str = "",
) -> dict:
    """
    Merge all agent results into a single report dict.
    Also calls the LLM for an overall synthesis narrative.
    """
    overall_status = _derive_overall_status(agent_results)
    overall_score  = _derive_overall_score(agent_results)
    critical_findings = _collect_critical_findings(agent_results)

    # LLM synthesis — the "executive summary" for a non-developer
    synthesis = _synthesize(agent_results, overall_status, overall_score)

    return {
        "schema_version":   "1.0",
        "repo":             repo_path,
        "commit_sha":       commit_sha,
        "pr_number":        pr_number,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "overall_status":   overall_status,
        "overall_score":    overall_score,
        "synthesis":        synthesis,
        "critical_findings": critical_findings,
        "agents":           agent_results,
        "repo_context":     repo_context,
    }


def write_json(report: dict, output_path: str) -> None:
    """Write the full JSON report to disk."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, default=str))
    logger.info(f"JSON report written to {output_path}")


def write_markdown(report: dict, output_path: str) -> None:
    """Write a human-readable markdown summary (for PR comments)."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_render_markdown(report))
    logger.info(f"Markdown report written to {output_path}")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _derive_overall_status(results: list[dict]) -> str:
    statuses = [r.get("status", "pass") for r in results]
    if "fail" in statuses or "error" in statuses:
        return "fail"
    if "warn" in statuses:
        return "warn"
    return "pass"


def _derive_overall_score(results: list[dict]) -> int:
    scored = [r.get("score", 100) for r in results if r.get("status") not in ("skipped", "error")]
    if not scored:
        return 100
    return round(sum(scored) / len(scored))


def _collect_critical_findings(results: list[dict]) -> list[dict]:
    """Collect all critical and high severity findings across agents."""
    critical: list[dict] = []
    for result in results:
        for finding in result.get("findings", []):
            if finding.get("severity") in ("critical", "high"):
                critical.append({**finding, "agent": result.get("agent")})
    return sorted(critical, key=lambda f: 0 if f.get("severity") == "critical" else 1)


def _synthesize(results: list[dict], status: str, score: int) -> str:
    """Ask the LLM to write an executive summary across all agent results."""
    agent_summaries = [
        f"- [{r.get('agent')}] {STATUS_EMOJI.get(r.get('status', 'pass'), '')} "
        f"Score {r.get('score', 100)}: {r.get('summary', '')}"
        for r in results
    ]

    prompt = f"""You are writing an executive summary of a code scan report for a non-developer building an AI application.

Overall scan status: {status.upper()} (score: {score}/100)

Per-agent summaries:
{chr(10).join(agent_summaries)}

Write a 3-4 sentence executive summary that:
1. States clearly whether the code is ready to ship or needs work
2. Calls out the most important issues to fix first
3. Notes any areas that look good
4. Uses plain language — no technical jargon without explanation

Return only the summary text, no JSON."""

    try:
        return llm.interpret(prompt, max_tokens=400)
    except Exception as exc:
        logger.warning(f"Synthesis LLM call failed: {exc}")
        if status == "pass":
            return "All scans passed. The codebase looks good to ship."
        elif status == "warn":
            return "Some warnings were found. Review the findings below before deploying."
        else:
            return "Critical issues were found. These must be addressed before deploying."


def _render_markdown(report: dict) -> str:
    status      = report.get("overall_status", "pass")
    score       = report.get("overall_score", 100)
    emoji       = STATUS_EMOJI.get(status, "")
    timestamp   = report.get("timestamp", "")[:19].replace("T", " ")
    commit      = report.get("commit_sha", "")[:7]
    synthesis   = report.get("synthesis", "")
    agents      = report.get("agents", [])
    critical    = report.get("critical_findings", [])

    lines = [
        f"## {emoji} AI Scanner Report — {status.upper()} (Score: {score}/100)",
        f"",
        f"_{timestamp} UTC_ {'| Commit: `' + commit + '`' if commit else ''}",
        f"",
        f"### Summary",
        f"{synthesis}",
        f"",
    ]

    # Critical findings block
    if critical:
        lines += [
            f"### 🔴 Critical & High Findings ({len(critical)})",
            "",
            "| Severity | Agent | File | Issue |",
            "|----------|-------|------|-------|",
        ]
        for f in critical[:15]:   # cap table length
            sev_emoji = SEVERITY_EMOJI.get(f.get("severity", "info"), "")
            file_str  = f.get("file", "N/A")
            line_str  = f":{f['line']}" if f.get("line") else ""
            lines.append(
                f"| {sev_emoji} {f.get('severity', '').upper()} "
                f"| {f.get('agent', '')} "
                f"| `{file_str}{line_str}` "
                f"| {f.get('message', '')[:100]} |"
            )
        if len(critical) > 15:
            lines.append(f"\n_...and {len(critical) - 15} more. See full JSON report._")
        lines.append("")

    # Per-agent summary table
    lines += [
        "### Agent Results",
        "",
        "| Agent | Status | Score | Summary |",
        "|-------|--------|-------|---------|",
    ]
    for agent in agents:
        e = STATUS_EMOJI.get(agent.get("status", "pass"), "")
        lines.append(
            f"| {agent.get('agent', '')} "
            f"| {e} {agent.get('status', '').upper()} "
            f"| {agent.get('score', 100)}/100 "
            f"| {agent.get('summary', '')[:120]} |"
        )

    lines += [
        "",
        "<details>",
        "<summary>View full findings per agent</summary>",
        "",
    ]

    # Detailed findings per agent
    for agent in agents:
        findings = agent.get("findings", [])
        if not findings:
            continue
        lines += [
            f"#### {STATUS_EMOJI.get(agent.get('status','pass'), '')} {agent.get('agent', '').replace('_', ' ').title()}",
            "",
        ]
        for f in findings[:10]:   # cap per-agent detail
            sev_e = SEVERITY_EMOJI.get(f.get("severity", "info"), "")
            file_str = f.get("file", "N/A")
            line_str = f":{f['line']}" if f.get("line") else ""
            lines += [
                f"**{sev_e} {f.get('severity', '').upper()}** — `{file_str}{line_str}`",
                f"> {f.get('message', '')}",
                f"",
                f"💡 _{f.get('suggestion', '')}_",
                "",
            ]
        if len(findings) > 10:
            lines.append(f"_...and {len(findings) - 10} more findings. See full JSON report._\n")

    lines += ["</details>", "", "---", "_Powered by AI Scanner_"]

    return "\n".join(lines)
