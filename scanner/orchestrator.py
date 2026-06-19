"""
AI Scanner Orchestrator — main entry point.

Usage:
  python -m scanner.orchestrator --repo /path/to/repo [options]

Options:
  --repo        Path to the repository to scan (required)
  --output      Path for JSON report output (default: scan-report.json)
  --markdown    Path for markdown summary output (default: scan-summary.md)
  --commit      Git commit SHA for the report header
  --pr          Pull request number for the report header
  --registry    Path to registry.json (default: /scanner/scanner/registry.json)

The orchestrator:
  1. Inspects the repo (languages, frameworks, AI usage)
  2. Loads the scanner registry
  3. Selects applicable agents based on repo context
  4. Runs all agents in parallel
  5. Compiles results into JSON and markdown reports
"""
import argparse
import importlib
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from scanner import repo_inspector, report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("orchestrator")

DEFAULT_REGISTRY = Path(__file__).parent / "registry.json"
MAX_WORKERS = 6   # parallel agent threads


def main() -> int:
    args = _parse_args()

    logger.info(f"AI Scanner starting — repo: {args.repo}")

    # ── Step 1: Inspect the repository ───────────────────────────────────────
    logger.info("Inspecting repository...")
    context = repo_inspector.inspect(args.repo)
    logger.info(
        f"Detected: languages={list(context['languages'].keys())}, "
        f"is_ai_app={context['is_ai_app']}, "
        f"has_dockerfile={context['has_dockerfile']}"
    )

    # ── Step 2: Load registry and select agents ───────────────────────────────
    registry_path = Path(args.registry)
    if not registry_path.exists():
        logger.error(f"Registry not found: {registry_path}")
        return 1

    all_agent_defs = json.loads(registry_path.read_text()).get("agents", [])
    selected = _select_agents(all_agent_defs, context)
    logger.info(f"Selected {len(selected)}/{len(all_agent_defs)} agents: {[a['id'] for a in selected]}")

    # ── Step 3: Instantiate agents ────────────────────────────────────────────
    agents = []
    for agent_def in selected:
        instance = _load_agent(agent_def, args.repo, context)
        if instance:
            agents.append((agent_def["id"], instance))

    if not agents:
        logger.error("No agents could be loaded. Check registry and imports.")
        return 1

    # ── Step 4: Run agents in parallel ────────────────────────────────────────
    logger.info(f"Running {len(agents)} agents in parallel (max_workers={MAX_WORKERS})...")
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_run_agent, agent_id, instance): agent_id
                   for agent_id, instance in agents}

        for future in as_completed(futures):
            agent_id = futures[future]
            try:
                result = future.result()
                results.append(result)
                logger.info(
                    f"[{agent_id}] done — status={result.get('status')}, "
                    f"score={result.get('score')}, "
                    f"findings={len(result.get('findings', []))}"
                )
            except Exception as exc:
                logger.exception(f"[{agent_id}] Fatal error: {exc}")
                results.append({
                    "agent": agent_id, "status": "error", "score": 0,
                    "summary": f"Agent crashed: {exc}", "findings": [],
                    "languages_scanned": [], "languages_unsupported": [],
                    "metadata": {"error": str(exc)},
                })

    # Sort results to match registry order
    agent_order = {a["id"]: i for i, a in enumerate(all_agent_defs)}
    results.sort(key=lambda r: agent_order.get(r.get("agent", ""), 999))

    # ── Step 5: Compile and write reports ─────────────────────────────────────
    logger.info("Compiling report...")
    final_report = report.compile_report(
        agent_results=results,
        repo_path=args.repo,
        repo_context=context,
        commit_sha=args.commit,
        pr_number=args.pr,
    )

    report.write_json(final_report, args.output)
    report.write_markdown(final_report, args.markdown)

    # ── Step 6: Print summary and exit code ───────────────────────────────────
    status = final_report.get("overall_status", "pass")
    score  = final_report.get("overall_score", 100)
    crits  = len(final_report.get("critical_findings", []))

    print(f"\n{'='*60}")
    print(f"  AI SCANNER COMPLETE")
    print(f"  Status : {status.upper()}")
    print(f"  Score  : {score}/100")
    print(f"  Critical/High findings: {crits}")
    print(f"  JSON   : {args.output}")
    print(f"  Summary: {args.markdown}")
    print(f"{'='*60}\n")

    # Exit 1 on fail so CI/CD can use the exit code (for future gate enforcement)
    return 1 if status == "fail" else 0


# ── Agent selection ───────────────────────────────────────────────────────────

def _select_agents(agent_defs: list[dict], context: dict) -> list[dict]:
    """
    Filter the registry to agents applicable to this repo.
    Uses the `requires` block in each agent definition.
    """
    selected = []

    for agent_def in agent_defs:
        req = agent_def.get("requires", {})

        if agent_def.get("always_run"):
            selected.append(agent_def)
            continue

        # Check language requirements
        if "languages" in req:
            repo_langs = set(context.get("languages", {}).keys())
            if not repo_langs.intersection(req["languages"]):
                logger.debug(f"Skipping {agent_def['id']}: no matching languages")
                continue

        # Check file requirements
        if "files" in req:
            repo_root = Path(context.get("_repo_path", "."))
            if not any((repo_root / f).exists() for f in req["files"]):
                # Fallback: check if noted in context frameworks
                if not any(f.split(".")[0] in context.get("frameworks", []) for f in req["files"]):
                    logger.debug(f"Skipping {agent_def['id']}: required files not found")
                    continue

        # Check boolean flags
        if "has_dockerfile" in req and req["has_dockerfile"]:
            if not context.get("has_dockerfile"):
                logger.debug(f"Skipping {agent_def['id']}: no Dockerfile")
                continue

        if "is_ai_app" in req and req["is_ai_app"]:
            if not context.get("is_ai_app"):
                logger.debug(f"Skipping {agent_def['id']}: not detected as AI app")
                continue

        selected.append(agent_def)

    return selected


# ── Agent loading ─────────────────────────────────────────────────────────────

def _load_agent(agent_def: dict, repo_path: str, context: dict):
    """Dynamically import and instantiate an agent class."""
    module_path = agent_def.get("module")
    class_name  = agent_def.get("class")

    try:
        module   = importlib.import_module(module_path)
        cls      = getattr(module, class_name)
        instance = cls(repo_path=repo_path, context=context)
        return instance
    except (ImportError, AttributeError) as exc:
        logger.error(f"Could not load agent {agent_def['id']} ({module_path}.{class_name}): {exc}")
        return None


def _run_agent(agent_id: str, instance) -> dict:
    """Run a single agent and return its result."""
    logger.info(f"[{agent_id}] Starting...")
    return instance.run()


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI Scanner Orchestrator")
    parser.add_argument("--repo",     required=True,  help="Path to the repository to scan")
    parser.add_argument("--output",   default="scan-report.json",  help="JSON output path")
    parser.add_argument("--markdown", default="scan-summary.md",   help="Markdown output path")
    parser.add_argument("--commit",   default="",     help="Git commit SHA")
    parser.add_argument("--pr",       default="",     help="Pull request number")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY), help="Path to registry.json")
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(main())
