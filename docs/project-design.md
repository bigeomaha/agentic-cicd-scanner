# Project Design — Agentic CI/CD Scanner

This document describes the architecture, design decisions, data flows, and
extension points of the AI Scanner. It is written for AI assistants and
developers who need to understand the project quickly before making changes.

---

## Purpose

The AI Scanner is a CI/CD pipeline add-on that runs automated code analysis
on every GitHub pull request and push. It combines traditional static analysis
tools (Semgrep, Gitleaks, Trivy, etc.) with LLM interpretation so findings are
explained in plain language suitable for non-developers building AI applications.

The system is **report-only in Iteration 1** — it never blocks merges. A
gating mechanism exists in the workflow but is commented-configurable.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│  GitHub Actions — Pipeline 2 (scan.yml)                  │
│                                                          │
│  Trigger: PR opened/updated, push to main                │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  GHCR Docker Image (ai-scanner:latest)           │    │
│  │                                                  │    │
│  │  python -m scanner.orchestrator --repo /scan     │    │
│  │       │                                          │    │
│  │       ▼                                          │    │
│  │  repo_inspector.inspect()                        │    │
│  │       │  returns: languages, frameworks,         │    │
│  │       │           is_ai_app, has_dockerfile, … │    │
│  │       ▼                                          │    │
│  │  _select_agents(registry.json, context)          │    │
│  │       │  returns: filtered list of agent defs    │    │
│  │       ▼                                          │    │
│  │  ThreadPoolExecutor(max_workers=6)               │    │
│  │       │  parallel fan-out to all selected agents │    │
│  │       ▼                                          │    │
│  │  [agent.run() × N] → list[dict]                  │    │
│  │       │                                          │    │
│  │       ▼                                          │    │
│  │  report.compile_report()                         │    │
│  │       │  → scan-report.json                      │    │
│  │       │  → scan-summary.md                       │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  Post: PR comment, commit status, Actions artifact       │
└─────────────────────────────────────────────────────────┘
```

---

## Two-Pipeline Design

The system uses two separate GitHub Actions workflows to separate concerns
and maximize performance.

### Pipeline 1 — `docker-build.yml` (image builder)

**Triggers:** push to `main` (path-filtered to scanner files), weekly cron
(Monday 02:00 UTC), manual dispatch.

**What it does:** Builds the Docker image and pushes it to GitHub Container
Registry (GHCR) as `ghcr.io/<owner>/ai-scanner:latest` and
`ghcr.io/<owner>/ai-scanner:sha-<short>`.

**Why it exists separately:** Security tools like Semgrep, Trivy, and Gitleaks
are large and slow to install. By pre-building an image, Pipeline 2 starts in
seconds with all tools already available. The weekly cron ensures security rule
caches stay fresh even when the code hasn't changed.

### Pipeline 2 — `scan.yml` (scanner)

**Triggers:** every PR (opened, updated, reopened), every push to `main`.

**What it does:** Pulls the pre-built image, mounts the repo being scanned,
runs the orchestrator, posts results.

**Key design choice:** The repo being scanned is mounted read-only at `/scan`.
The image itself is immutable. This means scanner code changes require a new
image build, but agent code is always baked in — no runtime git pulls.

---

## Docker Image Design

### Two-Stage Build

**Stage 1 (`downloader` — `debian:bookworm-slim`):**
Downloads three standalone binaries: Trivy, Gitleaks, Hadolint. Uses curl only.
Keeps curl out of the final image (security best practice).

**Stage 2 (`final` — `python:3.12-slim`):**
Copies binaries from Stage 1. Installs Node.js 20 (for ESLint), Python tools
from `requirements.txt`, ESLint from `package.json` (tools key), pre-warms
Semgrep rule caches, copies agent code, creates non-root `scanner` user (uid
1001), runs sanity checks on all tools.

### Layer Order (intentional, for cache efficiency)

```
1. OS packages + Node.js          (changes: never)
2. Binary tools (trivy/gitleaks)  (changes: quarterly)
3. Python tools (requirements)    (changes: when versions bump)
4. Node tools (eslint)            (changes: when versions bump)
5. Semgrep rule pre-warm          (changes: never in code, weekly via cron)
6. Agent code (scanner/)          (changes: frequently)
```

Agent code is last so that editing a prompt or adding an agent only rebuilds
the final layer, preserving all expensive tool-download layers in the cache.

### Environment Variables

| Variable | Source | Used by |
|----------|--------|---------|
| `GITHUB_TOKEN` | Actions secret / scanner.env.local | `llm.py` (GitHub Models auth) |
| `PYTHONPATH` | Set to `/scanner` in workflow | Python imports (`scanner.*`) |
| `SCANNER_MODEL` | Optional override | `llm.py` |
| `SCANNER_FALLBACK_MODEL` | Optional override | `llm.py` |

### File Paths Inside the Container

```
/scanner/scanner/          Agent code (COPY scanner/ /scanner/scanner/)
/scanner/scanner/registry.json
/scan/                     Repo being scanned (mounted read-only)
/reports/                  Output dir (mounted read-write)
```

`PYTHONPATH=/scanner` means `import scanner.agents.security` resolves to
`/scanner/scanner/agents/security.py`.

---

## Agent Architecture

### Base Class — `scanner/base_agent.py`

All agents subclass `BaseAgent`. The public interface is a single method:

```python
agent.run() -> dict   # returns the standard JSON envelope
```

Subclasses implement two abstract methods:

```python
_collect() -> tuple[Any, dict]       # gather raw data + metadata
_interpret(raw_data, metadata) -> dict  # call LLM, return structured result
```

`run()` calls `_collect()`, passes the result to `_interpret()`, merges
with the standard envelope, sorts findings by severity, and returns.

### Standard JSON Envelope (all agents return this shape)

```json
{
  "agent": "agent_id",
  "category": "security|quality|compliance|docs",
  "status": "pass|warn|fail|error|skipped",
  "score": 0,
  "summary": "Plain-language 2-3 sentence summary",
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "rule": "rule_id",
      "file": "relative/path.py",
      "line": 42,
      "message": "What this means in plain language",
      "suggestion": "Specific actionable fix"
    }
  ],
  "false_positive_notes": "",
  "languages_scanned": ["python"],
  "languages_unsupported": ["java"],
  "metadata": {}
}
```

Findings are sorted by severity before returning: critical → high → medium →
low → info.

### Helper Methods on BaseAgent

| Method | Purpose |
|--------|---------|
| `_run_tool(cmd, timeout, cwd)` | Runs a CLI tool, captures stdout/stderr, returns (stdout, returncode) |
| `_read_files(patterns, max_files, max_lines)` | Reads source files matching glob patterns, respects limits |
| `_find_files(patterns)` | Returns paths matching glob patterns under repo_path |
| `_skipped_envelope(reason)` | Returns a well-formed skipped result |
| `_error_envelope(error_msg)` | Returns a well-formed error result |

---

## The 11 Agents

### Tool-Based Agents (run CLI tools, then LLM interprets)

**`security`** (`scanner/agents/security.py`)
Runs Semgrep (5 config packs: python, javascript, typescript, owasp-top-ten,
security-audit) and Bandit (Python only). Merges findings, caps at 60 before
LLM call. Skips unsupported languages gracefully.
Requires: at least one Semgrep-supported language.

**`secrets`** (`scanner/agents/secrets.py`)
Runs Gitleaks (`detect --no-git`) and Semgrep `p/secrets`. Deduplicates by
(file, line). All Gitleaks findings are severity=critical. LLM prompt instructs
to redact actual secret values from its response.
Always runs: yes.

**`dependencies`** (`scanner/agents/dependencies.py`)
Runs Trivy (`fs --scanners vuln`) and pip-audit. Deduplicates by CVE ID.
Skips if no manifest files (requirements.txt, package.json, etc.) found.
Always runs: yes.

**`license`** (`scanner/agents/license.py`)
Reads manifest files to extract dependency names and versions. Classifies
licenses as HIGH_RISK (GPL, AGPL, SSPL) or MEDIUM_RISK (LGPL, MPL, EPL).
Uses a custom LLM prompt explaining commercial licensing implications.
Always runs: yes.

**`code_quality`** (`scanner/agents/code_quality.py`)
Runs Ruff (Python) and ESLint (JS/TS) with hardcoded security-focused rules
(no-eval, no-implied-eval, no-new-func as errors). Ruff severity is mapped
from rule prefix (E→medium, S→high, F→medium, etc.). Caps at 80 findings.
Requires: python or javascript or typescript.

**`dockerfile_lint`** (`scanner/agents/dockerfile_lint.py`)
Finds all Dockerfiles (Dockerfile, Dockerfile.*, **/Dockerfile). Runs Hadolint
on each. Severity mapping: error→high, warning→medium, info→low, style→info.
Requires: has_dockerfile=true in context.

### LLM-Only Agents (read source files, reason directly)

**`ai_safety`** (`scanner/agents/ai_safety.py`)
Reads .py/.js/.ts files containing AI import keywords and prompt/system .txt/.md
files. Covers 8 risk categories: prompt injection, model pinning, output
handling, PII in prompts, permissive system prompts, API key exposure, logging
risks, rate limiting.
Requires: is_ai_app=true in context.

**`api_design`** (`scanner/agents/api_design.py`)
Finds route/controller files by name patterns (routes.py, views.py, *router*.py,
*controller*.ts, etc.) and content keywords (@app.route, router.get, FastAPI,
etc.). Reviews HTTP verbs, error responses, input validation, data exposure,
versioning, pagination, auth enforcement.
Requires: python or javascript or typescript.

**`auth`** (`scanner/agents/auth.py`)
Finds auth-related files (*auth*.py, *login*.py, *token*.py, *session*.py,
*middleware*.py, etc.). Handles "no auth code found" case explicitly (returns
info-level finding). Reviews custom auth, password hashing, JWT validation,
session management, authz vs authn, token expiry, OAuth CSRF.
Requires: any code language.

**`non_code_files`** (`scanner/agents/non_code_files.py`)
Reads docs (.md/.txt/.rst), .env.example/.env.sample, and Jupyter notebooks.
Notebook reader extracts code cells, markdown cells, and notes if output cells
exist (may contain real data). Covers PII in examples, credentials in env files,
architecture exposure, notebook output risk, stale docs.
Always runs: yes.

**`test_coverage`** (`scanner/agents/test_coverage.py`)
Static analysis only — does NOT run tests. Detects test framework, counts
source vs test files, checks for coverage config files, samples test file
content for quality signals. Phase 2 (executing tests) is intentionally
excluded.
Always runs: yes.

---

## Agent Registry — `scanner/registry.json`

The orchestrator never hardcodes which agents to run. It reads the registry
at runtime and applies the `requires` filter against the repo context.

### Registry Entry Shape

```json
{
  "id": "agent_id",
  "module": "scanner.agents.module_name",
  "class": "ClassName",
  "category": "security|quality|compliance|docs",
  "type": "tool-wrapper|llm-agent",
  "description": "One-line description",
  "always_run": false,
  "requires": {
    "languages": ["python", "javascript"],
    "has_dockerfile": true,
    "is_ai_app": true
  }
}
```

### Selection Logic in `orchestrator._select_agents()`

1. If `always_run: true` → include unconditionally
2. If `requires.languages` → skip unless repo contains at least one matching language
3. If `requires.has_dockerfile: true` → skip unless `context.has_dockerfile` is true
4. If `requires.is_ai_app: true` → skip unless `context.is_ai_app` is true
5. If `requires.files` → skip unless at least one listed file exists in the repo

---

## Repo Inspector — `scanner/repo_inspector.py`

`inspect(repo_path) -> dict` is called once before agents run. It walks the
repository and builds a rich context dict that agents use to:
- Skip unsupported languages
- Detect AI-specific files
- Find relevant source files without re-walking the tree

### Context Dict Shape

```python
{
  "languages": {"python": 42, "javascript": 11},  # lang → file count
  "primary_language": "python",
  "frameworks": ["fastapi", "react"],
  "is_ai_app": True,           # True if openai/anthropic/langchain etc. found
  "has_dockerfile": True,
  "has_openapi": False,
  "test_framework": "pytest",
  "has_tests": True,
  "semgrep_unsupported": ["go"],  # languages present but not in Semgrep packs
  "file_counts": {"total": 120, "source": 80, "test": 15},
  "notable_files": {
    "source_files": [...],   # relative paths to source files
    "test_files": [...],     # relative paths to test files
  },
  "_repo_path": "/scan",     # absolute path (internal use)
}
```

### AI App Detection

`_detect_ai_usage()` checks requirements.txt, pyproject.toml, and package.json
for any of: `openai`, `anthropic`, `langchain`, `llama`, `huggingface`,
`transformers`, `google-generativeai`, `cohere`, `mistral`, `together`.

---

## LLM Client — `scanner/llm.py`

All LLM calls go through this module. It uses the OpenAI Python SDK pointed
at GitHub Models.

```
Endpoint: https://models.inference.ai.azure.com
Auth:     GITHUB_TOKEN (standard GitHub personal access token)
Default:  gpt-4o
Fallback: gpt-4o-mini
```

### Key Functions

`interpret(prompt, model, max_tokens, temperature=0.1) -> str`
Calls the LLM, retries up to 3 times with exponential backoff on
RateLimitError or APIError. Uses `response_format={"type": "json_object"}`.

`interpret_as_json(prompt) -> dict`
Wraps `interpret()`, parses JSON, returns `{}` on failure.

`build_findings_prompt(agent_name, tool_name, raw_findings, extra_context) -> str`
Standard prompt builder for tool-based agents. Truncates findings at 12,000
characters. Embeds the standard JSON schema so all tool agents return the
same finding shape.

### Model Overrides

`DEFAULT_MODEL` and `FALLBACK_MODEL` read from environment variables
`SCANNER_MODEL` and `SCANNER_FALLBACK_MODEL` at module load time. This
allows override per deployment without code changes.

---

## Report Compiler — `scanner/report.py`

Takes all agent result dicts and produces two outputs.

### `compile_report()` → dict

1. Derives `overall_status` — "fail" if any agent fails/errors, "warn" if any
   warns, otherwise "pass"
2. Derives `overall_score` — arithmetic mean of scored agents (skipped/error
   agents excluded)
3. Collects all critical+high findings across agents into `critical_findings`
   (sorted: critical first, then high)
4. Calls `_synthesize()` — LLM writes a 3-4 sentence executive summary across
   all agent results
5. Returns the full report dict

### `write_markdown()` — PR comment format

Renders: status header, executive summary, critical findings table (capped at
15 rows), per-agent status table, expandable `<details>` block with full
per-agent findings (capped at 10 per agent). Designed to fit within GitHub's
PR comment character limit in most cases.

---

## Local Runner — `scan.py`

A standalone Python 3 script with a shebang (`#!/usr/bin/env python3`) that
can be symlinked into `$PATH` as `ai-scan`. Uses only stdlib — no install
required.

```
ai-scan [PROJECT_PATH]         scan a project
ai-scan --build [PROJECT_PATH] build image first, then scan
ai-scan --build-only           build image and exit
```

Reads `scanner.env.local` from the same directory as `scan.py`. Passes only
`GITHUB_TOKEN`, `SCANNER_MODEL`, `SCANNER_FALLBACK_MODEL` into the container
(not `SCANNER_IMAGE`, which is a script-level config). Mounts the project
read-only at `/scan`, output dir read-write at `/reports`.

Reports land in `<project>/.ai-scanner/scan-report.json` and
`<project>/.ai-scanner/scan-summary.md`.

---

## Data Flow — End to End

```
1. PR opened on GitHub
      │
2. scan.yml triggers, runner starts with pre-built Docker image
      │
3. actions/checkout@v4 clones the PR's branch into $GITHUB_WORKSPACE
      │
4. orchestrator.main() called with --repo $GITHUB_WORKSPACE
      │
5. repo_inspector.inspect($GITHUB_WORKSPACE)
      → walks files, builds context dict
      │
6. _select_agents(registry.json, context)
      → filters to applicable agents (e.g., 8 of 11 if no Dockerfile + not AI app)
      │
7. [parallel] for each agent:
      agent._collect()
        → runs tool or reads files
        → returns (raw_data, metadata)
      agent._interpret(raw_data, metadata)
        → calls llm.interpret_as_json(prompt)
        → GitHub Models API call (authenticated with GITHUB_TOKEN)
        → returns structured findings dict
      agent.run()
        → merges _collect + _interpret results into standard envelope
      │
8. report.compile_report(agent_results, context, commit_sha, pr_number)
      → overall status + score
      → LLM synthesis call (executive summary)
      → critical_findings aggregated
      │
9. report.write_json()  → $GITHUB_WORKSPACE/scan-report.json
   report.write_markdown() → $GITHUB_WORKSPACE/scan-summary.md
      │
10. Post PR Comment step:
      → reads scan-summary.md
      → POSTs to GitHub API: /repos/{repo}/issues/{pr}/comments
      → if comment already exists from a prior scan, PATCHes it (no spam)
      │
11. Update Commit Status step:
      → reads scan-report.json
      → POSTs to GitHub API: /repos/{repo}/statuses/{sha}
      → state: success (pass/warn) or failure (fail)
      │
12. Upload Scan Report step:
      → uploads both files as Actions artifact (retained 30 days)
      │
13. Enforce Gate step:
      → exits 1 if status == "fail" (job fails, PR shows red check)
      → exits 0 otherwise (reporting only in Iteration 1)
```

---

## Key Design Decisions

**Why GitHub Models and not OpenAI directly?**
The target users are non-developers inside organizations. GitHub Models
requires only a GitHub account (which they already have for the repo) and uses
the same GITHUB_TOKEN already needed for CI/CD. No separate API account,
billing setup, or key rotation.

**Why bake agent code into the image instead of pulling at runtime?**
Runtime git pulls create fragility (network dependency, auth complexity) and
non-determinism (scan results vary based on agent code state). Baking code in
means a single rebuild deploys all changes, and every scan uses a known-good
agent version. The Dockerfile layer ordering ensures agent code changes only
rebuild the final layer.

**Why ThreadPoolExecutor over asyncio?**
Agent `_collect()` methods use subprocess calls (`_run_tool`) which are
blocking. `ThreadPoolExecutor` is the right primitive for I/O-bound blocking
work. Asyncio would require rewriting all subprocess calls to use asyncio
subprocess, adding complexity with no meaningful benefit.

**Why a registry instead of hardcoded agent list?**
Decoupling allows adding, disabling, or swapping agents without touching the
orchestrator. It also makes agent selection declarative and introspectable —
you can read `registry.json` to understand what the scanner does without
reading Python code.

**Why max_workers=6 for the thread pool?**
GitHub Models has rate limits (~15 req/min on free tier). With 11 agents and
some agents making 2 LLM calls, peak concurrency could hit 22 simultaneous
calls. Capping at 6 workers keeps LLM calls staggered enough to avoid rate
limit errors in most cases while still running most agents in parallel.

**Why report-only in Iteration 1?**
Non-developers building AI apps need visibility into issues before being
blocked by them. Gating before teams understand the scan results leads to
frustration and disabling the scanner. The Enforce Gate step is pre-written
and gating can be enabled with a one-line change.

---

## Extension Points

### Adding a new agent

1. Create `scanner/agents/my_agent.py` subclassing `BaseAgent`
2. Implement `_collect() -> tuple[Any, dict]` and `_interpret(raw, meta) -> dict`
3. Add entry to `scanner/registry.json`
4. Push to main — image rebuilds automatically

### Changing which LLM is used

Set `SCANNER_MODEL` environment variable (or update `scanner.env.local`).
Any model available at `https://models.inference.ai.azure.com` works.
The same endpoint supports any OpenAI-compatible API if the base URL is changed
in `llm.py`.

### Switching to a different LLM provider

Change `GITHUB_MODELS_BASE_URL` in `llm.py` to point to any OpenAI-compatible
endpoint (Azure OpenAI, local Ollama, etc.). Update auth accordingly.

### Adding a PR blocking gate

In `.github/workflows/scan.yml`, Enforce Gate step:
```python
if status == "fail":          # current: only block on critical issues
if status in ("fail", "warn"): # change to: also block on warnings
```

### Adding a new language to Semgrep scanning

Update the `SEMGREP_SUPPORTED` set in `repo_inspector.py` and add the
appropriate config pack to the `_run_semgrep()` call in `security.py`.

---

## File Reference

```
Dockerfile                    Two-stage image build
requirements.txt              Python tool versions (pinned)
package.json                  Node tool versions (under "tools" key, not "dependencies")
.dockerignore                 Excludes .git, node_modules, Python artifacts
.gitignore                    Excludes scanner.env.local, .ai-scanner/ output dirs
scan.py                       Local runner CLI (symlink to PATH as ai-scan)
scanner.env.local.example     Template for local environment config
aiprompt-setup.txt            AI-guided interactive setup prompt for Claude/ChatGPT
docs/
  project-design.md           This file
  local-scanner.md            Local scanner setup guide

.github/workflows/
  docker-build.yml            Pipeline 1: build + push image to GHCR
  scan.yml                    Pipeline 2: scan on PR/push, post results

scanner/
  __init__.py                 Empty module init
  llm.py                      GitHub Models client (OpenAI SDK)
  base_agent.py               Abstract base class for all agents
  repo_inspector.py           Repository language/framework detection
  registry.json               Agent registry (decoupling layer)
  orchestrator.py             Entry point: inspect → select → parallel run → report
  report.py                   Compile JSON report + render markdown

scanner/agents/
  __init__.py                 Empty module init
  security.py                 Semgrep + Bandit → LLM
  secrets.py                  Gitleaks + Semgrep p/secrets → LLM
  dependencies.py             Trivy + pip-audit → LLM
  license.py                  Manifest license scan → LLM
  code_quality.py             Ruff + ESLint → LLM
  dockerfile_lint.py          Hadolint → LLM
  ai_safety.py                LLM: AI app risk analysis
  api_design.py               LLM: API design review
  auth.py                     LLM: auth/session code review
  non_code_files.py           LLM: docs, notebooks, .env files
  test_coverage.py            Static: test posture assessment → LLM
```
