# agentic-cicd-scanner

AI-powered CI/CD code scanner for GitHub. Runs on every PR and push — parallel agents check security, secrets, dependencies, licenses, code quality, auth, API design, AI safety, and test coverage. Results posted as PR comments via GitHub Models (GPT-4o). No external API keys required.

---

## How it works

Every pull request and push triggers the scan pipeline. It pulls a pre-built Docker image from GitHub Container Registry, mounts your repository, and runs 11 specialist agents in parallel. Each agent combines tool output with LLM interpretation so findings are explained in plain language — not raw JSON noise. Results are compiled into a structured report and posted directly to the PR as a comment.

```
PR / Push
    │
    ▼
Repo Inspector  ──  detects languages, frameworks, AI libraries
    │
    ▼
Agent Selector  ──  reads registry.json, picks applicable agents
    │
    ├─► Security Agent      (Semgrep + Bandit → LLM)
    ├─► Secrets Agent       (Gitleaks + Semgrep → LLM)
    ├─► Dependencies Agent  (Trivy + pip-audit → LLM)
    ├─► License Agent       (dep manifest scan → LLM)
    ├─► Code Quality Agent  (Ruff + ESLint → LLM)
    ├─► Dockerfile Agent    (Hadolint → LLM)
    ├─► AI Safety Agent     (LLM — AI apps only)
    ├─► API Design Agent    (LLM — route files)
    ├─► Auth Agent          (LLM — auth/session files)
    ├─► Non-Code Agent      (LLM — docs, notebooks, .env)
    └─► Test Coverage Agent (static analysis → LLM)
            │
            ▼
       Orchestrator  ──  compiles JSON report + markdown summary
            │
            ▼
       PR Comment  +  Commit Status  +  Artifact (JSON)
```

The scanner is **decoupled**: agents are registered in `scanner/registry.json`. The orchestrator reads the registry at runtime, so you can add, remove, or swap agents without touching the orchestration code.

---

## Agents

| Agent | Type | Runs on |
|-------|------|---------|
| `security` | Tool + LLM | Repos with Python, JS, TS, Go, Java, Ruby |
| `secrets` | Tool + LLM | All repos |
| `dependencies` | Tool + LLM | All repos |
| `license` | Tool + LLM | All repos |
| `code_quality` | Tool + LLM | Python and/or JS/TS repos |
| `dockerfile_lint` | Tool + LLM | Repos with a Dockerfile |
| `ai_safety` | LLM only | Repos detected as AI apps |
| `api_design` | LLM only | Python and/or JS/TS repos |
| `auth` | LLM only | Repos with detectable code |
| `non_code_files` | LLM only | All repos |
| `test_coverage` | Static + LLM | All repos |

**Tool-based agents** run CLI security tools (Semgrep, Bandit, Trivy, Gitleaks, Hadolint, Ruff, ESLint), parse their JSON output, then send findings to the LLM for interpretation and plain-language explanations.

**LLM-only agents** read relevant source files directly and reason about them — used for areas where static tools don't exist (auth patterns, AI prompt safety, API design quality).

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| Orchestration | Python 3.12, `concurrent.futures.ThreadPoolExecutor` |
| LLM | GitHub Models (GPT-4o / GPT-4o-mini) via OpenAI SDK |
| SAST | Semgrep, Bandit, Ruff, ESLint |
| Secret detection | Gitleaks, Semgrep `p/secrets` |
| Dependency CVEs | Trivy, pip-audit |
| Dockerfile linting | Hadolint |
| Container registry | GitHub Container Registry (GHCR) |
| CI/CD | GitHub Actions |

No external API keys, no paid services. Everything runs on your existing GitHub account.

---

## Repository structure

```
├── Dockerfile                          # Two-stage image build
├── requirements.txt                    # Python tool versions
├── package.json                        # Node tool versions (ESLint)
├── .dockerignore
├── .gitignore
├── scan.py                             # Local scanner CLI (add to PATH)
├── scanner.env.local.example           # Environment config template
├── aiprompt-setup.txt                  # CI/CD setup guide (GitHub Actions)
├── docs/
│   └── local-scanner.md                # Local scanner setup guide
├── .github/
│   └── workflows/
│       ├── docker-build.yml            # Pipeline 1: build & push image
│       └── scan.yml                    # Pipeline 2: scan on PR/push
└── scanner/
    ├── llm.py                          # GitHub Models client
    ├── base_agent.py                   # Abstract base all agents inherit
    ├── repo_inspector.py               # Language/framework detection
    ├── registry.json                   # Agent registry (decoupling layer)
    ├── orchestrator.py                 # Main entry point
    ├── report.py                       # JSON + markdown report compiler
    └── agents/
        ├── security.py
        ├── secrets.py
        ├── dependencies.py
        ├── license.py
        ├── code_quality.py
        ├── dockerfile_lint.py
        ├── ai_safety.py
        ├── api_design.py
        ├── auth.py
        ├── non_code_files.py
        └── test_coverage.py
```

---

## Setup

There are two ways to use the scanner:

### CI/CD (GitHub Actions) — runs automatically on every PR

See **[`aiprompt-setup.txt`](aiprompt-setup.txt)** for the complete walkthrough. The short version:

1. Fork or clone this repo into your GitHub account
2. Create a fine-grained GitHub personal access token with `packages:write`, `pull-requests:write`, and `statuses:write`
3. Trigger the **Build & Push AI Scanner Image** workflow to build the Docker image
4. Open a pull request — the **AI Code Scan** workflow runs automatically

### Local — scan any project from your terminal

See **[`docs/local-scanner.md`](docs/local-scanner.md)** for full instructions. Quick start:

```bash
# 1. Configure your token
cp scanner.env.local.example scanner.env.local
# edit scanner.env.local — add your GITHUB_TOKEN

# 2. Add to PATH (one-time)
chmod +x scan.py
sudo ln -sf "$(pwd)/scan.py" /usr/local/bin/ai-scan

# 3. Build the Docker image (one-time)
ai-scan --build-only

# 4. Scan any project
ai-scan /path/to/your/project
```

GitHub Models access is included with your GitHub account. No OpenAI account required.

---

## Docker image

The image is built by `docker-build.yml` and pushed to GHCR. It is rebuilt automatically:
- When any scanner file changes (pushed to `main`)
- Weekly on Monday at 02:00 UTC (to pick up updated security rules)
- On manual dispatch from the Actions tab

The two-stage Dockerfile separates binary tool downloads from the runtime image so CI layer caching is maximized. Agent code is copied last, so updating a prompt only rebuilds the final layer.

---

## Adding an agent

1. Create `scanner/agents/your_agent.py` — subclass `BaseAgent`, implement `_collect()` and `_interpret()`
2. Add an entry to `scanner/registry.json` with `id`, `module`, `class`, `category`, `type`, `always_run`, and `requires`
3. Push to `main` — the image rebuilds automatically

The `requires` block controls when the agent runs:

```json
{
  "id": "your_agent",
  "module": "scanner.agents.your_agent",
  "class": "YourAgent",
  "category": "security",
  "type": "tool-wrapper",
  "always_run": false,
  "requires": {
    "languages": ["python", "javascript"]
  }
}
```

---

## Output

Every scan produces:

- **`scan-report.json`** — full structured report with all agent results, scores, and findings
- **`scan-summary.md`** — human-readable markdown posted as a PR comment
- **GitHub commit status** — `AI Scanner: Score 87/100 — WARN`
- **Actions artifact** — both files retained for 30 days

Local scans write reports to `<project>/.ai-scanner/` in the scanned project directory.

Iteration 1 is **report-only** — scans never block merges. To enforce a gate, edit the `Enforce Gate` step in `scan.yml`.

---

## License

MIT — see [LICENSE](LICENSE)
