# Local Scanner Setup

The AI Scanner can run on your local machine against any project directory — no GitHub Actions, no CI pipeline required. This is useful for scanning a project before you push, or for scanning projects that aren't hosted on GitHub.

**Prerequisites:** Docker Desktop (running), Python 3.8+, a GitHub account.

---

## How it works

`scan.py` is a Python CLI that:
1. Reads your configuration from `scanner.env.local`
2. Builds or pulls the scanner Docker image
3. Mounts your project (read-only) and an output directory into the container
4. Runs all 11 scanner agents against your project
5. Writes `scan-report.json` and `scan-summary.md` into `<your-project>/.ai-scanner/`

The same agents and LLM logic run locally as in CI — results are identical.

---

## Step 1 — Get a GitHub token

The scanner uses GitHub Models (GPT-4o) to interpret findings. Authentication uses a standard GitHub personal access token — no OpenAI account or credit card needed.

1. Go to [https://github.com/settings/tokens?type=beta](https://github.com/settings/tokens?type=beta)
2. Click **Generate new token**
3. Give it a name (e.g. `ai-scanner-local`) and set an expiration
4. Under **Permissions → Account permissions**, set **Models → Read**
   (Required for GitHub Models API access — without it you'll get a 401 error)
5. Click **Generate token** and copy the value

---

## Step 2 — Configure your environment

From the root of this repo:

```bash
cp scanner.env.local.example scanner.env.local
```

Open `scanner.env.local` and set your token:

```env
GITHUB_TOKEN=ghp_your_actual_token_here
```

`scanner.env.local` is listed in `.gitignore` — it will never be committed.

**Optional settings in `scanner.env.local`:**

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_IMAGE` | `ai-scanner:local` | Docker image to use. Change to `ghcr.io/YOUR_ORG/ai-scanner:latest` to use the pre-built GHCR image instead of a local build. |
| `SCANNER_MODEL` | `gpt-4o` | GitHub Models model for analysis |
| `SCANNER_FALLBACK_MODEL` | `gpt-4o-mini` | Used when rate limited |

---

## Step 3 — Add `scan.py` to your PATH

This is a one-time step that lets you run `ai-scan` from anywhere on your machine.

```bash
chmod +x scan.py
sudo ln -sf "$(pwd)/scan.py" /usr/local/bin/ai-scan
```

Verify it works:

```bash
ai-scan --help
```

If you prefer not to add it to PATH, you can always run it directly:

```bash
python3 /path/to/agentic-cicd-scanner/scan.py [args]
```

---

## Step 4 — Build the Docker image

The first time you scan, you need to build the image locally. This takes 5–10 minutes and only needs to be done once (or whenever scanner code changes).

```bash
ai-scan --build-only
```

This builds the image and tags it as `ai-scanner:local` (or whatever `SCANNER_IMAGE` is set to in your env file).

**Alternatively**, if you've already built and pushed to GHCR via GitHub Actions, you can skip building locally and point to the pre-built image:

```env
# in scanner.env.local
SCANNER_IMAGE=ghcr.io/YOUR_GITHUB_USERNAME/ai-scanner:latest
```

Then log in to GHCR first:

```bash
echo YOUR_GITHUB_TOKEN | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
```

---

## Step 5 — Scan a project

```bash
# Scan the current directory
ai-scan

# Scan a specific project
ai-scan /path/to/your/project

# Build the image AND scan in one command
ai-scan --build /path/to/your/project
```

The scan takes 1–3 minutes depending on project size and GitHub Models response times.

---

## Reading the results

Reports are written to `.ai-scanner/` inside the project you scanned:

```
your-project/
└── .ai-scanner/
    ├── scan-report.json   ← full structured report (all agents, all findings)
    └── scan-summary.md    ← human-readable markdown summary
```

**`scan-summary.md`** is the fastest way to review results — open it in any markdown viewer or text editor. It includes an overall score, a plain-language executive summary written by the LLM, a table of critical and high findings, and a per-agent breakdown.

**`scan-report.json`** contains the complete structured data: every finding from every agent, severity, file path, line number, suggested fix, per-agent scores, and the full repo context detected by the repo inspector.

The `.ai-scanner/` directory is git-ignored by default — reports stay local and won't be committed.

---

## Keeping the image up to date

Security rules and agent prompts are updated over time. Rebuild your local image periodically to pick up changes:

```bash
# Pull latest code
git pull

# Rebuild
ai-scan --build-only
```

If you're using the GHCR image (`ghcr.io/.../ai-scanner:latest`), pull the latest version:

```bash
docker pull ghcr.io/YOUR_GITHUB_USERNAME/ai-scanner:latest
```

---

## Troubleshooting

**`scanner.env.local not found`**
Run `cp scanner.env.local.example scanner.env.local` and fill in your token.

**`GITHUB_TOKEN is missing or still set to the placeholder`**
Open `scanner.env.local` and replace `ghp_your_token_here` with your actual token.

**`docker: command not found`**
Install Docker Desktop from [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop) and make sure it's running.

**`Cannot connect to the Docker daemon`**
Docker Desktop isn't running. Start it from your Applications folder.

**`Unable to find image 'ai-scanner:local'`**
The image hasn't been built yet. Run `ai-scan --build-only`.

**Scan runs but findings say "LLM unavailable"**
Your `GITHUB_TOKEN` may be invalid or expired. Create a new one at [https://github.com/settings/tokens](https://github.com/settings/tokens).

**Rate limit errors from GitHub Models**
The scanner retries automatically with backoff. If it still fails, wait a few minutes and retry. Free tier limits are approximately 15 requests/minute. Running `SCANNER_FALLBACK_MODEL=gpt-4o-mini` in your env file reduces token usage significantly.
