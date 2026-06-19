# =============================================================================
# AI Scanner — Docker Image
# =============================================================================
# Two-stage build:
#   Stage 1 (downloader) — fetches standalone binary tools (trivy, gitleaks, hadolint)
#   Stage 2 (final)      — python:3.12-slim + node + binaries + python/node tools
#
# Layer order is intentional: slowest/most-stable layers first so Docker cache
# is preserved across routine updates to agent code and prompts.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Binary downloader
# Keeps curl/wget out of the final image.
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS downloader

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Trivy — dependency & container vulnerability scanner (aquasecurity)
ARG TRIVY_VERSION=0.51.4
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"

# Gitleaks — secret & credential detection
ARG GITLEAKS_VERSION=8.18.2
RUN curl -sSfL \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

# Hadolint — Dockerfile linter
ARG HADOLINT_VERSION=2.12.0
RUN curl -sSfL \
    "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
    -o /usr/local/bin/hadolint \
    && chmod +x /usr/local/bin/hadolint

# Verify binaries exist before moving on
RUN trivy --version && gitleaks version && hadolint --version


# -----------------------------------------------------------------------------
# Stage 2: Final image
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS final

LABEL org.opencontainers.image.title="ai-scanner"
LABEL org.opencontainers.image.description="AI Scanner — pre-built CI/CD image with tools, runtimes, and agent system"
LABEL org.opencontainers.image.source="https://github.com/bigeomaha/agentic-cicd-scanner"

# ── System dependencies + Node.js LTS ────────────────────────────────────────
ARG NODE_MAJOR=20
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
        gnupg \
    # Node.js — official NodeSource repo
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# ── Binary tools from Stage 1 ────────────────────────────────────────────────
COPY --from=downloader /usr/local/bin/trivy    /usr/local/bin/trivy
COPY --from=downloader /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=downloader /usr/local/bin/hadolint /usr/local/bin/hadolint

# ── Python scanning tools ─────────────────────────────────────────────────────
# requirements.txt is copied first so this layer is only invalidated when
# tool versions change, not when agent code changes.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /tmp/requirements.txt

# ── Node scanning tools ───────────────────────────────────────────────────────
COPY package.json /tmp/package.json
RUN npm install --global \
        eslint@$(node -p "require('/tmp/package.json').tools.eslint") \
        @eslint/js@$(node -p "require('/tmp/package.json').tools['@eslint/js']") \
    && npm cache clean --force

# ── Pre-warm Semgrep rule cache ───────────────────────────────────────────────
# Downloads rule packs at build time so first scan doesn't pay the fetch cost.
RUN semgrep --config p/python       /dev/null 2>/dev/null || true \
    && semgrep --config p/javascript  /dev/null 2>/dev/null || true \
    && semgrep --config p/typescript  /dev/null 2>/dev/null || true \
    && semgrep --config p/secrets     /dev/null 2>/dev/null || true \
    && semgrep --config p/owasp-top-ten /dev/null 2>/dev/null || true

# ── Agent system ──────────────────────────────────────────────────────────────
# Copied after tools so tool layers stay cached when agent code changes.
COPY scanner/ /scanner/scanner/

# ── Non-root user ─────────────────────────────────────────────────────────────
RUN useradd -m -u 1001 -s /bin/bash scanner
USER scanner

# ── Working directory (repo will be mounted here) ─────────────────────────────
WORKDIR /scan

# ── Sanity-check all tools at build time ──────────────────────────────────────
RUN trivy --version \
    && gitleaks version \
    && hadolint --version \
    && semgrep --version \
    && ruff --version \
    && pip-audit --version \
    && bandit --version \
    && eslint --version \
    && node --version \
    && python --version

CMD ["python", "-m", "scanner.orchestrator", "--help"]
