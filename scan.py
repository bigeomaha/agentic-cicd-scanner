#!/usr/bin/env python3
"""
ai-scan — AI Scanner local runner

Usage:
    ai-scan [PROJECT_PATH]         Scan a project (default: current directory)
    ai-scan --build [PROJECT_PATH] Build image first, then scan
    ai-scan --build-only           Build image and exit

Installation (add to PATH):
    chmod +x scan.py
    sudo ln -sf "$(pwd)/scan.py" /usr/local/bin/ai-scan

Environment:
    Reads scanner.env.local from the same directory as this script.
    Copy scanner.env.local.example → scanner.env.local and fill in your values.
    See: aiprompt-setup.txt for full setup instructions.
"""
import argparse
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR  = Path(__file__).resolve().parent
ENV_FILE    = SCRIPT_DIR / "scanner.env.local"
DEFAULT_IMAGE = "ai-scanner:local"


# ── Env file loader ───────────────────────────────────────────────────────────

def load_env(path: Path) -> dict[str, str]:
    """Parse KEY=VALUE lines from an env file. Skips comments and blank lines."""
    if not path.exists():
        print(f"\n❌  {path} not found.")
        print(f"    Copy scanner.env.local.example → scanner.env.local")
        print(f"    and fill in your GITHUB_TOKEN.\n")
        sys.exit(1)

    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            env[key.strip()] = val.strip().strip('"').strip("'")
    return env


# ── Shell helper ──────────────────────────────────────────────────────────────

def run(cmd: list[str]) -> int:
    return subprocess.run(cmd).returncode


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ai-scan",
        description="AI Scanner — run a full security and quality scan locally",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  ai-scan                        scan the current directory
  ai-scan /path/to/project       scan a specific project
  ai-scan --build .              build image, then scan current directory
  ai-scan --build-only           just build the image (no scan)
""",
    )
    parser.add_argument(
        "project",
        nargs="?",
        default=None,
        help="path to the project to scan (default: current directory)",
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="build the Docker image before scanning",
    )
    parser.add_argument(
        "--build-only",
        action="store_true",
        help="build the Docker image and exit without scanning",
    )
    args = parser.parse_args()

    env   = load_env(ENV_FILE)
    image = env.get("SCANNER_IMAGE", DEFAULT_IMAGE)

    # ── Build ─────────────────────────────────────────────────────────────────
    if args.build or args.build_only:
        print(f"\n🔨  Building {image} from {SCRIPT_DIR} ...")
        rc = run(["docker", "build", "-t", image, str(SCRIPT_DIR)])
        if rc != 0:
            print("❌  Build failed. Check the output above.")
            sys.exit(rc)
        print(f"✅  Build complete: {image}\n")
        if args.build_only:
            sys.exit(0)

    # ── Resolve project path ──────────────────────────────────────────────────
    project = Path(args.project).resolve() if args.project else Path.cwd()
    if not project.is_dir():
        print(f"❌  Not a directory: {project}")
        sys.exit(1)

    # ── Validate token ────────────────────────────────────────────────────────
    github_token = env.get("GITHUB_TOKEN", "")
    if not github_token or "your_token_here" in github_token:
        print("❌  GITHUB_TOKEN is missing or still set to the placeholder value.")
        print(f"    Edit {ENV_FILE} and add a real GitHub token.")
        sys.exit(1)

    # ── Prepare output dir ────────────────────────────────────────────────────
    output_dir = project / ".ai-scanner"
    output_dir.mkdir(exist_ok=True)

    # ── Print run info ────────────────────────────────────────────────────────
    print(f"\n🔍  AI Scanner")
    print(f"    Project : {project}")
    print(f"    Image   : {image}")
    print(f"    Reports : {output_dir}")
    print()

    # ── Build docker env flags ────────────────────────────────────────────────
    # Only pass recognised variables into the container — not SCANNER_IMAGE etc.
    container_env = {"GITHUB_TOKEN": github_token, "PYTHONPATH": "/scanner"}
    for key in ("SCANNER_MODEL", "SCANNER_FALLBACK_MODEL"):
        if key in env:
            container_env[key] = env[key]

    env_flags: list[str] = []
    for k, v in container_env.items():
        env_flags += ["-e", f"{k}={v}"]

    # ── Run ───────────────────────────────────────────────────────────────────
    cmd = [
        "docker", "run", "--rm",
        *env_flags,
        "-v", f"{project}:/scan:ro",
        "-v", f"{output_dir}:/reports",
        image,
        "python", "-m", "scanner.orchestrator",
        "--repo",     "/scan",
        "--output",   "/reports/scan-report.json",
        "--markdown", "/reports/scan-summary.md",
    ]

    rc = run(cmd)

    print(f"\n{'─' * 52}")
    print(f"  Reports written to: {output_dir}/")
    print(f"    scan-report.json   ← full structured JSON")
    print(f"    scan-summary.md    ← human-readable summary")
    print(f"{'─' * 52}\n")

    sys.exit(rc)


if __name__ == "__main__":
    main()
