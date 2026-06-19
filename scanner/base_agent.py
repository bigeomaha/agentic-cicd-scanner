"""
Abstract base class for all scanner agents.

Every agent:
  1. Implements _collect()  — runs tools / gathers raw data
  2. Implements _interpret() — calls LLM to produce structured findings
  3. Returns the standard JSON report envelope via run()

The orchestrator only ever calls run() and reads the envelope.
"""
import time
import logging
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Standard severity ordering (highest → lowest)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class BaseAgent(ABC):
    """Abstract base for all scanner agents."""

    agent_id: str = "base"
    category: str = "general"

    def __init__(self, repo_path: str, context: dict | None = None):
        """
        Args:
            repo_path: Absolute path to the repository being scanned.
            context:   Output from repo_inspector.inspect() — languages, frameworks, etc.
        """
        self.repo_path = repo_path
        self.context = context or {}
        self._start_time: float = 0

    # ──────────────────────────────────────────────────────────────────────────
    # Public interface
    # ──────────────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        """
        Main entry point called by the orchestrator.
        Returns the standard report envelope.
        """
        self._start_time = time.time()

        try:
            raw_data, metadata = self._collect()
            result = self._interpret(raw_data, metadata)
        except Exception as exc:
            logger.exception(f"[{self.agent_id}] Unhandled error: {exc}")
            return self._error_envelope(str(exc))

        duration_ms = int((time.time() - self._start_time) * 1000)

        # Sort findings by severity
        findings = sorted(
            result.get("findings", []),
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 99),
        )

        return {
            "agent":                  self.agent_id,
            "category":               self.category,
            "status":                 result.get("status", "pass"),
            "score":                  result.get("score", 100),
            "summary":                result.get("summary", ""),
            "findings":               findings,
            "false_positive_notes":   result.get("false_positive_notes", ""),
            "languages_scanned":      metadata.get("languages_scanned", []),
            "languages_unsupported":  metadata.get("languages_unsupported", []),
            "metadata": {
                "duration_ms":   duration_ms,
                "files_scanned": metadata.get("files_scanned", 0),
                "tool":          metadata.get("tool", "llm-agent"),
                **{
                    k: v for k, v in metadata.items()
                    if k not in ("languages_scanned", "languages_unsupported",
                                 "files_scanned", "tool")
                },
            },
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Abstract methods — implement in each agent
    # ──────────────────────────────────────────────────────────────────────────

    @abstractmethod
    def _collect(self) -> tuple[Any, dict]:
        """
        Gather raw data (run tools, read files, etc.).

        Returns:
            raw_data : anything — passed straight to _interpret()
            metadata : dict with at minimum:
                        - tool (str)
                        - files_scanned (int)
                        - languages_scanned (list[str])
                        - languages_unsupported (list[str])
        """
        ...

    @abstractmethod
    def _interpret(self, raw_data: Any, metadata: dict) -> dict:
        """
        Produce the structured report by calling the LLM (or applying local logic).

        Returns a dict with keys:
            findings, summary, status, score, false_positive_notes (optional)
        """
        ...

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers available to all agents
    # ──────────────────────────────────────────────────────────────────────────

    def _run_tool(
        self,
        cmd: list[str],
        timeout: int = 120,
        cwd: str | None = None,
    ) -> tuple[str, str, int]:
        """
        Run a subprocess command.
        Returns (stdout, stderr, returncode).
        Never raises — errors are surfaced via returncode / stderr.
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd or self.repo_path,
            )
            return result.stdout, result.stderr, result.returncode

        except subprocess.TimeoutExpired:
            logger.warning(f"[{self.agent_id}] Tool timed out after {timeout}s: {' '.join(cmd)}")
            return "", f"Timed out after {timeout}s", 124

        except FileNotFoundError:
            logger.error(f"[{self.agent_id}] Tool not found: {cmd[0]}")
            return "", f"Tool not found: {cmd[0]}", 127

    def _read_files(
        self,
        patterns: list[str],
        max_files: int = 15,
        max_lines: int = 250,
        skip_dirs: set[str] | None = None,
    ) -> dict[str, str]:
        """
        Read files matching glob patterns from the repo.
        Returns {relative_path: content} with per-file line limits.
        """
        import fnmatch

        _skip = skip_dirs or {
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            "dist", "build", ".pytest_cache",
        }

        repo = Path(self.repo_path)
        results: dict[str, str] = {}

        for path in sorted(repo.rglob("*")):
            if len(results) >= max_files:
                break
            if path.is_dir():
                continue
            if any(part in _skip for part in path.parts):
                continue

            rel = str(path.relative_to(repo))
            if any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(path.name, p) for p in patterns):
                try:
                    lines = path.read_text(errors="ignore").splitlines()
                    results[rel] = "\n".join(lines[:max_lines])
                    if len(lines) > max_lines:
                        results[rel] += f"\n... [{len(lines) - max_lines} more lines truncated]"
                except OSError:
                    pass

        return results

    def _find_files(self, patterns: list[str], skip_dirs: set[str] | None = None) -> list[str]:
        """
        Return relative paths of files matching any of the given glob patterns.
        """
        import fnmatch

        _skip = skip_dirs or {
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            "dist", "build", ".pytest_cache",
        }

        repo = Path(self.repo_path)
        matches: list[str] = []

        for path in repo.rglob("*"):
            if path.is_dir():
                continue
            if any(part in _skip for part in path.parts):
                continue
            rel = str(path.relative_to(repo))
            if any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(path.name, p) for p in patterns):
                matches.append(rel)

        return sorted(matches)

    def _skipped_envelope(self, reason: str) -> tuple[Any, dict]:
        """
        Return a collect() result indicating this agent has nothing to scan.
        Use when the repo doesn't contain files relevant to this agent.
        """
        return None, {
            "tool": "n/a",
            "files_scanned": 0,
            "languages_scanned": [],
            "languages_unsupported": [],
            "skipped": True,
            "skip_reason": reason,
        }

    def _skipped_result(self, reason: str) -> dict:
        """Return an interpret() result for a skipped scan."""
        return {
            "findings": [],
            "summary": f"Skipped: {reason}",
            "status": "pass",
            "score": 100,
        }

    def _error_envelope(self, error_msg: str) -> dict:
        return {
            "agent":                 self.agent_id,
            "category":              self.category,
            "status":                "error",
            "score":                 0,
            "summary":               f"Agent error: {error_msg}",
            "findings":              [],
            "false_positive_notes":  "",
            "languages_scanned":     [],
            "languages_unsupported": [],
            "metadata": {
                "duration_ms": int((time.time() - self._start_time) * 1000),
                "tool":        "error",
                "error":       error_msg,
            },
        }
