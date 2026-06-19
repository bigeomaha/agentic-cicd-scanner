"""
Non-code files agent — LLM-only.

Reviews documentation, prompt files, and Jupyter notebooks for:
  - PII in examples or templates
  - Sensitive architecture details exposed in docs
  - Prompt template quality and injection risks
  - Real credentials in .env.example files
  - Notebook cell output containing sensitive data
"""
import json
import logging
from pathlib import Path
from typing import Any

from scanner.base_agent import BaseAgent
from scanner import llm

logger = logging.getLogger(__name__)


class NonCodeFilesAgent(BaseAgent):
    agent_id = "non_code_files"
    category = "security"

    def _collect(self) -> tuple[Any, dict]:
        repo = Path(self.repo_path)
        collected: dict[str, str] = {}

        # Markdown and text docs
        docs = self._read_files(["*.md", "*.txt", "*.rst"], max_files=15, max_lines=150)
        collected.update({f"[doc] {k}": v for k, v in docs.items()})

        # .env example files (check for real values)
        env_files = self._read_files([".env.example", ".env.sample", ".env.template"], max_files=5, max_lines=100)
        collected.update({f"[env] {k}": v for k, v in env_files.items()})

        # Jupyter notebooks — extract markdown cells and code cells (not output)
        notebooks = self._read_notebooks(max_notebooks=5)
        collected.update({f"[notebook] {k}": v for k, v in notebooks.items()})

        if not collected:
            return self._skipped_envelope("No documentation, prompt files, or notebooks found.")

        return collected, {
            "tool":                  "llm-agent",
            "files_scanned":         len(collected),
            "doc_files":             len(docs),
            "env_files":             len(env_files),
            "notebooks":             len(notebooks),
            "languages_scanned":     ["markdown", "text", "jupyter"],
            "languages_unsupported": [],
        }

    def _interpret(self, raw_data: Any, metadata: dict) -> dict:
        if metadata.get("skipped"):
            return self._skipped_result(metadata.get("skip_reason", ""))

        files_str = "\n\n".join(
            f"=== {path} ===\n{content}"
            for path, content in raw_data.items()
        )
        if len(files_str) > 14_000:
            files_str = files_str[:14_000] + "\n\n... [truncated]"

        prompt = f"""You are reviewing non-code files (documentation, prompt templates, environment files, and Jupyter notebooks) for security and privacy issues.

Files to review:
{files_str}

Evaluate these areas:

1. PII IN EXAMPLES — Real names, email addresses, phone numbers, addresses, or any identifiable
   personal data used as examples in documentation or as few-shot examples in prompts.
   Even "fake" examples that look real (john.smith@company.com) should be flagged.

2. CREDENTIALS IN ENV FILES — .env.example files sometimes contain real API keys, passwords,
   or connection strings that developers copy-pasted from their actual environment.
   Flag anything that looks like a real credential vs a placeholder like "your-api-key-here".

3. SENSITIVE ARCHITECTURE EXPOSURE — README or docs that describe internal systems,
   database schemas, server architecture, or security mechanisms in detail that could
   help an attacker. A public README should not include internal IP ranges, DB credentials,
   or detailed vulnerability information.

4. PROMPT TEMPLATE QUALITY — In .txt or .md prompt files, flag:
   - Instructions that are overly permissive ("do whatever the user asks")
   - Places where user input is inserted without any guidance about sanitisation
   - System prompts that reveal sensitive business logic unnecessarily

5. NOTEBOOK OUTPUT — Jupyter notebooks sometimes have cell output containing API responses,
   PII, or error messages with sensitive paths/credentials. Note: [notebook] prefixed files
   in this review have had output cells extracted — check for sensitive data there.

6. STALE OR MISLEADING DOCUMENTATION — Instructions pointing to deprecated APIs,
   old endpoints, or security practices that are no longer valid. This can mislead
   developers into using insecure approaches.

Return JSON with this exact schema:
{{
  "findings": [
    {{
      "severity": "critical|high|medium|low|info",
      "rule": "pii-in-examples|real-credential-in-env|architecture-exposure|permissive-prompt|notebook-sensitive-output|stale-docs",
      "file": "path/to/file",
      "line": null_or_integer,
      "message": "Plain language description of what was found and why it is a risk",
      "suggestion": "Specific action to remediate"
    }}
  ],
  "summary": "2-3 sentence summary of non-code file risks for a non-developer",
  "status": "pass|warn|fail",
  "score": 0-100,
  "false_positive_notes": ""
}}"""

        result = llm.interpret_as_json(prompt, max_tokens=2500)
        return result if result else {
            "findings": [],
            "summary": "Non-code file review could not be completed. Manual review recommended.",
            "status": "warn",
            "score": 50,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _read_notebooks(self, max_notebooks: int = 5) -> dict[str, str]:
        """
        Extract code cells and markdown cells from Jupyter notebooks.
        Skips output cells — they can be huge and often contain irrelevant data.
        But we DO note if output cells exist and flag that in the text.
        """
        repo = Path(self.repo_path)
        results: dict[str, str] = {}

        notebooks = list(repo.rglob("*.ipynb"))[:max_notebooks]
        for nb_path in notebooks:
            try:
                data = json.loads(nb_path.read_text(errors="ignore"))
                cells = data.get("cells", [])
                lines: list[str] = []
                has_output = False

                for cell in cells:
                    cell_type = cell.get("cell_type", "")
                    source = "".join(cell.get("source", []))
                    outputs = cell.get("outputs", [])

                    if outputs:
                        has_output = True
                        # Include first 5 lines of output to catch sensitive data
                        for out in outputs[:2]:
                            text = "".join(out.get("text", out.get("data", {}).get("text/plain", [])))
                            if text.strip():
                                lines.append(f"[OUTPUT]: {text[:300]}")

                    if cell_type == "markdown":
                        lines.append(f"[MARKDOWN]: {source[:500]}")
                    elif cell_type == "code":
                        lines.append(f"[CODE]: {source[:500]}")

                if has_output:
                    lines.insert(0, "[NOTE: This notebook has cell outputs — check for sensitive data above]")

                rel = str(nb_path.relative_to(repo))
                results[rel] = "\n".join(lines[:200])

            except (json.JSONDecodeError, OSError) as exc:
                logger.debug(f"[non_code_files] Could not read notebook {nb_path}: {exc}")

        return results
