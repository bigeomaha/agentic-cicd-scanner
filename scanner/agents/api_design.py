"""
API Design agent — LLM-only.

Reviews API route handlers for design quality:
  - Correct HTTP verb usage
  - Consistent error responses
  - Input validation
  - Data exposure (returning more than needed)
  - API versioning
  - Missing pagination on list endpoints
"""
import logging
from typing import Any

from scanner.base_agent import BaseAgent
from scanner import llm

logger = logging.getLogger(__name__)

# File patterns that typically contain route/API handler definitions
ROUTE_PATTERNS = [
    # Python web frameworks
    "routes.py", "views.py", "api.py", "endpoints.py", "handlers.py",
    "app.py", "main.py", "server.py",
    "*router*.py", "*route*.py", "*api*.py", "*view*.py", "*endpoint*.py",
    # Node / Express
    "*router*.js", "*route*.js", "*api*.js", "*controller*.js",
    "*router*.ts", "*route*.ts", "*api*.ts", "*controller*.ts",
]

# Keywords that indicate an API/route file
ROUTE_KEYWORDS = [
    "@app.route", "@router.", "app.get(", "app.post(", "app.put(", "app.delete(",
    "router.get(", "router.post(", "FastAPI", "flask", "express", "APIRouter",
    "Request", "Response", "HTTPException", "@get(", "@post(", "@put(", "@delete(",
]


class APIDesignAgent(BaseAgent):
    agent_id = "api_design"
    category = "quality"

    def _collect(self) -> tuple[Any, dict]:
        languages = self.context.get("languages", {})
        if not any(l in languages for l in ("python", "javascript", "typescript")):
            return self._skipped_envelope("No Python or JavaScript/TypeScript files found.")

        route_files = self._find_route_files()

        if not route_files:
            return self._skipped_envelope(
                "No API route handler files detected. "
                "This project may not expose an HTTP API."
            )

        return route_files, {
            "tool":                  "llm-agent",
            "files_scanned":         len(route_files),
            "languages_scanned":     [l for l in ("python", "javascript", "typescript") if l in languages],
            "languages_unsupported": [],
        }

    def _interpret(self, raw_data: Any, metadata: dict) -> dict:
        if metadata.get("skipped"):
            return self._skipped_result(metadata.get("skip_reason", ""))

        files_str = "\n\n".join(
            f"=== {path} ===\n{content}"
            for path, content in raw_data.items()
        )
        if len(files_str) > 12_000:
            files_str = files_str[:12_000] + "\n\n... [truncated]"

        prompt = f"""You are reviewing API route handlers for design quality. The developers are not professional software engineers — they are building AI applications and may not know REST API best practices.

API files to review:
{files_str}

Evaluate these areas:

1. HTTP VERB USAGE — Are GET/POST/PUT/DELETE/PATCH used semantically correctly?
   (e.g., using POST for data retrieval, or DELETE that actually updates a record)

2. ERROR RESPONSES — Are errors returned with appropriate HTTP status codes and
   consistent JSON error bodies? Or just generic 500s and plain text messages?

3. INPUT VALIDATION — Is incoming data validated before processing?
   Missing validation is both a security risk and a reliability issue.

4. DATA EXPOSURE — Are endpoints returning full database records when only a
   subset of fields is needed? Returning sensitive fields like passwords, tokens, internal IDs?

5. VERSIONING — Is there any API versioning (e.g., /v1/, /api/v2/)? Without it,
   breaking changes will affect all existing clients.

6. PAGINATION — Do list endpoints return all records, or is there pagination?
   Returning everything at once causes performance issues at scale.

7. AUTHENTICATION ENFORCEMENT — Are protected routes consistently checking authentication,
   or are some routes accidentally left open?

Return JSON with this exact schema:
{{
  "findings": [
    {{
      "severity": "critical|high|medium|low|info",
      "rule": "wrong-http-verb|missing-error-handling|no-input-validation|data-exposure|no-versioning|missing-pagination|missing-auth-check",
      "file": "path/to/file",
      "line": null_or_integer,
      "message": "Plain language description of the design issue",
      "suggestion": "Specific fix with example if helpful"
    }}
  ],
  "summary": "2-3 sentence assessment of the API design quality for a non-developer",
  "status": "pass|warn|fail",
  "score": 0-100,
  "false_positive_notes": ""
}}"""

        result = llm.interpret_as_json(prompt, max_tokens=2500)
        return result if result else {
            "findings": [],
            "summary": "API design review could not be completed. Manual review recommended.",
            "status": "warn",
            "score": 50,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_route_files(self) -> dict[str, str]:
        """Find and read files that contain route/API handler code."""
        candidates = self._read_files(
            ROUTE_PATTERNS,
            max_files=12,
            max_lines=300,
        )
        # Filter to files that actually contain routing keywords
        return {
            path: content
            for path, content in candidates.items()
            if any(kw.lower() in content.lower() for kw in ROUTE_KEYWORDS)
        }
