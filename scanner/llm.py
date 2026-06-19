"""
GitHub Models LLM client.

GitHub Models exposes an OpenAI-compatible API authenticated with GITHUB_TOKEN.
Endpoint: https://models.inference.ai.azure.com
No external API keys required — the job's GITHUB_TOKEN is sufficient.
"""
import os
import json
import time
import logging
from typing import Any

from openai import OpenAI, APIError, RateLimitError

logger = logging.getLogger(__name__)

GITHUB_MODELS_BASE_URL = "https://models.inference.ai.azure.com"
DEFAULT_MODEL  = os.environ.get("SCANNER_MODEL",          "gpt-4o")
FALLBACK_MODEL = os.environ.get("SCANNER_FALLBACK_MODEL", "gpt-4o-mini")
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2  # seconds, doubles on each retry

# System prompt shared by all agents
SYSTEM_PROMPT = """You are a code security and quality analyst reviewing code written by \
non-developers building AI applications. Your role is to interpret automated scan results \
and communicate findings clearly to people who may not have a software engineering background.

Always:
- Use plain language — avoid unexplained jargon
- Explain what each finding means in practice, not just what the rule is
- Describe the real-world risk if the issue is left unfixed
- Provide a specific, actionable fix — not a generic suggestion
- Be honest about likely false positives
- Prioritise: distinguish "must fix now" from "nice to have"
- Be encouraging — these developers are learning and building real things

Respond only with valid JSON matching the schema provided in each prompt."""

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            raise EnvironmentError(
                "GITHUB_TOKEN environment variable is required. "
                "In GitHub Actions this is automatically available."
            )
        _client = OpenAI(
            base_url=GITHUB_MODELS_BASE_URL,
            api_key=token,
        )
    return _client


def interpret(
    user_prompt: str,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 2000,
    temperature: float = 0.1,
) -> str:
    """
    Call the LLM and return the raw text response.
    Retries on transient errors with exponential backoff.
    """
    client = _get_client()
    delay = RETRY_BASE_DELAY

    for attempt in range(MAX_RETRIES):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_prompt},
                ],
                max_tokens=max_tokens,
                temperature=temperature,
                response_format={"type": "json_object"},
            )
            return response.choices[0].message.content.strip()

        except RateLimitError:
            if attempt < MAX_RETRIES - 1:
                logger.warning(f"Rate limited — retrying in {delay}s (attempt {attempt + 1})")
                time.sleep(delay)
                delay *= 2
                continue
            raise

        except APIError as exc:
            if attempt < MAX_RETRIES - 1:
                logger.warning(f"API error (attempt {attempt + 1}): {exc} — retrying in {delay}s")
                time.sleep(delay)
                delay *= 2
                continue
            raise

    raise RuntimeError("LLM interpretation failed after all retries.")


def interpret_as_json(user_prompt: str, **kwargs) -> dict[str, Any]:
    """
    Call interpret() and parse the result as JSON.
    Returns an empty dict on parse failure (logged as warning).
    """
    raw = interpret(user_prompt, **kwargs)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning(f"LLM returned non-JSON response: {raw[:200]}")
        return {}


def build_findings_prompt(
    agent_name: str,
    tool_name: str,
    raw_findings: Any,
    extra_context: str = "",
) -> str:
    """
    Build a standard findings interpretation prompt.
    raw_findings can be a list, dict, or string.
    """
    findings_str = (
        json.dumps(raw_findings, indent=2)
        if not isinstance(raw_findings, str)
        else raw_findings
    )

    # Truncate very large outputs to avoid token limits
    if len(findings_str) > 12_000:
        findings_str = findings_str[:12_000] + "\n... [truncated for length]"

    return f"""Agent: {agent_name}
Tool: {tool_name}
{f"Context: {extra_context}" if extra_context else ""}

Raw tool output:
{findings_str}

Interpret these findings and return JSON with this exact schema:
{{
  "findings": [
    {{
      "severity": "critical|high|medium|low|info",
      "rule": "short_rule_id",
      "file": "path/to/file or 'N/A'",
      "line": null_or_integer,
      "message": "Plain language description of what this issue is and why it matters",
      "suggestion": "Specific actionable fix the developer can apply"
    }}
  ],
  "summary": "2-3 sentence plain-language summary suitable for a non-developer",
  "status": "pass|warn|fail",
  "score": integer_0_to_100,
  "false_positive_notes": "Optional note if some findings are likely false positives"
}}

Rules for status and score:
- pass (90-100): no real issues found
- warn (60-89): issues present but not immediately dangerous
- fail (0-59): critical or high severity issues that need attention

If no findings, return an empty findings array and status=pass, score=100."""
