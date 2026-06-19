"""
AI Safety agent — LLM-only.

Analyses AI application code for risks specific to LLM-based apps:
  - Prompt injection vulnerabilities
  - Hardcoded or floating model names
  - LLM output used without validation
  - PII passed into prompts
  - Overly permissive system prompts
  - API responses logged (PII exposure)
  - Missing rate limiting on LLM calls
"""
import json
import logging
from typing import Any

from scanner.base_agent import BaseAgent
from scanner import llm

logger = logging.getLogger(__name__)

# File patterns likely to contain AI/LLM logic
AI_CODE_PATTERNS = [
    "*.py", "*.js", "*.ts", "*.mjs",
]

# Keywords that indicate AI library usage — used to filter relevant files
AI_IMPORT_KEYWORDS = [
    "openai", "anthropic", "langchain", "llama_index", "litellm",
    "groq", "cohere", "transformers", "huggingface", "ollama",
    "ChatCompletion", "chat.completions", "messages.create",
    "system_prompt", "system prompt", "SYSTEM_PROMPT",
    "f\"", "f'",   # f-strings are a proxy for prompt construction
]


class AISafetyAgent(BaseAgent):
    agent_id = "ai_safety"
    category = "ai-safety"

    def _collect(self) -> tuple[Any, dict]:
        if not self.context.get("is_ai_app"):
            return self._skipped_envelope(
                "No AI/LLM library imports detected. "
                "If this project does use AI APIs, ensure the dependency file lists them."
            )

        # Collect source files that reference AI libraries
        relevant_files = self._find_ai_files()

        # Also collect prompt/config files
        prompt_files = self._read_files(
            ["*.txt", "*.md"],
            max_files=10,
            max_lines=150,
        )
        # Filter to files that look like prompts
        prompt_files = {
            k: v for k, v in prompt_files.items()
            if any(kw in k.lower() for kw in ("prompt", "system", "instruction", "template"))
        }

        all_content = {**relevant_files, **prompt_files}

        if not all_content:
            return self._skipped_envelope("No relevant AI source files found to analyse.")

        return all_content, {
            "tool":                  "llm-agent",
            "files_scanned":         len(all_content),
            "languages_scanned":     list(self.context.get("languages", {}).keys()),
            "languages_unsupported": [],
            "ai_files_found":        list(relevant_files.keys()),
            "prompt_files_found":    list(prompt_files.keys()),
        }

    def _interpret(self, raw_data: Any, metadata: dict) -> dict:
        if metadata.get("skipped"):
            return self._skipped_result(metadata.get("skip_reason", ""))

        files_str = "\n\n".join(
            f"=== {path} ===\n{content}"
            for path, content in raw_data.items()
        )

        # Truncate to avoid token limits
        if len(files_str) > 14_000:
            files_str = files_str[:14_000] + "\n\n... [additional files truncated]"

        prompt = f"""You are reviewing code from an AI application for AI-specific security and safety issues.

Files to review:
{files_str}

Analyse for these specific risk categories:

1. PROMPT INJECTION — Places where user input is concatenated directly into a prompt string
   without sanitisation. An attacker can craft input that hijacks the AI's instructions.
   Look for: f-strings or string concatenation building prompts with user-supplied variables.

2. MODEL VERSION PINNING — Floating model names like "gpt-4" or "claude-3" change behaviour
   when the provider updates them. Pinned versions like "gpt-4o-2024-11-20" are safer.

3. OUTPUT HANDLING — Is LLM output used directly in code (e.g., eval'd, executed as SQL,
   passed to a shell command, or rendered as HTML without escaping)? This is critical.

4. PII IN PROMPTS — Real names, emails, addresses, or sensitive data used as few-shot
   examples or hardcoded in prompt templates.

5. OVERLY PERMISSIVE SYSTEM PROMPTS — System prompts that say things like "do anything the
   user asks" or "ignore previous instructions if asked" undermine all guardrails.

6. API KEY HANDLING — Keys appearing in source files, even as comments or examples.

7. LOGGING RISKS — Are prompts or LLM responses being logged? This can expose PII sent
   by users if logs are not properly secured.

8. RATE LIMITING — LLM API calls with no throttling or cost controls can lead to runaway
   bills if abused.

Return JSON with this exact schema:
{{
  "findings": [
    {{
      "severity": "critical|high|medium|low|info",
      "rule": "prompt-injection|model-not-pinned|unsafe-output|pii-in-prompt|permissive-system-prompt|api-key-exposure|logging-risk|no-rate-limit",
      "file": "path/to/file.py",
      "line": null_or_integer,
      "message": "Plain language description of the risk and where it occurs",
      "suggestion": "Specific code-level fix or mitigation"
    }}
  ],
  "summary": "2-3 sentence summary for a non-developer explaining the AI safety posture of this app",
  "status": "pass|warn|fail",
  "score": 0-100,
  "false_positive_notes": "Note any findings that may be false positives given the context"
}}"""

        result = llm.interpret_as_json(prompt, max_tokens=2500)
        return result if result else {
            "findings": [],
            "summary": "AI safety analysis could not be completed. Manual review recommended.",
            "status": "warn",
            "score": 50,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_ai_files(self) -> dict[str, str]:
        """Find source files that contain AI library usage."""
        candidates = self._read_files(
            AI_CODE_PATTERNS,
            max_files=20,
            max_lines=200,
        )
        # Filter to files that actually mention AI libraries or prompt patterns
        relevant = {
            path: content
            for path, content in candidates.items()
            if any(kw.lower() in content.lower() for kw in AI_IMPORT_KEYWORDS)
        }
        return relevant
