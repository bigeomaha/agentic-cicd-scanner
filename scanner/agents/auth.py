"""
Authentication & Authorisation agent — LLM-only.

Reviews auth implementation for architectural issues beyond what static tools catch:
  - Rolling custom auth vs using an established library
  - JWT configuration and validation
  - Session management
  - Password handling
  - OAuth/OIDC implementation
  - Missing authorisation checks (authn ≠ authz)
"""
import logging
from typing import Any

from scanner.base_agent import BaseAgent
from scanner import llm

logger = logging.getLogger(__name__)

# File patterns likely to contain auth logic
AUTH_PATTERNS = [
    "*auth*.py",  "*login*.py",  "*token*.py",  "*session*.py",
    "*password*.py", "*user*.py", "*account*.py", "*middleware*.py",
    "*auth*.ts",  "*auth*.js",   "*login*.ts",   "*login*.js",
    "*token*.ts", "*token*.js",  "*session*.ts", "*session*.js",
    "*middleware*.ts", "*middleware*.js",
]

# Keywords that indicate auth-related code
AUTH_KEYWORDS = [
    "password", "token", "jwt", "oauth", "session", "login", "logout",
    "authenticate", "authorise", "authorize", "credential", "bcrypt",
    "hashlib", "hmac", "bearer", "api_key", "api key", "secret_key",
]


class AuthAgent(BaseAgent):
    agent_id = "auth"
    category = "security"

    def _collect(self) -> tuple[Any, dict]:
        languages = self.context.get("languages", {})
        has_code = any(l in languages for l in ("python", "javascript", "typescript", "java", "go"))

        if not has_code:
            return self._skipped_envelope("No supported source languages detected.")

        auth_files = self._find_auth_files()

        if not auth_files:
            return {"_note": "No auth files found"}, {
                "tool":                  "llm-agent",
                "files_scanned":         0,
                "languages_scanned":     list(languages.keys()),
                "languages_unsupported": [],
                "no_auth_found":         True,
            }

        return auth_files, {
            "tool":                  "llm-agent",
            "files_scanned":         len(auth_files),
            "languages_scanned":     list(languages.keys()),
            "languages_unsupported": [],
        }

    def _interpret(self, raw_data: Any, metadata: dict) -> dict:
        if metadata.get("skipped"):
            return self._skipped_result(metadata.get("skip_reason", ""))

        # No auth code found — that itself might be noteworthy
        if metadata.get("no_auth_found"):
            return {
                "findings": [
                    {
                        "severity":   "info",
                        "rule":       "no-auth-detected",
                        "file":       "N/A",
                        "line":       None,
                        "message":    "No authentication code was detected in this project.",
                        "suggestion": (
                            "If this application handles user data or sensitive information, "
                            "authentication should be implemented. Consider using an established "
                            "library like Auth.js, Clerk, Supabase Auth, or Django's built-in auth."
                        ),
                    }
                ],
                "summary": "No authentication code was detected. If this is intentional (e.g., internal tool), this is fine. If users log in, authentication needs to be implemented.",
                "status": "warn",
                "score": 70,
            }

        files_str = "\n\n".join(
            f"=== {path} ===\n{content}"
            for path, content in raw_data.items()
        )
        if len(files_str) > 12_000:
            files_str = files_str[:12_000] + "\n\n... [truncated]"

        prompt = f"""You are reviewing authentication and authorisation code for security issues.
The developers may not be experienced with security best practices.

Auth-related files:
{files_str}

Evaluate these areas:

1. CUSTOM AUTH VS ESTABLISHED LIBRARY — Is the developer rolling their own authentication
   from scratch? This is almost always a mistake. Flag it clearly.

2. PASSWORD HANDLING — Passwords should be hashed with bcrypt, argon2, or scrypt.
   Using MD5, SHA1, or SHA256 without salt for passwords is a critical vulnerability.
   Storing plain-text passwords is catastrophic.

3. JWT USAGE — Are JWTs being validated properly (signature, expiry, issuer)?
   Using `decode` without signature verification is a critical flaw.
   Are JWTs stored in localStorage (XSS risk) vs httpOnly cookies (safer)?

4. SESSION MANAGEMENT — Are sessions properly invalidated on logout?
   Session tokens should be random and unpredictable.

5. AUTHORISATION vs AUTHENTICATION — The code may check if a user is logged in (authn)
   but not whether they have permission to access a specific resource (authz).
   Flag missing ownership/role checks.

6. TOKEN EXPIRY — Do JWTs or API tokens have expiry times?
   Tokens that never expire are a long-term risk.

7. OAUTH/OIDC — If OAuth is used, is the state parameter validated (CSRF protection)?

Return JSON with this exact schema:
{{
  "findings": [
    {{
      "severity": "critical|high|medium|low|info",
      "rule": "custom-auth|weak-password-hash|invalid-jwt|session-management|missing-authz|no-token-expiry|oauth-csrf",
      "file": "path/to/file",
      "line": null_or_integer,
      "message": "Plain language description of the auth issue",
      "suggestion": "Specific fix, including recommended library if relevant"
    }}
  ],
  "summary": "2-3 sentence auth security summary for a non-developer",
  "status": "pass|warn|fail",
  "score": 0-100,
  "false_positive_notes": ""
}}"""

        result = llm.interpret_as_json(prompt, max_tokens=2500)
        return result if result else {
            "findings": [],
            "summary": "Auth review could not be completed. Manual review recommended.",
            "status": "warn",
            "score": 50,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_auth_files(self) -> dict[str, str]:
        """Find files that contain authentication/authorisation logic."""
        candidates = self._read_files(
            AUTH_PATTERNS,
            max_files=12,
            max_lines=250,
        )
        return {
            path: content
            for path, content in candidates.items()
            if any(kw in content.lower() for kw in AUTH_KEYWORDS)
        }
