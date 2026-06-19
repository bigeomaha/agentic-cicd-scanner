"""
Test coverage agent — static phase only.

Does NOT run tests. Analyses the repo structure statically to assess
the testing posture: framework detection, file ratios, coverage config.

Phase 2 (running tests) is intentionally excluded — the CI/CD pipeline's
own test job handles that. This agent answers "do tests exist and are they
set up correctly?" not "do they pass?".
"""
import logging
from pathlib import Path
from typing import Any

from scanner.base_agent import BaseAgent
from scanner import llm

logger = logging.getLogger(__name__)


class TestCoverageAgent(BaseAgent):
    agent_id = "test_coverage"
    category = "quality"

    # Coverage configuration files — presence indicates tests are wired up properly
    COVERAGE_CONFIG_FILES = (
        ".coveragerc", "pytest.ini", "pyproject.toml", "setup.cfg",
        "jest.config.js", "jest.config.ts", "vitest.config.ts", "vitest.config.js",
        ".nycrc", ".nycrc.json", "nyc.config.js",
    )

    def _collect(self) -> tuple[Any, dict]:
        context       = self.context
        file_counts   = context.get("file_counts", {})
        notable       = context.get("notable_files", {})
        test_framework = context.get("test_framework")
        has_tests     = context.get("has_tests", False)

        source_files = notable.get("source_files", [])
        test_files   = notable.get("test_files", [])

        # Check for coverage config
        repo = Path(self.repo_path)
        coverage_configs = [f for f in self.COVERAGE_CONFIG_FILES if (repo / f).exists()]

        # Sample a few test files to inspect quality
        sample_tests: dict[str, str] = {}
        if test_files:
            sample_paths = test_files[:5]
            sample_tests = self._read_files(
                [Path(p).name for p in sample_paths],
                max_files=5,
                max_lines=80,
            )

        data = {
            "framework":          test_framework,
            "has_tests":          has_tests,
            "source_file_count":  file_counts.get("source", 0),
            "test_file_count":    file_counts.get("test", 0),
            "coverage_configs":   coverage_configs,
            "source_files_sample": source_files[:20],
            "test_files_sample":   test_files[:20],
            "test_file_content_sample": sample_tests,
            "languages":           context.get("languages", {}),
        }

        return data, {
            "tool":                  "static-analysis",
            "files_scanned":         file_counts.get("total", 0),
            "languages_scanned":     list(context.get("languages", {}).keys()),
            "languages_unsupported": [],
        }

    def _interpret(self, raw_data: Any, metadata: dict) -> dict:
        # Calculate ratio locally before LLM call
        source = raw_data.get("source_file_count", 0)
        tests  = raw_data.get("test_file_count", 0)
        ratio  = round(tests / source, 2) if source > 0 else 0

        prompt = f"""You are assessing the testing posture of a codebase. You are NOT running tests — you are doing a static analysis of whether tests exist and appear meaningful.

Repository test data:
- Test framework detected: {raw_data.get("framework") or "None detected"}
- Total source files: {source}
- Total test files: {tests}
- Test-to-source ratio: {ratio} (ideally > 0.5 for well-tested code)
- Coverage configuration files: {raw_data.get("coverage_configs") or "None found"}
- Languages: {list(raw_data.get("languages", {}).keys())}

Source files (sample): {raw_data.get("source_files_sample", [])[:15]}
Test files (sample):   {raw_data.get("test_files_sample", [])[:15]}

Sample test file contents:
{self._format_test_samples(raw_data.get("test_file_content_sample", {}))}

Assess:

1. TEST FRAMEWORK — Is one configured? Which one? Is it appropriate for the language?

2. TEST EXISTENCE — Do test files exist? What is the ratio of test to source files?
   A ratio below 0.3 suggests significant gaps. A ratio of 0 means no tests at all.

3. TEST QUALITY SIGNALS — From the sample content, do the tests look meaningful?
   Warning signs: tests that only assert True, empty test functions, tests with no assertions,
   tests that just print output.

4. CRITICAL UNTESTED AREAS — Based on the source file names, which important parts of
   the codebase appear to have no corresponding test file?
   (e.g., auth logic, payment processing, AI prompt handling with no tests)

5. COVERAGE CONFIGURATION — Is coverage measurement set up? Without it, the team
   has no visibility into what percentage of code is tested.

6. AI-SPECIFIC TESTING — For AI applications, note if there appear to be tests for:
   prompt template rendering, LLM response handling, or integration with external AI APIs.

Return JSON with this exact schema:
{{
  "findings": [
    {{
      "severity": "critical|high|medium|low|info",
      "rule": "no-tests|no-test-framework|low-test-ratio|poor-test-quality|no-coverage-config|untested-critical-area",
      "file": "path/to/file or 'N/A'",
      "line": null,
      "message": "Plain language description of the testing gap",
      "suggestion": "Specific actionable recommendation"
    }}
  ],
  "summary": "2-3 sentence testing posture summary for a non-developer. Be direct: if there are no tests, say so clearly.",
  "status": "pass|warn|fail",
  "score": 0-100,
  "false_positive_notes": ""
}}

Score guidance:
- 90-100: good framework, ratio > 0.5, coverage configured, quality tests
- 70-89:  framework exists, some tests, minor gaps
- 50-69:  tests exist but sparse or framework missing
- 20-49:  very few tests or test framework not configured
- 0-19:   no tests at all"""

        result = llm.interpret_as_json(prompt, max_tokens=2000)
        if result:
            return result

        # Fallback: basic assessment without LLM
        return self._fallback_assessment(source, tests, raw_data.get("framework"))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _format_test_samples(self, samples: dict[str, str]) -> str:
        if not samples:
            return "No test file content available."
        return "\n\n".join(f"--- {path} ---\n{content}" for path, content in samples.items())

    def _fallback_assessment(self, source: int, tests: int, framework: str | None) -> dict:
        ratio = tests / source if source > 0 else 0

        if tests == 0:
            return {
                "findings": [{
                    "severity": "high", "rule": "no-tests",
                    "file": "N/A", "line": None,
                    "message": "No test files found in this project.",
                    "suggestion": "Start by adding a test framework (pytest for Python, Jest for JavaScript) and write tests for your most important functionality first.",
                }],
                "summary": "No tests found. This project has no automated test coverage. This is a significant risk — bugs may go undetected.",
                "status": "fail",
                "score": 10,
            }
        elif not framework:
            return {
                "findings": [{
                    "severity": "medium", "rule": "no-test-framework",
                    "file": "N/A", "line": None,
                    "message": "Test files exist but no test framework configuration was detected.",
                    "suggestion": "Add a pytest.ini or jest.config.js so tests can be run consistently.",
                }],
                "summary": f"{tests} test files found but no framework configured. Tests may not be runnable.",
                "status": "warn",
                "score": 50,
            }
        else:
            score = min(90, int(ratio * 100) + 30)
            return {
                "findings": [],
                "summary": f"{tests} test files for {source} source files (ratio: {ratio:.1f}). Framework: {framework}.",
                "status": "pass" if ratio >= 0.3 else "warn",
                "score": score,
            }
