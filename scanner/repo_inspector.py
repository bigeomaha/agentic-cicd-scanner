"""
Repository inspector.

Walks the repo and returns a context dict the orchestrator uses to:
  - Select which agents to run
  - Give agents language/framework context for better LLM prompts
"""
import json
import logging
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)

# ── Language detection ────────────────────────────────────────────────────────

EXTENSION_MAP: dict[str, str] = {
    ".py":   "python",
    ".js":   "javascript",  ".mjs": "javascript", ".cjs": "javascript",
    ".jsx":  "javascript",
    ".ts":   "typescript",  ".tsx": "typescript",
    ".java": "java",
    ".go":   "go",
    ".rb":   "ruby",
    ".php":  "php",
    ".rs":   "rust",
    ".cs":   "csharp",
    ".cpp":  "cpp",         ".cc": "cpp",
    ".c":    "c",
    ".ipynb":"jupyter",
}

# Languages Semgrep covers well (used to flag unsupported languages)
SEMGREP_SUPPORTED = {"python", "javascript", "typescript", "java", "go", "ruby", "php"}

# ── Framework / tool detection ────────────────────────────────────────────────

FRAMEWORK_FILES: dict[str, str] = {
    "requirements.txt": "python",
    "pyproject.toml":   "python",
    "setup.py":         "python",
    "Pipfile":          "python",
    "package.json":     "node",
    "package-lock.json":"node",
    "yarn.lock":        "node",
    "pnpm-lock.yaml":   "node",
    "Dockerfile":       "docker",
    "docker-compose.yml":  "docker",
    "docker-compose.yaml": "docker",
    ".env.example":     "config",
    ".env":             "config",
}

# Keywords that indicate AI/LLM usage (checked in dependency files)
AI_LIBRARY_KEYWORDS = [
    "openai", "anthropic", "langchain", "llama_index", "llamaindex",
    "huggingface", "transformers", "litellm", "groq", "cohere",
    "pinecone", "chromadb", "weaviate", "qdrant", "llm", "gpt",
    "claude", "gemini", "mistral", "ollama", "together",
]

# Test framework indicators
TEST_FRAMEWORK_FILES: dict[str, str] = {
    "pytest.ini":      "pytest",
    "conftest.py":     "pytest",
    "jest.config.js":  "jest",
    "jest.config.ts":  "jest",
    "jest.config.mjs": "jest",
    "vitest.config.ts":"vitest",
    "vitest.config.js":"vitest",
    ".mocharc.yml":    "mocha",
    ".mocharc.js":     "mocha",
}

# Directories to ignore during inspection
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "coverage", ".coverage", ".tox",
}

# File name patterns that indicate test files
TEST_NAME_PATTERNS = ("test_", "_test.", ".test.", "_spec.", ".spec.")


def inspect(repo_path: str) -> dict:
    """
    Walk the repo and return a rich context dictionary.

    Keys:
        languages           dict[str, int]  — language → file count
        primary_language    str | None      — most common language
        frameworks          list[str]       — detected frameworks/runtimes
        is_ai_app           bool            — uses AI/LLM libraries
        has_dockerfile      bool
        has_openapi         bool
        test_framework      str | None
        has_tests           bool
        semgrep_unsupported list[str]       — languages present but not in Semgrep
        file_counts         dict
        notable_files       dict            — notebooks, prompts, docs, test files
    """
    repo = Path(repo_path)

    language_counts: dict[str, int] = defaultdict(int)
    all_files:    list[str] = []
    source_files: list[str] = []
    test_files:   list[str] = []
    doc_files:    list[str] = []
    notebook_files: list[str] = []
    prompt_files: list[str] = []

    for path in repo.rglob("*"):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue

        rel = str(path.relative_to(repo))
        all_files.append(rel)

        ext  = path.suffix.lower()
        lang = EXTENSION_MAP.get(ext)
        name = path.name.lower()

        if lang:
            language_counts[lang] += 1

        # Categorise
        if ext == ".ipynb":
            notebook_files.append(rel)
        elif ext in (".md", ".txt", ".rst"):
            doc_files.append(rel)
            if any(kw in name for kw in ("prompt", "system", "instruction")):
                prompt_files.append(rel)
        elif lang in ("python", "javascript", "typescript", "java", "go", "ruby"):
            if any(pat in name for pat in TEST_NAME_PATTERNS):
                test_files.append(rel)
            else:
                source_files.append(rel)

    # Frameworks present
    frameworks = sorted({
        fw for indicator, fw in FRAMEWORK_FILES.items()
        if (repo / indicator).exists()
    })

    # AI/LLM usage
    is_ai_app = _detect_ai_usage(repo)

    # Test framework
    test_framework = _detect_test_framework(repo)

    # Semgrep unsupported languages
    detected_langs  = set(language_counts.keys()) - {"jupyter"}
    unsupported = sorted(detected_langs - SEMGREP_SUPPORTED)

    # Primary language
    code_langs = {l: c for l, c in language_counts.items() if l != "jupyter"}
    primary = max(code_langs, key=code_langs.get) if code_langs else None

    return {
        "languages":          dict(language_counts),
        "primary_language":   primary,
        "frameworks":         frameworks,
        "is_ai_app":          is_ai_app,
        "has_dockerfile":     (repo / "Dockerfile").exists(),
        "has_openapi":        _has_openapi(repo),
        "test_framework":     test_framework,
        "has_tests":          len(test_files) > 0,
        "semgrep_unsupported": unsupported,
        "file_counts": {
            "total":    len(all_files),
            "source":   len(source_files),
            "test":     len(test_files),
            "docs":     len(doc_files),
            "notebooks":len(notebook_files),
            "prompts":  len(prompt_files),
        },
        "notable_files": {
            "notebooks":  notebook_files[:20],
            "prompts":    prompt_files[:20],
            "docs":       doc_files[:30],
            "test_files": test_files[:30],
            "source_files": source_files[:50],
        },
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _detect_ai_usage(repo: Path) -> bool:
    """Return True if any dependency file references an AI/LLM library."""
    # Python dependency files
    for fname in ("requirements.txt", "Pipfile", "pyproject.toml", "setup.py"):
        p = repo / fname
        if p.exists():
            if any(kw in p.read_text(errors="ignore").lower() for kw in AI_LIBRARY_KEYWORDS):
                return True

    # Node dependency files
    pkg = repo / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text())
            all_deps = {
                **data.get("dependencies", {}),
                **data.get("devDependencies", {}),
            }
            if any(kw in key.lower() for key in all_deps for kw in AI_LIBRARY_KEYWORDS):
                return True
        except (json.JSONDecodeError, KeyError):
            pass

    return False


def _detect_test_framework(repo: Path) -> str | None:
    """Return the name of the first detected test framework, or None."""
    for fname, framework in TEST_FRAMEWORK_FILES.items():
        p = repo / fname
        if not p.exists():
            continue
        # pyproject.toml only counts if it has a pytest section
        if fname == "pyproject.toml":
            if "[tool.pytest" in p.read_text(errors="ignore"):
                return framework
        else:
            return framework

    # Fallback: conftest.py anywhere in the tree
    if any(True for _ in repo.rglob("conftest.py")):
        return "pytest"

    return None


def _has_openapi(repo: Path) -> bool:
    """Return True if an OpenAPI/Swagger spec file is present."""
    spec_names = (
        "openapi.yml", "openapi.yaml", "openapi.json",
        "swagger.yml", "swagger.yaml", "swagger.json",
    )
    return any((repo / name).exists() for name in spec_names)
