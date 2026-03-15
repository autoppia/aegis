from pathlib import Path


APP_NAME = "aegis"
BEGIN_MARKER = "# BEGIN AEGIS MANAGED BLOCK"
END_MARKER = "# END AEGIS MANAGED BLOCK"
PROJECT_DOC_FILENAME = "AGENTS.override.md"
RULES_FILENAME = "RULES.md"
INJECT_INTERRUPT_DELAY_SECONDS = 1.2
INPUT_COUNT_WARMUP_SECONDS = 3.0
STOP_GRACE_SECONDS = 2.0
STOP_TERM_SECONDS = 2.0
SESSION_FILENAME = "active-session.json"
PROFANITY_MODEL_OPENAI = "gpt-4o-mini"
PROFANITY_MODEL_ANTHROPIC = "claude-haiku-4-5-20251001"
OPENAI_API_BASE = "https://api.openai.com/v1"
ANTHROPIC_API_BASE = "https://api.anthropic.com"
OPA_VERSION = "0.68.0"
OPA_DOWNLOAD_BASE = "https://openpolicyagent.org/downloads"
PROXY_HOST = "127.0.0.1"


def wrapper_home() -> Path:
    return Path.home() / ".aegis"


def codex_home() -> Path:
    return Path.home() / ".codex"
