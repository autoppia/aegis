"""Runtime context providers for proxy-level prompt injection.

Each provider is a callable that returns a string (or None to skip).
The proxy combines all non-None results into a single system message
injected into every chat/completions request before it hits upstream.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from aegis.constants import RULES_FILENAME

ContextProvider = Callable[[], str | None]


def rules_provider(cwd: Path) -> ContextProvider:
    """Provider that reads RULES.md and returns its content as context."""
    def _provide() -> str | None:
        search = cwd
        while True:
            candidate = search / RULES_FILENAME
            if candidate.is_file():
                content = candidate.read_text(encoding="utf-8").strip()
                if content:
                    return (
                        "[AEGIS POLICY RULES]\n"
                        "The following rules MUST be enforced for all operations "
                        "in this workspace. Violating these rules will cause your "
                        "tool calls to be blocked by the policy engine.\n\n"
                        + content
                    )
                return None
            parent = search.parent
            if parent == search:
                return None
            search = parent
    return _provide


def compiled_policies_provider(cwd: Path) -> ContextProvider:
    """Provider that summarizes compiled OPA policies so the LLM is aware of them."""
    compiled_dir = cwd / ".aegis" / "compiled"

    def _provide() -> str | None:
        manifest = compiled_dir / "manifest.json"
        if not manifest.exists():
            return None
        try:
            rules = json.loads(manifest.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

        if not rules:
            return None

        lines = [
            "[AEGIS COMPILED POLICIES]",
            "The following policies are actively enforced. Tool calls that "
            "violate them will be automatically blocked:\n",
        ]
        for rule in rules:
            title = rule.get("title", "Unknown")
            body = rule.get("body", "")
            has_errors = bool(rule.get("errors"))
            status = " (compilation warnings)" if has_errors else ""
            lines.append(f"- {title}{status}: {body}")

        return "\n".join(lines)

    return _provide


def build_context_providers(cwd: Path) -> list[ContextProvider]:
    """Build the default set of context providers for a project directory."""
    return [
        rules_provider(cwd),
        compiled_policies_provider(cwd),
    ]
