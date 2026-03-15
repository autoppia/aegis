from __future__ import annotations

import json
from pathlib import Path

from aegis.constants import BEGIN_MARKER, END_MARKER, codex_home
from aegis.runtime.session import ensure_layout, python_executable


def notify_hook_path() -> Path:
    return Path(__file__).resolve().parent / "notify_hook.py"


def managed_block() -> str:
    command = [
        python_executable(),
        str(notify_hook_path()),
    ]
    command_toml = ", ".join(json.dumps(part) for part in command)
    return "\n".join(
        [
            BEGIN_MARKER,
            "# Managed by aegis. Safe to remove if you uninstall the wrapper.",
            f"notify = [{command_toml}]",
            END_MARKER,
            "",
        ]
    )


def ensure_codex_notify_hook() -> Path:
    ensure_layout()
    home = codex_home()
    home.mkdir(parents=True, exist_ok=True)
    config_path = home / "config.toml"
    existing = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    block = managed_block()

    if BEGIN_MARKER in existing and END_MARKER in existing:
        start = existing.index(BEGIN_MARKER)
        end = existing.index(END_MARKER) + len(END_MARKER)
        updated = existing[:start] + block + existing[end:]
    else:
        if existing and not existing.endswith("\n"):
            existing += "\n"
        updated = existing + ("\n" if existing else "") + block

    if updated != existing:
        config_path.write_text(updated, encoding="utf-8")
    return config_path
