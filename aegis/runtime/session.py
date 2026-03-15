from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis.constants import SESSION_FILENAME, wrapper_home


@dataclass
class SessionState:
    session_id: str
    pid: int
    pgid: int
    socket_path: str
    event_log_path: str
    launch_cwd: str
    real_codex_path: str
    argv: list[str]
    started_at: str
    wrapper_pid: int

    @classmethod
    def new(
        cls,
        *,
        pid: int,
        pgid: int,
        socket_path: Path,
        event_log_path: Path,
        launch_cwd: Path,
        real_codex_path: str,
        argv: list[str],
    ) -> "SessionState":
        return cls(
            session_id=uuid.uuid4().hex,
            pid=pid,
            pgid=pgid,
            socket_path=str(socket_path),
            event_log_path=str(event_log_path),
            launch_cwd=str(launch_cwd),
            real_codex_path=real_codex_path,
            argv=argv,
            started_at=datetime.now(timezone.utc).isoformat(),
            wrapper_pid=os.getpid(),
        )


def ensure_layout() -> Path:
    home = wrapper_home()
    for child in ("run", "sessions", "logs", "hooks", "bin", "policies"):
        (home / child).mkdir(parents=True, exist_ok=True)
    return home


def active_session_path() -> Path:
    return ensure_layout() / SESSION_FILENAME


def session_record_path(session_id: str) -> Path:
    return ensure_layout() / "sessions" / f"{session_id}.json"


def event_log_path(session_id: str) -> Path:
    return ensure_layout() / "logs" / f"{session_id}.jsonl"


def write_active_session(session: SessionState) -> None:
    data = asdict(session)
    active_session_path().write_text(json.dumps(data, indent=2), encoding="utf-8")
    session_record_path(session.session_id).write_text(
        json.dumps(data, indent=2), encoding="utf-8"
    )


def read_active_session() -> dict[str, Any] | None:
    path = active_session_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def clear_active_session(session_id: str) -> None:
    path = active_session_path()
    if not path.exists():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        path.unlink(missing_ok=True)
        return
    if data.get("session_id") == session_id:
        path.unlink(missing_ok=True)


def is_executable_file(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return False
    return stat.S_ISREG(mode) and os.access(path, os.X_OK)


def resolve_real_codex(current_executable: str) -> str:
    override = os.environ.get("CODEX_WRAPPER_REAL_CODEX")
    if override:
        return override

    current = Path(current_executable).resolve()
    candidates: list[Path] = []
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        candidate = Path(directory) / "codex"
        if candidate.exists():
            candidates.append(candidate.resolve())

    for candidate in candidates:
        if candidate == current:
            continue
        if candidate.parent == current.parent:
            continue
        if is_executable_file(candidate):
            return str(candidate)

    direct = shutil.which("codex")
    if direct:
        resolved = Path(direct).resolve()
        if resolved != current and is_executable_file(resolved):
            return str(resolved)

    raise RuntimeError(
        "Could not resolve the upstream 'codex' binary. Set CODEX_WRAPPER_REAL_CODEX to the real executable path."
    )


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def python_executable() -> str:
    return sys.executable
