#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from aegis.constants import wrapper_home
from aegis.runtime.events import append_event
from aegis.runtime.session import read_active_session


def main() -> int:
    if len(sys.argv) < 2:
        return 0

    raw = sys.argv[-1]
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = {"raw": raw}

    active = read_active_session()
    log_path = None
    session_id = None
    if active:
        session_id = active.get("session_id")
        log_path = active.get("event_log_path")

    fallback = wrapper_home() / "logs" / "notify-fallback.jsonl"
    target = Path(log_path) if log_path else fallback
    append_event(
        target,
        "turn.completed",
        session_id=session_id,
        payload=payload,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
