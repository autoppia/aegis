from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sys
from pathlib import Path

from aegis.runtime.config import ensure_codex_notify_hook
from aegis.constants import APP_NAME, codex_home, wrapper_home
from aegis.runtime.session import active_session_path, read_active_session, resolve_real_codex


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="aegis")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status")

    stop = sub.add_parser("stop")
    stop.add_argument("--kill", action="store_true")

    inject = sub.add_parser("inject")
    inject.add_argument("text")
    inject.add_argument("--no-submit", action="store_true")

    sub.add_parser("doctor")
    return parser.parse_args(argv)


def send(socket_path: str, payload: dict[str, object]) -> dict[str, object]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(socket_path)
    with client:
        client.sendall(json.dumps(payload).encode("utf-8"))
        raw = client.recv(65536)
    return json.loads(raw.decode("utf-8"))


def require_active_session() -> dict[str, object]:
    active = read_active_session()
    if not active:
        raise SystemExit("No active wrapped Codex session.")
    return active


def command_status() -> int:
    active = read_active_session()
    if not active:
        print("No active wrapped Codex session.")
        return 0
    print(json.dumps(active, indent=2))
    return 0


def command_stop(kill: bool) -> int:
    active = require_active_session()
    payload = {"action": "stop", "mode": "kill" if kill else "graceful"}
    print(json.dumps(send(str(active["socket_path"]), payload), indent=2))
    return 0


def command_inject(text: str, no_submit: bool) -> int:
    active = require_active_session()
    payload = {"action": "inject", "text": text, "submit": not no_submit}
    print(json.dumps(send(str(active["socket_path"]), payload), indent=2))
    return 0


def command_doctor() -> int:
    problems: list[str] = []
    details: dict[str, object] = {}

    details["wrapper_home"] = str(wrapper_home())
    details["codex_home"] = str(codex_home())
    details["active_session_file"] = str(active_session_path())

    try:
        details["real_codex"] = resolve_real_codex(str(Path(sys.argv[0]).resolve()))
    except RuntimeError as exc:
        problems.append(str(exc))

    try:
        config_path = ensure_codex_notify_hook()
        details["codex_config"] = str(config_path)
        details["notify_hook_installed"] = True
    except OSError as exc:
        problems.append(f"Failed to provision Codex notify hook: {exc}")

    details["active_session"] = read_active_session()
    print(json.dumps({"ok": not problems, "details": details, "problems": problems}, indent=2))
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    ns = parse_args(sys.argv[1:] if argv is None else argv)
    if ns.command == "status":
        return command_status()
    if ns.command == "stop":
        return command_stop(ns.kill)
    if ns.command == "inject":
        return command_inject(ns.text, ns.no_submit)
    if ns.command == "doctor":
        return command_doctor()
    return 1
