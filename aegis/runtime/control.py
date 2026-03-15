from __future__ import annotations

import json
import os
import signal
import socket
import time
from pathlib import Path
from typing import Any

from aegis.constants import INJECT_INTERRUPT_DELAY_SECONDS, STOP_GRACE_SECONDS, STOP_TERM_SECONDS
from aegis.runtime.events import append_event


class SessionController:
    def __init__(self, *, child_pid: int, child_pgid: int, master_fd: int, event_log_path: Path) -> None:
        self.child_pid = child_pid
        self.child_pgid = child_pgid
        self.master_fd = master_fd
        self.event_log_path = event_log_path

    def handle(self, payload: dict[str, Any]) -> dict[str, Any]:
        action = payload.get("action")
        if action == "status":
            return {
                "ok": True,
                "pid": self.child_pid,
                "pgid": self.child_pgid,
            }
        if action == "stop":
            mode = payload.get("mode", "graceful")
            self.stop(mode=mode)
            return {"ok": True, "mode": mode}
        if action == "inject":
            text = payload.get("text", "")
            submit = bool(payload.get("submit", True))
            self.inject(text, submit=submit)
            return {"ok": True, "submit": submit}
        return {"ok": False, "error": f"unsupported action: {action}"}

    def _send_signal(self, sig: signal.Signals) -> None:
        try:
            os.killpg(self.child_pgid, sig)
        except ProcessLookupError:
            pass

    def stop(self, *, mode: str = "graceful") -> None:
        append_event(self.event_log_path, "session.stop_requested", mode=mode)
        if mode == "kill":
            self._send_signal(signal.SIGKILL)
            return

        self._send_signal(signal.SIGINT)
        if self._wait_for_exit(STOP_GRACE_SECONDS):
            return
        self._send_signal(signal.SIGTERM)
        if self._wait_for_exit(STOP_TERM_SECONDS):
            return
        self._send_signal(signal.SIGKILL)

    def inject(self, text: str, *, submit: bool = True) -> None:
        append_event(self.event_log_path, "inject.requested", text=text, submit=submit)
        os.write(self.master_fd, b"\x03")
        time.sleep(INJECT_INTERRUPT_DELAY_SECONDS)
        data = text.encode("utf-8")
        if submit:
            data += b"\r"
        os.write(self.master_fd, data)
        append_event(self.event_log_path, "inject.completed", text=text, submit=submit)

    def _wait_for_exit(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                os.kill(self.child_pid, 0)
            except ProcessLookupError:
                return True
            time.sleep(0.05)
        return False


class ControlServer:
    def __init__(self, socket_path: Path, controller: SessionController) -> None:
        self.socket_path = socket_path
        self.controller = controller
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(socket_path))
        self.server.listen()
        self.server.setblocking(False)

    def fileno(self) -> int:
        return self.server.fileno()

    def close(self) -> None:
        try:
            self.server.close()
        finally:
            self.socket_path.unlink(missing_ok=True)

    def accept_once(self) -> None:
        conn, _ = self.server.accept()
        with conn:
            raw = conn.recv(65536)
            if not raw:
                return
            try:
                payload = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError as exc:
                response = {"ok": False, "error": f"invalid json: {exc}"}
            else:
                response = self.controller.handle(payload)
            conn.sendall(json.dumps(response).encode("utf-8"))
