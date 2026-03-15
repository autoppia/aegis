from __future__ import annotations

import errno
import fcntl
import os
import selectors
import signal
import subprocess
import sys
import termios
import time
import tty
from pathlib import Path

from aegis.runtime.config import ensure_codex_notify_hook
from aegis.constants import (
    ANTHROPIC_API_BASE,
    INPUT_COUNT_WARMUP_SECONDS,
    OPENAI_API_BASE,
    PROXY_HOST,
)
# unused PROFANITY_MODEL_OPENAI removed — policy model handles this now
from aegis.core.context import build_context_providers
from aegis.runtime.control import ControlServer, SessionController
from aegis.runtime.events import append_event
from aegis.core.engine import OpaEngine, ensure_opa_binary
from aegis.core.proxy import OpaProxy
from aegis.core.policy_model import load_classifiers
from aegis.runtime.session import (
    SessionState,
    clear_active_session,
    ensure_layout,
    event_log_path,
    read_active_session,
    resolve_real_codex,
    write_active_session,
)


def get_winsize(fd: int) -> bytes:
    return fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 8)


def set_winsize(fd: int, winsize: bytes) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def send_to_socket(socket_path: str, payload: dict[str, object]) -> dict[str, object] | None:
    import json
    import socket

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(socket_path)
        client.sendall(json.dumps(payload).encode("utf-8"))
        raw = client.recv(65536)
    except OSError:
        return None
    finally:
        client.close()
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"))


class InputMediator:
    def __init__(self, event_log_path: Path) -> None:
        self.event_log_path = event_log_path
        self.draft = bytearray()
        self.submit_count = 0
        self.escape_sequence = bytearray()
        self.started_at = time.monotonic()

    def process(self, data: bytes) -> tuple[bytes, str | None]:
        forwarded = bytearray()
        notice = None

        for byte in data:
            if self.escape_sequence:
                self.escape_sequence.append(byte)
                if self._escape_sequence_complete(byte):
                    sequence = bytes(self.escape_sequence)
                    forwarded.extend(sequence)
                    if self._is_enter_sequence(sequence):
                        notice = self._handle_submit_attempt() or notice
                    self.escape_sequence.clear()
                continue

            if byte in (0x03, 0x04):
                self.draft.clear()
                forwarded.append(byte)
                continue

            if byte in (0x7F, 0x08):
                if self.draft:
                    self.draft = self.draft[:-1]
                forwarded.append(byte)
                continue

            if byte == 0x1B:
                self.escape_sequence.append(byte)
                continue

            if byte in (0x0D, 0x0A):
                blocked_notice = self._handle_submit_attempt()
                if blocked_notice:
                    notice = blocked_notice
                    continue
                self.draft.clear()
                forwarded.append(byte)
                continue

            forwarded.append(byte)
            if byte >= 0x20:
                self.draft.append(byte)

        return bytes(forwarded), notice

    def _decoded_draft(self) -> str:
        return self.draft.decode("utf-8", errors="ignore")

    def _handle_submit_attempt(self) -> str | None:
        """Track submit events. Content policy is enforced at the proxy level."""
        draft_text = self._decoded_draft()
        if not draft_text.strip():
            return None
        if time.monotonic() - self.started_at < INPUT_COUNT_WARMUP_SECONDS:
            append_event(
                self.event_log_path,
                "input.submit_ignored_warmup",
                draft=draft_text,
            )
            self.draft.clear()
            return None
        self.submit_count += 1
        append_event(
            self.event_log_path,
            "input.submit_seen",
            submit_count=self.submit_count,
            draft=draft_text,
        )
        return None

    @staticmethod
    def _escape_sequence_complete(byte: int) -> bool:
        return 0x40 <= byte <= 0x7E

    @staticmethod
    def _is_enter_sequence(sequence: bytes) -> bool:
        if not sequence.startswith(b"\x1b["):
            return False
        body = sequence[2:]
        if not body:
            return False
        if body.endswith(b"u"):
            first = body[:-1].split(b";", 1)[0]
            return first == b"13"
        if body.endswith(b"~"):
            first = body[:-1].split(b";", 1)[0]
            return first == b"13"
        return False


def main(argv: list[str] | None = None, *, no_policy: bool = False) -> int:
    codex_args = list(sys.argv[1:] if argv is None else argv)
    real_codex = resolve_real_codex(sys.argv[0])
    ensure_layout()
    ensure_codex_notify_hook()

    active = read_active_session()
    if active:
        response = send_to_socket(active.get("socket_path", ""), {"action": "status"})
        if response and response.get("ok"):
            print(
                f"aegis: another wrapped Codex session is active ({active.get('session_id')}).",
                file=sys.stderr,
            )
            return 1
        clear_active_session(active.get("session_id", ""))

    master_fd, slave_fd = os.openpty()
    set_winsize(slave_fd, get_winsize(sys.stdin.fileno()))

    env = os.environ.copy()
    env["CODEX_WRAPPER_ACTIVE"] = "1"
    env["CODEX_WRAPPER_REAL_CODEX"] = real_codex
    env.setdefault("TERM", os.environ.get("TERM", "xterm-256color"))

    # OPA policy proxy + runtime context injection
    proxy: OpaProxy | None = None
    cwd = Path.cwd()
    if not no_policy:
        try:
            ensure_opa_binary()
            engine = OpaEngine(
                project_dir=cwd,
                event_log_path=event_log_path("proxy"),
            )

            def _terminal_notify(msg: str) -> None:
                try:
                    os.write(sys.stdout.fileno(), msg.encode("utf-8"))
                except OSError:
                    pass

            context_providers = build_context_providers(cwd)
            compiled_dir = cwd / ".aegis" / "compiled"
            classifiers = load_classifiers(compiled_dir)

            # State getter for classifiers (reuse OPA state system)
            def _get_state() -> dict:
                from aegis.compiler.state_manager import gather_state
                return gather_state(compiled_dir)

            real_openai_base = env.get("OPENAI_BASE_URL", OPENAI_API_BASE)
            real_anthropic_base = env.get("ANTHROPIC_BASE_URL", ANTHROPIC_API_BASE)
            proxy = OpaProxy(
                engine=engine,
                real_base_url=real_openai_base,
                anthropic_base_url=real_anthropic_base,
                notify_callback=_terminal_notify,
                context_providers=context_providers,
                classifiers=classifiers,
                state_getter=_get_state,
            )
            port = proxy.start()
            proxy_url = f"http://{PROXY_HOST}:{port}"
            env["OPENAI_BASE_URL"] = f"{proxy_url}/v1"
            env["ANTHROPIC_BASE_URL"] = proxy_url
        except RuntimeError as exc:
            print(f"aegis: OPA setup failed: {exc}", file=sys.stderr)
            return 1

    child = subprocess.Popen(
        [real_codex, *codex_args],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        start_new_session=True,
        env=env,
        cwd=os.getcwd(),
        close_fds=True,
    )
    os.close(slave_fd)

    session_id = SessionState.new(
        pid=child.pid,
        pgid=os.getpgid(child.pid),
        socket_path=ensure_layout() / "run" / f"{child.pid}.sock",
        event_log_path=event_log_path(f"{child.pid}"),
        launch_cwd=Path.cwd(),
        real_codex_path=real_codex,
        argv=codex_args,
    )
    session = SessionState(
        session_id=session_id.session_id,
        pid=session_id.pid,
        pgid=session_id.pgid,
        socket_path=session_id.socket_path,
        event_log_path=session_id.event_log_path,
        launch_cwd=session_id.launch_cwd,
        real_codex_path=session_id.real_codex_path,
        argv=session_id.argv,
        started_at=session_id.started_at,
        wrapper_pid=session_id.wrapper_pid,
    )
    write_active_session(session)
    log_path = Path(session.event_log_path)
    append_event(
        log_path,
        "session.started",
        session_id=session.session_id,
        pid=child.pid,
        pgid=session.pgid,
        argv=session.argv,
        cwd=session.launch_cwd,
        real_codex=session.real_codex_path,
    )
    append_event(
        log_path,
        "session.config",
        context_injection="proxy",
        classifiers_loaded=len(proxy.classifiers) if proxy else 0,
    )

    controller = SessionController(
        child_pid=child.pid,
        child_pgid=session.pgid,
        master_fd=master_fd,
        event_log_path=log_path,
    )
    server = ControlServer(Path(session.socket_path), controller)

    def forward_signal(sig: int, _frame: object) -> None:
        try:
            os.killpg(session.pgid, sig)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGINT, forward_signal)
    signal.signal(signal.SIGTERM, forward_signal)

    def on_winch(_sig: int, _frame: object) -> None:
        try:
            winsize = get_winsize(sys.stdin.fileno())
            set_winsize(master_fd, winsize)
        except OSError:
            pass

    signal.signal(signal.SIGWINCH, on_winch)

    selector = selectors.DefaultSelector()
    selector.register(master_fd, selectors.EVENT_READ, "pty")
    selector.register(sys.stdin.fileno(), selectors.EVENT_READ, "stdin")
    selector.register(server.fileno(), selectors.EVENT_READ, "sock")

    old_tty = termios.tcgetattr(sys.stdin.fileno())
    tty.setraw(sys.stdin.fileno())
    mediator = InputMediator(log_path)

    try:
        while True:
            if child.poll() is not None:
                break
            for key, _mask in selector.select(timeout=0.1):
                if key.data == "pty":
                    try:
                        data = os.read(master_fd, 65536)
                    except OSError as exc:
                        if exc.errno != errno.EIO:
                            raise
                        data = b""
                    if not data:
                        break
                    os.write(sys.stdout.fileno(), data)
                elif key.data == "stdin":
                    data = os.read(sys.stdin.fileno(), 65536)
                    if data:
                        forwarded, notice = mediator.process(data)
                        if forwarded:
                            os.write(master_fd, forwarded)
                        if notice:
                            os.write(sys.stdout.fileno(), notice.encode("utf-8"))
                elif key.data == "sock":
                    server.accept_once()
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_tty)
        selector.close()
        server.close()
        if proxy:
            proxy.stop()

    returncode = child.wait()
    append_event(
        log_path,
        "session.exited",
        session_id=session.session_id,
        returncode=returncode,
    )
    clear_active_session(session.session_id)
    try:
        os.close(master_fd)
    except OSError:
        pass
    return returncode
