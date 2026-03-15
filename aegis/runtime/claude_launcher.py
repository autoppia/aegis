"""Launch Claude Code wrapped with Aegis policy proxy.

Same proxy as Codex — intercepts Anthropic API calls to:
1. Inject runtime context (RULES.md, compiled policies) into system prompts
2. Run POLICY_MODEL classifiers on user input (non-deterministic rules)
3. Evaluate tool calls against OPA policies and block denied ones
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from aegis.constants import ANTHROPIC_API_BASE, OPENAI_API_BASE, PROXY_HOST
from aegis.core.context import build_context_providers
from aegis.runtime.events import append_event
from aegis.core.engine import OpaEngine, ensure_opa_binary
from aegis.core.proxy import OpaProxy
from aegis.core.policy_model import load_classifiers
from aegis.runtime.session import ensure_layout, event_log_path


def _find_claude() -> str:
    """Find the real claude binary."""
    binary = shutil.which("claude")
    if binary:
        return binary
    raise RuntimeError(
        "Could not find 'claude' binary in PATH. "
        "Install Claude Code: npm install -g @anthropic-ai/claude-code"
    )


def main(argv: list[str] | None = None) -> int:
    claude_args = list(argv if argv is not None else [])
    real_claude = _find_claude()
    ensure_layout()

    cwd = Path.cwd()
    log = event_log_path("claude")
    proxy: OpaProxy | None = None

    no_policy = "--no-policy" in claude_args
    if no_policy:
        claude_args = [a for a in claude_args if a != "--no-policy"]

    env = os.environ.copy()
    env["AEGIS_ACTIVE"] = "1"

    if not no_policy:
        try:
            ensure_opa_binary()
            engine = OpaEngine(
                project_dir=cwd,
                event_log_path=event_log_path("proxy"),
            )

            context_providers = build_context_providers(cwd)
            compiled_dir = cwd / ".aegis" / "compiled"
            classifiers = load_classifiers(compiled_dir)

            def _get_state() -> dict:
                from aegis.compiler.state_manager import gather_state
                return gather_state(compiled_dir)

            def _terminal_notify(msg: str) -> None:
                try:
                    sys.stderr.write(msg)
                    sys.stderr.flush()
                except OSError:
                    pass

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
            env["ANTHROPIC_BASE_URL"] = proxy_url

            append_event(log, "claude.session_started",
                         proxy_port=port, cwd=str(cwd),
                         classifiers=len(classifiers))
            print(
                f"\033[1;36m[aegis]\033[0m Proxy :{port} — "
                f"{len(context_providers)} context providers, "
                f"{len(classifiers)} classifiers",
                file=sys.stderr,
            )
        except RuntimeError as exc:
            print(f"aegis: OPA setup failed: {exc}", file=sys.stderr)
            return 1

    try:
        result = subprocess.run(
            [real_claude, *claude_args],
            env=env,
            cwd=str(cwd),
        )
        return result.returncode
    except KeyboardInterrupt:
        return 130
    finally:
        if proxy:
            proxy.stop()
        append_event(log, "claude.session_ended")
