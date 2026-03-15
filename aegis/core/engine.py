"""OPA binary management and policy evaluation."""

from __future__ import annotations

import json
import os
import platform
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from aegis.constants import OPA_VERSION, OPA_DOWNLOAD_BASE, wrapper_home
from aegis.runtime.events import append_event


@dataclass
class ToolCall:
    name: str
    arguments: dict


@dataclass
class PolicyDecision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)


def _opa_binary_path() -> Path:
    return wrapper_home() / "bin" / "opa"


def _detect_platform() -> tuple[str, str]:
    """Return (os, arch) for OPA download URL."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin":
        opa_os = "darwin"
    elif system == "linux":
        opa_os = "linux"
    else:
        raise RuntimeError(f"Unsupported OS for OPA: {system}")

    if machine in ("x86_64", "amd64"):
        opa_arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        opa_arch = "arm64"
    else:
        raise RuntimeError(f"Unsupported architecture for OPA: {machine}")

    return opa_os, opa_arch


def ensure_opa_binary() -> Path:
    """Download OPA binary if not present. Returns path to binary."""
    binary = _opa_binary_path()
    if binary.exists() and os.access(binary, os.X_OK):
        return binary

    opa_os, opa_arch = _detect_platform()

    if opa_os == "darwin":
        suffix = f"opa_{opa_os}_{opa_arch}"
    else:
        suffix = f"opa_{opa_os}_{opa_arch}_static"

    url = f"{OPA_DOWNLOAD_BASE}/v{OPA_VERSION}/{suffix}"

    import urllib.request

    binary.parent.mkdir(parents=True, exist_ok=True)
    print(f"[aegis] Downloading OPA v{OPA_VERSION}...")
    try:
        urllib.request.urlretrieve(url, str(binary))
    except Exception as exc:
        binary.unlink(missing_ok=True)
        raise RuntimeError(
            f"Failed to download OPA binary from {url}: {exc}\n"
            "Use --no-policy to bypass OPA policy enforcement."
        ) from exc

    binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"[aegis] OPA v{OPA_VERSION} installed to {binary}")
    return binary


class OpaEngine:
    """Evaluates tool calls against OPA policies."""

    def __init__(
        self,
        project_dir: Path,
        event_log_path: Path | None = None,
    ) -> None:
        self.project_dir = project_dir
        self.event_log_path = event_log_path
        self.opa_binary = _opa_binary_path()
        self._policy_dirs = self._discover_policy_dirs()
        self._compiled_dir = project_dir / ".aegis" / "compiled"

    def _discover_policy_dirs(self) -> list[Path]:
        """Find policy directories: shipped defaults, global, project-local."""
        dirs: list[Path] = []

        # Shipped default policies
        shipped = Path(__file__).resolve().parent.parent / "policies"
        if shipped.is_dir():
            dirs.append(shipped)

        # Global user policies
        global_policies = wrapper_home() / "policies"
        if global_policies.is_dir():
            dirs.append(global_policies)

        # Project-local policies
        local_policies = self.project_dir / ".aegis" / "policies"
        if local_policies.is_dir():
            dirs.append(local_policies)

        return dirs

    def _collect_policy_files(self) -> list[Path]:
        """Collect all .rego files from policy directories and compiled rules."""
        files: list[Path] = []
        for d in self._policy_dirs:
            files.extend(sorted(d.glob("*.rego")))
        # Include compiled rule policies
        if self._compiled_dir.exists():
            files.extend(sorted(self._compiled_dir.glob("*/policy.rego")))
        return files

    def evaluate(self, tool_call: ToolCall) -> PolicyDecision:
        """Evaluate a tool call against OPA policies.

        Returns PolicyDecision. On OPA failure, denies (fail-closed).
        """
        policy_files = self._collect_policy_files()
        if not policy_files:
            return PolicyDecision(allowed=True)

        # Gather runtime state from compiled state gatherers
        state: dict = {}
        if self._compiled_dir.exists():
            from aegis.compiler.state_manager import gather_state
            state = gather_state(self._compiled_dir)

        input_doc = {
            "tool": {
                "name": tool_call.name,
                "arguments": tool_call.arguments,
            },
            "project_dir": str(self.project_dir),
            "state": state,
        }

        try:
            decision = self._run_opa_eval(input_doc, policy_files)
        except Exception as exc:
            # Fail-closed: deny on OPA errors
            decision = PolicyDecision(
                allowed=False,
                reasons=[f"OPA evaluation error: {exc}"],
            )

        if self.event_log_path:
            append_event(
                self.event_log_path,
                "policy.evaluated",
                tool_name=tool_call.name,
                tool_arguments=tool_call.arguments,
                allowed=decision.allowed,
                reasons=decision.reasons,
            )

        return decision

    def _run_opa_eval(
        self, input_doc: dict, policy_files: list[Path]
    ) -> PolicyDecision:
        """Run opa eval subprocess and parse result."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(input_doc, f)
            input_path = f.name

        try:
            cmd = [str(self.opa_binary), "eval"]
            for pf in policy_files:
                cmd.extend(["-d", str(pf)])
            cmd.extend(["-i", input_path, "-f", "json", "data.aegis.deny"])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                raise RuntimeError(
                    f"OPA eval failed (rc={result.returncode}): {result.stderr.strip()}"
                )

            output = json.loads(result.stdout)
            deny_set = self._extract_deny_set(output)

            if deny_set:
                return PolicyDecision(allowed=False, reasons=list(deny_set))
            return PolicyDecision(allowed=True)

        finally:
            os.unlink(input_path)

    @staticmethod
    def _extract_deny_set(opa_output: dict) -> set[str]:
        """Extract deny reasons from OPA eval JSON output."""
        reasons: set[str] = set()
        try:
            result = opa_output.get("result", [])
            if not result:
                return reasons
            expressions = result[0].get("expressions", [])
            for expr in expressions:
                value = expr.get("value", [])
                if isinstance(value, list):
                    reasons.update(str(v) for v in value)
                elif isinstance(value, set):
                    reasons.update(str(v) for v in value)
        except (IndexError, KeyError, TypeError):
            pass
        return reasons
