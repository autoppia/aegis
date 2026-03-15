"""Test compiled policies against simulated tool calls.

Usage:
    aegis test <tool_name> [key=value ...]

Examples:
    aegis test aws_create_ec2_instance region=us-east-1
    aegis test Bash command="git push --force origin main"
    aegis test runpod_create_pod name=my-pod gpu_type_id=A100
    aegis test Bash command="aws s3api put-bucket-acl --bucket foo --acl public-read"
    aegis test github_create_pull_request owner=me repo=stuff title="new PR"

    aegis test --list              List compiled rules
    aegis test --state             Show gathered state (without evaluating)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# ANSI
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
DIM = "\033[2m"
RESET = "\033[0m"


def _parse_args(argv: list[str]) -> tuple[str, dict]:
    """Parse 'tool_name key=value ...' into (name, arguments)."""
    if not argv:
        return "", {}
    tool_name = argv[0]
    arguments: dict = {}
    for arg in argv[1:]:
        if "=" in arg:
            k, v = arg.split("=", 1)
            # Try to parse as JSON for numbers/bools
            try:
                v = json.loads(v)
            except (json.JSONDecodeError, ValueError):
                pass
            arguments[k] = v
    return tool_name, arguments


def _show_rules(project_dir: Path) -> int:
    compiled = project_dir / ".aegis" / "compiled"
    if not compiled.exists():
        print("No compiled policies. Run 'aegis compile' first.")
        return 1

    manifest = compiled / "manifest.json"
    if not manifest.exists():
        print("No manifest found. Run 'aegis compile' first.")
        return 1

    rules = json.loads(manifest.read_text())
    print(f"\n{CYAN}Compiled rules:{RESET}\n")
    for r in rules:
        errors = r.get("errors", [])
        status = f"{GREEN}OK{RESET}" if not errors else f"{YELLOW}WARN{RESET}"
        print(f"  [{status}] {r['title']}")
        print(f"       {DIM}{r['id']}{RESET}")
        if errors:
            for e in errors:
                print(f"       {RED}{e}{RESET}")
    print()
    return 0


def _show_state(project_dir: Path) -> int:
    from aegis.compiler.state_manager import gather_state
    compiled = project_dir / ".aegis" / "compiled"
    if not compiled.exists():
        print("No compiled policies. Run 'aegis compile' first.")
        return 1

    print(f"\n{CYAN}Gathering state from all rules...{RESET}\n")
    state = gather_state(compiled)

    if not state:
        print(f"  {DIM}(no state gatherers returned data){RESET}")
    else:
        for rule_id, data in state.items():
            print(f"  {GREEN}{rule_id}{RESET}:")
            if isinstance(data, dict) and "_error" in data:
                print(f"    {RED}ERROR: {data['_error'][:200]}{RESET}")
            else:
                for k, v in (data if isinstance(data, dict) else {"value": data}).items():
                    print(f"    {k}: {v}")
            print()
    return 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    project_dir = Path.cwd()

    if argv[0] == "--list":
        return _show_rules(project_dir)

    if argv[0] == "--state":
        return _show_state(project_dir)

    tool_name, arguments = _parse_args(argv)
    if not tool_name:
        print("Usage: aegis test <tool_name> [key=value ...]")
        return 1

    # Check compiled policies exist
    compiled = project_dir / ".aegis" / "compiled"
    if not compiled.exists():
        print("No compiled policies. Run 'aegis compile' first.")
        return 1

    from aegis.core.engine import OpaEngine, ToolCall, ensure_opa_binary

    print(f"\n{CYAN}Testing tool call:{RESET}")
    print(f"  tool:      {tool_name}")
    if arguments:
        for k, v in arguments.items():
            print(f"  {k}: {v}")
    print()

    # Ensure OPA binary
    try:
        ensure_opa_binary()
    except RuntimeError as exc:
        print(f"{RED}OPA binary not available: {exc}{RESET}")
        return 1

    # Evaluate
    engine = OpaEngine(project_dir=project_dir)
    tc = ToolCall(name=tool_name, arguments=arguments)
    decision = engine.evaluate(tc)

    if decision.allowed:
        print(f"  {GREEN}ALLOWED{RESET}")
    else:
        print(f"  {RED}DENIED{RESET}")
        for reason in decision.reasons:
            print(f"    {RED}→ {reason}{RESET}")

    print()
    return 0
