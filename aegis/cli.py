"""Aegis CLI — policy enforcement for AI coding agents.

Usage:
    aegis init                       Initialize RULES.md in current directory
    aegis add "rule description"     Add a rule and compile it
    aegis list                       List all rules
    aegis delete <number>            Delete a rule by number
    aegis compile                    Compile RULES.md into OPA policies
    aegis codex [args...]            Launch Codex with policy enforcement
    aegis claude [args...]           Launch Claude Code with policy enforcement
    aegis test <tool> [k=v ...]      Test a tool call against policies
    aegis ctl <subcommand>           Control active session
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

# ANSI colors
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
RED = "\033[1;31m"
YELLOW = "\033[1;33m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _warn_missing_keys() -> None:
    """Print warnings if relevant API keys are missing."""
    has_openai = bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("CODEX_API_KEY"))
    has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY"))

    if not has_openai and not has_anthropic:
        print(
            f"{YELLOW}[aegis] Warning: No API keys found (OPENAI_API_KEY or ANTHROPIC_API_KEY).{RESET}",
            file=sys.stderr,
        )
        print(
            f"{YELLOW}        Deterministic rules (OPA) will work, but POLICY_MODEL classifiers won't.{RESET}",
            file=sys.stderr,
        )
        print(
            f"{YELLOW}        Set keys in .env or environment. See .env.template{RESET}",
            file=sys.stderr,
        )


def _rules_path() -> Path:
    return Path.cwd() / "RULES.md"


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"  {CYAN}>{RESET} {prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return answer or default


def _ask_yn(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    try:
        answer = input(f"  {CYAN}>{RESET} {prompt} ({hint}): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not answer:
        return default
    return answer.startswith("y")


# ── init ─────────────────────────────────────────────────────────────

def cmd_init() -> int:
    path = _rules_path()
    if path.exists():
        print(f"{YELLOW}RULES.md already exists in this directory.{RESET}")
        return 1

    path.write_text(
        "## No push to main\n"
        "Block any git push to main or master. Use feature branches and PRs.\n",
        encoding="utf-8",
    )
    print(f"{GREEN}Created RULES.md with a starter rule.{RESET}")
    print(f"Edit it, then run: {CYAN}aegis compile{RESET}")
    return 0


# ── add ──────────────────────────────────────────────────────────────

def cmd_add(args: list[str]) -> int:
    # Get the rule description
    if not args:
        print(f"\n{BOLD}Add a new rule{RESET}\n")
        description = _ask("Describe the rule")
        if not description:
            print(f"{RED}No description provided.{RESET}")
            return 1
    else:
        description = " ".join(args)

    # Extract title
    title = description.split(".")[0].split("\n")[0].strip()
    if len(title) > 80:
        title = title[:80]

    print(f"\n  {BOLD}{title}{RESET}")
    print(f"  {DIM}{description}{RESET}\n")

    # Ask about data source — only if the rule likely needs live data
    extra_lines: list[str] = []

    if _ask_yn("Does this rule need to check live data? (e.g. instance count, balance)"):
        print(f"\n  {DIM}How should the data be fetched?{RESET}")
        print(f"    {CYAN}1{RESET} — Shell command     e.g. aws ec2 describe-instances, kubectl get pods")
        print(f"    {CYAN}2{RESET} — HTTP API          provide URL + auth header")
        print(f"    {CYAN}3{RESET} — Custom script     a script that outputs JSON")
        print(f"    {CYAN}4{RESET} — Auto              let the compiler figure it out\n")

        choice = _ask("Choice", "4")

        if choice == "1":
            cmd = _ask("Command to run")
            if cmd:
                extra_lines.append(f"State: run `{cmd}` and parse the JSON output.")
        elif choice == "2":
            url = _ask("API endpoint")
            auth = _ask("Auth header (e.g. Bearer $RUNPOD_API_KEY)", "")
            if url:
                extra_lines.append(f"State: GET {url}")
                if auth:
                    extra_lines.append(f"Authorization: {auth}")
        elif choice == "3":
            script = _ask("Script path (must output JSON to stdout)")
            if script:
                extra_lines.append(f"State: run `{script}` (outputs JSON).")
        # choice 4 = auto, no extra lines

    # Build final text
    full_description = description
    if extra_lines:
        full_description += "\n" + "\n".join(extra_lines)

    # Write to RULES.md
    path = _rules_path()
    if not path.exists():
        path.write_text("", encoding="utf-8")

    existing = path.read_text(encoding="utf-8")
    if existing and not existing.endswith("\n"):
        existing += "\n"

    path.write_text(
        existing + f"\n## {title}\n{full_description}\n",
        encoding="utf-8",
    )
    print(f"\n{GREEN}Added rule: {title}{RESET}")

    # Compile
    if _ask_yn("Compile now?", default=True):
        print()
        return cmd_compile()

    print(f"Run {CYAN}aegis compile{RESET} when ready.")
    return 0


# ── list ─────────────────────────────────────────────────────────────

def cmd_list() -> int:
    path = _rules_path()
    if not path.exists():
        print(f"{YELLOW}No RULES.md found. Run: aegis init{RESET}")
        return 1

    from aegis.compiler.rule_parser import parse_rules
    text = path.read_text(encoding="utf-8")
    rules = parse_rules(text)

    if not rules:
        print(f"{YELLOW}No rules found in RULES.md{RESET}")
        return 0

    # Check compiled state
    compiled_dir = Path.cwd() / ".aegis" / "compiled"
    manifest = compiled_dir / "manifest.json" if compiled_dir.exists() else None
    compiled_rules: dict[str, dict] = {}
    if manifest and manifest.exists():
        import json
        try:
            for r in json.loads(manifest.read_text(encoding="utf-8")):
                compiled_rules[r.get("title", "")] = r
        except (json.JSONDecodeError, OSError):
            pass

    print(f"\n{BOLD}Rules ({len(rules)}):{RESET}\n")
    for i, rule in enumerate(rules, 1):
        compiled = compiled_rules.get(rule.title)
        if compiled:
            rule_type = compiled.get("type", "deterministic")
            label = "OPA" if rule_type == "deterministic" else "POLICY_MODEL"
            warnings = compiled.get("warnings", [])
            if warnings:
                status = f"{YELLOW}compiled [{label}] ({len(warnings)} warning{'s' if len(warnings) != 1 else ''}){RESET}"
            else:
                status = f"{GREEN}compiled [{label}]{RESET}"
        else:
            status = f"{DIM}not compiled{RESET}"

        print(f"  {CYAN}{i}.{RESET} {rule.title}  {status}")
        if rule.body and rule.body != rule.title:
            first_line = rule.body.split("\n")[0].strip()
            if first_line and first_line != rule.title:
                print(f"     {DIM}{first_line[:80]}{RESET}")
    print()
    return 0


# ── delete ───────────────────────────────────────────────────────────

def cmd_delete(args: list[str]) -> int:
    if not args:
        print(f"{RED}Usage: aegis delete <rule-number>{RESET}")
        print(f"  Run 'aegis list' to see rule numbers.")
        return 1

    try:
        num = int(args[0])
    except ValueError:
        print(f"{RED}Invalid rule number: {args[0]}{RESET}")
        return 1

    path = _rules_path()
    if not path.exists():
        print(f"{YELLOW}No RULES.md found.{RESET}")
        return 1

    from aegis.compiler.rule_parser import parse_rules
    text = path.read_text(encoding="utf-8")
    rules = parse_rules(text)

    if num < 1 or num > len(rules):
        print(f"{RED}Rule {num} not found. Have {len(rules)} rule(s).{RESET}")
        return 1

    target = rules[num - 1]
    print(f"{RED}Deleting rule {num}: {target.title}{RESET}")

    new_text = text.replace(target.raw, "").strip()
    new_text = re.sub(r"\n{3,}", "\n\n", new_text)
    if new_text and not new_text.endswith("\n"):
        new_text += "\n"

    path.write_text(new_text, encoding="utf-8")
    print(f"{GREEN}Rule deleted. Run 'aegis compile' to update policies.{RESET}")
    return 0


# ── compile ──────────────────────────────────────────────────────────

def cmd_compile() -> int:
    from aegis.compiler.compiler import compile_all
    try:
        results = compile_all(Path.cwd())
        # Show actionable errors for state fetcher failures
        for r in results:
            for w in r.get("warnings", []):
                if "get_state()" in w and ("raised" in w or "error" in w):
                    print(f"\n{YELLOW}[aegis] Rule '{r['title']}' state fetcher failed:{RESET}")
                    print(f"  {w}")
                    print(f"  {DIM}Fix options:{RESET}")
                    print(f"    1. Install the required CLI tool (aws, kubectl, etc.)")
                    print(f"    2. Set the required env var (see .env.template)")
                    print(f"    3. Edit the rule in RULES.md to specify how to fetch data")
                    print(f"    4. Edit .aegis/compiled/<rule>/state.py directly")
        errors = [r for r in results if r.get("errors")]
        if errors:
            print(f"\n{len(errors)} rule(s) had errors.")
            return 1
        return 0
    except (FileNotFoundError, ValueError) as exc:
        print(f"{RED}aegis: {exc}{RESET}", file=sys.stderr)
        return 1


# ── main ─────────────────────────────────────────────────────────────

def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(f"{BOLD}Aegis{RESET} — policy enforcement for AI coding agents\n")
        print(f"Usage: {CYAN}aegis{RESET} <command> [args...]\n")
        print("Setup:")
        print(f"  {CYAN}init{RESET}                       Create RULES.md with starter rules")
        print(f"  {CYAN}add{RESET} \"description\"          Add a rule (interactive)")
        print(f"  {CYAN}list{RESET}                       List all rules and their status")
        print(f"  {CYAN}delete{RESET} <number>            Delete a rule by number")
        print(f"  {CYAN}compile{RESET}                    Compile RULES.md into OPA policies")
        print()
        print("Run:")
        print(f"  {CYAN}codex{RESET} [args...]            Launch Codex with policy enforcement")
        print(f"  {CYAN}claude{RESET} [args...]           Launch Claude Code with policy enforcement")
        print()
        print("Debug:")
        print(f"  {CYAN}test{RESET} <tool> [k=v ...]      Test a tool call against policies")
        print(f"  {CYAN}test --list{RESET}                List compiled rules")
        print(f"  {CYAN}test --state{RESET}               Show gathered runtime state")
        print(f"  {CYAN}ctl{RESET} status|stop|inject     Control active session")
        print(f"  {CYAN}--version{RESET}                  Show version")
        print()
        print(f"Quick start: {CYAN}aegis init && aegis compile && aegis claude{RESET}")
        return 0 if sys.argv[1:] in (["-h"], ["--help"]) else 1

    command = sys.argv[1]

    if command == "init":
        return cmd_init()

    if command == "add":
        return cmd_add(sys.argv[2:])

    if command == "list":
        return cmd_list()

    if command == "delete":
        return cmd_delete(sys.argv[2:])

    if command == "compile":
        return cmd_compile()

    if command == "codex":
        _warn_missing_keys()
        codex_args = sys.argv[2:]

        if codex_args and codex_args[0] in ("--help", "-h", "--version"):
            from aegis.runtime.session import resolve_real_codex
            real_codex = resolve_real_codex(sys.argv[0])
            return subprocess.call([real_codex, *codex_args])

        no_policy = "--no-policy" in codex_args
        if no_policy:
            codex_args = [a for a in codex_args if a != "--no-policy"]
        from aegis.runtime.launcher import main as launcher_main
        return launcher_main(codex_args, no_policy=no_policy)

    if command == "claude":
        _warn_missing_keys()
        from aegis.runtime.claude_launcher import main as claude_main
        return claude_main(sys.argv[2:])

    if command == "test":
        from aegis.runtime.test_policy import main as test_main
        return test_main(sys.argv[2:])

    if command == "ctl":
        from aegis.runtime.control_cli import main as ctl_main
        return ctl_main(sys.argv[2:])

    if command == "--version":
        from aegis import __version__
        print(f"aegis {__version__}")
        return 0

    print(f"{RED}Unknown command: {command}{RESET}")
    print(f"Run {CYAN}aegis --help{RESET} for usage.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
