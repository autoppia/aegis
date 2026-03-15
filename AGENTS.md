# Aegis

Policy enforcement wrapper for AI coding agents (Codex, Claude Code). Intercepts API calls via a local HTTP proxy to inject runtime context and enforce OPA policies.

**IMPORTANT**: Policies are only active when launched through Aegis:
- `aegis codex` — NOT plain `codex`
- `aegis claude` — NOT plain `claude`

Running the agent directly bypasses all policy enforcement.

## Architecture

```
Agent (Codex / Claude Code)
  │
  ▼
Aegis Proxy (single localhost HTTP server, both APIs)
  │
  ├─ REQUEST:  Inject runtime context (RULES.md + compiled policies)
  │            OpenAI  → system message in messages[]
  │            Anthropic → appended to system field
  │
  ├─ RESPONSE: Extract tool calls, evaluate against OPA
  │            OpenAI  → message.tool_calls[].function
  │            Anthropic → content[].type=="tool_use"
  │
  ├─ ALLOWED → pass through unchanged
  └─ DENIED  → rewrite response + terminal notification
```

## Key Modules

- `opa_proxy.py` — HTTP reverse proxy handling both OpenAI and Anthropic APIs. Injects context on requests, evaluates OPA policies on responses. Handles streaming (SSE) by buffering and reassembling before evaluation.
- `context.py` — Context providers that read RULES.md and compiled policy manifest to produce text injected into every API request.
- `opa_engine.py` — OPA binary download/management + `opa eval` subprocess. Fail-closed on errors.
- `compiler.py` — Compiles RULES.md → Rego + state.py per rule via LLM (claude/codex CLI). Validates artifacts, retries on errors.
- `rule_parser.py` — Parses RULES.md into `Rule` objects (supports ## headings or numbered lists).
- `tools.py` — Zero-dependency API clients (AWS CLI, RunPod GraphQL, GitHub REST, Contabo OAuth2, kubectl). Used by generated state gatherers.
- `state_manager.py` — Dynamically loads compiled `state.py` modules, runs `get_state()`, feeds results into OPA input under `input.state["<rule_id>"]`.
- `launcher.py` — Codex wrapper: PTY proxy + input mediation (profanity filter) + session management.
- `claude_launcher.py` — Claude Code wrapper: proxy only, no PTY.
- `config.py` — Manages `~/.codex/config.toml` aegis block (notify hook only).
- `control.py` / `control_cli.py` — Unix socket server + CLI for session control (status, stop, inject).
- `profanity_filter.py` — Input profanity detection (OpenAI gpt-4o-mini with local fallback list).
- `test_policy.py` — CLI to test tool calls against compiled policies without launching an agent.

## Data Flow

1. `RULES.md` — human-written natural language rules
2. `aegis compile` → `.aegis/compiled/<rule_id>/policy.rego` + `state.py` + `rule.json`
3. `opa_policies/default.rego` — hardcoded safety (rm -rf, network exfil, writes outside project)
4. Runtime: proxy reads RULES.md + manifest → injects as system context
5. OPA evaluates all `.rego` (default + compiled) against every tool call in responses

## File Layout

```
~/.aegis/
  bin/opa              # auto-downloaded OPA binary
  logs/                # JSONL event logs
  sessions/            # session state
  policies/            # global user .rego policies
  run/                 # unix sockets

<project>/
  RULES.md             # policy rules (human-authored)
  AGENTS.md            # this file (Codex project docs)
  CLAUDE.md            # Claude Code project docs
  .aegis/
    compiled/          # output of `aegis compile`
      manifest.json
      <rule_id>/
        policy.rego
        state.py
        rule.json
    policies/          # project-local manual .rego files
```

## Commands

```
aegis init                       # Create RULES.md with starter rules
aegis add "rule description"     # Add a rule and auto-compile
aegis list                       # List all rules and their status
aegis delete <number>            # Delete a rule by number
aegis compile                    # RULES.md → OPA policies + state gatherers
aegis codex [args...]            # Codex with policy proxy + PTY wrapper
aegis claude [args...]           # Claude Code with policy proxy
aegis test <tool> [k=v ...]      # Test tool call against policies
aegis test --list                # List compiled rules
aegis test --state               # Show runtime state from all gatherers
aegis ctl status                 # Active session info
aegis ctl stop [--kill]          # Stop active session
```

## Development Notes

- Python 3.10+, zero pip dependencies (all stdlib)
- OPA binary auto-downloaded on first use (~30MB)
- Compiler needs `claude` or `codex` CLI in PATH as the LLM backend
- `tools.py` uses subprocess for CLI tools (aws, kubectl) and urllib for REST/GraphQL — no external packages
- State gatherers: `def get_state() -> dict:` — must handle errors, return safe defaults
- Rego policies: package `aegis`, `import rego.v1`, add strings to `deny` set
- Proxy buffers full streaming responses before evaluating tool calls, then replays or rewrites
- Context injection is runtime-only (proxy level) — never mutate AGENTS.md or config files with instructions
- All OPA evaluation is fail-closed: errors → deny
- Event logs are append-only JSONL, one per session, under `~/.aegis/logs/`
