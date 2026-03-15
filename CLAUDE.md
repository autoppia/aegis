# Aegis

Policy enforcement wrapper for AI coding agents (Codex, Claude Code). Intercepts API calls at the proxy level to inject context and enforce OPA policies — no static file mutation needed.

**IMPORTANT**: Policies are only active when launched through Aegis:
- `aegis claude` — NOT plain `claude`
- `aegis codex` — NOT plain `codex`

Running the agent directly bypasses all policy enforcement.

## Architecture

```
Agent (Codex / Claude Code)
  │
  ▼
Aegis Proxy (single HTTP server on localhost)
  │
  ├─ REQUEST:  Inject runtime context (RULES.md, compiled policies)
  │            OpenAI:    system message in messages[]
  │            Anthropic: appended to system field
  │
  ├─ RESPONSE: Extract tool calls, evaluate against OPA policies
  │            OpenAI:    message.tool_calls[].function
  │            Anthropic: content[].type=="tool_use"
  │
  ├─ ALLOWED:  Pass response through unchanged
  └─ DENIED:   Rewrite response with denial message + terminal notification
```

### Package structure

```
aegis/
  cli.py                         # entry point — init, add, list, delete, compile, run
  constants.py                   # shared config (paths, markers, model names)

  core/                          # proxy + policy engine
    proxy.py                     # HTTP reverse proxy (OpenAI + Anthropic)
    engine.py                    # OPA binary management + policy evaluation
    context.py                   # context providers (RULES.md → system message)
    policy_model.py              # POLICY_MODEL — LLM-as-judge with allow/deny tools

  compiler/                      # rule compilation pipeline
    compiler.py                  # RULES.md → rego + state.py + classifier.json
    rule_parser.py               # parse RULES.md into Rule objects
    state_manager.py             # load + run generated state.py modules
    tools.py                     # API clients for state fetchers (AWS, RunPod, GitHub, etc.)

  runtime/                       # session management + launchers
    launcher.py                  # Codex PTY wrapper
    claude_launcher.py           # Claude Code launcher
    session.py                   # session state, layout, codex resolution
    control.py / control_cli.py  # unix socket session control
    config.py                    # codex config.toml management
    events.py                    # JSONL event logging
    notify_hook.py               # codex turn notification hook
    test_policy.py               # CLI for testing tool calls against policies

  policies/                      # shipped OPA policies
    default.rego                 # built-in safety (rm -rf, push to main, etc.)
```

### Data flow

1. `RULES.md` → natural language rules (human-written)
2. `aegis compile` → `.aegis/compiled/<rule_id>/policy.rego` + `state.py` + `classifier.json`
3. `aegis/policies/default.rego` → hardcoded safety policies (rm -rf, network exfil, etc.)
4. At runtime, proxy reads rules + compiled manifest → injects as context
5. OPA evaluates all `.rego` files (default + compiled) against tool calls

### File layout

```
~/.aegis/
  bin/opa              # downloaded OPA binary
  logs/                # JSONL event logs per session
  sessions/            # session state JSON files
  policies/            # global user OPA policies
  run/                 # unix sockets for active sessions

<project>/
  RULES.md             # policy rules (human-written)
  .aegis/
    compiled/          # LLM-generated from RULES.md
      manifest.json
      <rule_id>/
        policy.rego    # OPA policy
        state.py       # runtime state gatherer
        rule.json      # metadata
    policies/          # project-local OPA policies (manual .rego)
```

## Commands

```bash
aegis init                       # Create RULES.md with starter rules
aegis add "rule description"     # Add a rule and auto-compile
aegis list                       # List all rules and their status
aegis delete <number>            # Delete a rule by number
aegis compile                    # Compile RULES.md → OPA policies + state gatherers
aegis codex [args...]            # Launch Codex with policy proxy
aegis claude [args...]           # Launch Claude Code with policy proxy
aegis test <tool> [k=v ...]      # Test a tool call against compiled policies
aegis test --list                # List compiled rules
aegis test --state               # Show gathered runtime state
aegis ctl status                 # Show active session
aegis ctl stop [--kill]          # Stop active session
```

## Development

- Python 3.10+, zero runtime dependencies (stdlib only)
- OPA binary is auto-downloaded on first use
- Compiler requires `claude` or `codex` CLI in PATH (uses it as the LLM)
- `tools.py` clients use subprocess (aws cli, kubectl) or urllib (REST APIs) — no pip deps
- All state gatherers must define `get_state() -> dict` and handle errors gracefully
- Rego policies use package `aegis`, import `rego.v1`, add to `deny` set
- The proxy buffers streaming responses to evaluate tool calls before replaying

## Conventions

- Context injection happens at the proxy level, never by mutating project files
- OPA policies are fail-closed: if evaluation errors, the tool call is denied
- Event logging is append-only JSONL (one file per session)
- The profanity filter on Codex input uses a warmup period to avoid blocking initial prompts
