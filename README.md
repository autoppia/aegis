# Aegis

Policy enforcement for AI coding agents. Write rules in plain English, Aegis compiles them to [OPA](https://www.openpolicyagent.org/) policies and enforces them at runtime by intercepting every API call.

Works with **OpenAI Codex** and **Claude Code**.

## How it works

```
RULES.md (plain English)
    │
    ▼
aegis compile
    │
    ├─ Deterministic rules  → OPA Rego policy + state fetcher
    └─ Non-deterministic    → POLICY_MODEL classifier + state fetcher

aegis claude / aegis codex
    │
    ▼
┌────────────────────────────────────────────────┐
│              Local HTTP Proxy                  │
│                                                │
│  REQUEST:  1. POLICY_MODEL classifiers         │
│               (profanity, tone, etc.)          │
│            2. Context injection                │
│               (rules → system message)         │
│                                                │
│  RESPONSE: 3. OPA policy evaluation            │
│               (tool calls → allow / deny)      │
│                                                │
│  BLOCKED → rewrite response, notify terminal   │
└────────────────────────────────────────────────┘
```

## Install

```bash
git clone https://github.com/autoppia/aegis.git
cd aegis
pip install -e .
```

## Quick start

```bash
# 1. Initialize rules in your project
cd your-project
aegis init
```

Edit `RULES.md` and write your rules:

```markdown
## No push to main
Block any git push to main or master. Use feature branches and PRs.

## No more than 5 EC2 instances
Block creating EC2 instances if there are already 5 or more running.

## No curse words in prompts
Block any user input containing profanity, slurs, or curse words.
```

```bash
# 2. Compile rules
aegis compile

# 3. Run your agent through Aegis
aegis claude          # wraps Claude Code
aegis codex           # wraps Codex
```

That's it. Tool calls that violate rules get blocked before the agent executes them.

## CLI

```
aegis init                       Create RULES.md with starter rules
aegis add "rule description"     Add a rule and auto-compile
aegis list                       List all rules and their status
aegis delete <number>            Delete a rule by number
aegis compile                    Compile RULES.md into policies

aegis claude [args...]           Launch Claude Code with enforcement
aegis codex [args...]            Launch Codex with enforcement

aegis test <tool> [k=v ...]      Test a tool call against policies
aegis test --list                List compiled rules
aegis test --state               Show gathered runtime state
aegis ctl status                 Show active session
aegis ctl stop [--kill]          Stop active session
```

## Two types of rules

### Deterministic → OPA

Rules about tool calls, commands, and resource limits. Enforced locally with zero latency.

```markdown
## No push to main
Block any git push to main or master. Use feature branches and PRs.

## No more than 5 EC2 instances
Block creating EC2 instances if there are already 5 or more running.

## No public S3 buckets
Block setting bucket ACL to public-read or public-read-write.
```

### Non-deterministic → POLICY_MODEL

Rules about content, tone, and language. Enforced by an LLM-as-judge that calls `allow()` or `deny(reason)` tools.

```markdown
## No curse words
Block any user input containing profanity, slurs, or curse words.

## Professional tone only
Block unprofessional or hostile language in prompts.
```

## Configuration

### API keys

**Most setups need zero API keys.** Aegis uses `claude` CLI (which has its own auth) for compilation, and local OPA for deterministic rules.

API keys are only needed for **non-deterministic rules** (profanity, tone, etc.):

```bash
cp .env.template .env

# Add one of:
OPENAI_API_KEY=sk-...          # POLICY_MODEL uses gpt-4o-mini
ANTHROPIC_API_KEY=sk-ant-...   # POLICY_MODEL uses claude-haiku-4-5
```

### POLICY_MODEL

The LLM that enforces non-deterministic rules. Override with env vars:

```bash
AEGIS_POLICY_MODEL=your-fine-tuned-model
AEGIS_POLICY_MODEL_BASE_URL=https://your-endpoint.com/v1
```

### State gatherer keys

If your rules reference external services, add their API keys to `.env`:

```bash
RUNPOD_API_KEY=...           # RunPod balance checks
GITHUB_TOKEN=ghp_...         # GitHub PR count checks
AWS_ACCESS_KEY_ID=...        # EC2 instance counts
```

## How blocking works

### Tool call blocked (OPA)

```
> commit and push to main

[AEGIS] Blocked: Bash — push to main/master branch is blocked
        — use a feature branch and create a PR
```

The LLM's tool call is rewritten into a denial message. The agent sees this and adjusts.

### User input blocked (POLICY_MODEL)

```
> what the fuck is this code doing

[AEGIS] Blocked by POLICY_MODEL (No curse words):
        Input contains profanity
```

The request never reaches the LLM. A synthetic denial response is returned.

## Architecture

Single proxy server handles both OpenAI and Anthropic APIs:

| | OpenAI (Codex) | Anthropic (Claude Code) |
|---|---|---|
| Endpoint | `/v1/chat/completions` | `/v1/messages` |
| Context injection | system message in `messages[]` | appended to `system` field |
| Tool call extraction | `tool_calls[].function` | `content[].type=="tool_use"` |
| Env var | `OPENAI_BASE_URL` | `ANTHROPIC_BASE_URL` |

### Compilation output

```
.aegis/compiled/
  manifest.json
  rule_001_no_push_to_main_xxx/
    policy.rego        # OPA policy
    state.py           # runtime state fetcher
    classifier.json    # POLICY_MODEL config (enabled: true/false)
    rule.json          # metadata
```

### Built-in safety (no compilation needed)

`aegis/opa_policies/default.rego` ships with:
- Block `rm -rf /` and destructive commands
- Block file writes outside the project directory
- Block any `git push` to main/master

## Requirements

- Python 3.10+
- `claude` or `codex` CLI in PATH (for rule compilation)
- OPA binary (auto-downloaded on first run)
- Zero pip dependencies — stdlib only
