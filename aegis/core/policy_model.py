"""Non-deterministic policy evaluation via LLM (POLICY_MODEL).

For rules that can't be enforced deterministically (e.g. "no profanity",
"no toxic content"), the POLICY_MODEL is called as an LLM-as-judge.

It receives:
  - The rule description
  - The content to evaluate (user input, agent output, tool call)
  - Runtime state from state gatherers
  - Two tools: allow() and deny(reason)

The LLM decides whether the content violates the rule by calling one of
these tools. This makes the decision structured and parseable, and works
with any LLM that supports tool calling (OpenAI, Anthropic, or custom).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib import error, request

from aegis.constants import ANTHROPIC_API_BASE, OPENAI_API_BASE


# ── Tool schemas ─────────────────────────────────────────────────────

OPENAI_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "allow",
            "description": "The content does NOT violate the rule.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "deny",
            "description": "The content VIOLATES the rule. Provide a reason.",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "Why the content violates the rule.",
                    }
                },
                "required": ["reason"],
            },
        },
    },
]

ANTHROPIC_TOOLS = [
    {
        "name": "allow",
        "description": "The content does NOT violate the rule.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "deny",
        "description": "The content VIOLATES the rule. Provide a reason.",
        "input_schema": {
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "description": "Why the content violates the rule.",
                }
            },
            "required": ["reason"],
        },
    },
]


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str = ""
    rule_id: str = ""
    rule_title: str = ""


@dataclass
class ClassifierConfig:
    """Loaded from classifier.json in compiled rule directory."""

    rule_id: str
    rule_title: str
    system_prompt: str
    check_request: bool = True     # check user input messages
    check_response: bool = False   # check agent output text
    deny_reason: str = ""

    @classmethod
    def from_file(cls, path: Path, rule_id: str, rule_title: str) -> ClassifierConfig | None:
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if not data.get("enabled", True):
            return None
        return cls(
            rule_id=rule_id,
            rule_title=rule_title,
            system_prompt=data.get("system_prompt", ""),
            check_request=data.get("check_request", True),
            check_response=data.get("check_response", False),
            deny_reason=data.get("deny_reason", ""),
        )


def _detect_provider() -> str:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY") or os.environ.get("CODEX_API_KEY"):
        return "openai"
    return "none"


def _get_policy_model() -> str:
    """Get the policy model name from env or use defaults."""
    explicit = os.environ.get("AEGIS_POLICY_MODEL")
    if explicit:
        return explicit
    provider = _detect_provider()
    if provider == "anthropic":
        return "claude-haiku-4-5-20251001"
    return "gpt-4o-mini"


def _build_messages(classifier: ClassifierConfig, content: str,
                    state: dict | None = None) -> list[dict]:
    """Build messages for the policy model."""
    user_parts = [f"Evaluate this content against the rule:\n\n{content}"]
    if state:
        user_parts.append(f"\nRuntime state:\n{json.dumps(state, indent=2)}")
    return [{"role": "user", "content": "\n".join(user_parts)}]


def _call_openai(system_prompt: str, messages: list[dict],
                 model: str) -> PolicyDecision:
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("CODEX_API_KEY")
    if not api_key:
        return PolicyDecision(allowed=True, reason="no_api_key")

    base = os.environ.get("AEGIS_POLICY_MODEL_BASE_URL",
                          os.environ.get("OPENAI_BASE_URL", OPENAI_API_BASE))
    # Don't use the proxy URL — use the real API
    if "127.0.0.1" in base or "localhost" in base:
        base = OPENAI_API_BASE

    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system_prompt}] + messages,
        "tools": OPENAI_TOOLS,
        "tool_choice": "required",
        "temperature": 0,
        "max_tokens": 150,
    }
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        f"{base}/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (error.HTTPError, error.URLError, OSError):
        # Fail-open on API errors — don't block user if model is down
        return PolicyDecision(allowed=True, reason="api_error")

    # Extract tool call
    for choice in data.get("choices", []):
        msg = choice.get("message", {})
        for tc in msg.get("tool_calls", []):
            func = tc.get("function", {})
            name = func.get("name", "")
            if name == "deny":
                try:
                    args = json.loads(func.get("arguments", "{}"))
                except json.JSONDecodeError:
                    args = {}
                return PolicyDecision(
                    allowed=False,
                    reason=args.get("reason", "policy violation"),
                )
            if name == "allow":
                return PolicyDecision(allowed=True)

    # No tool call — default allow
    return PolicyDecision(allowed=True, reason="no_tool_call")


def _call_anthropic(system_prompt: str, messages: list[dict],
                    model: str) -> PolicyDecision:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return PolicyDecision(allowed=True, reason="no_api_key")

    base = os.environ.get("AEGIS_POLICY_MODEL_BASE_URL",
                          os.environ.get("ANTHROPIC_BASE_URL", ANTHROPIC_API_BASE))
    if "127.0.0.1" in base or "localhost" in base:
        base = ANTHROPIC_API_BASE

    payload = {
        "model": model,
        "system": system_prompt,
        "messages": messages,
        "tools": ANTHROPIC_TOOLS,
        "tool_choice": {"type": "any"},
        "max_tokens": 150,
    }
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        f"{base}/v1/messages",
        data=body,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (error.HTTPError, error.URLError, OSError):
        return PolicyDecision(allowed=True, reason="api_error")

    for block in data.get("content", []):
        if block.get("type") == "tool_use":
            name = block.get("name", "")
            if name == "deny":
                inp = block.get("input", {})
                return PolicyDecision(
                    allowed=False,
                    reason=inp.get("reason", "policy violation"),
                )
            if name == "allow":
                return PolicyDecision(allowed=True)

    return PolicyDecision(allowed=True, reason="no_tool_call")


def evaluate(classifier: ClassifierConfig, content: str,
             state: dict | None = None) -> PolicyDecision:
    """Evaluate content against a classifier rule using the POLICY_MODEL.

    Returns a PolicyDecision with allow/deny and reason.
    """
    if not classifier.system_prompt:
        return PolicyDecision(allowed=True, reason="no_system_prompt")

    model = _get_policy_model()
    messages = _build_messages(classifier, content, state)
    provider = _detect_provider()

    if provider == "anthropic":
        decision = _call_anthropic(classifier.system_prompt, messages, model)
    elif provider == "openai":
        decision = _call_openai(classifier.system_prompt, messages, model)
    else:
        return PolicyDecision(allowed=True, reason="no_provider")

    decision.rule_id = classifier.rule_id
    decision.rule_title = classifier.rule_title
    if not decision.allowed and not decision.reason:
        decision.reason = classifier.deny_reason
    return decision


def load_classifiers(compiled_dir: Path) -> list[ClassifierConfig]:
    """Load all classifier configs from compiled rule directories."""
    classifiers: list[ClassifierConfig] = []
    if not compiled_dir.exists():
        return classifiers

    for rule_dir in sorted(compiled_dir.iterdir()):
        if not rule_dir.is_dir():
            continue
        classifier_file = rule_dir / "classifier.json"
        # Get rule metadata for title
        rule_meta_file = rule_dir / "rule.json"
        rule_title = rule_dir.name
        if rule_meta_file.exists():
            try:
                meta = json.loads(rule_meta_file.read_text(encoding="utf-8"))
                rule_title = meta.get("title", rule_dir.name)
            except (json.JSONDecodeError, OSError):
                pass

        config = ClassifierConfig.from_file(
            classifier_file, rule_id=rule_dir.name, rule_title=rule_title
        )
        if config:
            classifiers.append(config)

    return classifiers
