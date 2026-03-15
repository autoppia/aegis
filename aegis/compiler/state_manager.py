"""Runtime state gathering for compiled policy rules.

Loads generated state.py modules and runs get_state() at evaluation time,
feeding the combined state into OPA alongside the tool call input.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import traceback
from pathlib import Path
from typing import Any


def _load_state_module(state_file: Path) -> Any:
    """Dynamically load a state.py module."""
    spec = importlib.util.spec_from_file_location(
        f"aegis_state_{state_file.parent.name}", str(state_file)
    )
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gather_state(compiled_dir: Path) -> dict[str, Any]:
    """Run all state gatherers and return merged state dict.

    Each rule's state.py contributes a key in the state dict named after
    the rule_id. This prevents collisions between rules that fetch
    different kinds of state.

    Returns:
        {"rule_001_no_aws_instances_abc123": {"instance_count": 3}, ...}
    """
    state: dict[str, Any] = {}

    if not compiled_dir.exists():
        return state

    for rule_dir in sorted(compiled_dir.iterdir()):
        if not rule_dir.is_dir():
            continue
        state_file = rule_dir / "state.py"
        if not state_file.exists():
            continue

        try:
            module = _load_state_module(state_file)
            if module is None:
                continue
            get_state = getattr(module, "get_state", None)
            if not callable(get_state):
                continue
            result = get_state()
            if isinstance(result, dict):
                state[rule_dir.name] = result
        except Exception:
            # State gathering failure should not block evaluation.
            # Log but continue — OPA will evaluate with missing state,
            # and the policy can handle that (fail-open or fail-closed
            # depending on how the Rego was generated).
            state[rule_dir.name] = {"_error": traceback.format_exc()}

    return state


def list_compiled_rules(compiled_dir: Path) -> list[dict]:
    """List all compiled rules from the manifest."""
    manifest = compiled_dir / "manifest.json"
    if not manifest.exists():
        return []
    return json.loads(manifest.read_text(encoding="utf-8"))
