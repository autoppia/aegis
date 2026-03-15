"""Compile natural-language rules into OPA Rego policies, state gatherers,
and optionally non-deterministic classifiers.

Pipeline:
    RULES.md → parse → LLM generate → .aegis/compiled/<rule_id>/
        policy.rego      — OPA policy (deterministic enforcement)
        state.py         — get_state() function (runtime data for OPA & classifier)
        classifier.json  — non-deterministic classifier config (optional, uses POLICY_MODEL)
        rule.json        — metadata
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

from aegis.constants import wrapper_home
from aegis.core.engine import _opa_binary_path
from aegis.compiler.rule_parser import Rule, find_rules_file, parse_rules

COMPILED_DIR = ".aegis/compiled"

GENERATION_PROMPT = textwrap.dedent("""\
You are a policy compiler for Aegis, a policy enforcement wrapper for AI coding agents.

Given a natural-language rule, generate THREE artifacts:

## Artifact 1: policy.rego
An OPA Rego policy file for DETERMINISTIC enforcement. Requirements:
- Package: `aegis`
- Import: `import rego.v1`
- Add to the `deny` set with a reason string when the rule is violated
- The input document has this structure:
  ```json
  {{
    "tool": {{ "name": "<tool_name>", "arguments": {{...}} }},
    "project_dir": "/path/to/project",
    "state": {{
      "<rule_id>": {{ <data returned by get_state()> }}
    }}
  }}
  ```
- IMPORTANT: Shell/bash tool names differ by agent:
  - Claude Code uses `"Bash"` with `arguments.command`
  - Codex uses `"shell"` with `arguments.command`
  - Your policy MUST handle BOTH names. Use a helper like:
    `is_shell if {{ input.tool.name == "Bash" }}` and
    `is_shell if {{ input.tool.name == "shell" }}`
  - Claude Code file writes use `"Write"` with `arguments.file_path`
  - Codex file writes use `"write_file"` with `arguments.path`
- `input.state` contains runtime data fetched by the state gatherer (Artifact 2).
  Each rule's state is nested under a key matching the rule_id.
  Use the rule_id `{rule_id}` to access this rule's state:
  `input.state["{rule_id}"]`
- If the rule is purely about the tool call itself (e.g. "don't delete files"),
  you don't need `input.state` at all.
- If the rule is NON-DETERMINISTIC (e.g. "no profanity", "no toxic content",
  "be polite") and CANNOT be enforced by checking tool names/arguments/state,
  generate a MINIMAL rego that just allows everything (no deny rules).
  The classifier (Artifact 3) will handle enforcement instead.

## Artifact 2: state.py
A Python module that defines `get_state() -> dict`. Requirements:
- You MUST use the `aegis.compiler.tools` module for external data. It provides
  self-contained API clients with zero external dependencies.
- If the rule needs NO external data (purely about the tool call), return an empty dict.
- Must handle errors gracefully — return a safe default on failure.
- Must be fast (timeout-aware, no blocking forever).
- Include a DESCRIPTION string constant explaining what state is gathered.
- The function signature is exactly: `def get_state() -> dict:`
- NOTE: State is shared — both OPA and the POLICY_MODEL classifier can use it.

{tool_catalog}

## Artifact 3: classifier.json
A JSON config for non-deterministic enforcement via a POLICY_MODEL (LLM-as-judge).

The POLICY_MODEL is called with allow/deny tools to decide if content violates the rule.
It receives the rule description, the content to check, and runtime state.

Generate this for rules that CANNOT be fully enforced deterministically — rules about
content quality, tone, language, profanity, toxicity, appropriateness, etc.

Schema:
```json
{{
  "enabled": true/false,
  "system_prompt": "You enforce the following rule: <rule description>. Evaluate the provided content. If it violates the rule, call the deny tool with a clear reason. If it does not violate the rule, call the allow tool.",
  "check_request": true/false,
  "check_response": true/false,
  "deny_reason": "Default denial reason if the model doesn't provide one"
}}
```

Fields:
- `enabled`: true if this rule needs non-deterministic classification. false if OPA
  handles it fully (most rules about tool calls, commands, resource limits).
- `system_prompt`: Instructions for the POLICY_MODEL. Be specific about what
  to check and what constitutes a violation. Include edge cases.
- `check_request`: true to check user input messages before they reach the LLM.
- `check_response`: true to check the agent's text output.
- `deny_reason`: Fallback denial reason.

## Output format
Respond with EXACTLY this format, no other text:

```rego
<rego policy content>
```

```python
<state.py content>
```

```json
<classifier.json content>
```

## Rule to compile
Title: {title}
Description: {body}
""")


def _compiled_dir(project_dir: Path) -> Path:
    return project_dir / COMPILED_DIR


def _call_llm(prompt: str) -> str:
    """Call claude CLI to generate policy artifacts."""
    for cmd in ("claude", "codex"):
        binary = shutil.which(cmd)
        if binary:
            break
    else:
        raise RuntimeError(
            "Neither 'claude' nor 'codex' found in PATH. "
            "Install Claude Code or Codex CLI to use the compiler."
        )

    result = subprocess.run(
        [binary, "-p", prompt, "--dangerously-skip-permissions"],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "CLAUDE_CODE_ENTRYPOINT": "aegis-compiler"},
    )
    if result.returncode != 0:
        raise RuntimeError(f"{cmd} failed (rc={result.returncode}): {result.stderr[:500]}")
    return result.stdout


def _parse_artifacts(llm_output: str) -> tuple[str, str, str]:
    """Extract rego, python, and json blocks from LLM output."""
    import re

    rego_match = re.search(r"```rego\s*\n(.*?)```", llm_output, re.DOTALL)
    python_match = re.search(r"```python\s*\n(.*?)```", llm_output, re.DOTALL)
    json_match = re.search(r"```json\s*\n(.*?)```", llm_output, re.DOTALL)

    if not rego_match:
        raise ValueError("LLM output missing ```rego``` block")
    if not python_match:
        raise ValueError("LLM output missing ```python``` block")

    rego = rego_match.group(1).strip()
    python = python_match.group(1).strip()
    classifier = json_match.group(1).strip() if json_match else '{"enabled": false}'

    return rego, python, classifier


def _validate_rego(rego_content: str, rule_id: str) -> list[str]:
    """Validate generated Rego with opa check. Returns list of errors."""
    import tempfile

    opa = _opa_binary_path()
    if not opa.exists():
        return []

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".rego", delete=False, prefix=f"{rule_id}_"
    ) as f:
        f.write(rego_content)
        tmp_path = f.name

    try:
        result = subprocess.run(
            [str(opa), "check", tmp_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return [result.stderr.strip()]
        return []
    finally:
        os.unlink(tmp_path)


def _validate_python(python_content: str) -> list[str]:
    """Basic syntax check on generated Python."""
    try:
        compile(python_content, "<state.py>", "exec")
        return []
    except SyntaxError as exc:
        return [f"SyntaxError: {exc}"]


def _validate_classifier(classifier_content: str) -> list[str]:
    """Validate classifier JSON."""
    try:
        data = json.loads(classifier_content)
        if not isinstance(data, dict):
            return ["classifier.json must be a JSON object"]
        return []
    except json.JSONDecodeError as exc:
        return [f"Invalid classifier JSON: {exc}"]


def _validate_state_runtime(state_file: Path, rule_id: str) -> list[str]:
    """Dry-run the state fetcher: import, call get_state(), check result.

    Also inspects the source to detect missing CLI tools and env vars
    so we can give actionable errors even if get_state() silently returns {}.
    """
    import importlib.util
    import shutil
    warnings: list[str] = []

    source = state_file.read_text(encoding="utf-8") if state_file.exists() else ""

    # Check for required CLI tools in subprocess calls
    cli_tools = {
        "aws": "AWS CLI (pip install awscli / brew install awscli)",
        "kubectl": "kubectl (https://kubernetes.io/docs/tasks/tools/)",
        "gcloud": "gcloud CLI (https://cloud.google.com/sdk/docs/install)",
        "az": "Azure CLI (https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)",
    }
    for tool, install_hint in cli_tools.items():
        if f'"{tool}"' in source or f"'{tool}'" in source or f"[{tool!r}" in source:
            if not shutil.which(tool):
                warnings.append(
                    f"state.py requires `{tool}` but it's not installed. "
                    f"Install: {install_hint}"
                )

    # Check for required env vars
    env_vars_found = []
    for match in __import__("re").finditer(
        r'os\.environ\.get\(["\'](\w+)["\']', source
    ):
        var = match.group(1)
        env_vars_found.append(var)
        if not os.environ.get(var):
            warnings.append(
                f"state.py reads ${var} but it's not set. "
                f"Add it to .env or export it."
            )

    # Import and run
    try:
        spec = importlib.util.spec_from_file_location(
            f"_validate_{rule_id}", str(state_file)
        )
        if spec is None or spec.loader is None:
            return ["state.py: could not load module"]
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:
        warnings.append(f"state.py import error: {type(exc).__name__}: {exc}")
        return warnings

    get_state = getattr(module, "get_state", None)
    if not callable(get_state):
        warnings.append("state.py: missing get_state() function")
        return warnings

    try:
        result = get_state()
    except Exception as exc:
        warnings.append(f"state.py get_state() raised {type(exc).__name__}: {exc}")
        return warnings

    if not isinstance(result, dict):
        warnings.append(f"state.py get_state() returned {type(result).__name__}, expected dict")
    elif not result and env_vars_found:
        # Empty dict + env vars used = likely unconfigured
        missing = [v for v in env_vars_found if not os.environ.get(v)]
        if missing:
            warnings.append(
                f"state.py returned empty dict — likely because "
                f"${', $'.join(missing)} not set."
            )

    return warnings


def _validate_opa_smoke(
    rego_content: str, rule_id: str, state_file: Path, project_dir: Path
) -> list[str]:
    """Smoke test: run OPA eval with a dummy tool call to verify the policy loads."""
    import tempfile

    opa = _opa_binary_path()
    if not opa.exists():
        return []

    # Minimal input that should NOT trigger any deny
    input_doc = {
        "tool": {"name": "__smoke_test__", "arguments": {}},
        "project_dir": str(project_dir),
        "state": {},
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as f:
        json.dump(input_doc, f)
        input_path = f.name

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".rego", delete=False, prefix=f"{rule_id}_smoke_"
    ) as f:
        f.write(rego_content)
        rego_path = f.name

    try:
        result = subprocess.run(
            [str(opa), "eval", "-d", rego_path, "-i", input_path,
             "-f", "json", "data.aegis.deny"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return [f"OPA smoke test failed: {result.stderr.strip()[:200]}"]

        # Parse output — just verify OPA produced valid JSON
        json.loads(result.stdout)
        return []
    except subprocess.TimeoutExpired:
        return ["OPA smoke test: timed out"]
    except (json.JSONDecodeError, OSError) as exc:
        return [f"OPA smoke test error: {exc}"]
    finally:
        os.unlink(input_path)
        os.unlink(rego_path)


def _validate_classifier_schema(data: dict) -> list[str]:
    """Validate classifier.json has the required fields with correct types."""
    warnings: list[str] = []
    if not data.get("system_prompt"):
        warnings.append("classifier.json: missing or empty system_prompt")
    if not isinstance(data.get("check_request", False), bool):
        warnings.append("classifier.json: check_request should be boolean")
    if not isinstance(data.get("check_response", False), bool):
        warnings.append("classifier.json: check_response should be boolean")
    if not data.get("check_request") and not data.get("check_response"):
        warnings.append("classifier.json: neither check_request nor check_response is true")
    if not data.get("deny_reason"):
        warnings.append("classifier.json: missing deny_reason")
    return warnings


def compile_rule(rule: Rule, project_dir: Path) -> dict:
    """Compile a single rule into Rego + state gatherer + optional classifier.

    Returns metadata dict with compilation result.
    """
    from aegis.compiler.tools import TOOL_CATALOG
    prompt = GENERATION_PROMPT.format(
        title=rule.title,
        body=rule.body,
        rule_id=rule.id,
        tool_catalog=TOOL_CATALOG,
    )
    llm_output = _call_llm(prompt)
    rego_content, python_content, classifier_content = _parse_artifacts(llm_output)

    # Validate
    rego_errors = _validate_rego(rego_content, rule.id)
    python_errors = _validate_python(python_content)
    classifier_errors = _validate_classifier(classifier_content)
    errors = rego_errors + python_errors + classifier_errors

    if rego_errors or python_errors:
        # Retry on rego/python errors (classifier errors are less critical)
        retry_prompt = (
            prompt
            + "\n\n## Previous attempt had errors, fix them:\n"
            + "\n".join(errors)
            + "\n\nPrevious rego:\n```rego\n" + rego_content + "\n```"
            + "\n\nPrevious python:\n```python\n" + python_content + "\n```"
            + "\n\nPrevious classifier:\n```json\n" + classifier_content + "\n```"
        )
        llm_output = _call_llm(retry_prompt)
        rego_content, python_content, classifier_content = _parse_artifacts(llm_output)
        rego_errors = _validate_rego(rego_content, rule.id)
        python_errors = _validate_python(python_content)
        classifier_errors = _validate_classifier(classifier_content)
        errors = rego_errors + python_errors + classifier_errors

    # Write artifacts
    out_dir = _compiled_dir(project_dir) / rule.id
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "policy.rego").write_text(rego_content, encoding="utf-8")
    (out_dir / "state.py").write_text(python_content, encoding="utf-8")
    (out_dir / "classifier.json").write_text(classifier_content, encoding="utf-8")

    # Parse classifier to check if enabled
    try:
        classifier_data = json.loads(classifier_content)
        classifier_enabled = classifier_data.get("enabled", False)
    except json.JSONDecodeError:
        classifier_enabled = False

    # ── Post-generation validation ───────────────────────────────────
    warnings = list(errors)  # keep generation errors, add validation warnings

    # 1. State fetcher: dry-run get_state()
    state_result = _validate_state_runtime(out_dir / "state.py", rule.id)
    if state_result:
        warnings.extend(state_result)

    # 2. OPA smoke test: feed a dummy tool call through the policy
    opa_smoke = _validate_opa_smoke(
        rego_content, rule.id, out_dir / "state.py", project_dir
    )
    if opa_smoke:
        warnings.extend(opa_smoke)

    # 3. Classifier schema validation (beyond just valid JSON)
    if classifier_enabled:
        cls_schema = _validate_classifier_schema(classifier_data)
        if cls_schema:
            warnings.extend(cls_schema)

    metadata = {
        "id": rule.id,
        "title": rule.title,
        "body": rule.body,
        "raw": rule.raw,
        "errors": errors,
        "warnings": [w for w in warnings if w not in errors],
        "type": "classifier" if classifier_enabled else "deterministic",
        "rego_file": str(out_dir / "policy.rego"),
        "state_file": str(out_dir / "state.py"),
        "classifier_file": str(out_dir / "classifier.json") if classifier_enabled else None,
    }
    (out_dir / "rule.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )
    return metadata


def compile_all(project_dir: Path) -> list[dict]:
    """Compile all rules from RULES.md.

    Returns list of metadata dicts, one per rule.
    """
    rules_file = find_rules_file(project_dir)
    if not rules_file:
        raise FileNotFoundError(
            f"No RULES.md found in {project_dir} or any parent directory."
        )

    text = rules_file.read_text(encoding="utf-8")
    rules = parse_rules(text)
    if not rules:
        raise ValueError("RULES.md contains no parseable rules.")

    # Clean previous compilation
    compiled = _compiled_dir(project_dir)
    if compiled.exists():
        shutil.rmtree(compiled)
    compiled.mkdir(parents=True, exist_ok=True)

    import time
    t0 = time.monotonic()
    print(f"[aegis] Compiling {len(rules)} rules in parallel...")

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _compile_one(rule: Rule) -> dict:
        try:
            return compile_rule(rule, project_dir)
        except Exception as exc:
            return {
                "id": rule.id,
                "title": rule.title,
                "errors": [str(exc)],
                "type": "error",
            }

    results: list[dict] = [{}] * len(rules)
    det_count = 0
    cls_count = 0

    with ThreadPoolExecutor(max_workers=len(rules)) as pool:
        future_to_idx = {
            pool.submit(_compile_one, rule): i
            for i, rule in enumerate(rules)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            meta = future.result()
            results[idx] = meta
            rule_type = meta.get("type", "deterministic")
            errors = meta.get("errors", [])
            warnings = meta.get("warnings", [])
            status = "FAIL" if rule_type == "error" else ("WARN" if errors else "OK")
            label = {"deterministic": "OPA", "classifier": "POLICY_MODEL"}.get(rule_type, "ERR")
            warn_tag = f" ({len(warnings)} warning{'s' if len(warnings) != 1 else ''})" if warnings else ""
            print(f"  [{status}] {meta.get('title', '?')} [{label}]{warn_tag}")
            if rule_type == "deterministic":
                det_count += 1
            elif rule_type == "classifier":
                cls_count += 1
            for err in errors:
                print(f"       ! {err}")
            for w in warnings:
                print(f"       ~ {w}")

    # Write manifest
    compiled.mkdir(parents=True, exist_ok=True)
    manifest_path = compiled / "manifest.json"
    manifest_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    elapsed = time.monotonic() - t0
    print(f"\n[aegis] Compiled {len(results)} rules in {elapsed:.1f}s -> {compiled}")
    print(f"  {det_count} deterministic (OPA), {cls_count} non-deterministic (POLICY_MODEL)")
    return results
