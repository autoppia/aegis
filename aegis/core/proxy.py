"""HTTP reverse proxy that intercepts OpenAI and Anthropic API requests/responses.

Handles both APIs through a single proxy:
- OpenAI:    POST /v1/chat/completions  (Codex)
- Anthropic: POST /v1/messages          (Claude Code)

Three layers of enforcement:
1. Context injection — injects rules into every request so the LLM is aware
2. POLICY_MODEL classifiers — non-deterministic rules evaluated on user input (REQUEST side)
3. OPA policy evaluation — deterministic rules evaluated on tool calls (RESPONSE side)
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Callable
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from aegis.core.engine import OpaEngine, ToolCall
from aegis.core.policy_model import ClassifierConfig, evaluate as evaluate_classifier

ContextProvider = Callable[[], str | None]

ANTHROPIC_DEFAULT_BASE = "https://api.anthropic.com"


def _gather_context(providers: list[ContextProvider]) -> str | None:
    """Run all providers, return combined text or None."""
    parts: list[str] = []
    for provider in providers:
        try:
            ctx = provider()
            if ctx:
                parts.append(ctx)
        except Exception:
            pass
    return "\n\n".join(parts) if parts else None


class _ProxyHandler(BaseHTTPRequestHandler):
    """Handles proxied requests to upstream APIs."""

    # Set by OpaProxy before server starts
    engine: OpaEngine
    real_base_url: str          # OpenAI upstream
    anthropic_base_url: str     # Anthropic upstream
    notify_callback: object
    context_providers: list[ContextProvider]
    classifiers: list[ClassifierConfig]
    state_getter: object        # callable returning dict, or None

    def log_message(self, format: str, *args: object) -> None:
        pass

    # ── Routing ──────────────────────────────────────────────────────────

    def do_POST(self) -> None:
        path = self.path.rstrip("/")
        if path.endswith("/chat/completions"):
            self._handle_openai()
        elif path.endswith("/messages"):
            self._handle_anthropic()
        else:
            self._passthrough("POST")

    def do_GET(self) -> None:
        self._passthrough("GET")

    def do_PUT(self) -> None:
        self._passthrough("PUT")

    def do_DELETE(self) -> None:
        self._passthrough("DELETE")

    def do_OPTIONS(self) -> None:
        self._passthrough("OPTIONS")

    def do_PATCH(self) -> None:
        self._passthrough("PATCH")

    # ── Upstream URL helpers ─────────────────────────────────────────────

    def _openai_url(self) -> str:
        base = self.real_base_url.rstrip("/")
        path = self.path
        if base.endswith("/v1") and path.startswith("/v1"):
            path = path[3:]
        return base + path

    def _anthropic_url(self) -> str:
        base = self.anthropic_base_url.rstrip("/")
        path = self.path
        # Anthropic base is typically https://api.anthropic.com (no /v1)
        return base + path

    def _forward_headers(self) -> dict[str, str]:
        skip = {"host", "transfer-encoding", "connection"}
        headers = {}
        for key, value in self.headers.items():
            if key.lower() not in skip:
                headers[key] = value
        return headers

    # ── Generic passthrough ──────────────────────────────────────────────

    def _passthrough(self, method: str) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        # Route to correct upstream based on headers
        url = self._route_url()
        req = Request(url, data=body, headers=self._forward_headers(), method=method)

        try:
            with urlopen(req, timeout=300) as resp:
                resp_body = resp.read()
                self.send_response(resp.status)
                for key, value in resp.getheaders():
                    if key.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(key, value)
                self.end_headers()
                self.wfile.write(resp_body)
        except HTTPError as e:
            self.send_response(e.code)
            for key, value in e.headers.items():
                if key.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(e.read())
        except (URLError, OSError) as e:
            self.send_error(502, f"Upstream error: {e}")

    def _route_url(self) -> str:
        """Pick upstream based on whether request looks like Anthropic or OpenAI."""
        if self._is_anthropic_request():
            return self._anthropic_url()
        return self._openai_url()

    def _is_anthropic_request(self) -> bool:
        """Detect Anthropic requests by header or path."""
        if self.headers.get("anthropic-version"):
            return True
        if self.headers.get("x-api-key") and not self.headers.get("Authorization"):
            return True
        return False

    # ── Request-side classification (POLICY_MODEL) ─────────────────────

    def _extract_last_user_message(self, body: dict) -> str | None:
        """Extract the most recent user message from the request."""
        messages = body.get("messages", [])
        for msg in reversed(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    return content
                # Anthropic/OpenAI array-of-blocks format
                if isinstance(content, list):
                    parts = []
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            parts.append(block.get("text", ""))
                        elif isinstance(block, str):
                            parts.append(block)
                    return "\n".join(parts) if parts else None
        return None

    def _run_request_classifiers(self, body: dict) -> str | None:
        """Run POLICY_MODEL classifiers on the latest user message.

        Returns a denial message if any classifier denies, or None if all pass.
        """
        classifiers = [c for c in self.classifiers if c.check_request]
        if not classifiers:
            return None

        user_msg = self._extract_last_user_message(body)
        if not user_msg or not user_msg.strip():
            return None

        # Gather state for classifiers
        state = None
        if callable(self.state_getter):
            try:
                state = self.state_getter()
            except Exception:
                pass

        for classifier in classifiers:
            decision = evaluate_classifier(classifier, user_msg, state)
            if not decision.allowed:
                self._notify_terminal_classifier(classifier, decision.reason)
                return (
                    f"[POLICY] Blocked by rule '{classifier.rule_title}': "
                    f"{decision.reason}"
                )
        return None

    def _notify_terminal_classifier(self, classifier: ClassifierConfig,
                                     reason: str) -> None:
        callback = self.notify_callback
        if not callable(callback):
            return
        msg = (
            f"\033[1;31m[AEGIS] Blocked by POLICY_MODEL "
            f"({classifier.rule_title}): {reason}\033[0m\n"
        )
        try:
            callback(msg)
        except Exception:
            pass

    # ── Read request body ────────────────────────────────────────────────

    def _read_body(self) -> tuple[dict, bytes]:
        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length) if content_length > 0 else b""
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {}
        return body, raw

    # ── Send helpers ─────────────────────────────────────────────────────

    def _send_upstream_response(self, resp, body: bytes) -> None:
        self.send_response(resp.status)
        for key, value in resp.getheaders():
            if key.lower() not in ("transfer-encoding", "connection"):
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _forward_request(self, url: str, body: bytes) -> object:
        """Forward request to upstream, return response object or send error."""
        headers = self._forward_headers()
        headers["Content-Length"] = str(len(body))
        req = Request(url, data=body, headers=headers, method="POST")
        try:
            return urlopen(req, timeout=300)
        except HTTPError as e:
            self.send_response(e.code)
            for key, value in e.headers.items():
                if key.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(e.read())
            return None
        except (URLError, OSError) as e:
            self.send_error(502, f"Upstream error: {e}")
            return None

    # ── Shared policy evaluation ─────────────────────────────────────────

    def _evaluate_tool_calls(
        self, tool_calls: list[ToolCall]
    ) -> list[tuple[ToolCall, list[str]]]:
        denied = []
        for tc in tool_calls:
            decision = self.engine.evaluate(tc)
            if not decision.allowed:
                denied.append((tc, decision.reasons))
        return denied

    def _format_denial(self, denied: list[tuple[ToolCall, list[str]]]) -> str:
        parts = []
        for tc, reasons in denied:
            reason_str = "; ".join(reasons)
            parts.append(
                f"[POLICY] Blocked: {tc.name}({json.dumps(tc.arguments)}) — {reason_str}"
            )
        return "\n".join(parts)

    def _notify_terminal(self, denied: list[tuple[ToolCall, list[str]]]) -> None:
        callback = self.notify_callback
        if not callable(callback):
            return
        for tc, reasons in denied:
            reason_str = "; ".join(reasons)
            msg = f"\033[1;31m[AEGIS] Blocked: {tc.name} — {reason_str}\033[0m\n"
            try:
                callback(msg)
            except Exception:
                pass

    # ═════════════════════════════════════════════════════════════════════
    # OpenAI API handling
    # ═════════════════════════════════════════════════════════════════════

    def _inject_context_openai(self, body: dict) -> dict:
        """Inject context as a system message in the OpenAI messages array."""
        context = _gather_context(self.context_providers)
        if not context:
            return body

        messages = list(body.get("messages", []))

        # Insert after the last system message
        insert_idx = 0
        for i, msg in enumerate(messages):
            if msg.get("role") == "system":
                insert_idx = i + 1

        messages.insert(insert_idx, {"role": "system", "content": context})
        return {**body, "messages": messages}

    def _handle_openai(self) -> None:
        body, _ = self._read_body()

        # REQUEST-side: run POLICY_MODEL classifiers on user input
        denial = self._run_request_classifiers(body)
        if denial:
            self._send_json({
                "id": "aegis-denied",
                "object": "chat.completion",
                "model": body.get("model", ""),
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": denial},
                    "finish_reason": "stop",
                }],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            })
            return

        body = self._inject_context_openai(body)
        raw = json.dumps(body).encode("utf-8")
        is_streaming = body.get("stream", False)

        resp = self._forward_request(self._openai_url(), raw)
        if resp is None:
            return

        if is_streaming:
            self._handle_openai_streaming(resp)
        else:
            self._handle_openai_non_streaming(resp)

    def _handle_openai_non_streaming(self, resp) -> None:
        resp_body = resp.read()
        try:
            data = json.loads(resp_body)
        except json.JSONDecodeError:
            self._send_upstream_response(resp, resp_body)
            return

        tool_calls = self._extract_openai_tool_calls(data)
        if not tool_calls:
            self._send_upstream_response(resp, resp_body)
            return

        denied = self._evaluate_tool_calls(tool_calls)
        if not denied:
            self._send_upstream_response(resp, resp_body)
            return

        denial_text = self._format_denial(denied)
        self._notify_terminal(denied)
        self._send_json({
            "id": data.get("id", ""),
            "object": "chat.completion",
            "model": data.get("model", ""),
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": denial_text},
                "finish_reason": "stop",
            }],
            "usage": data.get("usage", {}),
        })

    def _handle_openai_streaming(self, resp) -> None:
        raw_data = resp.read()
        resp.close()

        events = self._parse_sse(raw_data)
        assembled = self._assemble_openai_stream(events)

        tool_calls = self._extract_openai_tool_calls(assembled)
        if not tool_calls:
            self._send_sse_passthrough(raw_data)
            return

        denied = self._evaluate_tool_calls(tool_calls)
        if not denied:
            self._send_sse_passthrough(raw_data)
            return

        denial_text = self._format_denial(denied)
        self._notify_terminal(denied)
        self._send_openai_denial_sse(assembled, denial_text)

    @staticmethod
    def _extract_openai_tool_calls(data: dict) -> list[ToolCall]:
        tool_calls = []
        for choice in data.get("choices", []):
            msg = choice.get("message", {})
            for tc in msg.get("tool_calls", []):
                func = tc.get("function", {})
                name = func.get("name", "")
                try:
                    args = json.loads(func.get("arguments", "{}"))
                except json.JSONDecodeError:
                    args = {}
                tool_calls.append(ToolCall(name=name, arguments=args))
        return tool_calls

    def _assemble_openai_stream(self, events: list[dict]) -> dict:
        assembled: dict = {
            "id": "",
            "model": "",
            "choices": [{
                "message": {"role": "assistant", "content": None, "tool_calls": []},
                "finish_reason": None,
            }],
        }
        tool_call_map: dict[int, dict] = {}

        for event in events:
            if "id" in event:
                assembled["id"] = event["id"]
            if "model" in event:
                assembled["model"] = event["model"]

            for choice in event.get("choices", []):
                delta = choice.get("delta", {})
                finish = choice.get("finish_reason")
                if finish:
                    assembled["choices"][0]["finish_reason"] = finish

                if "content" in delta and delta["content"] is not None:
                    if assembled["choices"][0]["message"]["content"] is None:
                        assembled["choices"][0]["message"]["content"] = ""
                    assembled["choices"][0]["message"]["content"] += delta["content"]

                for tc_delta in delta.get("tool_calls", []):
                    idx = tc_delta.get("index", 0)
                    if idx not in tool_call_map:
                        tool_call_map[idx] = {
                            "id": tc_delta.get("id", ""),
                            "type": "function",
                            "function": {"name": "", "arguments": ""},
                        }
                    tc = tool_call_map[idx]
                    if tc_delta.get("id"):
                        tc["id"] = tc_delta["id"]
                    func = tc_delta.get("function", {})
                    if func.get("name"):
                        tc["function"]["name"] = func["name"]
                    if func.get("arguments"):
                        tc["function"]["arguments"] += func["arguments"]

        if tool_call_map:
            assembled["choices"][0]["message"]["tool_calls"] = [
                tool_call_map[i] for i in sorted(tool_call_map)
            ]
        else:
            del assembled["choices"][0]["message"]["tool_calls"]

        return assembled

    def _send_openai_denial_sse(self, assembled: dict, denial_text: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        chunk = {
            "id": assembled.get("id", ""),
            "object": "chat.completion.chunk",
            "model": assembled.get("model", ""),
            "choices": [{
                "index": 0,
                "delta": {"role": "assistant", "content": denial_text},
                "finish_reason": None,
            }],
        }
        self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))

        done_chunk = {
            "id": assembled.get("id", ""),
            "object": "chat.completion.chunk",
            "model": assembled.get("model", ""),
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop",
            }],
        }
        self.wfile.write(f"data: {json.dumps(done_chunk)}\n\n".encode("utf-8"))
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    # ═════════════════════════════════════════════════════════════════════
    # Anthropic API handling
    # ═════════════════════════════════════════════════════════════════════

    def _inject_context_anthropic(self, body: dict) -> dict:
        """Inject context into the Anthropic `system` field.

        Anthropic system can be:
        - absent → set it
        - a string → wrap in array, append our block
        - an array of content blocks → append our block
        """
        context = _gather_context(self.context_providers)
        if not context:
            return body

        context_block = {"type": "text", "text": context}

        system = body.get("system")
        if system is None:
            new_system = [context_block]
        elif isinstance(system, str):
            new_system = [
                {"type": "text", "text": system},
                context_block,
            ]
        elif isinstance(system, list):
            new_system = list(system) + [context_block]
        else:
            new_system = [context_block]

        return {**body, "system": new_system}

    def _handle_anthropic(self) -> None:
        body, _ = self._read_body()

        # REQUEST-side: run POLICY_MODEL classifiers on user input
        denial = self._run_request_classifiers(body)
        if denial:
            self._send_json({
                "id": "aegis-denied",
                "type": "message",
                "role": "assistant",
                "model": body.get("model", ""),
                "content": [{"type": "text", "text": denial}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 0, "output_tokens": 0},
            })
            return

        body = self._inject_context_anthropic(body)
        raw = json.dumps(body).encode("utf-8")
        is_streaming = body.get("stream", False)

        resp = self._forward_request(self._anthropic_url(), raw)
        if resp is None:
            return

        if is_streaming:
            self._handle_anthropic_streaming(resp)
        else:
            self._handle_anthropic_non_streaming(resp)

    def _handle_anthropic_non_streaming(self, resp) -> None:
        resp_body = resp.read()
        try:
            data = json.loads(resp_body)
        except json.JSONDecodeError:
            self._send_upstream_response(resp, resp_body)
            return

        tool_calls = self._extract_anthropic_tool_calls(data)
        if not tool_calls:
            self._send_upstream_response(resp, resp_body)
            return

        denied = self._evaluate_tool_calls(tool_calls)
        if not denied:
            self._send_upstream_response(resp, resp_body)
            return

        denial_text = self._format_denial(denied)
        self._notify_terminal(denied)
        self._send_json({
            "id": data.get("id", ""),
            "type": "message",
            "role": "assistant",
            "model": data.get("model", ""),
            "content": [{"type": "text", "text": denial_text}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": data.get("usage", {"input_tokens": 0, "output_tokens": 0}),
        })

    def _handle_anthropic_streaming(self, resp) -> None:
        raw_data = resp.read()
        resp.close()

        events = self._parse_anthropic_sse(raw_data)
        assembled = self._assemble_anthropic_stream(events)

        tool_calls = self._extract_anthropic_tool_calls(assembled)
        if not tool_calls:
            self._send_sse_passthrough(raw_data)
            return

        denied = self._evaluate_tool_calls(tool_calls)
        if not denied:
            self._send_sse_passthrough(raw_data)
            return

        denial_text = self._format_denial(denied)
        self._notify_terminal(denied)
        self._send_anthropic_denial_sse(assembled, denial_text)

    @staticmethod
    def _extract_anthropic_tool_calls(data: dict) -> list[ToolCall]:
        """Extract tool_use blocks from Anthropic response content."""
        tool_calls = []
        for block in data.get("content", []):
            if block.get("type") == "tool_use":
                tool_calls.append(ToolCall(
                    name=block.get("name", ""),
                    arguments=block.get("input", {}),
                ))
        return tool_calls

    @staticmethod
    def _parse_anthropic_sse(raw: bytes) -> list[dict]:
        """Parse Anthropic SSE stream into event dicts.

        Anthropic SSE has `event:` lines followed by `data:` lines.
        """
        events = []
        text = raw.decode("utf-8", errors="replace")
        current_event_type = None

        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("event: "):
                current_event_type = line[7:]
            elif line.startswith("data: "):
                payload = line[6:]
                try:
                    data = json.loads(payload)
                    data["_event_type"] = current_event_type
                    events.append(data)
                except json.JSONDecodeError:
                    pass
        return events

    @staticmethod
    def _assemble_anthropic_stream(events: list[dict]) -> dict:
        """Reconstruct a complete Anthropic response from SSE events."""
        assembled: dict = {
            "id": "",
            "type": "message",
            "role": "assistant",
            "model": "",
            "content": [],
            "stop_reason": None,
            "usage": {"input_tokens": 0, "output_tokens": 0},
        }

        # Track content blocks by index
        blocks: dict[int, dict] = {}

        for event in events:
            etype = event.get("_event_type", "")

            if etype == "message_start":
                msg = event.get("message", {})
                assembled["id"] = msg.get("id", assembled["id"])
                assembled["model"] = msg.get("model", assembled["model"])
                usage = msg.get("usage", {})
                if usage:
                    assembled["usage"]["input_tokens"] = usage.get(
                        "input_tokens", 0
                    )

            elif etype == "content_block_start":
                idx = event.get("index", 0)
                block = event.get("content_block", {})
                blocks[idx] = dict(block)
                # For tool_use, initialize input as empty string to accumulate JSON
                if block.get("type") == "tool_use":
                    blocks[idx]["_input_json"] = ""

            elif etype == "content_block_delta":
                idx = event.get("index", 0)
                delta = event.get("delta", {})
                if idx in blocks:
                    if delta.get("type") == "text_delta":
                        blocks[idx].setdefault("text", "")
                        blocks[idx]["text"] += delta.get("text", "")
                    elif delta.get("type") == "input_json_delta":
                        blocks[idx]["_input_json"] += delta.get(
                            "partial_json", ""
                        )

            elif etype == "content_block_stop":
                idx = event.get("index", 0)
                if idx in blocks and blocks[idx].get("type") == "tool_use":
                    raw_json = blocks[idx].pop("_input_json", "")
                    try:
                        blocks[idx]["input"] = json.loads(raw_json) if raw_json else {}
                    except json.JSONDecodeError:
                        blocks[idx]["input"] = {}

            elif etype == "message_delta":
                delta = event.get("delta", {})
                if "stop_reason" in delta:
                    assembled["stop_reason"] = delta["stop_reason"]
                usage = event.get("usage", {})
                if usage:
                    assembled["usage"]["output_tokens"] = usage.get(
                        "output_tokens", 0
                    )

        assembled["content"] = [blocks[i] for i in sorted(blocks)]
        return assembled

    def _send_anthropic_denial_sse(self, assembled: dict, denial_text: str) -> None:
        """Send a denial as a synthetic Anthropic SSE stream."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        msg_id = assembled.get("id", "msg_denied")
        model = assembled.get("model", "")

        # message_start
        self._write_sse("message_start", {
            "type": "message_start",
            "message": {
                "id": msg_id,
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [],
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": 0, "output_tokens": 0},
            },
        })

        # content_block_start
        self._write_sse("content_block_start", {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""},
        })

        # content_block_delta with the denial text
        self._write_sse("content_block_delta", {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": denial_text},
        })

        # content_block_stop
        self._write_sse("content_block_stop", {
            "type": "content_block_stop",
            "index": 0,
        })

        # message_delta
        self._write_sse("message_delta", {
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": None},
            "usage": {"output_tokens": len(denial_text)},
        })

        # message_stop
        self._write_sse("message_stop", {"type": "message_stop"})
        self.wfile.flush()

    def _write_sse(self, event_type: str, data: dict) -> None:
        self.wfile.write(f"event: {event_type}\n".encode("utf-8"))
        self.wfile.write(f"data: {json.dumps(data)}\n\n".encode("utf-8"))

    # ── Shared SSE helpers ───────────────────────────────────────────────

    @staticmethod
    def _parse_sse(raw: bytes) -> list[dict]:
        """Parse OpenAI-style SSE (data-only, no event: lines)."""
        events = []
        text = raw.decode("utf-8", errors="replace")
        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("data: "):
                payload = line[6:]
                if payload == "[DONE]":
                    continue
                try:
                    events.append(json.loads(payload))
                except json.JSONDecodeError:
                    pass
        return events

    def _send_sse_passthrough(self, raw_data: bytes) -> None:
        """Replay an SSE stream unchanged."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(raw_data)


class OpaProxy:
    """Local reverse proxy — context injection, POLICY_MODEL classifiers, OPA enforcement.

    Handles both OpenAI and Anthropic APIs through a single port.
    """

    def __init__(
        self,
        engine: OpaEngine,
        real_base_url: str,
        anthropic_base_url: str = ANTHROPIC_DEFAULT_BASE,
        notify_callback: object = None,
        context_providers: list[ContextProvider] | None = None,
        classifiers: list[ClassifierConfig] | None = None,
        state_getter: object = None,
    ) -> None:
        self.engine = engine
        self.real_base_url = real_base_url
        self.anthropic_base_url = anthropic_base_url
        self.notify_callback = notify_callback
        self.context_providers: list[ContextProvider] = context_providers or []
        self.classifiers: list[ClassifierConfig] = classifiers or []
        self.state_getter = state_getter
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int | None = None

    def start(self) -> int:
        """Start the proxy on a random port. Returns the port."""
        handler_class = type(
            "_BoundHandler",
            (_ProxyHandler,),
            {
                "engine": self.engine,
                "real_base_url": self.real_base_url,
                "anthropic_base_url": self.anthropic_base_url,
                "notify_callback": self.notify_callback,
                "context_providers": self.context_providers,
                "classifiers": self.classifiers,
                "state_getter": self.state_getter,
            },
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        self.port = sock.getsockname()[1]
        sock.close()

        self._server = HTTPServer(("127.0.0.1", self.port), handler_class)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="aegis-proxy",
        )
        self._thread.start()
        return self.port

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
