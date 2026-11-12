"""Bridge between AgentDojo and MCP Guard.

AgentDojo tools are Python functions that act on an in-memory environment.
To measure the gateway, every tool call has to travel through it as a real
MCP ``tools/call``:

    AgentDojo agent
        -> GatewayToolsExecutor   (this file; replaces AgentDojo's ToolsExecutor)
        -> MCP Guard              (the Go gateway under test)
        -> BridgeServer           (this file; an MCP server over Streamable HTTP)
        -> AgentDojo tool function, acting on the task's environment

The bridge server and the executor live in the same Python process, so the
server runs each call against the very environment object AgentDojo will
later inspect to score the task.

The server speaks the subset of MCP Streamable HTTP that tool calls need
(initialize, ping, tools/list, tools/call, notifications; JSON responses),
using only the standard library. It is a test fixture, not a general MCP
server.
"""

from __future__ import annotations

import json
import re
import threading
import urllib.error
import urllib.request
from ast import literal_eval
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionReturnType, FunctionsRuntime
from agentdojo.types import (
    ChatAssistantMessage,
    ChatMessage,
    ChatToolResultMessage,
    text_content_block_from_string,
)

QUARANTINE_MARK = "[MCP Guard] The output of tool"
DENIAL_MARK = "Denied by MCP Guard policy"


def squash(text: str) -> str:
    """Reduces text to its lower-case letters and digits, so that an injection
    string can still be found in a tool result after YAML or JSON has folded,
    quoted and escaped it."""
    text = re.sub(r"\\[a-zA-Z]", " ", text)  # literal \n, \t ... left by serialisers
    return re.sub(r"[^a-z0-9]+", "", text.lower())


@dataclass
class CallRecord:
    """What happened to one tool call, as seen from both ends of the gateway."""

    tool: str
    reached_server: bool = False  # the bridge server executed it
    result_injected: bool = False  # the real result contained an injection string
    denied: bool = False  # the gateway refused the call
    quarantined: bool = False  # the gateway withheld the result


@dataclass
class BridgeState:
    """The task the bridge server is currently serving. Set by the executor
    immediately before each call; calls are strictly sequential."""

    runtime: FunctionsRuntime | None = None
    env: Env | None = None
    formatter: Callable[[FunctionReturnType], str] = tool_result_to_str
    injections: tuple[str, ...] = ()  # squash()-ed injection strings for the current task
    current: CallRecord | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state: BridgeState  # set on the subclass by BridgeServer

    def log_message(self, *_args) -> None:  # keep benchmark output readable
        pass

    def _send(self, status: int, body: dict | None) -> None:
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        if data:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # no server-initiated stream
        self._send(405, None)

    def do_DELETE(self) -> None:
        self._send(405, None)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        try:
            msg = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            return
        if not isinstance(msg, dict) or "method" not in msg:
            self._send(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}})
            return

        method, msg_id, params = msg["method"], msg.get("id"), msg.get("params") or {}
        if msg_id is None:  # notification
            self._send(202, None)
            return

        def ok(result: dict) -> None:
            self._send(200, {"jsonrpc": "2.0", "id": msg_id, "result": result})

        if method == "initialize":
            ok(
                {
                    "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "agentdojo-bridge", "version": "0.1.0"},
                }
            )
        elif method == "ping":
            ok({})
        elif method == "tools/list":
            ok({"tools": self._tools()})
        elif method == "tools/call":
            ok(self._call(params.get("name", ""), params.get("arguments") or {}))
        else:
            self._send(404, {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "method not found"}})

    def _tools(self) -> list[dict]:
        runtime = self.state.runtime
        if runtime is None:
            return []
        return [
            {"name": f.name, "description": f.description, "inputSchema": f.parameters.model_json_schema()}
            for f in runtime.functions.values()
        ]

    def _call(self, name: str, arguments: dict) -> dict:
        state = self.state
        with state.lock:
            if state.runtime is None:
                return {"content": [{"type": "text", "text": "bridge has no active task"}], "isError": True}
            result, error = state.runtime.run_function(state.env, name, arguments)
            text = error if error is not None else state.formatter(result)
            if state.current is not None:
                state.current.reached_server = True
                squashed = squash(text)
                state.current.result_injected = any(inj and inj in squashed for inj in state.injections)
        return {"content": [{"type": "text", "text": text}], "isError": error is not None}


class BridgeServer:
    """The MCP server in front of AgentDojo's tools. Listens on 127.0.0.1."""

    def __init__(self) -> None:
        self.state = BridgeState()
        handler = type("Handler", (_Handler,), {"state": self.state})
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}/mcp"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


class GatewayError(RuntimeError):
    """The gateway answered in a way that means the run itself is broken
    (bad token, gateway down), as opposed to a tool call being refused."""


class GatewayClient:
    """Sends tool calls to MCP Guard as MCP ``tools/call`` requests."""

    def __init__(self, endpoint: str, timeout: float = 120.0) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        self.token = ""
        self._next_id = 0

    def call_tool(self, name: str, arguments: dict) -> tuple[str, bool]:
        """Returns (text, is_error) from the tool result the gateway sent back."""
        self._next_id += 1
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self._next_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        ).encode()
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {self.token}",
                "MCP-Protocol-Version": "2025-06-18",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as e:
            raise GatewayError(f"gateway returned HTTP {e.code} for {name}: {e.read()[:300]!r}") from e
        except urllib.error.URLError as e:
            raise GatewayError(f"gateway unreachable: {e}") from e

        if "error" in payload:
            raise GatewayError(f"gateway returned a JSON-RPC error for {name}: {payload['error']}")
        result = payload["result"]
        text = "\n".join(block.get("text", "") for block in result.get("content", []) if block.get("type") == "text")
        return text, bool(result.get("isError"))


class GatewayToolsExecutor(BasePipelineElement):
    """AgentDojo's ToolsExecutor, with the function call replaced by a round
    trip through MCP Guard. Everything else follows the original so results
    stay comparable with published AgentDojo runs."""

    def __init__(
        self,
        client: GatewayClient,
        state: BridgeState,
        tool_output_formatter: Callable[[FunctionReturnType], str] = tool_result_to_str,
    ) -> None:
        self.client = client
        self.state = state
        self.output_formatter = tool_output_formatter
        self.calls: list[CallRecord] = []

    def execute(self, runtime: FunctionsRuntime, env: Env, tool_call: FunctionCall) -> tuple[str, str | None]:
        """Runs one tool call through the gateway. Returns (content, error)
        with the same meaning as AgentDojo's own executor."""
        if any(isinstance(v, FunctionCall) for v in tool_call.args.values()):
            raise GatewayError(f"{tool_call.function}: nested function calls cannot be sent over MCP")

        record = CallRecord(tool=tool_call.function)
        self.calls.append(record)
        self.state.runtime, self.state.env = runtime, env
        self.state.formatter, self.state.current = self.output_formatter, record
        try:
            text, is_error = self.client.call_tool(tool_call.function, dict(tool_call.args))
        finally:
            self.state.current = None

        record.quarantined = is_error and text.startswith(QUARANTINE_MARK)
        record.denied = is_error and text.startswith(DENIAL_MARK)
        if is_error:
            return "", text
        return text, None

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if len(messages) == 0 or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
            return query, runtime, env, messages, extra_args

        results = []
        for tool_call in messages[-1]["tool_calls"]:
            # Same input normalisation as AgentDojo's ToolsExecutor.
            for arg_k, arg_v in tool_call.args.items():
                if isinstance(arg_v, str) and is_string_list(arg_v):
                    tool_call.args[arg_k] = literal_eval(arg_v)
            content, error = self.execute(runtime, env, tool_call)
            results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(content)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *results], extra_args


class GatewayGroundTruth(BasePipelineElement):
    """A scripted agent with no model: it issues the task's ground-truth tool
    calls through the gateway and ignores what comes back.

    It cannot be attacked, so it says nothing about attack success. It is
    used to check the plumbing and to measure what the gateway does to tool
    traffic (denials, quarantines, latency) without spending on a model.
    """

    def __init__(self, task: BaseUserTask | BaseInjectionTask, executor: GatewayToolsExecutor) -> None:
        self._task = task
        self._executor = executor

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        new_messages: list[ChatMessage] = []
        for tool_call in self._task.ground_truth(env):
            new_messages.append(
                ChatAssistantMessage(
                    role="assistant", tool_calls=[tool_call], content=[text_content_block_from_string("")]
                )
            )
            content, error = self._executor.execute(runtime, env, tool_call)
            new_messages.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(content)],
                    tool_call=tool_call,
                    tool_call_id=None,
                    error=error,
                )
            )
        new_messages.append(
            ChatAssistantMessage(
                role="assistant",
                content=[text_content_block_from_string(self._task.GROUND_TRUTH_OUTPUT)],
                tool_calls=None,
            )
        )
        return query, runtime, env, [*messages, *new_messages], extra_args
