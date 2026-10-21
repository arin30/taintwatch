"""Model Context Protocol (MCP) Information-Flow Control Guard.

Provides zero-trust mediation for MCP client-server communication, preventing
untrusted MCP resources and tool outputs from hijacking sensitive MCP tools
(such as filesystem modification, database access, or shell execution).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from taintwatch.guard import Guard, PolicyViolation
from taintwatch.labels import Confidentiality, Integrity, Label
from taintwatch.spans.guard_ext import derive_text, ingest_text
from taintwatch.spans.tstr import TStr
from taintwatch.tainted import Labeled


@dataclass(frozen=True, slots=True)
class MCPToolCall:
    """An intercepted MCP CallToolRequest."""

    name: str
    arguments: Mapping[str, Any]
    server_id: str = "default"


@dataclass(frozen=True, slots=True)
class MCPToolResult:
    """An intercepted MCP CallToolResult."""

    content: list[dict[str, Any]]
    is_error: bool = False
    server_id: str = "default"


class MCPGuard:
    """Guards Model Context Protocol (MCP) tool execution and resource reads."""

    def __init__(
        self,
        guard: Guard,
        *,
        default_server_id: str = "mcp",
    ) -> None:
        self._guard = guard
        self._default_server_id = default_server_id
        self._context_nodes: list[Labeled[TStr]] = []

    @property
    def guard(self) -> Guard:
        return self._guard

    def ingest_resource(
        self,
        uri: str,
        content: str,
        *,
        integrity: Integrity = Integrity.UNTRUSTED,
        confidentiality: Confidentiality = Confidentiality.PUBLIC,
    ) -> Labeled[TStr]:
        """Ingest external content read from an MCP resource (e.g. mcp://search, file://)."""
        labeled = ingest_text(
            self._guard,
            content,
            source=f"mcp:resource:{uri}",
            integrity=integrity,
            confidentiality=confidentiality,
        )
        self._context_nodes.append(labeled)
        return labeled

    def execute_tool(
        self,
        call: MCPToolCall,
        handler: Callable[[Mapping[str, Any]], MCPToolResult],
        *,
        output_integrity: Integrity = Integrity.TOOL_OUTPUT,
    ) -> MCPToolResult:
        """Gate an MCP tool call against the security policy before executing it."""
        # 1. Prepare labeled arguments
        labeled_args: dict[str, Labeled[Any]] = {}
        for arg_name, arg_val in call.arguments.items():
            if isinstance(arg_val, str):
                parents = [
                    n
                    for n in self._context_nodes
                    if arg_val in n.value.text or n.value.text in arg_val
                ]
                if parents:
                    parent_label = Label.join_all(p.label for p in parents)
                    tval = TStr.of(arg_val, parent_label)
                    labeled_args[arg_name] = derive_text(
                        self._guard, tval, parents, f"mcp argument {arg_name}"
                    )
                else:
                    tval = TStr.of(arg_val)
                    labeled_args[arg_name] = self._guard.ingest(
                        tval,
                        source="agent",
                        integrity=Integrity.USER,
                    )
            else:
                labeled_args[arg_name] = self._guard.ingest(
                    arg_val,
                    source="agent",
                    integrity=Integrity.USER,
                )

        # 2. Gate through the TaintWatch guard
        tool_qual_name = f"mcp.{call.server_id}.{call.name}"
        # Also check without prefix for standard policy rules (e.g. fs.write)
        target_tool = call.name if "." in call.name else tool_qual_name

        def _run_handler(**kwargs: Any) -> MCPToolResult:
            # Unpack labeled arguments back to raw values for the handler
            raw_kwargs = {k: getattr(v, "value", v) for k, v in kwargs.items()}
            return handler(raw_kwargs)

        try:
            labeled_result = self._guard.call(
                target_tool,
                labeled_args,
                _run_handler,
                output_integrity=output_integrity,
            )
        except PolicyViolation:
            raise

        result: MCPToolResult = labeled_result.value

        # 3. Label tool output and register into context memory
        for idx, item in enumerate(result.content):
            text_val = item.get("text", "")
            if text_val:
                out_node = ingest_text(
                    self._guard,
                    text_val,
                    source=f"mcp:output:{call.name}:{idx}",
                    integrity=output_integrity,
                )
                self._context_nodes.append(out_node)

        return result
