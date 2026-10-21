"""OpenAI Function & Tool Calling Information-Flow Control Guard."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from taintwatch.guard import Guard, PolicyViolation
from taintwatch.labels import Confidentiality, Integrity, Label
from taintwatch.spans.guard_ext import derive_text, ingest_text
from taintwatch.spans.tstr import TStr
from taintwatch.tainted import Labeled


@dataclass(frozen=True, slots=True)
class OpenAIToolCall:
    """An intercepted OpenAI Tool Call."""

    id: str
    function_name: str
    arguments_json: str


class OpenAIToolGuard:
    """Guards OpenAI Function/Tool Calls against unauthorized information flow."""

    def __init__(self, guard: Guard) -> None:
        self._guard = guard
        self._context_nodes: list[Labeled[TStr]] = []

    @property
    def guard(self) -> Guard:
        return self._guard

    def ingest_untrusted_input(
        self,
        text: str,
        *,
        source: str = "user_prompt",
        integrity: Integrity = Integrity.UNTRUSTED,
        confidentiality: Confidentiality = Confidentiality.PUBLIC,
    ) -> Labeled[TStr]:
        """Ingest text from user prompts, RAG retrieval chunks, or third-party web content."""
        node = ingest_text(
            self._guard,
            text,
            source=source,
            integrity=integrity,
            confidentiality=confidentiality,
        )
        self._context_nodes.append(node)
        return node

    def execute_tool_call(
        self,
        call: OpenAIToolCall,
        handler: Callable[..., Any],
        *,
        output_integrity: Integrity = Integrity.TOOL_OUTPUT,
    ) -> Any:
        """Parse arguments, label their origin against context, and gate execution."""
        try:
            raw_args: dict[str, Any] = json.loads(call.arguments_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in tool arguments: {exc}") from exc

        labeled_args: dict[str, Labeled[Any]] = {}
        for name, val in raw_args.items():
            if isinstance(val, str):
                parents = [
                    n
                    for n in self._context_nodes
                    if val in n.value.text or n.value.text in val
                ]
                if parents:
                    parent_label = Label.join_all(p.label for p in parents)
                    tval = TStr.of(val, parent_label)
                    labeled_args[name] = derive_text(
                        self._guard, tval, parents, f"openai tool argument {name}"
                    )
                else:
                    tval = TStr.of(val)
                    labeled_args[name] = self._guard.ingest(
                        tval,
                        source="llm_generated",
                        integrity=Integrity.USER,
                    )
            else:
                labeled_args[name] = self._guard.ingest(
                    val,
                    source="llm_generated",
                    integrity=Integrity.USER,
                )

        def _runner(**kwargs: Any) -> Any:
            clean_kwargs = {k: getattr(v, "value", v) for k, v in kwargs.items()}
            return handler(**clean_kwargs)

        try:
            return self._guard.call(
                call.function_name,
                labeled_args,
                _runner,
                output_integrity=output_integrity,
            ).value
        except PolicyViolation:
            raise
