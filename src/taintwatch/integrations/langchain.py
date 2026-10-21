"""LangChain integration: Information-Flow Control callback handler."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from taintwatch.guard import Guard, PolicyViolation
from taintwatch.labels import Confidentiality, Integrity, Label
from taintwatch.spans.guard_ext import derive_text, ingest_text
from taintwatch.spans.tstr import TStr
from taintwatch.tainted import Labeled


@dataclass(frozen=True, slots=True)
class LangChainToolExecution:
    tool_name: str
    input_str: str
    run_id: str = ""


class TaintwatchLangChainHandler:
    """Callback and enforcement handler for LangChain agents and chains."""

    def __init__(self, guard: Guard) -> None:
        self._guard = guard
        self._context_nodes: list[Labeled[TStr]] = []
        self._history: list[LangChainToolExecution] = []

    @property
    def guard(self) -> Guard:
        return self._guard

    @property
    def history(self) -> tuple[LangChainToolExecution, ...]:
        return tuple(self._history)

    def ingest_document(
        self,
        content: str,
        *,
        source: str = "retriever",
        integrity: Integrity = Integrity.UNTRUSTED,
        confidentiality: Confidentiality = Confidentiality.PUBLIC,
    ) -> Labeled[TStr]:
        """Ingest retrieved documents (RAG) or web pages as untrusted context."""
        node = ingest_text(
            self._guard,
            content,
            source=source,
            integrity=integrity,
            confidentiality=confidentiality,
        )
        self._context_nodes.append(node)
        return node

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Called before a LangChain tool executes. Verifies against security policy."""
        tool_name = serialized.get("name", "tool")
        self._history.append(LangChainToolExecution(tool_name, input_str, run_id))

        parents = [
            n
            for n in self._context_nodes
            if input_str in n.value.text or n.value.text in input_str
        ]
        if parents:
            parent_label = Label.join_all(p.label for p in parents)
            tval = TStr.of(input_str, parent_label)
            labeled_arg = derive_text(
                self._guard, tval, parents, f"langchain input to {tool_name}"
            )
        else:
            tval = TStr.of(input_str)
            labeled_arg = self._guard.ingest(tval, source="agent_thought", integrity=Integrity.USER)

        verdict = self._guard.check(tool_name, {"input": labeled_arg})
        if not verdict.allowed:
            raise PolicyViolation(tool_name, verdict)
