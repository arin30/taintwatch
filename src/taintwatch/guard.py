"""The runtime guard: ingest data, derive new data, and gate tool calls."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from taintwatch.errors import TaintwatchError
from taintwatch.labels import Confidentiality, Integrity, Label
from taintwatch.policy import Action, Policy, Verdict
from taintwatch.provenance import NodeKind, ProvenanceGraph
from taintwatch.tainted import Labeled

T = TypeVar("T")
R = TypeVar("R")

ConfirmFn = Callable[[str, Verdict], bool]


class PolicyViolation(TaintwatchError):
    """A tool call was refused by policy."""

    def __init__(self, tool: str, verdict: Verdict) -> None:
        super().__init__(f"tool call {tool!r} blocked: {verdict.explain()}")
        self.tool = tool
        self.verdict = verdict


@dataclass(frozen=True, slots=True)
class AuditRecord:
    tool: str
    arg_nodes: tuple[tuple[str, str], ...]
    verdict: Verdict
    evasions: tuple[str, ...] = ()


class Guard:
    def __init__(
        self,
        policy: Policy,
        graph: ProvenanceGraph | None = None,
        confirm: ConfirmFn | None = None,
        *,
        canonicalize: bool = False,
    ) -> None:
        self._policy = policy
        self._graph = graph if graph is not None else ProvenanceGraph()
        self._confirm = confirm
        self._canonicalize = canonicalize
        self._audit: list[AuditRecord] = []

    @property
    def graph(self) -> ProvenanceGraph:
        return self._graph

    @property
    def audit(self) -> tuple[AuditRecord, ...]:
        return tuple(self._audit)

    def ingest(
        self,
        value: T,
        *,
        source: str,
        integrity: Integrity,
        confidentiality: Confidentiality = Confidentiality.PUBLIC,
    ) -> Labeled[T]:
        """Register data entering the agent from an external source."""
        label = Label(integrity, confidentiality, frozenset({source}))
        node = self._graph.add(NodeKind.SOURCE, label, source)
        return Labeled(value, node.id, label)

    def derive(
        self, value: T, parents: Sequence[Labeled[Any]], description: str
    ) -> Labeled[T]:
        """Register a value computed from other labeled values."""
        label = Label.join_all(p.label for p in parents)
        node = self._graph.add(
            NodeKind.DERIVED, label, description, tuple(p.node_id for p in parents)
        )
        return Labeled(value, node.id, label)

    def _prepare_args(
        self, args: Mapping[str, Labeled[Any]]
    ) -> tuple[dict[str, Labeled[Any]], tuple[str, ...]]:
        if not self._canonicalize:
            return dict(args), ()

        from taintwatch.spans.canonical import detect_evasion
        from taintwatch.spans.tstr import TStr

        prepared: dict[str, Labeled[Any]] = {}
        detected_evasions: list[str] = []

        for name, labeled in args.items():
            val = labeled.value
            if isinstance(val, TStr):
                report = detect_evasion(val)
                if report.has_evasion:
                    detected_evasions.extend(report.techniques)
                    canonical_val = report.canonical
                    node = self._graph.add(
                        NodeKind.DERIVED,
                        canonical_val.overall_label(),
                        f"canonicalized {name}",
                        (labeled.node_id,),
                    )
                    prepared[name] = Labeled(
                        canonical_val, node.id, canonical_val.overall_label()
                    )
                else:
                    prepared[name] = labeled
            elif isinstance(val, str):
                tval = TStr.of(val, labeled.label)
                report = detect_evasion(tval)
                if report.has_evasion:
                    detected_evasions.extend(report.techniques)
                    canonical_val = report.canonical
                    node = self._graph.add(
                        NodeKind.DERIVED,
                        canonical_val.overall_label(),
                        f"canonicalized {name}",
                        (labeled.node_id,),
                    )
                    prepared[name] = Labeled(
                        str(canonical_val), node.id, canonical_val.overall_label()
                    )
                else:
                    prepared[name] = labeled
            else:
                prepared[name] = labeled

        return prepared, tuple(detected_evasions)

    def check(self, tool: str, args: Mapping[str, Labeled[Any]]) -> Verdict:
        """Evaluate a prospective tool call and record it in the audit log."""
        prepared_args, evasions = self._prepare_args(args)
        verdict = self._policy.evaluate(tool, prepared_args)
        arg_nodes = tuple((name, labeled.node_id) for name, labeled in prepared_args.items())
        self._audit.append(AuditRecord(tool, arg_nodes, verdict, evasions))
        return verdict

    def call(
        self,
        tool: str,
        args: Mapping[str, Labeled[Any]],
        fn: Callable[..., R],
        *,
        output_integrity: Integrity = Integrity.TOOL_OUTPUT,
    ) -> Labeled[R]:
        """Run ``fn`` only if policy permits; label and track its result."""
        prepared_args, evasions = self._prepare_args(args)
        verdict = self._policy.evaluate(tool, prepared_args)
        arg_nodes = tuple((name, labeled.node_id) for name, labeled in prepared_args.items())
        self._audit.append(AuditRecord(tool, arg_nodes, verdict, evasions))

        if verdict.action is Action.BLOCK:
            raise PolicyViolation(tool, verdict)
        if verdict.action is Action.CONFIRM and (
            self._confirm is None or not self._confirm(tool, verdict)
        ):
            raise PolicyViolation(tool, verdict)

        result = fn(**{name: labeled.value for name, labeled in prepared_args.items()})
        base_label = Label.join_all(a.label for a in prepared_args.values())
        label = base_label.cap_integrity(output_integrity)
        node = self._graph.add(
            NodeKind.TOOL_RESULT,
            label,
            f"result of {tool}",
            tuple(a.node_id for a in prepared_args.values()),
        )
        return Labeled(result, node.id, label)
