"""Declarative policies: which labeled data may flow into which tool arguments."""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum, IntEnum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, TypeVar

from taintwatch.errors import PolicyError
from taintwatch.labels import Confidentiality, Integrity, Label
from taintwatch.tainted import Labeled

E = TypeVar("E", bound=Enum)


class Action(IntEnum):
    """Ordered by severity so the strictest violated rule wins."""

    ALLOW = 0
    CONFIRM = 1
    BLOCK = 2


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    tool: str
    arg: str = "*"
    min_integrity: Integrity | None = None
    max_confidentiality: Confidentiality | None = None
    action: Action = Action.BLOCK
    reason: str = ""

    def applies_to(self, tool: str, arg: str) -> bool:
        return fnmatchcase(tool, self.tool) and fnmatchcase(arg, self.arg)

    def violated_by(self, label: Label) -> bool:
        if self.min_integrity is not None and label.integrity < self.min_integrity:
            return True
        return (
            self.max_confidentiality is not None
            and label.confidentiality > self.max_confidentiality
        )


@dataclass(frozen=True, slots=True)
class Violation:
    rule: Rule
    arg: str
    label: Label


@dataclass(frozen=True, slots=True)
class Verdict:
    action: Action
    violations: tuple[Violation, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.action is Action.ALLOW

    def explain(self) -> str:
        if not self.violations:
            return "no policy violations"
        return "; ".join(
            f"{v.rule.name} (arg {v.arg!r}: integrity={v.label.integrity.name}, "
            f"confidentiality={v.label.confidentiality.name})"
            for v in self.violations
        )


_KNOWN_FIELDS = frozenset(
    {"name", "tool", "arg", "min_integrity", "max_confidentiality", "action", "reason"}
)
_DECLASSIFICATION_FIELDS = frozenset(
    {"name", "tool", "arg", "target_integrity", "target_confidentiality", "pattern", "reason"}
)


@dataclass(frozen=True, slots=True)
class DeclassificationRule:
    """Formal rule allowing bounded sanitization and label adjustment."""

    name: str
    tool: str
    arg: str = "*"
    target_integrity: Integrity | None = None
    target_confidentiality: Confidentiality | None = None
    pattern: str = ""
    reason: str = ""

    def applies_to(self, tool: str, arg: str) -> bool:
        return fnmatchcase(tool, self.tool) and fnmatchcase(arg, self.arg)

    def validates(self, value: object) -> bool:
        if not self.pattern:
            return True
        import re

        try:
            return bool(re.fullmatch(self.pattern, str(value)))
        except re.error:
            return False


def _parse_enum(enum_type: type[E], value: object, field_name: str) -> E | None:
    if value is None:
        return None
    try:
        return enum_type[str(value).upper()]
    except KeyError:
        valid = ", ".join(m.name.lower() for m in enum_type)
        raise PolicyError(
            f"invalid {field_name} {value!r}; expected one of: {valid}"
        ) from None


def _parse_rule(raw: Mapping[str, Any]) -> Rule:
    unknown = set(raw) - _KNOWN_FIELDS
    if unknown:
        raise PolicyError(f"unknown rule field(s): {', '.join(sorted(unknown))}")
    for required in ("name", "tool"):
        if required not in raw:
            raise PolicyError(f"rule is missing required field {required!r}")
    action = _parse_enum(Action, raw.get("action"), "action")
    return Rule(
        name=str(raw["name"]),
        tool=str(raw["tool"]),
        arg=str(raw.get("arg", "*")),
        min_integrity=_parse_enum(Integrity, raw.get("min_integrity"), "min_integrity"),
        max_confidentiality=_parse_enum(
            Confidentiality, raw.get("max_confidentiality"), "max_confidentiality"
        ),
        action=Action.BLOCK if action is None else action,
        reason=str(raw.get("reason", "")),
    )


def _parse_declassification(raw: Mapping[str, Any]) -> DeclassificationRule:
    unknown = set(raw) - _DECLASSIFICATION_FIELDS
    if unknown:
        raise PolicyError(f"unknown declassification field(s): {', '.join(sorted(unknown))}")
    for required in ("name", "tool"):
        if required not in raw:
            raise PolicyError(f"declassification rule is missing required field {required!r}")
    return DeclassificationRule(
        name=str(raw["name"]),
        tool=str(raw["tool"]),
        arg=str(raw.get("arg", "*")),
        target_integrity=_parse_enum(Integrity, raw.get("target_integrity"), "target_integrity"),
        target_confidentiality=_parse_enum(
            Confidentiality, raw.get("target_confidentiality"), "target_confidentiality"
        ),
        pattern=str(raw.get("pattern", "")),
        reason=str(raw.get("reason", "")),
    )


class Policy:
    def __init__(
        self,
        rules: Iterable[Rule] = (),
        declassifications: Iterable[DeclassificationRule] = (),
    ) -> None:
        self._rules = tuple(rules)
        self._declassifications = tuple(declassifications)

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    @property
    def declassifications(self) -> tuple[DeclassificationRule, ...]:
        return self._declassifications

    def find_declassification(self, tool: str, arg: str) -> DeclassificationRule | None:
        for d in self._declassifications:
            if d.applies_to(tool, arg):
                return d
        return None

    @classmethod
    def from_toml(cls, text: str) -> Policy:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise PolicyError(f"policy is not valid TOML: {exc}") from exc
        rules = [_parse_rule(raw) for raw in data.get("rule", [])]
        declass = [_parse_declassification(raw) for raw in data.get("declassification", [])]
        return cls(rules, declass)

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        return cls.from_toml(Path(path).read_text(encoding="utf-8"))

    def evaluate(self, tool: str, args: Mapping[str, Labeled[Any]]) -> Verdict:
        violations: list[Violation] = []
        for arg_name, labeled in args.items():
            for rule in self._rules:
                if rule.applies_to(tool, arg_name) and rule.violated_by(labeled.label):
                    declass = self.find_declassification(tool, arg_name)
                    if declass is not None and declass.validates(labeled.value):
                        promoted_integrity = (
                            declass.target_integrity
                            if declass.target_integrity is not None
                            else labeled.label.integrity
                        )
                        lowered_conf = (
                            declass.target_confidentiality
                            if declass.target_confidentiality is not None
                            else labeled.label.confidentiality
                        )
                        candidate_label = Label(
                            integrity=max(labeled.label.integrity, promoted_integrity),
                            confidentiality=min(labeled.label.confidentiality, lowered_conf),
                            sources=labeled.label.sources,
                        )
                        if not rule.violated_by(candidate_label):
                            continue
                    violations.append(Violation(rule, arg_name, labeled.label))
        action = max((v.rule.action for v in violations), default=Action.ALLOW)
        return Verdict(action, tuple(violations))


DEFAULT_POLICY_TOML = """
[[rule]]
name = "untrusted-input-to-shell"
tool = "shell.*"
min_integrity = "user"
action = "block"
reason = "Shell commands must not be influenced by untrusted content."

[[rule]]
name = "untrusted-email-recipient"
tool = "email.send"
arg = "to"
min_integrity = "user"
action = "block"
reason = "Only the user may choose who receives email."

[[rule]]
name = "secret-leaves-via-email"
tool = "email.send"
max_confidentiality = "internal"
action = "block"

[[rule]]
name = "secret-leaves-via-http"
tool = "http.*"
max_confidentiality = "internal"
action = "block"

[[rule]]
name = "untrusted-file-write"
tool = "fs.write"
arg = "content"
min_integrity = "tool_output"
action = "confirm"
"""


def default_policy() -> Policy:
    return Policy.from_toml(DEFAULT_POLICY_TOML)
