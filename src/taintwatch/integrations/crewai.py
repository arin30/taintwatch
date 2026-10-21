"""CrewAI tool decorator backed by a TaintWatch guard."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from functools import wraps
from typing import Any, ParamSpec, TypeVar, cast

from taintwatch.guard import Guard
from taintwatch.labels import Integrity
from taintwatch.tainted import Labeled

P = ParamSpec("P")
R = TypeVar("R")


def _labeled_values(value: Any) -> list[Labeled[Any]]:
    if isinstance(value, Labeled):
        return [value]
    if isinstance(value, Mapping):
        return [item for child in value.values() for item in _labeled_values(child)]
    if isinstance(value, (list, tuple, set, frozenset)):
        return [item for child in value for item in _labeled_values(child)]
    return []


def _unwrap(value: Any) -> Any:
    if isinstance(value, Labeled):
        return _unwrap(value.value)
    if isinstance(value, dict):
        return {key: _unwrap(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_unwrap(child) for child in value]
    if isinstance(value, tuple):
        return tuple(_unwrap(child) for child in value)
    if isinstance(value, set):
        return {_unwrap(child) for child in value}
    if isinstance(value, frozenset):
        return frozenset(_unwrap(child) for child in value)
    return value


def taint_guarded(
    guard: Guard,
    *,
    tool_name: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Gate a CrewAI-compatible tool function with ``guard`` before it runs.

    ``Labeled`` arguments retain their labels. Containers may mix labeled and
    ordinary values; their labels are joined before policy evaluation. Plain
    arguments are treated as user-provided CrewAI input.
    """

    def decorate(fn: Callable[P, R]) -> Callable[P, R]:
        signature = inspect.signature(fn)
        guarded_name = tool_name or fn.__name__

        @wraps(fn)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            labeled_args: dict[str, Labeled[Any]] = {}

            for name, value in bound.arguments.items():
                parents = _labeled_values(value)
                clean_value = _unwrap(value)
                if len(parents) == 1 and isinstance(value, Labeled):
                    labeled_args[name] = parents[0]
                elif parents:
                    labeled_args[name] = guard.derive(
                        clean_value,
                        parents,
                        f"crewai argument {name}",
                    )
                else:
                    labeled_args[name] = guard.ingest(
                        clean_value,
                        source="crewai",
                        integrity=Integrity.USER,
                    )

            def invoke(**clean_args: Any) -> R:
                bound.arguments.update(clean_args)
                return fn(*bound.args, **bound.kwargs)

            result = guard.call(guarded_name, labeled_args, invoke)
            return cast(R, result.value)

        return wrapped

    return decorate
