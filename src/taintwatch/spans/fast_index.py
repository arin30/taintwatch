"""High-performance augmented interval tree for span-level taint tracking in large contexts."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from taintwatch.labels import Integrity, Label
from taintwatch.spans.tstr import Segment, TStr


@dataclass(frozen=True, slots=True)
class IntervalNode:
    """Augmented interval tree node with subtree label aggregation for O(1) branch pruning."""

    start: int
    end: int
    label: Label
    max_end: int
    min_subtree_integrity: Integrity
    left: IntervalNode | None = None
    right: IntervalNode | None = None


def _build_tree(segments: Sequence[Segment]) -> IntervalNode | None:
    if not segments:
        return None
    mid = len(segments) // 2
    seg = segments[mid]

    left_node = _build_tree(segments[:mid])
    right_node = _build_tree(segments[mid + 1 :])

    max_end = seg.end
    min_integrity = seg.label.integrity

    if left_node is not None:
        max_end = max(max_end, left_node.max_end)
        min_integrity = min(min_integrity, left_node.min_subtree_integrity)
    if right_node is not None:
        max_end = max(max_end, right_node.max_end)
        min_integrity = min(min_integrity, right_node.min_subtree_integrity)

    return IntervalNode(
        start=seg.start,
        end=seg.end,
        label=seg.label,
        max_end=max_end,
        min_subtree_integrity=min_integrity,
        left=left_node,
        right=right_node,
    )


class FastSpanIndex:
    """Augmented Interval Tree index for O(log N) point and O(K + log N) range queries."""

    __slots__ = ("_root", "_size", "_total_length")

    def __init__(self, segments: Sequence[Segment], total_length: int) -> None:
        sorted_segs = sorted(segments, key=lambda s: s.start)
        self._root = _build_tree(sorted_segs)
        self._size = len(segments)
        self._total_length: Final[int] = total_length

    @classmethod
    def from_tstr(cls, text: TStr) -> FastSpanIndex:
        return cls(text.segments, len(text))

    @property
    def size(self) -> int:
        return self._size

    @property
    def total_length(self) -> int:
        return self._total_length

    def query_point(self, index: int) -> Label:
        """Find the exact label at a specific character index in O(log N) time."""
        if not 0 <= index < self._total_length:
            raise IndexError(f"character index {index} out of range [0, {self._total_length})")
        node = self._root
        while node is not None:
            if node.start <= index < node.end:
                return node.label
            node = (
                node.left
                if node.left is not None and node.left.max_end > index
                else node.right
            )
        return Label()

    def query_range(self, start: int, end: int) -> list[Segment]:
        """Find all segments intersecting [start, end) in O(K + log N) time."""
        if start >= end or self._root is None:
            return []
        found: list[Segment] = []

        def _search(node: IntervalNode | None) -> None:
            if node is None:
                return
            # If current node intersects [start, end)
            if node.start < end and node.end > start:
                found.append(Segment(node.start, node.end, node.label))
            # If left subtree could contain intersecting intervals
            if node.left is not None and node.left.max_end > start:
                _search(node.left)
            # If right subtree could contain intersecting intervals
            if node.right is not None and node.start < end:
                _search(node.right)

        _search(self._root)
        found.sort(key=lambda s: s.start)
        return found

    def has_taint_below(self, floor: Integrity, start: int = 0, end: int | None = None) -> bool:
        """Rapidly check if [start, end) contains any taint below ``floor`` using branch pruning."""
        actual_end = self._total_length if end is None else end
        if start >= actual_end or self._root is None:
            return False

        def _check(node: IntervalNode | None) -> bool:
            if node is None:
                return False
            # Branch pruning: if the entire subtree has integrity >= floor, skip it!
            if node.min_subtree_integrity >= floor:
                return False
            # Check current node
            if node.start < actual_end and node.end > start and node.label.integrity < floor:
                return True
            # Search left
            if node.left is not None and node.left.max_end > start and _check(node.left):
                return True
            # Search right
            return node.right is not None and node.start < actual_end and _check(node.right)

        return _check(self._root)
