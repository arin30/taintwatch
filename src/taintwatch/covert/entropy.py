"""Information-theoretic entropy tracking and mutual information bounds for agent tool calls."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass


def shannon_entropy(data: Sequence[str] | str) -> float:
    """Calculate the Shannon entropy in bits for a sequence of discrete symbols."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


@dataclass(frozen=True, slots=True)
class LeakageBudget:
    """Tracks cumulative observable entropy bits leaked across agent steps."""

    max_bits_per_session: float = 4.0
    accumulated_bits: float = 0.0

    @property
    def remaining_bits(self) -> float:
        return max(0.0, self.max_bits_per_session - self.accumulated_bits)

    def can_leak(self, bits: float) -> bool:
        return (self.accumulated_bits + bits) <= self.max_bits_per_session

    def consume(self, bits: float) -> LeakageBudget:
        return LeakageBudget(
            max_bits_per_session=self.max_bits_per_session,
            accumulated_bits=self.accumulated_bits + bits,
        )


def estimate_channel_capacity(
    vocabulary_size: int,
    sequence_length: int = 1,
) -> float:
    """Theoretical maximum information capacity (in bits) of a discrete tool channel."""
    if vocabulary_size <= 1:
        return 0.0
    return sequence_length * math.log2(vocabulary_size)
