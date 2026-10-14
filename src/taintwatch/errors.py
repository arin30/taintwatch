"""Exception types shared across Taintwatch."""

from __future__ import annotations


class TaintwatchError(Exception):
    """Base class for all Taintwatch errors."""


class PolicyError(TaintwatchError):
    """Raised when a policy definition is malformed."""


class DeclassificationError(TaintwatchError):
    """Raised when a value cannot be safely declassified under policy rules."""
