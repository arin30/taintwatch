"""Taintwatch: information-flow control for LLM agents."""

from taintwatch.crypto import TaintToken, TaintTokenSigner, TaintTokenVerifier
from taintwatch.errors import DeclassificationError, PolicyError, TaintwatchError
from taintwatch.guard import Guard, PolicyViolation
from taintwatch.labels import Confidentiality, Integrity, Label
from taintwatch.policy import Action, DeclassificationRule, Policy, Verdict, default_policy
from taintwatch.provenance import ProvenanceGraph
from taintwatch.tainted import Labeled

__all__ = [
    "Action",
    "Confidentiality",
    "DeclassificationError",
    "DeclassificationRule",
    "Guard",
    "Integrity",
    "Label",
    "Labeled",
    "Policy",
    "PolicyError",
    "PolicyViolation",
    "ProvenanceGraph",
    "TaintToken",
    "TaintTokenSigner",
    "TaintTokenVerifier",
    "TaintwatchError",
    "Verdict",
    "default_policy",
]
__version__ = "0.1.0"
