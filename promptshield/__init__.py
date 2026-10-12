"""PromptShield - Local secret and PII sanitiser for developer AI workflows."""

__version__ = "1.0.0"
__author__ = "PromptShield"

from promptshield.detector import Detector, Finding
from promptshield.guard import GuardResult, PromptGuard, ThreatCategory, ThreatLevel
from promptshield.redactor import RedactionResult, Redactor

__all__ = [
    "Detector",
    "Finding",
    "GuardResult",
    "PromptGuard",
    "RedactionResult",
    "Redactor",
    "ThreatCategory",
    "ThreatLevel",
]
