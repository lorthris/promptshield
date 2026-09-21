"""PromptShield - Local secret and PII sanitiser for developer AI workflows."""

__version__ = "1.0.0"
__author__ = "PromptShield"

from promptshield.detector import Detector, Finding
from promptshield.redactor import Redactor, RedactionResult

__all__ = ["Detector", "Finding", "Redactor", "RedactionResult"]
