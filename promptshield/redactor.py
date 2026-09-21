"""Redaction and deterministic masking engine with session rehydration."""

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from promptshield.detector import Detector, Finding


@dataclass
class RedactionResult:
    """Result of a redaction operation."""

    sanitised_text: str
    findings: List[Finding]
    mapping: Dict[str, str] = field(default_factory=dict)
    session_id: Optional[str] = None


class Redactor:
    """Applies deterministic masking to sensitive findings with restore support."""

    def __init__(
        self,
        detector: Optional[Detector] = None,
        style: str = "pseudonym",
        session_dir: Optional[Path] = None,
    ):
        self.detector = detector or Detector()
        self.style = style  # pseudonym, redacted, or hash
        self.session_dir = session_dir or (Path.cwd() / ".promptshield_sessions")

    def _generate_pseudonym(
        self, rule_name: str, index: int, value: str
    ) -> str:
        if self.style == "redacted":
            return f"[REDACTED:{rule_name.upper()}]"
        elif self.style == "hash":
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
            return f"[SECRET_HASH_{digest}]"
        else:  # default: pseudonym
            clean_name = rule_name.upper().replace("_API_KEY", "_KEY")
            return f"[{clean_name}_{index}]"

    def redact(
        self, text: str, session_id: Optional[str] = None
    ) -> RedactionResult:
        """Scan and mask sensitive tokens deterministically."""
        findings = self.detector.scan(text)
        if not findings:
            return RedactionResult(
                sanitised_text=text,
                findings=[],
                mapping={},
                session_id=session_id,
            )

        # Build deterministic mapping so identical secrets share the same pseudonym
        value_to_pseudonym: Dict[str, str] = {}
        category_counters: Dict[str, int] = {}

        for finding in findings:
            val = finding.value
            if val not in value_to_pseudonym:
                counter = category_counters.get(finding.rule_name, 1)
                category_counters[finding.rule_name] = counter + 1
                pseudonym = self._generate_pseudonym(finding.rule_name, counter, val)
                value_to_pseudonym[val] = pseudonym

        # Replace findings in reverse order of start index to preserve string offsets
        chars = list(text)
        for finding in reversed(findings):
            start = finding.start
            end = finding.end
            pseudonym = value_to_pseudonym[finding.value]
            chars[start:end] = list(pseudonym)

        sanitised_text = "".join(chars)
        reverse_mapping = {p: v for v, p in value_to_pseudonym.items()}

        if session_id:
            self._save_session(session_id, reverse_mapping)

        return RedactionResult(
            sanitised_text=sanitised_text,
            findings=findings,
            mapping=reverse_mapping,
            session_id=session_id,
        )

    def restore(self, text: str, session_id: Optional[str] = None, mapping: Optional[Dict[str, str]] = None) -> str:
        """Swap pseudonyms back to real values using session or mapping dictionary."""
        effective_map: Dict[str, str] = {}
        if session_id:
            effective_map.update(self._load_session(session_id))
        if mapping:
            effective_map.update(mapping)

        if not effective_map:
            return text

        restored_text = text
        # Sort keys longest first to avoid partial prefix replacement collisions
        for pseudonym in sorted(effective_map.keys(), key=len, reverse=True):
            original = effective_map[pseudonym]
            restored_text = restored_text.replace(pseudonym, original)

        return restored_text

    def _save_session(self, session_id: str, mapping: Dict[str, str]) -> None:
        self.session_dir.mkdir(parents=True, exist_ok=True)
        session_file = self.session_dir / f"{session_id}.json"
        existing = {}
        if session_file.exists():
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = {}
        existing.update(mapping)
        with open(session_file, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def _load_session(self, session_id: str) -> Dict[str, str]:
        session_file = self.session_dir / f"{session_id}.json"
        if not session_file.exists():
            return {}
        try:
            with open(session_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
