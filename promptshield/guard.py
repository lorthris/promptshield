"""Prompt injection and jailbreak defense engine for LLM applications.

Detects direct prompt injections, jailbreak attempts, system prompt leaks,
delimiter manipulation, and obfuscated payloads in user prompts.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from enum import Enum


class ThreatCategory(str, Enum):
    """Categories of prompt attacks."""
    DIRECT_INJECTION = "direct_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    DATA_EXFILTRATION = "data_exfiltration"
    DELIMITER_INJECTION = "delimiter_injection"
    OBFUSCATED_PAYLOAD = "obfuscated_payload"


class ThreatLevel(str, Enum):
    """Assessment levels for detected threats."""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ThreatFinding:
    """Individual security finding in a prompt."""
    category: ThreatCategory
    score: int
    matched_text: str
    description: str
    start: int
    end: int


@dataclass
class GuardResult:
    """Complete evaluation result for an analyzed prompt."""
    is_safe: bool
    threat_level: ThreatLevel
    threat_score: int
    findings: list[ThreatFinding] = field(default_factory=list)
    sanitized_prompt: str = ""

    def to_dict(self) -> dict[str, object]:
        """Convert result to dictionary representation."""
        return {
            "is_safe": self.is_safe,
            "threat_level": self.threat_level.value,
            "threat_score": self.threat_score,
            "findings": [
                {
                    "category": f.category.value,
                    "score": f.score,
                    "matched_text": f.matched_text,
                    "description": f.description,
                    "start": f.start,
                    "end": f.end,
                }
                for f in self.findings
            ],
            "sanitized_prompt": self.sanitized_prompt,
        }


class PromptGuard:
    """Analyzes and neutralizes prompt injection threats."""

    # Direct instruction override patterns
    _DIRECT_INJECTION_PATTERNS = [
        (
            re.compile(
                r"(?i)\b(?:ignore|disregard|forget|override|bypass|clear|drop)\s+"
                r"(?:all\s+)?(?:previous|prior|above|former|initial)\s+"
                r"(?:instructions|directions|rules|prompts|system\s+prompts|commands|constraints)\b"
            ),
            50,
            "Direct instruction override attempt",
        ),
        (
            re.compile(
                r"(?i)\b(?:do\s+not|never\s+mind)\s+(?:follow|obey|listen\s+to)\s+"
                r"(?:the\s+)?(?:system|developer|safety|guidelines|rules)\b"
            ),
            45,
            "Guideline defiance instruction",
        ),
        (
            re.compile(
                r"(?i)\b(?:start\s+new\s+session|reset\s+all\s+rules|system\s+override\s+code)\b"
            ),
            40,
            "Session reset / override command",
        ),
    ]

    # Jailbreak and persona hijacking patterns
    _JAILBREAK_PATTERNS = [
        (
            re.compile(
                r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+"
                r"(?:dan|developer\s+mode|aim|unfiltered|evil\s+twin|chaosgpt|nexus)\b"
            ),
            50,
            "Known jailbreak persona activation",
        ),
        (
            re.compile(
                r"(?i)\bdo\s+anything\s+now\b"
            ),
            50,
            "DAN jailbreak signature",
        ),
        (
            re.compile(
                r"(?i)\b(?:simulate|enter|enable)\s+(?:developer\s+mode|jailbreak\s+mode|unrestricted\s+mode)\b"
            ),
            45,
            "Mode manipulation request",
        ),
        (
            re.compile(
                r"(?i)\bfor\s+an\s+educational\s+paper|in\s+a\s+fictional\s+story\s+where\s+safety\s+does\s+not\s+apply\b"
            ),
            25,
            "Hypothetical/fictional safety bypass frame",
        ),
        (
            re.compile(
                r"(?i)\b(?:my\s+grandmother\s+used\s+to\s+read\s+me|grandma\s+story\s+about\s+napalm)\b"
            ),
            40,
            "Grandmother persona exploit signature",
        ),
    ]

    # System prompt extraction patterns
    _PROMPT_LEAK_PATTERNS = [
        (
            re.compile(
                r"(?i)\b(?:repeat|print|output|display|show|reveal|echo|copy)\s+"
                r"(?:verbatim\s+)?(?:the\s+)?(?:exact\s+)?(?:system\s+prompt|initial\s+instructions|"
                r"everything\s+above|text\s+before\s+this|prompt\s+template)\b"
            ),
            45,
            "System prompt extraction attempt",
        ),
        (
            re.compile(
                r"(?i)\bwhat\s+(?:are|were)\s+your\s+(?:initial\s+)?(?:system\s+)?(?:instructions|rules|directives)\b"
            ),
            35,
            "System instructions inquiry",
        ),
        (
            re.compile(
                r"(?i)\boutput\s+initialization\s+(?:configuration|text|prompt)\b"
            ),
            40,
            "Initialization prompt extraction attempt",
        ),
    ]

    # Data exfiltration patterns (markdown image injections)
    _EXFILTRATION_PATTERNS = [
        (
            re.compile(
                r"!\[[^\]]*\]\((?:https?:)?//[^\s\)]+\?[^\s\)]*(?:leak|key|token|data|secret|exfil|q=)[^\s\)]*\)"
            ),
            50,
            "Markdown image data exfiltration payload",
        ),
        (
            re.compile(
                r"<img\s+[^>]*src=[\"'](?:https?:)?//[^\s\"']+\?[^\s\"']*(?:leak|key|token|data|secret)[^\s\"']*[\"']"
            ),
            50,
            "HTML image data exfiltration payload",
        ),
    ]

    # Special token and delimiter injection patterns
    _DELIMITER_PATTERNS = [
        (
            re.compile(
                r"<\|(?:im_start|im_end|endoftext|system|assistant|user)\|>"
            ),
            50,
            "ChatML special token injection",
        ),
        (
            re.compile(
                r"\[\/?(?:INST|SYS)\]"
            ),
            45,
            "LLaMA instruction delimiter injection",
        ),
        (
            re.compile(
                r"<\/(?:context|system|instruction|rules|user_query)>"
            ),
            40,
            "XML prompt container escape tag",
        ),
    ]

    # Zero-width character detector
    _ZERO_WIDTH_CHARS = re.compile(r"[\u200b\u200c\u200d\ufeff\u2060]")

    def __init__(self, threshold: int = 40) -> None:
        """Initialize guard with score threshold for safe classification.
        
        Args:
            threshold: Cumulative score above which a prompt is marked unsafe.
        """
        self.threshold = threshold

    def scan(self, prompt: str) -> GuardResult:
        """Scan prompt for injection attacks, leaks, and exploits.
        
        Args:
            prompt: Text to analyze.
            
        Returns:
            GuardResult containing safety status, threat level, score, and findings.
        """
        findings: list[ThreatFinding] = []

        if not prompt or not prompt.strip():
            return GuardResult(
                is_safe=True,
                threat_level=ThreatLevel.CLEAN,
                threat_score=0,
                findings=[],
                sanitized_prompt=prompt,
            )

        # 1. Zero-width character / steganography check
        zero_width_matches = list(self._ZERO_WIDTH_CHARS.finditer(prompt))
        if len(zero_width_matches) >= 3:
            findings.append(
                ThreatFinding(
                    category=ThreatCategory.OBFUSCATED_PAYLOAD,
                    score=30,
                    matched_text=f"{len(zero_width_matches)} zero-width characters",
                    description="Hidden zero-width unicode characters detected",
                    start=zero_width_matches[0].start(),
                    end=zero_width_matches[-1].end(),
                )
            )

        # 2. Base64 payload detection
        for match in re.finditer(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])", prompt):
            candidate = match.group(1)
            try:
                decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
                if len(decoded) >= 12 and any(
                    kw in decoded.lower()
                    for kw in ["ignore", "system", "instruction", "prompt", "bypass", "jailbreak"]
                ):
                    findings.append(
                        ThreatFinding(
                            category=ThreatCategory.OBFUSCATED_PAYLOAD,
                            score=45,
                            matched_text=candidate[:30] + "...",
                            description="Base64 encoded instruction payload detected",
                            start=match.start(),
                            end=match.end(),
                        )
                    )
            except Exception:
                pass

        # 3. Pattern suites
        pattern_groups = [
            (ThreatCategory.DIRECT_INJECTION, self._DIRECT_INJECTION_PATTERNS),
            (ThreatCategory.JAILBREAK, self._JAILBREAK_PATTERNS),
            (ThreatCategory.SYSTEM_PROMPT_LEAK, self._PROMPT_LEAK_PATTERNS),
            (ThreatCategory.DATA_EXFILTRATION, self._EXFILTRATION_PATTERNS),
            (ThreatCategory.DELIMITER_INJECTION, self._DELIMITER_PATTERNS),
        ]

        for category, patterns in pattern_groups:
            for pattern, score, desc in patterns:
                for match in pattern.finditer(prompt):
                    findings.append(
                        ThreatFinding(
                            category=category,
                            score=score,
                            matched_text=match.group(0),
                            description=desc,
                            start=match.start(),
                            end=match.end(),
                        )
                    )

        total_score = sum(f.score for f in findings)
        threat_score = min(100, total_score)

        if threat_score == 0:
            level = ThreatLevel.CLEAN
        elif threat_score < 30:
            level = ThreatLevel.LOW
        elif threat_score < 60:
            level = ThreatLevel.MEDIUM
        elif threat_score < 85:
            level = ThreatLevel.HIGH
        else:
            level = ThreatLevel.CRITICAL

        is_safe = threat_score < self.threshold
        sanitized = self.sanitize(prompt) if not is_safe else prompt

        return GuardResult(
            is_safe=is_safe,
            threat_level=level,
            threat_score=threat_score,
            findings=findings,
            sanitized_prompt=sanitized,
        )

    def sanitize(self, prompt: str) -> str:
        """Strip or neutralize detected malicious attack vectors.
        
        Args:
            prompt: Text to sanitize.
            
        Returns:
            Cleaned text safe for LLM context inclusion.
        """
        # Strip zero-width characters
        cleaned = self._ZERO_WIDTH_CHARS.sub("", prompt)

        # Strip special token delimiters
        for _, patterns in [
            (ThreatCategory.DELIMITER_INJECTION, self._DELIMITER_PATTERNS),
            (ThreatCategory.DATA_EXFILTRATION, self._EXFILTRATION_PATTERNS),
            (ThreatCategory.DIRECT_INJECTION, self._DIRECT_INJECTION_PATTERNS),
            (ThreatCategory.JAILBREAK, self._JAILBREAK_PATTERNS),
            (ThreatCategory.SYSTEM_PROMPT_LEAK, self._PROMPT_LEAK_PATTERNS),
        ]:
            for pattern, _, _ in patterns:
                cleaned = pattern.sub("[REMOVED_SECURITY_THREAT]", cleaned)

        return cleaned
