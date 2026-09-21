"""Detection engine for credentials, tokens, PII, and high-entropy secrets."""

from dataclasses import dataclass
import math
import re
from typing import List, Optional


@dataclass(frozen=True)
class Finding:
    """Represents a sensitive item found in text."""

    category: str
    rule_name: str
    value: str
    start: int
    end: int
    confidence: float


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for a given text token.

    Higher values show higher randomness, common in generated secrets.
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def luhn_checksum_valid(card_number_str: str) -> bool:
    """Validate a numeric string with the Luhn algorithm."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def australian_tfn_valid(tfn_str: str) -> bool:
    """Validate Australian Tax File Number using the ATO modulus 11 algorithm."""
    digits = [int(c) for c in tfn_str if c.isdigit()]
    if len(digits) == 8:
        weights = [10, 7, 8, 4, 6, 3, 5, 1]
    elif len(digits) == 9:
        weights = [1, 4, 3, 7, 5, 8, 6, 9, 10]
    else:
        return False
    total = sum(d * w for d, w in zip(digits, weights))
    return total % 11 == 0


class Detector:
    """Scans text for sensitive patterns, PII, and high-entropy tokens."""

    PATTERNS = [
        (
            "CREDENTIAL",
            "anthropic_api_key",
            re.compile(r"\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{32,100}\b"),
            0.98,
        ),
        (
            "CREDENTIAL",
            "openai_api_key",
            re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,100}\b"),
            0.98,
        ),
        (
            "CREDENTIAL",
            "google_gemini_api_key",
            re.compile(r"\bAIzaSy[A-Za-z0-9_-]{33}\b"),
            0.98,
        ),
        (
            "CREDENTIAL",
            "aws_access_key_id",
            re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b"),
            0.95,
        ),
        (
            "CREDENTIAL",
            "github_token",
            re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b"),
            0.98,
        ),
        (
            "CREDENTIAL",
            "slack_token",
            re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9-]*\b"),
            0.95,
        ),
        (
            "CREDENTIAL",
            "stripe_api_key",
            re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99}\b"),
            0.98,
        ),
        (
            "CREDENTIAL",
            "sendgrid_api_key",
            re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
            0.98,
        ),
        (
            "CREDENTIAL",
            "jwt_token",
            re.compile(r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b"),
            0.90,
        ),
        (
            "CREDENTIAL",
            "private_key",
            re.compile(
                r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY[^-]*-----",
                re.DOTALL,
            ),
            0.99,
        ),
        (
            "CREDENTIAL",
            "database_connection_uri",
            re.compile(
                r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^\s:]+:[^\s@]+@[^\s/:]+(?::\d+)?/[^\s]*\b"
            ),
            0.95,
        ),
        (
            "PII",
            "email_address",
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            0.85,
        ),
        (
            "PII",
            "australian_mobile",
            re.compile(r"\b(?:\+?61\s?4|04)\d{2}[\s.-]?\d{3}[\s.-]?\d{3}\b"),
            0.85,
        ),
        (
            "NETWORK",
            "private_ipv4",
            re.compile(
                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
            ),
            0.80,
        ),
    ]

    CANDIDATE_CC = re.compile(r"\b(?:\d[ -]?){13,19}\b")
    CANDIDATE_TFN = re.compile(r"\b\d{3}[\s-]?\d{3}[\s-]?\d{2,3}\b")
    HIGH_ENTROPY_TOKEN = re.compile(r"\b[A-Za-z0-9+/_-]{24,}\b")

    def __init__(self, check_entropy: bool = True, entropy_threshold: float = 4.2):
        self.check_entropy = check_entropy
        self.entropy_threshold = entropy_threshold

    def scan(self, text: str) -> List[Finding]:
        """Scan input text and return all detected sensitive findings."""
        if not text:
            return []

        findings: List[Finding] = []
        covered_spans = []

        def span_overlaps(start: int, end: int) -> bool:
            return any(not (end <= s or start >= e) for s, e in covered_spans)

        # 1. Regex pattern scans
        for category, rule_name, pattern, conf in self.PATTERNS:
            for match in pattern.finditer(text):
                start, end = match.span()
                if not span_overlaps(start, end):
                    findings.append(
                        Finding(
                            category=category,
                            rule_name=rule_name,
                            value=match.group(0),
                            start=start,
                            end=end,
                            confidence=conf,
                        )
                    )
                    covered_spans.append((start, end))

        # 2. Credit card validation with Luhn check
        for match in self.CANDIDATE_CC.finditer(text):
            raw = match.group(0)
            digits_only = re.sub(r"\D", "", raw)
            if 13 <= len(digits_only) <= 19 and luhn_checksum_valid(digits_only):
                start, end = match.span()
                if not span_overlaps(start, end):
                    findings.append(
                        Finding(
                            category="PII",
                            rule_name="credit_card_number",
                            value=raw,
                            start=start,
                            end=end,
                            confidence=0.95,
                        )
                    )
                    covered_spans.append((start, end))

        # 3. Australian Tax File Number check
        for match in self.CANDIDATE_TFN.finditer(text):
            raw = match.group(0)
            digits_only = re.sub(r"\D", "", raw)
            if len(digits_only) in (8, 9) and australian_tfn_valid(digits_only):
                start, end = match.span()
                if not span_overlaps(start, end):
                    findings.append(
                        Finding(
                            category="PII",
                            rule_name="australian_tfn",
                            value=raw,
                            start=start,
                            end=end,
                            confidence=0.90,
                        )
                    )
                    covered_spans.append((start, end))

        # 4. High-entropy token detection (catches custom tokens and passwords)
        if self.check_entropy:
            for match in self.HIGH_ENTROPY_TOKEN.finditer(text):
                token = match.group(0)
                start, end = match.span()
                if span_overlaps(start, end):
                    continue
                entropy = calculate_shannon_entropy(token)
                if entropy >= self.entropy_threshold:
                    findings.append(
                        Finding(
                            category="CREDENTIAL",
                            rule_name="high_entropy_secret",
                            value=token,
                            start=start,
                            end=end,
                            confidence=round(min(1.0, 0.70 + (entropy - 4.0) * 0.15), 2),
                        )
                    )
                    covered_spans.append((start, end))

        findings.sort(key=lambda f: f.start)
        return findings
