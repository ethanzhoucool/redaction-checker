"""Shared types + constants. STABLE INTERFACE — all modules import from here.

Ownership: this file is owned by the orchestrator. Other modules import it; do not
redefine these types elsewhere.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Optional

# Patterns whose presence in a backgrounded snapshot constitutes a leak.
DEFAULT_SECRET_PATTERNS: list[str] = [
    r"\b\d{3}-\d{2}-\d{4}\b",        # US SSN
    r"\b\d(?:[ -]?\d){12,18}\b",     # PAN / payment card (13-19 digits, ends on a digit)
    r"(?i)\bCVV\b",
    r"(?i)\bSSN\b",
    r"(?i)\brouting\b",
]

PASS, FAIL, ERROR = "PASS", "FAIL", "ERROR"


@dataclass
class Verdict:
    status: str                       # PASS | FAIL | ERROR
    reasons: list[str] = field(default_factory=list)
    leaked_text: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)  # ocr_chars, compressed_bytes, pixel_stddev, diff_ratio


@dataclass
class ScreenResult:
    name: str
    platform: str                     # "ios" | "android"
    sensitive: bool
    verdict: Verdict
    live_image: Optional[str] = None      # path to foregrounded screenshot
    snapshot_image: Optional[str] = None  # path to decoded app-switcher / recents card

    def to_dict(self) -> dict:
        return asdict(self)


def compile_secret_patterns(patterns: Optional[list[str]] = None) -> list[re.Pattern]:
    compiled: list[re.Pattern] = []
    for p in (patterns or DEFAULT_SECRET_PATTERNS):
        try:
            compiled.append(re.compile(p))
        except re.error:
            # Skip a malformed operator-supplied pattern rather than crash the
            # whole run; the other patterns still apply.
            continue
    return compiled
