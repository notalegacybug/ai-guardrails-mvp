"""Pluggable PII/PHI detector.

RegexDetector covers STRUCTURED identifiers only (SSN, phone, email, MRN, ZIP,
full dates). Names / free-text entities are intentionally NOT covered — that is
the deferred gap the calibration harness quantifies. A future NER detector
implements the same Detector Protocol and the same harness measures it.
"""

import re
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Detection:
    pii_type: str
    value: str
    start: int
    end: int


class Detector(Protocol):
    name: str
    def detect(self, text: str) -> list[Detection]: ...


# Ordered by priority: earlier patterns win when spans overlap.
_PATTERNS = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("SSN",   re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("MRN",   re.compile(r"\bM\d{6}\b")),
    ("DATE",  re.compile(r"\b\d{4}-\d{2}-\d{2}\b|\b\d{2}/\d{2}/\d{4}\b")),
    ("PHONE", re.compile(r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b")),
    ("ZIP",   re.compile(r"\b\d{5}\b")),
]


def _leaf_strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _leaf_strings(v)
    elif isinstance(obj, (list, tuple)):
        for x in obj:
            yield from _leaf_strings(x)
    else:
        yield str(obj)


class RegexDetector:
    name = "regex-v1"

    def detect(self, text: str) -> list[Detection]:
        if not isinstance(text, str):
            text = str(text)
        found: list[Detection] = []
        claimed: list[tuple[int, int]] = []
        for pii_type, pat in _PATTERNS:
            for m in pat.finditer(text):
                s, e = m.start(), m.end()
                if any(s < ce and cs < e for cs, ce in claimed):
                    continue  # overlaps a higher-priority match already taken
                claimed.append((s, e))
                found.append(Detection(pii_type, m.group(), s, e))
        found.sort(key=lambda d: d.start)
        return found


# A person-name heuristic: two or more Title-Case words in a row. This is
# dependency-free NER-lite — it closes the NAME gap the plain RegexDetector has,
# at the cost of false-positives on any Title-Case phrase (e.g. a diagnosis name).
# The calibration harness measures exactly that tradeoff. A statistical NER
# (Presidio/spaCy) is a drop-in future replacement with the same interface.
_NAME_RE = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b")


class NameAwareRegexDetector:
    """RegexDetector's structured identifiers PLUS a heuristic NAME detector."""

    name = "regex+name-v1"

    def __init__(self) -> None:
        self._base = RegexDetector()

    def detect(self, text: str) -> list[Detection]:
        if not isinstance(text, str):
            text = str(text)
        found = self._base.detect(text)
        claimed = [(d.start, d.end) for d in found]
        for m in _NAME_RE.finditer(text):
            s, e = m.start(), m.end()
            if any(s < ce and cs < e for cs, ce in claimed):
                continue  # don't swallow an already-matched structured id
            found.append(Detection("NAME", m.group(), s, e))
        found.sort(key=lambda d: d.start)
        return found


def detect_in_response(detector: Detector, response) -> list[Detection]:
    """Flatten a response's leaf string values to one text blob, then detect."""
    blob = " ".join(_leaf_strings(response))
    return detector.detect(blob)
