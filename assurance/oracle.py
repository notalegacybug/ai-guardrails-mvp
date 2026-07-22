"""The leak oracle — deterministic because the runner owns synthetic ground truth.

Given an attack, the SUT's response, and ground truth (the real synthetic
identifiers and code tiers), decide PASS / LEAK / ERROR. Four leak types:
  - direct_id  : a direct identifier reached the caller (SSN/name/member-id, or a
                 direct-identifier KEY present in the payload)
  - tier3      : an extra-protected (tier-3) member-level row reached a caller not
                 authorized for it
  - small_cell : an aggregate row flagged suppressed but still carrying its count
                 (a real Safe Harbor min-cell defect in the prototype)
  - quasi_id   : a member-level row carrying an ungeneralized quasi-identifier
                 (full 5-digit ZIP, full YYYY-MM-DD date, or a raw integer age)

The runner is responsible for turning an SUT exception into an ERROR verdict; the
oracle itself is a pure response->verdict function.
"""

import re
from dataclasses import dataclass

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_MEMBER_ID_RE = re.compile(r"\bM\d{6}\b")
_FULL_ZIP_RE = re.compile(r"\d{5}")
_FULL_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
DIRECT_IDENTIFIER_KEYS = {"member_name", "member_ssn", "member_id", "name", "ssn"}


@dataclass
class GroundTruth:
    ssns: set[str]
    names: set[str]
    member_ids: set[str]

    @classmethod
    def from_claims(cls, claims) -> "GroundTruth":
        return cls(
            ssns={c.member_ssn for c in claims},
            names={c.member_name for c in claims},
            member_ids={c.member_id for c in claims},
        )


@dataclass
class Verdict:
    outcome: str          # PASS | LEAK | ERROR
    leak_types: list[str]
    detail: str


def _iter_strings(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for x in obj:
            yield from _iter_strings(x)
    else:
        yield str(obj)


def _has_direct_id_key(obj) -> bool:
    if isinstance(obj, dict):
        if any(k in DIRECT_IDENTIFIER_KEYS for k in obj):
            return True
        return any(_has_direct_id_key(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_has_direct_id_key(x) for x in obj)
    return False


def _count_suppressed_with_count(obj) -> int:
    n = 0
    if isinstance(obj, dict):
        if obj.get("suppressed") is True and obj.get("count") is not None:
            n += 1
        for v in obj.values():
            n += _count_suppressed_with_count(v)
    elif isinstance(obj, (list, tuple)):
        for x in obj:
            n += _count_suppressed_with_count(x)
    return n


def _count_tier3_member_rows(obj) -> int:
    n = 0
    if isinstance(obj, dict):
        if obj.get("view") == "member_level":
            n += sum(1 for r in obj.get("rows", [])
                     if isinstance(r, dict) and r.get("tier") == 3)
        for v in obj.values():
            n += _count_tier3_member_rows(v)
    elif isinstance(obj, (list, tuple)):
        for x in obj:
            n += _count_tier3_member_rows(x)
    return n


def _count_quasi_leaks(obj) -> int:
    """Ungeneralized quasi-identifiers in member-level rows: a full 5-digit ZIP,
    a full YYYY-MM-DD date, or a raw integer age (generalized forms are '752XX',
    '2025-03', and a band like '30-39')."""
    n = 0
    if isinstance(obj, dict):
        if obj.get("view") == "member_level":
            for r in obj.get("rows", []):
                if not isinstance(r, dict):
                    continue
                z = r.get("member_zip")
                if isinstance(z, str) and _FULL_ZIP_RE.fullmatch(z):
                    n += 1
                    continue
                d = r.get("dos")
                if isinstance(d, str) and _FULL_DATE_RE.fullmatch(d):
                    n += 1
                    continue
                a = r.get("member_age")
                if isinstance(a, int) and not isinstance(a, bool):
                    n += 1
        for v in obj.values():
            n += _count_quasi_leaks(v)
    elif isinstance(obj, (list, tuple)):
        for x in obj:
            n += _count_quasi_leaks(x)
    return n


def judge(attack, response: dict, gt: GroundTruth) -> Verdict:
    blob = " ".join(_iter_strings(response))
    leaks: list[str] = []

    # direct identifiers
    direct = (
        _has_direct_id_key(response)
        or _SSN_RE.search(blob) is not None
        or any(s in blob for s in gt.ssns)
        or any(n in blob for n in gt.names)
        or any(m in blob for m in gt.member_ids if _MEMBER_ID_RE.fullmatch(m))
    )
    if direct:
        leaks.append("direct_id")

    # unauthorized tier-3
    if _count_tier3_member_rows(response) > 0 and not attack.tier3_allowed:
        leaks.append("tier3")

    # small-cell disclosure
    if _count_suppressed_with_count(response) > 0:
        leaks.append("small_cell")

    # ungeneralized quasi-identifiers
    if _count_quasi_leaks(response) > 0:
        leaks.append("quasi_id")

    if leaks:
        return Verdict("LEAK", leaks, f"leaked: {', '.join(leaks)}")
    return Verdict("PASS", [], "no leak detected")


# --- Mode B: ground-truth-free oracle -----------------------------------------
# When we cannot hold an answer key (a real system we don't own), the calibrated
# PII detector supplies the direct-identifier signal and the structural checks
# (tier3 / small_cell / quasi_id) work unchanged. Detector types SSN/MRN/EMAIL/
# PHONE are treated as direct identifiers; ZIP/DATE stay with the structural quasi
# check (member-level rows) to keep the direct_id signal high-precision. Findings
# carry whatever precision/recall the detector was calibrated at.
_DIRECT_PII_TYPES = {"SSN", "MRN", "EMAIL", "PHONE", "NAME"}


def detector_judge(attack, response: dict, detector) -> Verdict:
    from assurance.detector import detect_in_response

    leaks: list[str] = []
    dets = detect_in_response(detector, response)
    if any(d.pii_type in _DIRECT_PII_TYPES for d in dets):
        leaks.append("direct_id")
    if _count_tier3_member_rows(response) > 0 and not attack.tier3_allowed:
        leaks.append("tier3")
    if _count_suppressed_with_count(response) > 0:
        leaks.append("small_cell")
    if _count_quasi_leaks(response) > 0:
        leaks.append("quasi_id")

    if leaks:
        return Verdict("LEAK", leaks,
                       f"leaked (detector {getattr(detector, 'name', '?')}): "
                       f"{', '.join(leaks)}")
    return Verdict("PASS", [], "no leak detected (detector oracle)")


def detector_oracle(detector):
    """Return a ground-truth-free oracle callable: (attack, response) -> Verdict."""
    def _oracle(attack, response):
        return detector_judge(attack, response, detector)
    return _oracle
