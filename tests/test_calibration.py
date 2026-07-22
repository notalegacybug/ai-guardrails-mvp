import json
from assurance.detector import RegexDetector, Detection
from assurance.corpus import build_labeled_corpus
from assurance.calibration import calibrate


def _by_type(report):
    return {m.pii_type: m for m in report.per_type}


def test_regex_detector_recall_perfect_but_zip_precision_dinged_by_cpt():
    report = calibrate(RegexDetector(), build_labeled_corpus(7))
    m = _by_type(report)
    # All structured identifiers are fully recalled:
    for t in ("SSN", "MRN", "ZIP", "DATE"):
        assert m[t].recall == 1.0, (t, m[t])
    # SSN / MRN / DATE carry no false positives:
    for t in ("SSN", "MRN", "DATE"):
        assert m[t].precision == 1.0, (t, m[t])
    # ZIP precision is dinged — a 5-digit CPT code (90837) looks like a ZIP.
    # This is the calibration doing its job: surfacing a real detector weakness.
    assert m["ZIP"].fp >= 1 and m["ZIP"].precision < 1.0, m["ZIP"]
    # NAME is the known, measured detection gap:
    assert m["NAME"].recall == 0.0
    assert m["NAME"].precision is None      # detector made no NAME predictions
    assert 0.0 < report.overall.recall < 1.0


class _BlindDetector:
    name = "blind"
    def detect(self, text): return []


def test_blind_detector_has_zero_recall_and_undefined_precision():
    report = calibrate(_BlindDetector(), build_labeled_corpus(7))
    assert report.overall.recall == 0.0
    assert report.overall.precision is None   # no predictions at all


def test_empty_corpus_does_not_crash():
    report = calibrate(RegexDetector(), [])
    assert report.samples == 0
    assert report.overall.precision is None and report.overall.recall is None


def test_to_json_roundtrips():
    report = calibrate(RegexDetector(), build_labeled_corpus(7))
    parsed = json.loads(report.to_json())
    assert parsed["detector_name"] == "regex-v1"
    assert parsed["overall"]["pii_type"] == "OVERALL"
