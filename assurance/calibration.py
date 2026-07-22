"""Calibration: score a detector against the labeled corpus.

A detection is a TP if (pii_type, value) is in the sample's true_pii; a detected
pair not in truth is an FP; a truth pair not detected is an FN. Aggregated per
type and overall into precision / recall / F1. Undefined ratios (no predictions,
or no positives) are None ("n/a"), never a divide-by-zero. This makes the
detector auditable: it states its own miss rate.
"""

import json
from collections import defaultdict
from dataclasses import dataclass, asdict


@dataclass
class TypeMetrics:
    pii_type: str
    tp: int
    fp: int
    fn: int
    precision: float | None
    recall: float | None
    f1: float | None


@dataclass
class CalibrationReport:
    detector_name: str
    samples: int
    per_type: list[TypeMetrics]
    overall: TypeMetrics

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def _metrics(pii_type: str, tp: int, fp: int, fn: int) -> TypeMetrics:
    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    if precision and recall:            # both defined and non-zero
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = None
    return TypeMetrics(pii_type, tp, fp, fn, precision, recall, f1)


def calibrate(detector, corpus) -> CalibrationReport:
    tp: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)

    for sample in corpus:
        truth = {(s.pii_type, s.value) for s in sample.true_pii}
        preds = {(d.pii_type, d.value) for d in detector.detect(sample.text)}
        for pair in preds:
            if pair in truth:
                tp[pair[0]] += 1
            else:
                fp[pair[0]] += 1
        for pair in truth:
            if pair not in preds:
                fn[pair[0]] += 1

    types = sorted(set(tp) | set(fp) | set(fn))
    per_type = [_metrics(t, tp[t], fp[t], fn[t]) for t in types]
    overall = _metrics("OVERALL", sum(tp.values()), sum(fp.values()), sum(fn.values()))
    return CalibrationReport(getattr(detector, "name", "unknown"),
                             len(corpus), per_type, overall)
