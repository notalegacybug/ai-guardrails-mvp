"""A deterministic, labeled evaluation corpus for calibrating a detector.

Built from the same synthetic generator the SUT uses, so we hold ground truth:
positive samples embed a member's REAL synthetic identifiers (recorded as
PiiSpans); negative samples are clean/aggregated/generalized/denied responses
with no PII. This is the answer key the calibration harness scores against.
Constructing labeled test inputs is standard classifier calibration — not
fabricating leaks.
"""

from dataclasses import dataclass

from sut_claims.synthetic import generate


@dataclass(frozen=True)
class PiiSpan:
    pii_type: str
    value: str


@dataclass(frozen=True)
class LabeledSample:
    text: str
    true_pii: list[PiiSpan]


def build_labeled_corpus(seed: int = 7) -> list[LabeledSample]:
    claims, _ = generate(seed=seed)
    picks = sorted(claims, key=lambda c: c.claim_id)[:3]  # stable selection

    samples: list[LabeledSample] = []

    # Positives: a member's real direct + quasi identifiers embedded in a note.
    for c in picks:
        text = (f"Case note for {c.member_name} (SSN {c.member_ssn}, "
                f"MRN {c.member_id}); DOS {c.dos}; residence ZIP {c.member_zip}.")
        samples.append(LabeledSample(text=text, true_pii=[
            PiiSpan("NAME", c.member_name),   # detector does NOT catch this (the gap)
            PiiSpan("SSN", c.member_ssn),
            PiiSpan("MRN", c.member_id),
            PiiSpan("DATE", c.dos),
            PiiSpan("ZIP", c.member_zip),
        ]))

    # Negatives: no PII values present.
    samples.append(LabeledSample(
        text="Provider PRV1000 aggregate: cpt 90837 count 160 suppressed false; peer_mean 6.2.",
        true_pii=[]))
    samples.append(LabeledSample(
        text="Member-level (generalized): zip 752XX; age band 30-39; dos 2025-03; tier 3.",
        true_pii=[]))
    samples.append(LabeledSample(
        text="Request denied: exfiltration pattern detected; no member data returned.",
        true_pii=[]))
    # A Title-Case phrase that is NOT a person name — surfaces the name heuristic's
    # false-positive so the calibration reports it honestly.
    samples.append(LabeledSample(
        text="Aggregate note: Major Depressive Disorder prevalence up; no member identity disclosed.",
        true_pii=[]))
    return samples
