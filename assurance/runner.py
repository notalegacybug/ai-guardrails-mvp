"""Orchestration: generate synthetic data -> build the SUT -> run each attack ->
judge -> record evidence -> aggregate into an AssuranceReport.

Deterministic: a given (seed, min_cell) reproduces the same findings. The config
(including seed) is recorded so the run is replayable.
"""

import json

from sut_claims.synthetic import generate
from sut_claims.audit import AuditLog

from assurance.sut import LocalClaimsSUT
from assurance.attacks import BATTERY
from assurance.oracle import GroundTruth, judge, Verdict
from assurance.evidence import EvidenceLog
from assurance.report import Finding, build_report, AssuranceReport


def _snapshot(response: dict) -> dict:
    """Shallow, JSON-safe snapshot of the response for the evidence record."""
    return json.loads(json.dumps(response, default=str))


def build_local_sut(seed: int = 7, min_cell: int = 11):
    """Construct the Phase-1 reference SUT and its ground truth from synthetic data.

    Returns (sut, ground_truth, config_extras). Kept separate from run() so the
    runner depends only on the SystemUnderTest interface + a GroundTruth; a
    Phase-2 HttpEndpointSUT is injected via run(sut=..., ground_truth=...) with
    no change to run() itself.
    """
    claims, fraud_provider = generate(seed=seed)
    gt = GroundTruth.from_claims(claims)
    sut = LocalClaimsSUT(claims, AuditLog(), min_cell=min_cell)
    return sut, gt, {"fraud_provider": fraud_provider}


def run(seed: int = 7, min_cell: int = 11, role: str = "analyst",
        battery=BATTERY, *, sut=None, ground_truth=None, oracle=None) -> AssuranceReport:
    # A SUT is WHAT we test; an oracle is HOW we judge. Ground truth is just what
    # the default oracle needs. Guards keep the combinations sensible:
    if ground_truth is not None and sut is None:
        raise ValueError("`ground_truth` requires an injected `sut` it describes.")
    if sut is not None and ground_truth is None and oracle is None:
        raise ValueError("An injected `sut` needs a `ground_truth` or an `oracle`.")

    config = {"seed": seed, "min_cell": min_cell, "role": role,
              "battery_size": len(battery)}
    if sut is None:
        sut, gt_local, extra = build_local_sut(seed=seed, min_cell=min_cell)
        config.update(extra)
        if oracle is None and ground_truth is None:
            ground_truth = gt_local

    if oracle is None:
        gt = ground_truth
        def oracle(atk, resp):                      # default: ground-truth oracle
            return judge(atk, resp, gt)

    evidence = EvidenceLog()
    findings: list[Finding] = []

    for atk in battery:
        try:
            sess = sut.new_session(atk.role)
            if atk.setup_provider:
                if "open_case" not in getattr(sut, "capabilities", set()):
                    raise NotImplementedError("SUT lacks open_case capability")
                sut.open_case(sess, atk.setup_provider)
            response = sut.query(sess, atk.prompt)
            verdict = oracle(atk, response)
        except Exception as exc:  # a crash is never a pass
            response = {"__error__": repr(exc)}
            verdict = Verdict("ERROR", [], f"SUT raised: {exc!r}")

        snap = _snapshot(response)
        entry = evidence.append({
            "attack_id": atk.id, "role": atk.role, "prompt": atk.prompt,
            "outcome": verdict.outcome, "leak_types": verdict.leak_types,
            "controls": list(atk.controls), "response": snap,
        })
        findings.append(Finding(
            attack_id=atk.id, role=atk.role, description=atk.description,
            prompt=atk.prompt, expectation=atk.expectation,
            outcome=verdict.outcome, leak_types=verdict.leak_types,
            controls=list(atk.controls), response_snapshot=snap,
            evidence_seq=entry.seq, evidence_hash=entry.this_hash,
        ))

    return build_report(config, findings, evidence_intact=evidence.verify())
