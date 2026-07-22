import pytest

from assurance.runner import run
from assurance.oracle import GroundTruth


def test_run_uses_injected_sut_and_ground_truth():
    """An external SUT + its ground truth can be injected without touching run()."""
    class FakeSUT:
        capabilities = {"open_case"}
        def new_session(self, role): return {"role": role}
        def open_case(self, session, provider_id): pass
        # A direct-identifier KEY in every response -> oracle flags direct_id.
        def query(self, session, text): return {"status": "ok", "rows": [{"member_ssn": "x"}]}

    empty_gt = GroundTruth(ssns=set(), names=set(), member_ids=set())
    report = run(sut=FakeSUT(), ground_truth=empty_gt)

    assert report.attempts == 8
    # Every attack hits the injected SUT (not the local one), which always leaks:
    assert all(f.outcome == "LEAK" and "direct_id" in f.leak_types
               for f in report.findings)
    assert report.attestation_pass is False


def test_run_partial_injection_raises():
    """Injecting a SUT without ground truth (or vice versa) is a usage error."""
    class FakeSUT:
        capabilities = set()
        def new_session(self, role): return None
        def open_case(self, session, provider_id): pass
        def query(self, session, text): return {"status": "ok"}

    with pytest.raises(ValueError):
        run(sut=FakeSUT())
    with pytest.raises(ValueError):
        run(ground_truth=GroundTruth(ssns=set(), names=set(), member_ids=set()))


def test_baseline_known_outcomes_at_seed_7():
    report = run(seed=7, min_cell=11)
    by_id = {f.attack_id: f for f in report.findings}

    assert report.attempts == 8
    # Blocked/clean probes pass:
    for aid in ("A1", "A2", "A3", "A5", "A6", "A7", "A8"):
        assert by_id[aid].outcome == "PASS", (aid, by_id[aid].leak_types)
    # A4 exposes the small-cell defect in the aggregate view:
    assert by_id["A4"].outcome == "LEAK"
    assert "small_cell" in by_id["A4"].leak_types

    assert report.leaked == 1
    assert report.attestation_pass is False
    assert report.evidence_intact is True


def test_lowering_min_cell_removes_small_cell_leak():
    report = run(seed=7, min_cell=1)
    by_id = {f.attack_id: f for f in report.findings}
    assert by_id["A4"].outcome == "PASS"
    assert report.attestation_pass is True


def test_sut_exception_is_error_not_pass(monkeypatch):
    import assurance.runner as R

    class BoomSUT:
        capabilities = {"open_case"}
        def new_session(self, role): return object()
        def open_case(self, s, p): pass
        def query(self, s, t): raise RuntimeError("boom")

    monkeypatch.setattr(R, "LocalClaimsSUT", lambda *a, **k: BoomSUT())
    report = R.run(seed=7)
    assert all(f.outcome == "ERROR" for f in report.findings)
    assert report.attestation_pass is False


def test_new_session_exception_is_error(monkeypatch):
    import assurance.runner as R

    class BoomSessionSUT:
        capabilities = {"open_case"}
        def new_session(self, role): raise RuntimeError("session boom")
        def open_case(self, s, p): pass
        def query(self, s, t): return {"status": "ok"}

    monkeypatch.setattr(R, "LocalClaimsSUT", lambda *a, **k: BoomSessionSUT())
    report = R.run(seed=7)
    assert report.attempts == 8
    assert all(f.outcome == "ERROR" for f in report.findings)
    assert report.attestation_pass is False


def test_run_with_detector_oracle_and_no_ground_truth():
    """Mode B: an external SUT judged by the detector oracle — no ground truth."""
    from assurance.oracle import detector_oracle
    from assurance.detector import RegexDetector

    class SsnLeakSUT:
        capabilities = {"open_case"}
        def new_session(self, role): return {"role": role}
        def open_case(self, s, p): pass
        def query(self, s, t):
            return {"status": "ok", "rows": [{"note": "ssn 123-45-6789"}]}

    report = run(sut=SsnLeakSUT(), oracle=detector_oracle(RegexDetector()))
    assert report.attempts == 8
    assert all(f.outcome == "LEAK" and "direct_id" in f.leak_types
               for f in report.findings)
    assert report.attestation_pass is False
