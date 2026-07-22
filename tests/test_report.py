import json
from assurance.report import Finding, build_report, render_html


def _finding(aid, outcome, leaks, controls):
    return Finding(attack_id=aid, role="analyst", description="d", prompt="p",
                   expectation="DENY", outcome=outcome, leak_types=leaks,
                   controls=controls, response_snapshot={}, evidence_seq=0,
                   evidence_hash="h")


def test_attestation_fails_when_any_hard_leak_present():
    findings = [
        _finding("A1", "PASS", [], ["OWASP-LLM06"]),
        _finding("A4", "LEAK", ["small_cell"], ["HIPAA-MIN-CELL"]),
    ]
    r = build_report({"seed": 7}, findings, evidence_intact=True)
    assert r.attempts == 2 and r.leaked == 1 and r.passed == 1
    assert r.attestation_pass is False


def test_attestation_passes_when_all_pass():
    findings = [_finding("A1", "PASS", [], ["OWASP-LLM06"])]
    r = build_report({"seed": 7}, findings, evidence_intact=True)
    assert r.attestation_pass is True


def test_control_coverage_aggregates_pass_fail():
    findings = [
        _finding("A1", "PASS", [], ["OWASP-LLM06"]),
        _finding("A2", "LEAK", ["direct_id"], ["OWASP-LLM06"]),
    ]
    r = build_report({"seed": 7}, findings, evidence_intact=True)
    cov = {c.control_id: c for c in r.control_coverage}
    assert cov["OWASP-LLM06"].tested == 2
    assert cov["OWASP-LLM06"].passed == 1
    assert cov["OWASP-LLM06"].failed == 1


def test_to_json_roundtrips_and_html_renders():
    findings = [_finding("A1", "PASS", [], ["OWASP-LLM06"])]
    r = build_report({"seed": 7}, findings, evidence_intact=True)
    parsed = json.loads(r.to_json())
    assert parsed["attempts"] == 1
    html = render_html(r)
    assert "<html" in html.lower() and "A1" in html


def test_render_html_escapes_finding_text():
    findings = [_finding("A1", "LEAK", ["direct_id"], ["OWASP-LLM06"])]
    findings[0].description = "<script>alert(1)</script>"
    r = build_report({"seed": 7}, findings, evidence_intact=True)
    out = render_html(r)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out
