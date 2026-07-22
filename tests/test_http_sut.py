import pytest

from assurance.http_sut import HttpEndpointSUT
from assurance.runner import run
from assurance.oracle import GroundTruth


def _fake_transport(canned):
    """A stand-in transport that records calls and returns a canned response."""
    calls = []

    def transport(url, headers, body, timeout):
        calls.append({"url": url, "headers": headers, "body": body})
        return canned

    transport.calls = calls
    return transport


def test_query_posts_contract_shape_with_auth():
    t = _fake_transport({"status": "ok"})
    sut = HttpEndpointSUT("https://ai.example.com/", {"analyst": "tok-A"}, transport=t)
    sess = sut.new_session("analyst")
    sut.open_case(sess, "PRV1000")
    resp = sut.query(sess, "show pattern")

    assert resp == {"status": "ok"}
    call = t.calls[0]
    assert call["url"] == "https://ai.example.com/query"          # trailing slash normalized
    assert call["headers"]["Authorization"] == "Bearer tok-A"     # per-role bearer token
    assert call["body"] == {"role": "analyst",
                            "case_provider": "PRV1000",
                            "text": "show pattern"}


def test_capabilities_is_instance_level():
    a = HttpEndpointSUT("https://x", {"r": "t"}, transport=_fake_transport({}))
    b = HttpEndpointSUT("https://x", {"r": "t"}, transport=_fake_transport({}))
    a.capabilities.add("mutated")
    assert "mutated" not in b.capabilities          # not shared class state


def test_unknown_role_without_credential_raises():
    sut = HttpEndpointSUT("https://x", {"analyst": "t"}, transport=_fake_transport({}))
    with pytest.raises(KeyError):
        sut.new_session("junior_analyst")


def test_non_dict_response_is_rejected():
    sut = HttpEndpointSUT("https://x", {"analyst": "t"},
                          transport=_fake_transport(["not", "a", "dict"]))
    sess = sut.new_session("analyst")
    with pytest.raises(RuntimeError):
        sut.query(sess, "hi")


def test_plugs_into_runner_with_injected_ground_truth():
    # A fake external system that always denies -> every attack PASS (no leak).
    t = _fake_transport({"status": "denied", "reason": "policy"})
    sut = HttpEndpointSUT("https://ai.example.com",
                          {"analyst": "a", "junior_analyst": "j"}, transport=t)
    gt = GroundTruth(ssns=set(), names=set(), member_ids=set())
    report = run(sut=sut, ground_truth=gt)

    assert report.attempts == 8
    assert all(f.outcome == "PASS" for f in report.findings)
    assert report.attestation_pass is True
