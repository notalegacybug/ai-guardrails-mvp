from fastapi.testclient import TestClient
import web.app as W
from web.app import app

client = TestClient(app)


def test_blank_url_runs_local_reference():
    r = client.post("/run", data={"seed": "7", "min_cell": "11", "role": "analyst",
                                  "endpoint_url": ""})
    assert r.status_code == 200
    body = client.get("/report.json").json()
    assert "local" in body["config"]["target"].lower()
    assert body["attempts"] == 8
    assert body["attestation_pass"] is False   # local small-cell leak at K=11


def test_url_routes_to_http_endpoint_sut(monkeypatch):
    from assurance.http_sut import HttpEndpointSUT

    # Replace the SUT constructor the handler uses with one that injects a fake
    # transport, so no real network call happens.
    def fake_ctor(url, tokens, **kw):
        return HttpEndpointSUT(url, tokens,
                              transport=lambda u, h, b, t: {"status": "denied"})

    monkeypatch.setattr(W, "HttpEndpointSUT", fake_ctor)

    r = client.post("/run", data={
        "seed": "7", "min_cell": "11", "role": "analyst",
        "endpoint_url": "https://staging.acme.example.com",
        "analyst_token": "tok-a", "junior_analyst_token": "tok-j",
    })
    assert r.status_code == 200
    body = client.get("/report.json").json()
    assert body["config"]["target"] == "https://staging.acme.example.com"
    assert body["attempts"] == 8
    # every probe was denied by the fake external system -> no leaks
    assert body["attestation_pass"] is True


def test_real_data_mode_uses_detector_oracle(monkeypatch):
    from assurance.http_sut import HttpEndpointSUT

    # Fake external system that leaks an SSN in every response.
    def fake_ctor(url, tokens, **kw):
        return HttpEndpointSUT(
            url, tokens,
            transport=lambda u, h, b, t: {"status": "ok",
                                          "rows": [{"note": "ssn 123-45-6789"}]})

    monkeypatch.setattr(W, "HttpEndpointSUT", fake_ctor)

    r = client.post("/run", data={
        "seed": "7", "role": "analyst",
        "endpoint_url": "https://prod.acme.example.com",
        "analyst_token": "a", "junior_analyst_token": "j",
        "data_mode": "real",
    })
    assert r.status_code == 200
    body = client.get("/report.json").json()
    assert "detector" in body["config"]["mode"]     # Mode B, no ground truth
    assert body["leaked"] >= 1                       # detector caught the SSN
    assert body["attestation_pass"] is False
