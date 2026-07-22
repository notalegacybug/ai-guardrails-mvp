from fastapi.testclient import TestClient
from web.app import app

client = TestClient(app)


def test_dashboard_renders():
    r = client.get("/")
    assert r.status_code == 200
    assert "Assurance" in r.text


def test_run_then_report_json():
    r = client.post("/run", data={"seed": "7", "min_cell": "11", "role": "analyst"})
    assert r.status_code == 200
    rj = client.get("/report.json")
    assert rj.status_code == 200
    body = rj.json()
    assert body["attempts"] == 8
    assert body["attestation_pass"] is False  # small-cell leak at min_cell=11


def test_findings_and_detail_and_evidence():
    client.post("/run", data={"seed": "7", "min_cell": "11", "role": "analyst"})
    assert client.get("/findings").status_code == 200
    assert client.get("/findings/A4").status_code == 200
    assert client.get("/evidence").status_code == 200


def test_report_html_download():
    client.post("/run", data={"seed": "7", "min_cell": "11", "role": "analyst"})
    r = client.get("/report.html")
    assert r.status_code == 200
    assert "<html" in r.text.lower()


def test_finding_detail_has_explicit_back_link():
    client.post("/run", data={"seed": "7", "min_cell": "11", "role": "analyst"})
    r = client.get("/findings/A4")
    assert "Back to findings" in r.text


def test_standalone_report_links_back_to_console():
    client.post("/run", data={"seed": "7", "min_cell": "11", "role": "analyst"})
    r = client.get("/report.html")
    assert 'href="/"' in r.text  # standalone report must not be a dead end


def test_dashboard_has_self_guided_explanation():
    t = client.get("/").text.lower()
    assert "not a runtime shield" in t          # what-it-is intro
    assert "what do these terms mean" in t      # the legend
    assert "min cell (k)" in t and "re-identif" in t   # min-cell is explained


def test_findings_page_has_guidance():
    client.post("/run", data={"seed": "7", "min_cell": "11", "role": "analyst",
                              "endpoint_url": ""})
    assert "each row is one attack" in client.get("/findings").text.lower()
