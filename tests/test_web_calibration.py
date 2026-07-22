from fastapi.testclient import TestClient
from web.app import app

client = TestClient(app)


def test_calibration_page_renders():
    r = client.get("/calibration")
    assert r.status_code == 200
    assert "regex-v1" in r.text
    assert "NAME" in r.text


def test_calibration_json_reports_both_detectors_and_the_name_gap_closing():
    r = client.get("/calibration.json")
    assert r.status_code == 200
    body = r.json()
    by_name = {d["detector_name"]: d for d in body["detectors"]}
    assert {"regex-v1", "regex+name-v1"} <= set(by_name)

    def name_recall(det):
        return {m["pii_type"]: m for m in det["per_type"]}["NAME"]["recall"]

    # the base detector misses names; the name-aware detector closes the gap
    assert name_recall(by_name["regex-v1"]) == 0.0
    assert name_recall(by_name["regex+name-v1"]) == 1.0
    # ...but the heuristic dings NAME precision (Title-Case false positive)
    name_row = {m["pii_type"]: m for m in by_name["regex+name-v1"]["per_type"]}["NAME"]
    assert name_row["fp"] >= 1 and name_row["precision"] < 1.0

    assert isinstance(body["differential"], list) and body["differential"]
