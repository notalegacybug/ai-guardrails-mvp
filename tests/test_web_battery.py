import json
from fastapi.testclient import TestClient
from web.app import app

client = TestClient(app)


def _upload(name, records):
    return client.post(
        "/battery/upload",
        files={"battery_file": (name, json.dumps(records).encode(), "application/json")})


def test_battery_page_shows_default():
    client.post("/battery/reset")
    r = client.get("/battery")
    assert r.status_code == 200
    assert "A1" in r.text                      # a default attack id


def test_example_download_is_valid_json():
    r = client.get("/battery/example.json")
    assert r.status_code == 200
    data = json.loads(r.text)
    assert isinstance(data, list) and data[0]["id"] == "A1"


def test_upload_custom_then_run_uses_it():
    r = _upload("mine.json", [
        {"id": "CUST1", "description": "custom probe", "role": "analyst",
         "prompt": "hello", "expectation": "DENY", "controls": ["OWASP-LLM06"]}])
    assert r.status_code == 200
    assert "CUST1" in r.text
    client.post("/run", data={"seed": "7", "min_cell": "11", "role": "analyst",
                              "endpoint_url": ""})
    body = client.get("/report.json").json()
    assert body["attempts"] == 1
    assert body["config"]["battery_size"] == 1
    client.post("/battery/reset")


def test_upload_invalid_shows_error_and_keeps_previous():
    client.post("/battery/reset")
    r = _upload("bad.json", [
        {"id": "X", "description": "d", "role": "a", "prompt": "p",
         "expectation": "DENY", "controls": ["NOPE-1"]}])
    assert r.status_code == 200
    assert "unknown control" in r.text.lower()
    client.post("/run", data={"endpoint_url": ""})
    body = client.get("/report.json").json()
    assert body["attempts"] == 8               # default battery still active


def test_reset_restores_default():
    _upload("c.json", [{"id": "ONE", "description": "d", "role": "analyst",
                        "prompt": "p", "expectation": "DENY", "controls": []}])
    client.post("/battery/reset")
    r = client.get("/battery")
    assert "A1" in r.text
