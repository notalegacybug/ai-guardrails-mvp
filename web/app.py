"""The Assurance Console — a thin FastAPI + Jinja2 shell over assurance.runner.

Single-user MVP: the most recent report is held in a module-level variable. No
auth, no persistence beyond file export.
"""

from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import (HTMLResponse, JSONResponse, PlainTextResponse,
                               Response)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from assurance.runner import run, build_local_sut
from assurance.report import render_html, AssuranceReport
from assurance.detector import RegexDetector, NameAwareRegexDetector
from assurance.corpus import build_labeled_corpus
from assurance.calibration import calibrate
from assurance.differential import run_differential, DIFF_PROBES
from assurance.http_sut import HttpEndpointSUT
from assurance.oracle import GroundTruth, detector_oracle
from assurance.attacks import BATTERY
from assurance.battery_io import load_battery_json, default_battery_json
from sut_claims.synthetic import generate

_HERE = Path(__file__).parent
app = FastAPI(title="Guardrail Assurance Console")
app.mount("/static", StaticFiles(directory=_HERE / "static"), name="static")
templates = Jinja2Templates(directory=str(_HERE / "templates"))

_LAST_REPORT: AssuranceReport | None = None

# The active attack battery — defaults to the built-in one; a company can upload
# its own via /battery/upload (single-user MVP: held in a module variable).
_ACTIVE_BATTERY = list(BATTERY)
_BATTERY_SOURCE = "default (built-in)"


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(
        request, "dashboard.html",
        {"report": _LAST_REPORT, "battery_source": _BATTERY_SOURCE,
         "battery_count": len(_ACTIVE_BATTERY)})


@app.post("/run", response_class=HTMLResponse)
def do_run(request: Request,
           seed: int = Form(7), min_cell: int = Form(11),
           role: str = Form("analyst"),
           endpoint_url: str = Form(""),
           analyst_token: str = Form(""),
           junior_analyst_token: str = Form(""),
           data_mode: str = Form("canary")):
    global _LAST_REPORT
    url = endpoint_url.strip()
    if url:
        # Test an EXTERNAL system. The server makes outbound requests to this URL
        # — run the console in a trusted environment (single-user, local).
        tokens = {}
        if analyst_token.strip():
            tokens["analyst"] = analyst_token.strip()
        if junior_analyst_token.strip():
            tokens["junior_analyst"] = junior_analyst_token.strip()
        sut = HttpEndpointSUT(url, tokens)
        if data_mode == "real":
            # Mode B: real data, no answer key — the calibrated detector judges.
            _LAST_REPORT = run(seed=seed, min_cell=min_cell, role=role,
                               battery=_ACTIVE_BATTERY,
                               sut=sut,
                               oracle=detector_oracle(NameAwareRegexDetector()))
            _LAST_REPORT.config["mode"] = "real data (detector oracle regex+name-v1)"
        else:
            # Mode A: synthetic canary loaded into their staging -> deterministic.
            claims, _ = generate(seed=seed)
            gt = GroundTruth.from_claims(claims)
            _LAST_REPORT = run(seed=seed, min_cell=min_cell, role=role,
                               battery=_ACTIVE_BATTERY, sut=sut, ground_truth=gt)
            _LAST_REPORT.config["mode"] = "synthetic canary (deterministic)"
        _LAST_REPORT.config["target"] = url
    else:
        # No URL: run our own reference assistant on synthetic data (as before).
        _LAST_REPORT = run(seed=seed, min_cell=min_cell, role=role,
                           battery=_ACTIVE_BATTERY)
        _LAST_REPORT.config["target"] = "local reference (synthetic data)"
        _LAST_REPORT.config["mode"] = "synthetic canary (deterministic)"
    _LAST_REPORT.config["battery_source"] = _BATTERY_SOURCE
    return templates.TemplateResponse(
        request, "_summary.html", {"report": _LAST_REPORT})


@app.get("/findings", response_class=HTMLResponse)
def findings(request: Request):
    return templates.TemplateResponse(
        request, "findings.html", {"report": _LAST_REPORT})


@app.get("/findings/{attack_id}", response_class=HTMLResponse)
def finding_detail(request: Request, attack_id: str):
    f = None
    if _LAST_REPORT:
        f = next((x for x in _LAST_REPORT.findings
                  if x.attack_id == attack_id), None)
    return templates.TemplateResponse(
        request, "finding_detail.html",
        {"finding": f, "attack_id": attack_id})


@app.get("/evidence", response_class=HTMLResponse)
def evidence(request: Request):
    return templates.TemplateResponse(
        request, "evidence.html", {"report": _LAST_REPORT})


@app.get("/report.json")
def report_json():
    if not _LAST_REPORT:
        return JSONResponse({"error": "no run yet"}, status_code=404)
    return JSONResponse(_LAST_REPORT.to_dict())


@app.get("/report.html", response_class=HTMLResponse)
def report_html():
    if not _LAST_REPORT:
        return PlainTextResponse("no run yet", status_code=404)
    return HTMLResponse(render_html(_LAST_REPORT))


def _calibration_data(seed: int = 7):
    corpus = build_labeled_corpus(seed)
    reports = [calibrate(RegexDetector(), corpus),
               calibrate(NameAwareRegexDetector(), corpus)]
    sut, _, _ = build_local_sut(seed=seed)
    diffs = [run_differential(sut, p) for p in DIFF_PROBES]
    return reports, diffs


@app.get("/calibration", response_class=HTMLResponse)
def calibration(request: Request, seed: int = 7):
    reports, diffs = _calibration_data(seed)
    return templates.TemplateResponse(
        request, "calibration.html",
        {"reports": reports, "diffs": diffs, "seed": seed})


@app.get("/calibration.json")
def calibration_json(seed: int = 7):
    reports, diffs = _calibration_data(seed)
    return JSONResponse({
        "detectors": [r.to_dict() for r in reports],
        "differential": [asdict(d) for d in diffs],
    })


def _battery_ctx(error=None, notice=None):
    return {"attacks": _ACTIVE_BATTERY, "source": _BATTERY_SOURCE,
            "error": error, "notice": notice}


@app.get("/battery", response_class=HTMLResponse)
def battery_page(request: Request):
    return templates.TemplateResponse(request, "battery.html", _battery_ctx())


@app.post("/battery/upload", response_class=HTMLResponse)
def battery_upload(request: Request, battery_file: UploadFile = File(...)):
    global _ACTIVE_BATTERY, _BATTERY_SOURCE
    try:
        text = battery_file.file.read().decode("utf-8")
        attacks = load_battery_json(text)
    except (ValueError, UnicodeDecodeError) as exc:
        # Reject loudly; keep the previously-active battery.
        return templates.TemplateResponse(
            request, "battery.html", _battery_ctx(error=str(exc)))
    _ACTIVE_BATTERY = attacks
    _BATTERY_SOURCE = f"custom: {battery_file.filename} ({len(attacks)} attacks)"
    return templates.TemplateResponse(
        request, "battery.html",
        _battery_ctx(notice=f"Loaded {len(attacks)} attacks from "
                            f"{battery_file.filename}."))


@app.post("/battery/reset", response_class=HTMLResponse)
def battery_reset(request: Request):
    global _ACTIVE_BATTERY, _BATTERY_SOURCE
    _ACTIVE_BATTERY = list(BATTERY)
    _BATTERY_SOURCE = "default (built-in)"
    return templates.TemplateResponse(
        request, "battery.html",
        _battery_ctx(notice="Reset to the built-in battery."))


@app.get("/battery/example.json")
def battery_example():
    # The built-in battery serialized — a format template to copy and edit.
    return Response(default_battery_json(), media_type="application/json")
