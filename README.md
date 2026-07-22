# ai-guardrails-mvp — Guardrail Assurance Console

A black-box tool that fires an adversarial battery at an AI system-under-test,
detects PHI leaks deterministically against synthetic ground truth, and produces
a framework-mapped scorecard backed by a tamper-evident evidence chain.

It ships with a built-in **reference system-under-test** — the rules-based guarded
claims assistant (`sut_claims/`) on synthetic data — and an external-endpoint
adapter so an org can point the same battery at their own AI (local reference,
synthetic-canary staging, or a calibrated-detector run against real data).

## Layout

- `common/`     — tamper-evident hash-chain primitive
- `sut_claims/` — the reference system-under-test (guarded assistant + synthetic data)
- `assurance/`  — the product: adapter, attack battery, leak oracle, frameworks, runner, report
- `web/`        — FastAPI + Jinja2 + HTMX console

## Setup

```bash
python -m pip install -e ".[dev]"
```

## Run the tests

```bash
python -m pytest -v
```

## Run the console

```bash
python -m uvicorn web.app:app --reload --port 8000
# open http://127.0.0.1:8000/  → Run battery
```

### Try the external-endpoint path

`examples/demo_endpoint.py` is a stand-in "external system" speaking the assurance
contract, so you can exercise the console without a real target:

```bash
python examples/demo_endpoint.py --mode reference --port 8144   # real assistant (Mode A)
python examples/demo_endpoint.py --mode leaky --port 8144       # always leaks (Mode B)
python examples/demo_endpoint.py --mode clean --port 8144       # never leaks (Mode B)
```

Then in the console set the endpoint URL to `http://127.0.0.1:8144` — use Data mode
**synthetic canary** for `reference` (deterministic baseline) or **real data** for
`leaky`/`clean` (calibrated detector oracle).

## Run with Docker

No local Python needed — build once, run anywhere Docker runs:

```bash
docker build -t assurance-console .
docker run --rm -p 8000:8000 assurance-console
# open http://127.0.0.1:8000/
```

The image bundles only the runtime code and its dependencies.

## What the reference run demonstrates

The bundled reference system-under-test carries a realistic guardrail flaw: at the
default `min_cell=11`, small aggregate cells are flagged `suppressed` yet their raw
count is still returned — a HIPAA Safe Harbor min-cell violation. The console
**detects it** (attack **A4**, mapped to `HIPAA-MIN-CELL`) with replayable
evidence. That is the point: the tool surfaces a genuine leak in the system it
tests. Lowering `min_cell` clears the finding, showing how the K threshold trades
exposure against utility.

## Scope

Synthetic data only. No real LLM, no API keys, no network calls. Not a
certification of safety — a measurement of resistance to the included battery.
