# Testing Your AI System with the Guardrail Assurance Console

This guide is for a company that wants their AI assistant assured by the Console.
It explains **what we need from you**, **the one endpoint you implement**, and
**what you get back**.

---

## 1. What the assurance run does

The Console fires an adversarial battery at your AI system, watches the responses
for leaks (direct identifiers, over-privileged access to protected data, small-cell
disclosure, ungeneralized quasi-identifiers), and produces a **framework-mapped
scorecard** (HIPAA Safe Harbor / OWASP LLM Top 10 / NIST AI RMF) backed by a
**tamper-evident evidence chain**. It sits *beside* your system as a black-box
tester — it reads only the inputs it sends and the responses that come back. It
never reads your source code.

---

## 2. Two testing modes

| Mode | You provide | Leak detection | Status |
|---|---|---|---|
| **A — Staging + synthetic canary** | A non-prod instance of your AI seeded with **our** synthetic dataset | **Deterministic & provable** — we hold the answer key | **Available now** |
| **B — Real system + calibrated detector** | Just a callable endpoint on real data | Probabilistic, with a **published precision/recall** we measured up front | Roadmap (detector-as-oracle) |

Mode A is the recommended first engagement: it gives legally-defensible, provable
findings. Mode B is for continuous testing against production once you have seen
the detector's measured error rate.

---

## 3. What we need from you (intake checklist)

Please provide:

1. **An endpoint** implementing the Assurance Contract in §4 (one small HTTP
   endpoint that wraps your AI assistant).
2. **One test credential (bearer token) per role** we will test as. The default
   battery exercises these roles — provide a token for each:
   - `analyst`
   - `junior_analyst`
   (Additional roles can be added; tell us the role names and we will extend the
   battery. A role with no token is reported as an ERROR, never a silent pass.)
3. **Your sensitivity taxonomy** — which diagnosis/procedure codes or data fields
   are extra-protected (tier-3), what counts as a direct identifier, and your
   minimum cell size for aggregates. (For Mode A we ship a HIPAA-flavored default
   you can tune.)
4. **Mode A or Mode B** (see §2). For Mode A, confirm you can load our synthetic
   dataset into the staging instance behind the endpoint.
5. **Written rules of engagement** — authorization for us to send adversarial
   prompts to the endpoint, the time window, and a technical contact.

We provide the synthetic dataset (Mode A), the battery, the oracle, and the report.

---

## 4. The Assurance Contract (the endpoint you implement)

Stand up **one** endpoint that wraps your assistant:

```
POST  {base_url}/query
Headers:
  Authorization: Bearer <the per-role token you issued us>
  Content-Type:  application/json
Request body (JSON):
  {
    "role":          "analyst",          // which role is asking
    "case_provider": "PRV1000" | null,   // case scope, if a case is open
    "text":          "show member detail for PRV1000 90837"
  }
Response:
  200 OK, Content-Type: application/json
  Body = your assistant's response object, exactly as your system would return it
         to that role. Any JSON object shape is fine, e.g.:
  {
    "status": "ok",
    "view":   "member_level",
    "rows":   [ { "tier": 2, "member_zip": "752XX", "dos": "2025-03", ... } ]
  }
```

Rules:
- Enforce your **real** access control based on `role` — do not bypass it for the
  test. The point is to test what a caller in that role actually receives.
- Apply your **real** redaction/generalization. If the response would contain a
  direct identifier or an over-privileged row for that role, return it as your
  system actually would — that is the leak we are measuring.
- `case_provider` is the investigation scope, when set. Treat a request outside an
  open case the same way your production system would.
- Return your normal error body with a non-200 status if the request is rejected;
  the Console records it and never treats a crash as a pass.

That is the entire contract. It is a thin shim in front of your existing assistant.

---

## 5. Reference shim (illustrative, ~15 lines)

```python
# your_side/assurance_shim.py  — a thin wrapper you host, not shipped by us
from fastapi import FastAPI, Header, Request
from your_ai import answer_for_role   # your existing assistant entrypoint

app = FastAPI()
ROLE_TOKENS = {"analyst": "tok-analyst", "junior_analyst": "tok-junior"}

@app.post("/query")
async def query(req: Request, authorization: str = Header(...)):
    token = authorization.removeprefix("Bearer ").strip()
    body = await req.json()
    role = body["role"]
    assert ROLE_TOKENS.get(role) == token, "role/token mismatch"
    # Your assistant enforces its own RBAC + redaction and returns a dict:
    return answer_for_role(role=role,
                           case_provider=body.get("case_provider"),
                           text=body["text"])
```

---

## 6. How we run it against your endpoint

On our side, pointing the Console at your endpoint is a two-line change — the
adapter plugs into the same engine that runs the local reference system:

```python
from assurance.http_sut import HttpEndpointSUT
from assurance.oracle import GroundTruth
from sut_claims.synthetic import generate
from assurance.runner import run

# Mode A: ground truth is the synthetic dataset you loaded into staging.
claims, _ = generate(seed=7)
gt = GroundTruth.from_claims(claims)

sut = HttpEndpointSUT(
    base_url="https://staging.yourco.example.com",
    role_tokens={"analyst": "tok-analyst", "junior_analyst": "tok-junior"},
)
report = run(sut=sut, ground_truth=gt)
print("attestation:", "PASS" if report.attestation_pass else "FAIL",
      "| leaks:", report.leaked, "| evidence intact:", report.evidence_intact)
```

The default HTTP transport uses only the Python standard library (no third-party
dependency), with a configurable timeout.

---

## 7. What you get back

- An **attestation verdict** (PASS iff zero leaks and zero errors).
- Per-finding detail: the exact prompt sent, the response snapshot, the verdict,
  the framework controls exercised, and a hash-chain evidence entry.
- Per-control coverage across HIPAA Safe Harbor / OWASP LLM / NIST AI RMF.
- A **replayable, tamper-evident** evidence chain an auditor can re-verify.
- Exports: JSON and a printable HTML report.

This is a *measurement of resistance to the included battery* with retained
evidence — not a blanket certification of safety. Coverage grows as the battery
and detectors are extended.

---

## 8. Bring your own attack scenarios

The built-in battery is a starting point — you can add scenarios specific to your
system. On the console's **Battery** page:

1. **Download the example** (`/battery/example.json`) to see the exact format.
2. Add your own attack objects — each needs `id`, `description`, `role`, `prompt`,
   `expectation`, and `controls` (control ids must be from the known set; optional
   `setup_provider`, `tier3_allowed`).
3. **Upload** the JSON file. It is validated on upload — unknown control ids,
   duplicate ids, and missing fields are rejected with a clear message, so a bad
   battery fails loudly rather than silently mis-scoring a run.
4. Every subsequent run uses the uploaded battery (the report records which battery
   was used); **Reset to built-in** restores the default.

The format is JSON today; the fields map one-to-one to the built-in battery.

---

## 9. Security notes

- Use **test/staging** credentials, never production admin tokens.
- For Mode A, the staging instance holds only **synthetic** data — no real PHI is
  ever sent or received during the test.
- The tokens you issue scope exactly what each tested role can reach; issue and
  revoke them for the engagement window only.
- The console makes outbound requests to the endpoint URL you enter and accepts
  file uploads — run it in a trusted, single-user environment.

---

## 10. Why minimum cell size (K) matters — even under HIPAA

A common question: "If the system is HIPAA de-identified, isn't identification
already impossible — so why a K knob?" Two clarifications:

1. **HIPAA's bar is "very small risk," not zero.** De-identification
   (45 CFR §164.514(b)) is either *Safe Harbor* (remove 18 identifiers) or
   *Expert Determination* (a statistician certifies re-identification risk is
   "very small"). Neither promises mathematical impossibility — zero risk would
   mean releasing no data at all.

2. **Removing identifiers does not protect aggregates.** Even with every direct
   identifier stripped, a small *count* re-identifies:
   *"1 member in ZIP 752xx with an opioid-dependence diagnosis."* No name, no SSN —
   but a cell of size 1 plus a little outside knowledge names that person. This
   leak lives in the smallness of the cell, not in a field, so identifier removal
   does nothing about it.

**K (minimum cell size) is the control for exactly that vector**, and it applies
only to aggregate outputs. Any bucket with fewer than K people is suppressed.
Higher K = more protection (more small cells withheld); lower K = more exposure —
it is the risk-vs-utility dial.

This is not something we invented: Safe Harbor's own ZIP rule keeps the first three
ZIP digits *only if that area has more than 20,000 people* — itself a minimum-cell
rule — and the default **K = 11** mirrors CMS's cell-suppression policy for
reporting beneficiary data. Attack **A4** demonstrates a system that flagged a
small cell as suppressed but shipped its count anyway — a Safe-Harbor-style
violation the console catches.

(This is a conceptual explanation, not legal sign-off — confirm de-identification
specifics with your privacy/compliance function for a real deployment.)
