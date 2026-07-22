"""A demo endpoint implementing the Assurance Contract, so you can exercise the
console against an "external" system without needing a real one.

Three modes:
  reference  serve the real guarded reference assistant (sut_claims) over HTTP.
             Point the console at it with Data mode = "synthetic canary" (Mode A):
             you get the true deterministic baseline (A4 small-cell leak, etc.),
             proving the HTTP path end to end.
  leaky      always returns a member SSN/MRN. Data mode = "real data" (Mode B):
             the calibrated detector oracle flags direct_id on every probe.
  clean      always denies. Data mode = "real data" (Mode B): everything PASSes.

Usage:
    python examples/demo_endpoint.py --mode reference --port 8144
    # then in the console (http://127.0.0.1:8000): endpoint URL = http://127.0.0.1:8144

Speaks the contract in docs/handover/how-to-test-your-system.md:
    POST /query  {role, case_provider, text}  ->  200 JSON (the system's response)
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# Make the project importable even without `pip install -e .`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def make_responder(mode):
    """Return a function (body: dict) -> response dict for the chosen mode."""
    if mode == "reference":
        from sut_claims.synthetic import generate
        from sut_claims.assistant import Assistant, Session
        from sut_claims.audit import AuditLog

        claims, _ = generate(seed=7)
        assistant = Assistant(claims, AuditLog())

        def respond(body):
            sess = Session(actor="demo", role=body.get("role", "analyst"))
            if body.get("case_provider"):
                assistant.open_case(sess, body["case_provider"])
            return assistant.query(sess, body.get("text", ""))
        return respond

    if mode == "leaky":
        def respond(body):
            return {"status": "ok", "view": "member_level",
                    "rows": [{"note": "member ssn 123-45-6789, MRN M123456"}]}
        return respond

    if mode == "clean":
        def respond(body):
            return {"status": "denied",
                    "reason": "policy: no member-level PHI returned"}
        return respond

    raise ValueError(f"unknown mode: {mode!r}")


_RESPONDER = None


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            body = {}
        payload = json.dumps(_RESPONDER(body), default=str).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def main():
    global _RESPONDER
    ap = argparse.ArgumentParser(description="Assurance Contract demo endpoint")
    ap.add_argument("--mode", choices=["reference", "leaky", "clean"],
                    default="reference")
    ap.add_argument("--port", type=int, default=8144)
    args = ap.parse_args()

    _RESPONDER = make_responder(args.mode)
    print(f"Demo endpoint [{args.mode}] on http://127.0.0.1:{args.port}/query "
          f"(Ctrl-C to stop)")
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
