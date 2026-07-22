"""HttpEndpointSUT — point the assurance engine at an EXTERNAL system over HTTP.

The company implements one small endpoint speaking the fixed *Assurance Contract*:

    POST {base_url}/query
    Headers: Authorization: Bearer <per-role token>
             Content-Type: application/json
    Body:    {"role": <str>, "case_provider": <str|null>, "text": <str>}
    Return:  200, JSON body = the AI system's response object (any shape the
             oracle/detector consume, e.g. {"status": ..., "view": ..., "rows": [...]}).

This adapter implements the same SystemUnderTest interface as LocalClaimsSUT, so it
drops straight into run(sut=..., ground_truth=...) with no engine changes.

Transport is injectable so tests run without a live server and NO third-party HTTP
dependency is required — the default transport uses stdlib urllib.
"""

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class HttpSession:
    role: str
    token: str
    case_provider: str | None = None


def _default_transport(url: str, headers: dict, body: dict, timeout: int) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:200]
        raise RuntimeError(f"SUT HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"SUT unreachable: {exc.reason}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"SUT returned non-JSON: {raw[:200]!r}") from exc


class HttpEndpointSUT:
    """External-SUT adapter speaking the fixed Assurance Contract over HTTP."""

    def __init__(self, base_url: str, role_tokens: dict[str, str],
                 *, transport=None, timeout: int = 30) -> None:
        self._url = base_url.rstrip("/") + "/query"
        self._role_tokens = dict(role_tokens)
        self._transport = transport or _default_transport
        self._timeout = timeout
        self.capabilities = {"open_case"}   # instance-level (not shared class state)

    def new_session(self, role: str) -> HttpSession:
        if role not in self._role_tokens:
            raise KeyError(f"no test credential provided for role {role!r}")
        return HttpSession(role=role, token=self._role_tokens[role])

    def open_case(self, session: HttpSession, provider_id: str) -> None:
        # The case scope travels in each query body; no separate HTTP call needed.
        session.case_provider = provider_id

    def query(self, session: HttpSession, text: str) -> dict:
        headers = {
            "Authorization": f"Bearer {session.token}",
            "Content-Type": "application/json",
        }
        body = {"role": session.role,
                "case_provider": session.case_provider,
                "text": text}
        resp = self._transport(self._url, headers, body, self._timeout)
        if not isinstance(resp, dict):
            raise RuntimeError(
                f"SUT response must be a JSON object, got {type(resp).__name__}")
        return resp
