"""
The assistant layer -- what the analyst actually talks to.

This is deliberately NOT an LLM in the prototype. It's a rules-based stand-in
that exposes the same attack surface an LLM would, so we can red-team the
GUARDRAILS deterministically. The point of the project is the guardrail layer,
not the language model; swapping a real LLM in later changes the parser, not the
access-control spine.

Threats this layer is responsible for:
  - Direct extraction ("dump everything", "show me names/SSNs")
  - Over-retrieval (broad queries that rake in member-level PHI)
  - Indirect injection: instructions hidden INSIDE claim free-text that try to
    escalate what the assistant reveals. Retrieved data is treated as untrusted
    and is never interpreted as commands.
  - Role / case-scope violations
"""

import re
from dataclasses import dataclass
from .disclosure import DisclosureEngine, MIN_CELL
from .audit import AuditLog

# Roles and what tier of member-level detail they may ever unlock (with a case).
ROLE_MAX_TIER = {
    "analyst": 3,          # can investigate behavioral/HIV cases IF case open
    "junior_analyst": 2,   # never sees tier-3 member-level detail
    "readonly": 0,         # aggregates only, never any drill-down
}

# Patterns that indicate an attempt to extract direct identifiers wholesale.
_EXFIL_PATTERNS = [
    r"\b(ssn|social security)\b",
    r"\b(full )?names?\b",
    r"\bevery (member|patient|claim)\b",
    r"\ball (members|patients|claims)\b",
    r"\bdump\b", r"\bexport all\b", r"\braw\b",
    r"\bignore (the |your )?(previous |above )?(instructions|rules)\b",
]

# Marker for detecting injected instructions embedded in retrieved text.
_INJECTION_MARKERS = [
    r"ignore (previous|above|all) instructions",
    r"system:", r"assistant:", r"</?system>",
    r"reveal (the )?(ssn|name|identity)",
    r"disregard (the )?(policy|rules|guardrails)",
]


@dataclass
class Session:
    actor: str
    role: str
    case_id: str | None = None      # set when an investigation case is opened
    case_provider: str | None = None  # case is scoped to ONE provider


class Assistant:
    def __init__(self, claims, audit: AuditLog, min_cell: int = MIN_CELL):
        self.engine = DisclosureEngine(claims, min_cell=min_cell)
        self.audit = audit

    # -- open a case: this is what unlocks (scoped, logged) drill-down --------
    def open_case(self, sess: Session, provider_id: str):
        sess.case_id = f"CASE-{provider_id}"
        sess.case_provider = provider_id
        self.audit.record(sess.actor, sess.role, "CASE_OPENED",
                          sess.case_id, {"provider": provider_id})
        return sess.case_id

    def _looks_like_exfil(self, text: str) -> bool:
        t = text.lower()
        return any(re.search(p, t) for p in _EXFIL_PATTERNS)

    def _scan_injection(self, text: str) -> list[str]:
        t = text.lower()
        return [p for p in _INJECTION_MARKERS if re.search(p, t)]

    def query(self, sess: Session, text: str):
        """
        Main entry point. Returns a dict result. Every path logs.
        """
        # 1. Block direct-extraction intent outright.
        if self._looks_like_exfil(text):
            self.audit.record(sess.actor, sess.role, "DENIED", sess.case_id,
                              {"query": text, "reason": "exfil_intent"})
            return {"status": "denied",
                    "reason": "Query appears to request bulk or direct-identifier "
                              "extraction. Not permitted."}

        # 2. Aggregate provider profile -- always allowed (no member identity).
        m = re.search(r"(prv\d{4})", text.lower())
        if "pattern" in text.lower() or "profile" in text.lower() or "over" in text.lower():
            if not m:
                return {"status": "need_input", "reason": "Specify a provider id."}
            prof = self.engine.provider_profile(m.group(1).upper())
            self.audit.record(sess.actor, sess.role, "AGGREGATE_QUERY",
                              sess.case_id, {"provider": m.group(1).upper()})
            return {"status": "ok", "view": "aggregate", "data": prof}

        # 3. Member-level drill-down -- gated by case + role + cell size.
        if "member" in text.lower() or "detail" in text.lower() or "drill" in text.lower():
            if not m:
                return {"status": "need_input", "reason": "Specify a provider id."}
            provider = m.group(1).upper()
            cptm = re.search(r"\b(\d{5}|[a-z]\d{4})\b", text.lower())
            cpt = cptm.group(1).upper() if cptm else "90837"

            # role/case-scope enforcement
            if sess.case_provider != provider:
                self.audit.record(sess.actor, sess.role, "DENIED", sess.case_id,
                                  {"query": text, "reason": "out_of_case_scope",
                                   "requested": provider})
                return {"status": "denied",
                        "reason": f"No open case scoped to {provider}."}

            rows, meta = self.engine.drilldown(provider, cpt,
                                               case_open=bool(sess.case_id))
            if meta.get("denied"):
                self.audit.record(sess.actor, sess.role, "DENIED", sess.case_id,
                                  {"query": text, **meta})
                return {"status": "denied", "reason": meta["reason"], "meta": meta}

            # role tier ceiling: filter out rows above the role's max tier
            max_tier = ROLE_MAX_TIER.get(sess.role, 0)
            visible = [r for r in rows if r["tier"] <= max_tier]
            suppressed = len(rows) - len(visible)
            self.audit.record(sess.actor, sess.role, "DRILLDOWN", sess.case_id,
                              {"provider": provider, "cpt": cpt,
                               "rows_returned": len(visible),
                               "rows_tier_suppressed": suppressed})
            return {"status": "ok", "view": "member_level",
                    "rows": visible, "tier_suppressed": suppressed, "meta": meta}

        return {"status": "unhandled",
                "reason": "Query not understood. Try 'show provider PRV1000 pattern'."}

    def ingest_claim_text(self, sess: Session, free_text: str):
        """
        Simulates retrieved free-text (e.g. an 837 NTE note) flowing toward the
        model. We scan for injected instructions and neutralize them -- the text
        is DATA, never commands. Returns (safe_text, findings).
        """
        findings = self._scan_injection(free_text)
        if findings:
            self.audit.record(sess.actor, sess.role, "INJECTION_NEUTRALIZED",
                              sess.case_id, {"markers": findings})
        # Neutralize by quoting/escaping; a real system would strip or sandbox.
        safe = "[UNTRUSTED CLAIM TEXT] " + free_text.replace("\n", " ")
        return safe, findings
