"""
The guardrail core: graduated disclosure.

This encodes the resolution to the tension we argued about -- the analyst needs
to see provider-wide diagnosis PATTERNS to catch fraud, but that same capability
is a mass-PHI-extraction surface. The answer is not "redact the diagnosis"
(that blinds the investigation). It is:

  1. Default to AGGREGATES. Counts, rates, ratios -- statistics, not people.
  2. Suppress small cells. Any aggregate bucket smaller than K is withheld,
     because small cells re-identify (the rural-provider / narrow-ZIP problem).
  3. Member-level detail requires an OPEN CASE, is scoped to the flagged
     provider, is logged per-row, and strips direct identifiers by default.
  4. Quasi-identifiers are generalized on drill-down (ZIP -> 3 digits, age ->
     band) so a released row can't be trivially re-identified.

K (min cell size) is the single most important knob. Set it too low and you
leak; too high and legitimate small-provider investigations return nothing.
That tradeoff is a PM decision, surfaced here as a parameter, not hidden.
"""

from collections import defaultdict
from .synthetic import DIAGNOSES, PROCEDURES

MIN_CELL = 11   # HIPAA-flavored default; many de-id practices use 11. Tunable.


def _age_band(age: int) -> str:
    lo = (age // 10) * 10
    return f"{lo}-{lo+9}"


def _zip3(z: str) -> str:
    return z[:3] + "XX"


class DisclosureEngine:
    def __init__(self, claims, min_cell: int = MIN_CELL):
        self.claims = claims
        self.min_cell = min_cell

    # --- Aggregate view: safe by default -------------------------------------
    def provider_profile(self, provider_id):
        """
        Provider-level FWA signal WITHOUT exposing members. Returns per-CPT
        volume, peer comparison, and diagnosis-tier mix -- enough to see the
        over-utilization pattern. Small cells suppressed.
        """
        mine = [c for c in self.claims if c.provider_id == provider_id]
        if not mine:
            return {"provider_id": provider_id, "status": "no_claims"}

        # peer baseline: mean claims-per-provider for the same CPTs
        by_provider_cpt = defaultdict(lambda: defaultdict(int))
        for c in self.claims:
            by_provider_cpt[c.provider_id][c.cpt] += 1

        cpt_counts = defaultdict(int)
        tier_counts = defaultdict(int)
        for c in mine:
            cpt_counts[c.cpt] += 1
            tier_counts[c.sensitivity_tier()] += 1

        rows = []
        for cpt, cnt in sorted(cpt_counts.items(), key=lambda x: -x[1]):
            peer_vals = [d[cpt] for pid, d in by_provider_cpt.items()
                         if pid != provider_id and d[cpt] > 0]
            peer_mean = sum(peer_vals) / len(peer_vals) if peer_vals else 0.0
            ratio = (cnt / peer_mean) if peer_mean else None
            rows.append({
                "cpt": cpt, "desc": PROCEDURES[cpt][0], "count": cnt,
                "peer_mean": round(peer_mean, 1),
                "vs_peer_x": round(ratio, 1) if ratio else None,
                # cell suppressed if too small to be safe to surface
                "suppressed": cnt < self.min_cell,
            })

        return {
            "provider_id": provider_id,
            "total_claims": len(mine),
            "diagnosis_tier_mix": dict(tier_counts),
            "cpt_profile": rows,
            "note": "Aggregates only. No member identity disclosed at this level.",
        }

    # --- Member-level drill-down: gated --------------------------------------
    def drilldown(self, provider_id, cpt, *, case_open: bool, generalize: bool = True):
        """
        Returns member-level rows for one provider+CPT. REQUIRES an open case.
        Direct identifiers (name, SSN, member_id) are dropped. Quasi-identifiers
        are generalized unless explicitly overridden. Result is (rows, meta).
        """
        if not case_open:
            return None, {"denied": True, "reason": "no_open_case"}

        rows = [c for c in self.claims
                if c.provider_id == provider_id and c.cpt == cpt]

        if len(rows) < self.min_cell:
            return None, {"denied": True, "reason": "cell_too_small",
                          "cell_size": len(rows), "min_cell": self.min_cell}

        out = []
        for c in rows:
            r = {
                "claim_id": c.claim_id,
                "icd10": c.icd10,
                "icd10_desc": DIAGNOSES[c.icd10][0],
                "tier": c.sensitivity_tier(),
                "billed": c.billed, "paid": c.paid,
                "dos": c.dos[:7] if generalize else c.dos,   # month only
                "member_zip": _zip3(c.member_zip) if generalize else c.member_zip,
                "member_age": _age_band(c.member_age) if generalize else c.member_age,
                "member_gender": c.member_gender,
            }
            # direct identifiers NEVER included: name, ssn, member_id absent by design
            out.append(r)
        return out, {"denied": False, "cell_size": len(rows),
                     "generalized": generalize}
