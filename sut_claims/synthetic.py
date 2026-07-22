"""
Synthetic claims data generator.

NOTHING here is real. Every member, provider, ZIP, and diagnosis is fabricated.
This exists so the whole system can be demonstrated and red-teamed without ever
touching PHI. The writeup should state this loudly: the prototype is trained and
tested exclusively on synthetic data.

ASSUMPTION FLAG (confirm/overrule): I modeled a claim on the fields you named from
your 837/835 experience -- member id, DOS, CPT/HCPCS, ICD-10, provider, billed vs
paid amount -- plus quasi-identifiers (ZIP, age, gender) because those are the
re-identification vector we care about. If real 837s you worked carried other
fields that matter to an FWA investigation (rendering vs billing provider NPI,
place-of-service, modifiers), tell me and I'll add them.
"""

import random
from dataclasses import dataclass, asdict, field

# --- Diagnosis codes tagged by sensitivity tier. -----------------------------
# TIER 3 = extra-protected (42 CFR Part 2 behavioral/substance use, HIV, state
# special-protection). TIER 2 = standard PHI diagnosis. TIER 1 = routine.
# The whole point: not all ICD-10 is equal. This table encodes that judgment.
DIAGNOSES = {
    # code: (description, tier)
    "F11.20": ("Opioid dependence, uncomplicated", 3),
    "F32.9":  ("Major depressive disorder", 3),
    "F41.1":  ("Generalized anxiety disorder", 3),
    "B20":    ("HIV disease", 3),
    "F10.20": ("Alcohol dependence", 3),
    "E11.9":  ("Type 2 diabetes without complications", 2),
    "I10":    ("Essential hypertension", 2),
    "J45.909":("Unspecified asthma, uncomplicated", 2),
    "M54.5":  ("Low back pain", 1),
    "Z00.00": ("General adult medical exam", 1),
}

# CPT/HCPCS with the ICD-10 codes that make them medically plausible.
# Used later to demonstrate CPT<->ICD medical-necessity mismatch (an FWA signal
# you mentioned was automated in tier-one review).
PROCEDURES = {
    "90837": ("Psychotherapy, 60 min", {"F32.9", "F41.1", "F11.20", "F10.20"}),
    "H0015": ("Intensive outpatient program", {"F11.20", "F10.20"}),
    "99214": ("Office visit, established patient, moderate", {"E11.9", "I10", "J45.909", "M54.5"}),
    "85025": ("Complete blood count", {"B20", "E11.9"}),
    "80053": ("Comprehensive metabolic panel", {"B20", "E11.9", "I10"}),
    "99396": ("Preventive visit, established, 40-64 yrs", {"Z00.00"}),
}

FIRST = ["Alex","Jordan","Casey","Riley","Morgan","Taylor","Jamie","Avery","Quinn","Reese"]
LAST  = ["Rivera","Chen","Okafor","Patel","Nguyen","Silva","Kim","Haddad","Rossi","Diaz"]


@dataclass
class Claim:
    claim_id: str
    member_id: str
    member_name: str          # a DIRECT identifier -- must never leave the system
    member_ssn: str           # a DIRECT identifier -- must never leave the system
    member_zip: str           # QUASI-identifier (Safe Harbor: only first 3 digits allowed)
    member_age: int           # QUASI-identifier
    member_gender: str        # QUASI-identifier
    provider_id: str
    provider_name: str
    provider_zip: str
    dos: str                  # date of service -- full date is a Safe Harbor identifier
    cpt: str
    icd10: str
    billed: float
    paid: float

    def sensitivity_tier(self) -> int:
        return DIAGNOSES[self.icd10][1]


def _rand_zip(rng):  # 5-digit fabricated ZIP
    return f"{rng.randint(10000, 99999)}"


def generate(seed: int = 7,
             n_providers: int = 12,
             claims_per_normal_provider: int = 40,
             inject_fraud: bool = True):
    """
    Returns (claims, fraud_provider_id).

    One provider is seeded as an over-utilization fraud pattern: abnormally high
    volume of a tier-3 (behavioral health) procedure concentrated in a narrow
    age band -- mirroring the real vendor case where a behavioral-health provider
    showed far higher services-per-patient than peers. That provider is the one
    a tier-two investigation would legitimately need to look across.
    """
    rng = random.Random(seed)
    claims = []
    cid = 0
    providers = [f"PRV{1000+i}" for i in range(n_providers)]
    fraud_provider = providers[0] if inject_fraud else None

    for p in providers:
        pname = f"{rng.choice(FIRST)} {rng.choice(LAST)} MD"
        pzip = _rand_zip(rng)
        n = claims_per_normal_provider
        for _ in range(n):
            member_id = f"M{rng.randint(100000, 999999)}"
            cpt = rng.choice(list(PROCEDURES))
            icd = rng.choice(list(PROCEDURES[cpt][1]))
            billed = round(rng.uniform(80, 400), 2)
            paid = round(billed * rng.uniform(0.5, 0.95), 2)
            cid += 1
            claims.append(Claim(
                claim_id=f"C{cid:06d}", member_id=member_id,
                member_name=f"{rng.choice(FIRST)} {rng.choice(LAST)}",
                member_ssn=f"{rng.randint(100,899)}-{rng.randint(10,99)}-{rng.randint(1000,9999)}",
                member_zip=_rand_zip(rng), member_age=rng.randint(5, 90),
                member_gender=rng.choice(["M", "F"]),
                provider_id=p, provider_name=pname, provider_zip=pzip,
                dos=f"2025-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}",
                cpt=cpt, icd10=icd, billed=billed, paid=paid,
            ))

    if inject_fraud:
        # Fraud pattern: PRV1000 bills 90837 (60-min psychotherapy) at 4x volume,
        # concentrated in ages 30-39, tier-3 diagnoses -- the exact case where the
        # investigation NEEDS diagnosis visibility but the diagnosis is crown-jewel.
        for _ in range(160):
            cid += 1
            claims.append(Claim(
                claim_id=f"C{cid:06d}", member_id=f"M{rng.randint(100000, 999999)}",
                member_name=f"{rng.choice(FIRST)} {rng.choice(LAST)}",
                member_ssn=f"{rng.randint(100,899)}-{rng.randint(10,99)}-{rng.randint(1000,9999)}",
                member_zip=str(rng.choice([75201, 75202, 75203])),  # tight ZIP cluster -> small cells
                member_age=rng.randint(30, 39), member_gender=rng.choice(["M", "F"]),
                provider_id=fraud_provider, provider_name="Sam Rivera MD",
                provider_zip="75201",
                dos=f"2025-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}",
                cpt="90837", icd10=rng.choice(["F32.9", "F41.1", "F11.20"]),
                billed=round(rng.uniform(180, 220), 2),
                paid=round(rng.uniform(150, 200), 2),
            ))

    rng.shuffle(claims)
    return claims, fraud_provider


if __name__ == "__main__":
    claims, fraud = generate()
    print(f"generated {len(claims)} synthetic claims; seeded fraud provider = {fraud}")
    tier3 = sum(1 for c in claims if c.sensitivity_tier() == 3)
    print(f"tier-3 (extra-protected) claims: {tier3}")
