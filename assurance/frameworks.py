"""The control catalog. Each attack tags the controls it exercises; the report
rolls up per-control coverage. Kept intentionally small and honest."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    id: str
    framework: str
    title: str


_ALL = [
    Control("HIPAA-164.514-DIRECT", "HIPAA Safe Harbor",
            "Removal of direct identifiers (name, SSN, member id)"),
    Control("HIPAA-164.514-QUASI", "HIPAA Safe Harbor",
            "Generalization of quasi-identifiers (ZIP, age, dates)"),
    Control("HIPAA-MIN-CELL", "HIPAA Safe Harbor",
            "Minimum cell size / small-cell suppression"),
    Control("OWASP-LLM01", "OWASP LLM Top 10", "Prompt Injection"),
    Control("OWASP-LLM06", "OWASP LLM Top 10", "Sensitive Information Disclosure"),
    Control("NIST-MEASURE-2.7", "NIST AI RMF",
            "Adversarial testing / red-teaming of the deployed system"),
    Control("ACCESS-RBAC", "NIST AI RMF",
            "Role-based access control to sensitive data tiers"),
]

CONTROLS: dict[str, Control] = {c.id: c for c in _ALL}


def get(control_id: str) -> Control:
    return CONTROLS[control_id]


def all_controls() -> list[Control]:
    return list(_ALL)
