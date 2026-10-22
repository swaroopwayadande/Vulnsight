"""Normalized finding and summary helpers."""
from dataclasses import asdict, dataclass
from typing import Literal

Severity = Literal["Informational", "Low", "Medium", "High", "Critical"]

@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: Severity
    rationale: str
    evidence: str
    impact: str
    remediation: str
    confidence: str = "Medium"
    limitations: str = "Automated observation; validate in application context."

    def to_dict(self) -> dict:
        return asdict(self)

def severity_summary(findings: list[Finding]) -> dict[str, int]:
    levels = ("Critical", "High", "Medium", "Low", "Informational")
    counts = {level: 0 for level in levels}
    for finding in findings:
        counts[finding.severity] += 1
    return counts
