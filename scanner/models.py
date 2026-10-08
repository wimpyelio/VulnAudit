from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")

@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    owasp_category: str
    severity: str
    description: str
    evidence: dict[str, str]
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(frozen=True)
class ScanResult:
    target_url: str
    scanner_version: str
    duration_ms: int
    findings: list[Finding]
