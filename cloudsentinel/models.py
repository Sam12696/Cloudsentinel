from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    COST = "Cost Optimization"
    PERFORMANCE = "Performance"
    SECURITY = "Security"
    RELIABILITY = "Reliability"
    UNUSED = "Unused Resource"
    RIGHTSIZING = "Right-Sizing"


@dataclass
class Finding:
    service: str
    resource_id: str
    resource_name: str
    region: str
    severity: Severity
    category: Category
    title: str
    description: str
    recommendation: str
    estimated_monthly_savings: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "region": self.region,
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "estimated_monthly_savings_usd": round(self.estimated_monthly_savings, 2),
            "metadata": self.metadata,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    scanned_services: list[str] = field(default_factory=list)
    scanned_regions: list[str] = field(default_factory=list)
    ai_summary: Optional[str] = None
    scan_duration_seconds: float = 0.0

    @property
    def total_monthly_savings(self) -> float:
        return sum(f.estimated_monthly_savings for f in self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def by_service(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.service, []).append(f)
        return result

    def by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.severity.value, []).append(f)
        return result
