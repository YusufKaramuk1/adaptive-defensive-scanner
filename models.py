"""
ADS – Data Models (v2.3)
Tüm veri yapılarını merkezi olarak tanımlar. Tip güvenliği için dataclass ve Enum kullanılır.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


class Environment(str, Enum):
    INTERNAL   = "internal"
    EXTERNAL   = "external"
    PRODUCTION = "production"


class Criticality(str, Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"


class RiskLevel(str, Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"


class ConfidenceLevel(str, Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"


class PriorityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


@dataclass
class ScanFinding:
    host:     str  = ""   # YENİ: Hangi IP'den geldiği
    port:     int  = 0
    service:  str  = ""
    protocol: str  = "tcp"
    state:    str  = "open"
    version:  str  = ""
    product:  str  = ""


@dataclass
class ServiceClassification:
    category:          str
    expected_exposure: str
    description:       str


@dataclass
class CVEInfo:
    cve_id:      str
    description: str
    cvss_score:  float
    url:         str
    match_type:  str = "service"


@dataclass
class Fixes:
    quick_fix:  str
    proper_fix: str


@dataclass
class FirewallRules:
    ufw:      str
    iptables: str
    note:     str


@dataclass
class AnalyzedFinding:
    # Temel bilgiler
    host:     str  = ""   # YENİ: Hangi IP'den geldiği
    port:     int  = 0
    service:  str  = ""
    protocol: str  = "tcp"
    state:    str  = "open"

    # Sınıflandırma
    category:          str = ""
    expected_exposure: str = ""

    # Risk skorlaması
    base_score:  int = 0
    final_score: int = 0
    risk:        RiskLevel = RiskLevel.LOW

    # Açıklama ve kanıt (varsayılan değersiz alanlar önce)
    reason:   str = ""
    evidence: list = field(default_factory=list)

    # Güven ve öncelik (varsayılan değerli alanlar sonra)
    confidence:  ConfidenceLevel = ConfidenceLevel.LOW
    priority:    PriorityLevel   = PriorityLevel.MEDIUM

    # Öneriler (sonradan eklenir)
    quick_fix:     str = ""
    proper_fix:    str = ""
    ufw_rule:      str = ""
    iptables_rule: str = ""
    rule_note:     str = ""

    # CVE bilgileri
    cves: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk"] = self.risk.value
        d["confidence"] = self.confidence.value
        d["priority"] = self.priority.value
        return d


@dataclass
class ScanContext:
    target:      str
    environment: Environment
    criticality: Criticality

    def to_dict(self) -> dict:
        return {
            "target":      self.target,
            "environment": self.environment.value,
            "criticality": self.criticality.value,
        }


@dataclass
class ScanReport:
    context:  ScanContext
    findings: list  # list[AnalyzedFinding]

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.LOW)

    @property
    def critical_priority_count(self) -> int:
        return sum(1 for f in self.findings if f.priority == PriorityLevel.CRITICAL)

    @property
    def high_priority_count(self) -> int:
        return sum(1 for f in self.findings if f.priority == PriorityLevel.HIGH)

    @property
    def overall_risk(self) -> str:
        if self.high_count > 0:
            return "HIGH"
        if self.medium_count > 0:
            return "MEDIUM"
        return "LOW"

    @property
    def overall_priority(self) -> str:
        if self.critical_priority_count > 0:
            return "CRITICAL"
        if self.high_priority_count > 0:
            return "HIGH"
        if self.medium_count > 0:
            return "MEDIUM"
        return "LOW"

    @property
    def top_risks(self) -> list:
        """Önceliğe göre sıralanmış ilk 5 bulgu."""
        priority_order = {PriorityLevel.CRITICAL: 0, PriorityLevel.HIGH: 1, PriorityLevel.MEDIUM: 2, PriorityLevel.LOW: 3}
        return sorted(self.findings, key=lambda f: (priority_order.get(f.priority, 99), -f.final_score))[:5]

    def to_dict(self) -> dict:
        return {
            "context":        self.context.to_dict(),
            "summary": {
                "total":                len(self.findings),
                "high":                 self.high_count,
                "medium":               self.medium_count,
                "low":                  self.low_count,
                "overall_risk":         self.overall_risk,
                "overall_priority":     self.overall_priority,
                "critical_priority":    self.critical_priority_count,
                "high_priority":        self.high_priority_count,
            },
            "findings": [f.to_dict() for f in self.findings],
        }


# ─── Diff Modelleri (v2.3) ──────────────────────────────────

@dataclass
class PortChange:
    port: int
    protocol: str
    service: str
    change_type: str  # "new", "removed", "risk_increased", "risk_decreased", "unchanged"
    old_risk: Optional[str] = None
    new_risk: Optional[str] = None
    old_priority: Optional[str] = None
    new_priority: Optional[str] = None
    cves: list = field(default_factory=list)
    details: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DiffReport:
    previous_report_path: str
    current_report_path: str
    timestamp: str
    summary: dict = field(default_factory=dict)
    changes: list = field(default_factory=list)  # list[PortChange]

    @property
    def new_ports(self) -> list:
        return [c for c in self.changes if c.change_type == "new"]

    @property
    def removed_ports(self) -> list:
        return [c for c in self.changes if c.change_type == "removed"]

    @property
    def risk_changes(self) -> list:
        return [c for c in self.changes if c.change_type in ("risk_increased", "risk_decreased")]

    def to_dict(self) -> dict:
        return {
            "previous_report": self.previous_report_path,
            "current_report": self.current_report_path,
            "timestamp": self.timestamp,
            "summary": self.summary,
            "changes": [c.to_dict() for c in self.changes],
        }