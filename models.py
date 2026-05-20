"""
ADS – Data Models (v1.0.0)

Central data models used by the Adaptive Defensive Scanner.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


class Environment(str, Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    PRODUCTION = "production"


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ConfidenceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PriorityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SecuritySeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class ScanFinding:
    host: str = ""
    port: int = 0
    service: str = ""
    protocol: str = "tcp"
    state: str = "open"
    version: str = ""
    product: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class SecurityFinding:
    """
    Normalized vulnerability / misconfiguration finding.

    Intended for tools like:
    - Nuclei
    - Tsunami
    - future validated vulnerability importers

    This is separate from ScanFinding because Nuclei/Tsunami usually report
    direct security issues rather than only open ports or service fingerprints.
    """

    source_tool: str = ""
    finding_type: str = "vulnerability"

    template_id: str = ""
    name: str = ""
    severity: SecuritySeverity = SecuritySeverity.UNKNOWN

    host: str = ""
    matched_at: str = ""
    ip: str = ""

    port: int = 0
    scheme: str = ""

    description: str = ""
    tags: list = field(default_factory=list)
    references: list = field(default_factory=list)
    cve_ids: list = field(default_factory=list)

    matcher_name: str = ""
    extracted_results: list = field(default_factory=list)
    curl_command: str = ""

    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value if hasattr(self.severity, "value") else str(self.severity)
        return d


@dataclass
class AnalyzedSecurityFinding:
    """
    ADS-analyzed vulnerability / misconfiguration finding.

    Produced from SecurityFinding by analyzer/security_finding_analyzer.py.
    """

    source_tool: str = ""
    finding_type: str = "vulnerability"

    template_id: str = ""
    name: str = ""
    severity: SecuritySeverity = SecuritySeverity.UNKNOWN

    host: str = ""
    matched_at: str = ""
    ip: str = ""

    port: int = 0
    scheme: str = ""

    description: str = ""
    tags: list = field(default_factory=list)
    references: list = field(default_factory=list)
    cve_ids: list = field(default_factory=list)

    matcher_name: str = ""
    extracted_results: list = field(default_factory=list)
    curl_command: str = ""

    base_score: int = 0
    final_score: int = 0
    risk: RiskLevel = RiskLevel.LOW
    priority: PriorityLevel = PriorityLevel.LOW
    confidence: ConfidenceLevel = ConfidenceLevel.LOW

    reason: str = ""
    evidence: list = field(default_factory=list)

    quick_fix: str = ""
    proper_fix: str = ""

    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value if hasattr(self.severity, "value") else str(self.severity)
        d["risk"] = self.risk.value if hasattr(self.risk, "value") else str(self.risk)
        d["priority"] = self.priority.value if hasattr(self.priority, "value") else str(self.priority)
        d["confidence"] = self.confidence.value if hasattr(self.confidence, "value") else str(self.confidence)
        return d


@dataclass
class ServiceClassification:
    category: str
    expected_exposure: str
    description: str


@dataclass
class CVEInfo:
    cve_id: str
    description: str
    cvss_score: float
    url: str
    match_type: str = "service"


@dataclass
class Fixes:
    quick_fix: str
    proper_fix: str


@dataclass
class FirewallRules:
    ufw: str
    iptables: str
    note: str


@dataclass
class AnalyzedFinding:
    host: str = ""
    port: int = 0
    service: str = ""
    protocol: str = "tcp"
    state: str = "open"
    version: str = ""
    product: str = ""

    category: str = ""
    expected_exposure: str = ""

    base_score: int = 0
    final_score: int = 0
    risk: RiskLevel = RiskLevel.LOW

    reason: str = ""
    evidence: list = field(default_factory=list)

    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    priority: PriorityLevel = PriorityLevel.MEDIUM

    quick_fix: str = ""
    proper_fix: str = ""
    ufw_rule: str = ""
    iptables_rule: str = ""
    rule_note: str = ""

    cves: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk"] = self.risk.value
        d["confidence"] = self.confidence.value
        d["priority"] = self.priority.value
        return d


@dataclass
class ScanContext:
    target: str
    environment: Environment
    criticality: Criticality

    mock: bool = False
    parallel: bool = False
    workers: int = 1
    scan_mode: str = "nmap_live"

    source_tool: str = ""
    source_file: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "environment": self.environment.value if hasattr(self.environment, "value") else str(self.environment),
            "criticality": self.criticality.value if hasattr(self.criticality, "value") else str(self.criticality),
            "mock": self.mock,
            "parallel": self.parallel,
            "workers": self.workers,
            "scan_mode": self.scan_mode,
            "source_tool": self.source_tool,
            "source_file": self.source_file,
        }


@dataclass
class ScanReport:
    context: ScanContext
    findings: list  # list[AnalyzedFinding]
    security_findings: list = field(default_factory=list)  # list[AnalyzedSecurityFinding]

    # ── Scan finding counts (risk-based) ─────────────────────────
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.LOW)

    # ── Scan finding counts (priority-based) ─────────────────────
    @property
    def critical_priority_count(self) -> int:
        return sum(1 for f in self.findings if f.priority == PriorityLevel.CRITICAL)

    @property
    def high_priority_count(self) -> int:
        return sum(1 for f in self.findings if f.priority == PriorityLevel.HIGH)

    # ── Security finding counts (risk-based; shares RiskLevel) ───
    @property
    def security_high_count(self) -> int:
        return sum(1 for f in self.security_findings if f.risk == RiskLevel.HIGH)

    @property
    def security_medium_count(self) -> int:
        return sum(1 for f in self.security_findings if f.risk == RiskLevel.MEDIUM)

    @property
    def security_low_count(self) -> int:
        return sum(1 for f in self.security_findings if f.risk == RiskLevel.LOW)

    # ── Security finding counts (priority-based) ─────────────────
    @property
    def security_critical_priority_count(self) -> int:
        return sum(1 for f in self.security_findings if f.priority == PriorityLevel.CRITICAL)

    @property
    def security_high_priority_count(self) -> int:
        return sum(1 for f in self.security_findings if f.priority == PriorityLevel.HIGH)

    # ── Security finding counts (raw severity, for display) ──────
    @property
    def security_critical_severity_count(self) -> int:
        return sum(1 for f in self.security_findings if f.severity == SecuritySeverity.CRITICAL)

    @property
    def security_high_severity_count(self) -> int:
        return sum(1 for f in self.security_findings if f.severity == SecuritySeverity.HIGH)

    @property
    def security_medium_severity_count(self) -> int:
        return sum(1 for f in self.security_findings if f.severity == SecuritySeverity.MEDIUM)

    @property
    def security_low_severity_count(self) -> int:
        return sum(1 for f in self.security_findings if f.severity == SecuritySeverity.LOW)

    @property
    def security_info_severity_count(self) -> int:
        return sum(1 for f in self.security_findings if f.severity == SecuritySeverity.INFO)

    # ── Overall (considers both lists) ───────────────────────────
    @property
    def overall_risk(self) -> str:
        if self.high_count > 0 or self.security_high_count > 0:
            return "HIGH"
        if self.medium_count > 0 or self.security_medium_count > 0:
            return "MEDIUM"
        return "LOW"

    @property
    def overall_priority(self) -> str:
        if self.critical_priority_count > 0 or self.security_critical_priority_count > 0:
            return "CRITICAL"
        if self.high_priority_count > 0 or self.security_high_priority_count > 0:
            return "HIGH"
        if self.medium_count > 0 or self.security_medium_count > 0:
            return "MEDIUM"
        return "LOW"

    # ── Sorting ──────────────────────────────────────────────────
    @property
    def top_risks(self) -> list:
        """Top 5 scan findings only. Kept for backward compatibility."""
        priority_order = {
            PriorityLevel.CRITICAL: 0,
            PriorityLevel.HIGH: 1,
            PriorityLevel.MEDIUM: 2,
            PriorityLevel.LOW: 3,
        }
        return sorted(
            self.findings,
            key=lambda f: (priority_order.get(f.priority, 99), -f.final_score),
        )[:5]

    @property
    def top_priority(self) -> list:
        """Top 5 across both scan and security findings, merged and sorted by priority."""
        priority_order = {
            PriorityLevel.CRITICAL: 0,
            PriorityLevel.HIGH: 1,
            PriorityLevel.MEDIUM: 2,
            PriorityLevel.LOW: 3,
        }
        merged = list(self.findings) + list(self.security_findings)
        return sorted(
            merged,
            key=lambda f: (priority_order.get(f.priority, 99), -getattr(f, "final_score", 0)),
        )[:5]

    def to_dict(self) -> dict:
        return {
            "context": self.context.to_dict(),
            "summary": {
                "total": len(self.findings),
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "overall_risk": self.overall_risk,
                "overall_priority": self.overall_priority,
                "critical_priority": self.critical_priority_count,
                "high_priority": self.high_priority_count,
            },
            "security_summary": {
                "total": len(self.security_findings),
                "critical_severity": self.security_critical_severity_count,
                "high_severity": self.security_high_severity_count,
                "medium_severity": self.security_medium_severity_count,
                "low_severity": self.security_low_severity_count,
                "info_severity": self.security_info_severity_count,
                "high_risk": self.security_high_count,
                "medium_risk": self.security_medium_count,
                "low_risk": self.security_low_count,
                "critical_priority": self.security_critical_priority_count,
                "high_priority": self.security_high_priority_count,
            },
            "findings": [f.to_dict() for f in self.findings],
            "security_findings": [f.to_dict() for f in self.security_findings],
        }


@dataclass
class PortChange:
    host: str = ""
    port: int = 0
    protocol: str = "tcp"
    service: str = ""
    change_type: str = "unchanged"
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
    previous_report_path: str = ""
    current_report_path: str = ""
    timestamp: str = ""
    summary: dict = field(default_factory=dict)
    changes: list = field(default_factory=list)

    @property
    def new_ports(self) -> list:
        return [c for c in self.changes if c.change_type == "new"]

    @property
    def removed_ports(self) -> list:
        return [c for c in self.changes if c.change_type == "removed"]

    @property
    def risk_changes(self) -> list:
        return [
            c for c in self.changes
            if c.change_type in ("risk_increased", "risk_decreased")
        ]

    def to_dict(self) -> dict:
        return {
            "previous_report": self.previous_report_path,
            "current_report": self.current_report_path,
            "timestamp": self.timestamp,
            "summary": self.summary,
            "changes": [c.to_dict() for c in self.changes],
        }