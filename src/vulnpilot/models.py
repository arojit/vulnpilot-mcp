from datetime import date
from typing import Literal
from pydantic import BaseModel, Field


Ecosystem = Literal[
    "PyPI",
    "npm",
    "Maven",
    "Gradle",
]

TriagePriority = Literal[
    "IMMEDIATE",
    "URGENT",
    "HIGH",
    "NORMAL",
]

DependencyScope = Literal[
    "production",
    "development",
    "unknown",
]

class ExploitIntelligence(BaseModel):
    """Real-world exploitation intelligence for a vulnerability."""

    epss_cve: str | None = None

    epss_probability: float | None = Field(
        default=None,
        ge=0,
        le=1,
    )

    epss_percentile: float | None = Field(
        default=None,
        ge=0,
        le=1,
    )

    known_exploited: bool = False
    cisa_kev_cve: str | None = None
    cisa_date_added: date | None = None
    cisa_due_date: date | None = None
    cisa_required_action: str | None = None
    known_ransomware_campaign_use: str | None = None

class Vulnerability(BaseModel):
    """A vulnerability reported by OSV."""

    id: str
    summary: str
    aliases: list[str] = Field(default_factory=list)
    severity: str | None = None
    fixed_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    exploit_intelligence: ExploitIntelligence = Field(
        default_factory=ExploitIntelligence
    )
    priority: TriagePriority = "NORMAL"

class PackageCheckResult(BaseModel):
    """Structured result returned by check_package."""
    
    package_name: str
    version: str
    ecosystem: Ecosystem
    vulnerable: bool
    vulnerability_count: int
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    enrichment_warnings: list[str] = Field(
        default_factory=list
    )
