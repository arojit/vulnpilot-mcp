from typing import Literal
from pydantic import BaseModel, Field


Ecosystem = Literal[
    "PyPI",
    "npm",
    "Maven",
    "Gradle",
]

class ExploitIntelligence(BaseModel):
    """Real-world exploitation intelligence for a vulnerability."""

    matched_cve: str | None = None

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

class PackageCheckResult(BaseModel):
    """Structured result returned by check_package."""
    
    package_name: str
    version: str
    ecosystem: Ecosystem
    vulnerable: bool
    vulnerability_count: int
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
