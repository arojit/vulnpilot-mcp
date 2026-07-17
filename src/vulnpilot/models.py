from typing import Literal
from pydantic import BaseModel, Field


Ecosystem = Literal["PyPI", "npm", "Maven"]

class Vulnerability(BaseModel):
    """A vulnerability reported by OSV."""

    id: str
    summary: str
    aliases: list[str] = Field(default_factory=list)
    severity: str | None = None
    fixed_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

class PackageCheckResult(BaseModel):
    """Structured result returned by check_package."""
    
    package_name: str
    version: str
    ecosystem: Ecosystem
    vulnerable: bool
    vulnerability_count: int
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)