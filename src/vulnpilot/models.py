from pydantic import BaseModel, Field

class Vulnerability(BaseModel):
    """A vulnerability reported by OSV."""

    id: str
    summary: str
    aliases: list[str] = Field(default_factory=list)

class PackageCheckResult(BaseModel):
    """Structured result returned by check_package."""
    
    package_name: str
    version: str
    ecosystem: str
    vulnerable: bool
    vulnerability_count: int
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)