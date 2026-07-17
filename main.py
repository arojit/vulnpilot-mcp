from typing import Literal

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

mcp = FastMCP("VulnPilot")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

class Vulnerability(BaseModel):
    id: str
    summary: str
    aliases: list[str] = Field(default_factory=list)

class PackageCheckResult(BaseModel):
    package_name: str
    version: str
    ecosystem: str
    vulnerable: bool
    vulnerability_count: int
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


async def query_osv(payload: dict) -> dict:
    """Send a vulnerability query to OSV."""

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                OSV_QUERY_URL,
                json=payload,
            )
            response.raise_for_status()

    except httpx.TimeoutException as exc:
        raise RuntimeError(
            "The OSV request timed out. Please try again."
        ) from exc

    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"OSV returned HTTP status {exc.response.status_code}."
        ) from exc

    except httpx.RequestError as exc:
        raise RuntimeError(
            "Could not connect to the OSV service."
        ) from exc

    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(
            "OSV returned an invalid JSON response."
        ) from exc


@mcp.tool(
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
)
async def check_package(
    package_name: str,
    version: str,
    ecosystem: Literal["PyPI"] = "PyPI",
) -> PackageCheckResult:
    """Check a package version for known vulnerabilities using OSV

    Args:
        package_name: Name of the package, for example django.
        version: Exact package version, for example 2.2.0.
        ecosystem: Package ecosystem, currently PyPI.
    """
    package_name = package_name.strip()
    version = version.strip()

    if not package_name:
        raise ValueError("Package name is required")

    if not version:
        raise ValueError("Version is required")
    
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        },
        "version": version,
    }

    data = await query_osv(payload)

    vulnerabilities = data.get("vulns", [])
    
    simplified_vulnerabilities = []

    for vulnerability in vulnerabilities:
        simplified_vulnerabilities.append(
            Vulnerability(
                id = vulnerability.get("id", "UNKNOWN"),
                summary = vulnerability.get("summary", "No summery available"),
                aliases = vulnerability.get("aliases", [])
            )
        )

    return PackageCheckResult(
        package_name=package_name,
        version=version,
        ecosystem=ecosystem,
        vulnerable=len(simplified_vulnerabilities) > 0,
        vulnerability_count=len(simplified_vulnerabilities),
        vulnerabilities=simplified_vulnerabilities
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
