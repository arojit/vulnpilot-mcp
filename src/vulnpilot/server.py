from typing import Literal

from mcp.server.fastmcp import FastMCP
from vulnpilot.models import PackageCheckResult, Vulnerability
from vulnpilot.osv_client import query_osv

mcp = FastMCP("VulnPilot")

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


def main() -> None:
    """Start VulnPilot using the STDIO transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
