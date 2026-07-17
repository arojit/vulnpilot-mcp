from typing import Literal

from mcp.server.fastmcp import FastMCP
from vulnpilot.models import PackageCheckResult, Ecosystem
from vulnpilot.osv_client import normalize_vulnerability, query_osv

mcp = FastMCP("VulnPilot")

OSV_ECOSYSTEM_MAPPING = {
    "PyPI": "PyPI",
    "npm": "npm",
    "Maven": "Maven",
    "Gradle": "Maven",
}


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
    ecosystem: Ecosystem = "PyPI",
) -> PackageCheckResult:
    """Check a package version for known vulnerabilities using OSV

    Args:
        package_name: Name of the package, for example django.
        version: Exact package version, for example 2.2.0.
        ecosystem: One of PyPI, npm, Maven or Gradle.
    """
    package_name = package_name.strip()
    version = version.strip()
    osv_ecosystem = OSV_ECOSYSTEM_MAPPING[ecosystem]

    if ecosystem in {"Maven", "Gradle"}:
        coordinate_parts = package_name.split(":")

        if (
            len(coordinate_parts) != 2
            or not coordinate_parts[0]
            or not coordinate_parts[1]
        ):
            raise ValueError(
                f"{ecosystem} package_name must use "
                "the format groupId:artifactId"
            )

    if not package_name:
        raise ValueError("Package name is required")

    if not version:
        raise ValueError("Version is required")
    
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": osv_ecosystem,
        },
        "version": version,
    }

    data = await query_osv(payload)

    vulnerabilities = data.get("vulns", [])

    simplified_vulnerabilities = [
        normalize_vulnerability(vulnerability)
        for vulnerability in vulnerabilities
    ]

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
