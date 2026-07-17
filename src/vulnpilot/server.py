from typing import Literal

from mcp.server.fastmcp import FastMCP
from vulnpilot.models import PackageCheckResult, Ecosystem
from vulnpilot.osv_client import normalize_vulnerability, query_osv
from vulnpilot.exploit_intel_client import (
    ExploitIntelligenceError,
    enrich_with_epss,
)

mcp = FastMCP(
    "VulnPilot",
    instructions=(
        "Use check_package whenever the user asks about "
        "known vulnerabilities in a specific dependency version. "
        "Supported ecosystems are PyPI, npm, and Maven."
    ),
)

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
    """Check an exact dependency version for known vulnerabilities.

    Use this tool when the user asks whether a Python, npm, Maven,
    or Gradle dependency version is vulnerable.

    For Gradle JVM dependencies, use the Maven ecosystem and provide
    the package as groupId:artifactId.

    Args:
        package_name: Package name, or groupId:artifactId for Maven. Example: django, org.apache.logging.log4j:log4j-core
        version: Exact installed dependency version. Example: 2.2.0, 2.14.1
        ecosystem: One of PyPI, npm, or Maven.
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

    warnings = []
    try:
        simplified_vulnerabilities = await enrich_with_epss(
            simplified_vulnerabilities
        )
    except ExploitIntelligenceError as exc:
        warnings.append(str(exc))

    return PackageCheckResult(
        package_name=package_name,
        version=version,
        ecosystem=ecosystem,
        vulnerable=len(simplified_vulnerabilities) > 0,
        vulnerability_count=len(simplified_vulnerabilities),
        vulnerabilities=simplified_vulnerabilities,
        warnings=warnings,
    )


def main() -> None:
    """Start VulnPilot using the STDIO transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
