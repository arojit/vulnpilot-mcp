from typing import Literal

from mcp.server.fastmcp import FastMCP
from vulnpilot.models import PackageCheckResult, Ecosystem
from vulnpilot.osv_client import normalize_vulnerability, query_osv
from vulnpilot.models import DependencyScope, ReachabilityResult
from vulnpilot.triage import assign_priorities

from vulnpilot.reachability import (
    analyze_python_reachability as run_python_reachability,
    analyze_javascript_reachability as run_javascript_reachability,
    analyze_java_reachability as run_java_reachability,
)

from vulnpilot.cisa_kev_client import (
    CISAKEVClientError,
    enrich_with_cisa_kev,
)
from vulnpilot.epss_client import (
    EPSSClientError,
    enrich_with_epss,
)

mcp = FastMCP(
    "VulnPilot",
    instructions=(
        "Use check_package whenever the user asks about "
        "known vulnerabilities in a specific dependency version. "
        "Use analyze_reachability to determine whether a package "
        "is actually imported in a project's source code. "
        "Supported ecosystems are PyPI, npm, Maven, and Gradle."
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
    is_reachable: bool | None = None,
    dependency_scope: DependencyScope = "unknown",
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

    enrichment_warnings = []
    try:
        simplified_vulnerabilities = await enrich_with_epss(
            simplified_vulnerabilities
        )
    except EPSSClientError as exc:
        enrichment_warnings.append(str(exc))

    try:
        simplified_vulnerabilities = await enrich_with_cisa_kev(
            simplified_vulnerabilities
        )
    except CISAKEVClientError as exc:
        enrichment_warnings.append(str(exc))
    
    simplified_vulnerabilities = assign_priorities(
        simplified_vulnerabilities,
        is_reachable=is_reachable,
        dependency_scope=dependency_scope,
    )

    return PackageCheckResult(
        package_name=package_name,
        version=version,
        ecosystem=ecosystem,
        vulnerable=len(simplified_vulnerabilities) > 0,
        vulnerability_count=len(simplified_vulnerabilities),
        vulnerabilities=simplified_vulnerabilities,
        enrichment_warnings=enrichment_warnings,
    )


REACHABILITY_ANALYZERS = {
    "PyPI": run_python_reachability,
    "npm": run_javascript_reachability,
    "Maven": run_java_reachability,
    "Gradle": run_java_reachability,
}


@mcp.tool()
def analyze_reachability(
    project_path: str,
    package_name: str,
    ecosystem: Ecosystem = "PyPI",
    import_names: list[str] | None = None,
) -> ReachabilityResult:
    """
    Analyze a project to determine whether a package is actually imported.

    Statically scans source files for imports of the given package and
    classifies each usage as production or test-only. Supports Python
    (PyPI), JavaScript/TypeScript (npm), and Java (Maven/Gradle).

    Args:
        project_path: Absolute path to the project root directory.
        package_name: Package name to look for. Use groupId:artifactId for Maven/Gradle.
        ecosystem: One of PyPI, npm, Maven, or Gradle. Determines which scanner to use.
        import_names: Override the import name when it differs from the package name
                      (e.g. ["bs4"] for beautifulsoup4, or a Java package prefix).
    """
    analyzer = REACHABILITY_ANALYZERS.get(ecosystem)

    if analyzer is None:
        raise ValueError(
            f"Unsupported ecosystem for reachability analysis: {ecosystem}. "
            f"Supported: {', '.join(REACHABILITY_ANALYZERS)}"
        )

    return analyzer(
        project_path=project_path,
        package_name=package_name,
        import_names=import_names,
    )


def main() -> None:
    """Start VulnPilot using the STDIO transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
