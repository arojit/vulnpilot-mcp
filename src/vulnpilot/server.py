import json
from textwrap import dedent
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


# ── Tools ────────────────────────────────────────────────────────


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


# ── Prompts ──────────────────────────────────────────────────────


@mcp.prompt()
def security_audit(
    project_path: str,
    ecosystem: str,
    dependencies: str,
) -> str:
    """Run a full security audit on a list of project dependencies.

    Guides the assistant to check every dependency for vulnerabilities
    and run reachability analysis on the vulnerable ones.

    Args:
        project_path: Absolute path to the project root directory.
        ecosystem: One of PyPI, npm, Maven, or Gradle.
        dependencies: Comma-separated list of name:version pairs
                      (e.g. "django:4.2.0, requests:2.31.0").
    """
    return dedent(f"""\
        You are performing a security audit of a software project.

        Project path: {project_path}
        Ecosystem: {ecosystem}
        Dependencies to audit: {dependencies}

        For each dependency listed above, follow these steps:

        1. Call the `check_package` tool with the package name, version,
           and ecosystem to look up known vulnerabilities.
        2. If any vulnerabilities are found, call the `analyze_reachability`
           tool with the project path, package name, and ecosystem to
           determine whether the vulnerable package is actually imported
           in the project's source code.
        3. Combine the vulnerability data with the reachability result to
           assess the real-world risk.

        After processing all dependencies, produce a summary report with:
        - A table of all dependencies and their vulnerability status.
        - For vulnerable dependencies: severity, priority, reachability
          status (production / test-only / not used), dependency type
          (direct / transitive), and recommended fix versions.
        - An overall risk assessment for the project.

        Sort the report by priority (IMMEDIATE > URGENT > HIGH > NORMAL).\
    """)


@mcp.prompt()
def triage_vulnerability(
    package_name: str,
    version: str,
    ecosystem: str,
    project_path: str,
) -> str:
    """Deep-dive triage of a single dependency.

    Walks the assistant through vulnerability lookup, reachability
    analysis, and a prioritized remediation recommendation.

    Args:
        package_name: Package name (e.g. django, lodash, org.apache.logging.log4j:log4j-core).
        version: Exact version to check (e.g. 2.2.0).
        ecosystem: One of PyPI, npm, Maven, or Gradle.
        project_path: Absolute path to the project root directory.
    """
    return dedent(f"""\
        You are triaging a potentially vulnerable dependency.

        Package: {package_name}
        Version: {version}
        Ecosystem: {ecosystem}
        Project path: {project_path}

        Follow these steps:

        1. Call `check_package` with the package name, version, and
           ecosystem to retrieve all known vulnerabilities, EPSS scores,
           and CISA KEV status.

        2. Call `analyze_reachability` with the project path, package
           name, and ecosystem to determine whether and where the package
           is imported.

        3. Based on the results, provide:
           - A list of vulnerabilities with their severity and priority.
           - Whether the package is reachable in production code, test-only,
             or not imported at all.
           - Whether it is a direct or transitive dependency, and evidence.
           - A clear remediation recommendation: which version to upgrade to,
             or whether the risk can be accepted.
           - If the vulnerability is listed in CISA KEV, emphasize that
             immediate action is required.\
    """)


DEPENDENCY_EVIDENCE_COMMANDS: dict[str, str] = {
    "PyPI": dedent("""\
        ## Python — pip

        If you use pip without a modern lock file, export the
        installed-package metadata:

        ```bash
        mkdir -p .vulnpilot
        python -m pip inspect --local > .vulnpilot/pip-inspect.json
        ```

        If the virtual environment is **not** activated:

        ```bash
        mkdir -p .vulnpilot
        .venv/bin/python -m pip inspect --local > .vulnpilot/pip-inspect.json
        ```

        ## Python — uv, Poetry, or PDM

        No command is required when the corresponding lock file exists:
        - `uv.lock`
        - `poetry.lock`
        - `pdm.lock`
        - `pylock.toml`\
    """),
    "npm": dedent("""\
        ## JavaScript / TypeScript — npm, Yarn, or pnpm

        No command is required when the corresponding lock file exists:
        - `package-lock.json` (npm)
        - `yarn.lock` (Yarn)
        - `pnpm-lock.yaml` (pnpm)\
    """),
    "Maven": dedent("""\
        ## Java — Maven

        Generate the dependency tree report:

        ```bash
        mkdir -p .vulnpilot
        mvn dependency:tree \\
          -DoutputFile=.vulnpilot/maven-dependency-tree.txt
        ```\
    """),
    "Gradle": dedent("""\
        ## Java — Gradle

        Generate the runtime dependency tree:

        ```bash
        mkdir -p .vulnpilot
        ./gradlew dependencies \\
          --configuration runtimeClasspath \\
          > .vulnpilot/gradle-dependencies.txt
        ```

        For test dependencies:

        ```bash
        mkdir -p .vulnpilot
        ./gradlew dependencies \\
          --configuration testRuntimeClasspath \\
          > .vulnpilot/gradle-test-dependencies.txt
        ```\
    """),
}


@mcp.prompt()
def generate_dependency_evidence(
    ecosystem: str,
) -> str:
    """Get commands to generate dependency evidence for an ecosystem.

    Returns the shell commands the user needs to run so that VulnPilot
    can classify dependencies as direct or transitive.

    Args:
        ecosystem: One of PyPI, npm, Maven, or Gradle.
    """
    commands = DEPENDENCY_EVIDENCE_COMMANDS.get(ecosystem)

    if commands is None:
        supported = ", ".join(DEPENDENCY_EVIDENCE_COMMANDS)
        return (
            f"Unsupported ecosystem: {ecosystem}. "
            f"Supported ecosystems: {supported}."
        )

    return dedent(f"""\
        The user needs to generate dependency evidence so that
        VulnPilot can classify dependencies as direct or transitive.

        Provide the following instructions for the **{ecosystem}**
        ecosystem. The commands must be run from the root of the
        project being analyzed.

        {commands}

        Tip: The `.vulnpilot/` directory is a good candidate for
        `.gitignore` — the reports are generated per-environment
        and should not be committed.\
    """)


# ── Resources ────────────────────────────────────────────────────


SUPPORTED_ECOSYSTEMS = [
    {
        "ecosystem": "PyPI",
        "package_name_format": "package-name",
        "example": "django",
        "tools": [
            "check_package",
            "analyze_reachability",
        ],
        "reachability_scanner": "Python AST-based import scanner",
        "dependency_classification": True,
    },
    {
        "ecosystem": "npm",
        "package_name_format": "package-name or @scope/package-name",
        "example": "lodash",
        "tools": [
            "check_package",
            "analyze_reachability",
        ],
        "reachability_scanner": (
            "JavaScript/TypeScript import, require, "
            "and dynamic import() scanner"
        ),
        "dependency_classification": True,
    },
    {
        "ecosystem": "Maven",
        "package_name_format": "groupId:artifactId",
        "example": "org.apache.logging.log4j:log4j-core",
        "tools": [
            "check_package",
            "analyze_reachability",
        ],
        "reachability_scanner": (
            "Java import scanner with Maven pom.xml detection"
        ),
        "dependency_classification": True,
    },
    {
        "ecosystem": "Gradle",
        "package_name_format": "groupId:artifactId",
        "example": "com.google.guava:guava",
        "tools": [
            "check_package",
            "analyze_reachability",
        ],
        "reachability_scanner": (
            "Java import scanner with Gradle build file detection"
        ),
        "dependency_classification": True,
    },
]


@mcp.resource(
    "vulnpilot://supported-ecosystems",
    name="Supported Ecosystems",
    description=(
        "JSON listing of every ecosystem VulnPilot supports, "
        "including package name format, available tools, and "
        "example coordinates."
    ),
    mime_type="application/json",
)
def supported_ecosystems_resource() -> str:
    """Return the supported ecosystems as JSON."""
    return json.dumps(
        SUPPORTED_ECOSYSTEMS,
        indent=2,
    )


TRIAGE_RULES_MARKDOWN = dedent("""\
    # VulnPilot Triage Priority Rules

    VulnPilot automatically assigns a remediation priority to each
    vulnerability using deterministic rules based on code reachability,
    dependency scope, and exploit telemetry.

    ## Priority Levels

    ### IMMEDIATE
    **Condition:** Listed in the CISA Known Exploited Vulnerabilities
    (KEV) catalog (`known_exploited = true`).

    **Reasoning:** The vulnerability is actively exploited in
    cyberattacks or ransomware campaigns in the wild. Immediate
    remediation is required.

    ### URGENT
    **Condition:** Reachable code (`is_reachable = true`) AND high
    EPSS probability (`>= 0.5`).

    **Reasoning:** There is a high probability of imminent exploitation
    and the vulnerable code path is active in the project.

    ### HIGH
    **Condition:** Production dependency (`dependency_scope = "production"`)
    AND severity is `CRITICAL`.

    **Reasoning:** A critical-severity vulnerability is exposed in the
    production environment.

    ### NORMAL
    **Condition:** Default fallback for all other vulnerabilities.

    **Reasoning:** Lower risk or exploit probability, or the vulnerability
    is restricted to development dependencies or unreachable code.

    ## How to Use These Rules

    When interpreting results from `check_package`:
    - **IMMEDIATE** findings require same-day remediation.
    - **URGENT** findings should be addressed within the current sprint.
    - **HIGH** findings should be planned for the next release.
    - **NORMAL** findings can be tracked and addressed at convenience.

    You can refine the priority by providing `is_reachable` and
    `dependency_scope` to the `check_package` tool after running
    `analyze_reachability`.\
""")


@mcp.resource(
    "vulnpilot://triage-rules",
    name="Triage Priority Rules",
    description=(
        "Explains the deterministic rules VulnPilot uses to assign "
        "IMMEDIATE, URGENT, HIGH, or NORMAL priority to each "
        "vulnerability."
    ),
    mime_type="text/markdown",
)
def triage_rules_resource() -> str:
    """Return the triage priority rules as markdown."""
    return TRIAGE_RULES_MARKDOWN


def _build_dependency_evidence_guide() -> str:
    """Assemble the full dependency evidence guide from per-ecosystem blocks."""
    sections = [
        "# Generating Dependency Evidence",
        "",
        "Run these commands from the root of the project being "
        "analyzed — not from the VulnPilot directory.",
        "",
    ]

    for ecosystem, commands in DEPENDENCY_EVIDENCE_COMMANDS.items():
        sections.append(commands)
        sections.append("")

    sections.append(
        "> **Tip:** The `.vulnpilot/` directory is a good candidate "
        "for `.gitignore` — the reports are generated per-environment "
        "and should not be committed."
    )

    return "\n".join(sections)


DEPENDENCY_EVIDENCE_GUIDE = _build_dependency_evidence_guide()


@mcp.resource(
    "vulnpilot://dependency-evidence-guide",
    name="Dependency Evidence Guide",
    description=(
        "Step-by-step commands to generate lock files and dependency "
        "tree reports so VulnPilot can classify dependencies as "
        "direct or transitive."
    ),
    mime_type="text/markdown",
)
def dependency_evidence_guide_resource() -> str:
    """Return the dependency evidence generation guide."""
    return DEPENDENCY_EVIDENCE_GUIDE


def main() -> None:
    """Start VulnPilot using the STDIO transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
