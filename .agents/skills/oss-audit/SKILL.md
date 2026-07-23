---
name: oss-vulnerability-audit
description: >
  Audit open-source dependencies for known vulnerabilities using the
  VulnPilot MCP server. Triggers when the user asks about security
  audits, dependency vulnerabilities, CVEs, supply-chain risk, or
  OSS analysis.
---

# OSS Vulnerability Audit with VulnPilot

Use the **VulnPilot** MCP server tools whenever the user asks to:
- Audit dependencies for vulnerabilities
- Check if a package version is vulnerable
- Analyze reachability of a dependency
- Generate a security report
- Perform supply-chain or OSS risk analysis

## Workflow

### 1. Identify Dependencies

Read the project's manifest file to extract dependency names and versions:

| Ecosystem | Files to read |
|-----------|---------------|
| PyPI      | `pyproject.toml`, `requirements.txt`, `uv.lock`, `poetry.lock` |
| npm       | `package.json`, `package-lock.json`, `yarn.lock` |
| Maven     | `pom.xml` |
| Gradle    | `build.gradle`, `build.gradle.kts` |

### 2. Check Each Package

For every dependency, call the VulnPilot `check_package` tool:

```
check_package(
    package_name="<name>",
    version="<version>",
    ecosystem="PyPI"  # or npm, Maven, Gradle
)
```

### 3. Analyze Reachability (for vulnerable packages)

For each **vulnerable** package, call `analyze_reachability`:

```
analyze_reachability(
    project_path="/absolute/path/to/project",
    package_name="<name>",
    ecosystem="PyPI"
)
```

Then re-call `check_package` with the reachability and scope info to refine priority:

```
check_package(
    package_name="<name>",
    version="<version>",
    ecosystem="PyPI",
    is_reachable=True,
    dependency_scope="production"
)
```

### 4. Generate Report

After all packages are checked, aggregate the results and call `generate_report`:

```
generate_report(
    results=[...],           # list of PackageReport objects
    project_name="my-app",
    ecosystem="PyPI",
    output_dir=".vulnpilot"
)
```

This produces a self-contained HTML report saved to `.vulnpilot/`.

### 5. Summarize

Present a concise summary to the user:
- Total packages scanned vs vulnerable
- Breakdown by priority (IMMEDIATE > URGENT > HIGH > NORMAL)
- Top recommended actions
- Path to the saved HTML report

## Priority Levels

| Priority   | Meaning | Action |
|------------|---------|--------|
| IMMEDIATE  | Listed in CISA KEV — actively exploited | Patch today |
| URGENT     | Reachable + EPSS ≥ 50% | Fix this sprint |
| HIGH       | Production + CRITICAL severity | Plan for next release |
| NORMAL     | Lower risk | Track and address at convenience |

## Important Notes

- Use `Maven` ecosystem for both Maven and Gradle JVM dependencies.
- For Maven/Gradle, package names use `groupId:artifactId` format.
- Always use absolute paths for `project_path`.
- The `.vulnpilot/` output directory should be added to `.gitignore`.
