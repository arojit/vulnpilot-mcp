"""Java reachability analysis for Maven and Gradle projects."""

import re
from pathlib import Path

from vulnpilot.models import (
    ReachabilityResult,
    UsageLocation,
)
from vulnpilot.reachability._common import (
    is_ignored_file,
    is_test_file,
    line_number,
)
from vulnpilot.reachability.java_dependencies import (
    classify_java_dependency,
)

JAVA_EXTENSIONS = {
    ".java",
}

JAVA_IMPORT_PATTERN = re.compile(
    r"""
    ^[ \t]*import[ \t]+
    (?:static[ \t]+)?
    (?P<module>
        [A-Za-z_$][\w$]*
        (?:\.[A-Za-z_$][\w$*]*)+
    )
    [ \t]*;
    """,
    re.MULTILINE | re.VERBOSE,
)


def matches_java_import(
    imported_module: str,
    import_names: list[str],
) -> bool:
    return any(
        imported_module == import_name
        or imported_module.startswith(
            f"{import_name}."
        )
        for import_name in import_names
    )


def default_java_import_names(
    package_name: str,
) -> list[str]:
    """
    Derive a default Java import prefix from a Maven
    coordinate.

    Example:

        org.apache.logging.log4j:log4j-core

    becomes:

        org.apache.logging.log4j

    This is only an estimate. The Maven group ID does not
    always equal the Java package name.
    """
    coordinate_parts = package_name.split(":")

    if len(coordinate_parts) >= 2:
        group_id = coordinate_parts[0].strip()

        if group_id:
            return [group_id]

    return [package_name]


def scan_java_imports(
    project_path: Path,
    import_names: list[str],
) -> list[UsageLocation]:
    usages: list[UsageLocation] = []
    seen: set[tuple[str, int, str, str]] = set()

    for file_path in project_path.rglob("*"):
        if not file_path.is_file():
            continue

        if (
            file_path.suffix.lower()
            not in JAVA_EXTENSIONS
        ):
            continue

        if is_ignored_file(
            file_path,
            project_path,
        ):
            continue

        try:
            content = file_path.read_text(
                encoding="utf-8",
                errors="ignore",
            )
        except OSError:
            continue

        relative_path = file_path.relative_to(
            project_path
        )
        relative_path_string = (
            relative_path.as_posix()
        )

        for match in JAVA_IMPORT_PATTERN.finditer(
            content
        ):
            imported_module = match.group(
                "module"
            )

            if not matches_java_import(
                imported_module,
                import_names,
            ):
                continue

            usage_line = line_number(
                content,
                match.start(),
            )

            usage_key = (
                relative_path_string,
                usage_line,
                imported_module,
                "import",
            )

            if usage_key in seen:
                continue

            seen.add(usage_key)

            usages.append(
                UsageLocation(
                    file=relative_path_string,
                    line=usage_line,
                    imported_name=imported_module,
                    kind="import",
                    is_test_file=is_test_file(
                        relative_path
                    ),
                )
            )

    return sorted(
        usages,
        key=lambda usage: (
            usage.file,
            usage.line,
        ),
    )


def detect_java_build_system(
    project_path: Path,
) -> str:
    """
    Detect whether the project uses Maven or Gradle.

    Root build files take precedence over build files found
    in nested modules.
    """
    root_pom = project_path / "pom.xml"

    if root_pom.is_file():
        return "maven"

    root_gradle_files = (
        project_path / "build.gradle",
        project_path / "build.gradle.kts",
        project_path / "settings.gradle",
        project_path / "settings.gradle.kts",
    )

    if any(
        path.is_file()
        for path in root_gradle_files
    ):
        return "gradle"

    for pom_path in project_path.rglob(
        "pom.xml"
    ):
        if not pom_path.is_file():
            continue

        if not is_ignored_file(
            pom_path,
            project_path,
        ):
            return "maven"

    for filename in (
        "build.gradle",
        "build.gradle.kts",
    ):
        for gradle_path in project_path.rglob(
            filename
        ):
            if not gradle_path.is_file():
                continue

            if not is_ignored_file(
                gradle_path,
                project_path,
            ):
                return "gradle"

    return "unknown"


def analyze_java_reachability(
    project_path: str,
    package_name: str,
    import_names: list[str] | None = None,
) -> ReachabilityResult:
    root = Path(
        project_path
    ).expanduser().resolve()

    if not root.exists():
        raise ValueError(
            f"Project path does not exist: {root}"
        )

    if not root.is_dir():
        raise ValueError(
            f"Project path is not a directory: {root}"
        )

    resolved_import_names = (
        import_names
        or default_java_import_names(
            package_name
        )
    )

    build_system = detect_java_build_system(
        root
    )

    usages = scan_java_imports(
        project_path=root,
        import_names=resolved_import_names,
    )

    dependency_classification = (
        classify_java_dependency(
            project_path=root,
            package_name=package_name,
        )
    )

    production_usage_found = any(
        not usage.is_test_file
        for usage in usages
    )

    test_only = (
        bool(usages)
        and not production_usage_found
    )

    reachability = (
        "likely"
        if production_usage_found
        else "unlikely"
    )

    return ReachabilityResult(
        package_name=package_name,
        ecosystem="Maven",
        import_names=resolved_import_names,
        build_system=build_system,
        dependency_type=(
            dependency_classification.dependency_type
        ),
        dependency_evidence=(
            dependency_classification.evidence
        ),
        usage_found=bool(usages),
        production_usage_found=(
            production_usage_found
        ),
        test_only=test_only,
        used_in=usages,
        vulnerable_api_used=None,
        internet_facing=None,
        reachability=reachability,
        limitations=[
            (
                "The Maven group ID is only an estimated "
                "Java import prefix. Use import_names when "
                "the Java package differs."
            ),
            (
                "Maven transitive classification requires "
                "a saved dependency:tree report."
            ),
            (
                "Gradle transitive classification requires "
                "a saved dependencies report or dependency "
                "lockfile."
            ),
            (
                "Gradle version catalogs, variables, "
                "dependency constraints, and custom "
                "configurations may not be detected."
            ),
            (
                "Static import detection does not prove "
                "that the imported code executes at "
                "runtime."
            ),
        ],
    )
