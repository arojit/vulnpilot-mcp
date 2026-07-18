"""Java reachability analysis (Maven & Gradle)."""

import re
import xml.etree.ElementTree as ET
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

GRADLE_DEPENDENCY_CONFIGURATIONS = (
    "api",
    "implementation",
    "compile",
    "compileOnly",
    "runtime",
    "runtimeOnly",
    "annotationProcessor",
    "testImplementation",
    "testCompileOnly",
    "testRuntimeOnly",
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
    Maven coordinates normally look like:

        group_id:artifact_id

    The group ID is a reasonable default import prefix, but it
    is not guaranteed to match the Java package name.
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

    for file_path in project_path.rglob("*.java"):
        if not file_path.is_file():
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
        relative_path_string = relative_path.as_posix()

        for match in JAVA_IMPORT_PATTERN.finditer(
            content
        ):
            imported_module = match.group("module")

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


# ---------------------------------------------------------------------------
# Maven helpers
# ---------------------------------------------------------------------------

def xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def xml_child_text(
    element: ET.Element,
    child_name: str,
) -> str | None:
    for child in element:
        if xml_local_name(child.tag) == child_name:
            if child.text:
                return child.text.strip()

    return None


def is_maven_dependency_direct(
    pom_path: Path,
    group_id: str,
    artifact_id: str,
) -> bool:
    try:
        tree = ET.parse(pom_path)
    except (ET.ParseError, OSError):
        return False

    root = tree.getroot()

    parent_map = {
        child: parent
        for parent in root.iter()
        for child in parent
    }

    for element in root.iter():
        if xml_local_name(element.tag) != "dependency":
            continue

        ancestor = parent_map.get(element)
        excluded = False

        while ancestor is not None:
            ancestor_name = xml_local_name(
                ancestor.tag
            )

            if ancestor_name in {
                "dependencyManagement",
                "plugin",
                "plugins",
                "reporting",
            }:
                excluded = True
                break

            ancestor = parent_map.get(ancestor)

        if excluded:
            continue

        dependency_group = xml_child_text(
            element,
            "groupId",
        )
        dependency_artifact = xml_child_text(
            element,
            "artifactId",
        )

        if (
            dependency_group == group_id
            and dependency_artifact == artifact_id
        ):
            return True

    return False


def has_direct_maven_dependency(
    project_path: Path,
    package_name: str,
) -> bool:
    coordinate = package_name.split(":")

    if len(coordinate) < 2:
        return False

    group_id = coordinate[0]
    artifact_id = coordinate[1]

    for pom_path in project_path.rglob("pom.xml"):
        if is_ignored_file(
            pom_path,
            project_path,
        ):
            continue

        if is_maven_dependency_direct(
            pom_path,
            group_id,
            artifact_id,
        ):
            return True

    return False


# ---------------------------------------------------------------------------
# Gradle helpers
# ---------------------------------------------------------------------------

def gradle_dependency_pattern(
    group_id: str,
    artifact_id: str,
) -> re.Pattern[str]:
    configurations = "|".join(
        re.escape(configuration)
        for configuration
        in GRADLE_DEPENDENCY_CONFIGURATIONS
    )

    coordinate = (
        f"{re.escape(group_id)}:"
        f"{re.escape(artifact_id)}"
    )

    return re.compile(
        rf"""
        \b(?:{configurations})
        \s*
        \(?
        \s*
        (?:platform\s*\(\s*)?
        ["']
        {coordinate}
        (?=[:'"]) 
        """,
        re.VERBOSE,
    )


def has_direct_gradle_dependency(
    project_path: Path,
    package_name: str,
) -> bool:
    coordinate = package_name.split(":")

    if len(coordinate) < 2:
        return False

    group_id = coordinate[0]
    artifact_id = coordinate[1]

    pattern = gradle_dependency_pattern(
        group_id,
        artifact_id,
    )

    build_files = [
        *project_path.rglob("build.gradle"),
        *project_path.rglob("build.gradle.kts"),
    ]

    for build_file in build_files:
        if is_ignored_file(
            build_file,
            project_path,
        ):
            continue

        try:
            content = build_file.read_text(
                encoding="utf-8",
                errors="ignore",
            )
        except OSError:
            continue

        if pattern.search(content):
            return True

    return False


# ---------------------------------------------------------------------------
# Build-system detection
# ---------------------------------------------------------------------------

def detect_java_build_system(
    project_path: Path,
) -> str:
    root_pom = project_path / "pom.xml"

    if root_pom.exists():
        return "maven"

    root_gradle_files = [
        project_path / "build.gradle",
        project_path / "build.gradle.kts",
        project_path / "settings.gradle",
        project_path / "settings.gradle.kts",
    ]

    if any(path.exists() for path in root_gradle_files):
        return "gradle"

    for pom_path in project_path.rglob("pom.xml"):
        if not is_ignored_file(
            pom_path,
            project_path,
        ):
            return "maven"

    for pattern in (
        "build.gradle",
        "build.gradle.kts",
    ):
        for gradle_path in project_path.rglob(pattern):
            if not is_ignored_file(
                gradle_path,
                project_path,
            ):
                return "gradle"

    return "unknown"


# ---------------------------------------------------------------------------
# Public analyser
# ---------------------------------------------------------------------------

def analyze_java_reachability(
    project_path: str,
    package_name: str,
    import_names: list[str] | None = None,
) -> ReachabilityResult:
    root = Path(project_path).expanduser().resolve()

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
        or default_java_import_names(package_name)
    )

    build_system = detect_java_build_system(root)

    usages = scan_java_imports(
        project_path=root,
        import_names=resolved_import_names,
    )

    if build_system == "maven":
        directly_declared = (
            has_direct_maven_dependency(
                root,
                package_name,
            )
        )
    elif build_system == "gradle":
        directly_declared = (
            has_direct_gradle_dependency(
                root,
                package_name,
            )
        )
    else:
        directly_declared = False

    dependency_type = (
        "direct"
        if directly_declared
        else "unknown"
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
        dependency_type=dependency_type,
        usage_found=bool(usages),
        production_usage_found=production_usage_found,
        test_only=test_only,
        used_in=usages,
        vulnerable_api_used=None,
        internet_facing=None,
        reachability=reachability,
        limitations=[
            (
                "The Maven group ID is only an estimated Java "
                "import prefix. Use import_names when they differ."
            ),
            (
                "A dependency absent from the build file is marked "
                "unknown, not transitive, until a resolved dependency "
                "graph is available."
            ),
            (
                "Gradle version catalogs, variables, dependency "
                "constraints, and custom configurations may not be "
                "detected."
            ),
            (
                "Import detection does not prove that the imported "
                "code executes at runtime."
            ),
        ],
    )
