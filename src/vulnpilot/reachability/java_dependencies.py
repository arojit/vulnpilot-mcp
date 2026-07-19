from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ._common import (
    DependencyClassification,
    is_ignored_file,
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
    "kapt",
)

MAVEN_REPORT_FILENAMES = (
    "maven-dependency-tree.txt",
    "dependency-tree.txt",
)

GRADLE_REPORT_FILENAMES = (
    "gradle-dependencies.txt",
    "dependencies.txt",
)


def parse_java_coordinate(
    package_name: str,
) -> tuple[str, str] | None:
    """
    Parse a Maven-style coordinate.

    Supported:

        group:artifact
        group:artifact:version
    """
    parts = package_name.strip().split(":")

    if len(parts) < 2:
        return None

    group_id = parts[0].strip()
    artifact_id = parts[1].strip()

    if not group_id or not artifact_id:
        return None

    return group_id, artifact_id


def xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def xml_child_text(
    element: ET.Element,
    child_name: str,
) -> str | None:
    for child in element:
        if xml_local_name(child.tag) != child_name:
            continue

        if child.text:
            return child.text.strip()

    return None


def has_excluded_maven_ancestor(
    element: ET.Element,
    parent_map: dict[ET.Element, ET.Element],
) -> bool:
    ancestor = parent_map.get(element)

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
            return True

        ancestor = parent_map.get(ancestor)

    return False


def read_maven_direct_dependencies(
    pom_path: Path,
) -> set[tuple[str, str]]:
    try:
        tree = ET.parse(pom_path)
    except (ET.ParseError, OSError):
        return set()

    root = tree.getroot()

    parent_map = {
        child: parent
        for parent in root.iter()
        for child in parent
    }

    dependencies: set[tuple[str, str]] = set()

    for element in root.iter():
        if xml_local_name(
            element.tag
        ) != "dependency":
            continue

        if has_excluded_maven_ancestor(
            element,
            parent_map,
        ):
            continue

        group_id = xml_child_text(
            element,
            "groupId",
        )
        artifact_id = xml_child_text(
            element,
            "artifactId",
        )

        if group_id and artifact_id:
            dependencies.add(
                (group_id, artifact_id)
            )

    return dependencies


def find_maven_direct_sources(
    project_path: Path,
    group_id: str,
    artifact_id: str,
) -> tuple[set[str], set[str]]:
    direct_sources: set[str] = set()
    manifest_files: set[str] = set()

    for pom_path in project_path.rglob(
        "pom.xml"
    ):
        if not pom_path.is_file():
            continue

        if is_ignored_file(
            pom_path,
            project_path,
        ):
            continue

        try:
            relative_path = pom_path.relative_to(
                project_path
            ).as_posix()
        except ValueError:
            relative_path = pom_path.as_posix()

        manifest_files.add(relative_path)

        dependencies = (
            read_maven_direct_dependencies(
                pom_path
            )
        )

        if (
            group_id,
            artifact_id,
        ) in dependencies:
            direct_sources.add(relative_path)

    return direct_sources, manifest_files

def gradle_string_dependency_pattern(
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


def gradle_map_dependency_pattern(
    group_id: str,
    artifact_id: str,
) -> re.Pattern[str]:
    configurations = "|".join(
        re.escape(configuration)
        for configuration
        in GRADLE_DEPENDENCY_CONFIGURATIONS
    )

    return re.compile(
        rf"""
        \b(?:{configurations})
        \s*
        \(?
        [^)\n]*
        \bgroup\s*:\s*
        ["']{re.escape(group_id)}["']
        \s*,\s*
        \bname\s*:\s*
        ["']{re.escape(artifact_id)}["']
        """,
        re.VERBOSE,
    )


def read_gradle_build_file(
    build_file: Path,
) -> str | None:
    try:
        return build_file.read_text(
            encoding="utf-8"
        )
    except (OSError, UnicodeDecodeError):
        return None


def find_gradle_direct_sources(
    project_path: Path,
    group_id: str,
    artifact_id: str,
) -> tuple[set[str], set[str]]:
    direct_sources: set[str] = set()
    manifest_files: set[str] = set()

    string_pattern = (
        gradle_string_dependency_pattern(
            group_id,
            artifact_id,
        )
    )
    map_pattern = gradle_map_dependency_pattern(
        group_id,
        artifact_id,
    )

    build_files = [
        *project_path.rglob("build.gradle"),
        *project_path.rglob("build.gradle.kts"),
    ]

    for build_file in build_files:
        if not build_file.is_file():
            continue

        if is_ignored_file(
            build_file,
            project_path,
        ):
            continue

        content = read_gradle_build_file(
            build_file
        )

        if content is None:
            continue

        relative_path = build_file.relative_to(
            project_path
        ).as_posix()

        manifest_files.add(relative_path)

        if (
            string_pattern.search(content)
            or map_pattern.search(content)
        ):
            direct_sources.add(relative_path)

    return direct_sources, manifest_files

def coordinate_pattern(
    group_id: str,
    artifact_id: str,
) -> re.Pattern[str]:
    """
    Match an exact group:artifact coordinate.

    It will match:

        org.example:library:1.0

    but not:

        org.example:library-extra:1.0
    """
    return re.compile(
        rf"""
        (?<![A-Za-z0-9_.-])
        {re.escape(group_id)}
        :
        {re.escape(artifact_id)}
        (?=:)
        """,
        re.VERBOSE,
    )


def file_contains_coordinate(
    path: Path,
    group_id: str,
    artifact_id: str,
) -> bool:
    try:
        content = path.read_text(
            encoding="utf-8"
        )
    except (OSError, UnicodeDecodeError):
        return False

    return (
        coordinate_pattern(
            group_id,
            artifact_id,
        ).search(content)
        is not None
    )


def relative_path_string(
    path: Path,
    project_path: Path,
) -> str:
    try:
        return path.relative_to(
            project_path
        ).as_posix()
    except ValueError:
        return path.as_posix()


def find_named_report_files(
    project_path: Path,
    filenames: tuple[str, ...],
) -> list[Path]:
    report_files: set[Path] = set()

    for filename in filenames:
        # Root-level report.
        root_report = project_path / filename

        if root_report.is_file():
            report_files.add(root_report)

        # Recommended VulnPilot report directory.
        vulnpilot_report = (
            project_path
            / ".vulnpilot"
            / filename
        )

        if vulnpilot_report.is_file():
            report_files.add(vulnpilot_report)

        # Multi-module reports.
        for report_path in project_path.rglob(
            filename
        ):
            if not report_path.is_file():
                continue

            if is_ignored_file(
                report_path,
                project_path,
            ):
                continue

            report_files.add(report_path)

    return sorted(report_files)


def find_dependency_report_evidence(
    project_path: Path,
    group_id: str,
    artifact_id: str,
) -> list[str]:
    evidence: set[str] = set()

    report_filenames = (
        *MAVEN_REPORT_FILENAMES,
        *GRADLE_REPORT_FILENAMES,
    )

    for report_path in find_named_report_files(
        project_path,
        report_filenames,
    ):
        if file_contains_coordinate(
            report_path,
            group_id,
            artifact_id,
        ):
            evidence.add(
                relative_path_string(
                    report_path,
                    project_path,
                )
            )

    return sorted(evidence)

def find_gradle_lockfiles(
    project_path: Path,
) -> list[Path]:
    lockfiles: set[Path] = set()

    for lock_path in project_path.rglob(
        "*.lockfile"
    ):
        if not lock_path.is_file():
            continue

        if is_ignored_file(
            lock_path,
            project_path,
        ):
            continue

        lockfiles.add(lock_path)

    root_lockfile = (
        project_path / "gradle.lockfile"
    )

    if root_lockfile.is_file():
        lockfiles.add(root_lockfile)

    return sorted(lockfiles)


def find_gradle_lock_evidence(
    project_path: Path,
    group_id: str,
    artifact_id: str,
) -> list[str]:
    evidence: set[str] = set()

    for lock_path in find_gradle_lockfiles(
        project_path
    ):
        if file_contains_coordinate(
            lock_path,
            group_id,
            artifact_id,
        ):
            evidence.add(
                relative_path_string(
                    lock_path,
                    project_path,
                )
            )

    return sorted(evidence)

def classify_java_dependency(
    project_path: Path,
    package_name: str,
) -> DependencyClassification:
    root = project_path.expanduser().resolve()

    coordinate = parse_java_coordinate(
        package_name
    )

    if coordinate is None:
        return DependencyClassification(
            dependency_type="unknown",
            evidence=[
                (
                    "Java dependency names must use "
                    "groupId:artifactId format"
                )
            ],
        )

    group_id, artifact_id = coordinate

    maven_direct_sources, pom_files = (
        find_maven_direct_sources(
            project_path=root,
            group_id=group_id,
            artifact_id=artifact_id,
        )
    )

    gradle_direct_sources, gradle_files = (
        find_gradle_direct_sources(
            project_path=root,
            group_id=group_id,
            artifact_id=artifact_id,
        )
    )

    direct_sources = {
        *maven_direct_sources,
        *gradle_direct_sources,
    }

    manifest_files = {
        *pom_files,
        *gradle_files,
    }

    # Direct declarations take precedence over resolved
    # dependency reports and lockfiles.
    if direct_sources:
        return DependencyClassification(
            dependency_type="direct",
            evidence=[
                (
                    f"{package_name} is directly declared "
                    f"in {', '.join(sorted(direct_sources))}"
                )
            ],
        )

    report_evidence = (
        find_dependency_report_evidence(
            project_path=root,
            group_id=group_id,
            artifact_id=artifact_id,
        )
    )

    gradle_lock_evidence = (
        find_gradle_lock_evidence(
            project_path=root,
            group_id=group_id,
            artifact_id=artifact_id,
        )
    )

    resolved_evidence = sorted(
        {
            *report_evidence,
            *gradle_lock_evidence,
        }
    )

    if resolved_evidence and manifest_files:
        return DependencyClassification(
            dependency_type="transitive",
            evidence=[
                (
                    f"{package_name} appears in resolved "
                    f"dependency evidence "
                    f"{', '.join(resolved_evidence)}, "
                    "but is not directly declared in a "
                    "Maven or Gradle build file"
                )
            ],
        )

    if resolved_evidence:
        return DependencyClassification(
            dependency_type="unknown",
            evidence=[
                (
                    f"{package_name} appears in "
                    f"{', '.join(resolved_evidence)}, "
                    "but no Maven or Gradle build "
                    "manifest was found"
                )
            ],
        )

    return DependencyClassification(
        dependency_type="unknown",
        evidence=[
            (
                "No direct declaration or resolved "
                "dependency evidence was found"
            )
        ],
    )
