from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ._common import (
    DependencyClassification,
    is_ignored_file,
)


DIRECT_DEPENDENCY_FIELDS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
    "bundledDependencies",
    "bundleDependencies",
)

JSON_LOCK_FILENAMES = (
    "package-lock.json",
    "npm-shrinkwrap.json",
)

TEXT_LOCK_FILENAMES = (
    "yarn.lock",
    "pnpm-lock.yaml",
)


def normalize_npm_package_name(
    package_name: str,
) -> str:
    """
    Normalize an npm package name.

    Examples:

        lodash -> lodash
        @Example/Client -> @example/client
    """
    return package_name.strip().lower()


def load_json_file(
    path: Path,
) -> dict[str, Any] | None:
    try:
        data = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        return None

    if not isinstance(data, dict):
        return None

    return data


def find_project_files(
    project_path: Path,
    filename: str,
) -> list[Path]:
    files: list[Path] = []

    for file_path in project_path.rglob(
        filename
    ):
        if not file_path.is_file():
            continue

        if is_ignored_file(
            file_path,
            project_path,
        ):
            continue

        files.append(file_path)

    return sorted(files)


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


def read_package_json_dependencies(
    package_json_path: Path,
) -> set[str]:
    data = load_json_file(
        package_json_path
    )

    if data is None:
        return set()

    dependencies: set[str] = set()

    for dependency_field in (
        DIRECT_DEPENDENCY_FIELDS
    ):
        declared_dependencies = data.get(
            dependency_field
        )

        if isinstance(
            declared_dependencies,
            dict,
        ):
            dependencies.update(
                normalize_npm_package_name(name)
                for name
                in declared_dependencies
                if isinstance(name, str)
            )

        # bundledDependencies may also be an array.
        elif isinstance(
            declared_dependencies,
            list,
        ):
            dependencies.update(
                normalize_npm_package_name(name)
                for name
                in declared_dependencies
                if isinstance(name, str)
            )

    return dependencies


def find_direct_javascript_dependencies(
    project_path: Path,
) -> tuple[dict[str, set[str]], set[str]]:
    """
    Return:

        package name -> package.json files declaring it

    The second value contains every valid package.json
    manifest found in the project.
    """
    declarations: dict[str, set[str]] = {}
    manifest_files: set[str] = set()

    for package_json_path in find_project_files(
        project_path,
        "package.json",
    ):
        data = load_json_file(
            package_json_path
        )

        if data is None:
            continue

        relative_path = relative_path_string(
            package_json_path,
            project_path,
        )
        manifest_files.add(relative_path)

        dependencies = (
            read_package_json_dependencies(
                package_json_path
            )
        )

        for dependency_name in dependencies:
            declarations.setdefault(
                dependency_name,
                set(),
            ).add(relative_path)

    return declarations, manifest_files


def collect_legacy_lock_dependencies(
    dependencies: Any,
    resolved_packages: set[str],
) -> None:
    """
    Read package-lock.json lockfileVersion 1 dependency
    trees recursively.
    """
    if not isinstance(dependencies, dict):
        return

    for package_name, package_data in (
        dependencies.items()
    ):
        if isinstance(package_name, str):
            resolved_packages.add(
                normalize_npm_package_name(
                    package_name
                )
            )

        if not isinstance(package_data, dict):
            continue

        collect_legacy_lock_dependencies(
            package_data.get("dependencies"),
            resolved_packages,
        )


def package_name_from_node_modules_path(
    package_path: str,
) -> str | None:
    """
    Examples:

        node_modules/lodash
            -> lodash

        node_modules/a/node_modules/lodash
            -> lodash

        node_modules/@scope/package
            -> @scope/package
    """
    marker = "node_modules/"

    if marker not in package_path:
        return None

    package_name = package_path.rsplit(
        marker,
        1,
    )[-1]

    if not package_name:
        return None

    return normalize_npm_package_name(
        package_name
    )


def read_package_lock_packages(
    lock_path: Path,
) -> set[str]:
    data = load_json_file(lock_path)

    if data is None:
        return set()

    resolved_packages: set[str] = set()

    # package-lock v2/v3:
    #
    # "packages": {
    #     "node_modules/lodash": {...}
    # }
    packages = data.get("packages")

    if isinstance(packages, dict):
        for package_path in packages:
            if not isinstance(package_path, str):
                continue

            package_name = (
                package_name_from_node_modules_path(
                    package_path
                )
            )

            if package_name:
                resolved_packages.add(
                    package_name
                )

    # package-lock v1, and compatibility data in
    # some newer lockfiles.
    collect_legacy_lock_dependencies(
        data.get("dependencies"),
        resolved_packages,
    )

    return resolved_packages


def text_lockfile_contains_package(
    lock_path: Path,
    package_name: str,
) -> bool:
    """
    Detect package selectors in yarn.lock and
    pnpm-lock.yaml.

    Yarn examples:

        lodash@^4.17.0:
        "@scope/client@^1.0.0":

    pnpm examples:

        lodash@4.17.21:
        '@scope/client@1.0.0':
        /lodash/4.17.21:
    """
    try:
        content = lock_path.read_text(
            encoding="utf-8"
        )
    except (OSError, UnicodeDecodeError):
        return False

    normalized_name = (
        normalize_npm_package_name(
            package_name
        )
    )

    pattern = re.compile(
        rf"""
        ^[ \t]*
        ["']?
        /?
        {re.escape(normalized_name)}
        (?:@|/)
        [^:\n]*
        ["']?
        :
        """,
        re.MULTILINE | re.VERBOSE | re.IGNORECASE,
    )

    return pattern.search(content) is not None


def find_resolved_javascript_lockfiles(
    project_path: Path,
    package_name: str,
) -> list[str]:
    target_name = normalize_npm_package_name(
        package_name
    )
    resolved_lockfiles: set[str] = set()

    for lock_filename in JSON_LOCK_FILENAMES:
        for lock_path in find_project_files(
            project_path,
            lock_filename,
        ):
            resolved_packages = (
                read_package_lock_packages(
                    lock_path
                )
            )

            if target_name in resolved_packages:
                resolved_lockfiles.add(
                    relative_path_string(
                        lock_path,
                        project_path,
                    )
                )

    for lock_filename in TEXT_LOCK_FILENAMES:
        for lock_path in find_project_files(
            project_path,
            lock_filename,
        ):
            if text_lockfile_contains_package(
                lock_path=lock_path,
                package_name=package_name,
            ):
                resolved_lockfiles.add(
                    relative_path_string(
                        lock_path,
                        project_path,
                    )
                )

    return sorted(resolved_lockfiles)


def format_sources(
    sources: set[str],
) -> str:
    return ", ".join(sorted(sources))


def classify_javascript_dependency(
    project_path: Path,
    package_name: str,
) -> DependencyClassification:
    root = project_path.expanduser().resolve()

    target_name = normalize_npm_package_name(
        package_name
    )

    direct_dependencies, manifest_files = (
        find_direct_javascript_dependencies(
            root
        )
    )

    direct_sources = direct_dependencies.get(
        target_name
    )

    # package.json is the authoritative source for
    # direct dependencies.
    if direct_sources:
        return DependencyClassification(
            dependency_type="direct",
            evidence=[
                (
                    f"{package_name} is directly declared "
                    f"in {format_sources(direct_sources)}"
                )
            ],
        )

    resolved_lockfiles = (
        find_resolved_javascript_lockfiles(
            project_path=root,
            package_name=package_name,
        )
    )

    # A resolved package absent from every package.json
    # dependency section is transitive.
    if resolved_lockfiles and manifest_files:
        return DependencyClassification(
            dependency_type="transitive",
            evidence=[
                (
                    f"{package_name} appears in "
                    f"{', '.join(resolved_lockfiles)}, "
                    "but is not directly declared in any "
                    "package.json"
                )
            ],
        )

    # A lockfile without package.json proves resolution,
    # but cannot reliably distinguish direct/transitive.
    if resolved_lockfiles:
        return DependencyClassification(
            dependency_type="unknown",
            evidence=[
                (
                    f"{package_name} appears in "
                    f"{', '.join(resolved_lockfiles)}, "
                    "but no valid package.json was found"
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
