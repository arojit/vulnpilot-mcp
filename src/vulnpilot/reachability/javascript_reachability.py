"""JavaScript / TypeScript reachability analysis."""

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
from vulnpilot.reachability.javascript_dependencies import (
    classify_javascript_dependency,
)


JAVASCRIPT_EXTENSIONS = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
}

STATIC_IMPORT_PATTERN = re.compile(
    r"""
    ^[ \t]*import[ \t]+
    (?!\()
    (?:type[ \t]+)?
    (?:[^;"']*?[ \t\r\n]+from[ \t\r\n]+)?
    (?P<quote>["'])
    (?P<module>[^"']+)
    (?P=quote)
    """,
    re.MULTILINE | re.VERBOSE,
)

REQUIRE_PATTERN = re.compile(
    r"""
    \brequire
    [ \t\r\n]*\(
    [ \t\r\n]*
    (?P<quote>["'])
    (?P<module>[^"']+)
    (?P=quote)
    [ \t\r\n]*\)
    """,
    re.VERBOSE,
)

DYNAMIC_IMPORT_PATTERN = re.compile(
    r"""
    \bimport
    [ \t\r\n]*\(
    [ \t\r\n]*
    (?P<quote>["'])
    (?P<module>[^"']+)
    (?P=quote)
    [ \t\r\n]*\)
    """,
    re.VERBOSE,
)


def matches_javascript_import(
    imported_module: str,
    import_names: list[str],
) -> bool:
    return any(
        imported_module == import_name
        or imported_module.startswith(f"{import_name}/")
        for import_name in import_names
    )


def is_probably_commented(
    content: str,
    position: int,
) -> bool:
    line_start = content.rfind("\n", 0, position) + 1
    prefix = content[line_start:position]
    stripped_prefix = prefix.lstrip()

    if stripped_prefix.startswith(("//", "/*", "*")):
        return True

    # Handles inline comments such as:
    # // const lodash = require("lodash")
    return "//" in prefix


def scan_javascript_imports(
    project_path: Path,
    import_names: list[str],
) -> list[UsageLocation]:
    usages: list[UsageLocation] = []
    seen: set[tuple[str, int, str, str]] = set()

    patterns = [
        (STATIC_IMPORT_PATTERN, "import"),
        (REQUIRE_PATTERN, "require"),
        (DYNAMIC_IMPORT_PATTERN, "dynamic_import"),
    ]

    for file_path in project_path.rglob("*"):
        if not file_path.is_file():
            continue

        if file_path.suffix.lower() not in JAVASCRIPT_EXTENSIONS:
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

        relative_path = file_path.relative_to(project_path)
        relative_path_string = relative_path.as_posix()

        for pattern, usage_kind in patterns:
            for match in pattern.finditer(content):
                imported_module = match.group("module")

                if not matches_javascript_import(
                    imported_module,
                    import_names,
                ):
                    continue

                if is_probably_commented(
                    content,
                    match.start(),
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
                    usage_kind,
                )

                if usage_key in seen:
                    continue

                seen.add(usage_key)

                usages.append(
                    UsageLocation(
                        file=relative_path_string,
                        line=usage_line,
                        imported_name=imported_module,
                        kind=usage_kind,
                        is_test_file=is_test_file(relative_path),
                    )
                )

    return sorted(
        usages,
        key=lambda usage: (
            usage.file,
            usage.line,
            usage.kind,
        ),
    )


def analyze_javascript_reachability(
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

    resolved_import_names = import_names or [package_name]

    usages = scan_javascript_imports(
        project_path=root,
        import_names=resolved_import_names,
    )

    production_usage_found = any(
        not usage.is_test_file
        for usage in usages
    )

    test_only = bool(usages) and not production_usage_found

    if production_usage_found:
        reachability = "likely"
    elif usages:
        reachability = "unlikely"
    else:
        reachability = "unlikely"
    
    dependency_classification = (
        classify_javascript_dependency(
            project_path=root,
            package_name=package_name,
        )
    )

    return ReachabilityResult(
        package_name=package_name,
        ecosystem="npm",
        import_names=resolved_import_names,
        dependency_type=(
            dependency_classification.dependency_type
        ),
        dependency_evidence=(
            dependency_classification.evidence
        ),
        usage_found=bool(usages),
        production_usage_found=production_usage_found,
        test_only=test_only,
        used_in=usages,
        vulnerable_api_used=None,
        internet_facing=None,
        reachability=reachability,
        limitations=[
            (
                "Static import detection does not prove that "
                "the imported code executes at runtime."
            ),
            (
                "Computed module names, bundler aliases, and "
                "custom module resolvers may not be detected."
            ),
            (
                "Yarn and pnpm lockfiles are detected using "
                "package selector patterns rather than a full "
                "package-manager-specific parser."
            ),
        ],
    )
