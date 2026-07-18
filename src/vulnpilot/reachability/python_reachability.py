"""Python reachability analysis."""

import ast
from pathlib import Path

from vulnpilot.models import (
    ReachabilityResult,
    UsageLocation,
)
from vulnpilot.reachability._common import (
    is_ignored_file,
    is_test_file,
    matches_import,
)


def default_python_import_name(
    package_name: str,
) -> str:
    """Derive a likely import name from a PyPI name."""

    return package_name.replace("-", "_")


def scan_python_imports(
    project_path: Path,
    import_names: list[str],
) -> list[UsageLocation]:
    """Find Python imports matching a dependency."""

    expected_names = set(import_names)
    usages = []

    for file_path in project_path.rglob("*.py"):
        if is_ignored_file(file_path, project_path):
            continue

        try:
            source_code = file_path.read_text(
                encoding="utf-8"
            )
            syntax_tree = ast.parse(
                source_code,
                filename=str(file_path),
            )
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue

        relative_path = file_path.relative_to(project_path)
        relative_file = relative_path.as_posix()

        for node in ast.walk(syntax_tree):
            if isinstance(node, ast.Import):
                for imported_module in node.names:
                    if matches_import(
                        imported_module.name,
                        expected_names,
                    ):
                        usages.append(
                            UsageLocation(
                                file=relative_file,
                                line=node.lineno,
                                imported_name=(
                                    imported_module.name
                                ),
                                kind="import",
                                is_test_file=is_test_file(
                                    relative_path
                                ),
                            )
                        )

            elif isinstance(node, ast.ImportFrom):
                module_name = node.module

                if (
                    module_name
                    and matches_import(
                        module_name,
                        expected_names,
                    )
                ):
                    usages.append(
                        UsageLocation(
                            file=relative_file,
                            line=node.lineno,
                            imported_name=module_name,
                            kind="from_import",
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
            usage.imported_name,
        ),
    )


def analyze_python_reachability(
    project_path: str,
    package_name: str,
    import_names: list[str] | None = None,
) -> ReachabilityResult:
    """Analyze whether a Python dependency is imported."""

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
        if import_names
        else [default_python_import_name(package_name)]
    )

    usages = scan_python_imports(
        root,
        resolved_import_names,
    )

    usage_found = bool(usages)

    production_usage_found = any(
        not usage.is_test_file
        for usage in usages
    )

    test_only = (
        usage_found
        and not production_usage_found
    )

    reachability = (
        "likely"
        if production_usage_found
        else "unlikely"
    )

    return ReachabilityResult(
        package_name=package_name,
        ecosystem="PyPI",
        import_names=resolved_import_names,
        dependency_type="unknown",
        usage_found=usage_found,
        production_usage_found=production_usage_found,
        test_only=test_only,
        used_in=usages,
        vulnerable_api_used=None,
        internet_facing=None,
        reachability=reachability,
        limitations=[
            (
                "This is static import detection and does not "
                "prove that vulnerable code executes at runtime."
            ),
            (
                "Dynamic imports, plugin loading and reflection "
                "may not be detected."
            ),
        ],
    )
