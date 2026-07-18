"""Shared helpers used across all reachability analysers."""

from pathlib import Path


IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "target",
}


def is_ignored_file(
    file_path: Path,
    project_root: Path,
) -> bool:
    """Return whether a file is inside an ignored directory."""

    relative_path = file_path.relative_to(project_root)

    return any(
        part in IGNORED_DIRECTORIES
        for part in relative_path.parts
    )


def is_test_file(path: Path) -> bool:
    directory_names = {
        part.lower()
        for part in path.parts[:-1]
    }
    filename = path.name.lower()

    if directory_names & {
        "test",
        "tests",
        "__tests__",
        "spec",
        "specs",
    }:
        return True

    return (
        filename.startswith("test_")
        or filename.endswith("_test.py")
        or ".test." in filename
        or ".spec." in filename
    )


def matches_import(
    imported_name: str,
    expected_names: set[str],
) -> bool:
    """Check whether an import belongs to the dependency."""

    return any(
        imported_name == expected
        or imported_name.startswith(f"{expected}.")
        for expected in expected_names
    )


def line_number(content: str, position: int) -> int:
    return content.count("\n", 0, position) + 1
