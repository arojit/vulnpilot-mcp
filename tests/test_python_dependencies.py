import json
from pathlib import Path

from vulnpilot.reachability.python_dependencies import (
    classify_python_dependency,
)


def write_pyproject(
    project_path: Path,
    dependencies: list[str],
) -> None:
    formatted_dependencies = ",\n".join(
        f'    "{dependency}"'
        for dependency in dependencies
    )

    (project_path / "pyproject.toml").write_text(
        f"""
[project]
name = "example-project"
version = "0.1.0"
dependencies = [
{formatted_dependencies}
]
""".strip(),
        encoding="utf-8",
    )


def write_pip_inspect(
    project_path: Path,
    package_name: str,
    requested: bool | None,
) -> None:
    package: dict[str, object] = {
        "metadata": {
            "name": package_name,
            "version": "1.0.0",
        }
    }

    if requested is not None:
        package["requested"] = requested

    report = {
        "version": "1",
        "pip_version": "25.0",
        "installed": [package],
        "environment": {},
    }

    (
        project_path / "pip-inspect.json"
    ).write_text(
        json.dumps(report),
        encoding="utf-8",
    )


def test_pyproject_dependency_is_direct(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        ["requests>=2.31"],
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="requests",
    )

    assert result.dependency_type == "direct"
    assert "pyproject.toml" in result.evidence[0]


def test_optional_dependency_is_direct(
    tmp_path,
):
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "example"
version = "0.1.0"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=8"]
""".strip(),
        encoding="utf-8",
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="pytest",
    )

    assert result.dependency_type == "direct"


def test_dependency_group_is_direct(
    tmp_path,
):
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "example"
version = "0.1.0"
dependencies = []

[dependency-groups]
dev = ["pytest>=8"]
""".strip(),
        encoding="utf-8",
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="pytest",
    )

    assert result.dependency_type == "direct"


def test_poetry_dependency_is_direct(
    tmp_path,
):
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.poetry]
name = "example"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.31"
""".strip(),
        encoding="utf-8",
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="requests",
    )

    assert result.dependency_type == "direct"


def test_requirements_in_dependency_is_direct(
    tmp_path,
):
    (tmp_path / "requirements.in").write_text(
        """
django>=4.2
requests>=2.31
""".strip(),
        encoding="utf-8",
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="requests",
    )

    assert result.dependency_type == "direct"
    assert "requirements.in" in result.evidence[0]


def test_requirements_txt_dependency_is_direct(
    tmp_path,
):
    (tmp_path / "requirements.txt").write_text(
        """
django==4.2
requests==2.31
""".strip(),
        encoding="utf-8",
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="requests",
    )

    assert result.dependency_type == "direct"
    assert "requirements.txt" in result.evidence[0]


def test_uv_lock_dependency_is_transitive(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        ["requests>=2.31"],
    )

    (tmp_path / "uv.lock").write_text(
        """
version = 1
revision = 1

[[package]]
name = "requests"
version = "2.32.0"

[[package]]
name = "urllib3"
version = "2.2.0"
""".strip(),
        encoding="utf-8",
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="urllib3",
    )

    assert result.dependency_type == "transitive"
    assert "uv.lock" in result.evidence[0]


def test_direct_declaration_beats_lockfile(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        ["urllib3>=2"],
    )

    (tmp_path / "uv.lock").write_text(
        """
version = 1

[[package]]
name = "urllib3"
version = "2.2.0"
""".strip(),
        encoding="utf-8",
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="urllib3",
    )

    assert result.dependency_type == "direct"


def test_pip_requested_package_is_direct(
    tmp_path,
):
    write_pip_inspect(
        project_path=tmp_path,
        package_name="requests",
        requested=True,
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="requests",
    )

    assert result.dependency_type == "direct"
    assert "requested=true" in result.evidence[0]


def test_pip_unrequested_package_is_transitive(
    tmp_path,
):
    write_pip_inspect(
        project_path=tmp_path,
        package_name="urllib3",
        requested=False,
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="urllib3",
    )

    assert result.dependency_type == "transitive"
    assert "requested=false" in result.evidence[0]


def test_pip_inspect_overrides_generated_requirements(
    tmp_path,
):
    (tmp_path / "requirements.txt").write_text(
        "urllib3==2.2.0",
        encoding="utf-8",
    )

    write_pip_inspect(
        project_path=tmp_path,
        package_name="urllib3",
        requested=False,
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="urllib3",
    )

    assert result.dependency_type == "transitive"


def test_pip_missing_requested_is_unknown(
    tmp_path,
):
    write_pip_inspect(
        project_path=tmp_path,
        package_name="urllib3",
        requested=None,
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="urllib3",
    )

    assert result.dependency_type == "unknown"


def test_normalizes_python_package_names(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        ["Flask-SQLAlchemy>=3"],
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="flask_sqlalchemy",
    )

    assert result.dependency_type == "direct"


def test_lock_without_manifest_is_unknown(
    tmp_path,
):
    (tmp_path / "uv.lock").write_text(
        """
version = 1

[[package]]
name = "urllib3"
version = "2.2.0"
""".strip(),
        encoding="utf-8",
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="urllib3",
    )

    assert result.dependency_type == "unknown"


def test_missing_dependency_is_unknown(
    tmp_path,
):
    write_pyproject(
        tmp_path,
        ["requests>=2"],
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="urllib3",
    )

    assert result.dependency_type == "unknown"


def test_malformed_pip_report_does_not_crash(
    tmp_path,
):
    (
        tmp_path / "pip-inspect.json"
    ).write_text(
        "not valid JSON",
        encoding="utf-8",
    )

    result = classify_python_dependency(
        project_path=tmp_path,
        package_name="requests",
    )

    assert result.dependency_type == "unknown"
