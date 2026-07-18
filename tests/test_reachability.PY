from vulnpilot.reachability import (
    analyze_python_reachability,
)


def test_detects_production_python_imports(
    tmp_path,
):
    source_directory = tmp_path / "src"
    source_directory.mkdir()

    source_file = source_directory / "service.py"
    source_file.write_text(
        "\n".join(
            [
                "import requests",
                "from requests.sessions import Session",
            ]
        ),
        encoding="utf-8",
    )

    result = analyze_python_reachability(
        project_path=str(tmp_path),
        package_name="requests",
    )

    assert result.usage_found is True
    assert result.production_usage_found is True
    assert result.test_only is False
    assert result.reachability == "likely"

    assert len(result.used_in) == 2

    assert result.used_in[0].file == "src/service.py"
    assert result.used_in[0].line == 1
    assert result.used_in[0].kind == "import"

    assert result.used_in[1].line == 2
    assert result.used_in[1].kind == "from_import"


def test_detects_test_only_imports(
    tmp_path,
):
    tests_directory = tmp_path / "tests"
    tests_directory.mkdir()

    test_file = tests_directory / "test_service.py"
    test_file.write_text(
        "import requests\n",
        encoding="utf-8",
    )

    result = analyze_python_reachability(
        project_path=str(tmp_path),
        package_name="requests",
    )

    assert result.usage_found is True
    assert result.production_usage_found is False
    assert result.test_only is True
    assert result.reachability == "unlikely"
    assert result.used_in[0].is_test_file is True


def test_returns_unlikely_when_import_not_found(
    tmp_path,
):
    source_file = tmp_path / "service.py"
    source_file.write_text(
        "import json\n",
        encoding="utf-8",
    )

    result = analyze_python_reachability(
        project_path=str(tmp_path),
        package_name="requests",
    )

    assert result.usage_found is False
    assert result.production_usage_found is False
    assert result.test_only is False
    assert result.used_in == []
    assert result.reachability == "unlikely"


def test_supports_custom_import_name(
    tmp_path,
):
    source_file = tmp_path / "parser.py"
    source_file.write_text(
        "from bs4 import BeautifulSoup\n",
        encoding="utf-8",
    )

    result = analyze_python_reachability(
        project_path=str(tmp_path),
        package_name="beautifulsoup4",
        import_names=["bs4"],
    )

    assert result.usage_found is True
    assert result.used_in[0].imported_name == "bs4"


def test_ignores_virtual_environment(
    tmp_path,
):
    virtual_environment = tmp_path / ".venv"
    virtual_environment.mkdir()

    dependency_file = virtual_environment / "dependency.py"
    dependency_file.write_text(
        "import requests\n",
        encoding="utf-8",
    )

    result = analyze_python_reachability(
        project_path=str(tmp_path),
        package_name="requests",
    )

    assert result.usage_found is False
