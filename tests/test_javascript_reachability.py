from vulnpilot.reachability import (
    analyze_javascript_reachability,
)


def test_detects_static_javascript_import(tmp_path):
    source_directory = tmp_path / "src"
    source_directory.mkdir()

    source_file = source_directory / "query-builder.js"
    source_file.write_text(
        'import lodash from "lodash";\n',
        encoding="utf-8",
    )

    result = analyze_javascript_reachability(
        project_path=str(tmp_path),
        package_name="lodash",
    )

    assert result.usage_found is True
    assert result.production_usage_found is True
    assert result.test_only is False
    assert result.reachability == "likely"

    assert len(result.used_in) == 1
    assert result.used_in[0].file == "src/query-builder.js"
    assert result.used_in[0].line == 1
    assert result.used_in[0].imported_name == "lodash"
    assert result.used_in[0].kind == "import"


def test_detects_typescript_named_import(tmp_path):
    source_file = tmp_path / "app.ts"
    source_file.write_text(
        'import { get, set } from "lodash";\n',
        encoding="utf-8",
    )

    result = analyze_javascript_reachability(
        project_path=str(tmp_path),
        package_name="lodash",
    )

    assert result.usage_found is True
    assert result.used_in[0].kind == "import"


def test_detects_multiline_typescript_import(tmp_path):
    source_file = tmp_path / "app.ts"
    source_file.write_text(
        """
import {
    get,
    set,
} from "lodash";
""".strip(),
        encoding="utf-8",
    )

    result = analyze_javascript_reachability(
        project_path=str(tmp_path),
        package_name="lodash",
    )

    assert result.usage_found is True
    assert result.used_in[0].imported_name == "lodash"


def test_detects_commonjs_require(tmp_path):
    source_file = tmp_path / "app.cjs"
    source_file.write_text(
        'const lodash = require("lodash");\n',
        encoding="utf-8",
    )

    result = analyze_javascript_reachability(
        project_path=str(tmp_path),
        package_name="lodash",
    )

    assert result.usage_found is True
    assert result.used_in[0].kind == "require"


def test_detects_dynamic_import(tmp_path):
    source_file = tmp_path / "app.js"
    source_file.write_text(
        'const lodash = await import("lodash");\n',
        encoding="utf-8",
    )

    result = analyze_javascript_reachability(
        project_path=str(tmp_path),
        package_name="lodash",
    )

    assert result.usage_found is True
    assert result.used_in[0].kind == "dynamic_import"


def test_detects_package_subpath(tmp_path):
    source_file = tmp_path / "app.js"
    source_file.write_text(
        'import get from "lodash/get";\n',
        encoding="utf-8",
    )

    result = analyze_javascript_reachability(
        project_path=str(tmp_path),
        package_name="lodash",
    )

    assert result.usage_found is True
    assert result.used_in[0].imported_name == "lodash/get"


def test_does_not_match_similar_package_name(tmp_path):
    source_file = tmp_path / "app.js"
    source_file.write_text(
        'import lodash from "lodash-es";\n',
        encoding="utf-8",
    )

    result = analyze_javascript_reachability(
        project_path=str(tmp_path),
        package_name="lodash",
    )

    assert result.usage_found is False


def test_detects_scoped_npm_package(tmp_path):
    source_file = tmp_path / "app.ts"
    source_file.write_text(
        'import client from "@example/api-client/http";\n',
        encoding="utf-8",
    )

    result = analyze_javascript_reachability(
        project_path=str(tmp_path),
        package_name="@example/api-client",
    )

    assert result.usage_found is True
    assert (
        result.used_in[0].imported_name
        == "@example/api-client/http"
    )


def test_marks_javascript_test_only_usage(tmp_path):
    test_directory = tmp_path / "src" / "__tests__"
    test_directory.mkdir(parents=True)

    test_file = test_directory / "query-builder.test.ts"
    test_file.write_text(
        'import lodash from "lodash";\n',
        encoding="utf-8",
    )

    result = analyze_javascript_reachability(
        project_path=str(tmp_path),
        package_name="lodash",
    )

    assert result.usage_found is True
    assert result.production_usage_found is False
    assert result.test_only is True
    assert result.reachability == "unlikely"
    assert result.used_in[0].is_test_file is True


def test_ignores_node_modules(tmp_path):
    dependency_directory = (
        tmp_path / "node_modules" / "example"
    )
    dependency_directory.mkdir(parents=True)

    dependency_file = dependency_directory / "index.js"
    dependency_file.write_text(
        'const lodash = require("lodash");\n',
        encoding="utf-8",
    )

    result = analyze_javascript_reachability(
        project_path=str(tmp_path),
        package_name="lodash",
    )

    assert result.usage_found is False


def test_returns_unlikely_when_package_is_unused(tmp_path):
    source_file = tmp_path / "app.ts"
    source_file.write_text(
        'import express from "express";\n',
        encoding="utf-8",
    )

    result = analyze_javascript_reachability(
        project_path=str(tmp_path),
        package_name="lodash",
    )

    assert result.usage_found is False
    assert result.production_usage_found is False
    assert result.test_only is False
    assert result.used_in == []
    assert result.reachability == "unlikely"

def test_javascript_reachability_includes_dependency_type(
    tmp_path,
):
    (tmp_path / "package.json").write_text(
        """
{
  "name": "example",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21"
  }
}
""".strip(),
        encoding="utf-8",
    )

    source_directory = tmp_path / "src"
    source_directory.mkdir()

    (
        source_directory / "query-builder.ts"
    ).write_text(
        """
import lodash from "lodash";
""".strip(),
        encoding="utf-8",
    )

    result = analyze_javascript_reachability(
        project_path=str(tmp_path),
        package_name="lodash",
    )

    assert result.usage_found is True
    assert result.reachability == "likely"
    assert result.dependency_type == "direct"
    assert "package.json" in (
        result.dependency_evidence[0]
    )
