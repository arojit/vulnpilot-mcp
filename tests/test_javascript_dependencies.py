import json
from pathlib import Path

from vulnpilot.reachability.javascript_dependencies import (
    classify_javascript_dependency,
)


def write_package_json(
    project_path: Path,
    **dependency_sections,
) -> None:
    package_json = {
        "name": "example-project",
        "version": "1.0.0",
        **dependency_sections,
    }

    (project_path / "package.json").write_text(
        json.dumps(package_json),
        encoding="utf-8",
    )


def write_package_lock(
    project_path: Path,
    packages: dict,
) -> None:
    package_lock = {
        "name": "example-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": packages,
    }

    (
        project_path / "package-lock.json"
    ).write_text(
        json.dumps(package_lock),
        encoding="utf-8",
    )


def test_production_dependency_is_direct(
    tmp_path,
):
    write_package_json(
        tmp_path,
        dependencies={
            "lodash": "^4.17.21",
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="lodash",
    )

    assert result.dependency_type == "direct"
    assert "package.json" in result.evidence[0]


def test_dev_dependency_is_direct(
    tmp_path,
):
    write_package_json(
        tmp_path,
        devDependencies={
            "vitest": "^2.0.0",
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="vitest",
    )

    assert result.dependency_type == "direct"


def test_peer_dependency_is_direct(
    tmp_path,
):
    write_package_json(
        tmp_path,
        peerDependencies={
            "react": "^18.0.0",
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="react",
    )

    assert result.dependency_type == "direct"


def test_optional_dependency_is_direct(
    tmp_path,
):
    write_package_json(
        tmp_path,
        optionalDependencies={
            "fsevents": "^2.3.0",
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="fsevents",
    )

    assert result.dependency_type == "direct"


def test_package_lock_v3_dependency_is_transitive(
    tmp_path,
):
    write_package_json(
        tmp_path,
        dependencies={
            "express": "^4.18.0",
        },
    )

    write_package_lock(
        tmp_path,
        packages={
            "": {
                "name": "example-project",
                "dependencies": {
                    "express": "^4.18.0",
                },
            },
            "node_modules/express": {
                "version": "4.18.0",
            },
            "node_modules/body-parser": {
                "version": "1.20.0",
            },
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="body-parser",
    )

    assert result.dependency_type == "transitive"
    assert (
        "package-lock.json"
        in result.evidence[0]
    )


def test_nested_package_lock_path_is_detected(
    tmp_path,
):
    write_package_json(
        tmp_path,
        dependencies={
            "example-parent": "^1.0.0",
        },
    )

    write_package_lock(
        tmp_path,
        packages={
            "": {},
            "node_modules/example-parent": {
                "version": "1.0.0",
            },
            (
                "node_modules/example-parent/"
                "node_modules/lodash"
            ): {
                "version": "4.17.21",
            },
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="lodash",
    )

    assert result.dependency_type == "transitive"


def test_package_lock_v1_dependency_is_transitive(
    tmp_path,
):
    write_package_json(
        tmp_path,
        dependencies={
            "express": "^4.18.0",
        },
    )

    package_lock = {
        "name": "example-project",
        "lockfileVersion": 1,
        "dependencies": {
            "express": {
                "version": "4.18.0",
                "dependencies": {
                    "body-parser": {
                        "version": "1.20.0",
                    }
                },
            }
        },
    }

    (
        tmp_path / "package-lock.json"
    ).write_text(
        json.dumps(package_lock),
        encoding="utf-8",
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="body-parser",
    )

    assert result.dependency_type == "transitive"


def test_scoped_package_is_direct(
    tmp_path,
):
    write_package_json(
        tmp_path,
        dependencies={
            "@example/api-client": "^1.0.0",
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="@example/api-client",
    )

    assert result.dependency_type == "direct"


def test_scoped_package_is_transitive(
    tmp_path,
):
    write_package_json(
        tmp_path,
        dependencies={
            "example-parent": "^1.0.0",
        },
    )

    write_package_lock(
        tmp_path,
        packages={
            "": {},
            "node_modules/example-parent": {
                "version": "1.0.0",
            },
            "node_modules/@example/api-client": {
                "version": "1.0.0",
            },
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="@example/api-client",
    )

    assert result.dependency_type == "transitive"


def test_yarn_lock_dependency_is_transitive(
    tmp_path,
):
    write_package_json(
        tmp_path,
        dependencies={
            "express": "^4.18.0",
        },
    )

    (tmp_path / "yarn.lock").write_text(
        """
express@^4.18.0:
  version "4.18.0"

body-parser@^1.20.0:
  version "1.20.0"
""".strip(),
        encoding="utf-8",
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="body-parser",
    )

    assert result.dependency_type == "transitive"
    assert "yarn.lock" in result.evidence[0]


def test_pnpm_lock_dependency_is_transitive(
    tmp_path,
):
    write_package_json(
        tmp_path,
        dependencies={
            "express": "^4.18.0",
        },
    )

    (
        tmp_path / "pnpm-lock.yaml"
    ).write_text(
        """
lockfileVersion: '9.0'

packages:
  express@4.18.0:
    resolution: {}

  body-parser@1.20.0:
    resolution: {}
""".strip(),
        encoding="utf-8",
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="body-parser",
    )

    assert result.dependency_type == "transitive"
    assert (
        "pnpm-lock.yaml"
        in result.evidence[0]
    )


def test_direct_declaration_beats_lockfile(
    tmp_path,
):
    write_package_json(
        tmp_path,
        dependencies={
            "lodash": "^4.17.21",
        },
    )

    write_package_lock(
        tmp_path,
        packages={
            "node_modules/lodash": {
                "version": "4.17.21",
            }
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="lodash",
    )

    assert result.dependency_type == "direct"


def test_workspace_dependency_is_direct(
    tmp_path,
):
    write_package_json(
        tmp_path,
        workspaces=["packages/*"],
    )

    workspace = tmp_path / "packages" / "api"
    workspace.mkdir(parents=True)

    write_package_json(
        workspace,
        dependencies={
            "lodash": "^4.17.21",
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="lodash",
    )

    assert result.dependency_type == "direct"
    assert (
        "packages/api/package.json"
        in result.evidence[0]
    )


def test_lockfile_without_manifest_is_unknown(
    tmp_path,
):
    write_package_lock(
        tmp_path,
        packages={
            "node_modules/lodash": {
                "version": "4.17.21",
            }
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="lodash",
    )

    assert result.dependency_type == "unknown"


def test_missing_dependency_is_unknown(
    tmp_path,
):
    write_package_json(
        tmp_path,
        dependencies={
            "express": "^4.18.0",
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="lodash",
    )

    assert result.dependency_type == "unknown"


def test_does_not_match_similar_package(
    tmp_path,
):
    write_package_json(
        tmp_path,
        dependencies={
            "lodash-es": "^4.17.21",
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="lodash",
    )

    assert result.dependency_type == "unknown"


def test_ignores_node_modules_manifests(
    tmp_path,
):
    write_package_json(
        tmp_path,
        dependencies={},
    )

    dependency_directory = (
        tmp_path / "node_modules" / "lodash"
    )
    dependency_directory.mkdir(parents=True)

    write_package_json(
        dependency_directory,
        dependencies={
            "another-package": "^1.0.0",
        },
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="another-package",
    )

    assert result.dependency_type == "unknown"


def test_malformed_package_json_does_not_crash(
    tmp_path,
):
    (tmp_path / "package.json").write_text(
        "not valid JSON",
        encoding="utf-8",
    )

    result = classify_javascript_dependency(
        project_path=tmp_path,
        package_name="lodash",
    )

    assert result.dependency_type == "unknown"
