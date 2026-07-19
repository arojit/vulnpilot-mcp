"""Tests for MCP prompts and resources."""

import json

from vulnpilot.server import (
    DEPENDENCY_EVIDENCE_COMMANDS,
    DEPENDENCY_EVIDENCE_GUIDE,
    SUPPORTED_ECOSYSTEMS,
    TRIAGE_RULES_MARKDOWN,
    generate_dependency_evidence,
    security_audit,
    supported_ecosystems_resource,
    triage_rules_resource,
    triage_vulnerability,
    dependency_evidence_guide_resource,
)


# ── Prompt Tests ─────────────────────────────────────────────────


class TestSecurityAuditPrompt:
    """Tests for the security_audit prompt."""

    def test_returns_string(self):
        result = security_audit(
            project_path="/tmp/project",
            ecosystem="PyPI",
            dependencies="django:4.2.0, requests:2.31.0",
        )
        assert isinstance(result, str)

    def test_contains_project_path(self):
        result = security_audit(
            project_path="/home/user/myproject",
            ecosystem="npm",
            dependencies="lodash:4.17.21",
        )
        assert "/home/user/myproject" in result

    def test_contains_ecosystem(self):
        result = security_audit(
            project_path="/tmp/project",
            ecosystem="Maven",
            dependencies="org.apache.logging.log4j:log4j-core:2.14.1",
        )
        assert "Maven" in result

    def test_contains_dependencies(self):
        deps = "django:4.2.0, requests:2.31.0"
        result = security_audit(
            project_path="/tmp/project",
            ecosystem="PyPI",
            dependencies=deps,
        )
        assert deps in result

    def test_references_check_package(self):
        result = security_audit(
            project_path="/tmp/project",
            ecosystem="PyPI",
            dependencies="django:4.2.0",
        )
        assert "check_package" in result

    def test_references_analyze_reachability(self):
        result = security_audit(
            project_path="/tmp/project",
            ecosystem="PyPI",
            dependencies="django:4.2.0",
        )
        assert "analyze_reachability" in result


class TestTriageVulnerabilityPrompt:
    """Tests for the triage_vulnerability prompt."""

    def test_returns_string(self):
        result = triage_vulnerability(
            package_name="django",
            version="2.2.0",
            ecosystem="PyPI",
            project_path="/tmp/project",
        )
        assert isinstance(result, str)

    def test_contains_package_name(self):
        result = triage_vulnerability(
            package_name="lodash",
            version="4.17.21",
            ecosystem="npm",
            project_path="/tmp/project",
        )
        assert "lodash" in result

    def test_contains_version(self):
        result = triage_vulnerability(
            package_name="django",
            version="2.2.0",
            ecosystem="PyPI",
            project_path="/tmp/project",
        )
        assert "2.2.0" in result

    def test_contains_project_path(self):
        result = triage_vulnerability(
            package_name="django",
            version="2.2.0",
            ecosystem="PyPI",
            project_path="/home/user/app",
        )
        assert "/home/user/app" in result

    def test_references_check_package(self):
        result = triage_vulnerability(
            package_name="django",
            version="2.2.0",
            ecosystem="PyPI",
            project_path="/tmp/project",
        )
        assert "check_package" in result

    def test_references_analyze_reachability(self):
        result = triage_vulnerability(
            package_name="django",
            version="2.2.0",
            ecosystem="PyPI",
            project_path="/tmp/project",
        )
        assert "analyze_reachability" in result

    def test_mentions_cisa_kev(self):
        result = triage_vulnerability(
            package_name="django",
            version="2.2.0",
            ecosystem="PyPI",
            project_path="/tmp/project",
        )
        assert "CISA KEV" in result

    def test_mentions_direct_transitive(self):
        result = triage_vulnerability(
            package_name="django",
            version="2.2.0",
            ecosystem="PyPI",
            project_path="/tmp/project",
        )
        assert "direct" in result
        assert "transitive" in result


class TestGenerateDependencyEvidencePrompt:
    """Tests for the generate_dependency_evidence prompt."""

    def test_pypi_returns_pip_commands(self):
        result = generate_dependency_evidence(ecosystem="PyPI")
        assert "pip inspect" in result
        assert ".vulnpilot" in result

    def test_pypi_mentions_lock_files(self):
        result = generate_dependency_evidence(ecosystem="PyPI")
        assert "uv.lock" in result
        assert "poetry.lock" in result

    def test_npm_mentions_lock_files(self):
        result = generate_dependency_evidence(ecosystem="npm")
        assert "package-lock.json" in result
        assert "yarn.lock" in result
        assert "pnpm-lock.yaml" in result

    def test_maven_returns_mvn_command(self):
        result = generate_dependency_evidence(ecosystem="Maven")
        assert "mvn dependency:tree" in result
        assert "maven-dependency-tree.txt" in result

    def test_gradle_returns_gradlew_command(self):
        result = generate_dependency_evidence(ecosystem="Gradle")
        assert "gradlew dependencies" in result
        assert "runtimeClasspath" in result

    def test_gradle_includes_test_config(self):
        result = generate_dependency_evidence(ecosystem="Gradle")
        assert "testRuntimeClasspath" in result

    def test_unsupported_ecosystem(self):
        result = generate_dependency_evidence(ecosystem="Cargo")
        assert "Unsupported ecosystem" in result
        assert "Cargo" in result

    def test_all_ecosystems_have_commands(self):
        for ecosystem in ("PyPI", "npm", "Maven", "Gradle"):
            result = generate_dependency_evidence(
                ecosystem=ecosystem,
            )
            assert isinstance(result, str)
            assert len(result) > 50


# ── Resource Tests ───────────────────────────────────────────────


class TestSupportedEcosystemsResource:
    """Tests for the supported-ecosystems resource."""

    def test_returns_valid_json(self):
        result = supported_ecosystems_resource()
        data = json.loads(result)
        assert isinstance(data, list)

    def test_contains_all_ecosystems(self):
        result = supported_ecosystems_resource()
        data = json.loads(result)
        ecosystems = {e["ecosystem"] for e in data}
        assert ecosystems == {"PyPI", "npm", "Maven", "Gradle"}

    def test_each_ecosystem_has_required_fields(self):
        result = supported_ecosystems_resource()
        data = json.loads(result)

        required_fields = {
            "ecosystem",
            "package_name_format",
            "example",
            "tools",
            "reachability_scanner",
            "dependency_classification",
        }

        for entry in data:
            assert required_fields.issubset(entry.keys()), (
                f"Missing fields in {entry.get('ecosystem')}: "
                f"{required_fields - entry.keys()}"
            )

    def test_each_ecosystem_lists_tools(self):
        result = supported_ecosystems_resource()
        data = json.loads(result)

        for entry in data:
            assert "check_package" in entry["tools"]
            assert "analyze_reachability" in entry["tools"]

    def test_constant_matches_resource(self):
        result = supported_ecosystems_resource()
        assert json.loads(result) == SUPPORTED_ECOSYSTEMS


class TestTriageRulesResource:
    """Tests for the triage-rules resource."""

    def test_returns_string(self):
        result = triage_rules_resource()
        assert isinstance(result, str)

    def test_contains_all_priority_levels(self):
        result = triage_rules_resource()
        for level in ("IMMEDIATE", "URGENT", "HIGH", "NORMAL"):
            assert level in result

    def test_mentions_cisa_kev(self):
        result = triage_rules_resource()
        assert "CISA" in result
        assert "KEV" in result

    def test_mentions_epss(self):
        result = triage_rules_resource()
        assert "EPSS" in result

    def test_constant_matches_resource(self):
        result = triage_rules_resource()
        assert result == TRIAGE_RULES_MARKDOWN


class TestDependencyEvidenceGuideResource:
    """Tests for the dependency-evidence-guide resource."""

    def test_returns_string(self):
        result = dependency_evidence_guide_resource()
        assert isinstance(result, str)

    def test_contains_all_ecosystem_sections(self):
        result = dependency_evidence_guide_resource()
        assert "Python" in result
        assert "JavaScript" in result
        assert "Maven" in result
        assert "Gradle" in result

    def test_contains_pip_command(self):
        result = dependency_evidence_guide_resource()
        assert "pip inspect" in result

    def test_contains_mvn_command(self):
        result = dependency_evidence_guide_resource()
        assert "mvn dependency:tree" in result

    def test_contains_gradlew_command(self):
        result = dependency_evidence_guide_resource()
        assert "gradlew dependencies" in result

    def test_contains_gitignore_tip(self):
        result = dependency_evidence_guide_resource()
        assert ".gitignore" in result

    def test_constant_matches_resource(self):
        result = dependency_evidence_guide_resource()
        assert result == DEPENDENCY_EVIDENCE_GUIDE
