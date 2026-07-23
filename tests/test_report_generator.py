"""Tests for the VulnPilot HTML report generator."""

import os
from pathlib import Path

import pytest

from vulnpilot.models import (
    ExploitIntelligence,
    PackageCheckResult,
    PackageReport,
    ReachabilityResult,
    Vulnerability,
)
from vulnpilot.report_generator import (
    build_report,
    generate_html_report,
    save_report,
)


# ── Fixtures ─────────────────────────────────────────────


def _make_vuln(
    vuln_id: str = "GHSA-1234-abcd-5678",
    summary: str = "Test vulnerability",
    severity: str | None = "HIGH",
    priority: str = "NORMAL",
    fixed_versions: list[str] | None = None,
    aliases: list[str] | None = None,
    references: list[str] | None = None,
    known_exploited: bool = False,
    epss_probability: float | None = None,
) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        summary=summary,
        severity=severity,
        priority=priority,
        fixed_versions=fixed_versions or [],
        aliases=aliases or [],
        references=references or [],
        exploit_intelligence=ExploitIntelligence(
            known_exploited=known_exploited,
            epss_probability=epss_probability,
        ),
    )


def _make_check_result(
    package_name: str = "example-pkg",
    version: str = "1.0.0",
    vulns: list[Vulnerability] | None = None,
) -> PackageCheckResult:
    vulns = vulns or []
    return PackageCheckResult(
        package_name=package_name,
        version=version,
        ecosystem="PyPI",
        vulnerable=len(vulns) > 0,
        vulnerability_count=len(vulns),
        vulnerabilities=vulns,
    )


def _make_reachability(
    usage_found: bool = True,
    production_usage_found: bool = True,
    test_only: bool = False,
) -> ReachabilityResult:
    return ReachabilityResult(
        package_name="example-pkg",
        ecosystem="PyPI",
        import_names=["example_pkg"],
        usage_found=usage_found,
        production_usage_found=production_usage_found,
        test_only=test_only,
        reachability="likely" if production_usage_found else "unlikely",
    )


# ── Tests ────────────────────────────────────────────────


class TestGenerateHtmlReport:
    """Tests for generate_html_report."""

    def test_empty_packages_produces_valid_html(self):
        html = generate_html_report([], project_name="Empty")
        assert "<!DOCTYPE html>" in html
        assert "All Clear" in html
        assert "Empty" in html

    def test_no_vulns_shows_all_clear(self):
        pkg = PackageReport(
            check_result=_make_check_result(vulns=[]),
        )
        html = generate_html_report([pkg])
        assert "All Clear" in html
        assert "No known vulnerabilities" in html

    def test_single_vulnerable_package(self):
        vuln = _make_vuln(
            vuln_id="GHSA-test-0001",
            severity="CRITICAL",
            priority="HIGH",
        )
        pkg = PackageReport(
            check_result=_make_check_result(
                package_name="django",
                version="2.2.0",
                vulns=[vuln],
            ),
        )
        html = generate_html_report([pkg], project_name="MyApp")
        assert "GHSA-test-0001" in html
        assert "django" in html
        assert "2.2.0" in html
        assert "MyApp" in html
        # Stats cards
        assert ">1<" in html  # vulnerable count

    def test_mixed_vulnerable_and_clean(self):
        vuln = _make_vuln(priority="URGENT")
        vulnerable_pkg = PackageReport(
            check_result=_make_check_result(
                package_name="vuln-pkg", vulns=[vuln],
            ),
        )
        clean_pkg = PackageReport(
            check_result=_make_check_result(
                package_name="safe-pkg", vulns=[],
            ),
        )
        html = generate_html_report(
            [vulnerable_pkg, clean_pkg],
        )
        assert "vuln-pkg" in html
        # Should not appear in the table, but the card stats
        # should reflect 2 total packages
        assert ">2<" in html  # total packages

    def test_priority_badges_present(self):
        vulns = [
            _make_vuln(
                vuln_id="V1",
                priority="IMMEDIATE",
                known_exploited=True,
            ),
            _make_vuln(
                vuln_id="V2",
                priority="URGENT",
            ),
            _make_vuln(
                vuln_id="V3",
                priority="HIGH",
            ),
            _make_vuln(
                vuln_id="V4",
                priority="NORMAL",
            ),
        ]
        pkg = PackageReport(
            check_result=_make_check_result(vulns=vulns),
        )
        html = generate_html_report([pkg])
        assert "badge-immediate" in html
        assert "badge-urgent" in html
        assert "badge-high" in html
        assert "badge-normal" in html

    def test_cisa_kev_badge_when_exploited(self):
        vuln = _make_vuln(
            known_exploited=True,
            priority="IMMEDIATE",
        )
        pkg = PackageReport(
            check_result=_make_check_result(vulns=[vuln]),
        )
        html = generate_html_report([pkg])
        assert "badge-kev" in html
        assert "KEV" in html

    def test_cisa_kev_absent_when_not_exploited(self):
        vuln = _make_vuln(known_exploited=False)
        pkg = PackageReport(
            check_result=_make_check_result(vulns=[vuln]),
        )
        html = generate_html_report([pkg])
        # The KEV warning badge should NOT be rendered in the table
        assert '"badge badge-kev">⚠ KEV<' not in html

    def test_epss_display(self):
        vuln = _make_vuln(epss_probability=0.85)
        pkg = PackageReport(
            check_result=_make_check_result(vulns=[vuln]),
        )
        html = generate_html_report([pkg])
        assert "85.0%" in html

    def test_reachability_badge_production(self):
        pkg = PackageReport(
            check_result=_make_check_result(
                vulns=[_make_vuln()],
            ),
            reachability=_make_reachability(
                production_usage_found=True,
            ),
        )
        html = generate_html_report([pkg])
        assert "badge-reachable" in html
        assert "Production" in html

    def test_reachability_badge_test_only(self):
        pkg = PackageReport(
            check_result=_make_check_result(
                vulns=[_make_vuln()],
            ),
            reachability=_make_reachability(
                production_usage_found=False,
                test_only=True,
            ),
        )
        html = generate_html_report([pkg])
        assert "badge-test-only" in html

    def test_reachability_badge_not_used(self):
        pkg = PackageReport(
            check_result=_make_check_result(
                vulns=[_make_vuln()],
            ),
            reachability=_make_reachability(
                usage_found=False,
                production_usage_found=False,
            ),
        )
        html = generate_html_report([pkg])
        assert "badge-not-used" in html

    def test_reachability_not_analyzed(self):
        pkg = PackageReport(
            check_result=_make_check_result(
                vulns=[_make_vuln()],
            ),
            reachability=None,
        )
        html = generate_html_report([pkg])
        assert "Not analyzed" in html

    def test_fix_versions_displayed(self):
        vuln = _make_vuln(fixed_versions=["3.2.1", "4.0.0"])
        pkg = PackageReport(
            check_result=_make_check_result(vulns=[vuln]),
        )
        html = generate_html_report([pkg])
        assert "3.2.1" in html
        assert "4.0.0" in html

    def test_no_fix_available(self):
        vuln = _make_vuln(fixed_versions=[])
        pkg = PackageReport(
            check_result=_make_check_result(vulns=[vuln]),
        )
        html = generate_html_report([pkg])
        assert "No fix available" in html

    def test_risk_gauge_critical(self):
        vuln = _make_vuln(
            priority="IMMEDIATE",
            known_exploited=True,
        )
        pkg = PackageReport(
            check_result=_make_check_result(vulns=[vuln]),
        )
        html = generate_html_report([pkg])
        assert "risk-critical" in html
        assert "CRITICAL" in html

    def test_risk_gauge_low(self):
        html = generate_html_report([])
        assert "risk-low" in html
        assert "LOW" in html

    def test_html_escaping(self):
        vuln = _make_vuln(
            vuln_id="<script>alert(1)</script>",
        )
        pkg = PackageReport(
            check_result=_make_check_result(
                package_name="<b>bad</b>",
                vulns=[vuln],
            ),
        )
        html = generate_html_report([pkg])
        # The user-supplied vuln ID must be escaped
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        # The user-supplied package name must be escaped
        assert "&lt;b&gt;bad&lt;/b&gt;" in html
        # Raw injection must NOT appear in table cells
        assert "<b>bad</b>" not in html

    def test_vuln_id_linked_when_references_present(self):
        vuln = _make_vuln(
            vuln_id="GHSA-link-test",
            references=["https://osv.dev/GHSA-link-test"],
        )
        pkg = PackageReport(
            check_result=_make_check_result(vulns=[vuln]),
        )
        html = generate_html_report([pkg])
        assert 'href="https://osv.dev/GHSA-link-test"' in html

    def test_ecosystem_in_header(self):
        html = generate_html_report(
            [], project_name="Test", ecosystem="npm",
        )
        assert "npm" in html

    def test_contains_sort_js(self):
        html = generate_html_report([])
        assert "data-sort" in html or "sort" in html.lower()


class TestSaveReport:
    """Tests for save_report."""

    def test_saves_file_to_disk(self, tmp_path):
        html = "<html><body>test</body></html>"
        path = save_report(
            html,
            output_dir=str(tmp_path),
            filename="test-report.html",
        )
        assert os.path.isfile(path)
        assert path.endswith("test-report.html")
        assert Path(path).read_text() == html

    def test_creates_directory(self, tmp_path):
        nested = tmp_path / "deep" / "nested"
        path = save_report(
            "<html/>",
            output_dir=str(nested),
            filename="report.html",
        )
        assert os.path.isfile(path)

    def test_auto_generates_filename(self, tmp_path):
        path = save_report("<html/>", output_dir=str(tmp_path))
        assert "vulnpilot-report-" in path
        assert path.endswith(".html")
        assert os.path.isfile(path)


class TestBuildReport:
    """Tests for build_report (end-to-end)."""

    def test_end_to_end_empty(self, tmp_path):
        result = build_report(
            packages=[],
            project_name="E2E Test",
            output_dir=str(tmp_path),
        )
        assert result.total_packages == 0
        assert result.vulnerable_packages == 0
        assert result.total_vulnerabilities == 0
        assert os.path.isfile(result.report_path)
        assert "<!DOCTYPE html>" in result.report_html

    def test_end_to_end_with_vulns(self, tmp_path):
        vulns = [
            _make_vuln(priority="IMMEDIATE", known_exploited=True),
            _make_vuln(vuln_id="V2", priority="HIGH"),
        ]
        pkg = PackageReport(
            check_result=_make_check_result(vulns=vulns),
            reachability=_make_reachability(),
            dependency_scope="production",
        )
        result = build_report(
            packages=[pkg],
            project_name="Vuln Test",
            output_dir=str(tmp_path),
        )
        assert result.total_packages == 1
        assert result.vulnerable_packages == 1
        assert result.total_vulnerabilities == 2
        assert result.immediate_count == 1
        assert result.high_count == 1
        assert os.path.isfile(result.report_path)
