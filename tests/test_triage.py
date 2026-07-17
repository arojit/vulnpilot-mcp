import pytest

from vulnpilot.models import Vulnerability
from vulnpilot.triage import calculate_priority


def make_vulnerability(
    *,
    severity="HIGH",
    known_exploited=False,
    epss_probability=None,
):
    vulnerability = Vulnerability(
        id="GHSA-test",
        summary="Test vulnerability",
        severity=severity,
    )

    intelligence = vulnerability.exploit_intelligence
    intelligence.known_exploited = known_exploited
    intelligence.epss_probability = epss_probability

    return vulnerability


def test_kev_is_immediate():
    vulnerability = make_vulnerability(
        known_exploited=True,
    )

    priority = calculate_priority(
        vulnerability,
        is_reachable=False,
        dependency_scope="development",
    )

    assert priority == "IMMEDIATE"


def test_reachable_high_epss_is_urgent():
    vulnerability = make_vulnerability(
        epss_probability=0.75,
    )

    priority = calculate_priority(
        vulnerability,
        is_reachable=True,
        dependency_scope="development",
    )

    assert priority == "URGENT"


def test_critical_production_dependency_is_high():
    vulnerability = make_vulnerability(
        severity="CRITICAL",
        epss_probability=0.01,
    )

    priority = calculate_priority(
        vulnerability,
        is_reachable=False,
        dependency_scope="production",
    )

    assert priority == "HIGH"


@pytest.mark.parametrize(
    ("reachable", "scope"),
    [
        (False, "production"),
        (True, "development"),
        (None, "unknown"),
    ],
)
def test_other_findings_are_normal(
    reachable,
    scope,
):
    vulnerability = make_vulnerability(
        severity="MODERATE",
        epss_probability=0.01,
    )

    priority = calculate_priority(
        vulnerability,
        is_reachable=reachable,
        dependency_scope=scope,
    )

    assert priority == "NORMAL"
