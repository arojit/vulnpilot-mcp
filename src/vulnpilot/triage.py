from vulnpilot.models import (
    DependencyScope,
    TriagePriority,
    Vulnerability,
)


HIGH_EPSS_THRESHOLD = 0.5


def calculate_priority(
    vulnerability: Vulnerability,
    *,
    is_reachable: bool | None,
    dependency_scope: DependencyScope,
) -> TriagePriority:
    """Calculate an explainable remediation priority."""

    intelligence = vulnerability.exploit_intelligence

    if intelligence.known_exploited:
        return "IMMEDIATE"

    if (
        is_reachable is True
        and intelligence.epss_probability is not None
        and intelligence.epss_probability
        >= HIGH_EPSS_THRESHOLD
    ):
        return "URGENT"

    if (
        dependency_scope == "production"
        and vulnerability.severity == "CRITICAL"
    ):
        return "HIGH"

    return "NORMAL"


def assign_priorities(
    vulnerabilities: list[Vulnerability],
    *,
    is_reachable: bool | None,
    dependency_scope: DependencyScope,
) -> list[Vulnerability]:
    """Assign priority to every vulnerability."""

    for vulnerability in vulnerabilities:
        vulnerability.priority = calculate_priority(
            vulnerability,
            is_reachable=is_reachable,
            dependency_scope=dependency_scope,
        )

    return vulnerabilities
