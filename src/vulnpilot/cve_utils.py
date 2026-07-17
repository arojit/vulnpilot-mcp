from vulnpilot.models import Vulnerability


def extract_cve_ids(
    vulnerability: Vulnerability,
) -> list[str]:
    """Extract unique CVE identifiers from a vulnerability."""

    identifiers = {
        vulnerability.id,
        *vulnerability.aliases,
    }

    return sorted(
        identifier.upper()
        for identifier in identifiers
        if identifier.upper().startswith("CVE-")
    )
