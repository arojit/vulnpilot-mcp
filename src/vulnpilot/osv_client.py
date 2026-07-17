import httpx
from typing import Any
from vulnpilot.models import Vulnerability


OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def normalize_vulnerability(
    vulnerability: dict[str, Any],
) -> Vulnerability:
    """Convert an OSV vulnerability into our response model."""

    database_specific = (
        vulnerability.get("database_specific") or {}
    )

    severity = database_specific.get("severity")

    fixed_versions = set()

    for affected_package in vulnerability.get("affected", []):
        for version_range in affected_package.get("ranges", []):
            for event in version_range.get("events", []):
                fixed_version = event.get("fixed")

                if fixed_version:
                    fixed_versions.add(fixed_version)

    references = set()

    for reference in vulnerability.get("references", []):
        url = reference.get("url")

        if url:
            references.add(url)

    return Vulnerability(
        id=vulnerability.get("id", "UNKNOWN"),
        summary=vulnerability.get(
            "summary",
            "No summary available",
        ),
        aliases=sorted(set(vulnerability.get("aliases", []))),
        severity=severity,
        fixed_versions=sorted(fixed_versions),
        references=sorted(references),
    )

async def query_osv(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Send a vulnerability query to OSV."""

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                OSV_QUERY_URL,
                json=payload,
            )
            response.raise_for_status()

    except httpx.TimeoutException as exc:
        raise RuntimeError(
            "The OSV request timed out. Please try again."
        ) from exc

    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"OSV returned HTTP status {exc.response.status_code}."
        ) from exc

    except httpx.RequestError as exc:
        raise RuntimeError(
            "Could not connect to the OSV service."
        ) from exc

    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(
            "OSV returned an invalid JSON response."
        ) from exc