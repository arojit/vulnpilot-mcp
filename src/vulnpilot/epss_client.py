from dataclasses import dataclass
from vulnpilot.models import Vulnerability
from vulnpilot.cve_utils import extract_cve_ids
import httpx


EPSS_API_URL = "https://api.first.org/data/v1/epss"


class EPSSClientError(RuntimeError):
    """Raised when EPSS information cannot be retrieved."""


@dataclass(frozen=True)
class EPSSScore:
    """Normalized EPSS information for one CVE."""

    cve: str
    probability: float
    percentile: float


def extract_cve_ids(
    vulnerability: Vulnerability,
) -> list[str]:
    """Extract CVE identifiers from an OSV vulnerability."""

    identifiers = {
        vulnerability.id,
        *vulnerability.aliases,
    }

    return sorted(
        identifier.upper()
        for identifier in identifiers
        if identifier.upper().startswith("CVE-")
    )


async def fetch_epss_scores(
    cve_ids: list[str],
) -> dict[str, EPSSScore]:
    """Fetch EPSS scores for multiple CVEs in one request."""

    unique_cves = sorted(set(cve_ids))

    if not unique_cves:
        return {}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                EPSS_API_URL,
                params={
                    "cve": ",".join(unique_cves),
                },
            )
            response.raise_for_status()

    except httpx.TimeoutException as exc:
        raise EPSSClientError(
            "The EPSS request timed out."
        ) from exc

    except httpx.HTTPStatusError as exc:
        raise EPSSClientError(
            f"EPSS returned HTTP status "
            f"{exc.response.status_code}."
        ) from exc

    except httpx.RequestError as exc:
        raise EPSSClientError(
            "Could not connect to the EPSS service."
        ) from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise EPSSClientError(
            "EPSS returned invalid JSON."
        ) from exc

    scores = {}

    for item in data.get("data", []):
        try:
            score = EPSSScore(
                cve=item["cve"].upper(),
                probability=float(item["epss"]),
                percentile=float(item["percentile"]),
            )
        except (KeyError, TypeError, ValueError):
            continue

        scores[score.cve] = score

    return scores


async def enrich_with_epss(
    vulnerabilities: list[Vulnerability],
) -> list[Vulnerability]:
    """Add the highest matching EPSS score to each vulnerability."""

    cve_ids = [
        cve
        for vulnerability in vulnerabilities
        for cve in extract_cve_ids(vulnerability)
    ]

    scores = await fetch_epss_scores(cve_ids)

    for vulnerability in vulnerabilities:
        matching_scores = [
            scores[cve]
            for cve in extract_cve_ids(vulnerability)
            if cve in scores
        ]

        if not matching_scores:
            continue

        highest_score = max(
            matching_scores,
            key=lambda score: score.probability,
        )

        intelligence = vulnerability.exploit_intelligence
        intelligence.epss_cve = highest_score.cve
        intelligence.epss_probability = highest_score.probability
        intelligence.epss_percentile = highest_score.percentile

    return vulnerabilities