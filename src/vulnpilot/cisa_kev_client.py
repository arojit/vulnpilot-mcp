from dataclasses import dataclass
from datetime import date
from time import monotonic

import httpx

from vulnpilot.cve_utils import extract_cve_ids
from vulnpilot.models import Vulnerability


CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

KEV_CACHE_TTL_SECONDS = 3600


class CISAKEVClientError(RuntimeError):
    """Raised when CISA KEV information cannot be retrieved."""


@dataclass(frozen=True)
class KEVEntry:
    """Normalized CISA KEV entry."""

    cve: str
    date_added: date
    due_date: date
    required_action: str
    known_ransomware_campaign_use: str | None


_kev_cache: dict[str, KEVEntry] | None = None
_kev_cache_expires_at: float = 0


async def fetch_cisa_kev_catalog() -> dict[str, KEVEntry]:
    """Download and normalize the CISA KEV catalog."""

    global _kev_cache
    global _kev_cache_expires_at

    current_time = monotonic()

    if (
        _kev_cache is not None
        and current_time < _kev_cache_expires_at
    ):
        return _kev_cache

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                CISA_KEV_URL,
                headers={
                    "User-Agent": (
                        "VulnPilot/0.1 "
                        "dependency-security-assistant"
                    )
                },
            )
            response.raise_for_status()

    except httpx.TimeoutException as exc:
        raise CISAKEVClientError(
            "The CISA KEV request timed out."
        ) from exc

    except httpx.HTTPStatusError as exc:
        raise CISAKEVClientError(
            f"CISA KEV returned HTTP status "
            f"{exc.response.status_code}."
        ) from exc

    except httpx.RequestError as exc:
        raise CISAKEVClientError(
            "Could not connect to CISA KEV."
        ) from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise CISAKEVClientError(
            "CISA KEV returned invalid JSON."
        ) from exc

    catalog = {}

    for item in data.get("vulnerabilities", []):
        try:
            entry = KEVEntry(
                cve=item["cveID"].upper(),
                date_added=date.fromisoformat(
                    item["dateAdded"]
                ),
                due_date=date.fromisoformat(
                    item["dueDate"]
                ),
                required_action=item["requiredAction"],
                known_ransomware_campaign_use=item.get(
                    "knownRansomwareCampaignUse"
                ),
            )
        except (KeyError, TypeError, ValueError):
            continue

        catalog[entry.cve] = entry

    _kev_cache = catalog
    _kev_cache_expires_at = (
        current_time + KEV_CACHE_TTL_SECONDS
    )

    return catalog


async def enrich_with_cisa_kev(
    vulnerabilities: list[Vulnerability],
) -> list[Vulnerability]:
    """Enrich vulnerabilities using the CISA KEV catalog."""

    catalog = await fetch_cisa_kev_catalog()

    for vulnerability in vulnerabilities:
        matched_entry = None

        for cve in extract_cve_ids(vulnerability):
            if cve in catalog:
                matched_entry = catalog[cve]
                break

        if matched_entry is None:
            continue

        intelligence = vulnerability.exploit_intelligence

        intelligence.known_exploited = True
        intelligence.cisa_kev_cve = matched_entry.cve
        intelligence.cisa_date_added = (
            matched_entry.date_added
        )
        intelligence.cisa_due_date = (
            matched_entry.due_date
        )
        intelligence.cisa_required_action = (
            matched_entry.required_action
        )
        intelligence.known_ransomware_campaign_use = (
            matched_entry.known_ransomware_campaign_use
        )

    return vulnerabilities