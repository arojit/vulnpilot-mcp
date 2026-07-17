from datetime import date

import httpx
import pytest
import respx

import vulnpilot.cisa_kev_client as cisa_client
from vulnpilot.cisa_kev_client import (
    CISA_KEV_URL,
    CISAKEVClientError,
    KEVEntry,
    enrich_with_cisa_kev,
    fetch_cisa_kev_catalog,
)
from vulnpilot.models import Vulnerability


@pytest.fixture(autouse=True)
def reset_cisa_cache(monkeypatch):
    """Ensure every test starts with an empty cache."""

    monkeypatch.setattr(
        cisa_client,
        "_kev_cache",
        None,
    )
    monkeypatch.setattr(
        cisa_client,
        "_kev_cache_expires_at",
        0,
    )


@pytest.mark.asyncio
@respx.mock
async def test_fetch_cisa_catalog_returns_entries():
    route = respx.get(CISA_KEV_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "title": (
                    "CISA Known Exploited "
                    "Vulnerabilities Catalog"
                ),
                "catalogVersion": "2026.07.17",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2021-44228",
                        "vendorProject": "Apache",
                        "product": "Log4j",
                        "vulnerabilityName": (
                            "Apache Log4j Remote "
                            "Code Execution"
                        ),
                        "dateAdded": "2021-12-10",
                        "shortDescription": (
                            "Log4j contains an RCE "
                            "vulnerability."
                        ),
                        "requiredAction": (
                            "Apply mitigations per "
                            "vendor instructions."
                        ),
                        "dueDate": "2021-12-24",
                        "knownRansomwareCampaignUse": (
                            "Known"
                        ),
                        "notes": "",
                    }
                ],
            },
        )
    )

    catalog = await fetch_cisa_kev_catalog()

    assert route.called
    assert len(catalog) == 1

    entry = catalog["CVE-2021-44228"]

    assert entry.cve == "CVE-2021-44228"
    assert entry.date_added == date(2021, 12, 10)
    assert entry.due_date == date(2021, 12, 24)
    assert entry.required_action == (
        "Apply mitigations per vendor instructions."
    )
    assert (
        entry.known_ransomware_campaign_use
        == "Known"
    )


@pytest.mark.asyncio
@respx.mock
async def test_fetch_cisa_catalog_uses_cache():
    route = respx.get(CISA_KEV_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2021-44228",
                        "dateAdded": "2021-12-10",
                        "dueDate": "2021-12-24",
                        "requiredAction": "Apply updates.",
                        "knownRansomwareCampaignUse": (
                            "Known"
                        ),
                    }
                ]
            },
        )
    )

    first_result = await fetch_cisa_kev_catalog()
    second_result = await fetch_cisa_kev_catalog()

    assert first_result is second_result
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_fetch_cisa_catalog_skips_bad_entries():
    respx.get(CISA_KEV_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2021-44228",
                        "dateAdded": "2021-12-10",
                        "dueDate": "2021-12-24",
                        "requiredAction": "Apply updates.",
                        "knownRansomwareCampaignUse": (
                            "Known"
                        ),
                    },
                    {
                        "cveID": "CVE-BAD-DATE",
                        "dateAdded": "invalid-date",
                        "dueDate": "2021-12-24",
                        "requiredAction": "Apply updates.",
                    },
                    {
                        "cveID": "CVE-MISSING-FIELDS",
                    },
                ]
            },
        )
    )

    catalog = await fetch_cisa_kev_catalog()

    assert list(catalog) == ["CVE-2021-44228"]


@pytest.mark.asyncio
@respx.mock
async def test_fetch_cisa_catalog_handles_timeout():
    respx.get(CISA_KEV_URL).mock(
        side_effect=httpx.ReadTimeout(
            "CISA request timed out"
        )
    )

    with pytest.raises(
        CISAKEVClientError,
        match="CISA KEV request timed out",
    ):
        await fetch_cisa_kev_catalog()


@pytest.mark.asyncio
@respx.mock
async def test_fetch_cisa_catalog_handles_http_error():
    respx.get(CISA_KEV_URL).mock(
        return_value=httpx.Response(
            503,
            json={"error": "Unavailable"},
        )
    )

    with pytest.raises(
        CISAKEVClientError,
        match="HTTP status 503",
    ):
        await fetch_cisa_kev_catalog()


@pytest.mark.asyncio
@respx.mock
async def test_fetch_cisa_catalog_handles_invalid_json():
    respx.get(CISA_KEV_URL).mock(
        return_value=httpx.Response(
            200,
            content=b"not-json",
        )
    )

    with pytest.raises(
        CISAKEVClientError,
        match="invalid JSON",
    ):
        await fetch_cisa_kev_catalog()


@pytest.mark.asyncio
async def test_enriches_known_exploited_vulnerability(
    monkeypatch,
):
    async def fake_fetch_catalog():
        return {
            "CVE-2021-44228": KEVEntry(
                cve="CVE-2021-44228",
                date_added=date(2021, 12, 10),
                due_date=date(2021, 12, 24),
                required_action=(
                    "Apply vendor mitigations."
                ),
                known_ransomware_campaign_use="Known",
            )
        }

    monkeypatch.setattr(
        cisa_client,
        "fetch_cisa_kev_catalog",
        fake_fetch_catalog,
    )

    vulnerability = Vulnerability(
        id="GHSA-jfh8-c2jp-5v3q",
        summary="Log4Shell",
        aliases=["CVE-2021-44228"],
    )

    results = await enrich_with_cisa_kev(
        [vulnerability]
    )

    intelligence = results[0].exploit_intelligence

    assert intelligence.known_exploited is True
    assert intelligence.cisa_kev_cve == "CVE-2021-44228"
    assert intelligence.cisa_date_added == date(
        2021,
        12,
        10,
    )
    assert intelligence.cisa_due_date == date(
        2021,
        12,
        24,
    )
    assert intelligence.cisa_required_action == (
        "Apply vendor mitigations."
    )
    assert (
        intelligence.known_ransomware_campaign_use
        == "Known"
    )


@pytest.mark.asyncio
async def test_unmatched_vulnerability_is_not_exploited(
    monkeypatch,
):
    async def fake_fetch_catalog():
        return {
            "CVE-2021-44228": KEVEntry(
                cve="CVE-2021-44228",
                date_added=date(2021, 12, 10),
                due_date=date(2021, 12, 24),
                required_action="Apply updates.",
                known_ransomware_campaign_use="Known",
            )
        }

    monkeypatch.setattr(
        cisa_client,
        "fetch_cisa_kev_catalog",
        fake_fetch_catalog,
    )

    vulnerability = Vulnerability(
        id="GHSA-different",
        summary="Different vulnerability",
        aliases=["CVE-2026-99999"],
    )

    results = await enrich_with_cisa_kev(
        [vulnerability]
    )

    intelligence = results[0].exploit_intelligence

    assert intelligence.known_exploited is False
    assert intelligence.cisa_kev_cve is None
    assert intelligence.cisa_date_added is None
    assert intelligence.cisa_due_date is None


@pytest.mark.asyncio
async def test_matches_primary_cve_identifier(
    monkeypatch,
):
    async def fake_fetch_catalog():
        return {
            "CVE-2021-44228": KEVEntry(
                cve="CVE-2021-44228",
                date_added=date(2021, 12, 10),
                due_date=date(2021, 12, 24),
                required_action="Apply updates.",
                known_ransomware_campaign_use="Known",
            )
        }

    monkeypatch.setattr(
        cisa_client,
        "fetch_cisa_kev_catalog",
        fake_fetch_catalog,
    )

    vulnerability = Vulnerability(
        id="CVE-2021-44228",
        summary="Log4Shell",
        aliases=[],
    )

    results = await enrich_with_cisa_kev(
        [vulnerability]
    )

    assert (
        results[0]
        .exploit_intelligence
        .known_exploited
        is True
    )