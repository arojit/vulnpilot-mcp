import httpx
import pytest
import respx

import vulnpilot.epss_client as epss_client
from vulnpilot.epss_client import (
    EPSS_API_URL,
    EPSSClientError,
    fetch_epss_scores,
)
from vulnpilot.models import Vulnerability


@pytest.mark.asyncio
@respx.mock
async def test_fetch_epss_scores_returns_scores():
    route = respx.get(
        EPSS_API_URL,
        params={
            "cve": (
                "CVE-2021-44228,"
                "CVE-2023-12345"
            )
        },
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "OK",
                "data": [
                    {
                        "cve": "CVE-2021-44228",
                        "epss": "0.943210000",
                        "percentile": "0.999100000",
                        "date": "2026-07-17",
                    },
                    {
                        "cve": "CVE-2023-12345",
                        "epss": "0.123400000",
                        "percentile": "0.751200000",
                        "date": "2026-07-17",
                    },
                ],
            },
        )
    )

    scores = await fetch_epss_scores(
        [
            "CVE-2023-12345",
            "CVE-2021-44228",
            "CVE-2021-44228",
        ]
    )

    assert route.called
    assert len(scores) == 2

    log4shell = scores["CVE-2021-44228"]

    assert log4shell.cve == "CVE-2021-44228"
    assert log4shell.probability == pytest.approx(
        0.94321
    )
    assert log4shell.percentile == pytest.approx(
        0.9991
    )


@pytest.mark.asyncio
@respx.mock
async def test_fetch_epss_scores_handles_empty_input():
    scores = await fetch_epss_scores([])

    assert scores == {}
    assert len(respx.calls) == 0


@pytest.mark.asyncio
@respx.mock
async def test_fetch_epss_scores_skips_malformed_items():
    respx.get(
        EPSS_API_URL,
        params={"cve": "CVE-2021-44228"},
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "cve": "CVE-2021-44228",
                        "epss": "0.9",
                        "percentile": "0.99",
                    },
                    {
                        "cve": "CVE-MALFORMED",
                        "epss": "not-a-number",
                        "percentile": "0.5",
                    },
                    {
                        "cve": "CVE-MISSING-FIELDS",
                    },
                ]
            },
        )
    )

    scores = await fetch_epss_scores(
        ["CVE-2021-44228"]
    )

    assert list(scores) == ["CVE-2021-44228"]


@pytest.mark.asyncio
@respx.mock
async def test_fetch_epss_scores_handles_timeout():
    respx.get(
        EPSS_API_URL,
        params={"cve": "CVE-2021-44228"},
    ).mock(
        side_effect=httpx.ReadTimeout(
            "EPSS timed out"
        )
    )

    with pytest.raises(
        EPSSClientError,
        match="EPSS request timed out",
    ):
        await fetch_epss_scores(
            ["CVE-2021-44228"]
        )


@pytest.mark.asyncio
@respx.mock
async def test_fetch_epss_scores_handles_http_error():
    respx.get(
        EPSS_API_URL,
        params={"cve": "CVE-2021-44228"},
    ).mock(
        return_value=httpx.Response(
            503,
            json={"error": "Unavailable"},
        )
    )

    with pytest.raises(
        EPSSClientError,
        match="HTTP status 503",
    ):
        await fetch_epss_scores(
            ["CVE-2021-44228"]
        )


@pytest.mark.asyncio
@respx.mock
async def test_fetch_epss_scores_handles_invalid_json():
    respx.get(
        EPSS_API_URL,
        params={"cve": "CVE-2021-44228"},
    ).mock(
        return_value=httpx.Response(
            200,
            content=b"not-json",
        )
    )

    with pytest.raises(
        EPSSClientError,
        match="invalid JSON",
    ):
        await fetch_epss_scores(
            ["CVE-2021-44228"]
        )


@pytest.mark.asyncio
async def test_enrich_with_epss_uses_highest_score(
    monkeypatch,
):
    async def fake_fetch_epss_scores(cve_ids):
        assert set(cve_ids) == {
            "CVE-2021-44228",
            "CVE-2021-99999",
        }

        return {
            "CVE-2021-44228": epss_client.EPSSScore(
                cve="CVE-2021-44228",
                probability=0.94,
                percentile=0.99,
            ),
            "CVE-2021-99999": epss_client.EPSSScore(
                cve="CVE-2021-99999",
                probability=0.25,
                percentile=0.70,
            ),
        }

    monkeypatch.setattr(
        epss_client,
        "fetch_epss_scores",
        fake_fetch_epss_scores,
    )

    vulnerability = Vulnerability(
        id="GHSA-test-1234",
        summary="Test vulnerability",
        aliases=[
            "CVE-2021-99999",
            "CVE-2021-44228",
        ],
    )

    results = await epss_client.enrich_with_epss(
        [vulnerability]
    )

    intelligence = results[0].exploit_intelligence

    assert intelligence.epss_cve == "CVE-2021-44228"
    assert intelligence.epss_probability == pytest.approx(
        0.94
    )
    assert intelligence.epss_percentile == pytest.approx(
        0.99
    )


@pytest.mark.asyncio
async def test_enrich_with_epss_handles_no_cve(
    monkeypatch,
):
    received_cves = None

    async def fake_fetch_epss_scores(cve_ids):
        nonlocal received_cves
        received_cves = cve_ids
        return {}

    monkeypatch.setattr(
        epss_client,
        "fetch_epss_scores",
        fake_fetch_epss_scores,
    )

    vulnerability = Vulnerability(
        id="GHSA-without-cve",
        summary="Advisory without CVE",
        aliases=[],
    )

    results = await epss_client.enrich_with_epss(
        [vulnerability]
    )

    intelligence = results[0].exploit_intelligence

    assert received_cves == []
    assert intelligence.epss_cve is None
    assert intelligence.epss_probability is None
    assert intelligence.epss_percentile is None
