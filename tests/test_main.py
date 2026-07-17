import pytest

from main import check_package


@pytest.mark.asyncio
async def test_check_package_returns_vulnerabilities(monkeypatch):
    async def fake_query_osv(payload):
        assert payload == {
            "package": {
                "name": "django",
                "ecosystem": "PyPI",
            },
            "version": "2.2.0",
        }

        return {
            "vulns": [
                {
                    "id": "GHSA-test-1234",
                    "summary": "Test Django vulnerability",
                    "aliases": ["CVE-2026-1234"],
                }
            ]
        }

    monkeypatch.setattr(
        "main.query_osv",
        fake_query_osv,
    )

    result = await check_package(
        package_name=" django ",
        version=" 2.2.0 ",
    )

    assert result.package_name == "django"
    assert result.version == "2.2.0"
    assert result.ecosystem == "PyPI"
    assert result.vulnerable is True
    assert result.vulnerability_count == 1

    vulnerability = result.vulnerabilities[0]

    assert vulnerability.id == "GHSA-test-1234"
    assert vulnerability.summary == "Test Django vulnerability"
    assert vulnerability.aliases == ["CVE-2026-1234"]


@pytest.mark.asyncio
async def test_check_package_returns_clean_result(monkeypatch):
    async def fake_query_osv(payload):
        return {}

    monkeypatch.setattr(
        "main.query_osv",
        fake_query_osv,
    )

    result = await check_package(
        package_name="safe-package",
        version="1.0.0",
    )

    assert result.vulnerable is False
    assert result.vulnerability_count == 0
    assert result.vulnerabilities == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("package_name", "version", "expected_error"),
    [
        (" ", "1.0.0", "Package name is required"),
        ("django", " ", "Version is required"),
    ],
)
async def test_check_package_rejects_empty_inputs(
    package_name,
    version,
    expected_error,
):
    with pytest.raises(ValueError, match=expected_error):
        await check_package(
            package_name=package_name,
            version=version,
        )