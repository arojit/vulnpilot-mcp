import pytest

from vulnpilot.server import check_package


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
                    "database_specific": {
                        "severity": "HIGH",
                    },
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.2.10"},
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [
                        {
                            "url": "https://example.com/advisory"
                        }
                    ],
                }
            ]
        }

    monkeypatch.setattr(
        "vulnpilot.server.query_osv",
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

    assert vulnerability.severity == "HIGH"
    assert vulnerability.fixed_versions == ["2.2.10"]
    assert vulnerability.references == [
        "https://example.com/advisory"
    ]


@pytest.mark.asyncio
async def test_check_package_returns_clean_result(monkeypatch):
    async def fake_query_osv(payload):
        return {}

    monkeypatch.setattr(
        "vulnpilot.server.query_osv",
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ecosystem", "package_name", "version"),
    [
        ("PyPI", "django", "2.2.0"),
        ("npm", "lodash", "4.17.20"),
        (
            "Maven",
            "org.apache.logging.log4j:log4j-core",
            "2.14.1",
        ),
    ],
)
async def test_check_package_supports_ecosystems(
    monkeypatch,
    ecosystem,
    package_name,
    version,
):
    captured_payload = {}

    async def fake_query_osv(payload):
        captured_payload.update(payload)
        return {}

    monkeypatch.setattr(
        "vulnpilot.server.query_osv",
        fake_query_osv,
    )

    result = await check_package(
        package_name=package_name,
        version=version,
        ecosystem=ecosystem,
    )

    assert captured_payload == {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        },
        "version": version,
    }

    assert result.package_name == package_name
    assert result.ecosystem == ecosystem
    assert result.vulnerable is False


@pytest.mark.asyncio
async def test_rejects_invalid_maven_coordinate():
    with pytest.raises(
        ValueError,
        match="groupId:artifactId",
    ):
        await check_package(
            package_name="log4j-core",
            version="2.14.1",
            ecosystem="Maven",
        )