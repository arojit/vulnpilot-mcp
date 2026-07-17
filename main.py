import httpx
from mcp.server.fastmcp import FastMCP


mcp = FastMCP("VulnPilot")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

@mcp.tool()
async def check_package(
    package_name: str,
    version: str,
    ecosystem: str = "PyPI",
) -> dict:
    """Check a package version for known vulnerabilities using OSV

    Args:
        package_name: Name of the package, for example django.
        version: Exact package version, for example 2.2.0.
        ecosystem: Package ecosystem, currently PyPI.
    """
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        },
        "version": version,
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            OSV_QUERY_URL,
            json=payload
        )

        response.raise_for_status()
    
    data = response.json()
    vulnerabilities = data.get("vulns", [])
    
    simplified_vulnerabilities = []

    for vulnerability in vulnerabilities:
        simplified_vulnerabilities.append(
            {
                "id": vulnerability.get("id"),
                "summery": vulnerability.get("summery", "No summery available"),
                "aliases": vulnerability.get("aliases", [])
            }
        )



    return {
        "package_name": package_name,
        "version": version,
        "ecosystem": ecosystem,
        "vulnerable": len(simplified_vulnerabilities) > 0,
        "vulnerability_count": len(simplified_vulnerabilities),
        "vulnerabilities": simplified_vulnerabilities
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
