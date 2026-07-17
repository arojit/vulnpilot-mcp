from typing import Any

import httpx


OSV_QUERY_URL = "https://api.osv.dev/v1/query"


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