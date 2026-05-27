"""Cobalt Strike API client for authentication and communication."""

from __future__ import annotations

import logging
from typing import Any

import httpx

USER_AGENT = "cs-mcp/1.0"

logger = logging.getLogger(__name__)


def mcp_error(
    message: str,
    *,
    endpoint: str | None = None,
    status_code: int | None = None,
    exception: str | None = None,
) -> dict[str, Any]:
    """Build a consistent error envelope for MCP-facing helpers."""
    result: dict[str, Any] = {
        "ok": False,
        "error": message,
    }
    if endpoint is not None:
        result["endpoint"] = endpoint
    if status_code is not None:
        result["status_code"] = status_code
    if exception is not None:
        result["exception"] = exception
    return result


class CobaltStrikeClient:
    """Client for authenticating and communicating with the Cobalt Strike REST API."""

    def __init__(
        self,
        base_url: str,
        verify_tls: bool = True,
        timeout: float = 30.0,
    ):
        """Initialize the Cobalt Strike client.
        
        Args:
            base_url: Base URL for the Cobalt Strike REST API
            verify_tls: Whether to verify TLS certificates
            timeout: HTTP request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._token: str | None = None
        self._client: httpx.AsyncClient | None = None

    async def authenticate(
        self,
        username: str,
        password: str,
        duration_ms: int = 86400000,
        login_path: str = "/api/auth/login",
    ) -> str:
        """Authenticate with the Cobalt Strike API and return a JWT token.
        
        Args:
            username: Cobalt Strike username
            password: Cobalt Strike password
            duration_ms: Requested session duration in milliseconds
            login_path: Authentication endpoint path
            
        Returns:
            JWT token for authenticated requests
            
        Raises:
            RuntimeError: If authentication fails
        """
        payload = {
            "username": username,
            "password": password,
            "duration_ms": duration_ms,
        }

        client = httpx.AsyncClient(
            base_url=self.base_url,
            verify=self.verify_tls,
            timeout=self.timeout,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )

        try:
            response = await client.post(login_path, json=payload)
            response.raise_for_status()
            data: dict[str, Any] = response.json()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text.strip()
            raise RuntimeError(
                f"Authentication failed with status {exc.response.status_code}: {detail or exc}"
            ) from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Authentication request failed: {exc}") from exc
        finally:
            await client.aclose()

        token = data.get("access_token")
        if not token:
            raise RuntimeError("Authentication response did not include 'access_token'.")

        self._token = token
        logger.info("Successfully authenticated with Cobalt Strike API")
        return token

    @property
    def access_token(self) -> str:
        """Return the current bearer token for non-HTTP clients.

        Raises:
            RuntimeError: If not authenticated (call authenticate() first)
        """
        if not self._token:
            raise RuntimeError("Not authenticated. Call authenticate() first.")
        return self._token

    def get_authenticated_client(self) -> httpx.AsyncClient:
        """Get an authenticated HTTP client for API requests.
        
        Returns:
            Configured httpx.AsyncClient with authentication headers
            
        Raises:
            RuntimeError: If not authenticated (call authenticate() first)
        """
        if not self._token:
            raise RuntimeError("Not authenticated. Call authenticate() first.")

        if self._client is None:
            headers = {
                "Authorization": f"Bearer {self._token}",
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            }
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                verify=self.verify_tls,
                timeout=self.timeout,
                headers=headers,
            )

        return self._client

    async def fetch_openapi_spec(self, spec_url: str = "/v3/api-docs") -> dict[str, Any]:
        """Download the OpenAPI specification from the Cobalt Strike API.
        
        Args:
            spec_url: URL path to the OpenAPI specification
            
        Returns:
            OpenAPI specification as a dictionary
            
        Raises:
            RuntimeError: If fetching the spec fails
        """
        client = self.get_authenticated_client()

        try:
            response = await client.get(spec_url)
            response.raise_for_status()
            spec = response.json()
            logger.info("Successfully fetched OpenAPI specification")
            return spec
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text.strip()
            raise RuntimeError(
                f"Failed to fetch OpenAPI spec (status {exc.response.status_code}): {detail or exc}"
            ) from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Failed to fetch OpenAPI spec: {exc}") from exc

    async def request_json(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        """Make an authenticated request and return a normalized JSON result."""
        try:
            client = self.get_authenticated_client()
            response = await client.request(method, path, **kwargs)
            if response.status_code >= 400:
                return mcp_error(
                    f"HTTP {response.status_code}",
                    endpoint=path,
                    status_code=response.status_code,
                    exception=response.text.strip() or None,
                )
            try:
                data = response.json()
            except ValueError as exc:
                return mcp_error(
                    "Response did not contain valid JSON",
                    endpoint=path,
                    status_code=response.status_code,
                    exception=str(exc),
                )
            return {
                "ok": True,
                "endpoint": path,
                "status_code": response.status_code,
                "data": data,
            }
        except (httpx.HTTPError, RuntimeError) as exc:
            return mcp_error("HTTP request failed", endpoint=path, exception=str(exc))

    async def request_text(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        """Make an authenticated request and return a normalized text result."""
        try:
            client = self.get_authenticated_client()
            response = await client.request(method, path, **kwargs)
            if response.status_code >= 400:
                return mcp_error(
                    f"HTTP {response.status_code}",
                    endpoint=path,
                    status_code=response.status_code,
                    exception=response.text.strip() or None,
                )
            return {
                "ok": True,
                "endpoint": path,
                "status_code": response.status_code,
                "text": response.text,
            }
        except (httpx.HTTPError, RuntimeError) as exc:
            return mcp_error("HTTP request failed", endpoint=path, exception=str(exc))

    async def close(self) -> None:
        """Close the HTTP client and clean up resources."""
        if self._client:
            await self._client.aclose()
            self._client = None
        logger.debug("Cobalt Strike client closed")

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
