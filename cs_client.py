"""Cobalt Strike API client for authentication and communication."""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any

import httpx

from cs_audit import audit_event

USER_AGENT = "cs-mcp/1.0"

logger = logging.getLogger(__name__)
_BEACON_PATH_RE = re.compile(r"/api/v\d+/beacons/([^/]+)")
_TASK_PATH_RE = re.compile(r"/api/v\d+/tasks/([^/]+)")


@dataclass(frozen=True)
class AuthContext:
    username: str
    password: str
    duration_ms: int
    login_path: str


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
        self._auth_context: AuthContext | None = None

    async def _request_access_token(
        self,
        *,
        username: str,
        password: str,
        duration_ms: int,
        login_path: str,
    ) -> str:
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
        return token

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
        token = await self._request_access_token(
            username=username,
            password=password,
            duration_ms=duration_ms,
            login_path=login_path,
        )

        if self._client:
            await self.close()

        self._token = token
        self._auth_context = AuthContext(
            username=username,
            password=password,
            duration_ms=duration_ms,
            login_path=login_path,
        )
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
            self._client = ReauthenticatingAsyncClient(
                self,
                base_url=self.base_url,
                verify=self.verify_tls,
                timeout=self.timeout,
                headers=headers,
                event_hooks={
                    "request": [self._audit_request],
                    "response": [self._audit_response],
                },
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
            response = await self._request_with_reauth(method, path, **kwargs)
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
            response = await self._request_with_reauth(method, path, **kwargs)
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

    async def _request_with_reauth(self, method: str, path: str, **kwargs) -> httpx.Response:
        client = self.get_authenticated_client()
        response = await client.request(method, path, **kwargs)
        if (
            response.status_code == 401
            and not getattr(client, "handles_reauth", False)
            and await self._reauthenticate()
        ):
            client = self.get_authenticated_client()
            response = await client.request(method, path, **kwargs)
        return response

    async def _reauthenticate(self) -> bool:
        if self._auth_context is None:
            return False

        logger.info("Refreshing Cobalt Strike API token after authentication failure")
        try:
            token = await self._request_access_token(
                username=self._auth_context.username,
                password=self._auth_context.password,
                duration_ms=self._auth_context.duration_ms,
                login_path=self._auth_context.login_path,
            )
            self._token = token
            if self._client is not None:
                self._client.headers["Authorization"] = f"Bearer {token}"
            return True
        except RuntimeError as exc:
            logger.warning("Cobalt Strike API token refresh failed: %s", exc)
            return False

    def reauthenticate_blocking(self) -> bool:
        """Refresh the API token from non-async worker threads."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self._reauthenticate())
        logger.warning("Cannot run blocking token refresh from an active event loop")
        return False

    async def _audit_request(self, request: httpx.Request) -> None:
        path = request.url.path
        audit_event(
            "api_request",
            status="started",
            beacon_id=_extract_path_id(_BEACON_PATH_RE, path),
            task_id=_extract_path_id(_TASK_PATH_RE, path),
            details={
                "method": request.method,
                "path": path,
            },
        )

    async def _audit_response(self, response: httpx.Response) -> None:
        path = response.request.url.path
        audit_event(
            "api_request",
            status="completed" if response.status_code < 400 else "failed",
            beacon_id=_extract_path_id(_BEACON_PATH_RE, path),
            task_id=_extract_path_id(_TASK_PATH_RE, path),
            details={
                "method": response.request.method,
                "path": path,
                "status_code": response.status_code,
            },
        )

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


def _extract_path_id(pattern: re.Pattern, path: str) -> str | None:
    match = pattern.search(path)
    if not match:
        return None
    return match.group(1)


class ReauthenticatingAsyncClient(httpx.AsyncClient):
    """HTTP client that retries one request after refreshing an expired bearer token."""

    handles_reauth = True

    def __init__(self, owner: CobaltStrikeClient, *args, **kwargs) -> None:
        self._owner = owner
        super().__init__(*args, **kwargs)

    async def request(self, method: str, url, **kwargs) -> httpx.Response:
        response = await super().request(method, url, **kwargs)
        if response.status_code != 401:
            return response

        if not await self._owner._reauthenticate():  # pylint: disable=protected-access
            return response

        await response.aclose()
        return await super().request(method, url, **kwargs)
