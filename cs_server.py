"""MCP server implementation for exposing Cobalt Strike API."""

from __future__ import annotations

import asyncio
import ipaddress
import logging

from fastmcp import FastMCP
from fastmcp.server.providers.openapi import RouteMap, MCPType

from cs_client import CobaltStrikeClient
from cs_files import add_cobalt_strike_file_tools
from cs_prompts import add_cobalt_strike_prompts
from cs_resources import add_cobalt_strike_resources
from cs_streams import CobaltStrikeWebSocketStreamManager, add_cobalt_strike_stream_tools

logger = logging.getLogger(__name__)

HTTP_TRANSPORTS = {"http", "streamable-http", "sse"}
SUPPORTED_TRANSPORTS = HTTP_TRANSPORTS | {"stdio"}


def build_route_maps() -> list[RouteMap]:
    """Build the OpenAPI route policy for generated MCP tools."""
    return [
        RouteMap(tags={"Security"}, mcp_type=MCPType.EXCLUDE),
        RouteMap(pattern=r"^/.*/config/resetData", mcp_type=MCPType.EXCLUDE),
    ]


class CobaltStrikeMCPServer:
    """MCP server that exposes Cobalt Strike REST API endpoints as MCP tools."""

    def __init__(
        self,
        cs_client: CobaltStrikeClient,
        server_name: str = "Cobalt Strike API",
        instructions: str | None = None,
        websocket_streams_enabled: bool = True,
        auto_start_websocket_streams: bool = True,
        websocket_buffer_size: int = 1000,
        websocket_reconnect_seconds: float = 2.0,
    ):
        """Initialize the MCP server.
        
        Args:
            cs_client: Authenticated Cobalt Strike client
            server_name: Name to display for the MCP server
            instructions: Optional instructions for MCP clients
            websocket_streams_enabled: Whether WebSocket stream-backed tools can connect
            auto_start_websocket_streams: Whether to subscribe to beacons/eventlog at startup
            websocket_buffer_size: Maximum entries retained per stream buffer
            websocket_reconnect_seconds: Delay between WebSocket reconnect attempts
        """
        self.cs_client = cs_client
        self.server_name = server_name
        self.instructions = instructions
        self._mcp_server: FastMCP | None = None
        self._websocket_auto_start_task: asyncio.Task | None = None
        self.stream_manager = CobaltStrikeWebSocketStreamManager(
            cs_client,
            enabled=websocket_streams_enabled,
            auto_start=auto_start_websocket_streams,
            buffer_size=websocket_buffer_size,
            reconnect_seconds=websocket_reconnect_seconds,
        )

    async def create_server(self, spec_url: str = "/v3/api-docs") -> FastMCP:
        """Create the FastMCP server from the Cobalt Strike OpenAPI specification.
        
        Args:
            spec_url: URL path to fetch the OpenAPI specification from
            
        Returns:
            Configured FastMCP server instance
        """
        # Fetch the OpenAPI specification
        logger.info("Fetching OpenAPI specification from %s", spec_url)
        openapi_spec = await self.cs_client.fetch_openapi_spec(spec_url)

        # Get the authenticated HTTP client for FastMCP to use
        http_client = self.cs_client.get_authenticated_client()

        # Create the FastMCP server from the OpenAPI spec
        # Exclude authentication endpoints since MCP handles auth automatically
        create_kwargs = {
            "openapi_spec": openapi_spec,
            "client": http_client,
            "name": self.server_name,
            "tags": {"openapi", "cobalt-strike"},
            "route_maps": build_route_maps(),
        }

        self._mcp_server = FastMCP.from_openapi(**create_kwargs)
        logger.info("Excluded authentication endpoints from MCP tools")

        if self.instructions:
            self._mcp_server.instructions = self.instructions

        # Add MCP prompts and resources from separate modules
        add_cobalt_strike_prompts(self._mcp_server)
        add_cobalt_strike_resources(self._mcp_server, self.cs_client, self.stream_manager)
        add_cobalt_strike_stream_tools(self._mcp_server, self.stream_manager)
        add_cobalt_strike_file_tools(self._mcp_server, self.cs_client)

        logger.info("Created FastMCP server with OpenAPI specification")
        return self._mcp_server

    async def run(
        self,
        transport: str = "http",
        host: str = "127.0.0.1",
        port: int = 3000,
        path: str = "/mcp",
        log_level: str | None = None,
        allow_remote_bind: bool = False,
        external_auth: bool = False,
    ) -> None:
        """Run the MCP server.
        
        Args:
            transport: MCP transport type ("http" or "streamable-http")
            host: Host to bind the server to
            port: Port to bind the server to
            path: URL path for the MCP endpoint
            log_level: Log level for uvicorn (if using HTTP transport)
            allow_remote_bind: Allow non-loopback HTTP/SSE binds when externally protected
            external_auth: Confirm non-loopback binds are protected by external auth
        """
        if not self._mcp_server:
            raise RuntimeError("Server not created. Call create_server() first.")

        # Normalize the path to ensure it starts with /
        normalized_path = path if path.startswith("/") else f"/{path}"
        normalized_path = normalized_path.rstrip("/") or "/"

        logger.info(
            "Starting MCP server '%s' on %s://%s:%s%s",
            self.server_name,
            transport,
            host,
            port,
            normalized_path,
        )

        try:
            run_kwargs = build_run_kwargs(
                transport=transport,
                host=host,
                port=port,
                path=normalized_path,
                log_level=log_level,
                allow_remote_bind=allow_remote_bind,
                external_auth=external_auth,
            )
            self._schedule_websocket_auto_start()
            await self._mcp_server.run_async(**run_kwargs)
        except Exception as exc:
            logger.error("MCP server error: %s", exc)
            raise

    async def stop(self) -> None:
        """Stop the MCP server and clean up resources."""
        if self._websocket_auto_start_task:
            self._websocket_auto_start_task.cancel()
            self._websocket_auto_start_task = None
        if self._mcp_server:
            # FastMCP doesn't have an explicit stop method, but we can clean up our resources
            logger.info("Stopping MCP server")
            self.stream_manager.stop_all()
            self._mcp_server = None

    def _schedule_websocket_auto_start(self) -> None:
        if not self.stream_manager.enabled or not self.stream_manager.auto_start or self._websocket_auto_start_task:
            return
        self._websocket_auto_start_task = asyncio.create_task(self._start_websocket_streams())

    async def _start_websocket_streams(self) -> None:
        await asyncio.sleep(0)
        logger.info("Starting configured Cobalt Strike WebSocket subscriptions")
        self.stream_manager.start_defaults()


def build_run_kwargs(
    *,
    transport: str,
    host: str,
    port: int,
    path: str,
    log_level: str | None = None,
    allow_remote_bind: bool = False,
    external_auth: bool = False,
) -> dict[str, object]:
    """Build FastMCP run_async kwargs and enforce bind safety."""
    if transport not in SUPPORTED_TRANSPORTS:
        raise ValueError(f"Unsupported MCP transport: {transport}")

    if transport == "stdio":
        return {"transport": "stdio"}

    if not is_loopback_bind_host(host):
        if not allow_remote_bind:
            raise ValueError(
                "Refusing to bind MCP HTTP/SSE transport to non-loopback host "
                f"{host!r}. Use --allow-remote-bind only when protected by external auth/TLS."
            )
        if not external_auth:
            raise ValueError(
                "Refusing non-loopback MCP HTTP/SSE bind without external auth confirmation. "
                "Set MCP_EXTERNAL_AUTH=true or pass --external-auth when a reverse proxy, "
                "mTLS, OIDC, or VPN protects the endpoint."
            )

    kwargs: dict[str, object] = {
        "transport": transport,
        "host": host,
        "port": port,
        "path": path,
    }
    if log_level and transport in {"http", "streamable-http"}:
        kwargs["log_level"] = log_level
    return kwargs


def is_loopback_bind_host(host: str) -> bool:
    """Return whether a bind host is loopback-only."""
    normalized = (host or "").strip().lower().strip("[]")
    if normalized in {"localhost", "localhost."}:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False
