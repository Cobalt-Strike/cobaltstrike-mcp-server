"""MCP server implementation for exposing Cobalt Strike API."""

from __future__ import annotations

import logging
from typing import Any

import fastmcp
from fastmcp import FastMCP
from fastmcp.server.providers.openapi import RouteMap, MCPType

from cs_client import CobaltStrikeClient
from cs_prompts import add_cobalt_strike_prompts
from cs_resources import add_cobalt_strike_resources

logger = logging.getLogger(__name__)


class CobaltStrikeMCPServer:
    """MCP server that exposes Cobalt Strike REST API endpoints as MCP tools."""

    def __init__(
        self,
        cs_client: CobaltStrikeClient,
        server_name: str = "Cobalt Strike API",
        instructions: str | None = None,
    ):
        """Initialize the MCP server.
        
        Args:
            cs_client: Authenticated Cobalt Strike client
            server_name: Name to display for the MCP server
            instructions: Optional instructions for MCP clients
        """
        self.cs_client = cs_client
        self.server_name = server_name
        self.instructions = instructions
        self._mcp_server: FastMCP | None = None

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
            "route_maps": [
                RouteMap(tags={"Security"}, mcp_type=MCPType.EXCLUDE),
                RouteMap(pattern=r"^/.*/config/resetData", mcp_type=MCPType.EXCLUDE),
            ],
        }

        self._mcp_server = FastMCP.from_openapi(**create_kwargs)
        logger.info("Excluded authentication endpoints from MCP tools")

        if self.instructions:
            self._mcp_server.instructions = self.instructions

        # Add MCP prompts and resources from separate modules
        add_cobalt_strike_prompts(self._mcp_server)
        add_cobalt_strike_resources(self._mcp_server, self.cs_client)

        logger.info("Created FastMCP server with OpenAPI specification")
        return self._mcp_server

    async def run(
        self,
        transport: str = "http",
        host: str = "127.0.0.1",
        port: int = 3000,
        path: str = "/mcp",
        log_level: str | None = None,
    ) -> None:
        """Run the MCP server.
        
        Args:
            transport: MCP transport type ("http" or "streamable-http")
            host: Host to bind the server to
            port: Port to bind the server to
            path: URL path for the MCP endpoint
            log_level: Log level for uvicorn (if using HTTP transport)
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
            # Convert string transport to proper type for FastMCP
            if transport == "stdio":
                # stdio transport doesn't use host, port, or path
                logger.info("Starting MCP server '%s' with stdio transport", self.server_name)
                await self._mcp_server.run_async(transport="stdio")
            else:
                # HTTP-based transports use host, port, and path
                logger.info(
                    "Starting MCP server '%s' on %s://%s:%s%s",
                    self.server_name,
                    transport,
                    host,
                    port,
                    normalized_path,
                )
                
                if transport == "http":
                    if log_level:
                        await self._mcp_server.run_async(
                            transport="http",
                            host=host,
                            port=port,
                            path=normalized_path,
                            log_level=log_level,
                        )
                    else:
                        await self._mcp_server.run_async(
                            transport="http",
                            host=host,
                            port=port,
                            path=normalized_path,
                        )
                elif transport == "streamable-http":
                    if log_level:
                        await self._mcp_server.run_async(
                            transport="streamable-http",
                            host=host,
                            port=port,
                            path=normalized_path,
                            log_level=log_level,
                        )
                    else:
                        await self._mcp_server.run_async(
                            transport="streamable-http",
                            host=host,
                            port=port,
                            path=normalized_path,
                        )
                elif transport == "sse":
                    await self._mcp_server.run_async(
                        transport="sse",
                        host=host,
                        port=port,
                        path=normalized_path,
                    )
                else:
                    # Default to http
                    await self._mcp_server.run_async(
                        transport="http",
                        host=host,
                        port=port,
                        path=normalized_path,
                    )
        except Exception as exc:
            logger.error("MCP server error: %s", exc)
            raise

    async def stop(self) -> None:
        """Stop the MCP server and clean up resources."""
        if self._mcp_server:
            # FastMCP doesn't have an explicit stop method, but we can clean up our resources
            logger.info("Stopping MCP server")
            self._mcp_server = None


def _normalize_path_parameter(param: Any, route_path: str) -> None:
    """Ensure path parameters are required and have no blank defaults.
    
    This is a utility function that can be used to normalize OpenAPI path parameters
    if needed. Currently not used but kept for potential future use.
    
    Args:
        param: Parameter definition from OpenAPI spec
        route_path: The route path this parameter belongs to
    """
    if not isinstance(param, dict):
        return

    if param.get("in") != "path":
        return

    if not param.get("required", False):
        logger.debug(
            "Marking path parameter '%s' on %s as required.",
            param.get("name", "<unknown>"),
            route_path,
        )
        param["required"] = True

    if param.get("default") in ("", None):
        param.pop("default", None)

    schema = param.get("schema")
    if isinstance(schema, dict) and schema.get("default") in ("", None):
        schema.pop("default", None)