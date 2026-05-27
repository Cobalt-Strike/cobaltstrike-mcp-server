"""MCP resources for Cobalt Strike data access."""

from __future__ import annotations

import json
import logging
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from cs_client import CobaltStrikeClient

logger = logging.getLogger(__name__)


def _json(data: Any) -> str:
    return json.dumps(data, indent=2)


def _resource_error(result: dict[str, Any], message: str) -> str:
    error = {
        "error": result.get("error", "Request failed"),
        "status_code": result.get("status_code"),
        "endpoint": result.get("endpoint"),
        "message": message,
    }
    if result.get("exception"):
        error["exception"] = result["exception"]
    return _json({key: value for key, value in error.items() if value is not None})


def add_cobalt_strike_resources(mcp_server: FastMCP, cs_client: CobaltStrikeClient) -> None:
    """Add MCP resources to the Cobalt Strike server.
    
    Args:
        mcp_server: The FastMCP server instance to add resources to
        cs_client: The authenticated Cobalt Strike client
    """
    
    @mcp_server.resource("cobalt-strike://beacons/active")
    async def active_beacons_resource() -> str:
        """Get current active beacons in JSON format.
        
        Returns:
            JSON representation of all active beacons
        """
        result = await cs_client.request_text("GET", "/api/v1/beacons")
        if result.get("ok"):
            return str(result.get("text", ""))
        return _resource_error(result, "Unable to retrieve active beacon data")

    @mcp_server.resource("cobalt-strike://config/server-info")
    async def server_info_resource() -> str:
        """Get Cobalt Strike server information and configuration.
        
        Returns:
            JSON representation of server information
        """
        localip_result = await cs_client.request_text("GET", "/api/v1/config/localip")
        if localip_result.get("ok"):
            version_data = {
                "version": "available",
                "api_status": "operational",
                "local_ip": localip_result.get("text", ""),
            }
        else:
            version_data = {"version": "unknown", "api_status": "limited"}

        server_info = {
            "cobalt_strike": {
                "version": version_data,
                "api_base_url": cs_client.base_url,
                "health_status": "connected",
            },
            "mcp_server": {
                "name": "Cobalt Strike API",
                "authenticated": True,
                "transport": "MCP",
                "capabilities": [
                    "tools", "prompts", "resources"
                ],
            },
            "api_endpoints": {
                "base_url": cs_client.base_url,
                "api_docs": f"{cs_client.base_url}/v3/api-docs",
                "health_check": f"{cs_client.base_url}/api/v1/version",
                "authentication": f"{cs_client.base_url}/api/auth/login",
            },
            "resources": {
                "beacons": "cobalt-strike://beacons/active",
                "server_info": "cobalt-strike://config/server-info",
                "activity_logs": "cobalt-strike://logs/recent-activity",
                "listeners": "cobalt-strike://listeners/active",
            },
        }

        system_result = await cs_client.request_text("GET", "/api/v1/config/systeminformation")
        if system_result.get("ok"):
            server_info["cobalt_strike"]["system_information"] = system_result.get("text", "")

        return _json(server_info)

    @mcp_server.resource("cobalt-strike://logs/recent-activity")
    async def recent_activity_resource() -> str:
        """Get recent Cobalt Strike activity logs.
        
        Returns:
            JSON representation of recent activities
        """
        result = await cs_client.request_json("GET", "/api/v1/tasks")
        if not result.get("ok"):
            return _resource_error(result, "Unable to retrieve recent activity data")

        tasks_data = result.get("data")
        recent_tasks = tasks_data[:50] if isinstance(tasks_data, list) else tasks_data
        activity_summary = {
            "metadata": {
                "timestamp": "recent",
                "total_tasks_shown": len(recent_tasks) if isinstance(recent_tasks, list) else 1,
                "total_tasks_available": len(tasks_data) if isinstance(tasks_data, list) else 1,
                "note": "Limited to 50 most recent tasks for performance",
            },
            "activities": recent_tasks,
        }

        return _json(activity_summary)

    @mcp_server.resource("cobalt-strike://listeners/active")
    async def active_listeners_resource() -> str:
        """Get current active listeners in JSON format.
        
        Returns:
            JSON representation of all active listeners
        """
        result = await cs_client.request_json("GET", "/api/v1/listeners")
        if not result.get("ok"):
            return _resource_error(result, "Unable to retrieve listener data")

        listeners_data = result.get("data")
        listener_summary = {
            "metadata": {
                "total_listeners": len(listeners_data) if isinstance(listeners_data, list) else 1,
                "status": "active",
                "last_updated": "real-time",
            },
            "listeners": listeners_data,
        }

        return _json(listener_summary)

    @mcp_server.resource("cobalt-strike://stats/dashboard")
    async def dashboard_stats_resource() -> str:
        """Get Cobalt Strike dashboard statistics and summary.
        
        Returns:
            JSON representation of dashboard statistics
        """
        endpoints = {
            "beacons": "/api/v1/beacons",
            "listeners": "/api/v1/listeners",
            "tasks": "/api/v1/tasks",
        }

        stats = {
            "dashboard": {
                "timestamp": "real-time",
                "status": "operational",
            }
        }

        for name, endpoint in endpoints.items():
            result = await cs_client.request_json("GET", endpoint)
            if result.get("ok"):
                data = result.get("data")
                stats[name] = {
                    "count": str(len(data)) if isinstance(data, list) else "1",
                    "status": "available",
                }
            else:
                stats[name] = {
                    "count": "0",
                    "status": "unavailable",
                    "error": result.get("error"),
                    "error_code": str(result.get("status_code")),
                }

        return _json(stats)

    logger.info("Added MCP resources: beacons, server-info, activity-logs, listeners, dashboard-stats")
