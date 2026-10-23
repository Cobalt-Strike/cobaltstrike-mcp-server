"""MCP server for the Cobalt Strike REST API."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cobaltstrike-mcp-server")
except PackageNotFoundError:
    __version__ = "0+unknown"
