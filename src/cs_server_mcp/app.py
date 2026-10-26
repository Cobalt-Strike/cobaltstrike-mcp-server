"""ASGI factory and environment defaults shared with the CLI."""

import os
from typing import Any

from cs_server_mcp.config import (
    DEFAULT_MCP_PATH,
    DEFAULT_PORT,
    BindOptions,
    ConfigurationError,
    load_settings,
)


def _env_value(name: str, default: str) -> str:
    return os.getenv(name, default).strip() or default


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env_value(name, str(default)))
    except ValueError:
        raise ConfigurationError(f"{name} must be an integer") from None


def bind_options(*, port: int | None = None, mcp_path: str | None = None) -> BindOptions:
    return BindOptions(
        port=port if port is not None else _env_int("CS_MCP_PORT", DEFAULT_PORT),
        mcp_path=mcp_path or _env_value("CS_MCP_PATH", DEFAULT_MCP_PATH),
    )


def create_app() -> Any:
    from cs_server_mcp.server import create_asgi_app

    settings = load_settings()
    return create_asgi_app(settings, bind=bind_options())
