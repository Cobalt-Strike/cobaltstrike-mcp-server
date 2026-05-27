"""Main launcher for the Cobalt Strike MCP server."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from typing import Callable

from cs_audit import configure_audit_logging
from cs_client import CobaltStrikeClient
from cs_server import CobaltStrikeMCPServer

# Default configuration values
DEFAULT_BASE_URL = "https://localhost:50443"
DEFAULT_SPEC_URL = "/v3/api-docs"
DEFAULT_LOGIN_PATH = "/api/auth/login"
DEFAULT_DURATION_MS = 86_400_000
DEFAULT_HTTP_TIMEOUT = 30.0
DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 3000
DEFAULT_LISTEN_PATH = "/mcp"
DEFAULT_TRANSPORT = "http"
DEFAULT_WS_ENABLED = True
DEFAULT_WS_AUTO_START = True
DEFAULT_WS_BUFFER_SIZE = 1000
DEFAULT_WS_RECONNECT_SECONDS = 2.0
SENSITIVE_ENV_MARKERS = ("PASSWORD", "TOKEN", "KEY", "SECRET")

DEFAULT_SERVER_INSTRUCTIONS = """\
You are a cybersecurity operations assistant interacting with a Cobalt Strike MCP (Model-Context-Protocol) server, which acts as an automation and integration layer over a live Cobalt Strike Team Server. The MCP server exposes a set of actions for managing and tasking beacons (compromised systems), automating common red team workflows, and retrieving results. You are responsible for orchestrating operations, querying beacon status, and triggering post-exploitation actions.
              
Behavior:
- Always verify a beacon exists before issuing a task.
- Provide clear and valid arguments to each action.
- If the user provides incomplete input, ask clarifying questions.
- Never fabricate beacon outputs — only return what's retrieved from the MCP.
- Output results in a concise, readable way (e.g., as tables or summaries).
"""

logger = logging.getLogger(__name__)


def env_bool(name: str, default: bool) -> bool:
    """Parse a boolean value from environment variables."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    """Parse an integer value from environment variables."""
    return _env_number(name, default, int, "integer")


def env_float(name: str, default: float) -> float:
    """Parse a float value from environment variables."""
    return _env_number(name, default, float, "number")


def _env_number(name: str, default, parser: Callable, value_type: str):
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return parser(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid {value_type}") from exc


def load_env_file(env_file: str = ".env") -> None:
    """Load environment variables from a .env file if it exists."""
    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                parsed = parse_env_line(line)
                if parsed is None:
                    continue
                key, value = parsed
                if key not in os.environ:
                    os.environ[key] = value


def parse_env_line(line: str) -> tuple[str, str] | None:
    """Parse a simple .env assignment line."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[7:].lstrip()
    if "=" not in stripped:
        return None

    key, value = stripped.split("=", 1)
    key = key.strip()
    if not key:
        return None

    value = _strip_inline_comment(value.strip())
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return key, value


def _strip_inline_comment(value: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            continue
        if char == "#" and not in_single and not in_double:
            if index == 0 or value[index - 1].isspace():
                return value[:index].rstrip()
    return value


def is_sensitive_env_var(name: str) -> bool:
    """Return whether an environment variable name likely contains a secret."""
    upper_name = name.upper()
    return any(marker in upper_name for marker in SENSITIVE_ENV_MARKERS)


def format_env_status(name: str, value: str | None) -> str:
    """Format an environment value for display without leaking secrets."""
    if value is None:
        return "NOT SET"
    if is_sensitive_env_var(name):
        return f"SET: <redacted, {len(value)} chars>"
    return f"SET: {value}"


def show_environment_variables() -> None:
    """Display all supported environment variables and their current values."""
    env_vars = {
        # Cobalt Strike API
        "CS_API_BASE_URL": f"Base URL for Cobalt Strike API (default: {DEFAULT_BASE_URL})",
        "CS_API_SPEC_URL": f"OpenAPI document URL path (default: {DEFAULT_SPEC_URL})",
        "CS_API_LOGIN_PATH": f"Authentication endpoint path (default: {DEFAULT_LOGIN_PATH})",
        "CS_API_USERNAME": "Cobalt Strike username (required if not passed as argument)",
        "CS_API_PASSWORD": "Cobalt Strike password (required if not passed as argument)",
        "CS_API_DURATION_MS": f"JWT session duration in milliseconds (default: {DEFAULT_DURATION_MS})",
        "CS_API_HTTP_TIMEOUT": f"HTTP request timeout in seconds (default: {DEFAULT_HTTP_TIMEOUT})",
        "CS_API_VERIFY_TLS": "Enable TLS certificate verification (default: true)",
        
        # MCP Server
        "MCP_TRANSPORT": f"MCP transport protocol (default: {DEFAULT_TRANSPORT})",
        "MCP_LISTEN_HOST": f"Host interface to bind server to (default: {DEFAULT_LISTEN_HOST})",
        "MCP_LISTEN_PORT": f"Port to bind server to (default: {DEFAULT_LISTEN_PORT})",
        "MCP_LISTEN_PATH": f"URL path for MCP endpoint (default: {DEFAULT_LISTEN_PATH})",
        "MCP_SERVER_NAME": "Name displayed to MCP clients (default: Cobalt Strike API)",
        "MCP_SERVER_INSTRUCTIONS": "Instructions for MCP clients",
        "MCP_LOG_LEVEL": "Override uvicorn log level for HTTP transport",
        "MCP_ALLOW_REMOTE_BIND": "Allow non-loopback MCP HTTP/SSE binds when protected by external auth/TLS",
        "MCP_EXTERNAL_AUTH": "Confirm non-loopback MCP HTTP/SSE binds are protected by external auth",
        "MCP_OPERATOR_ID": "Operator identity included in audit logs when available",
        "MCP_AUDIT_LOG_FILE": "Optional dedicated JSONL audit log file path",

        # Cobalt Strike WebSocket streams
        "CS_WS_ENABLED": "Enable Cobalt Strike WebSocket stream tools (default: true)",
        "CS_WS_AUTO_START": "Start beacons/eventlog WebSocket subscriptions at server startup (default: true)",
        "CS_WS_BUFFER_SIZE": f"Entries retained per WebSocket stream buffer (default: {DEFAULT_WS_BUFFER_SIZE})",
        "CS_WS_RECONNECT_SECONDS": f"Seconds between WebSocket reconnect attempts (default: {DEFAULT_WS_RECONNECT_SECONDS})",
        
        # Advanced
        "LOG_LEVEL": "Application log level (default: INFO)",
    }
    
    print("Supported Environment Variables:")
    print("=" * 50)
    for var, description in env_vars.items():
        status = format_env_status(var, os.getenv(var))
        print(f"{var:<40} | {status}")
        print(f"{'':40} | {description}")
        print("-" * 80)


def configure_logging(default_level: str = "INFO") -> None:
    """Configure application logging."""
    level_name = os.getenv("LOG_LEVEL", default_level).upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
    configure_audit_logging(os.getenv("MCP_AUDIT_LOG_FILE"))


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Run an MCP server that exposes the Cobalt Strike REST API.",
        prog="cs-mcp",
    )
    try:
        duration_default = env_int("CS_API_DURATION_MS", DEFAULT_DURATION_MS)
        http_timeout_default = env_float("CS_API_HTTP_TIMEOUT", DEFAULT_HTTP_TIMEOUT)
        listen_port_default = env_int("MCP_LISTEN_PORT", DEFAULT_LISTEN_PORT)
        websocket_buffer_size_default = env_int("CS_WS_BUFFER_SIZE", DEFAULT_WS_BUFFER_SIZE)
        websocket_reconnect_default = env_float(
            "CS_WS_RECONNECT_SECONDS",
            DEFAULT_WS_RECONNECT_SECONDS,
        )
    except ValueError as exc:
        parser.error(str(exc))

    # Special options
    parser.add_argument(
        "--show-env",
        action="store_true",
        help="Show all supported environment variables and exit",
    )

    # Cobalt Strike API configuration
    api_group = parser.add_argument_group("Cobalt Strike API")
    api_group.add_argument(
        "--base-url",
        default=os.getenv("CS_API_BASE_URL", DEFAULT_BASE_URL),
        help="Base URL for the Cobalt Strike REST API (default: %(default)s)",
    )
    api_group.add_argument(
        "--spec-url",
        default=os.getenv("CS_API_SPEC_URL", DEFAULT_SPEC_URL),
        help="OpenAPI document URL path to fetch (default: %(default)s)",
    )
    api_group.add_argument(
        "--login-path",
        default=os.getenv("CS_API_LOGIN_PATH", DEFAULT_LOGIN_PATH),
        help="Authentication endpoint path (default: %(default)s)",
    )

    # Authentication
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--username",
        default=os.getenv("CS_API_USERNAME"),
        required=False,  # We'll check this later after handling --show-env
        help="Cobalt Strike username (or set CS_API_USERNAME)",
    )
    auth_group.add_argument(
        "--password",
        default=os.getenv("CS_API_PASSWORD"),
        required=False,  # We'll check this later after handling --show-env
        help="Cobalt Strike password (or set CS_API_PASSWORD)",
    )
    auth_group.add_argument(
        "--duration-ms",
        type=int,
        default=duration_default,
        help="JWT session duration in milliseconds (default: %(default)s)",
    )

    # HTTP client configuration
    http_group = parser.add_argument_group("HTTP Client")
    http_group.add_argument(
        "--http-timeout",
        type=float,
        default=http_timeout_default,
        help="HTTP request timeout in seconds (default: %(default)s)",
    )
    
    verify_default = env_bool("CS_API_VERIFY_TLS", True)
    tls_group = http_group.add_mutually_exclusive_group()
    tls_group.add_argument(
        "--insecure",
        dest="verify_tls",
        action="store_false",
        default=verify_default,
        help="Disable TLS certificate verification",
    )
    tls_group.add_argument(
        "--verify-tls",
        dest="verify_tls",
        action="store_true",
        help="Enable TLS certificate verification",
    )

    # MCP server configuration
    mcp_group = parser.add_argument_group("MCP Server")
    mcp_group.add_argument(
        "--transport",
        choices=["http", "streamable-http", "sse", "stdio"],
        default=os.getenv("MCP_TRANSPORT", DEFAULT_TRANSPORT),
        help="MCP transport protocol (default: %(default)s)",
    )
    mcp_group.add_argument(
        "--listen-host",
        default=os.getenv("MCP_LISTEN_HOST", DEFAULT_LISTEN_HOST),
        help="Host interface to bind the server to (default: %(default)s)",
    )
    mcp_group.add_argument(
        "--listen-port",
        type=int,
        default=listen_port_default,
        help="Port to bind the server to (default: %(default)s)",
    )
    mcp_group.add_argument(
        "--listen-path",
        default=os.getenv("MCP_LISTEN_PATH", DEFAULT_LISTEN_PATH),
        help="URL path for the MCP endpoint (default: %(default)s)",
    )
    mcp_group.add_argument(
        "--server-name",
        default=os.getenv("MCP_SERVER_NAME", "Cobalt Strike API"),
        help="Name displayed to MCP clients (default: %(default)s)",
    )
    mcp_group.add_argument(
        "--instructions",
        default=os.getenv("MCP_SERVER_INSTRUCTIONS",DEFAULT_SERVER_INSTRUCTIONS),
        help="Instructions for MCP clients",
    )

    # Advanced options
    advanced_group = parser.add_argument_group("Advanced")
    advanced_group.add_argument(
        "--log-level",
        default=os.getenv("MCP_LOG_LEVEL"),
        help="Override uvicorn log level for HTTP transport",
    )
    advanced_group.add_argument(
        "--allow-remote-bind",
        action="store_true",
        default=env_bool("MCP_ALLOW_REMOTE_BIND", False),
        help=(
            "Allow MCP HTTP/SSE transports to bind non-loopback addresses. "
            "Use only behind external auth/TLS controls."
        ),
    )
    advanced_group.add_argument(
        "--external-auth",
        action="store_true",
        default=env_bool("MCP_EXTERNAL_AUTH", False),
        help="Confirm non-loopback MCP HTTP/SSE binds are protected by external auth",
    )
    ws_enabled_default = env_bool("CS_WS_ENABLED", DEFAULT_WS_ENABLED)
    ws_enabled_group = advanced_group.add_mutually_exclusive_group()
    ws_enabled_group.add_argument(
        "--enable-websocket-streams",
        dest="websocket_enabled",
        action="store_true",
        default=ws_enabled_default,
        help="Enable Cobalt Strike WebSocket stream tools",
    )
    ws_enabled_group.add_argument(
        "--disable-websocket-streams",
        dest="websocket_enabled",
        action="store_false",
        help="Disable Cobalt Strike WebSocket streams and use REST-only command waiting",
    )
    advanced_group.add_argument(
        "--websocket-auto-start",
        dest="websocket_auto_start",
        action="store_true",
        default=env_bool("CS_WS_AUTO_START", DEFAULT_WS_AUTO_START),
        help="Start beacons/eventlog WebSocket subscriptions at server startup",
    )
    advanced_group.add_argument(
        "--no-websocket-auto-start",
        dest="websocket_auto_start",
        action="store_false",
        help="Do not start WebSocket subscriptions until stream tools are called",
    )
    advanced_group.add_argument(
        "--websocket-buffer-size",
        type=int,
        default=websocket_buffer_size_default,
        help="Entries retained per WebSocket stream buffer (default: %(default)s)",
    )
    advanced_group.add_argument(
        "--websocket-reconnect-seconds",
        type=float,
        default=websocket_reconnect_default,
        help="Seconds between WebSocket reconnect attempts (default: %(default)s)",
    )

    args = parser.parse_args()

    # Handle special options first
    if args.show_env:
        show_environment_variables()
        exit(0)

    # Check required arguments for normal operation
    if not args.username:
        parser.error("--username is required (or set CS_API_USERNAME environment variable)")
    if not args.password:
        parser.error("--password is required (or set CS_API_PASSWORD environment variable)")

    # Validation
    if args.duration_ms <= 0:
        parser.error("--duration-ms must be a positive integer")
    if args.http_timeout <= 0:
        parser.error("--http-timeout must be positive")
    if args.websocket_buffer_size <= 0:
        parser.error("--websocket-buffer-size must be a positive integer")
    if args.websocket_reconnect_seconds <= 0:
        parser.error("--websocket-reconnect-seconds must be positive")

    return args


async def main() -> None:
    """Main application entry point."""
    # Load .env file if it exists (before parsing args)
    load_env_file()
    
    args = parse_args()
    configure_logging()

    # Log configuration
    if not args.verify_tls:
        logger.warning("TLS verification disabled; connections will not be validated")

    logger.info("Starting Cobalt Strike MCP server")
    logger.debug("Configuration: %s", {
        "base_url": args.base_url,
        "username": args.username,
        "transport": args.transport,
        "listen_address": f"{args.listen_host}:{args.listen_port}{args.listen_path}",
        "external_auth": args.external_auth,
        "websocket_enabled": args.websocket_enabled,
        "websocket_auto_start": args.websocket_auto_start,
    })

    # Create the Cobalt Strike client
    async with CobaltStrikeClient(
        base_url=args.base_url,
        verify_tls=args.verify_tls,
        timeout=args.http_timeout,
    ) as cs_client:
        
        # Authenticate with Cobalt Strike
        logger.info("Authenticating with Cobalt Strike API as '%s'", args.username)
        await cs_client.authenticate(
            username=args.username,
            password=args.password,
            duration_ms=args.duration_ms,
            login_path=args.login_path,
        )

        # Create and configure the MCP server
        mcp_server = CobaltStrikeMCPServer(
            cs_client=cs_client,
            server_name=args.server_name,
            instructions=args.instructions,
            websocket_streams_enabled=args.websocket_enabled,
            auto_start_websocket_streams=args.websocket_auto_start,
            websocket_buffer_size=args.websocket_buffer_size,
            websocket_reconnect_seconds=args.websocket_reconnect_seconds,
        )

        # Create the server from the OpenAPI spec
        await mcp_server.create_server(args.spec_url)

        # Run the server
        try:
            await mcp_server.run(
                transport=args.transport,
                host=args.listen_host,
                port=args.listen_port,
                path=args.listen_path,
                log_level=args.log_level,
                allow_remote_bind=args.allow_remote_bind,
                external_auth=args.external_auth,
            )
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt; shutting down")
        except Exception as exc:
            logger.exception("Server error: %s", exc)
            raise
        finally:
            await mcp_server.stop()


def run() -> None:
    """Console script entry point."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown complete")
    except Exception:
        exit(1)


if __name__ == "__main__":
    run()
