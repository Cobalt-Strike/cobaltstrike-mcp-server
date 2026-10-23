"""Console entry point."""

import argparse

from cs_server_mcp import __version__
from cs_server_mcp.app import bind_options
from cs_server_mcp.config import BIND_HOST, DEFAULT_MCP_PATH, DEFAULT_PORT, ConfigurationError


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cobaltstrike-mcp-server",
        description=f"Run the Cobalt Strike MCP HTTP server; it listens on {BIND_HOST} only.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--config", help="YAML config path. Default: CS_MCP_CONFIG or ./config.yml."
    )
    parser.add_argument(
        "--port", type=int, help=f"HTTP port. Default: CS_MCP_PORT or {DEFAULT_PORT}."
    )
    parser.add_argument("--mcp-path", help=f"MCP path. Default: CS_MCP_PATH or {DEFAULT_MCP_PATH}.")
    args = parser.parse_args()
    # Imported after parsing so --help and --version skip loading the server stack.
    from cs_server_mcp.server import run

    try:
        run(
            config_path=args.config,
            bind=bind_options(port=args.port, mcp_path=args.mcp_path),
        )
    except ConfigurationError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
