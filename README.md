# Cobalt Strike MCP Server

This is a PoC MCP server developed as part of some internal experiments during the development of [CS 4.12](https://www.cobaltstrike.com/blog/cobalt-strike-412-fix-up-look-sharp) and the [CS REST API](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/api/index.html). More information can be found [here](https://www.cobaltstrike.com/blog/me-myself-and-ai).

https://github.com/user-attachments/assets/92d15b5f-4744-41aa-a803-abe342db8075

> [!NOTE]
> This tool is still in early development stage and subject to breaking changes. It has been heavily vibe-coded, so don't be too hard on the quality of the code 😉

## Getting Started

This MCP server provides a bridge between large language models like Claude and the [Cobalt Strike](https://www.cobaltstrike.com) C2 framework. It allows AI assistants to dynamically access and control the [Cobalt Strike](https://www.cobaltstrike.com) functionality through standardized tools, enabling a natural language interface to adversary simulation workflows.

<img width="5061" height="1836" alt="CS_MCP_arch" src="https://github.com/user-attachments/assets/682b7691-df0e-4dbf-b56e-9649b2f8a416" />

### Prerequisites

- **Python 3.8+** installed
- FastMCP 2.12.5 or higher 
- The Cobalt Strike API Server should be running.
- Cobalt Strike should be installed and configured.
- Cobalt Strike should be properly licensed

### Installation

1. **Clone the repository**

    ```bash
    git clone <repository-url>
    cd cobaltstrike-mcp-server
    ```

2. **Create and activate a virtual environment**

- **Windows**:
    ```cmd
    setup.bat
    venv\Scripts\activate
    ```

- **macOS/Linux**:
    ```bash
    setup.sh
    source venv/bin/activate
    ```

3. **Install dependencies**

    ```powershell
    pip install -r requirements.txt
    ```

4. **Verify Installation**

    ```bash
    python cs_mcp.py --help
    ```

#### Alternative: System-wide Installation

```bash
pip install -r requirements.txt
```

### Configuration

#### Environment Variables

You can configure the server using environment variables:

```bash
# Cobalt Strike API Configuration
export CS_API_BASE_URL="https://your-teamserver:50443"
export CS_API_USERNAME="your_username"
export CS_API_PASSWORD="your_password"
export CS_API_VERIFY_TLS="false"  # Set to "true" for production
export CS_API_HTTP_TIMEOUT="30.0"

# MCP Server Configuration
export MCP_LISTEN_HOST="127.0.0.1"
export MCP_LISTEN_PORT="3000"
export MCP_TRANSPORT="http"
export MCP_SERVER_NAME="Cobalt Strike MCP"

# Logging
export LOG_LEVEL="INFO"  # DEBUG, INFO, WARNING, ERROR
```

#### .env File Support

The server automatically loads environment variables from a `.env` file in the current directory if it exists:

1. **Copy the example file**:
   ```bash
   cp .env.example .env
   ```

2. **Edit the configuration**:
   ```bash
   # Edit .env with your settings
   CS_API_USERNAME=rest_client
   CS_API_PASSWORD=SecurePassword123
   CS_API_VERIFY_TLS=false
   MCP_TRANSPORT=stdio
   ```

3. **Run without command line arguments**:
   ```bash
   python cs_mcp.py
   ```

#### Viewing Environment Variables

Use the `--show-env` option to see all supported environment variables and their current values:

```bash
python cs_mcp.py --show-env
```

This displays:
- All supported environment variables
- Current values (SET/NOT SET)
- Description and default values
- No authentication required

#### Command Line Arguments

The following parameters can be used while starting the MCP Server:

##### Cobalt Strike API
- `--base-url`: Base URL for the Cobalt Strike REST API (`https://<CS_HOST>:50443`)

##### Authentication
- `--username`: Cobalt Strike username (required)
- `--password`: Cobalt Strike password (required)
- `--duration-ms`: JWT session duration in milliseconds

##### HTTP Client
- `--http-timeout`: HTTP request timeout in seconds
- `--insecure`: Disable TLS certificate verification
- `--verify-tls`: Enable TLS certificate verification

##### MCP Server
- `--transport`: MCP transport protocol (http, streamable-http, sse, stdio)
- `--listen-host`: Host interface to bind the server to
- `--listen-port`: Port to bind the server to
- `--listen-path`: URL path for the MCP endpoint
- `--server-name`: Name displayed to MCP clients
- `--instructions`: Instructions for MCP clients

##### Advanced
- `--log-level`: Override uvicorn log level for HTTP transport


### Basic Usage

The MCP Server can be run standalone from the command line.

```bash
# Activate virtual environment first
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Start the MCP server with command line arguments
python cs_mcp.py --username your_username --password your_password --insecure
```

#### Using Environment Variables

```bash
# Set credentials via environment variables
export CS_API_USERNAME="rest_client"
export CS_API_PASSWORD="CobaltStrikePassword"
export CS_API_VERIFY_TLS="false"

# Run with minimal command line arguments
python cs_mcp.py
```

#### Using .env File

```bash
# Create and edit .env file
cp .env.example .env
# Edit .env with your credentials

# Run
python cs_mcp.py --transport stdio
```
## Available Tools

The MCP server automatically exposes all [Cobalt Strike REST API endpoints](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/api/index.html) as tools. Some key categories include:

### Beacon Management
- `listBeacons`: Get all active beacons
- `getBeacon`: Get specific beacon information
- `removeBeacon`: Remove a beacon
- [...]

### Commands
- `executeShell`: Execute shell commands on beacons
- `executeSleep`: Change beacon sleep intervals
- `executeUpload`: Upload files to target systems
- `executeDownload`: Download files from target systems
- [...]

### Payloads
- `generatePayload`: Generate various payload types
- `listPayloads`: Get available payload options
- [...]

### Listeners
- `createListener`: Create new listeners
- `listListeners`: Get active listeners
- `removeListener`: Remove listeners
- [...]

## MCP Prompts

The server includes built-in [MCP example prompts](https://github.com/Cobalt-Strike/cobaltstrike-mcp-server/blob/main/cs_prompts.py) to help operation planning.

## MCP Resources

The server exposes static Cobalt Strike data through [MCP resources](https://github.com/Cobalt-Strike/cobaltstrike-mcp-server/blob/main/cs_resources.py):

> [!NOTE]
> Resources provide read-only access to live Cobalt Strike data and are automatically updated.

## Claude Desktop Integration

1. **Copy the configuration example**:
   ```bash
   cp claude_desktop_config_example.json ~/.config/claude-desktop/claude_desktop_config.json
   ```

2. **Edit the configuration**:
   - Set your Cobalt Strike credentials
   - Adjust the server URL and ports as needed

    ```json
    {
        "mcpServers": {
        "Cobalt Strike MCP": {
            "name": "Cobalt Strike MCP",
            "command": "<PROJECT LOCATION>/venv/Scripts/python.exe",
            "args": [
                        "<PROJECT LOCATION>\\cs_mcp.py"
                    ],
            "env": {
                        "CS_API_BASE_URL": "https://localhost:50443",
                        "CS_API_USERNAME": "resp_api_user",
                        "CS_API_PASSWORD": "CobaltStrikePassword",
                        "CS_API_VERIFY_TLS": "false",
                        "MCP_TRANSPORT": "stdio"
                    }
        }
    }
    }
    ```

3. **Restart Claude Desktop** to load the new configuration.

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   ```
   RuntimeError: Authentication failed with status 401 or 403
   ```
   - Verify your username and password
   - Ensure the user has API access permissions
   - Check that the [Cobalt Strike team server is running](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_starting-cs-team-server.htm)

2. **Connection Refused**
   ```
   httpx.ConnectError: [Errno 61] Connection refused
   ```
   - Verify the base URL and port
   - Ensure the team server's REST API is enabled
   - Check firewall settings

3. **TLS Certificate Errors**
   ```
   httpx.HTTPStatusError: SSL: CERTIFICATE_VERIFY_FAILED
   ```
   - Use `--insecure` flag for self-signed certificates
   - Or install the proper CA certificate and use `--verify-tls`

4. **Import Errors**
   ```
   ModuleNotFoundError: No module named 'fastmcp'
   ```
   - Ensure virtual environment is activated
   - Run `pip install -r requirements.txt`

## Support

For issues and questions:
- Check the troubleshooting section above
- Review [Cobalt Strike documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_starting-rest-server.htm) for API requirements
- Consult [FastMCP documentation](https://gofastmcp.com/getting-started/welcome) for MCP-specific issues

---

> [!WARNING]
> This tool provides direct access to Cobalt Strike capabilities, which include powerful adversary simulation capabilities. Use responsibly and only in environments where you have explicit permission to perform security testing.
