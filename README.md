# Cobalt Strike MCP Server

Version 0.2 of the official Cobalt Strike MCP

## Tools

| Name | Description |
| --- | --- |
| cs_list_beacons | List beacons, or get one beacon by ID |
| cs_list_commands | List the commands beacons can run, with their help text |
| cs_execute_command | Execute one command on a beacon and return a submission receipt |
| cs_list_command_executions | List past command executions, or get one by ID |
| cs_read_command_output | Read the output of one command execution as plain text |
| cs_list_artifacts | List artifacts stored on the team server for beacons to use |
| cs_upload_artifact | Get a one-time link that stores a file as a new artifact |
| cs_list_downloads | List files downloaded from beacons, with transfers in progress |
| cs_fetch_download | Get a one-time link to fetch a download's file |
| cs_list_screenshots | List screenshots taken on beacons |
| cs_fetch_screenshot | Get a one-time link to fetch a screenshot's image |

## Requirements

- Cobalt Strike 4.13+
- Must run on the team server host
- Python 3.13+
- uv
- Optimized for Codex CLI and Claude Code, but should be compatible with any MCP client

## Usage

### Team Server

1. Create `config.yml`

```bash
cp config.example.yml config.yml
```

2. Update `config.yml` as needed (or use environment variable overrides)

| Setting | Environment variable | Default |
|---|---|---|
| `cobalt_strike.url` | `CS_MCP_URL` | `https://localhost:50443` |
| `cobalt_strike.username` | `CS_MCP_USERNAME` | `mcp` |
| | `CS_MCP_PASSWORD` | |
| `cobalt_strike.password_path` | `CS_MCP_PASSWORD_PATH` | `/run/secrets/cs_password` |
| `cobalt_strike.verify_ssl` | `CS_MCP_VERIFY_SSL` | `false` |
| `cobalt_strike.token_duration_ms` | `CS_MCP_TOKEN_DURATION_MS` | `86400000` |
| `limits.session_idle_timeout_seconds` | `CS_MCP_SESSION_IDLE_TIMEOUT_SECONDS` | `1800` |
| `limits.request_timeout_seconds` | `CS_MCP_REQUEST_TIMEOUT_SECONDS` | `30` |
| `limits.max_response_chars` | `CS_MCP_MAX_RESPONSE_CHARS` | `40000` |
| `limits.max_upload_bytes` | `CS_MCP_MAX_UPLOAD_BYTES` | `4000000` |
| `limits.output_wait_seconds` | `CS_MCP_OUTPUT_WAIT_SECONDS` | `30` |
| `commands.default` | `CS_MCP_COMMANDS_DEFAULT` | `ask` |
| `commands.allow` | `CS_MCP_COMMANDS_ALLOW` | [] |
| `commands.ask` | `CS_MCP_COMMANDS_ASK` | [] |
| `commands.deny` | `CS_MCP_COMMANDS_DENY` | [] |
| `artifacts.directory` | `CS_MCP_ARTIFACTS_DIRECTORY` | `../server/rest-server/restapi/artifacts` |

3. Start the MCP server

```bash
uv sync --locked --no-dev
uv run --locked --no-dev cobaltstrike-mcp-server --config ./config.yml
```

### Operator Workstation

4. Add to your preferred client

You may need to port forward or allow 50051 from your client to the team server.

*Codex CLI*

```bash
codex mcp add cobaltstrike --url http://teamserver:50051/mcp
```

*Claude Code*

```bash
claude mcp add --transport http cobaltstrike http://teamserver:50051/mcp
```

5. Install the SpecterOps Skills marketplace (optional)

We recommend installing the [SpecterOps skills repo](https://github.com/SpecterOps/skills) and its Cobalt Strike operations plugin.

*Codex CLI*

```bash
codex plugin marketplace add SpecterOps/skills
```

*Claude Code*

```bash
/plugin marketplace add SpecterOps/skills
```

Once the marketplace is installed, make sure to enable the `c2-cobaltstrike` plugin.
