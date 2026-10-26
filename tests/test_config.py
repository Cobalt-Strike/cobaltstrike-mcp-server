from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from cs_server_mcp.command_policy import CommandPolicy, CommandRule
from cs_server_mcp.config import (
    ConfigurationError,
    Settings,
    load_settings,
    load_settings_from_file,
    resolve_password,
)

pytestmark = pytest.mark.usefixtures("clean_environment")

TEAMSERVER_URL = "https://teamserver.example:50443"

FULL_CONFIG = """\
cobalt_strike:
  url: https://teamserver.example:50443/
  username: mcp-service
  password_path: /etc/cs/service-password
  verify_ssl: false
  token_duration_ms: 3600000

limits:
  session_idle_timeout_seconds: 600
  request_timeout_seconds: 12.5
  max_response_chars: 25000
  max_upload_bytes: 2000000
  output_wait_seconds: 15

commands:
  default: deny
  allow:
    - group:housekeeping
    - screenshot
  ask:
    - execute-assembly
  deny:
    - group:postexdll
    - exit

artifacts:
  directory: /opt/cobaltstrike/rest-server/restapi/artifacts
"""


@pytest.fixture
def clean_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in list(os.environ):
        if name.startswith("CS_MCP_"):
            monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)


def write_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yml"
    path.write_text(text, encoding="utf-8")
    return path


def test_load_settings_from_file_full_yaml_loads_every_section(tmp_path: Path) -> None:
    path = write_config(tmp_path, FULL_CONFIG)

    settings = load_settings_from_file(path)

    assert settings == Settings(
        url="https://teamserver.example:50443",
        username="mcp-service",
        password=None,
        password_path=Path("/etc/cs/service-password"),
        verify_ssl=False,
        token_duration_ms=3_600_000,
        request_timeout_seconds=12.5,
        max_response_chars=25_000,
        max_upload_bytes=2_000_000,
        output_wait_seconds=15.0,
        command_policy=CommandPolicy(
            default="deny",
            allow=(CommandRule("housekeeping", group=True), CommandRule("screenshot")),
            ask=(CommandRule("execute-assembly"),),
            deny=(CommandRule("postexdll", group=True), CommandRule("exit")),
        ),
        session_idle_timeout_seconds=600.0,
        artifacts_directory=Path("/opt/cobaltstrike/rest-server/restapi/artifacts"),
    )


def test_load_settings_from_file_env_overrides_replace_file_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_config(tmp_path, FULL_CONFIG)
    monkeypatch.setenv("CS_MCP_URL", "https://backup.example:8443")
    monkeypatch.setenv("CS_MCP_USERNAME", "override-user")
    monkeypatch.setenv("CS_MCP_PASSWORD", "env-secret")
    monkeypatch.setenv("CS_MCP_VERIFY_SSL", "/etc/ssl/teamserver.pem")
    monkeypatch.setenv("CS_MCP_MAX_RESPONSE_CHARS", "8000")
    monkeypatch.setenv("CS_MCP_OUTPUT_WAIT_SECONDS", "0")
    monkeypatch.setenv("CS_MCP_COMMANDS_DEFAULT", "ask")
    monkeypatch.setenv("CS_MCP_COMMANDS_ALLOW", "shell, group:bof")
    monkeypatch.setenv("CS_MCP_MAX_UPLOAD_BYTES", "3000000")
    monkeypatch.setenv("CS_MCP_ARTIFACTS_DIRECTORY", "/srv/cs/artifacts")
    # An empty value clears the file's list.
    monkeypatch.setenv("CS_MCP_COMMANDS_DENY", "")

    settings = load_settings_from_file(path)

    assert settings.url == "https://backup.example:8443"
    assert settings.username == "override-user"
    assert settings.password == "env-secret"
    assert settings.verify_ssl == "/etc/ssl/teamserver.pem"
    assert settings.max_response_chars == 8000
    assert settings.output_wait_seconds == 0.0
    assert settings.command_policy == CommandPolicy(
        default="ask",
        allow=(CommandRule("shell"), CommandRule("bof", group=True)),
        ask=(CommandRule("execute-assembly"),),
        deny=(),
    )
    assert settings.max_upload_bytes == 3_000_000
    assert settings.artifacts_directory == Path("/srv/cs/artifacts")
    assert settings.request_timeout_seconds == 12.5, "a value the environment leaves alone stays"


def test_load_settings_max_upload_bytes_over_the_hard_maximum_is_capped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CS_MCP_MAX_UPLOAD_BYTES", "99999999")

    settings = load_settings()

    assert settings.max_upload_bytes == 10_000_000


def test_load_settings_artifacts_directory_expands_a_tilde(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CS_MCP_ARTIFACTS_DIRECTORY", "~/artifacts")

    settings = load_settings()

    assert settings.artifacts_directory == Path.home() / "artifacts"


def test_load_settings_without_file_uses_documented_defaults() -> None:
    settings = load_settings()

    assert settings.url == "https://localhost:50443"
    assert settings.username == "mcp"
    assert settings.password_path == Path("/run/secrets/cs_password")
    assert settings.verify_ssl is False
    assert settings.token_duration_ms == 86_400_000
    assert settings.session_idle_timeout_seconds == 1800.0
    assert settings.request_timeout_seconds == 30.0
    assert settings.max_response_chars == 40_000
    assert settings.output_wait_seconds == 30.0
    assert settings.command_policy == CommandPolicy(default="ask")
    assert settings.max_upload_bytes == 4_000_000
    assert settings.artifacts_directory == Path.cwd() / "../server/rest-server/restapi/artifacts", (
        "relative to the start cwd"
    )


def test_load_settings_from_file_url_with_path_is_refused(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        """\
cobalt_strike:
  url: https://teamserver.example:50443/api/v1
  username: mcp-service
""",
    )

    with pytest.raises(
        ConfigurationError,
        match=re.escape(
            "cobalt_strike.url: Value error, must be an HTTP(S) origin, "
            "without credentials, path, query, or fragment"
        ),
    ):
        load_settings_from_file(path)


def test_load_settings_from_file_password_in_yaml_is_refused(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        """\
cobalt_strike:
  url: https://teamserver.example:50443
  username: mcp-service
  password: hunter2
""",
    )

    with pytest.raises(
        ConfigurationError,
        match=re.escape(
            "Passwords are refused in YAML; use CS_MCP_PASSWORD or cobalt_strike.password_path"
        ),
    ):
        load_settings_from_file(path)


def test_load_settings_from_file_unknown_key_is_refused_not_ignored(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        """\
cobalt_strike:
  url: https://teamserver.example:50443
  username: mcp-service
limits:
  max_rows: 5
""",
    )

    with pytest.raises(
        ConfigurationError, match=re.escape("limits.max_rows: Extra inputs are not permitted")
    ):
        load_settings_from_file(path)


def test_resolve_password_reads_the_secret_file_without_its_trailing_newline(
    tmp_path: Path,
) -> None:
    secret = tmp_path / "cs_password"
    secret.write_text("hunter2\n", encoding="utf-8")
    settings = Settings(url=TEAMSERVER_URL, username="mcp-service", password_path=secret)

    assert resolve_password(settings) == "hunter2"
