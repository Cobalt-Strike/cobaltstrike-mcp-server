"""Validated YAML configuration, scalar environment overrides, and secret resolution."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from cs_server_mcp.command_policy import (
    CommandPolicy,
    CommandRule,
    parse_env_rules,
    parse_rule_text,
)

DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_OUTPUT_WAIT_SECONDS = 30.0
MAX_OUTPUT_WAIT_SECONDS = 50.0
DEFAULT_MAX_RESPONSE_CHARS = 40_000
MIN_MAX_RESPONSE_CHARS = 5_000
DEFAULT_MAX_UPLOAD_BYTES = 4_000_000
HARD_MAX_UPLOAD_BYTES = 10_000_000
SEARCH_REGEX_MAX_CHARS = 256
SEARCH_REGEX_BUDGET_SECONDS = 1.0
DEFAULT_TOKEN_DURATION_MS = 86_400_000
DEFAULT_CONFIG_FILENAME = "config.yml"
DEFAULT_COBALT_STRIKE_URL = "https://localhost:50443"
DEFAULT_COBALT_STRIKE_USERNAME = "mcp"
DEFAULT_COBALT_STRIKE_VERIFY_SSL = False
DEFAULT_PASSWORD_PATH = Path("/run/secrets/cs_password")
DEFAULT_ARTIFACTS_DIRECTORY = Path("../server/rest-server/restapi/artifacts")
BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 50051
DEFAULT_MCP_PATH = "/mcp"
DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS = 1800.0

_CONFIG_SECTIONS: Mapping[str, frozenset[str]] = {
    "cobalt_strike": frozenset(
        {"url", "username", "password_path", "verify_ssl", "token_duration_ms"}
    ),
    "limits": frozenset(
        {
            "session_idle_timeout_seconds",
            "request_timeout_seconds",
            "max_response_chars",
            "max_upload_bytes",
            "output_wait_seconds",
        }
    ),
    "artifacts": frozenset({"directory"}),
    "commands": frozenset({"default", "allow", "ask", "deny"}),
}
_SECTION_FIELD_PREFIXES: Mapping[str, str] = {
    "artifacts": "artifacts_",
    "commands": "commands_",
}


class ConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class ListLimits:
    default: int
    maximum: int


LIST_LIMITS: Mapping[str, ListLimits] = {
    "beacons": ListLimits(default=10, maximum=50),
    "commands": ListLimits(default=50, maximum=100),
    "command_executions": ListLimits(default=10, maximum=50),
    "artifacts": ListLimits(default=10, maximum=50),
    "downloads": ListLimits(default=10, maximum=50),
    "screenshots": ListLimits(default=10, maximum=50),
}


@dataclass(frozen=True)
class Settings:
    url: str = DEFAULT_COBALT_STRIKE_URL
    username: str = DEFAULT_COBALT_STRIKE_USERNAME
    password: str | None = field(default=None, repr=False)
    password_path: Path = DEFAULT_PASSWORD_PATH
    verify_ssl: bool | str = DEFAULT_COBALT_STRIKE_VERIFY_SSL
    token_duration_ms: int = DEFAULT_TOKEN_DURATION_MS
    request_timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_response_chars: int = DEFAULT_MAX_RESPONSE_CHARS
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
    output_wait_seconds: float = DEFAULT_OUTPUT_WAIT_SECONDS
    command_policy: CommandPolicy = field(default_factory=CommandPolicy)
    session_idle_timeout_seconds: float = DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS
    artifacts_directory: Path = field(
        default_factory=lambda: Path.cwd() / DEFAULT_ARTIFACTS_DIRECTORY
    )

    def clamp_list_limit(self, limit: int | None, *, resource: str) -> int:
        """A limit over the maximum is clamped and reported, not refused, so a generous limit
        never costs the model a round trip."""
        limits = LIST_LIMITS[resource]
        requested = limits.default if limit is None else limit
        if requested < 1:
            raise ValueError("limit must be greater than or equal to 1")
        return min(requested, limits.maximum)

    def argument_ceilings(self) -> dict[str, int]:
        """The ceilings ``tool_schema.ConfiguredCeiling`` publishes in argument descriptions."""
        return {
            f"{resource}_list_limit": limits.maximum for resource, limits in LIST_LIMITS.items()
        }


@dataclass(frozen=True)
class BindOptions:
    port: int = DEFAULT_PORT
    mcp_path: str = DEFAULT_MCP_PATH


class _CommandRuleModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    group: str | None = None

    @field_validator("name", "group")
    @classmethod
    def nonempty(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("must not be empty")
        return None if value is None else value.strip()

    @model_validator(mode="after")
    def one_kind(self) -> _CommandRuleModel:
        if (self.name is None) == (self.group is None):
            raise ValueError("must have exactly one of name and group")
        return self

    def to_rule(self) -> CommandRule:
        if self.group is not None:
            return CommandRule(self.group, group=True)
        assert self.name is not None
        return CommandRule(self.name)


class _CommandPolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    default: Literal["allow", "ask", "deny"] = "ask"
    allow: list[_CommandRuleModel] = Field(default_factory=list)
    ask: list[_CommandRuleModel] = Field(default_factory=list)
    deny: list[_CommandRuleModel] = Field(default_factory=list)

    @field_validator("allow", "ask", "deny", mode="before")
    @classmethod
    def rules(cls, value: Any) -> Any:
        if not isinstance(value, list):
            raise ValueError("must be a list")
        return [parse_rule_text(rule) if isinstance(rule, str) else rule for rule in value]

    def to_policy(self) -> CommandPolicy:
        return CommandPolicy(
            default=self.default,
            **{
                tier: tuple(rule.to_rule() for rule in getattr(self, tier))
                for tier in ("allow", "ask", "deny")
            },
        )


class _SettingsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = DEFAULT_COBALT_STRIKE_URL
    username: str = Field(default=DEFAULT_COBALT_STRIKE_USERNAME, min_length=1)
    password: str | None = Field(default=None, repr=False)
    password_path: Path = DEFAULT_PASSWORD_PATH
    verify_ssl: bool | str = DEFAULT_COBALT_STRIKE_VERIFY_SSL
    token_duration_ms: int = Field(
        default=DEFAULT_TOKEN_DURATION_MS, ge=1, le=DEFAULT_TOKEN_DURATION_MS
    )
    request_timeout_seconds: float = Field(
        default=DEFAULT_TIMEOUT_SECONDS, gt=0, allow_inf_nan=False
    )
    max_response_chars: int = Field(default=DEFAULT_MAX_RESPONSE_CHARS, ge=MIN_MAX_RESPONSE_CHARS)
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
    output_wait_seconds: float = Field(
        default=DEFAULT_OUTPUT_WAIT_SECONDS, ge=0, le=MAX_OUTPUT_WAIT_SECONDS, allow_inf_nan=False
    )
    command_policy: _CommandPolicyModel = Field(default_factory=_CommandPolicyModel)
    session_idle_timeout_seconds: float = Field(
        default=DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS, ge=60, allow_inf_nan=False
    )
    artifacts_directory: Path = Field(default=DEFAULT_ARTIFACTS_DIRECTORY, validate_default=True)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        parts = urlsplit(value)
        is_http_host = parts.scheme in {"http", "https"} and bool(parts.hostname)
        has_more_than_origin = any(
            (parts.username, parts.password, parts.path, parts.query, parts.fragment)
        )
        if not is_http_host or has_more_than_origin:
            raise ValueError(
                "must be an HTTP(S) origin, without credentials, path, query, or fragment"
            )
        try:
            parts.port  # Parsed on access; an invalid port raises.
        except ValueError:
            raise ValueError("must have a valid port") from None
        return value

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value.strip()

    @field_validator("artifacts_directory")
    @classmethod
    def validate_artifacts_directory(cls, value: Path) -> Path:
        if not str(value).strip():
            raise ValueError("must not be empty")
        # Made absolute now so a later chdir cannot move it.
        return Path.cwd() / Path(str(value).strip()).expanduser()

    @field_validator("max_upload_bytes")
    @classmethod
    def validate_max_upload_bytes(cls, value: int) -> int:
        if value < 1:
            raise ValueError("must be greater than or equal to 1")
        return min(value, HARD_MAX_UPLOAD_BYTES)

    @field_validator("verify_ssl", mode="before")
    @classmethod
    def normalize_verify_ssl(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = value.strip()
            if value.lower() in {"true", "1", "yes", "on"}:
                return True
            if value.lower() in {"false", "0", "no", "off"}:
                return False
            if not value:
                raise ValueError("must be a boolean or a CA bundle path")
        return value

    def to_settings(self) -> Settings:
        values = self.model_dump(exclude={"command_policy"})
        return Settings(**values, command_policy=self.command_policy.to_policy())


class _EnvOverrideSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CS_MCP_",
        env_ignore_empty=True,
        extra="ignore",
    )

    session_idle_timeout_seconds: float | None = None
    commands_default: str | None = None

    url: str | None = None
    username: str | None = None
    password: str | None = Field(default=None, repr=False)
    password_path: Path | None = None
    verify_ssl: str | None = None
    token_duration_ms: int | None = None
    request_timeout_seconds: float | None = None
    max_response_chars: int | None = None
    max_upload_bytes: int | None = None
    output_wait_seconds: float | None = None
    artifacts_directory: Path | None = None


def _require_mapping(value: Any, *, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{name} must be a table/object")
    return value


def _optional_mapping(value: Any, *, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    return _require_mapping(value, name=name)


def _config_location(field_name: str) -> str:
    if field_name == "command_policy":
        return "commands"
    for section, keys in _CONFIG_SECTIONS.items():
        prefix = _SECTION_FIELD_PREFIXES.get(section, "")
        for key in keys:
            if field_name == f"{prefix}{key}":
                return f"{section}.{key}"
    return field_name


def _validation_error(exc: ValidationError) -> ConfigurationError:
    first_error = exc.errors(include_input=False)[0]
    parts = [str(part) for part in first_error["loc"]]
    if parts:
        parts[0] = _config_location(parts[0])
    return ConfigurationError(f"{'.'.join(parts)}: {first_error['msg']}")


def _settings_from_values(values: dict[str, Any]) -> Settings:
    try:
        return _SettingsModel.model_validate(values).to_settings()
    except ValidationError as exc:
        # Not chained: the pydantic error echoes inputs, which may include a pasted secret.
        raise _validation_error(exc) from None


def _env_overrides() -> dict[str, Any]:
    try:
        return _EnvOverrideSettings().model_dump(exclude_none=True)
    except ValidationError as exc:
        raise _validation_error(exc) from None


def _flatten_config_mapping(data: dict[str, Any]) -> dict[str, Any]:
    if "password" in data or "password" in _optional_mapping(
        data.get("cobalt_strike"), name="cobalt_strike"
    ):
        raise ConfigurationError(
            "Passwords are refused in YAML; use CS_MCP_PASSWORD or cobalt_strike.password_path"
        )
    unknown_sections = set(data) - _CONFIG_SECTIONS.keys()
    if unknown_sections:
        raise ConfigurationError(f"Unknown configuration section: {min(unknown_sections)}")
    values: dict[str, Any] = {}
    for section, keys in _CONFIG_SECTIONS.items():
        entries = _optional_mapping(data.get(section), name=section)
        unknown_keys = set(entries) - keys
        if unknown_keys:
            raise ConfigurationError(
                f"{section}.{min(unknown_keys)}: Extra inputs are not permitted"
            )
        if section == "commands":
            values["command_policy"] = dict(entries)
            continue
        prefix = _SECTION_FIELD_PREFIXES.get(section, "")
        values.update(
            {f"{prefix}{key}": value for key, value in entries.items() if value is not None}
        )
    return values


def settings_from_mapping(data: dict[str, Any], *, env_overrides: bool = True) -> Settings:
    values = _flatten_config_mapping(_optional_mapping(data, name="config file"))
    if env_overrides:
        values = _with_env_overrides(values)
    return _settings_from_values(values)


def _with_env_overrides(values: dict[str, Any]) -> dict[str, Any]:
    overrides = _env_overrides()
    policy = dict(values["command_policy"])
    default = overrides.pop("commands_default", None)
    if default is not None:
        policy["default"] = default
    for tier in ("allow", "ask", "deny"):
        # Not via _EnvOverrideSettings: its env_ignore_empty would drop CS_MCP_COMMANDS_ALLOW=,
        # which deliberately clears the YAML list.
        env = os.getenv(f"CS_MCP_COMMANDS_{tier.upper()}")
        if env is not None:
            policy[tier] = parse_env_rules(env)
    return {**values, **overrides, "command_policy": policy}


def load_settings_from_file(config_path: str | Path) -> Settings:
    path = Path(config_path).expanduser()
    if path.suffix.lower() not in {".yml", ".yaml"}:
        raise ConfigurationError("Config file must use the .yml or .yaml extension")
    try:
        data = yaml.safe_load(path.read_bytes())
    except OSError as exc:
        raise ConfigurationError(f"Could not read config file {path}") from exc
    except yaml.YAMLError:
        # Not chained: YAML errors echo source lines, which may include a pasted password.
        raise ConfigurationError(f"Invalid YAML config file {path}") from None
    return settings_from_mapping(_optional_mapping(data, name="config file"))


def load_settings(config_path: str | Path | None = None) -> Settings:
    if config_path is not None:
        return load_settings_from_file(config_path)

    env_config_path = os.getenv("CS_MCP_CONFIG", "").strip()
    if env_config_path:
        return load_settings_from_file(env_config_path)

    path = Path(DEFAULT_CONFIG_FILENAME)
    if path.is_file():
        return load_settings_from_file(path)

    return settings_from_mapping({})


def resolve_password(settings: Settings) -> str:
    password = settings.password
    if password is None:
        try:
            password = (
                settings.password_path.expanduser().read_text(encoding="utf-8").rstrip("\r\n")
            )
        except (OSError, UnicodeError) as exc:
            raise ConfigurationError(
                "Could not read Cobalt Strike password; set CS_MCP_PASSWORD or password_path"
            ) from exc
    if not password:
        raise ConfigurationError(
            "Cobalt Strike password is empty; set CS_MCP_PASSWORD or password_path"
        )
    return password
