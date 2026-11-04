"""Service-account SDK facade."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from email.message import Message
from ipaddress import ip_address
from time import monotonic
from typing import Any, Protocol

import aiohttp
import anyio
from cs_sdk_python.api_client import ApiClient, Configuration
from cs_sdk_python.api_client.api import (
    BeaconInfoApi,
    CaptureApi,
    ConsoleCommandApi,
    CredsAndTokensApi,
    FileAndRegistryApi,
    JobsAndTasksApi,
    ListenersApi,
    PayloadAndArtifactsApi,
    ProcessAndExecutionApi,
    SecurityApi,
    ServerConfigApi,
)
from cs_sdk_python.api_client.exceptions import ApiException
from cs_sdk_python.api_client.models import CommandDto, LoginRequest
from cs_sdk_python.api_client.rest import RESTResponse
from pydantic import BaseModel, ValidationError

from cs_server_mcp import __version__, agent_text
from cs_server_mcp.config import Settings
from cs_server_mcp.serialization import to_plain_data

SdkOperation = Callable[..., Awaitable[Any]]


class ClientCall(Protocol):
    """``await call_cs("get_beacon", bid)``: a call into the client by method name, with the
    result converted to plain data. Taken instead of the client so a fake can stand in."""

    def __call__(self, method_name: str, /, *args: Any, **kwargs: Any) -> Awaitable[Any]: ...


class _CheckedApiClient(ApiClient):
    """The generated ``*_without_preload_content`` methods return a failure response as if it
    had succeeded, so the status is checked here for every request."""

    async def call_api(
        self,
        method: str,
        url: str,
        header_params: dict[str, str] | None = None,
        body: Any = None,
        post_params: Any = None,
        _request_timeout: float | tuple[float, float] | None = None,
    ) -> RESTResponse:
        result = await super().call_api(
            method, url, header_params, body, post_params, _request_timeout
        )
        if not 200 <= result.status < 300:
            await result.read()
            raise ApiException(http_resp=result)
        return result


class CobaltStrikeResponseError(Exception):
    """A successful response did not have the documented shape."""


@dataclass
class ResponseStream:
    """An aiohttp response as ``file_transfer.BinaryStream``."""

    media_type: str
    filename: str | None
    content_length: int | None
    response: aiohttp.ClientResponse = field(repr=False)

    def chunks(self, size: int = 65_536) -> AsyncIterator[bytes]:
        return self.response.content.iter_chunked(size)

    async def aclose(self) -> None:
        self.response.release()


def _filename_from_content_disposition(value: str | None) -> str | None:
    if not value:
        return None
    message = Message()
    message["content-disposition"] = value
    return message.get_filename()


def _segment(value: str | int) -> str:
    # Dot segments are normalized to another endpoint even when percent-encoded.
    if str(value) in {"", ".", ".."}:
        raise CobaltStrikeResponseError(agent_text.API_IDENTIFIER_INVALID)
    return str(value)


def _sdk_configuration(settings: Settings) -> Configuration:
    config = Configuration(host=settings.url.rstrip("/"))
    if isinstance(settings.verify_ssl, str):
        config.ssl_ca_cert = settings.verify_ssl
    else:
        config.verify_ssl = settings.verify_ssl
    return config


def _plain_response(value: Any) -> Any:
    # to_dict keeps the wire's camelCase keys and flattens additional_properties, which
    # model_dump would nest.
    if isinstance(value, BaseModel):
        return to_plain_data(value.to_dict())
    if isinstance(value, list):
        return [_plain_response(item) for item in value]
    return value


class CobaltStrikeClient:
    """One service account's session, opened as an async context manager.

    Each method wraps one REST call. An HTTP failure raises the SDK's ``ApiException``; an
    answer outside the documented shape raises ``CobaltStrikeResponseError``. The JWT is
    refreshed before it expires and once more after a 401.
    """

    def __init__(self, settings: Settings, *, password: str):
        self.settings = settings
        self._password = password
        self._api_client: ApiClient | None = None
        self._token: str | None = None
        self._refresh_at: float | None = None
        self._login_lock = asyncio.Lock()

    async def __aenter__(self) -> CobaltStrikeClient:
        if self._api_client is not None:
            raise RuntimeError("CobaltStrikeClient is already open")
        api_client = _CheckedApiClient(_sdk_configuration(self.settings))
        await api_client.__aenter__()
        api_client.user_agent = f"cobaltstrike-mcp-server/{__version__}"
        self._api_client = api_client
        self.beacons = BeaconInfoApi(self._api_client)
        self.console = ConsoleCommandApi(self._api_client)
        self.jobs = JobsAndTasksApi(self._api_client)
        self.files = FileAndRegistryApi(self._api_client)
        self.capture = CaptureApi(self._api_client)
        self.artifacts = PayloadAndArtifactsApi(self._api_client)
        self.security = SecurityApi(self._api_client)
        self.config = ServerConfigApi(self._api_client)
        self.execution = ProcessAndExecutionApi(self._api_client)
        self.creds = CredsAndTokensApi(self._api_client)
        self.listeners = ListenersApi(self._api_client)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        sdk, self._api_client = self._api_client, None
        self._token = self._refresh_at = None
        if sdk is not None:
            sdk.configuration.access_token = None
            with anyio.CancelScope(shield=True):
                await sdk.__aexit__(*exc)

    @property
    def sdk(self) -> ApiClient:
        if self._api_client is None:
            raise RuntimeError("CobaltStrikeClient must be used as an async context manager")
        return self._api_client

    @property
    def timeout(self) -> float:
        return float(self.settings.request_timeout_seconds)

    async def login(self) -> None:
        await self._relogin(stale=self._token)

    async def _relogin(self, *, stale: str | None) -> None:
        async with self._login_lock:
            if self._token is not None and self._token != stale:
                return
            self._token = None
            self.sdk.configuration.access_token = None
            self._refresh_at = None
            started = monotonic()
            # Raw JSON: AuthDto rejects a malformed expires_in, which _token_lifetime tolerates.
            data = await self._raw_json(
                self.security.authenticate_user_without_preload_content,
                authenticate=False,
                request_model=LoginRequest(
                    username=self.settings.username,
                    password=self._password,
                    duration_ms=self.settings.token_duration_ms,
                ),
            )
            token = data.get("access_token")
            if not isinstance(token, str) or not token.strip():
                raise CobaltStrikeResponseError(agent_text.INVALID_LOGIN_RESPONSE)
            lifetime = self._token_lifetime(data.get("expires_in"))
            # Up to a minute early, for latency and JWT whole-second rounding.
            self._refresh_at = started + lifetime - min(60.0, lifetime / 2)
            self._token = token
            self.sdk.configuration.access_token = token

    def _token_lifetime(self, expires_in: Any) -> float:
        """Live servers may answer 403 rather than 401 once the JWT expires, and 403 is never
        retried, so the token must be refreshed before then. The configured duration stands in
        for an expires_in that is missing, malformed, or longer."""
        configured = self.settings.token_duration_ms / 1000
        if (
            isinstance(expires_in, (int, float))
            and not isinstance(expires_in, bool)
            and 0 < expires_in < configured
        ):
            return float(expires_in)
        return configured

    def _login_due(self, token: str | None) -> bool:
        if token is None:
            return True
        return self._refresh_at is not None and monotonic() >= self._refresh_at

    async def _call(
        self,
        operation: SdkOperation,
        *,
        authenticate: bool = True,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Any:
        token = self._token
        if authenticate and self._login_due(token):
            await self._relogin(stale=token)
            token = self._token
        for attempt in range(2):
            try:
                return await operation(_request_timeout=timeout or self.timeout, **kwargs)
            except ApiException as exc:
                if exc.status != 401 or not authenticate or attempt:
                    raise
                await self._relogin(stale=token)
            except (ValidationError, ValueError, TypeError) as exc:
                # Never retried: the request may already have submitted a command.
                raise CobaltStrikeResponseError(agent_text.INVALID_RESPONSE) from exc
        raise AssertionError("unreachable")

    @staticmethod
    def _shape(data: Any, expected: type) -> Any:
        if not isinstance(data, expected) or (
            expected is list and any(not isinstance(row, dict) for row in data)
        ):
            raise CobaltStrikeResponseError(
                agent_text.INVALID_RESPONSE_TYPE.format(expected=expected.__name__)
            )
        return data

    async def _get(self, operation: SdkOperation, expected: type = dict, **kwargs: Any) -> Any:
        return self._shape(_plain_response(await self._call(operation, **kwargs)), expected)

    async def _raw_json(self, operation: SdkOperation, expected: type = dict, **kwargs: Any) -> Any:
        response = await self._call(operation, **kwargs)
        try:
            data = json.loads(await response.read())
        except (ValueError, UnicodeError):
            raise CobaltStrikeResponseError(agent_text.INVALID_JSON) from None
        finally:
            response.release()
        return self._shape(data, expected)

    async def _post(self, operation: SdkOperation, **kwargs: Any) -> dict[str, Any]:
        data = await self._get(operation, **kwargs)
        if any(not isinstance(data.get(key), str) for key in ("name", "status", "message")):
            raise CobaltStrikeResponseError(agent_text.INVALID_COMMAND_RESPONSE)
        if data.get("taskId") is not None and not isinstance(data["taskId"], str):
            raise CobaltStrikeResponseError(agent_text.INVALID_TASK_ID)
        return data

    async def list_beacons(self) -> list[dict[str, Any]]:
        # Raw JSON: BeaconDto requires lastCheckinMs and a complete sleep object, which
        # existing server records can omit.
        return await self._raw_json(self.beacons.list_beacons_without_preload_content, list)

    async def get_beacon(self, bid: str) -> dict[str, Any]:
        return await self._raw_json(
            self.beacons.get_beacon_without_preload_content, bid=_segment(bid)
        )

    async def list_beacon_commands(self, bid: str) -> list[dict[str, Any]]:
        return await self._get(
            self.console.list_command_help,
            list,
            bid=_segment(bid),
        )

    async def get_beacon_command(self, bid: str, command: str) -> dict[str, Any]:
        return await self._get(
            self.console.get_command_help,
            bid=_segment(bid),
            command=_segment(command),
        )

    # The technique lists are served for any beacon ID, the catalog's pseudo-beacon included.
    async def list_jump_techniques(self, bid: str) -> list[dict[str, Any]]:
        return await self._get(
            self.execution.list_remote_execute_beacon_methods, list, bid=_segment(bid)
        )

    async def list_remote_exec_techniques(self, bid: str) -> list[dict[str, Any]]:
        return await self._get(
            self.execution.list_remote_execution_command_methods, list, bid=_segment(bid)
        )

    async def list_elevate_techniques(self, bid: str) -> list[dict[str, Any]]:
        return await self._get(self.creds.list_elevate_beacon_methods, list, bid=_segment(bid))

    async def list_runasadmin_techniques(self, bid: str) -> list[dict[str, Any]]:
        return await self._get(self.execution.list_elevate_command_methods, list, bid=_segment(bid))

    async def list_listeners(self) -> list[dict[str, Any]]:
        # Raw JSON: ListenerBaseDto drops the read-only payload and error fields when dumped.
        return await self._raw_json(self.listeners.list_listeners_without_preload_content, list)

    async def execute_console_command(
        self, bid: str, *, command: str, arguments: str | None
    ) -> dict[str, Any]:
        return await self._post(
            self.console.execute_console_command,
            bid=_segment(bid),
            request_model=CommandDto(command=command, arguments=arguments),
        )

    async def list_tasks(self) -> list[dict[str, Any]]:
        return await self._get(self.jobs.list_tasks, list)

    async def list_beacon_tasks(self, bid: str) -> list[dict[str, Any]]:
        return await self._get(
            self.jobs.list_task_summaries_by_bid,
            list,
            bid=_segment(bid),
        )

    async def get_task(self, task_id: str) -> dict[str, Any]:
        # Structured format carries ps and ls results as tables. Raw JSON: TaskDetailDto
        # cannot represent the live {taskStatus: NOT_FOUND} sentinel or malformed timestamps.
        return await self._raw_json(
            self.jobs.get_task_by_id_without_preload_content,
            task_id=_segment(task_id),
            format="structured",
        )

    async def list_artifacts(self) -> list[dict[str, Any]]:
        return await self._get(self.artifacts.list_artifacts, list)

    async def list_downloads(self) -> list[dict[str, Any]]:
        return await self._get(self.files.list_downloads, list)

    async def list_active_downloads(self, bid: str) -> list[dict[str, Any]]:
        return await self._get(self.files.list_active_downloads, list, bid=_segment(bid))

    async def open_download_file(self, download_id: str) -> ResponseStream:
        return await self._open_file(
            self.files.get_download_without_preload_content,
            download_id,
            "application/octet-stream",
        )

    async def list_screenshots(self) -> list[dict[str, Any]]:
        # Raw JSON: ScreenshotDto requires an integer timestamp; a malformed one is rendered
        # null instead of failing the listing.
        return await self._raw_json(self.capture.list_screenshots_without_preload_content, list)

    async def open_screenshot_image(self, screenshot_id: str) -> ResponseStream:
        return await self._open_file(
            self.capture.get_screenshot_without_preload_content, screenshot_id, "image/png"
        )

    async def get_teamserver_ip(self) -> str:
        value = await self._config_text(self.config.get_teamserver_ip_without_preload_content)
        try:
            ip_address(value)
        except ValueError:
            raise CobaltStrikeResponseError(agent_text.INVALID_TEAMSERVER_IP) from None
        return value

    async def get_kill_date(self) -> str:
        return await self._config_text(self.config.get_kill_date_without_preload_content)

    async def get_c2_profile(self) -> str:
        return await self._config_text(self.config.get_c2_profile_without_preload_content)

    async def get_system_information(self) -> str:
        return await self._config_text(self.config.get_system_information_without_preload_content)

    async def _config_text(self, operation: SdkOperation) -> str:
        response = await self._call(operation)
        try:
            body = await response.read()
        finally:
            response.release()
        try:
            value = json.loads(body)
        except (ValueError, UnicodeError):
            value = None
        if not isinstance(value, str):
            value = body.decode("utf-8", errors="replace")
        return value.strip()

    async def _open_file(
        self, operation: SdkOperation, content_id: str, default_media_type: str
    ) -> ResponseStream:
        response = await self._call(
            operation,
            id=_segment(content_id),
            # aiohttp's timeout is a total deadline, so a large file needs more.
            timeout=max(self.timeout, 300.0),
        )
        length = response.headers.get("content-length", "")
        # With compression, Content-Length counts wire bytes, not decoded bytes.
        content_length = (
            int(length)
            if length.isdigit() and not response.headers.get("content-encoding")
            else None
        )
        return ResponseStream(
            media_type=response.headers.get("content-type", default_media_type).split(";", 1)[0],
            filename=_filename_from_content_disposition(
                response.headers.get("content-disposition")
            ),
            content_length=content_length,
            response=response,
        )
