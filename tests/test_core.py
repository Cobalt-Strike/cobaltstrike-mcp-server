from __future__ import annotations

import contextlib
import base64
import io
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import httpx

if "fastmcp.server.providers.openapi" not in sys.modules:
    fastmcp_module = types.ModuleType("fastmcp")
    server_module = types.ModuleType("fastmcp.server")
    providers_module = types.ModuleType("fastmcp.server.providers")
    openapi_module = types.ModuleType("fastmcp.server.providers.openapi")

    class _FastMCP:
        pass

    class _RouteMap:
        def __init__(self, *, tags=None, pattern=None, mcp_type=None):
            self.tags = tags
            self.pattern = pattern
            self.mcp_type = mcp_type

    class _MCPType:
        EXCLUDE = "exclude"

    fastmcp_module.FastMCP = _FastMCP
    openapi_module.RouteMap = _RouteMap
    openapi_module.MCPType = _MCPType
    sys.modules.setdefault("fastmcp", fastmcp_module)
    sys.modules.setdefault("fastmcp.server", server_module)
    sys.modules.setdefault("fastmcp.server.providers", providers_module)
    sys.modules.setdefault("fastmcp.server.providers.openapi", openapi_module)

import cs_mcp
from cs_audit import audit_event, configure_audit_logging, logger as audit_logger
from cs_client import CobaltStrikeClient, ReauthenticatingAsyncClient
from cs_files import MAX_DOWNLOAD_TEXT_BYTES, _bounded_max_bytes, decode_text_payload
from cs_interpreter import (
    build_interpreter_arguments,
    build_interpreter_payload,
    lint_interpreter_c_code,
    run_interpreter_c_code,
)
from cs_resources import build_health_status
from cs_server import build_route_maps, build_run_kwargs, is_loopback_bind_host
from cs_streams import (
    CobaltStrikeWebSocketStream,
    CobaltStrikeWebSocketStreamManager,
    StreamBuffer,
    _task_is_terminal,
    _task_status_path,
    _websocket_url_from_base_url,
    parse_stomp_frame,
    validate_beacon_id,
)


class ConfigTests(unittest.TestCase):
    def test_env_bool(self) -> None:
        with patch.dict(os.environ, {"CS_TEST_BOOL": "yes"}):
            self.assertTrue(cs_mcp.env_bool("CS_TEST_BOOL", False))
        with patch.dict(os.environ, {"CS_TEST_BOOL": "off"}):
            self.assertFalse(cs_mcp.env_bool("CS_TEST_BOOL", True))

    def test_parse_env_line_handles_export_quotes_and_comments(self) -> None:
        self.assertEqual(
            cs_mcp.parse_env_line('export CS_API_USERNAME="rest client" # comment'),
            ("CS_API_USERNAME", "rest client"),
        )
        self.assertEqual(
            cs_mcp.parse_env_line("CS_API_PASSWORD='abc#123'"),
            ("CS_API_PASSWORD", "abc#123"),
        )
        self.assertIsNone(cs_mcp.parse_env_line("# comment"))

    def test_load_env_file_does_not_override_existing_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = os.path.join(temp_dir, ".env")
            with open(env_path, "w", encoding="utf-8") as handle:
                handle.write("CS_TEST_EXISTING=from_file\nCS_TEST_NEW=new_value\n")
            with patch.dict(os.environ, {"CS_TEST_EXISTING": "from_env"}, clear=False):
                os.environ.pop("CS_TEST_NEW", None)
                cs_mcp.load_env_file(env_path)
                self.assertEqual(os.environ["CS_TEST_EXISTING"], "from_env")
                self.assertEqual(os.environ["CS_TEST_NEW"], "new_value")

    def test_invalid_numeric_env_values_raise_clear_errors(self) -> None:
        with patch.dict(os.environ, {"CS_WS_BUFFER_SIZE": "not-an-int"}):
            with self.assertRaisesRegex(ValueError, "CS_WS_BUFFER_SIZE"):
                cs_mcp.env_int("CS_WS_BUFFER_SIZE", 1000)
        with patch.dict(os.environ, {"CS_WS_RECONNECT_SECONDS": "not-a-float"}):
            with self.assertRaisesRegex(ValueError, "CS_WS_RECONNECT_SECONDS"):
                cs_mcp.env_float("CS_WS_RECONNECT_SECONDS", 2.0)

    def test_show_env_redacts_secret_values(self) -> None:
        output = io.StringIO()
        with patch.dict(os.environ, {"CS_API_PASSWORD": "super-secret-value"}, clear=False):
            with contextlib.redirect_stdout(output):
                cs_mcp.show_environment_variables()
        rendered = output.getvalue()
        self.assertIn("CS_API_PASSWORD", rendered)
        self.assertIn("<redacted", rendered)
        self.assertNotIn("super-secret-value", rendered)


class FileToolTests(unittest.TestCase):
    def test_decode_text_payload_detects_text_and_binary(self) -> None:
        is_text, encoding, text = decode_text_payload(b"hello\nworld", "text/plain")
        self.assertTrue(is_text)
        self.assertIsNotNone(encoding)
        self.assertEqual(text, "hello\nworld")

        is_text, encoding, text = decode_text_payload(b"\x00\x01\x02binary", "application/octet-stream")
        self.assertFalse(is_text)
        self.assertIsNone(encoding)
        self.assertIsNone(text)

    def test_bounded_max_bytes_clamps_values(self) -> None:
        self.assertEqual(_bounded_max_bytes(0), 1)
        self.assertEqual(_bounded_max_bytes("bad"), 65_536)
        self.assertEqual(_bounded_max_bytes(MAX_DOWNLOAD_TEXT_BYTES + 1), MAX_DOWNLOAD_TEXT_BYTES)


class InterpreterPayloadTests(unittest.TestCase):
    def test_build_interpreter_payload_encodes_script_content(self) -> None:
        payload = build_interpreter_payload(script="int go() { return 0; }\n")

        self.assertEqual(payload["script"], "@files/script.c")
        self.assertEqual(
            base64.b64decode(payload["files"]["script.c"]).decode("utf-8"),
            "int go() { return 0; }\n",
        )

    def test_build_interpreter_payload_accepts_base64_script_and_extra_files(self) -> None:
        script_b64 = base64.b64encode(b"int go() { return helper(); }").decode("ascii")
        header_b64 = base64.b64encode(b"int helper(void);").decode("ascii")

        payload = build_interpreter_payload(
            script=script_b64,
            script_is_base64=True,
            script_file_name="main.c",
            files={"helper.h": header_b64},
            files_are_base64=True,
        )

        self.assertEqual(payload["script"], "@files/main.c")
        self.assertEqual(payload["files"]["main.c"], script_b64)
        self.assertEqual(payload["files"]["helper.h"], header_b64)

    def test_build_interpreter_arguments_formats_typed_values(self) -> None:
        arguments = build_interpreter_arguments(
            [
                {"value": "aGVsbG8A", "type": "binary"},
                {"value": 42, "type": "int"},
                {"value": 7, "type": "short"},
                {"value": 'he"llo', "type": "str"},
                {"value": "wide\\path", "type": "wideStr"},
            ]
        )

        self.assertEqual(arguments, '"biszZ" "aGVsbG8A" 42 7 "he\\"llo" "wide\\\\path"')

    def test_build_interpreter_arguments_matches_echo_example(self) -> None:
        arguments = build_interpreter_arguments(
            [
                {"value": "hello", "type": "str"},
                {"value": 42, "type": "int"},
            ]
        )

        self.assertEqual(arguments, '"zi" "hello" 42')

    def test_build_interpreter_arguments_rejects_bad_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "valid base64"):
            build_interpreter_arguments([{"value": "not base64!", "type": "binary"}])
        with self.assertRaisesRegex(ValueError, "between"):
            build_interpreter_arguments([{"value": 32768, "type": "short"}])
        with self.assertRaisesRegex(ValueError, "unsupported"):
            build_interpreter_arguments([{"value": "x", "type": "float"}])


class InterpreterRequestTests(unittest.IsolatedAsyncioTestCase):
    async def test_lint_interpreter_c_code_posts_lint_payload(self) -> None:
        cs_client = _FakeCobaltStrikeClient([{"ok": True, "data": {"lint": "ok"}}])

        result = await lint_interpreter_c_code(
            cs_client,
            bid="abc123",
            script="int go() { return 0; }",
        )

        self.assertTrue(result["ok"])
        self.assertEqual(cs_client.requests, [("POST", "/api/v1/beacons/abc123/execute/interpreter/lint")])
        payload = cs_client.request_kwargs[0]["json"]
        self.assertEqual(payload["script"], "@files/script.c")
        self.assertEqual(
            base64.b64decode(payload["files"]["script.c"]).decode("utf-8"),
            "int go() { return 0; }",
        )

    async def test_run_interpreter_c_code_posts_execution_payload_with_arguments(self) -> None:
        cs_client = _FakeCobaltStrikeClient([{"ok": True, "data": {"taskId": "task-1"}}])

        result = await run_interpreter_c_code(
            cs_client,
            bid="abc:123",
            script="int go() { return 0; }",
            arguments=[
                {"value": "hello", "type": "str"},
                {"value": 42, "type": "int"},
            ],
        )

        self.assertTrue(result["ok"])
        self.assertEqual(cs_client.requests, [("POST", "/api/v1/beacons/abc%3A123/execute/interpreter")])
        payload = cs_client.request_kwargs[0]["json"]
        self.assertEqual(payload["arguments"], '"zi" "hello" 42')

    async def test_run_interpreter_c_code_returns_validation_error_without_request(self) -> None:
        cs_client = _FakeCobaltStrikeClient([])

        result = await run_interpreter_c_code(
            cs_client,
            bid="../bad",
            script="int go() { return 0; }",
        )

        self.assertFalse(result["ok"])
        self.assertIn("invalid", result["exception"])
        self.assertEqual(cs_client.requests, [])


class ServerPolicyTests(unittest.TestCase):
    def test_loopback_bind_detection(self) -> None:
        self.assertTrue(is_loopback_bind_host("127.0.0.1"))
        self.assertTrue(is_loopback_bind_host("::1"))
        self.assertTrue(is_loopback_bind_host("localhost"))
        self.assertFalse(is_loopback_bind_host("0.0.0.0"))

    def test_remote_bind_requires_explicit_allow(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-loopback"):
            build_run_kwargs(
                transport="http",
                host="0.0.0.0",
                port=3000,
                path="/mcp",
            )
        kwargs = build_run_kwargs(
            transport="http",
            host="0.0.0.0",
            port=3000,
            path="/mcp",
            allow_remote_bind=True,
            external_auth=True,
        )
        self.assertEqual(kwargs["host"], "0.0.0.0")

    def test_remote_bind_requires_external_auth_confirmation(self) -> None:
        with self.assertRaisesRegex(ValueError, "external auth"):
            build_run_kwargs(
                transport="http",
                host="0.0.0.0",
                port=3000,
                path="/mcp",
                allow_remote_bind=True,
            )

    def test_unknown_transport_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unsupported MCP transport"):
            build_run_kwargs(
                transport="typo",
                host="127.0.0.1",
                port=3000,
                path="/mcp",
            )

    def test_route_policy_builds_exclusions(self) -> None:
        route_maps = build_route_maps()
        self.assertEqual(len(route_maps), 2)
        self.assertEqual(route_maps[0].tags, {"Security"})
        self.assertIn("resetData", route_maps[1].pattern)


class StreamParsingTests(unittest.TestCase):
    def test_parse_stomp_frame(self) -> None:
        frame = parse_stomp_frame('MESSAGE\ndestination:/topic\n\n{"x": 1}\x00')
        self.assertEqual(frame["command"], "MESSAGE")
        self.assertEqual(frame["headers"]["destination"], "/topic")
        self.assertEqual(frame["body"], {"x": 1})

    def test_websocket_url_from_base_url(self) -> None:
        ws_url, host = _websocket_url_from_base_url("https://teamserver.local:50443")
        self.assertEqual(ws_url, "wss://teamserver.local:50443/connect")
        self.assertEqual(host, "teamserver.local")

    def test_task_status_path_and_terminal_status(self) -> None:
        self.assertEqual(_task_status_path({"statusUrl": "/api/v1/tasks/1"}), "/api/v1/tasks/1")
        self.assertEqual(_task_status_path({"taskId": "abc"}), "/api/v1/tasks/abc")
        self.assertTrue(_task_is_terminal({"status": "COMPLETED"}))
        self.assertFalse(_task_is_terminal({"status": "RUNNING"}))

    def test_stream_buffer_reports_gaps(self) -> None:
        buffer = StreamBuffer(maxlen=3)
        for value in range(5):
            buffer.append(f"line-{value}")

        result = buffer.result_since(0)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["dropped_entries"], 2)
        self.assertEqual(result["first_retained_sequence"], 3)
        self.assertEqual([entry["sequence"] for entry in result["entries"]], [3, 4, 5])

    def test_beacon_id_validation(self) -> None:
        self.assertEqual(validate_beacon_id(" abc-123.DEF:4 "), "abc-123.DEF:4")
        for invalid in ("", "../bad", "abc/def", "abc\ndef", "a" * 129):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    validate_beacon_id(invalid)

    def test_websocket_connect_uses_current_token_provider_value(self) -> None:
        sent: list[str] = []
        stream = CobaltStrikeWebSocketStream(
            ws_url="wss://teamserver.local:50443/connect",
            host="teamserver.local",
            token_provider=lambda: "fresh-token",
            destination="/subscribe/eventlog",
            verify_tls=True,
            reconnect_seconds=0.1,
            on_payload=lambda _body: None,
        )

        stream._on_open(_FakeWebSocket(sent))  # pylint: disable=protected-access

        self.assertIn("Authorization:Bearer fresh-token", sent[0])

    def test_websocket_auth_error_refreshes_token_and_closes_socket(self) -> None:
        refreshed = []
        sent: list[str] = []
        ws = _FakeWebSocket(sent)
        stream = CobaltStrikeWebSocketStream(
            ws_url="wss://teamserver.local:50443/connect",
            host="teamserver.local",
            token_provider=lambda: "expired-token",
            token_refresh=lambda: refreshed.append(True) or True,
            destination="/subscribe/eventlog",
            verify_tls=True,
            reconnect_seconds=0.1,
            on_payload=lambda _body: None,
        )

        stream._on_message(ws, "ERROR\n\n{\"message\": \"401 unauthorized\"}\x00")  # pylint: disable=protected-access

        self.assertEqual(refreshed, [True])
        self.assertTrue(ws.closed)


class StreamFallbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_execute_console_and_wait_rest_only_when_websockets_disabled(self) -> None:
        cs_client = _FakeCobaltStrikeClient(
            [
                {
                    "ok": True,
                    "data": {
                        "bid": "abc123",
                        "sleep": {"sleep": 0, "jitter": 0},
                    },
                },
                {
                    "ok": True,
                    "data": {
                        "taskId": "task-1",
                        "statusUrl": "/api/v1/tasks/task-1",
                        "status": "RUNNING",
                    },
                },
                {
                    "ok": True,
                    "data": {
                        "taskId": "task-1",
                        "status": "COMPLETED",
                    },
                },
            ]
        )
        manager = CobaltStrikeWebSocketStreamManager(cs_client, enabled=False)

        result = await manager.execute_console_and_wait(
            bid="abc123",
            command_line="pwd",
            timeout_seconds=1.0,
            quiet_seconds=0.1,
        )

        self.assertTrue(result["task_completed"])
        self.assertEqual(result["output_source"], "rest_task_poll")
        self.assertEqual(result["output"], [])
        self.assertIn("disabled", result["output_unavailable_reason"])
        self.assertEqual(
            cs_client.requests,
            [
                ("GET", "/api/v1/beacons/abc123"),
                ("POST", "/api/v1/beacons/abc123/consoleCommand"),
                ("GET", "/api/v1/tasks/task-1"),
            ],
        )

    def test_disabled_manager_reports_stream_tools_unavailable(self) -> None:
        manager = CobaltStrikeWebSocketStreamManager(_FakeCobaltStrikeClient([]), enabled=False)
        self.assertFalse(manager.status()["enabled"])
        result = manager.eventlog_tail(10)
        self.assertEqual(result["entries"], [])
        self.assertIn("disabled", result["error"])


class HttpHelperTests(unittest.IsolatedAsyncioTestCase):
    async def test_request_json_normalizes_unauthenticated_error(self) -> None:
        client = CobaltStrikeClient("https://localhost:50443")
        result = await client.request_json("GET", "/api/v1/beacons")
        self.assertFalse(result["ok"])
        self.assertIn("Not authenticated", result["exception"])

    async def test_request_json_normalizes_success_and_error(self) -> None:
        client = CobaltStrikeClient("https://localhost:50443")
        client._token = "token"  # pylint: disable=protected-access
        client._client = _FakeHttpClient(  # pylint: disable=protected-access
            [
                _FakeResponse(200, {"value": 1}),
                _FakeResponse(500, {"error": "boom"}, text="boom"),
            ]
        )

        ok = await client.request_json("GET", "/ok")
        self.assertTrue(ok["ok"])
        self.assertEqual(ok["data"], {"value": 1})

        error = await client.request_json("GET", "/error")
        self.assertFalse(error["ok"])
        self.assertEqual(error["status_code"], 500)

    async def test_request_json_refreshes_token_once_on_401(self) -> None:
        client = _RefreshableCobaltStrikeClient("https://localhost:50443")
        client._token = "expired-token"  # pylint: disable=protected-access
        client._auth_context = object()  # pylint: disable=protected-access
        client._client = _FakeHttpClient(  # pylint: disable=protected-access
            [_FakeResponse(401, {"error": "expired"}, text="expired")]
        )
        client.refreshed_client = _FakeHttpClient([_FakeResponse(200, {"value": "ok"})])

        result = await client.request_json("GET", "/api/v1/beacons")

        self.assertTrue(result["ok"])
        self.assertEqual(result["data"], {"value": "ok"})
        self.assertTrue(client.refresh_called)

    async def test_authenticated_http_client_retries_after_token_refresh(self) -> None:
        seen_authorization: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_authorization.append(request.headers.get("authorization"))
            if len(seen_authorization) == 1:
                return httpx.Response(401, json={"error": "expired"})
            return httpx.Response(200, json={"value": "ok"})

        owner = _RawClientRefreshOwner()
        client = ReauthenticatingAsyncClient(
            owner,
            base_url="https://localhost:50443",
            headers={"Authorization": "Bearer expired-token"},
            transport=httpx.MockTransport(handler),
        )
        owner.client = client

        response = await client.get("/api/v1/beacons")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"value": "ok"})
        self.assertEqual(seen_authorization, ["Bearer expired-token", "Bearer fresh-token"])
        self.assertTrue(owner.refresh_called)
        await client.aclose()


class HealthStatusTests(unittest.IsolatedAsyncioTestCase):
    async def test_build_health_status_uses_mocked_api_response(self) -> None:
        cs_client = _FakeCobaltStrikeClient(
            [
                {
                    "ok": True,
                    "endpoint": "/api/v1/config/localip",
                    "status_code": 200,
                    "text": "10.0.0.1",
                }
            ]
        )
        manager = CobaltStrikeWebSocketStreamManager(cs_client, enabled=False)

        result = await build_health_status(cs_client, manager)

        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["cobalt_strike_api"]["ok"])
        self.assertFalse(result["websocket_streams"]["enabled"])
        self.assertNotIn("10.0.0.1", str(result["cobalt_strike_api"]))


class AuditTests(unittest.TestCase):
    def tearDown(self) -> None:
        for handler in list(audit_logger.handlers):
            handler.close()
            audit_logger.removeHandler(handler)
        audit_logger.propagate = True

    def test_audit_event_logs_sanitized_metadata(self) -> None:
        with patch.dict(os.environ, {"MCP_OPERATOR_ID": "operator-1"}):
            with self.assertLogs("cs_mcp.audit", level="INFO") as captured:
                audit_event(
                    "tool_invocation",
                    tool_name="executeBeaconConsoleAndWait",
                    beacon_id="abc123",
                    task_id="task-1",
                    status="completed",
                    details={"output_source": "rest_task_poll"},
                )
        rendered = "\n".join(captured.output)
        self.assertIn("operator-1", rendered)
        self.assertIn("executeBeaconConsoleAndWait", rendered)
        self.assertNotIn("password", rendered.lower())

    def test_configure_audit_logging_writes_jsonl_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_path = os.path.join(temp_dir, "audit.log")
            configure_audit_logging(audit_path)
            audit_event(
                "tool_invocation",
                tool_name="getCobaltStrikeWebsocketStatus",
                status="completed",
            )
            for handler in list(audit_logger.handlers):
                handler.flush()

            with open(audit_path, "r", encoding="utf-8") as handle:
                lines = handle.readlines()

            for handler in list(audit_logger.handlers):
                handler.close()
                audit_logger.removeHandler(handler)
            audit_logger.propagate = True

        self.assertEqual(len(lines), 1)
        self.assertIn('"action": "tool_invocation"', lines[0])
        self.assertIn('"tool_name": "getCobaltStrikeWebsocketStatus"', lines[0])


class _FakeResponse:
    def __init__(self, status_code: int, data, text: str | None = None) -> None:
        self.status_code = status_code
        self._data = data
        self.text = text if text is not None else str(data)

    def json(self):
        return self._data


class _FakeHttpClient:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self._responses = responses

    async def request(self, _method: str, _path: str, **_kwargs):
        return self._responses.pop(0)


class _RefreshableCobaltStrikeClient(CobaltStrikeClient):
    def __init__(self, base_url: str) -> None:
        super().__init__(base_url)
        self.refresh_called = False
        self.refreshed_client = None

    async def _reauthenticate(self) -> bool:
        self.refresh_called = True
        self._client = self.refreshed_client  # pylint: disable=protected-access
        return True


class _RawClientRefreshOwner:
    def __init__(self) -> None:
        self.client = None
        self.refresh_called = False

    async def _reauthenticate(self) -> bool:
        self.refresh_called = True
        self.client.headers["Authorization"] = "Bearer fresh-token"
        return True


class _FakeWebSocket:
    def __init__(self, sent: list[str]) -> None:
        self.sent = sent
        self.closed = False

    def send(self, value: str) -> None:
        self.sent.append(value)

    def close(self) -> None:
        self.closed = True


class _FakeCobaltStrikeClient:
    def __init__(self, responses: list[dict]) -> None:
        self.base_url = "https://localhost:50443"
        self.verify_tls = True
        self.access_token = "token"
        self._responses = responses
        self.requests: list[tuple[str, str]] = []
        self.request_kwargs: list[dict] = []

    async def request_json(self, method: str, path: str, **kwargs):
        self.requests.append((method, path))
        self.request_kwargs.append(kwargs)
        return self._responses.pop(0)

    async def request_text(self, method: str, path: str, **kwargs):
        self.requests.append((method, path))
        self.request_kwargs.append(kwargs)
        return self._responses.pop(0)


if __name__ == "__main__":
    unittest.main()
