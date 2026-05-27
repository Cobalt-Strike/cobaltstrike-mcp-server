from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

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
from cs_client import CobaltStrikeClient
from cs_files import MAX_DOWNLOAD_TEXT_BYTES, _bounded_max_bytes, decode_text_payload
from cs_server import build_route_maps, build_run_kwargs, is_loopback_bind_host
from cs_streams import (
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
        )
        self.assertEqual(kwargs["host"], "0.0.0.0")

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


class _FakeCobaltStrikeClient:
    def __init__(self, responses: list[dict]) -> None:
        self.base_url = "https://localhost:50443"
        self.verify_tls = True
        self.access_token = "token"
        self._responses = responses
        self.requests: list[tuple[str, str]] = []

    async def request_json(self, method: str, path: str, **_kwargs):
        self.requests.append((method, path))
        return self._responses.pop(0)


if __name__ == "__main__":
    unittest.main()
