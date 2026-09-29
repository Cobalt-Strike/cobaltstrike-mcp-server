"""Wire-level regressions for custom results; no Team Server connections."""

import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastmcp import Client, FastMCP

from cs_client import CobaltStrikeClient
from cs_files import add_cobalt_strike_file_tools
from cs_interpreter import add_cobalt_strike_interpreter_tools
from cs_server import CUSTOM_TOOL_NAMES
from cs_streams import CobaltStrikeWebSocketStreamManager, add_cobalt_strike_stream_tools


class CustomResultTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []
        self.response = httpx.Response(200, json={"taskId": "fixture-task", "status": "QUEUED"})

        def handler(request):
            self.requests.append(request)
            if isinstance(self.response, Exception):
                raise self.response
            return self.response

        self.owner = CobaltStrikeClient("https://example.test")
        self.owner._token = "fixture-token"
        self.owner._client = httpx.AsyncClient(
            base_url="https://example.test", transport=httpx.MockTransport(handler),
        )
        self.addAsyncCleanup(self.owner.close)
        self.streams = CobaltStrikeWebSocketStreamManager(self.owner, enabled=False)
        self.server = FastMCP("Custom result contracts")
        add_cobalt_strike_file_tools(self.server, self.owner)
        add_cobalt_strike_interpreter_tools(self.server, self.owner)
        add_cobalt_strike_stream_tools(self.server, self.streams)
        self.client = await self.enterAsyncContext(Client(self.server))

    async def call(self, name, arguments):
        result = await self.client.call_tool(name, arguments, raise_on_error=False)
        self.assertIsInstance(result.structured_content, dict)
        self.assertEqual(json.loads(result.content[0].text), result.structured_content)
        return result, result.structured_content

    async def test_custom_tools_publish_object_output_schemas(self):
        tools = {tool.name: tool for tool in await self.client.list_tools()}
        for name in CUSTOM_TOOL_NAMES:
            with self.subTest(name=name):
                schema = tools[name].outputSchema
                self.assertEqual(schema["type"], "object")
                self.assertNotIn("x-fastmcp-wrap-result", schema)
                self.assertNotIn("result", schema.get("required", []))

    async def test_all_custom_successes_return_objects_without_string_wrapping(self):
        fixtures = [
            ("getDownloadedFileText", {"file_id": "fixture-file"}, "cs_files.fetch_downloaded_file_text",
             {"file_id": "fixture-file", "text": "fixture text", "content_is_untrusted": True}),
            ("lintBeaconInterpreterC", {"bid": "123", "script": "fixture"}, "cs_interpreter.lint_interpreter_c_code",
             {"ok": True, "data": {"valid": True}}),
            ("runBeaconInterpreterC", {"bid": "123", "script": "fixture"}, "cs_interpreter.run_interpreter_c_code",
             {"ok": True, "data": {"taskId": "fixture-task", "status": "QUEUED"}}),
        ]
        for name, args, target, payload in fixtures:
            with self.subTest(name=name), patch(target, new=AsyncMock(return_value=payload)):
                result, body = await self.call(name, args)
                self.assertFalse(result.is_error)
                self.assertEqual(body, payload)
        for name, args, method, payload in [
            ("getLiveBeaconSnapshot", {}, "beacons_snapshot", {"payload": [], "updated_at": None}),
            ("getBeaconConsoleTail", {"bid": "123"}, "beaconlog_tail", {"entries": []}),
            ("executeBeaconConsoleAndWait", {"bid": "123", "command_line": "fixture"}, "execute_console_and_wait",
             {"task_id": "fixture-task", "task_submitted": True, "task_terminal": True,
              "task_completed": True, "task_status": "COMPLETED", "output_empty": True, "output": []}),
        ]:
            replacement = AsyncMock(return_value=payload) if name == "executeBeaconConsoleAndWait" else None
            with self.subTest(name=name), patch.object(self.streams, method, **(
                {"new": replacement} if replacement else {"return_value": payload}
            )):
                result, body = await self.call(name, args)
                self.assertFalse(result.is_error)
                self.assertEqual(body, payload)

    async def test_invalid_inputs_and_disabled_streams_are_actionable_errors(self):
        for name, args, code in [
            ("getDownloadedFileText", {"file_id": ""}, "invalid_arguments"),
            ("lintBeaconInterpreterC", {"bid": "123", "script": ""}, "invalid_arguments"),
            ("runBeaconInterpreterC", {"bid": "123", "script": ""}, "invalid_arguments"),
            ("getBeaconConsoleTail", {"bid": "bad/id"}, "invalid_arguments"),
            ("getLiveBeaconSnapshot", {}, "feature_unavailable"),
            ("executeBeaconConsoleAndWait", {"bid": "123", "command_line": ""}, "invalid_arguments"),
        ]:
            with self.subTest(name=name):
                result, body = await self.call(name, args)
                self.assertTrue(result.is_error)
                self.assertEqual(body["error_code"], code)
                self.assertTrue(body["resolution"])
        self.assertEqual(self.requests, [])

    async def test_metadata_only_and_target_error_words_are_successful_data(self):
        payload = {"file_id": "fixture-file", "is_text": False, "text": None,
                   "message": "Unsupported document", "extraction_error": "parser timeout"}
        with patch("cs_files.fetch_downloaded_file_text", new=AsyncMock(return_value=payload)):
            result, body = await self.call("getDownloadedFileText", {"file_id": "fixture-file"})
        self.assertFalse(result.is_error)
        self.assertEqual(body, payload)
        self.response = httpx.Response(200, json={"error": "target data: timeout, HTTP 401"})
        result, body = await self.call("lintBeaconInterpreterC", {"bid": "123", "script": "fixture"})
        self.assertFalse(result.is_error)
        self.assertEqual(body["data"]["error"], "target data: timeout, HTTP 401")

    async def test_http_error_does_not_expose_upstream_body(self):
        for status in (400, 401, 403, 404, 500):
            for name, args in [
                ("getDownloadedFileText", {"file_id": "fixture-file"}),
                ("lintBeaconInterpreterC", {"bid": "123", "script": "fixture"}),
                ("runBeaconInterpreterC", {"bid": "123", "script": "fixture"}),
                ("executeBeaconConsoleAndWait", {"bid": "123", "command_line": "fixture"}),
            ]:
                with self.subTest(status=status, name=name):
                    self.response = httpx.Response(status, json={"name": "SECRET-CANARY", "message": "SECRET-CANARY"})
                    result, body = await self.call(name, args)
                    self.assertTrue(result.is_error)
                    self.assertEqual(body["status_code"], status)
                    self.assertEqual(body["error_stage"], "upstream")
                    self.assertTrue(body["resolution"])
                    self.assertNotIn("SECRET-CANARY", json.dumps(body))
                    self.assertNotIn("exception", body)

    async def test_terminal_failure_retains_evidence_and_partial_wait_is_not_failure(self):
        payload = {"task_id": "fixture-task", "task_submitted": True, "task_terminal": True,
                   "task_completed": False, "task_status": "FAILED", "task_errors": ["fixture failure"],
                   "output": ["partial observation"], "content_is_untrusted": True,
                   "untrusted_content_fields": ["output", "task_errors"],
                   "wait_profile": {"requested_timeout_seconds": 60}}
        with patch.object(self.streams, "execute_console_and_wait", new=AsyncMock(return_value=payload)):
            result, body = await self.call("executeBeaconConsoleAndWait", {"bid": "123", "command_line": "fixture"})
        self.assertTrue(result.is_error)
        self.assertEqual(body["error_code"], "task_failed")
        self.assertEqual(body["error_stage"], "task")
        for key, value in payload.items():
            self.assertEqual(body[key], value)
        payload.update(task_terminal=False, task_status="OUTPUT_RECEIVED", task_errors=[], timed_out=True, output_partial=True)
        with patch.object(self.streams, "execute_console_and_wait", new=AsyncMock(return_value=payload)):
            result, body = await self.call("executeBeaconConsoleAndWait", {"bid": "123", "command_line": "fixture"})
        self.assertFalse(result.is_error)
        self.assertEqual(body, payload)

    async def test_uncertain_submission_is_not_replayed_or_reported_rejected(self):
        for response in (httpx.ReadTimeout("SECRET-CANARY-transport"), httpx.Response(200, text="SECRET-CANARY-invalid-json")):
            self.response = response
            for name, args in [
                ("runBeaconInterpreterC", {"bid": "123", "script": "fixture"}),
                ("executeBeaconConsoleAndWait", {"bid": "123", "command_line": "fixture"}),
            ]:
                self.requests.clear()
                with self.subTest(name=name, response=type(response).__name__):
                    result, body = await self.call(name, args)
                    self.assertTrue(result.is_error)
                    self.assertEqual(body["error_code"], "submission_uncertain")
                    self.assertIsNone(body["task_submitted"])
                    self.assertEqual(body["submission_state"], "unknown")
                    self.assertNotIn("SECRET-CANARY", json.dumps(body))
                    self.assertEqual(sum(r.method == "POST" for r in self.requests), 1)


if __name__ == "__main__":
    unittest.main()
