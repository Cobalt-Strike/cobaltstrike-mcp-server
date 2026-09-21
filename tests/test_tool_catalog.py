"""Offline MCP contract checks for the curated engagement tool catalog."""

from __future__ import annotations

import copy
import json
import re
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from cs_client import CobaltStrikeClient
from cs_openapi import create_openapi_client
from cs_server import CobaltStrikeMCPServer


# Keep the requested public contract independent of the implementation's sets.
REST_TOOLS = {
    "getHostCallbackInformation", "listCredentials", "listTokenStore",
    "getSyscallMethod", "listJobs", "listTasks", "getTaskById",
    "listListeners", "getListenerByName", "listRemoteExecutionCommandMethods",
    "listRemoteExecuteBeaconMethods", "listElevateCommandMethods",
    "listElevateBeaconMethods", "listScreenshots", "getScreenshot",
    "listKeyStrokes", "listDownloads", "getDownload", "getCredential",
    "getTeamserverIp", "getSystemInformation", "getC2Profile", "getKillDate",
    "listBeacons", "getBeacon", "listTaskSummariesByBid", "listTasksByBid",
    "listHostProfiles", "getKeyStrokesByBid", "listCommandHelp", "getCommandHelp",
    "listActiveDownloads", "listArtifacts", "getPayloadStoreMetadata",
    "addCredential",
}
CUSTOM_TOOLS = {
    "getDownloadedFileText", "getLiveBeaconSnapshot", "getBeaconConsoleTail",
    "lintBeaconInterpreterC", "executeBeaconConsoleAndWait", "runBeaconInterpreterC",
}
GROUPED_PATHS = {
    "getTeamserverIp": "/api/v1/config/teamserverIp",
    "getSystemInformation": "/api/v1/config/systeminformation",
    "getC2Profile": "/api/v1/config/profile",
    "getKillDate": "/api/v1/config/killdate",
    "listTasks": "/api/v1/tasks",
    "listTasksByBid": "/api/v1/beacons/{bid}/tasks/detail",
    "listTaskSummariesByBid": "/api/v1/beacons/{bid}/tasks/summary",
    "listListeners": "/api/v1/listeners",
    "getListenerByName": "/api/v1/listeners/{name}",
    "listCredentials": "/api/v1/data/credentials",
    "getCredential": "/api/v1/data/credentials/{id}",
    "listCommandHelp": "/api/v1/beacons/{bid}/help",
    "getCommandHelp": "/api/v1/beacons/{bid}/help/{command}",
    "listRemoteExecutionCommandMethods": "/api/v1/beacons/{bid}/remoteExec/command",
    "listRemoteExecuteBeaconMethods": "/api/v1/beacons/{bid}/remoteExec/beacon",
    "listElevateCommandMethods": "/api/v1/beacons/{bid}/elevate/command",
    "listElevateBeaconMethods": "/api/v1/beacons/{bid}/elevate/beacon",
    "listScreenshots": "/api/v1/data/screenshots",
    "getScreenshot": "/api/v1/data/screenshots/{id}",
    "listKeyStrokes": "/api/v1/data/keystrokes",
    "getKeyStrokesByBid": "/api/v1/beacons/{bid}/keystrokes",
}
QUERY_TOOLS = {
    "getServerConfiguration", "queryTasks", "queryListeners", "queryCredentials",
    "queryCommandHelp", "listExecutionMethods", "queryScreenshots", "queryKeyStrokes",
}
EXPECTED_TOOLS = (REST_TOOLS - GROUPED_PATHS.keys()) | CUSTOM_TOOLS | QUERY_TOOLS


def catalog_spec() -> dict:
    def operation(name: str) -> dict:
        return {
            "operationId": name,
            "responses": {"200": {"description": "Result", "content": {
                "application/json": {"schema": {"type": "string"}},
            }}},
        }

    paths = {
        f"/api/v1/fixture/{name}": {"get": operation(name)}
        for name in sorted(REST_TOOLS)
    }
    for name, path in GROUPED_PATHS.items():
        route = paths.pop(f"/api/v1/fixture/{name}")
        route["get"]["parameters"] = [{
            "name": parameter, "in": "path", "required": True,
            "schema": {"type": "string"},
        } for parameter in re.findall(r"\{(\w+)\}", path)]
        paths[path] = route
    paths[GROUPED_PATHS["getCredential"]]["get"]["parameters"][0]["schema"]["format"] = "uuid"
    paths[GROUPED_PATHS["listTasksByBid"]]["get"]["parameters"].append({
        "name": "format", "in": "query", "required": False,
        "schema": {"type": "string", "enum": ["plain", "structured"], "default": "structured"},
    })
    paths["/api/v1/fixture/addCredential"] = {
        "post": {
            **operation("addCredential"),
            "requestBody": {"required": True, "content": {"application/json": {
                "schema": {"type": "object", "properties": {
                    "realm": {"type": "string"},
                }, "required": ["realm"]},
            }}},
        },
    }
    task_operation = paths.pop("/api/v1/fixture/getTaskById")["get"]
    task_operation["parameters"] = [{
        "name": "taskId", "in": "path", "required": True,
        "schema": {"type": "string"},
    }]
    paths["/api/v1/tasks/{taskId}"] = {"get": task_operation}
    # Include new endpoints, similar names, and generated/custom name collisions.
    for name in ("executeShell", "futureEndpoint", "listBeacons__unexpected", *CUSTOM_TOOLS, *QUERY_TOOLS):
        paths[f"/api/v1/excluded/{name}"] = {"get": operation(name)}
    unnamed = operation("unused")
    del unnamed["operationId"]
    unnamed["summary"] = "listBeacons"
    paths["/api/v1/excluded/unnamed"] = {"get": unnamed}
    return {
        "openapi": "3.0.3",
        "info": {"title": "Offline catalog fixture", "version": "1.0"},
        "paths": paths,
    }


class ToolCatalogTests(unittest.IsolatedAsyncioTestCase):
    async def create_server(self, spec: dict, response_handler=None):
        self.requests = []

        def handler(request):
            self.requests.append(request)
            if response_handler:
                return response_handler(request)
            return httpx.Response(200, content=b"fixture result", headers={
                "content-type": "application/json",
            })

        raw = httpx.AsyncClient(
            base_url="https://example.test", transport=httpx.MockTransport(handler),
        )
        self.addAsyncCleanup(raw.aclose)
        owner = CobaltStrikeClient("https://example.test")
        owner._client = raw
        owner._token = "offline-token"
        wrapper = CobaltStrikeMCPServer(
            owner, websocket_streams_enabled=False, auto_start_websocket_streams=False,
        )
        self.addAsyncCleanup(wrapper.stop)
        with patch.object(owner, "fetch_openapi_spec", new=AsyncMock(return_value=spec)):
            server = await wrapper.create_server()
        return server, wrapper

    async def test_exact_catalog_preserves_prompts_resources_and_custom_helpers(self):
        spec = catalog_spec()
        original = copy.deepcopy(spec)
        server, wrapper = await self.create_server(spec)
        async with Client(server) as client:
            tools = await client.list_tools()
            self.assertEqual({tool.name for tool in tools}, EXPECTED_TOOLS)
            self.assertEqual(len(tools), 28)
            self.assertTrue(await client.list_prompts())
            resources = await client.list_resources()
            self.assertIn("cobalt-strike://health/status", {str(r.uri) for r in resources})
            by_name = {tool.name: tool for tool in tools}
            self.assertIn("bid", by_name["getBeaconConsoleTail"].inputSchema["properties"])
            self.assertIn("script", by_name["lintBeaconInterpreterC"].inputSchema["properties"])
            self.assertEqual(
                by_name["getServerConfiguration"].inputSchema["properties"]["section"]["enum"],
                ["teamserver_ip", "system_information", "c2_profile", "kill_date"],
            )
            self.assertIn("bid", by_name["listExecutionMethods"].inputSchema["required"])
            self.assertIn("bid", by_name["queryCommandHelp"].inputSchema["required"])
            for name in QUERY_TOOLS:
                self.assertTrue(by_name[name].annotations.readOnlyHint)
            with patch.object(wrapper.stream_manager, "beacons_snapshot", return_value={"beacons": []}) as snapshot:
                await client.call_tool("getLiveBeaconSnapshot")
                snapshot.assert_called_once_with()
        self.assertEqual(self.requests, [])
        self.assertEqual(spec, original)

    async def test_unlisted_tools_cannot_be_called_even_if_added_later(self):
        server, _ = await self.create_server(catalog_spec())

        @server.tool()
        def futureCustomTool() -> str:
            raise AssertionError("Unlisted custom tool must not run")

        async with Client(server) as client:
            self.assertNotIn("futureCustomTool", {tool.name for tool in await client.list_tools()})
            for name in (
                "executeShell", "futureEndpoint", "listBeacons__unexpected",
                "startCobaltStrikeWebsocketStreams", "getCobaltStrikeWebsocketStatus",
                "getRecentEventLogTail", "futureCustomTool", *GROUPED_PATHS,
            ):
                with self.subTest(name=name):
                    with self.assertRaises(ToolError):
                        await client.call_tool(name, {})
        self.assertEqual(self.requests, [])

    async def test_allowed_operations_keep_request_and_response_contracts(self):
        server, _ = await self.create_server(catalog_spec())
        async with Client(server) as client:
            profile = await client.call_tool("getServerConfiguration", {"section": "c2_profile"})
            self.assertEqual(profile.structured_content, {"result": "fixture result"})
            await client.call_tool("getTaskById", {"taskId": "offline-task"})
            await client.call_tool("addCredential", {"realm": "offline-realm"})
        self.assertEqual([(r.method, r.url.path) for r in self.requests], [
            ("GET", "/api/v1/config/profile"),
            ("GET", "/api/v1/tasks/offline-task"),
            ("POST", "/api/v1/fixture/addCredential"),
        ])
        self.assertEqual(self.requests[-1].content, b'{"realm":"offline-realm"}')

    async def test_security_and_reset_exclusions_override_allowlisted_names(self):
        spec = catalog_spec()
        spec["paths"][GROUPED_PATHS["getTeamserverIp"]]["get"]["tags"] = ["Security"]
        spec["paths"]["/api/v1/config/resetData"] = spec["paths"].pop(GROUPED_PATHS["getKillDate"])
        with self.assertLogs("cs_server", level="WARNING") as logs:
            server, _ = await self.create_server(spec)
        self.assertIn("getTeamserverIp", logs.output[0])
        self.assertIn("getKillDate", logs.output[0])
        async with Client(server) as client:
            self.assertEqual(
                {tool.name for tool in await client.list_tools()},
                EXPECTED_TOOLS,
            )
            for name in ("getTeamserverIp", "getKillDate"):
                with self.assertRaises(ToolError):
                    await client.call_tool(name)
            for section in ("teamserver_ip", "kill_date"):
                with self.assertRaisesRegex(ToolError, "unavailable"):
                    await client.call_tool("getServerConfiguration", {"section": section})
        self.assertEqual(self.requests, [])

    async def test_older_api_warns_and_publishes_only_available_operations(self):
        spec = catalog_spec()
        del spec["paths"]["/api/v1/fixture/getPayloadStoreMetadata"]
        with self.assertLogs("cs_server", level="WARNING") as logs:
            server, _ = await self.create_server(spec)
        self.assertIn("getPayloadStoreMetadata", logs.output[0])
        async with Client(server) as client:
            self.assertEqual(
                {tool.name for tool in await client.list_tools()},
                EXPECTED_TOOLS - {"getPayloadStoreMetadata"},
            )

    async def test_every_grouped_operation_matches_original_requests_and_results(self):
        cases = [
            ("getServerConfiguration", {"section": "teamserver_ip"}, "getTeamserverIp", {}),
            ("getServerConfiguration", {"section": "system_information"}, "getSystemInformation", {}),
            ("getServerConfiguration", {"section": "c2_profile"}, "getC2Profile", {}),
            ("getServerConfiguration", {"section": "kill_date"}, "getKillDate", {}),
            ("queryTasks", {}, "listTasks", {}),
            ("queryTasks", {"bid": "123"}, "listTasksByBid", {"bid": "123"}),
            ("queryTasks", {"bid": "123", "view": "summary"}, "listTaskSummariesByBid", {"bid": "123"}),
            ("queryListeners", {}, "listListeners", {}),
            ("queryListeners", {"name": "Listener A"}, "getListenerByName", {"name": "Listener A"}),
            ("queryCredentials", {}, "listCredentials", {}),
            ("queryCredentials", {"id": "00000000-0000-0000-0000-000000000001"}, "getCredential", {"id": "00000000-0000-0000-0000-000000000001"}),
            ("queryCommandHelp", {"bid": "123"}, "listCommandHelp", {"bid": "123"}),
            ("queryCommandHelp", {"bid": "123", "command": "help"}, "getCommandHelp", {"bid": "123", "command": "help"}),
            ("listExecutionMethods", {"bid": "123", "kind": "remote_command"}, "listRemoteExecutionCommandMethods", {"bid": "123"}),
            ("listExecutionMethods", {"bid": "123", "kind": "remote_beacon"}, "listRemoteExecuteBeaconMethods", {"bid": "123"}),
            ("listExecutionMethods", {"bid": "123", "kind": "elevate_command"}, "listElevateCommandMethods", {"bid": "123"}),
            ("listExecutionMethods", {"bid": "123", "kind": "elevate_beacon"}, "listElevateBeaconMethods", {"bid": "123"}),
            ("queryScreenshots", {}, "listScreenshots", {}),
            ("queryScreenshots", {"id": "offline-shot"}, "getScreenshot", {"id": "offline-shot"}),
            ("queryKeyStrokes", {}, "listKeyStrokes", {}),
            ("queryKeyStrokes", {"bid": "123"}, "getKeyStrokesByBid", {"bid": "123"}),
        ]
        self.assertEqual({case[2] for case in cases}, set(GROUPED_PATHS))
        spec = catalog_spec()
        server, wrapper = await self.create_server(spec)
        original_client = create_openapi_client(wrapper.cs_client.get_authenticated_client(), spec)
        self.addAsyncCleanup(original_client.aclose)
        original = FastMCP.from_openapi(openapi_spec=spec, client=original_client)
        async with Client(server) as client, Client(original) as baseline:
            for query, arguments, operation, original_arguments in cases:
                with self.subTest(operation=operation):
                    self.requests.clear()
                    expected = await baseline.call_tool(operation, original_arguments)
                    result = await client.call_tool(query, arguments)
                    self.assertEqual(len(self.requests), 2)
                    before, after = self.requests
                    self.assertEqual((after.method, after.url, after.content), (before.method, before.url, before.content))
                    self.assertEqual(after.url.path, GROUPED_PATHS[operation].format(**original_arguments))
                    self.assertEqual(result.structured_content, expected.structured_content)
                    self.assertEqual(result.content, expected.content)

    async def test_task_formats_are_forwarded_only_to_detailed_beacon_tasks(self):
        server, _ = await self.create_server(catalog_spec())
        async with Client(server) as client:
            for output_format in ("plain", "structured"):
                await client.call_tool("queryTasks", {"bid": "123", "format": output_format})
                self.assertEqual(self.requests[-1].url.params["format"], output_format)
                self.assertEqual(self.requests[-1].url.path, "/api/v1/beacons/123/tasks/detail")

    async def test_invalid_selectors_and_conflicting_arguments_make_no_requests(self):
        server, _ = await self.create_server(catalog_spec())
        cases = [
            ("getServerConfiguration", {}),
            ("getServerConfiguration", {"section": "resetData"}),
            ("queryTasks", {"view": "summary"}),
            ("queryTasks", {"format": "plain"}),
            ("queryTasks", {"bid": "123", "view": "summary", "format": "structured"}),
            ("queryTasks", {"bid": "123", "format": "xml"}),
            ("queryTasks", {"bid": ""}),
            ("queryListeners", {"name": " "}),
            ("queryCredentials", {"id": "invalid-uuid"}),
            ("queryCredentials", {"id": ""}),
            ("queryCommandHelp", {"command": "help"}),
            ("queryCommandHelp", {"bid": "123", "command": ""}),
            ("queryCommandHelp", {"bid": ""}),
            ("listExecutionMethods", {"kind": "remote_command"}),
            ("listExecutionMethods", {"bid": "123", "kind": "execute"}),
            ("listExecutionMethods", {"bid": "", "kind": "remote_command"}),
            ("queryScreenshots", {"id": ""}),
            ("queryKeyStrokes", {"bid": " "}),
            ("queryListeners", {"unexpected": "ignored?"}),
        ]
        async with Client(server) as client:
            for query, arguments in cases:
                with self.subTest(query=query, arguments=arguments):
                    with self.assertRaises(ToolError):
                        await client.call_tool(query, arguments)
        self.assertEqual(self.requests, [])

    async def test_missing_group_is_not_published_and_partial_group_reports_missing_mode(self):
        spec = catalog_spec()
        for operation in ("listListeners", "getListenerByName", "getC2Profile"):
            del spec["paths"][GROUPED_PATHS[operation]]
        with self.assertLogs("cs_server", level="WARNING") as logs:
            server, _ = await self.create_server(spec)
        self.assertIn("getC2Profile", logs.output[0])
        async with Client(server) as client:
            self.assertEqual({tool.name for tool in await client.list_tools()}, EXPECTED_TOOLS - {"queryListeners"})
            with self.assertRaisesRegex(ToolError, "unavailable"):
                await client.call_tool("getServerConfiguration", {"section": "c2_profile"})
            await client.call_tool("getServerConfiguration", {"section": "kill_date"})
        self.assertEqual(len(self.requests), 1)

    async def test_grouped_queries_preserve_json_content_and_upstream_errors(self):
        spec = catalog_spec()
        response_schema = spec["paths"][GROUPED_PATHS["listTasksByBid"]]["get"]["responses"]["200"]
        response_schema["content"]["application/json"]["schema"] = {"type": "array", "items": {"type": "object"}}
        body = [{"id": "offline-task", "status": "COMPLETED", "result": [{"text": "fixture"}]}]
        response = httpx.Response(200, json=body)
        server, _ = await self.create_server(spec, response_handler=lambda request: response)
        async with Client(server) as client:
            result = await client.call_tool("queryTasks", {"bid": "123"})
            self.assertEqual(result.structured_content, {"result": body})
            self.assertEqual(json.loads(result.content[0].text), {"result": body})
            response = httpx.Response(404, json={"error": "fixture missing"})
            with self.assertRaisesRegex(ToolError, "HTTP error 404"):
                await client.call_tool("queryTasks", {"bid": "123"})


if __name__ == "__main__":
    unittest.main()
