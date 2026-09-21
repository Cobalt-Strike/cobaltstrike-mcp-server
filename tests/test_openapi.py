"""Offline HTTP and MCP contract checks for OpenAPI response normalization."""

from __future__ import annotations

import gzip
import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from cs_client import AuthContext, CobaltStrikeClient, ReauthenticatingAsyncClient
from cs_openapi import create_openapi_client


def _spec(schema: dict, *, path: str = "/api/v1/config/value") -> dict:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Offline contract fixture", "version": "1.0"},
        "paths": {
            path: {
                "get": {
                    "operationId": "getValue",
                    "responses": {
                        "200": {
                            "description": "Value",
                            "content": {"application/json": {"schema": schema}},
                        }
                    },
                }
            }
        },
    }


class OpenAPIResponseTests(unittest.IsolatedAsyncioTestCase):
    def _clients(self, handler, spec, **kwargs):
        raw = httpx.AsyncClient(
            base_url="https://example.test", transport=httpx.MockTransport(handler), **kwargs
        )
        adapter = create_openapi_client(raw, spec)
        self.addAsyncCleanup(raw.aclose)
        self.addAsyncCleanup(adapter.aclose)
        return raw, adapter

    async def test_string_responses_satisfy_advertised_mcp_schema(self) -> None:
        body = b""

        def handler(request):
            return httpx.Response(200, content=body, headers={"content-type": "application/json"})

        spec = _spec({"type": "string"})
        _, adapter = self._clients(handler, spec)
        server = FastMCP.from_openapi(openapi_spec=spec, client=adapter)
        cases = [
            (b'set sample_name "example";\n', 'set sample_name "example";\n'),
            (b'"already a JSON string\\n"', "already a JSON string\n"),
            (b"20260921", "20260921"),
            (b"1.5", "1.5"),
            (b"true", "true"),
            (b"false", "false"),
            (b"null", "null"),
            ("  café 漢字 🙂\r\n".encode(), "  café 漢字 🙂\r\n"),
            (b"", ""),
        ]
        async with Client(server) as client:
            tool, = await client.list_tools()
            self.assertEqual(tool.outputSchema["type"], "object")
            self.assertEqual(tool.outputSchema["properties"]["result"]["type"], "string")
            self.assertIn("result", tool.outputSchema["required"])
            for body, expected in cases:
                with self.subTest(body=body):
                    result = await client.call_tool("getValue")
                    self.assertFalse(result.is_error)
                    self.assertEqual(result.structured_content, {"result": expected})

    async def test_valid_json_string_keeps_original_http_body(self) -> None:
        body = b'  "caf\\u00e9\\n"  '
        _, adapter = self._clients(
            lambda request: httpx.Response(200, content=body, headers={"content-type": "application/json"}),
            _spec({"type": "string"}),
        )
        response = await adapter.get("/api/v1/config/value")
        self.assertEqual(response.content, body)
        self.assertEqual(response.json(), "café\n")

    async def test_object_and_array_responses_keep_their_mcp_contracts(self) -> None:
        cases = [
            ({"type": "object", "properties": {"name": {"type": "string"}}}, {"name": "sample"}, {"name": "sample"}),
            ({"type": "array", "items": {"type": "string"}}, ["first", "second"], {"result": ["first", "second"]}),
        ]
        for schema, value, expected in cases:
            with self.subTest(schema=schema):
                body = json.dumps(value).encode()
                spec = _spec(schema)
                _, adapter = self._clients(
                    lambda request: httpx.Response(200, content=body, headers={"content-type": "application/json"}),
                    spec,
                )
                self.assertEqual((await adapter.get("/api/v1/config/value")).content, body)
                server = FastMCP.from_openapi(openapi_spec=spec, client=adapter)
                async with Client(server) as client:
                    result = await client.call_tool("getValue")
                    self.assertEqual(result.structured_content, expected)

    async def test_http_errors_and_no_content_are_not_normalized(self) -> None:
        status, body = 500, b"upstream failure"

        def handler(request):
            return httpx.Response(status, content=body, headers={"content-type": "application/json"})

        spec = _spec({"type": "string"})
        _, adapter = self._clients(handler, spec)
        server = FastMCP.from_openapi(openapi_spec=spec, client=adapter)
        async with Client(server) as client:
            with self.assertLogs("fastmcp", level="ERROR"):
                result = await client.call_tool("getValue", raise_on_error=False)
            self.assertTrue(result.is_error)
            self.assertIn("500", result.content[0].text)
            self.assertIn("upstream failure", result.content[0].text)
        for status, body in [(401, b"expired"), (403, b"forbidden"), (500, b"failed"), (204, b"")]:
            with self.subTest(status=status):
                response = await adapter.get("/api/v1/config/value")
                self.assertEqual(response.status_code, status)
                self.assertEqual(response.content, body)

    async def test_binary_responses_are_passed_through_without_text_decoding(self) -> None:
        body = b"\xff\x00\x80\xfe"
        cases = [
            ({"type": "string", "format": "byte"}, "application/json"),
            ({"type": "string", "format": "binary"}, "application/json"),
            ({"type": "string"}, "application/octet-stream"),
        ]
        for schema, media_type in cases:
            with self.subTest(schema=schema, media_type=media_type):
                _, adapter = self._clients(
                    lambda request: httpx.Response(200, content=body, headers={"content-type": media_type}),
                    _spec(schema),
                )
                response = await adapter.get("/api/v1/config/value")
                self.assertEqual(response.content, body)
                self.assertEqual(response.headers["content-type"], media_type)

    async def test_nullable_and_composed_schemas_are_not_reinterpreted(self) -> None:
        schemas = [
            {"type": "string", "nullable": True},
            {"type": ["string", "null"]},
            {"type": "string", "anyOf": [{"type": "string"}, {"type": "null"}]},
            {"type": "string", "contentEncoding": "base64"},
            {"type": "integer"},
        ]
        for schema in schemas:
            with self.subTest(schema=schema):
                _, adapter = self._clients(
                    lambda request: httpx.Response(200, content=b"null", headers={"content-type": "application/json"}),
                    _spec(schema),
                )
                self.assertEqual((await adapter.get("/api/v1/config/value")).content, b"null")

    async def test_binary_stream_is_not_eagerly_consumed(self) -> None:
        class BinaryStream(httpx.AsyncByteStream):
            started = False
            closed = False

            async def __aiter__(self):
                self.started = True
                yield b"\xff\x00"
                yield b"\x80\xfe"

            async def aclose(self):
                self.closed = True

        stream = BinaryStream()
        _, adapter = self._clients(
            lambda request: httpx.Response(200, stream=stream, headers={"content-type": "application/octet-stream"}),
            _spec({"type": "string"}),
        )
        async with adapter.stream("GET", "/api/v1/config/value") as response:
            self.assertFalse(stream.started)
            self.assertEqual(await response.aread(), b"\xff\x00\x80\xfe")
        self.assertTrue(stream.closed)

    async def test_object_and_array_mismatches_remain_visible_to_mcp_clients(self) -> None:
        value = {}

        def handler(request):
            return httpx.Response(200, json=value)

        spec = _spec({"type": "string"})
        _, adapter = self._clients(handler, spec)
        server = FastMCP.from_openapi(openapi_spec=spec, client=adapter)
        async with Client(server) as client:
            for value in ({"unexpected": "object"}, ["unexpected", "array"]):
                with self.subTest(value=value):
                    self.assertEqual((await adapter.get("/api/v1/config/value")).json(), value)
                    with self.assertRaisesRegex(ToolError, "Output validation error"):
                        await client.call_tool("getValue")

    async def test_concrete_route_and_operation_determine_response_schema(self) -> None:
        spec = _spec({"type": "string"}, path="/api/v1/config/{name}")
        spec["paths"]["/api/v1/config/status"] = _spec({"type": "boolean"})["paths"]["/api/v1/config/value"]
        _, adapter = self._clients(
            lambda request: httpx.Response(200, content=b"true", headers={"content-type": "application/json"}),
            spec,
        )
        for method, path, expected in [
            ("GET", "/api/v1/config/profile", "true"),
            ("GET", "/api/v1/config/status", True),
            ("POST", "/api/v1/config/profile", True),
            ("GET", "/api/v1/unknown", True),
        ]:
            with self.subTest(method=method, path=path):
                self.assertEqual((await adapter.request(method, path)).json(), expected)

    async def test_compressed_text_is_normalized_with_consistent_headers(self) -> None:
        text = "profile café\n"
        body = gzip.compress(text.encode())
        _, adapter = self._clients(
            lambda request: httpx.Response(200, content=body, headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
                "content-length": str(len(body)),
                "etag": '"original-body"',
            }),
            _spec({"type": "string"}),
        )
        response = await adapter.get("/api/v1/config/value")
        self.assertEqual(response.json(), text)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(int(response.headers["content-length"]), len(response.content))
        self.assertNotIn("content-encoding", response.headers)
        self.assertNotIn("etag", response.headers)

    async def test_response_and_schema_references_on_templated_paths(self) -> None:
        path = "/api/v1/config/{name}"
        spec = _spec({"$ref": "#/components/schemas/TextValue"}, path=path)
        operation = spec["paths"][path]["get"]
        operation["parameters"] = [{"name": "name", "in": "path", "required": True, "schema": {"type": "string"}}]
        response = operation["responses"]["200"]
        operation["responses"]["200"] = {"$ref": "#/components/responses/TextResponse"}
        spec["components"] = {
            "schemas": {"TextValue": {"type": "string"}},
            "responses": {"TextResponse": response},
        }
        seen = []

        def handler(request):
            seen.append(request.url.path)
            return httpx.Response(200, content=b"profile text", headers={"content-type": "application/json"})

        _, adapter = self._clients(handler, spec)
        server = FastMCP.from_openapi(openapi_spec=spec, client=adapter)
        async with Client(server) as client:
            result = await client.call_tool("getValue", {"name": "profile"})
            self.assertEqual(result.structured_content, {"result": "profile text"})
        self.assertEqual(seen, ["/api/v1/config/profile"])

    async def test_raw_helpers_and_client_ownership_are_preserved(self) -> None:
        text = 'set sample_name "raw";\n'
        raw, adapter = self._clients(
            lambda request: httpx.Response(200, content=text.encode(), headers={"content-type": "application/json"}),
            _spec({"type": "string"}),
        )
        owner = CobaltStrikeClient("https://example.test")
        owner._token = "offline-token"
        owner._client = raw

        self.assertEqual((await adapter.get("/api/v1/config/value")).json(), text)
        self.assertEqual((await owner.request_text("GET", "/api/v1/config/value"))["text"], text)
        json_result = await owner.request_json("GET", "/api/v1/config/value")
        self.assertFalse(json_result["ok"])
        self.assertEqual(json_result["error"], "Response did not contain valid JSON")
        await adapter.aclose()
        self.assertFalse(raw.is_closed)
        self.assertEqual((await raw.get("/api/v1/config/value")).text, text)

    async def test_mcp_calls_keep_auth_refresh_and_audit_hooks(self) -> None:
        for failure_status in (401, 403):
            with self.subTest(failure_status=failure_status):
                seen_authorization = []
                hook_events = []

                def handler(request):
                    seen_authorization.append(request.headers.get("authorization"))
                    self.assertEqual(request.extensions["timeout"]["read"], 17.0)
                    if len(seen_authorization) == 1:
                        return httpx.Response(failure_status, content=b"expired")
                    return httpx.Response(200, content=b"profile text", headers={"content-type": "application/json"})

                async def on_request(request):
                    hook_events.append(("request", request.url.path))

                async def on_response(response):
                    hook_events.append(("response", response.status_code))

                owner = CobaltStrikeClient("https://example.test")
                owner._token = "expired-token"
                owner._auth_context = AuthContext("offline", "unused", 1000, "/api/auth/login")
                raw = ReauthenticatingAsyncClient(
                    owner,
                    base_url=owner.base_url,
                    headers={"Authorization": "Bearer expired-token"},
                    timeout=17.0,
                    transport=httpx.MockTransport(handler),
                    event_hooks={"request": [on_request], "response": [on_response]},
                )
                owner._client = raw
                spec = _spec({"type": "string"})
                adapter = create_openapi_client(raw, spec)
                self.addAsyncCleanup(raw.aclose)
                self.addAsyncCleanup(adapter.aclose)
                server = FastMCP.from_openapi(openapi_spec=spec, client=adapter)
                with patch.object(owner, "_request_access_token", new=AsyncMock(return_value="fresh-token")) as refresh:
                    async with Client(server) as client:
                        for _ in range(2):
                            result = await client.call_tool("getValue")
                            self.assertEqual(result.structured_content, {"result": "profile text"})
                    refresh.assert_awaited_once()
                self.assertEqual(seen_authorization, ["Bearer expired-token", "Bearer fresh-token", "Bearer fresh-token"])
                self.assertEqual(hook_events, [
                    ("request", "/api/v1/config/value"), ("response", failure_status),
                    ("request", "/api/v1/config/value"), ("response", 200),
                    ("request", "/api/v1/config/value"), ("response", 200),
                ])


if __name__ == "__main__":
    unittest.main()
