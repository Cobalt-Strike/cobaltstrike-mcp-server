"""Offline HTTP and MCP contracts for unconstrained download responses."""

from __future__ import annotations

import json
import unittest
from unittest.mock import AsyncMock, Mock, patch

import httpx
from fastmcp import Client

from cs_openapi import create_openapi_client
from cs_server import CobaltStrikeMCPServer


def _spec() -> dict:
    def operation(name, media_type, schema):
        return {"get": {
            "operationId": name,
            "responses": {"200": {"description": "Result", "content": {
                media_type: {"schema": schema},
            }}},
        }}

    return {
        "openapi": "3.0.3",
        "info": {"title": "Offline download contract", "version": "1"},
        "components": {"schemas": {"StreamingResponseBody": {}}},
        "paths": {
            "/download": operation("getDownload", "*/*", {
                "$ref": "#/components/schemas/StreamingResponseBody",
            }),
            "/profile": operation("getSyscallMethod", "application/json", {"type": "string"}),
            "/beacon": operation("getBeacon", "application/json", {
                "type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"],
            }),
        },
    }


class DownloadContractTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.body = b"fixture file contents\n"
        self.status = 200
        self.headers = {
            "content-type": "application/octet-stream",
            "content-disposition": "attachment; filename=fixture.txt",
        }

    async def _server(self, spec=None):
        def handler(request):
            if request.url.path == "/download":
                return httpx.Response(self.status, content=self.body, headers=self.headers)
            if request.url.path == "/profile":
                return httpx.Response(200, text="fixture profile", headers={"content-type": "application/json"})
            return httpx.Response(200, json={"id": "wrong-type"})

        raw = httpx.AsyncClient(base_url="https://example.test", transport=httpx.MockTransport(handler))
        self.addAsyncCleanup(raw.aclose)
        cs = Mock()
        cs.fetch_openapi_spec = AsyncMock(return_value=spec or _spec())
        cs.get_authenticated_client.return_value = raw
        owner = CobaltStrikeMCPServer(cs, websocket_streams_enabled=False, auto_start_websocket_streams=False)
        self.addAsyncCleanup(owner.stop)
        with patch("cs_server.logger"):
            server = await owner.create_server()
        return server, raw, owner._openapi_client

    async def test_text_and_json_keep_the_result_envelope(self):
        server, raw, adapter = await self._server()
        text_cases = [
            (b"fixture file contents\n", "fixture file contents\n"),
            ("  caf\u00e9 \u6f22\u5b57 \U0001f642\r\n".encode(), "  caf\u00e9 \u6f22\u5b57 \U0001f642\r\n"),
            (b"", ""),
            (b" \t\r\n\f", " \t\r\n\f"),
        ]
        json_cases = [
            {"id": 7}, {"result": {"id": 7}}, [1, 2], "JSON text", 123, 1.5, True, False, None,
        ]
        async with Client(server) as client:
            catalog = {t.name: t for t in await client.list_tools()}
            schema = catalog["getDownload"].outputSchema
            self.assertEqual(schema["type"], "object")
            self.assertIn("result", schema["required"])
            for body, expected in text_cases + [(json.dumps(value).encode(), value) for value in json_cases]:
                with self.subTest(body=body):
                    self.body = body
                    result = await client.call_tool("getDownload")
                    self.assertFalse(result.is_error)
                    self.assertEqual(result.structured_content, {"result": expected})
                    self.assertEqual(json.loads(result.content[0].text), {"result": expected})
                    self.assertEqual((await raw.get("/download")).content, body)
            # Parsed JSON is passed through without altering its HTTP representation.
            self.body = b'  {"id": 7}\n'
            self.assertEqual((await adapter.get("/download")).content, self.body)

    async def test_binary_and_undecodable_bodies_return_actionable_mcp_errors(self):
        server, raw, _ = await self._server()
        cases = [
            (b"\xff\x00\x80\xfe", "application/octet-stream"),
            (b"PK\x03\x04\x00\x00\x80", "application/octet-stream"),
            (b"invalid utf8 \x80", "text/plain; charset=utf-8"),
            (b"text" * 1500 + b"\x00", "application/octet-stream"),
            ("control \u0080".encode(), "application/octet-stream"),
            (b"%PDF-1.4\n", "application/pdf"),
        ]
        async with Client(server) as client:
            for body, media_type in cases:
                with self.subTest(body_prefix=body[:24], media_type=media_type):
                    self.body = body
                    self.headers["content-type"] = media_type
                    with self.assertLogs("fastmcp", level="ERROR"):
                        result = await client.call_tool("getDownload", raise_on_error=False)
                    self.assertTrue(result.is_error)
                    message = result.content[0].text
                    self.assertIn("Unsupported binary or undecodable download content", message)
                    self.assertIn("getDownloadedFileText", message)
                    self.assertIn("download API", message)
                    self.assertEqual((await raw.get("/download")).content, body)

    async def test_declared_charset_is_decoded_without_replacement(self):
        self.body = b"caf\xe9\n"
        self.headers["content-type"] = "text/plain; charset=iso-8859-1"
        server, _, _ = await self._server()
        async with Client(server) as client:
            result = await client.call_tool("getDownload")
            self.assertEqual(result.structured_content, {"result": "caf\u00e9\n"})

    async def test_typed_tools_keep_their_output_contracts(self):
        server, _, _ = await self._server()
        async with Client(server) as client:
            catalog = {t.name: t for t in await client.list_tools()}
            self.assertIsNotNone(catalog["getSyscallMethod"].outputSchema)
            self.assertIsNotNone(catalog["getBeacon"].outputSchema)
            text = await client.call_tool("getSyscallMethod")
            self.assertEqual(text.structured_content, {"result": "fixture profile"})
            invalid = await client.call_tool("getBeacon", raise_on_error=False)
            self.assertTrue(invalid.is_error)

    async def test_typed_wildcard_schemas_still_reject_invalid_json_values(self):
        for schema, body in [
            ({"type": "string"}, b"123"),
            ({"type": "object", "properties": {"id": {"type": "integer"}}}, b'{"id":"wrong"}'),
            ({"type": "array", "items": {"type": "integer"}}, b'["wrong"]'),
        ]:
            with self.subTest(schema=schema):
                spec = _spec()
                spec["components"]["schemas"]["StreamingResponseBody"] = schema
                self.body = body
                server, _, adapter = await self._server(spec)
                self.assertEqual((await adapter.get("/download")).content, body)
                async with Client(server) as client:
                    result = await client.call_tool("getDownload", raise_on_error=False)
                    self.assertTrue(result.is_error)
                    self.assertIn("Output validation error", result.content[0].text)

    async def test_http_errors_no_content_and_partial_responses_are_not_normalized(self):
        server, _, adapter = await self._server()
        self.status = 404
        self.body = b"not found"
        async with Client(server) as client:
            with self.assertLogs("fastmcp", level="ERROR"):
                result = await client.call_tool("getDownload", raise_on_error=False)
            self.assertTrue(result.is_error)
            self.assertIn("404", result.content[0].text)
            self.assertIn("not found", result.content[0].text)
        for status, body in [(401, b"expired"), (500, b"failed"), (204, b""), (205, b""), (206, b"partial")]:
            with self.subTest(status=status):
                self.status, self.body = status, body
                response = await adapter.get("/download")
                self.assertEqual(response.status_code, status)
                self.assertEqual(response.content, body)
        self.status, self.body = 200, b"partial"
        response = await adapter.get("/download", headers={"range": "bytes=0-6"})
        self.assertEqual(response.content, self.body)

    async def test_missing_or_unresolved_schemas_are_not_treated_as_unconstrained(self):
        async with httpx.AsyncClient(
            base_url="https://example.test",
            transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"original body")),
        ) as raw:
            for media in [
                {},
                {"schema": {"$ref": "#/components/schemas/Missing"}},
                {"schema": {"$ref": "https://example.test/schema"}},
                {"schema": {"$ref": "#/paths/~1download/get/responses/200/content/*~1*/schema"}},
            ]:
                with self.subTest(media=media):
                    spec = _spec()
                    spec["paths"]["/download"]["get"]["responses"]["200"]["content"]["*/*"] = media
                    async with create_openapi_client(raw, spec) as adapter:
                        self.assertEqual((await adapter.get("/download")).content, b"original body")


if __name__ == "__main__":
    unittest.main()
