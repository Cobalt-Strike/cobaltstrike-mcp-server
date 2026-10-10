"""Offline provenance, extraction outcomes, and paging contract regressions."""

from __future__ import annotations

import asyncio
import codecs
import hashlib
import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastmcp import Client, FastMCP

from cs_client import CobaltStrikeClient
from cs_documents import DocumentExtractionResult, DocumentParseError, DocumentTooLargeError
from cs_downloads import DOWNLOAD_INVENTORY_PATH, DownloadInventory
from cs_files import add_cobalt_strike_file_tools
from tests.test_core import _docx_bytes, _xlsx_bytes


class DownloadMetadataTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []
        self.body = b"hello world"
        self.headers = {"content-type": "text/plain"}
        self.file_status = 200
        self.inventory = [{
            "id": "File-A", "bid": "42", "path": "C:\\Evidence",
            "name": "report.txt", "timestamp": 1640995200000,
        }]
        self.inventory_status = 200
        self.inventory_error = None
        self.inventory_delay = 0

        async def handler(request):
            self.requests.append(request.url.path)
            if request.url.path == DOWNLOAD_INVENTORY_PATH:
                if self.inventory_delay:
                    await asyncio.sleep(self.inventory_delay)
                if self.inventory_error:
                    raise self.inventory_error
                return httpx.Response(self.inventory_status, json=self.inventory)
            return httpx.Response(self.file_status, content=self.body, headers=self.headers)

        self.handler = handler
        self.owner = self._owner()
        self.server = FastMCP("Download metadata contracts")
        add_cobalt_strike_file_tools(self.server, self.owner)

    def _owner(self):
        owner = CobaltStrikeClient("https://example.test")
        owner._token = "offline-token"
        owner._client = httpx.AsyncClient(
            base_url=owner.base_url, transport=httpx.MockTransport(self.handler),
        )
        self.addAsyncCleanup(owner.close)
        return owner

    async def _call(self, **arguments):
        async with Client(self.server) as client:
            result = await client.call_tool(
                "getDownloadedFileText", {"file_id": "File-A", **arguments}, raise_on_error=False,
            )
        self.assertEqual(json.loads(result.content[0].text), result.structured_content)
        return result, result.structured_content

    async def test_exact_inventory_binding_preserves_paging_digest_and_unknown_host(self):
        self.inventory.insert(0, {
            "id": "file-a", "bid": "wrong", "host": "wrong-host", "path": "wrong-path",
        })
        first_result, first = await self._call(max_text_bytes=5)
        second_result, second = await self._call(
            max_text_bytes=6, text_offset_chars=first["text_page"]["next_offset_chars"],
        )
        self.assertFalse(first_result.is_error)
        self.assertFalse(second_result.is_error)
        self.assertEqual(first["text"] + second["text"], "hello world")
        self.assertFalse(first["text_page"]["complete"])
        self.assertTrue(second["text_page"]["complete"])
        self.assertEqual(first["source"], second["source"])
        source = first["source"]
        self.assertEqual(source["status"], "matched")
        self.assertEqual(source["file_id"], "File-A")
        self.assertEqual(source["beacon_id"], "42")
        self.assertIsNone(source["host"])
        self.assertEqual(source["remote_path"], "C:\\Evidence")
        self.assertEqual(source["file_name"], "report.txt")
        self.assertEqual(source["recorded_at"], "2022-01-01T00:00:00+00:00")
        self.assertEqual(source["inventory_timestamp_ms"], 1640995200000)
        self.assertTrue(source["inventory_observed_at"])
        self.assertIn("source", first["untrusted_content_fields"])
        for result in (first, second):
            self.assertEqual(result["extraction_outcome"], "extracted")
            self.assertIsNone(result["extraction_reason"])
            self.assertEqual(result["sha256_read_bytes"], hashlib.sha256(self.body).hexdigest())
            self.assertEqual(result["bytes_read"], len(self.body))
        self.assertEqual(self.requests.count(DOWNLOAD_INVENTORY_PATH), 1)

    async def test_missing_and_duplicate_ids_never_borrow_source_fields(self):
        for rows, status in [
            ([{"id": "file-a", "bid": "wrong", "path": "wrong"}], "missing"),
            ([self.inventory[0], dict(self.inventory[0], bid="different")], "ambiguous"),
        ]:
            with self.subTest(status=status):
                self.inventory = rows
                source = await self._owner().get_download_source("File-A")
                self.assertEqual(source["status"], status)
                for field in ("beacon_id", "host", "remote_path", "file_name", "recorded_at"):
                    self.assertIsNone(source[field])

    async def test_missing_fields_and_invalid_timestamps_remain_unknown(self):
        self.inventory = [{"id": "File-A", "host": "inventory-host", "timestamp": True}]
        source = await self.owner.get_download_source("File-A")
        self.assertEqual(source["status"], "matched")
        self.assertEqual(source["host"], "inventory-host")
        self.assertIsNone(source["beacon_id"])
        self.assertIsNone(source["remote_path"])
        self.assertIsNone(source["inventory_timestamp_ms"])
        self.assertIsNone(source["recorded_at"])

    async def test_inventory_failures_do_not_fail_extraction_or_leak_error_bodies(self):
        cases = [
            (503, {"error": "SECRET-CANARY"}, None, "http_error"),
            (200, {"unexpected": "SECRET-CANARY"}, None, "invalid_response"),
            (200, [{"path": "missing-id"}], None, "invalid_response"),
            (200, [], httpx.ReadTimeout("SECRET-CANARY"), "timeout"),
        ]
        for status, rows, error, reason in cases:
            with self.subTest(reason=reason):
                self.inventory_status, self.inventory, self.inventory_error = status, rows, error
                # Use the actual helper while giving each case a fresh client-owned cache.
                self.owner._download_inventory = DownloadInventory()
                result, body = await self._call()
                self.assertFalse(result.is_error)
                self.assertEqual(body["text"], "hello world")
                self.assertEqual(body["extraction_outcome"], "extracted")
                self.assertEqual(body["source"]["status"], "unavailable")
                self.assertEqual(body["source"]["reason"], reason)
                self.assertIsNone(body["source"]["inventory_observed_at"])
                self.assertNotIn("SECRET-CANARY", json.dumps(body))

    async def test_unexpected_lookup_failure_preserves_file_result(self):
        with patch.object(self.owner, "get_download_source", new=AsyncMock(side_effect=RuntimeError("failed"))):
            result, body = await self._call()
        self.assertFalse(result.is_error)
        self.assertEqual(body["text"], "hello world")
        self.assertEqual(body["source"]["reason"], "lookup_failed")

    async def test_inventory_size_and_total_time_are_bounded(self):
        with patch("cs_downloads.MAX_INVENTORY_BYTES", 4):
            source = await self.owner.get_download_source("File-A")
        self.assertEqual(source["reason"], "size_limit_exceeded")
        self.inventory_delay = 0.1
        with patch("cs_downloads.INVENTORY_TIMEOUT_SECONDS", 0.01):
            source = await self._owner().get_download_source("File-A")
        self.assertEqual(source["reason"], "timeout")

    async def test_concurrent_lookups_share_one_fetch_and_expiry_drops_stale_provenance(self):
        self.inventory_delay = 0.01
        with patch("cs_downloads.monotonic", return_value=100):
            sources = await asyncio.gather(*(self.owner.get_download_source("File-A") for _ in range(3)))
        self.assertTrue(all(source["status"] == "matched" for source in sources))
        self.assertEqual(self.requests.count(DOWNLOAD_INVENTORY_PATH), 1)
        self.inventory_status = 500
        with patch("cs_downloads.monotonic", return_value=131):
            source = await self.owner.get_download_source("File-A")
        self.assertEqual(source["status"], "unavailable")
        self.assertIsNone(source["beacon_id"])

    async def test_cache_is_separate_for_clients_and_cleared_on_close(self):
        await self.owner.get_download_source("File-A")
        self.inventory = [dict(self.inventory[0], bid="other")]
        other = self._owner()
        self.assertEqual((await other.get_download_source("File-A"))["beacon_id"], "other")
        self.assertEqual((await self.owner.get_download_source("File-A"))["beacon_id"], "42")
        previous_cache = self.owner._download_inventory
        await self.owner.close()
        self.assertIsNot(self.owner._download_inventory, previous_cache)
        self.owner._client = httpx.AsyncClient(
            base_url=self.owner.base_url, transport=httpx.MockTransport(self.handler),
        )
        self.assertEqual((await self.owner.get_download_source("File-A"))["beacon_id"], "other")

    async def test_metadata_only_outcomes_are_successful_mcp_results(self):
        cases = [
            (b"\x00binary", "file.bin", True, "binary_content"),
            (b"%PDF-1.7", "file.pdf", True, "unsupported_format"),
            (_docx_bytes("text"), "file.docx", False, "extraction_disabled"),
            (b"not a zip", "file.docx", True, "parse_error"),
        ]
        for data, filename, enabled, reason in cases:
            with self.subTest(reason=reason):
                self.body = data
                self.headers = {"content-type": "application/octet-stream", "content-disposition": f'attachment; filename="{filename}"'}
                result, body = await self._call(extract_documents=enabled)
                self.assertFalse(result.is_error)
                self.assertEqual(body["extraction_outcome"], "metadata_only")
                self.assertEqual(body["extraction_reason"], reason)
                self.assertEqual(body["source"]["status"], "matched")
                self.assertEqual(body["extraction_method"], "metadata_only")

    async def test_parser_errors_limits_and_timeout_have_distinct_reasons(self):
        self.body = _docx_bytes("text")
        self.headers["content-disposition"] = 'attachment; filename="file.docx"'
        for error, reason in [
            (DocumentTooLargeError("bounded"), "parser_limit_exceeded"),
            (DocumentParseError("broken"), "parse_error"),
            (RuntimeError("unexpected"), "unexpected_error"),
        ]:
            with self.subTest(reason=reason), patch("cs_files.extract_document_text", side_effect=error):
                result, body = await self._call()
                self.assertFalse(result.is_error)
                self.assertEqual(body["extraction_reason"], reason)
        with patch("cs_files.asyncio.to_thread", new=AsyncMock(side_effect=asyncio.TimeoutError)):
            result, body = await self._call()
        self.assertFalse(result.is_error)
        self.assertEqual(body["extraction_outcome"], "metadata_only")
        self.assertEqual(body["extraction_reason"], "timeout")

    async def test_truncated_input_is_not_reported_as_corrupt_document(self):
        self.body = _docx_bytes("text")
        self.headers["content-disposition"] = 'attachment; filename="file.docx"'
        result, body = await self._call(max_bytes=20)
        self.assertFalse(result.is_error)
        self.assertTrue(body["truncated"])
        self.assertEqual(body["extraction_reason"], "input_truncated")
        self.assertEqual(body["sha256_read_bytes"], hashlib.sha256(self.body[:20]).hexdigest())

    async def test_empty_text_and_partial_input_keep_completeness_distinct(self):
        self.body = b""
        result, body = await self._call()
        self.assertFalse(result.is_error)
        self.assertEqual(body["extraction_outcome"], "extracted")
        self.assertIsNone(body["extraction_reason"])
        self.assertTrue(body["text_page"]["complete"])
        self.body = b"hello world"
        result, body = await self._call(max_bytes=5)
        self.assertTrue(body["truncated"])
        self.assertTrue(body["text_page"]["complete"])
        self.assertEqual(body["extraction_reason"], "input_truncated")

    async def test_utf16_mcp_results_preserve_paging_provenance_and_raw_digest(self):
        original = "<root>A\U0001f642\u00e9\u6f22</root>"
        self.headers = {"content-type": "application/octet-stream"}
        for encoding, bom in (("utf-16-le", codecs.BOM_UTF16_LE), ("utf-16-be", codecs.BOM_UTF16_BE)):
            with self.subTest(encoding=encoding):
                self.body = bom + original.encode(encoding)
                digest = hashlib.sha256(self.body).hexdigest()
                text, offset, source = "", 0, None
                while True:
                    result, body = await self._call(text_offset_chars=offset, max_text_bytes=7)
                    self.assertFalse(result.is_error)
                    self.assertEqual(body["extraction_outcome"], "extracted")
                    self.assertIsNone(body["extraction_reason"])
                    self.assertEqual(body["encoding"], "utf-16")
                    self.assertEqual(body["bytes_read"], len(self.body))
                    self.assertEqual(body["sha256_read_bytes"], digest)
                    self.assertEqual(body["source"]["status"], "matched")
                    self.assertEqual(body["source"], source or body["source"])
                    source = body["source"]
                    self.assertLessEqual(len(body["text"].encode("utf-8")), 7)
                    text += body["text"]
                    if body["text_page"]["complete"]:
                        break
                    next_offset = body["text_page"]["next_offset_chars"]
                    self.assertGreater(next_offset, offset)
                    offset = next_offset
                self.assertEqual(text, original)

                self.body = bom + "A\U0001f642B".encode(encoding)
                result, body = await self._call(max_bytes=7)
                self.assertFalse(result.is_error)
                self.assertEqual(body["text"], "A")
                self.assertTrue(body["truncated"])
                self.assertEqual(body["extraction_reason"], "input_truncated")
                self.assertEqual(body["sha256_read_bytes"], hashlib.sha256(self.body[:7]).hexdigest())
                self.assertEqual(body["bytes_read"], 7)
                self.assertTrue(body["text_page"]["complete"])

    async def test_malformed_utf16_remains_metadata_only(self):
        self.body = codecs.BOM_UTF16_LE + b"A\x00\x00\xdc"
        self.headers = {"content-type": "text/plain"}
        result, body = await self._call()
        self.assertFalse(result.is_error)
        self.assertIsNone(body["text"])
        self.assertEqual(body["extraction_outcome"], "metadata_only")
        self.assertEqual(body["extraction_reason"], "binary_content")
        self.assertEqual(body["sha256_read_bytes"], hashlib.sha256(self.body).hexdigest())

    async def test_extracted_text_limit_retains_existing_flag(self):
        self.body = _xlsx_bytes()
        self.headers["content-disposition"] = 'attachment; filename="file.xlsx"'
        with patch("cs_files.extract_document_text") as extract:
            extract.return_value = DocumentExtractionResult("partial", "xlsx_native", "plain", True)
            result, body = await self._call()
        self.assertFalse(result.is_error)
        self.assertTrue(body["text_truncated"])
        self.assertEqual(body["extraction_reason"], "text_limit_exceeded")

    async def test_validation_and_fetch_failures_keep_their_original_error_contract(self):
        result, body = await self._call(file_id="")
        self.assertTrue(result.is_error)
        self.assertEqual(body["error_code"], "invalid_arguments")
        self.assertEqual(body["extraction_outcome"], "not_attempted")
        self.assertEqual(self.requests, [])
        self.file_status = 404
        result, body = await self._call()
        self.assertTrue(result.is_error)
        self.assertEqual(body["status_code"], 404)
        self.assertEqual(body["error_code"], "http_error")
        self.assertEqual(body["extraction_reason"], "fetch_failed")
        self.assertNotIn(DOWNLOAD_INVENTORY_PATH, self.requests)


if __name__ == "__main__":
    unittest.main()
