"""Normalize textual OpenAPI responses before FastMCP parses their JSON body.

This compatibility client is only for generated tools. The shared API client and
its raw-text/download helpers continue to receive the original HTTP responses.
"""

from __future__ import annotations

import re
from typing import Any, Literal
from urllib.parse import quote

import httpx
from fastmcp.exceptions import ToolError


def _resolve(spec: dict[str, Any], value: Any) -> dict[str, Any] | None:
    """Resolve local references; distinguish an invalid reference from ``{}``."""
    seen: set[str] = set()
    while isinstance(value, dict) and "$ref" in value:
        ref = value["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
            return None
        seen.add(ref)
        target: Any = spec
        for part in ref[2:].split("/"):
            if not isinstance(target, dict):
                return None
            target = target.get(part.replace("~1", "/").replace("~0", "~"))
        if not isinstance(target, dict):
            return None
        value = {**target, **{k: v for k, v in value.items() if k != "$ref"}}
    return value if isinstance(value, dict) else None


def _is_text_media_type(media_type: str) -> bool:
    return (
        media_type.startswith("text/") and media_type != "text/event-stream"
    ) or media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    )


def _is_text_schema(spec: dict[str, Any], schema: Any) -> bool:
    schema = _resolve(spec, schema) or {}
    return (
        schema.get("type") == "string"
        and schema.get("format") not in {"byte", "binary"}
        and not schema.get("nullable")
        and not any(
            key in schema
            for key in ("allOf", "anyOf", "oneOf", "contentEncoding", "contentMediaType")
        )
    )


class _OpenAPITextTransport(httpx.AsyncBaseTransport):
    """Normalize declared text and untyped wildcard bodies for generated tools."""

    def __init__(self, client: httpx.AsyncClient, spec: dict[str, Any]):
        self._client = client
        self._spec = spec
        self._routes: list[tuple[re.Pattern[str], dict[str, Any]]] = []
        prefix = client.base_url.path.rstrip("/")
        # A concrete route must win over a parameterized route, even when its
        # schema is not textual. Keep all routes so they can block normalization.
        for path, item in sorted(
            spec.get("paths", {}).items(), key=lambda entry: entry[0].count("{")
        ):
            parts = re.split(r"(\{[^{}]+\})", prefix + path)
            pattern = "".join(
                "[^/]+" if part.startswith("{") else re.escape(quote(part, safe="/%"))
                for part in parts
            )
            self._routes.append((re.compile(pattern), _resolve(spec, item) or {}))

    def _normalization_mode(
        self, request: httpx.Request, response: httpx.Response,
    ) -> Literal["text", "wildcard"] | None:
        if (
            not response.is_success
            or response.status_code in {204, 205, 206}
            or request.method == "HEAD"
            or "range" in request.headers
        ):
            return None
        media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type == "text/event-stream":
            return None
        path = request.url.raw_path.split(b"?", 1)[0].decode("ascii")
        for pattern, item in self._routes:
            if not pattern.fullmatch(path):
                continue
            operation = _resolve(self._spec, item.get(request.method.lower())) or {}
            responses = operation.get("responses", {})
            # Only the actual success response is eligible; never borrow a
            # schema from another status or reinterpret an HTTP error.
            response_spec = _resolve(
                self._spec,
                responses.get(
                    str(response.status_code), responses.get("2XX", responses.get("default"))
                ),
            ) or {}
            content = response_spec.get("content", {})
            # An explicitly empty wildcard schema permits JSON or plain text,
            # including attachments served as application/octet-stream. Missing
            # or unresolved schemas must not be mistaken for an empty schema.
            if set(content) == {"*/*"} and _resolve(
                self._spec, content["*/*"].get("schema"),
            ) == {}:
                return "wildcard"
            if "content-disposition" in response.headers or (
                media_type and not _is_text_media_type(media_type)
            ):
                return None
            candidates = (
                (media_type, media_type.split("/", 1)[0] + "/*", "*/*")
                if media_type else tuple(content)
            )
            for candidate in candidates:
                if candidate in content:
                    if not media_type and len(content) != 1:
                        return None
                    if candidate not in {"*/*", "text/*", "application/*"} and not _is_text_media_type(candidate):
                        return None
                    if _is_text_schema(self._spec, content[candidate].get("schema")):
                        return "text"
                    return None
            return None
        return None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # FastMCP builds requests itself. Apply current client defaults here so
        # a refreshed bearer token is used on every subsequent generated call.
        for name, value in self._client.headers.items():
            if name.lower() == "authorization" or name not in request.headers:
                request.headers[name] = value
        response = await self._client.send(request, stream=True)
        mode = self._normalization_mode(request, response)
        if mode is None:
            return response

        try:
            body = await response.aread()
        except BaseException:
            await response.aclose()
            raise
        try:
            parsed = response.json()
        except ValueError:
            parsed = None
        else:
            # Keep every valid JSON value (including scalars and null) so
            # FastMCP retains its original {"result": value} envelope.
            if mode == "wildcard":
                return response
        # Prefer a valid JSON string when the server already serialized it.
        # Keep object/array mismatches visible instead of silently stringifying.
        if isinstance(parsed, (str, dict, list)):
            return response
        try:
            text = body.decode(response.encoding or "utf-8", errors="strict")
        except (UnicodeError, LookupError):
            if mode == "text":
                return response
            text = None

        if mode == "wildcard":
            media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if (
                text is None
                or re.search(r"[\x00-\x08\x0b\x0e-\x1f\x7f-\x9f]", text)
                or (
                    media_type not in {"", "application/octet-stream"}
                    and not _is_text_media_type(media_type)
                )
            ):
                await response.aclose()
                raise ToolError(
                    "Unsupported binary or undecodable download content. "
                    "Use getDownloadedFileText for metadata and supported document extraction, "
                    "or the download API to retrieve the original bytes."
                )

        headers = response.headers.copy()
        # These headers describe the original representation, not the JSON
        # string delivered to FastMCP. httpx recalculates the content length.
        for name in (
            "content-length", "content-encoding", "transfer-encoding", "etag",
            "content-md5", "digest", "content-digest", "repr-digest", "accept-ranges",
        ):
            headers.pop(name, None)
        headers["content-type"] = "application/json"
        return httpx.Response(
            response.status_code,
            json=text,
            headers=headers,
            request=request,
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        # The CobaltStrikeClient owns the shared connection pool.
        pass


def create_openapi_client(
    client: httpx.AsyncClient, openapi_spec: dict[str, Any]
) -> httpx.AsyncClient:
    """Create a generated-tools-only client; closing it leaves ``client`` open."""
    headers = client.headers.copy()
    headers.pop("authorization", None)
    return httpx.AsyncClient(
        base_url=client.base_url,
        headers=headers,
        timeout=client.timeout,
        transport=_OpenAPITextTransport(client, openapi_spec),
        trust_env=False,
    )
