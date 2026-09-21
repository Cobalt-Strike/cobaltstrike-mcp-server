"""Normalize textual OpenAPI responses before FastMCP parses their JSON body.

This compatibility client is only for generated tools. The shared API client and
its raw-text/download helpers continue to receive the original HTTP responses.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

import httpx


def _resolve(spec: dict[str, Any], value: Any) -> dict[str, Any]:
    """Resolve local OpenAPI references conservatively, without changing the spec."""
    seen: set[str] = set()
    while isinstance(value, dict) and "$ref" in value:
        ref = value["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
            return {}
        seen.add(ref)
        target: Any = spec
        for part in ref[2:].split("/"):
            if not isinstance(target, dict):
                return {}
            target = target.get(part.replace("~1", "/").replace("~0", "~"))
        if not isinstance(target, dict):
            return {}
        value = {**target, **{k: v for k, v in value.items() if k != "$ref"}}
    return value if isinstance(value, dict) else {}


def _is_text_media_type(media_type: str) -> bool:
    return (
        media_type.startswith("text/") and media_type != "text/event-stream"
    ) or media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    )


def _is_text_schema(spec: dict[str, Any], schema: Any) -> bool:
    schema = _resolve(spec, schema)
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
    """Delegate to the authenticated client, then normalize declared text only."""

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
            self._routes.append((re.compile(pattern), _resolve(spec, item)))

    def _expects_text(self, request: httpx.Request, response: httpx.Response) -> bool:
        if (
            not response.is_success
            or response.status_code in {204, 205, 206}
            or request.method == "HEAD"
            or "range" in request.headers
            or "content-disposition" in response.headers
        ):
            return False
        media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type and not _is_text_media_type(media_type):
            return False
        path = request.url.raw_path.split(b"?", 1)[0].decode("ascii")
        for pattern, item in self._routes:
            if not pattern.fullmatch(path):
                continue
            operation = _resolve(self._spec, item.get(request.method.lower()))
            responses = operation.get("responses", {})
            # Only the actual success response is eligible; never borrow a
            # string schema from another status or reinterpret an HTTP error.
            response_spec = _resolve(
                self._spec,
                responses.get(
                    str(response.status_code), responses.get("2XX", responses.get("default"))
                ),
            )
            content = response_spec.get("content", {})
            candidates = (
                (media_type, media_type.split("/", 1)[0] + "/*", "*/*")
                if media_type else tuple(content)
            )
            for candidate in candidates:
                if candidate in content:
                    if not media_type and len(content) != 1:
                        return False
                    if candidate not in {"*/*", "text/*", "application/*"} and not _is_text_media_type(candidate):
                        return False
                    return _is_text_schema(self._spec, content[candidate].get("schema"))
            return False
        return False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # FastMCP builds requests itself. Apply current client defaults here so
        # a refreshed bearer token is used on every subsequent generated call.
        for name, value in self._client.headers.items():
            if name.lower() == "authorization" or name not in request.headers:
                request.headers[name] = value
        response = await self._client.send(request, stream=True)
        if not self._expects_text(request, response):
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
        # Prefer a valid JSON string when the server already serialized it.
        # Keep object/array mismatches visible instead of silently stringifying.
        if isinstance(parsed, (str, dict, list)):
            return response
        try:
            text = body.decode(response.encoding or "utf-8", errors="strict")
        except (UnicodeError, LookupError):
            return response

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
