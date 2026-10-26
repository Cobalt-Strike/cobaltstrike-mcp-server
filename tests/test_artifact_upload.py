"""Upload paths the harness's HTTP client cannot drive: a chunked body with no declared length
and an empty body."""

import pytest

from cs_server_mcp.artifact_upload import (
    UploadRejected,
    artifact_upload_name,
    read_upload_body,
)
from cs_server_mcp.tool_errors import InvalidArgument


@pytest.mark.parametrize("name", ["", "   ", ".", "..", "dir/x.bin", "..\\x.bin", "a\x00b"])
def test_artifact_upload_name_refuses_paths_and_empty_names(name) -> None:
    with pytest.raises(InvalidArgument, match="name must be"):
        artifact_upload_name(name)


async def chunks(*parts: bytes):
    for part in parts:
        yield part


async def test_a_body_that_grows_past_the_cap_is_refused_while_reading() -> None:
    with pytest.raises(UploadRejected) as info:
        await read_upload_body(chunks(b"12345", b"6789"), declared_length=None, max_bytes=8)

    assert info.value.status == 413
    assert (
        info.value.detail == "The file is larger than the limit; limits.max_upload_bytes allows 8."
    )


async def test_an_empty_body_is_refused() -> None:
    with pytest.raises(UploadRejected) as info:
        await read_upload_body(chunks(), declared_length=0, max_bytes=8)

    assert info.value.status == 400
    assert info.value.next_step == (
        "Send a non-empty file, then call cs_upload_artifact again for a new link."
    )
