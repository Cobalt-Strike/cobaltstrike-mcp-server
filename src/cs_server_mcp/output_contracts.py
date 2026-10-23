"""The output contracts published as each tool's ``outputSchema``.

The SDK validates every successful result against the return annotation and sends the
validated dump as ``structuredContent``, in the field order declared here. Class and field
docstrings are published in the schema, which Codex renders for the model. Extra keys are
allowed so an added field or a shortened result still validates; an error result is never
validated, and ``CommandRejection`` only documents its shape.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from cs_server_mcp import agent_text


class Contract(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        validate_by_name=True,
        validate_by_alias=True,
        serialize_by_alias=True,
    )


def _truncation_field() -> Any:
    return Field(default=None, alias="_truncation", description=agent_text.TRUNCATION_DESCRIPTION)


class ListPage(Contract):
    """The envelope of every paged listing. Paging keys lead so a client cut keeps them."""

    has_more: bool
    next_offset: int | None = Field(description=agent_text.LIST_PAGE_NEXT_OFFSET)
    total_records: int | None = Field(default=None, description=agent_text.LIST_PAGE_TOTAL_RECORDS)
    limit_clamped_to: int | None = Field(
        default=None,
        description=agent_text.LIST_PAGE_LIMIT_CLAMPED_TO,
    )
    truncation: dict[str, Any] | None = _truncation_field()


class ExecutionRow(Contract):
    """One task in a history listing."""

    command_execution_id: str
    execution_status: str | None = Field(
        description=agent_text.EXECUTION_OBSERVATION_EXECUTION_STATUS
    )
    execution_status_message: str | None = Field(
        default=None, description=agent_text.EXECUTION_OBSERVATION_STATUS_MESSAGE
    )
    result_count: int | None = Field(
        default=None, description=agent_text.EXECUTION_ROW_RESULT_COUNT
    )
    error_count: int | None = Field(default=None, description=agent_text.EXECUTION_ROW_ERROR_COUNT)
    command_name: str | None
    command_arguments: str | None
    beacon_id: str
    requested_by: str | None
    submitted_at: str | None = Field(description=agent_text.TIMESTAMP_DESCRIPTION)
    updated_at: str | None = Field(description=agent_text.EXECUTION_OBSERVATION_UPDATED_AT)
    job_id: str | None = Field(description=agent_text.EXECUTION_ROW_JOB_ID)


class TaskAcknowledgement(Contract):
    """One tasking confirmation the team server recorded for a task."""

    text: str | None
    tactics: list[str]


class ExecutionObservation(ExecutionRow):
    """One task's status and metadata."""

    execution_status_note: str | None = Field(
        default=None, description=agent_text.EXECUTION_OBSERVATION_STATUS_NOTE
    )
    last_error_message: str | None
    tactics: list[str]
    acknowledgements: list[TaskAcknowledgement]
    truncation: dict[str, Any] | None = _truncation_field()


class ExecutionListPage(ListPage):
    """A page of execution history rows; its one note says when their counts are incomplete."""

    execution_status_note: str | None = Field(
        default=None, description=agent_text.EXECUTION_LIST_PAGE_STATUS_NOTE
    )
    results: list[ExecutionRow]


class ExecutionHistory(RootModel[ExecutionObservation | ExecutionListPage]):
    """What ``cs_list_command_executions`` returns: an observation with an ID, otherwise a page.

    The root is declared an object so the schema stays valid for every protocol
    version; the two shapes are told apart by their required keys.
    """

    model_config = ConfigDict(json_schema_extra={"type": "object"})


class ExecutionReceipt(Contract):
    """An accepted submission that can be followed with ``cs_read_command_output``."""

    submission_outcome: Literal["accepted"]
    command_execution_id: str
    command_name: str
    command_arguments: str | None = Field(
        description=agent_text.EXECUTION_RECEIPT_COMMAND_ARGUMENTS
    )
    submitted_arguments: list[str] = Field(
        description=agent_text.EXECUTION_RECEIPT_SUBMITTED_ARGUMENTS
    )
    beacon_id: str
    execution_status: str | None = Field(
        description=agent_text.EXECUTION_OBSERVATION_EXECUTION_STATUS
    )
    execution_status_message: str | None = Field(
        default=None, description=agent_text.EXECUTION_OBSERVATION_STATUS_MESSAGE
    )
    execution_status_note: str | None = Field(
        default=None, description=agent_text.EXECUTION_OBSERVATION_STATUS_NOTE
    )
    submitted_at: str | None = Field(description=agent_text.TIMESTAMP_DESCRIPTION)
    truncation: dict[str, Any] | None = _truncation_field()


class RejectionDetail(Contract):
    """Why nothing ran: a policy or selection code, or the Cobalt Strike failure."""

    code: str = Field(description=agent_text.REJECTION_DETAIL_CODE)
    message: str
    http_status: int | None = None
    rule: str | None = Field(default=None, description=agent_text.REJECTION_DETAIL_RULE)


class CommandRejection(Contract):
    """The ``structuredContent`` of a refused, rejected, or uncertain submission.

    The same envelope every tool error carries, led by ``submission_outcome``.
    """

    submission_outcome: Literal["not_submitted", "rejected", "uncertain"] = Field(
        description=agent_text.COMMAND_REJECTION_SUBMISSION_OUTCOME
    )
    error: RejectionDetail
    tool: str
    request: dict[str, Any]
    truncated_arguments: list[str]
    next_step: str


class CommandRow(Contract):
    """A command name with its description: a listing row without help."""

    command_name: str
    description: str | None


class CommandDefinition(CommandRow):
    """A command with its console help, from a lookup or include_help."""

    help: str | None


class CommandCatalog(ListPage):
    """A page of commands from ``cs_list_commands``, sorted by name.

    A row carries ``help`` only when asked: a listing leaves it out unless
    ``include_help`` is true, and an exact lookup includes it.
    """

    results: list[Annotated[CommandDefinition | CommandRow, Field(union_mode="left_to_right")]]


class BeaconRow(Contract):
    """One beacon in a listing: the fields that identify it and say whether it can be tasked."""

    beacon_id: str
    parent_beacon_id: str | None
    hostname: str | None
    username: str | None
    is_admin: bool | None = Field(description=agent_text.BEACON_ROW_IS_ADMIN)
    process_name: str | None
    process_id: int | None
    listener: str | None
    alive: bool
    last_seen_at: str | None = Field(description=agent_text.TIMESTAMP_DESCRIPTION)
    last_checkin_age: str | None
    note: str


class BeaconRecord(BeaconRow):
    """One beacon read by ID, adding its addresses, platform, and check-in timing.

    ``impersonated_as``, ``pivot_hint``, and ``ssh_port`` pass through only when set.
    """

    internal_ip: str | None
    external_ip: str | None
    host_ip: str | None
    architecture_type: str | None
    system_arch: str | None
    os_version: str | None = Field(description=agent_text.BEACON_RECORD_OS_VERSION)
    os_build: int | None = Field(description=agent_text.BEACON_RECORD_OS_VERSION)
    link_state: str | None
    sleep_seconds: int | None
    jitter_percent: int | None
    supports_sleep: bool | None


class BeaconListPage(ListPage):
    """A page of beacons cut to their identifying fields."""

    results: list[BeaconRow]


class Beacons(RootModel[BeaconRecord | BeaconListPage]):
    """What ``cs_list_beacons`` returns: one beacon with beacon_id, otherwise a page."""

    model_config = ConfigDict(json_schema_extra={"type": "object"})


class ArtifactRecord(Contract):
    """One team-server artifact: the reference a command argument uses.

    ``size_bytes`` passes through only when the file is visible under the server's
    artifacts directory; Cobalt Strike records no size, hash, or timestamp of its own.
    """

    artifact_reference: str


class ArtifactListPage(ListPage):
    """What ``cs_list_artifacts`` returns: a page of artifacts."""

    results: list[ArtifactRecord]


class DownloadRecord(Contract):
    """One completed download, read by ID or listed, with the file's remote origin.

    ``host`` passes through only when a listed beacon names it, and ``size_bytes``
    only when the team server records a size.
    """

    download_id: str
    transfer_state: Literal["completed"] = Field(
        description=agent_text.DOWNLOAD_RECORD_TRANSFER_STATE
    )
    progress: Literal[1.0] = 1.0
    beacon_id: str
    remote_file_name: str | None
    remote_directory: str | None = Field(description=agent_text.DOWNLOAD_RECORD_REMOTE_DIRECTORY)
    downloaded_at: str | None = Field(description=agent_text.TIMESTAMP_DESCRIPTION)


class ActiveDownloadRecord(Contract):
    """One transfer still arriving, listed from the beacon's active-download progress.

    ``host`` passes through only when the beacon names it.
    """

    download_id: None = Field(description=agent_text.ACTIVE_DOWNLOAD_RECORD_DOWNLOAD_ID)
    transfer_state: Literal["in_progress"] = Field(
        description=agent_text.DOWNLOAD_RECORD_TRANSFER_STATE
    )
    beacon_id: str
    remote_file_name: str
    remote_directory: str = Field(description=agent_text.DOWNLOAD_RECORD_REMOTE_DIRECTORY)
    size_bytes: int = Field(ge=0)
    received_bytes: int = Field(ge=0)
    progress: float | None = Field(
        ge=0, le=1, description=agent_text.ACTIVE_DOWNLOAD_RECORD_PROGRESS
    )


class DownloadListPage(ListPage):
    """A page of downloads: active transfers first, then completed files."""

    results: list[DownloadRecord | ActiveDownloadRecord]


class Downloads(RootModel[DownloadRecord | DownloadListPage]):
    """What ``cs_list_downloads`` returns: one download with download_id, otherwise a page."""

    model_config = ConfigDict(json_schema_extra={"type": "object"})


class ScreenshotRecord(Contract):
    """One screenshot with the beacon and window it was captured from."""

    screenshot_id: str
    beacon_id: str
    hostname: str | None
    username: str | None
    window_title: str | None
    created_at: str | None = Field(description=agent_text.TIMESTAMP_DESCRIPTION)


class ScreenshotListPage(ListPage):
    """A page of screenshots."""

    results: list[ScreenshotRecord]


class Screenshots(RootModel[ScreenshotRecord | ScreenshotListPage]):
    """What ``cs_list_screenshots`` returns: one screenshot with screenshot_id, otherwise a page."""

    model_config = ConfigDict(json_schema_extra={"type": "object"})


class FileTransfer(Contract):
    """A staged Cobalt Strike file and the one-time link that fetches it to the MCP client host."""

    url: str = Field(description=agent_text.FILE_TRANSFER_URL)
    expires_at: str = Field(description=agent_text.TIMESTAMP_DESCRIPTION)
    size_bytes: int
    sha256: str = Field(description=agent_text.FILE_TRANSFER_SHA256)


class DownloadTransfer(FileTransfer):
    """What ``cs_fetch_download`` returns, repeating the download's origin."""

    source_filename: str | None = Field(description=agent_text.FILE_TRANSFER_SOURCE_FILENAME)
    download_id: str
    transfer_state: Literal["completed"] = Field(
        description=agent_text.DOWNLOAD_RECORD_TRANSFER_STATE
    )
    beacon_id: str
    remote_file_name: str | None
    remote_directory: str | None = Field(description=agent_text.DOWNLOAD_RECORD_REMOTE_DIRECTORY)


class ScreenshotTransfer(FileTransfer):
    """What ``cs_fetch_screenshot`` returns, repeating the screenshot's origin."""

    screenshot_id: str
    beacon_id: str
    created_at: str | None = Field(description=agent_text.TIMESTAMP_DESCRIPTION)


class ArtifactUploadLink(Contract):
    """What ``cs_upload_artifact`` returns: a one-time link that stores the file PUT to it."""

    url: str = Field(description=agent_text.ARTIFACT_UPLOAD_LINK_URL)
    expires_at: str = Field(description=agent_text.TIMESTAMP_DESCRIPTION)
    max_bytes: int = Field(description=agent_text.ARTIFACT_UPLOAD_LINK_MAX_BYTES)
