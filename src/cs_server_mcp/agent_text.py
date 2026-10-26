"""Text the model reads: server instructions, tool and argument descriptions, output
schema field descriptions, tool errors, notices, the JSON the file links answer, and
the fragments that compose a Cobalt Strike failure line and a command's argument
layout.

Wording lives here and nowhere else; the modules that publish it import this one.
A name whose value holds ``{placeholders}`` is a ``str.format`` template that the
publishing code fills in. Nothing here imports the rest of the package.
"""

from __future__ import annotations

from collections.abc import Mapping

# ---- Server instructions -----------------------------------------------------------------------

SERVER_INSTRUCTIONS = (
    "Tools for Cobalt Strike, a red-team command-and-control framework. Use them whenever "
    "the user asks about beacons, running console commands, task results or output, "
    "downloads, screenshots, or artifacts. Every tool is named cs_*.\n"
    "\n"
    "Concepts: a beacon is an agent on a remote system, named by beacon_id. A command "
    "execution is one console task, named by command_execution_id; command_name names a "
    "console command. Downloads are files a beacon pulled from its remote system. Screenshots "
    "are images of that system's screen captured by a beacon. Artifacts are files on the "
    "team server for beacons to use, listed by cs_list_artifacts and added by "
    "cs_upload_artifact.\n"
    "\n"
    "Paged results and tool errors say how to continue: follow next_offset, the "
    "start_line continuation notice, or an error's next_step rather "
    "than retrying on your own. After an uncertain submission, check "
    "cs_list_command_executions for the beacon before submitting again."
)


# ---- Tool titles -------------------------------------------------------------------------------

LIST_BEACONS_TITLE = "List beacons"

LIST_COMMANDS_TITLE = "List commands"

EXECUTE_COMMAND_TITLE = "Execute command"

LIST_COMMAND_EXECUTIONS_TITLE = "List command executions"

READ_COMMAND_OUTPUT_TITLE = "Read command output"

LIST_ARTIFACTS_TITLE = "List artifacts"

UPLOAD_ARTIFACT_TITLE = "Upload artifact"

LIST_DOWNLOADS_TITLE = "List downloads"

FETCH_DOWNLOAD_TITLE = "Fetch download"

LIST_SCREENSHOTS_TITLE = "List screenshots"

FETCH_SCREENSHOT_TITLE = "Fetch screenshot"

GET_TEAM_SERVER_TITLE = "Get team server"


# ---- Tool descriptions -------------------------------------------------------------------------

LIST_BEACONS = """\
List beacons, or get one beacon when beacon_id is given.

Beacons are Cobalt Strike agents on remote systems; beacon_id is what
cs_execute_command and the list filters take. List rows carry beacon_id,
parent_beacon_id (null for an egress beacon), hostname, username (no
domain), is_admin (an elevated token; false for a UAC-filtered local
admin), process_name, process_id, listener, alive, last_seen_at,
last_checkin_age, and note (empty when none). Listings hold beacons marked
alive and ones marked dead only recently (a long task blocks check-ins, so
they may be busy), alive first, then by beacon_id; the rest need
include_dead. A single lookup ignores include_dead and paging and adds internal_ip,
external_ip, host_ip, architecture_type (the beacon process), system_arch
(the host), os_version and os_build (can understate Windows 10), link_state,
supports_sleep, sleep_seconds and jitter_percent (how long a task may
wait), and impersonated_as, pivot_hint, and ssh_port only when set.
"""

LIST_COMMANDS = """\
List the commands beacons can run, with their help text.

Use it to find a command_name, or to read argument syntax from help before
cs_execute_command when unsure. Each result has command_name and
description; an exact command_name lookup, or include_help on a listing,
adds help (console usage), closed by what command_arguments takes for a
builtin this server encodes, plus any technique list Cobalt Strike serves
for the command. A lookup ignores letter case and returns the catalog's
spelling; an unknown name returns unsupported_command, and a name the
command policy denies returns command_not_permitted. Listings leave denied
commands out. Subcommands such as mode dns are part of their command's
help, not names. Results are sorted by command_name and paged, and
total_records counts the commands the search left; continue with
next_offset and the same arguments.
"""

EXECUTE_COMMAND = """\
Execute one command on a beacon and return a submission receipt.

An unsupported command_name or an item its layout cannot encode is
rejected before anything runs; when unsure read
cs_list_commands(command_name=...) first. An accepted submission returns a
receipt with command_execution_id, submitted_arguments as sent,
command_arguments as the encoded line, and the execution_status and
execution_status_message read after acceptance; the execution_status_note
is null unless the beacon is dead, the status is unreadable, or the task
may not have been queued. Then read output with cs_read_command_output,
which may wait for a near check-in. The command policy may refuse a
command or ask the user to approve it; a refusal or ungranted approval is
final: ask the user before submitting it again. Other rejections say in
next_step what to do first; their submission_outcome is not_submitted
(nothing sent), rejected (Cobalt Strike refused it), or uncertain (no
answer; it may have queued).
"""

LIST_COMMAND_EXECUTIONS = """\
List past command executions (Cobalt Strike tasks), or get one execution
when command_execution_id is given.

Rows carry command_execution_id, beacon_id, command_name, command_arguments,
execution_status, requested_by, submitted_at, updated_at, and job_id (for
jobkill; set once the beacon reports the job started, so a task
without one cannot be stopped). Statuses completed, failed, and canceled are
terminal; in_progress has no output yet; output_received may get more.
Completed means the beacon finished, not that the command succeeded; the
execution_status_message is the latest error (at most 200 characters) or
null. The result_count and error_count count observed entries; null means
unavailable, not zero. The execution_status_note is null unless diagnostics
could not be read or, in a single lookup, the task may never have been
queued. A single lookup adds last_error_message, tactics (MITRE ATT&CK
IDs), and acknowledgements. Filters and sorting are
local; continue with next_offset.
"""

READ_COMMAND_OUTPUT = """\
Read the output of one command execution as plain text.

Each read rebuilds the text: acknowledgements, output in arrival order,
then errors prefixed [-]. A ps result is a tab-separated table headed PID,
PPID, Name, Arch, Session, User; an ls result is the folder, a Type, Size,
Modified, Name header, and one entry per line (Modified: YYYY-MM-DD
HH:MM:SS, host local time); others are one [structured <type>] JSON line;
headers count as lines. Whole lines from start_line up to max_lines are
returned; a notice gives the next start_line if more remain. Bracketed
notices (a non-completed status, the error count) do not count toward line
offsets. While the status is in_progress or output_received, new output
can shift earlier lines: page with an old start_line once the status is
terminal, else reread from line 1. A read with nothing new may wait
for a check-in due soon; else its status notice says when the beacon is
next expected (do not read before then) or what to check first.
"""

LIST_ARTIFACTS = """\
List artifacts stored on the team server for beacons to use.

A command argument references an artifact as @artifacts/name, which is the
artifact_reference each result leads with. A result carries size_bytes when
the file is visible under the artifacts directory this server shares with the
team server (artifacts.directory); Cobalt Strike itself records no size, hash,
or timestamp, so a result without size_bytes is still a usable reference.
This is a shared catalog: artifacts have no beacon ownership to filter on,
and only references beginning with @artifacts/ are listed, sorted by
reference. An artifact_reference is a file input (upload, execute-assembly,
inline-execute), not a listener or payload source; a command's help says what
each argument accepts. The listing is paged with limit and offset and
narrowed with search_regex over the reference. Add an artifact with
cs_upload_artifact.
"""

UPLOAD_ARTIFACT = """\
Get a one-time link that stores a file from the MCP client host on the team
server as a new artifact named artifact_name.

This server cannot read your files. Send the file as the body of an HTTP PUT to
url with any client you have, such as curl --fail-with-body -T <file> <url> or PowerShell
Invoke-WebRequest -Method Put -InFile <file> <url>. The response is JSON: the
artifact_reference a command argument takes, plus size_bytes and sha256,
or an error with detail and next_step. The link works once, expires five minutes
after this call at expires_at, and accepts at most max_bytes. Identical bytes
under an existing name keep that artifact; different bytes fail with HTTP 409.
Check the PUT's HTTP status and JSON body: only HTTP 201 confirms success; this
MCP call only creates the link. With --fail-with-body, curl exits nonzero on
HTTP errors and preserves the JSON error body.
"""

LIST_DOWNLOADS = """\
List files downloaded from beacons, with transfers still in progress, or get
one completed download when download_id is given.

Rows carry beacon_id, host (the beacon's hostname, only when it is listed),
remote_file_name, and remote_directory. Active rows come first with
transfer_state=in_progress, size_bytes, received_bytes, and progress
(received/size, capped at 1; null for zero size); their download_id is
null, so they cannot be fetched, and they have no downloaded_at. Reread for
progress; progress=1 does not yet mean the file is available. Completed
rows follow newest first with transfer_state=completed, progress=1,
download_id, downloaded_at, and size_bytes when Cobalt Strike records it;
they carry no hash, so only cs_fetch_download reports sha256. Set
include_active false to list completed records only. An exact download_id
ignores filters and paging. Filter by beacon_id or search_regex
and continue with next_offset; restart at offset 0 after transfers move.
"""

FETCH_DOWNLOAD = """\
Get a one-time link to fetch a download's file from Cobalt Strike to the MCP
client host.

This server cannot write to your files. Fetch url with any HTTP client you
have, such as curl -o <file> <url> or PowerShell Invoke-WebRequest -OutFile
<file> <url>, then compare the saved file with sha256. The result repeats
the download's beacon_id, host, remote_file_name, remote_directory, and
transfer_state (completed); source_filename is the name Cobalt Strike
suggested, if any.
The link works once and expires five minutes after this call at expires_at;
the staged copy is deleted from this server after the first fetch or on expiry. Only
completed downloads have fetchable IDs, so the staged bytes are the whole
file. Use cs_list_downloads for metadata alone.
"""

LIST_SCREENSHOTS = """\
List screenshots taken on beacons, or get one screenshot when screenshot_id
is given.

Each result leads with screenshot_id and carries beacon_id, hostname,
username, window_title (the captured window's title as Cobalt Strike
recorded it), and created_at. Cobalt Strike keeps no comments, tags, or
hashes for screenshots, and screenshots from a dead beacon stay listed.
Filters are applied by this server: beacon_id limits rows to one beacon and
search_regex matches window_title, hostname, and username. Listings are
newest first. Fetch the image itself with cs_fetch_screenshot.
"""

FETCH_SCREENSHOT = """\
Get a one-time link to fetch a screenshot's image from Cobalt Strike to the
MCP client host.

This server cannot write to your files. Fetch url with any HTTP client you
have, such as curl -o <file> <url> or PowerShell Invoke-WebRequest -OutFile
<file> <url>, then compare the saved file with sha256. The result repeats
the screenshot's beacon_id and created_at. The link works once and expires
five minutes after this call at expires_at; the staged copy is deleted from this
server after the first fetch or on expiry. Use cs_list_screenshots for
metadata alone.
"""

GET_TEAM_SERVER = """\
Get team server settings from Cobalt Strike as plain text: the team server
IP address, the Beacon kill date, the Malleable C2 profile, and system
information.

Use it to answer questions about the team server or to review the C2
profile; it reads configuration and tasks no beacon. Without section, the
text starts with one teamserver_ip and one kill_date line (name: value),
then the profile under a [c2_profile] heading and Cobalt Strike's support
dump (version, runtime, environment, loaded scripts) under a
[system_information] heading.
"""


# ---- Argument descriptions ---------------------------------------------------------------------

LIST_BEACONS_BEACON_ID = "Beacon ID for a single lookup. Omit to list beacons."

LIST_BEACONS_INCLUDE_DEAD = (
    "Include every beacon Cobalt Strike marks dead (alive is false, including exited). Default: "
    "false, which lists alive beacons and ones marked dead only recently."
)

LIST_COMMANDS_BEACON_ID = (
    "Limit to commands the beacon currently supports, from cs_list_beacons. Omit for the global "
    "catalog."
)

LIST_COMMANDS_COMMAND_NAME = (
    "Command name to look up, such as shell, in any letter case. Omit or leave empty to list "
    "commands."
)

COMMAND_SEARCH_CONFLICT = (
    "Use command_name for an exact lookup or search_regex for a broad search, not both."
)

LIST_COMMANDS_INCLUDE_HELP = (
    "Whether each result carries help. Default: false for a listing, true for an exact "
    "command_name lookup. Pass true to include help while listing, or false to leave it out."
)

EXECUTE_COMMAND_BEACON_ID = "ID of the beacon that runs the command, from cs_list_beacons."

EXECUTE_COMMAND_COMMAND_NAME = (
    "Command name the beacon supports, such as shell or ls, in any letter case; "
    "cs_list_commands lists them, including server-side aliases. One word: the rest of the "
    "line goes in command_arguments."
)

EXECUTE_COMMAND_COMMAND_ARGUMENTS = (
    "Each item is one literal argument; do not add quotes or escapes. Follow the parameter "
    "order in the command's help: each leading parameter is one single-word item, and a "
    "trailing command line, path, or free text is the remaining items joined with single "
    'spaces, so ["cmd.exe /c dir"] and ["cmd.exe", "/c", "dir"] send shell the same line '
    'and ["C:\\Program Files"] reaches ls as one path. Builtins without a '
    "verified layout accept only single-word items without whitespace, quotes, or control "
    "characters. A user-defined (script) command takes one item per word; an item with "
    "spaces is double-quoted for the console, which an alias that reads its raw line sees. "
    "A rejected item's error states what the command takes. Help still decides required "
    "arguments and valid options; trailing items may be omitted where the command allows "
    "it. Use an artifact_reference from cs_list_artifacts as one item for a file input. "
    "Omit for no arguments."
)

LIST_COMMAND_EXECUTIONS_COMMAND_EXECUTION_ID = (
    "Execution (task) ID for a single lookup. Omit to list executions."
)

LIST_COMMAND_EXECUTIONS_BEACON_ID = (
    "Only executions on this beacon. This is a filter: no matches returns an empty page, "
    "including for an unknown ID. Use cs_list_beacons(beacon_id=...) to check existence. "
    "Ignored for a single-ID lookup."
)

LIST_COMMAND_EXECUTIONS_ORDER_BY = (
    "Sort fields in priority order: id, submitted_at, or updated_at; prefix with - for "
    "descending. Omit for newest submissions first (-submitted_at, -id). Each field may appear "
    "once; the server adds id as a tie-breaker if absent. Ignored for a single-ID lookup."
)

LIST_COMMAND_EXECUTIONS_STATUS = (
    "Only executions whose current execution_status equals this value (Cobalt Strike's task "
    "status, lowercased). Omit for all statuses. Ignored for a single-ID lookup."
)

LIST_COMMAND_EXECUTIONS_SINCE = (
    "Only executions submitted at or after this ISO 8601 timestamp, including a timezone "
    "(for example, 2026-09-25T00:00:00Z). Filters submitted_at, not updated_at. "
    "Omit for no time cutoff. Ignored for a single-ID lookup."
)

EXECUTION_ORDER_BY_DUPLICATE = "Each field may appear only once in order_by"

EXECUTION_ORDER_BY_UNSUPPORTED = "Unsupported order_by value {item!r}. Use one of {allowed}."

READ_COMMAND_OUTPUT_COMMAND_EXECUTION_ID = (
    "ID of the execution to read, from the cs_execute_command receipt or "
    "cs_list_command_executions."
)

READ_COMMAND_OUTPUT_START_LINE = (
    "1-based line to start reading at. Default: 1. Use the start_line from a continuation notice "
    "to read on."
)

READ_COMMAND_OUTPUT_MAX_LINES = "Maximum lines to return. Default: {default}. Max: {max}."

UPLOAD_ARTIFACT_ARTIFACT_NAME = (
    "File name to store the artifact under, without directories, such as stage.ps1. It is "
    "referenced as @artifacts/<name>."
)

LIST_DOWNLOADS_DOWNLOAD_ID = (
    "Completed download ID for a single lookup. Omit to list active and completed downloads."
)

LIST_DOWNLOADS_BEACON_ID = (
    "Only downloads from this beacon. This is a filter: no matches returns an empty page, "
    "including for an unknown ID. Use cs_list_beacons(beacon_id=...) to check existence. "
    "Ignored for a download_id lookup."
)

LIST_DOWNLOADS_INCLUDE_ACTIVE = (
    "Include active transfer progress. Default: true. Reads progress for the selected beacon "
    "or all known beacons, including dead ones, with bounded concurrent requests. A failed "
    "scan returns an error instead of an incomplete page; set false to list completed files "
    "only. Ignored for an exact download_id lookup."
)

FETCH_DOWNLOAD_DOWNLOAD_ID = (
    "ID of a completed download, from cs_list_downloads; active rows have no ID and cannot be "
    "fetched."
)

LIST_SCREENSHOTS_SCREENSHOT_ID = "Screenshot ID for a single lookup. Omit to list screenshots."

LIST_SCREENSHOTS_BEACON_ID = (
    "Only screenshots from this beacon. This is a filter: no matches returns an empty page, "
    "including for an unknown ID. Use cs_list_beacons(beacon_id=...) to check existence. "
    "Ignored for a screenshot_id lookup."
)

FETCH_SCREENSHOT_SCREENSHOT_ID = "ID of the screenshot, from cs_list_screenshots."

GET_TEAM_SERVER_SECTION = (
    "One setting to return verbatim: teamserver_ip, kill_date, c2_profile, or "
    "system_information. Omit for all four in one text."
)


# ---- Shared argument descriptions --------------------------------------------------------------

OFFSET = (
    "Rows to skip before the page. Default: 0. Pass the previous page's next_offset to continue."
)

LIST_LIMIT = "Rows to return in one offset page. Default: {default}. Max: {ceiling}."

SEARCH_REGEX = (
    "Python regex matched against {fields}; a match in any field includes the row. Prefix (?i) "
    "to ignore case. At most {max_chars} characters. {suffix}"
)

SEARCH_REGEX_LOOKUP_SUFFIX = "Ignored for a single-ID lookup."

SEARCH_REGEX_COMMAND_SUFFIX = "Cannot be combined with command_name."

COMMAND_SEARCH_FIELDS: Mapping[str, str] = {
    "command_name": "command name",
    "description": "description",
    "help": "help text",
}

EXECUTION_SEARCH_FIELDS: Mapping[str, str] = {
    "command_name": "command name",
    "command_arguments": "command arguments",
    "requested_by": "requesting user",
}

ARTIFACT_SEARCH_FIELDS: Mapping[str, str] = {
    "artifact_reference": "reference",
}

DOWNLOAD_SEARCH_FIELDS: Mapping[str, str] = {
    "remote_file_name": "file name",
    "remote_directory": "remote directory",
    "host": "host",
}

SCREENSHOT_SEARCH_FIELDS: Mapping[str, str] = {
    "window_title": "window title",
    "hostname": "hostname",
    "username": "username",
}


# ---- Output schema field descriptions ----------------------------------------------------------

TRUNCATION_DESCRIPTION = (
    "Present when the response ceiling shaped this result: the reason, the rows that continue at "
    "next_offset, any shortened free-text fields, and what to do next."
)

TIMESTAMP_DESCRIPTION = "UTC, ISO 8601 with a Z suffix."

LIST_PAGE_NEXT_OFFSET = "Pass as offset to read the next page; null on the last page."

LIST_PAGE_TOTAL_RECORDS = "Rows that matched the request before paging."

LIST_PAGE_LIMIT_CLAMPED_TO = (
    "The page size used when the requested limit was over the server ceiling; otherwise null."
)

EXECUTION_OBSERVATION_EXECUTION_STATUS = (
    "Cobalt Strike task status, lowercased: in_progress, output_received, completed, failed, or "
    "canceled. A completed task can still have reported errors."
)

EXECUTION_OBSERVATION_STATUS_NOTE = (
    "Null unless something needs attention: the beacon is dead, the status could not be read "
    "or is not one this server recognizes, or the task may never have been queued."
)

EXECUTION_LIST_PAGE_STATUS_NOTE = (
    "Null unless some rows' diagnostics could not be read, which leaves their counts null."
)

EXECUTION_OBSERVATION_STATUS_MESSAGE = (
    "Latest nonblank reported task error, with whitespace folded and capped at 200 characters. "
    "Null means no error message was available; a completed task can still have errors."
)

EXECUTION_OBSERVATION_UPDATED_AT = (
    "Latest change Cobalt Strike recorded, UTC with a Z suffix; null until the task is touched "
    "after creation."
)

EXECUTION_ROW_RESULT_COUNT = "Observed output entries, or null when unavailable."

EXECUTION_ROW_ERROR_COUNT = "Observed error entries, or null when unavailable, not zero."

EXECUTION_ROW_JOB_ID = (
    "Cobalt Strike job ID of a long-running task, which the jobkill command takes; null until "
    "the beacon reports the job started, or for a task without a job."
)

BEACON_ROW_IS_ADMIN = (
    "True when the beacon process holds an elevated (high-integrity) token, the * Cobalt Strike "
    "shows after a username; a local administrator with a UAC-filtered token is false."
)

EXECUTION_RECEIPT_COMMAND_ARGUMENTS = (
    "The encoded console argument line sent to Cobalt Strike, in the form execution rows report."
)

EXECUTION_RECEIPT_SUBMITTED_ARGUMENTS = (
    "The original command_arguments array supplied by the caller, before encoding. Empty when "
    "input arguments were omitted or null. Available only on the submission receipt; Cobalt "
    "Strike history retains only the encoded line."
)

REJECTION_DETAIL_CODE = (
    "invalid_argument, command_not_permitted, unsupported_command, ambiguous_command, "
    "help_unavailable, no_task_created, approval_declined, approval_canceled, "
    "approval_unavailable, or approval_failed when this server refused the "
    "submission; a Cobalt Strike failure code such as invalid_request, not_found, or "
    "transport_error when a request before or at submission failed."
)

REJECTION_DETAIL_RULE = (
    "The policy rule behind a refusal; present only for policy and approval decisions."
)

COMMAND_REJECTION_SUBMISSION_OUTCOME = (
    "not_submitted when this server refused it before anything reached Cobalt Strike, "
    "rejected when Cobalt Strike refused it, uncertain when Cobalt Strike did not answer and "
    "it may have queued."
)

BEACON_RECORD_OS_VERSION = (
    "What Windows reports to a program without a compatibility manifest, so 6.2 and 9200 can "
    "mean Windows 10 or later."
)

DOWNLOAD_RECORD_REMOTE_DIRECTORY = (
    "Directory on the remote system the file was read from, without a trailing separator."
)

DOWNLOAD_RECORD_TRANSFER_STATE = (
    "completed for a file Cobalt Strike finished receiving, in_progress for a transfer still "
    "arriving. Read from the download records alone, never from execution status."
)

ACTIVE_DOWNLOAD_RECORD_DOWNLOAD_ID = (
    "Active transfers have no completed-download ID and cannot be fetched. "
    "List again until the completed record supplies a download_id."
)

ACTIVE_DOWNLOAD_RECORD_PROGRESS = (
    "Fraction of reported bytes received, from 0 to 1; null when size_bytes is zero. "
    "A value of 1 on an active row does not establish completion or fetchability."
)

FILE_TRANSFER_URL = "Single-use link on this MCP server; GET it to fetch the file."

FILE_TRANSFER_SHA256 = "Hex SHA-256 of the file, to compare after fetching."

FILE_TRANSFER_SOURCE_FILENAME = "File name the link serves: Cobalt Strike's suggestion, if any."

ARTIFACT_UPLOAD_LINK_URL = "Single-use link on this MCP server; PUT the file's bytes to it."

ARTIFACT_UPLOAD_LINK_MAX_BYTES = "Largest file the link accepts."


# ---- Cobalt Strike failures reported by any tool -----------------------------------------------

UNCERTAIN_NEXT_STEP = "Retry later, and check the resource first if this call changes it."

CORRECT_REQUEST_NEXT_STEP = "Correct the request before retrying."

NEXT_STEP_BY_HTTP_STATUS: Mapping[int, str] = {
    400: CORRECT_REQUEST_NEXT_STEP,
    401: (
        "Cobalt Strike rejected the service account credentials this MCP server holds. Ask the "
        "user to check the Cobalt Strike username and password in the MCP server config."
    ),
    403: "The Cobalt Strike service account is not allowed to do this. Ask the user before retrying.",
    404: "Check the identifier, or list the resource to find one that exists.",
    409: "The resource changed. Read it again before retrying.",
    422: CORRECT_REQUEST_NEXT_STEP,
    429: "Cobalt Strike is rate limiting requests. Wait before retrying.",
}

CS_REQUEST_FAILED = "Cobalt Strike request failed: {detail}"

CS_NO_ANSWER = "Cobalt Strike did not answer ({exception})"

NOT_FOUND_WITHOUT_DETAIL = "nothing found for {argument} {value}"

IDENTIFIER_FAILURE_NEXT_STEP = (
    "Check {argument} against {list_tool}() and follow next_offset if needed."
)

SEARCH_VALIDATION_NEXT_STEP = (
    "Correct, shorten, or simplify search_regex as a Python regular expression and retry."
)

ACTIVE_DOWNLOADS_FAILED_NEXT_STEP = (
    "The active-download scan failed, so no combined page was returned. "
    "Set include_active=false to list completed downloads without scanning active transfers. "
    "Check the upstream error before retrying the active scan."
)


# ---- Local lookups -----------------------------------------------------------------------------

RESOURCE_NOT_FOUND = "No record has {field}={value!r}."

DUPLICATE_IDENTIFIER = (
    "Cobalt Strike returned multiple records with {field}={value!r}; inspect the records in the "
    "Cobalt Strike client before retrying."
)

TASK_NOT_FOUND = "No task with ID {task_id} is currently visible in Cobalt Strike."

TASK_NOT_FOUND_NEXT_STEP = (
    "If this ID came from an accepted cs_execute_command receipt, retry the lookup after a few "
    "seconds (Cobalt Strike lists a new task shortly after accepting it); do not resubmit the "
    "command. Otherwise check command_execution_id against cs_list_command_executions() and "
    "follow next_offset."
)

MALFORMED_TASK_NOT_FOUND = (
    "No task has ID {task_id!r}: Cobalt Strike task IDs are a hexadecimal task number, a "
    "hyphen, and the decimal beacon ID, such as 1a2b3c4d5e6f7a8b-123456789."
)

MALFORMED_TASK_NOT_FOUND_NEXT_STEP = (
    "Check command_execution_id against cs_list_command_executions() and follow next_offset, "
    "then pass the ID exactly as listed; do not resubmit the command."
)


# ---- Command selection and policy --------------------------------------------------------------

COMMAND_CATALOG_CALL = "cs_list_commands(beacon_id={beacon_id!r})"

COMMAND_CATALOG_CALL_GLOBAL = "cs_list_commands()"

COMMAND_SUBCOMMANDS_DESCRIPTION = "Subcommands: {names}"

COMMAND_SUBCOMMAND_HELP_LINE = "{name}: {description}"

COMMAND_NOT_PERMITTED = "Command {command_name!r} is not permitted by the MCP command policy"

COMMAND_NOT_PERMITTED_NEXT_STEP = (
    "This refusal is final: do not resubmit the command or send the same command line through "
    "another command. Commands cs_list_commands lists stay available."
)

COMMAND_NOT_PERMITTED_LOOKUP_NEXT_STEP = (
    "This refusal is final: cs_execute_command refuses the command too, so do not submit it or "
    "send the same command line through another command. Commands cs_list_commands lists stay "
    "available."
)

SCOPE_BEACON = "beacon {beacon_id}"

SCOPE_GLOBAL_CATALOG = "the global command catalog"

COMMAND_UNAVAILABLE = "Command {command_name!r} is not available in {scope}"

FIND_AVAILABLE_COMMAND_NEXT_STEP = "Call {catalog_call} to find an available command"

COMMAND_AMBIGUOUS = "More than one catalog command matches {command_name!r}."

COMMAND_AMBIGUOUS_NEXT_STEP = "Read {catalog_call} and use the exact command_name."

HELP_UNAVAILABLE = (
    "Cobalt Strike published no console help for beacon {beacon_id} (alive: {alive}), so no "
    "command can be verified for it."
)

HELP_UNAVAILABLE_COMMAND = " Command {command_name!r} was not verified."

HELP_UNAVAILABLE_NEXT_STEP = (
    "Check the beacon with cs_list_beacons(beacon_id={beacon_id!r}). If it is dead, wait for it "
    "to check in or choose another beacon; if it is alive, ask the user to run the command from "
    "the Cobalt Strike client."
)

NO_TASK_CREATED = "Cobalt Strike answered {status}: {message} and created no task."

NO_TASK_CREATED_NEXT_STEP = (
    "Read the message. If it reports a syntax or argument problem, correct command_arguments "
    "using cs_list_commands(beacon_id=..., command_name=...) and resubmit. Otherwise do not "
    "resubmit: a command Cobalt Strike completes on the team server (such as note or help) "
    "ends this way and has no output."
)

SUBMISSION_REJECTED_NEXT_STEP = (
    "Correct the request before submitting again. The command's help, from "
    "cs_list_commands(beacon_id=..., command_name=...), gives its arguments and any technique "
    "list."
)

SUBMISSION_REJECTED_HISTORY_NOTE = (
    "Cobalt Strike may still list this rejected request as an in_progress execution that "
    "never runs; such a row is not evidence the command was queued, and it cannot be canceled."
)

COMMAND_TECHNIQUES_HEADER = (
    "Techniques Cobalt Strike currently offers as the first item (typing {command_name} alone "
    "lists nothing through this API):"
)

COMMAND_TECHNIQUE_LINE = "{name}: {description}"

COMMAND_TECHNIQUE_LINE_ARCH = "{name} ({arch}): {description}"

COMMAND_TECHNIQUES_NONE = "Cobalt Strike currently offers no techniques for {command_name}."

COMMAND_TECHNIQUES_UNAVAILABLE = (
    "The techniques {command_name} accepts as its first item could not be read from Cobalt "
    "Strike; repeat this lookup before submitting."
)

COMMAND_LISTENERS_HEADER = (
    "The listener argument takes a listener name (or @listener:<name>). Listeners Cobalt "
    "Strike currently defines:"
)

COMMAND_LISTENER_LINE = "{name}: {payload}"

COMMAND_LISTENER_ERROR = " (listener error: {error})"

COMMAND_LISTENERS_NONE = (
    "Cobalt Strike currently defines no listeners, so this command cannot run yet; ask the user "
    "to create one in the Cobalt Strike client before submitting."
)

COMMAND_LISTENERS_UNAVAILABLE = (
    "The listeners the listener argument accepts could not be read from Cobalt Strike; repeat "
    "this lookup before submitting."
)

COMMAND_PAYLOAD_STORE_NOTE = (
    "The @payload:<name> form names an item in the Cobalt Strike payload store, which no tool "
    "here lists, so do not guess one. An @artifacts/ reference from cs_list_artifacts, a file "
    "under @artifacts/payloads/ included, is a file input and is not accepted as this argument."
)

COMMAND_PAYLOAD_STORE_SHELLCODE_NOTE = (
    "The @payload:<name> form names an item in the Cobalt Strike payload store, which no tool "
    "here lists, so do not guess one; pass an @artifacts/ reference to a shellcode file from "
    "cs_list_artifacts instead."
)

SUBMISSION_UNCERTAIN_NEXT_STEP = (
    "Check command execution history with cs_list_command_executions for the beacon; if a "
    "matching execution exists, read it with cs_read_command_output instead of resubmitting."
)

APPROVAL_FAILURE_CODE = "approval_{outcome}"

APPROVAL_FAILURE_MESSAGE = "Command approval {outcome}"

APPROVAL_DECLINED_NEXT_STEP = "The user declined. Do not resubmit unless the user asks again."

APPROVAL_CANCELED_NEXT_STEP = (
    "The user dismissed the prompt without deciding. Ask before resubmitting."
)

APPROVAL_UNAVAILABLE_NEXT_STEP = (
    "This MCP client cannot show approval prompts, so commands that need approval cannot run "
    "from it. Do not send the same command line through another command. Tell the user; they "
    "can use a client with MCP elicitation or list the command under commands.allow in the MCP "
    "server config."
)

APPROVAL_SUMMARY = """\
Command:   {command_name}
Arguments: {arguments}"""

APPROVAL_ARGUMENTS_NONE = "none"

APPROVAL_ARGUMENTS_MULTILINE = "[multi-line, expand to read all] "

APPROVAL_ARGUMENTS_TRUNCATED = "\n[Arguments truncated after 2,000 characters]"


# ---- Approval transport errors -----------------------------------------------------------------

APPROVAL_RETRY_NEXT_STEP = (
    "Nothing was submitted. Ask the user whether to submit the command again."
)

APPROVAL_UNEXPECTED_RESPONSE = "The approval prompt returned an unexpected answer"

APPROVAL_PROMPT_ERROR = "The MCP client answered the approval prompt with an error"

APPROVAL_INVALID_STATE = "The approval state the client returned is invalid"

APPROVAL_EXPIRED = "The approval is no longer pending or was already used"

APPROVAL_COMMAND_CHANGED = "The selected command changed after the approval prompt"

APPROVAL_MISSING_RESPONSE = "The client returned no valid approval answer"

APPROVAL_NO_PENDING_REQUEST = "The client sent an approval answer with no pending prompt"

APPROVAL_TOO_MANY_PENDING = "Too many approval prompts are waiting for an answer"

APPROVAL_TOO_MANY_PENDING_NEXT_STEP = (
    "Nothing was submitted. Tell the user that too many approval prompts are open; submit again "
    "only after they are answered or the server is restarted."
)


# ---- Tool errors about Cobalt Strike responses -------------------------------------------------

CS_RESPONSE_UNREADABLE_NEXT_STEP = (
    "Retry once; if it fails again, stop and tell the user that Cobalt Strike sent a response "
    "this server cannot read."
)

INVALID_RESPONSE = "Cobalt Strike returned an invalid response"

INVALID_RESPONSE_TYPE = "Cobalt Strike response must be a {expected}"

INVALID_JSON = "Cobalt Strike returned invalid JSON"

INVALID_LOGIN_RESPONSE = "Cobalt Strike returned a login response without an access token"

INVALID_COMMAND_RESPONSE = "Cobalt Strike returned an invalid command response"

INVALID_TASK_ID = "Cobalt Strike returned an invalid task ID"

TASK_ID_MISMATCH = "Cobalt Strike returned a different task ID"

INVALID_TASK_ENTRIES = "Cobalt Strike returned invalid task entries"

INVALID_TEAMSERVER_IP = "Cobalt Strike returned an invalid team server IP"

RECORD_WITHOUT_FIELD = "Cobalt Strike record is missing {field}"

INVALID_BEACON_SLEEP = "Cobalt Strike returned invalid beacon sleep data"

INVALID_ACTIVE_DOWNLOAD_BYTES = "Cobalt Strike returned invalid active download byte counts"

PLAIN_TEXT_OVER_CEILING = (
    "Output exceeds limits.max_response_chars ({max_chars} characters). Ask the user to raise "
    "limits.max_response_chars in the MCP server config or to inspect the output in the Cobalt "
    "Strike client."
)


# ---- Execution status notes --------------------------------------------------------------------

EXECUTION_STATUS_UNKNOWN = (
    "Cobalt Strike reported the unrecognized task status {status}; treat it as not terminal "
    "and read output with cs_read_command_output."
)

EXECUTION_NEVER_QUEUED = (
    "Cobalt Strike recorded this task but never queued it: the beacon has checked in since "
    "(last at {last_seen_at}) and the task still has no tasking acknowledgement, which every "
    "queued builtin gets within seconds. It will stay in_progress and cannot be canceled; do "
    "not wait for it. Check the arguments against cs_list_commands(beacon_id={beacon_id!r}, "
    "command_name={command_name!r}) before submitting a corrected command."
)

EXECUTION_UNACKNOWLEDGED = (
    "Cobalt Strike has not recorded a tasking acknowledgement for this task yet; every queued "
    "builtin gets one within seconds of its task row. Read it with cs_read_command_output, "
    "which waits for the beacon's next check-in when it is near and names a task that was "
    "never queued."
)

EXECUTION_UNANSWERED = (
    "The beacon has checked in since this task was created (last at {last_seen_at}) and "
    "returned nothing for it, so Cobalt Strike may have recorded the task without queuing it; "
    "a user-defined command that needs the Cobalt Strike client's own dialog ends this way. "
    "If the next check-in brings nothing either, treat it as never queued: it will stay "
    "in_progress and cannot be canceled. Check the arguments against "
    "cs_list_commands(beacon_id={beacon_id!r}, command_name={command_name!r}) before "
    "submitting a corrected command."
)

RECEIPT_BEACON_DEAD = (
    "Beacon {beacon_id} is marked dead{age}, so this task waits for a check-in that may never "
    "come. Check cs_list_beacons(beacon_id={beacon_id!r}) before polling."
)

RECEIPT_BEACON_DEAD_RECENT = (
    "Beacon {beacon_id} missed its expected check-in{age}, which Cobalt Strike reports as dead; "
    "a beacon running a long task cannot check in until it finishes, so it may only be busy. "
    "Read output with cs_read_command_output, and check cs_list_beacons(beacon_id={beacon_id!r}) "
    "if it stays dead for minutes."
)

RECEIPT_BEACON_DEAD_AGE = " (last check-in {age} ago)"

EXECUTION_DIAGNOSTICS_UNAVAILABLE = (
    "Some task diagnostics were unavailable. Null counts do not mean zero errors or output. "
    "Read the affected command_execution_id with cs_list_command_executions to retry the lookup."
)

RECEIPT_STATUS_UNAVAILABLE = (
    "Task status could not be read within a few seconds of submission. Check "
    "cs_list_command_executions(command_execution_id=...) shortly to see it. This accepted "
    "command must not be resubmitted just because status is unavailable."
)


# ---- Command output reads ----------------------------------------------------------------------

OUTPUT_PS_HEADER = "PID\tPPID\tName\tArch\tSession\tUser"

OUTPUT_LS_HEADER = "Type\tSize\tModified\tName"

OUTPUT_STRUCTURED = "[structured {type}] {json}"

TEAM_SERVER_LINE = "{name}: {value}"

TEAM_SERVER_BLOCK = "[{name}]\n{value}"

OUTPUT_EXECUTION_STATUS = "[Task status: {status}]"

OUTPUT_EXECUTION_STATUS_FORECAST = "[Task status: {status}. {forecast}]"

OUTPUT_ERRORS_REPORTED = "[Errors reported: {count}]"

OUTPUT_CONTINUATION = "[More output available. Read again with start_line={continuation}.]"

OUTPUT_LINE_SUBJECT = "Output line {line_number} and required notices"

OUTPUT_NOTICES_SUBJECT = "Required notices"

OUTPUT_OVER_CEILING = (
    "{subject} exceed limits.max_response_chars ({max_page_chars} characters). Reducing "
    "max_lines cannot fix a single oversized line: ask the user to raise "
    "limits.max_response_chars in the MCP server config or to inspect the output in the Cobalt "
    "Strike client."
)

OUTPUT_READ_TIMEOUT = (
    "Command output read exceeded its {read_timeout_seconds:g}-second deadline. Retry once with "
    "a smaller max_lines; if it times out again, tell the user that Cobalt Strike is answering "
    "too slowly."
)

OUTPUT_EMPTY = "No output is available."

OUTPUT_PAST_END = (
    "The requested start_line {start_line} is past the current end of output ({observed} {unit})."
)

OUTPUT_NEXT_CHECKIN = (
    "The beacon's next check-in is expected by {expected_at} (sleep {sleep_seconds:g}s; last "
    "check-in {last_seen_at})."
)

OUTPUT_BEACON_LATE = (
    "The beacon is overdue: its last check-in was {last_seen_at} on a {sleep_seconds:g}s sleep. "
    "A beacon running a task cannot check in until it finishes, so it may only be busy. Read "
    "again shortly, and check cs_list_beacons(beacon_id={beacon_id!r}) if it stays overdue."
)

OUTPUT_BEACON_DEAD = (
    "Beacon {beacon_id} is marked dead{age}, so output may never arrive. Check "
    "cs_list_beacons(beacon_id={beacon_id!r}) before reading again."
)

OUTPUT_BEACON_DEAD_RECENT = (
    "Beacon {beacon_id} missed its expected check-in{age}, which Cobalt Strike reports as dead; "
    "a beacon running a long task cannot check in until it finishes, so it may only be busy. "
    "Read again shortly, and check cs_list_beacons(beacon_id={beacon_id!r}) if it stays dead "
    "for minutes."
)

OUTPUT_BEACON_UNLISTED = (
    "Beacon {beacon_id} is no longer listed by Cobalt Strike, so this task will never be "
    "delivered. Do not read again; check cs_list_beacons for a live beacon before resubmitting."
)

OUTPUT_CHECKIN_UNKNOWN = (
    "The beacon's next check-in time could not be read. Check "
    "cs_list_beacons(beacon_id={beacon_id!r}) for its sleep_seconds and last check-in before "
    "reading again."
)

OUTPUT_STATUS_UNKNOWN = "unknown"


# ---- Response ceilings -------------------------------------------------------------------------

LISTING_SPLIT_NEXT_STEP = (
    "The omitted rows continue at next_offset: repeat this call with offset set to next_offset. A "
    "smaller limit can keep the response under the ceiling."
)

LISTING_LONE_ROW_SHORTENED = (
    "This row alone is over the ceiling, so its listed fields were cut to field_char_limit "
    "characters; every other field is complete."
)

LISTING_LONE_ROW_WHOLE = (
    "This row alone is over the ceiling and has no free text to cut, so it is sent whole."
)

RESULT_SHORTENED_NEXT_STEP = (
    "The listed fields were cut to field_char_limit characters; every other field is complete. A "
    "larger limits.max_response_chars in the server config shows more."
)

RESULT_EXCEEDS_NEXT_STEP = (
    "The result is over the ceiling even with its free text cut to the floor, so it is sent whole; "
    "an MCP client with a smaller cap may cut it further."
)


# ---- File links --------------------------------------------------------------------------------

NEW_LINK_NEXT_STEP = "Call cs_upload_artifact again for a new link."

ARTIFACT_NAME_INVALID = "The artifact_name must be a file name such as payload.bin."

ARTIFACT_NAME_HAS_DIRECTORIES = (
    "The artifact_name must be a bare file name without directories; got {candidate!r}."
)

UPLOAD_EMPTY_BODY = "The upload body was empty."

UPLOAD_EMPTY_BODY_NEXT_STEP = "Send a non-empty file, then {new_link}"

UPLOAD_DECLARED_SIZE = "The file is {declared_length:,} bytes"

UPLOAD_OVER_LIMIT = "The file is larger than the limit"

UPLOAD_TOO_LARGE = "{measured}; limits.max_upload_bytes allows {max_bytes:,}."

UPLOAD_TOO_LARGE_NEXT_STEP = (
    "Upload a smaller file or raise limits.max_upload_bytes on the MCP server, then {new_link}"
)

UPLOAD_LINK_UNKNOWN = "Unknown, expired, or already used upload link."

UPLOAD_CONFLICT = "An artifact named {name!r} already exists with different content."

UPLOAD_CONFLICT_NEXT_STEP = (
    "Call cs_upload_artifact with another name, or use cs_list_artifacts to inspect the existing "
    "one."
)

UPLOAD_STORE_FAILED = "Could not store the file under {directory}: {reason}."

UPLOAD_STORE_FAILED_NEXT_STEP = (
    "Retry once; if it fails again, tell the user to check artifacts.directory in the MCP server "
    "config."
)

UPLOAD_NOT_LISTED_NOTICE = (
    "Cobalt Strike did not list this artifact right after the write. Check cs_list_artifacts "
    "before using the reference; if it stays missing, tell the user to check that "
    "artifacts.directory is the team server's restapi/artifacts directory."
)

TRANSFER_LINK_UNKNOWN = "Unknown, expired, or already fetched transfer link"

TRANSFER_LINK_NEXT_STEP = "Call cs_fetch_download or cs_fetch_screenshot again for a new link."

TRANSFER_VANISHED = "The {resource} vanished between listing and fetch; list again."

TRANSFER_VANISHED_NEXT_STEP = "Call {list_tool} to find an available record before fetching again."

STAGING_FAILED = (
    "Could not stage the file: {reason}. Retry once; if it fails again, tell the user that the "
    "MCP server cannot write staged files."
)

STAGED_LENGTH_MISMATCH = (
    "Cobalt Strike announced {announced} bytes but sent {written}; nothing was staged. Retry the "
    "transfer."
)


# ---- Argument validation -----------------------------------------------------------------------

ARGUMENTS_REJECTED = "The arguments do not match the tool's input schema: {problems}"

ARGUMENTS_REJECTED_NEXT_STEP = (
    "Correct the named arguments to match the tool's input schema before retrying."
)

INVALID_IDENTIFIER = (
    "The {argument} must be a nonblank identifier other than '.' or '..'. Correct the request."
)

API_IDENTIFIER_INVALID = "An API identifier is empty or invalid"

COMMAND_NAME_INVALID = (
    "The command_name must be a single command word such as shell; cs_list_commands lists them."
)

OFFSET_INVALID = "The offset must be 0 or greater."

INVALID_SEARCH_REGEX = (
    "The search_regex is not a valid Python regular expression ({error}). Correct it and retry."
)

SEARCH_REGEX_TOO_LONG = (
    "The search_regex is {length} characters long; the limit is {max_chars}. Shorten the pattern "
    "and retry."
)

SEARCH_REGEX_TOO_SLOW = (
    "The search_regex took longer than {seconds:g} seconds to match against the records, so the "
    "filter was abandoned. Simplify the pattern (avoid nested or overlapping repeats such as "
    "(a|aa)+) and retry."
)


# ---- Command argument layouts ------------------------------------------------------------------

_JOINED = "in one item or several joined with spaces"
_WHOLE_COMMAND_LINE = f"the command line, {_JOINED}"
_WHOLE_POWERSHELL = f"the PowerShell command, {_JOINED}"
_WHOLE_PATH = f"the path, {_JOINED}"
_ARTIFACT_REFERENCE = "an artifact reference from cs_list_artifacts"
_SOURCE_DESTINATION = "exactly two path items: the source, then the destination"

COMMAND_ARGUMENT_LAYOUTS: Mapping[str, str] = {
    "shell": _WHOLE_COMMAND_LINE,
    "run": _WHOLE_COMMAND_LINE,
    "execute": _WHOLE_COMMAND_LINE,
    "powershell": _WHOLE_POWERSHELL,
    "powerpick": _WHOLE_POWERSHELL,
    "note": f"the note text, {_JOINED}",
    "execute-assembly": f"an artifact reference, then the assembly's argument line, {_JOINED}",
    "inline-execute": f"an artifact reference, then the BOF argument string, {_JOINED}",
    "beacon-interpreter": (
        f"a script reference, then the argument line in BOF-pack format, {_JOINED}"
    ),
    "argue": (
        f"a program name, then the fake argument line, {_JOINED}; omit it to stop spoofing "
        "that program"
    ),
    "setenv": f"a variable name, then the value, {_JOINED}; omit it to unset the variable",
    "runu": f"a parent PID, then {_WHOLE_COMMAND_LINE}",
    "psinject": f"a PID and an architecture (x86 or x64), then {_WHOLE_POWERSHELL}",
    "remote-exec": f"a method and a target, then {_WHOLE_COMMAND_LINE}",
    "runas": f"a DOMAIN\\user and a password, then {_WHOLE_COMMAND_LINE}",
    "spawnas": "a DOMAIN\\user and a password, then the listener or payload reference",
    "ls": f"the folder path, {_JOINED}; a file's path is reported not found even when it exists",
    "cd": _WHOLE_PATH,
    "download": _WHOLE_PATH,
    "mkdir": _WHOLE_PATH,
    "rm": _WHOLE_PATH,
    "upload": (
        f"{_ARTIFACT_REFERENCE}; the file is written to the beacon's current working directory "
        "under its own name, so cd there first or cp or mv it afterwards"
    ),
    "powershell-import": _ARTIFACT_REFERENCE,
    "kerberos_ticket_use": _ARTIFACT_REFERENCE,
    "cancel": f"the download file name or wildcard pattern, {_JOINED}",
    "spawnto": f"an architecture (x86 or x64), then the executable path, {_JOINED}",
    "dllload": f"a PID, then the DLL path, {_JOINED}",
    "cp": _SOURCE_DESTINATION,
    "mv": _SOURCE_DESTINATION,
    "timestomp": "exactly two path items: the file to change, then the file whose times it copies",
    "reg": (
        "query, an architecture (x86 or x64), and a key path; or queryv, an architecture, a key "
        "path, and a single-word value name. Other subcommands accept plain tokens only"
    ),
}

COMMAND_LAYOUT_HELP = "Through cs_execute_command, command_arguments takes {layout}."

COMMAND_ARGUMENTS_LAYOUT = (
    "{command_name} takes {layout}. Put a value that contains spaces in one item rather than one "
    "item per word, and do not add console quotes."
)

COMMAND_ARGUMENTS_WORD = (
    "Cannot encode a {command_name} argument exactly: Cobalt Strike splits that position at "
    "whitespace and has no quoting for it, so it must be one nonempty word without spaces, "
    "quotes, or control characters. {command_name} takes {layout}."
)

COMMAND_ARGUMENTS_UNSAFE_PATH = (
    "Cannot encode a path for {command_name} exactly: provide a nonempty path without double "
    "quotes or control characters and, except for cp, mv, and timestomp, without leading or "
    "trailing whitespace. Do not add console quotes yourself."
)

COMMAND_ARGUMENTS_EMPTY = (
    "{command_name} has an empty argument-line item; omit that item if there is no text to pass."
)

COMMAND_ARGUMENTS_NUL = (
    "{command_name} cannot pass a NUL byte in console text; remove it before retrying."
)

COMMAND_ARGUMENTS_PLAIN_ONLY = (
    "Cannot encode an argument for {command_name} exactly: this command has no verified quoting "
    "rule, so every item must be one word without spaces, quotes, or control characters. Pass "
    'one item per word, such as ["account", "name"] rather than ["account name"], and do not '
    "add console quotes yourself. A single value that must contain a space cannot be passed to "
    "this command."
)

COMMAND_ARGUMENTS_SCRIPT_UNSAFE = (
    "Cannot encode an argument for {command_name} exactly: an item for a user-defined command "
    "must contain no double quotes or control characters. An item may contain spaces; this "
    "server double-quotes it for the console. Do not add console quotes yourself."
)


# ---- Failure text composition ------------------------------------------------------------------

HTTP_FAILURE = "HTTP {status}"

HTTP_FAILURE_REASON = " {reason}"

HTTP_FAILURE_DETAIL = ": {detail}"

SELECTION_ERROR_TEXT = "{message}. {next_step}"
