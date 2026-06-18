"""Native document extraction helpers for downloaded files."""

from __future__ import annotations

import io
import os
import posixpath
import zipfile
from dataclasses import dataclass
from xml.etree import ElementTree

DOCX_EXTENSIONS = {".docx"}
XLSX_EXTENSIONS = {".xlsx", ".xlsm"}
UNSUPPORTED_DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".xls"}
SUPPORTED_DOCUMENT_EXTENSIONS = DOCX_EXTENSIONS | XLSX_EXTENSIONS
DOCUMENT_EXTENSIONS = SUPPORTED_DOCUMENT_EXTENSIONS | UNSUPPORTED_DOCUMENT_EXTENSIONS
DOCUMENT_CONTENT_TYPE_EXTENSIONS = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.ms-excel.sheet.macroenabled.12": ".xlsm",
    "application/vnd.ms-excel": ".xls",
}
MAX_DOCUMENT_ZIP_ENTRIES = 256
MAX_DOCUMENT_XML_ENTRY_BYTES = 2_000_000
MAX_DOCUMENT_XML_TOTAL_BYTES = 8_000_000


class DocumentExtractionError(ValueError):
    """Base error for bounded native document extraction failures."""


class UnsupportedDocumentError(DocumentExtractionError):
    """Raised when no native extractor supports a document type."""


class DocumentTooLargeError(DocumentExtractionError):
    """Raised when a document exceeds parser safety limits."""


class DocumentParseError(DocumentExtractionError):
    """Raised when a document cannot be parsed as expected."""


@dataclass(frozen=True)
class DocumentDetection:
    extension: str | None
    source: str | None


@dataclass(frozen=True)
class DocumentExtractionResult:
    text: str
    extraction_method: str
    text_format: str
    text_truncated: bool


def detect_document_extension(
    data: bytes,
    *,
    filename: str | None,
    content_type: str,
) -> str | None:
    return detect_document(data, filename=filename, content_type=content_type).extension


def detect_document(
    data: bytes,
    *,
    filename: str | None,
    content_type: str,
) -> DocumentDetection:
    if filename:
        extension = os.path.splitext(filename)[1].lower()
        if extension:
            return DocumentDetection(extension=extension, source="filename")

    mimetype = _content_type_mimetype(content_type)
    if mimetype in DOCUMENT_CONTENT_TYPE_EXTENSIONS:
        return DocumentDetection(
            extension=DOCUMENT_CONTENT_TYPE_EXTENSIONS[mimetype],
            source="content_type",
        )

    if data.startswith(b"%PDF-"):
        return DocumentDetection(extension=".pdf", source="magic")

    extension = _detect_ooxml_extension(data)
    if extension:
        return DocumentDetection(extension=extension, source="ooxml_manifest")
    return DocumentDetection(extension=None, source=None)


def is_document_extension(extension: str | None) -> bool:
    return extension in DOCUMENT_EXTENSIONS


def is_supported_document_extension(extension: str | None) -> bool:
    return extension in SUPPORTED_DOCUMENT_EXTENSIONS


def is_unsupported_document_extension(extension: str | None) -> bool:
    return extension in UNSUPPORTED_DOCUMENT_EXTENSIONS


def extract_document_text(
    data: bytes,
    *,
    extension: str,
    max_text_bytes: int,
) -> DocumentExtractionResult:
    if extension in DOCX_EXTENSIONS:
        text, text_truncated = _extract_docx_text(data, max_text_bytes)
        return DocumentExtractionResult(
            text=text,
            extraction_method="docx_native",
            text_format="plain",
            text_truncated=text_truncated,
        )

    if extension in XLSX_EXTENSIONS:
        text, text_truncated = _extract_xlsx_text(data, max_text_bytes)
        return DocumentExtractionResult(
            text=text,
            extraction_method="xlsx_native",
            text_format="plain",
            text_truncated=text_truncated,
        )

    raise UnsupportedDocumentError(f"Unsupported document extension: {extension}")


def _content_type_mimetype(content_type: str | None) -> str | None:
    if not content_type:
        return None
    mimetype = content_type.split(";", 1)[0].strip().lower()
    return mimetype or None


def _detect_ooxml_extension(data: bytes) -> str | None:
    if not data.startswith(b"PK"):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
    except zipfile.BadZipFile:
        return None
    if len(names) > MAX_DOCUMENT_ZIP_ENTRIES:
        return None

    if "word/document.xml" in names:
        return ".docx"
    if "xl/workbook.xml" in names:
        return ".xlsx"
    return None


@dataclass
class _XmlReadState:
    total_bytes: int = 0


def _open_document_archive(data: bytes, document_type: str) -> zipfile.ZipFile:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise DocumentParseError(f"{document_type} is not a valid ZIP container") from exc

    if len(archive.infolist()) > MAX_DOCUMENT_ZIP_ENTRIES:
        archive.close()
        raise DocumentTooLargeError(
            f"{document_type} ZIP has more than {MAX_DOCUMENT_ZIP_ENTRIES} entries"
        )
    return archive


def _read_xml_entry(
    archive: zipfile.ZipFile,
    name: str,
    state: _XmlReadState,
    *,
    missing_message: str | None = None,
) -> bytes | None:
    try:
        info = archive.getinfo(name)
    except KeyError as exc:
        if missing_message is None:
            return None
        raise DocumentParseError(missing_message) from exc

    if info.file_size > MAX_DOCUMENT_XML_ENTRY_BYTES:
        raise DocumentTooLargeError(
            f"{name} uncompressed size exceeds {MAX_DOCUMENT_XML_ENTRY_BYTES} bytes"
        )
    if state.total_bytes + info.file_size > MAX_DOCUMENT_XML_TOTAL_BYTES:
        raise DocumentTooLargeError(
            f"document XML reads exceed {MAX_DOCUMENT_XML_TOTAL_BYTES} bytes"
        )

    try:
        data = archive.read(info)
    except (RuntimeError, zipfile.BadZipFile) as exc:
        raise DocumentParseError(f"{name} could not be read: {exc}") from exc

    if len(data) > MAX_DOCUMENT_XML_ENTRY_BYTES:
        raise DocumentTooLargeError(
            f"{name} uncompressed size exceeds {MAX_DOCUMENT_XML_ENTRY_BYTES} bytes"
        )
    state.total_bytes += len(data)
    if state.total_bytes > MAX_DOCUMENT_XML_TOTAL_BYTES:
        raise DocumentTooLargeError(
            f"document XML reads exceed {MAX_DOCUMENT_XML_TOTAL_BYTES} bytes"
        )
    return data


def _extract_docx_text(data: bytes, max_text_bytes: int) -> tuple[str, bool]:
    with _open_document_archive(data, "DOCX") as archive:
        state = _XmlReadState()
        document_xml = _read_xml_entry(
            archive,
            "word/document.xml",
            state,
            missing_message="DOCX does not contain word/document.xml",
        )

    root = _parse_ooxml_xml(document_xml or b"", "DOCX document.xml parse failed")
    lines: list[str] = []
    current_bytes = 0

    for paragraph in root.findall(".//{*}p"):
        line = _ooxml_text_content(paragraph).strip()
        if not line:
            continue
        current_bytes, text_truncated = _append_capped_line(
            lines,
            line,
            max_text_bytes,
            current_bytes,
        )
        if text_truncated:
            return "\n".join(lines), True

    return "\n".join(lines), False


def _extract_xlsx_text(data: bytes, max_text_bytes: int) -> tuple[str, bool]:
    with _open_document_archive(data, "XLSX") as archive:
        state = _XmlReadState()
        shared_strings = _read_xlsx_shared_strings(archive, state)
        sheets = _read_xlsx_sheets(archive, state)
        lines: list[str] = []
        current_bytes = 0
        text_truncated = False

        for sheet_name, sheet_path in sheets:
            current_bytes, text_truncated = _append_capped_line(
                lines,
                f"[Sheet: {sheet_name}]",
                max_text_bytes,
                current_bytes,
            )
            if text_truncated:
                break

            sheet_xml = _read_xml_entry(archive, sheet_path, state)
            if sheet_xml is None:
                continue
            root = _parse_ooxml_xml(sheet_xml, f"{sheet_path} parse failed")
            for row in root.findall(".//{*}row"):
                values = []
                for cell in row.findall("{*}c"):
                    value = _xlsx_cell_text(cell, shared_strings)
                    if value:
                        values.append(value)
                if not values:
                    continue
                current_bytes, text_truncated = _append_capped_line(
                    lines,
                    "\t".join(values),
                    max_text_bytes,
                    current_bytes,
                )
                if text_truncated:
                    break
            if text_truncated:
                break

        return "\n".join(lines), text_truncated


def _read_xlsx_shared_strings(archive: zipfile.ZipFile, state: _XmlReadState) -> list[str]:
    shared_xml = _read_xml_entry(archive, "xl/sharedStrings.xml", state)
    if shared_xml is None:
        return []

    root = _parse_ooxml_xml(shared_xml, "sharedStrings.xml parse failed")
    return [_ooxml_text_content(item) for item in root.findall(".//{*}si")]


def _read_xlsx_sheets(archive: zipfile.ZipFile, state: _XmlReadState) -> list[tuple[str, str]]:
    workbook_xml = _read_xml_entry(
        archive,
        "xl/workbook.xml",
        state,
        missing_message="XLSX does not contain xl/workbook.xml",
    )

    root = _parse_ooxml_xml(workbook_xml or b"", "workbook.xml parse failed")
    relationships = _read_xlsx_workbook_relationships(archive, state)
    sheets: list[tuple[str, str]] = []

    for sheet in root.findall(".//{*}sheet"):
        name = sheet.attrib.get("name") or f"Sheet{len(sheets) + 1}"
        relationship_id = sheet.attrib.get(
            "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
        )
        target = relationships.get(relationship_id or "")
        sheet_path = _normalize_xlsx_target(target) if target else None
        if sheet_path:
            sheets.append((name, sheet_path))

    if sheets:
        return sheets

    worksheet_names = [
        name
        for name in sorted(archive.namelist())
        if _is_xlsx_worksheet_path(name)
    ]
    return [(f"Sheet{index + 1}", name) for index, name in enumerate(worksheet_names)]


def _read_xlsx_workbook_relationships(archive: zipfile.ZipFile, state: _XmlReadState) -> dict[str, str]:
    relationships_xml = _read_xml_entry(archive, "xl/_rels/workbook.xml.rels", state)
    if relationships_xml is None:
        return {}

    root = _parse_ooxml_xml(relationships_xml, "workbook.xml.rels parse failed")
    relationships: dict[str, str] = {}
    for relationship in root.findall(".//{*}Relationship"):
        relationship_id = relationship.attrib.get("Id")
        target = relationship.attrib.get("Target")
        target_mode = relationship.attrib.get("TargetMode", "")
        if relationship_id and target and target_mode.lower() != "external":
            relationships[relationship_id] = target
    return relationships


def _normalize_xlsx_target(target: str) -> str | None:
    normalized = target.replace("\\", "/").strip()
    if not normalized or "://" in normalized or normalized.startswith("//"):
        return None

    normalized = normalized.lstrip("/")
    if not normalized:
        return None

    if not normalized.startswith("xl/"):
        normalized = f"xl/{normalized}"

    normalized = posixpath.normpath(normalized)
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        return None
    if not _is_xlsx_worksheet_path(normalized):
        return None
    return normalized


def _is_xlsx_worksheet_path(path: str) -> bool:
    prefix = "xl/worksheets/"
    if not path.startswith(prefix) or not path.endswith(".xml"):
        return False
    name = path[len(prefix):]
    return bool(name) and "/" not in name and name != ".xml"


def _xlsx_cell_text(cell: ElementTree.Element, shared_strings: list[str]) -> str:
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        return _ooxml_text_content(cell)

    value_node = cell.find("{*}v")
    if value_node is None or value_node.text is None:
        return ""

    raw_value = value_node.text
    if cell_type == "s":
        try:
            return shared_strings[int(raw_value)]
        except (ValueError, IndexError):
            return raw_value
    if cell_type == "b":
        return "TRUE" if raw_value == "1" else "FALSE"
    return raw_value


def _ooxml_text_content(element: ElementTree.Element) -> str:
    parts: list[str] = []
    for node in element.iter():
        tag = _xml_local_name(node.tag)
        if tag == "t" and node.text:
            parts.append(node.text)
        elif tag == "tab":
            parts.append("\t")
        elif tag in {"br", "cr"}:
            parts.append("\n")
    return "".join(parts)


def _xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_ooxml_xml(data: bytes, error_prefix: str) -> ElementTree.Element:
    try:
        return ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        raise DocumentParseError(f"{error_prefix}: {exc}") from exc


def _append_capped_line(
    lines: list[str],
    line: str,
    max_text_bytes: int,
    current_bytes: int,
) -> tuple[int, bool]:
    separator_len = 1 if lines else 0
    available = max_text_bytes - current_bytes - separator_len
    if available <= 0:
        return current_bytes, True

    line_bytes = line.encode("utf-8")
    if len(line_bytes) > available:
        lines.append(_truncate_utf8(line, available))
        return max_text_bytes, True
    lines.append(line)
    return current_bytes + separator_len + len(line_bytes), False


def _truncate_utf8(text: str, max_bytes: int) -> str:
    if max_bytes <= 0:
        return ""
    return text.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore")
