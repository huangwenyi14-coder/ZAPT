# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Safe text extraction for TXT and text-layer PDF reports."""

import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from pypdf import PdfReader
from pypdf.errors import FileNotDecryptedError, PdfReadError

from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.report_ingest.models import SourceSpan

MAX_INPUT_BYTES = 50 * 1024 * 1024
MAX_PDF_PAGES = 1000
MAX_EXTRACTED_CHARS = 1_000_000
MIN_TXT_NONSPACE_CHARS = 12
MIN_PDF_NONSPACE_CHARS = 80
DEFAULT_CHUNK_CHARS = 60_000
DEFAULT_CHUNK_OVERLAP = 1500
MAX_SOURCE_SPAN_CHARS = 2000
SOURCE_SPAN_OVERLAP_CHARS = 200
MAX_SOURCE_QUOTE_CHARS = 600
MAX_SOURCE_SPANS = 10_000
_PDF_PAGE_MARKER_RE = re.compile(r"(?m)^--- PDF PAGE (\d+)/(\d+) ---\n")


class ReportInputError(EvidenceForgeError):
    """The supplied report cannot be safely converted to text."""


@dataclass(frozen=True)
class ExtractedDocument:
    """Normalized report text and non-secret extraction metadata."""

    text: str
    source_name: str
    source_type: str
    byte_size: int
    page_count: int | None = None
    spans: tuple[SourceSpan, ...] = ()

    def span_text(self, span_id: str) -> str:
        """Return the normalized source text covered by one known span."""
        for span in self.spans:
            if span.span_id == span_id:
                return self.text[span.char_start : span.char_end]
        raise ReportInputError(f"来源片段不存在：{span_id}")


def extract_document(path: Path) -> ExtractedDocument:
    """Extract a supported report into normalized Unicode text."""
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise ReportInputError(f"拒绝读取符号链接输入：{candidate.name}")
    if not candidate.exists():
        raise ReportInputError(f"输入文件不存在：{candidate}")
    if not candidate.is_file():
        raise ReportInputError(f"输入路径不是普通文件：{candidate}")
    size = candidate.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise ReportInputError(f"输入文件超过 {MAX_INPUT_BYTES // (1024 * 1024)} MiB 上限")

    suffix = candidate.suffix.casefold()
    if suffix == ".txt":
        text = _extract_txt(candidate)
        page_count = None
        source_type = "txt"
    elif suffix == ".pdf":
        text, page_count = _extract_pdf(candidate)
        source_type = "pdf"
    else:
        raise ReportInputError("仅支持 .txt 和带文本层的 .pdf 文件")

    normalized = _normalize_text(text)
    if len(normalized) > MAX_EXTRACTED_CHARS:
        raise ReportInputError(f"提取文本超过 {MAX_EXTRACTED_CHARS} 字符上限")
    nonspace_chars = len(re.sub(r"\s+", "", normalized))
    minimum_chars = MIN_PDF_NONSPACE_CHARS if suffix == ".pdf" else MIN_TXT_NONSPACE_CHARS
    if nonspace_chars < minimum_chars:
        if suffix == ".pdf":
            raise ReportInputError("PDF 几乎没有可提取文本，可能是扫描版；本期不支持 OCR")
        raise ReportInputError("TXT 内容过短，无法提取可验证的攻击事实")
    document = ExtractedDocument(
        text=normalized,
        source_name=candidate.name,
        source_type=source_type,
        byte_size=size,
        page_count=page_count,
        spans=tuple(_build_source_spans(normalized, source_type)),
    )
    validate_document_spans(document)
    return document


def validate_document_spans(document: ExtractedDocument) -> None:
    """Validate offsets, locators, hashes, and quotes against normalized text."""
    if not document.spans:
        raise ReportInputError("提取文本没有生成任何可引用来源片段")
    span_ids = [span.span_id for span in document.spans]
    if len(span_ids) != len(set(span_ids)):
        raise ReportInputError("来源片段 ID 重复")

    for span in document.spans:
        if span.char_end > len(document.text):
            raise ReportInputError(f"来源片段 {span.span_id} 字符范围越界")
        fragment = document.text[span.char_start : span.char_end]
        if not fragment:
            raise ReportInputError(f"来源片段 {span.span_id} 为空")
        digest = sha256(fragment.encode("utf-8")).hexdigest()
        if digest != span.text_sha256:
            raise ReportInputError(f"来源片段 {span.span_id} 摘要不匹配")
        if _bounded_quote(fragment) != span.quote:
            raise ReportInputError(f"来源片段 {span.span_id} 引用文本不匹配")
        if document.source_type == "pdf" and span.page_number is None:
            raise ReportInputError(f"PDF 来源片段 {span.span_id} 缺少页码")
        if document.source_type == "txt" and span.paragraph_number is None:
            raise ReportInputError(f"TXT 来源片段 {span.span_id} 缺少段落号")

    expected_spans = tuple(_build_source_spans(document.text, document.source_type))
    if document.spans != expected_spans:
        raise ReportInputError("来源片段集合、页码或段落号与规范化文本不一致")


def split_document(
    text: str,
    *,
    chunk_chars: int = DEFAULT_CHUNK_CHARS,
    overlap_chars: int = DEFAULT_CHUNK_OVERLAP,
) -> list[str]:
    """Split long text on paragraph boundaries with a bounded overlap."""
    if chunk_chars < 1000:
        raise ValueError("chunk_chars 不能小于 1000")
    if overlap_chars < 0 or overlap_chars >= chunk_chars:
        raise ValueError("overlap_chars 必须大于等于 0 且小于 chunk_chars")
    if len(text) <= chunk_chars:
        return [text]

    chunks: list[str] = []
    start = 0
    while start < len(text):
        desired_end = min(start + chunk_chars, len(text))
        end = desired_end
        if desired_end < len(text):
            paragraph = text.rfind("\n\n", start + chunk_chars // 2, desired_end)
            if paragraph > start:
                end = paragraph
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        next_start = max(end - overlap_chars, start + 1)
        start = next_start
    return chunks


def _build_source_spans(text: str, source_type: str) -> list[SourceSpan]:
    """Build stable paragraph/page-aware spans over normalized text."""
    spans: list[SourceSpan] = []
    sequence = 0
    if source_type == "pdf":
        page_matches = list(_PDF_PAGE_MARKER_RE.finditer(text))
        for page_index, marker in enumerate(page_matches):
            region_start = marker.end()
            region_end = (
                page_matches[page_index + 1].start()
                if page_index + 1 < len(page_matches)
                else len(text)
            )
            page_number = int(marker.group(1))
            for paragraph_number, start, end in _paragraph_ranges(
                text,
                region_start,
                region_end,
            ):
                del paragraph_number
                for chunk_start, chunk_end in _bounded_ranges(start, end):
                    sequence += 1
                    _validate_source_span_count(sequence)
                    spans.append(
                        _make_source_span(
                            text,
                            sequence=sequence,
                            char_start=chunk_start,
                            char_end=chunk_end,
                            page_number=page_number,
                            paragraph_number=None,
                        )
                    )
    else:
        for paragraph_number, start, end in _paragraph_ranges(text, 0, len(text)):
            for chunk_start, chunk_end in _bounded_ranges(start, end):
                sequence += 1
                _validate_source_span_count(sequence)
                spans.append(
                    _make_source_span(
                        text,
                        sequence=sequence,
                        char_start=chunk_start,
                        char_end=chunk_end,
                        page_number=None,
                        paragraph_number=paragraph_number,
                    )
                )
    return spans


def _validate_source_span_count(sequence: int) -> None:
    """Bound citation metadata for adversarially fragmented input."""
    if sequence > MAX_SOURCE_SPANS:
        raise ReportInputError(f"来源片段超过 {MAX_SOURCE_SPANS} 个上限")


def _paragraph_ranges(text: str, start: int, end: int) -> list[tuple[int, int, int]]:
    """Return one-based paragraph numbers and exact non-whitespace ranges."""
    region = text[start:end]
    pattern = re.compile(r"\S(?:.*?\S)?(?=\n[ \t]*\n|\Z)", re.DOTALL)
    return [
        (index, start + match.start(), start + match.end())
        for index, match in enumerate(pattern.finditer(region), start=1)
    ]


def _bounded_ranges(start: int, end: int) -> list[tuple[int, int]]:
    """Split unusually long paragraphs with bounded overlap."""
    if end - start <= MAX_SOURCE_SPAN_CHARS:
        return [(start, end)]
    ranges: list[tuple[int, int]] = []
    chunk_start = start
    while chunk_start < end:
        chunk_end = min(chunk_start + MAX_SOURCE_SPAN_CHARS, end)
        ranges.append((chunk_start, chunk_end))
        if chunk_end == end:
            break
        chunk_start = chunk_end - SOURCE_SPAN_OVERLAP_CHARS
    return ranges


def _make_source_span(
    text: str,
    *,
    sequence: int,
    char_start: int,
    char_end: int,
    page_number: int | None,
    paragraph_number: int | None,
) -> SourceSpan:
    """Create one hashed source span with a stable ID."""
    fragment = text[char_start:char_end]
    digest = sha256(fragment.encode("utf-8")).hexdigest()
    locator = page_number if page_number is not None else paragraph_number
    stable_material = f"{locator}|{char_start}|{char_end}|{digest}"
    stable_suffix = sha256(stable_material.encode("utf-8")).hexdigest()[:12]
    return SourceSpan(
        span_id=f"span-{sequence:04d}-{stable_suffix}",
        page_number=page_number,
        paragraph_number=paragraph_number,
        char_start=char_start,
        char_end=char_end,
        text_sha256=digest,
        quote=_bounded_quote(fragment),
    )


def _bounded_quote(fragment: str) -> str:
    """Return a reviewable quote without embedding an unbounded report passage."""
    if len(fragment) <= MAX_SOURCE_QUOTE_CHARS:
        return fragment
    return fragment[: MAX_SOURCE_QUOTE_CHARS - 3] + "..."


def _extract_txt(path: Path) -> str:
    """Decode TXT without lossy replacement."""
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return raw.decode(encoding, errors="strict")
        except UnicodeDecodeError:
            continue
    raise ReportInputError("TXT 无法按 UTF-8、UTF-8 BOM 或 GB18030 无损解码")


def _extract_pdf(path: Path) -> tuple[str, int]:
    """Extract PDF pages in source order."""
    try:
        reader = PdfReader(path)
        if reader.is_encrypted and reader.decrypt("") == 0:
            raise ReportInputError("PDF 已加密且无法使用空密码读取")
        page_count = len(reader.pages)
        if page_count == 0:
            raise ReportInputError("PDF 页数为零")
        if page_count > MAX_PDF_PAGES:
            raise ReportInputError(f"PDF 超过 {MAX_PDF_PAGES} 页上限")
        pages: list[str] = []
        for index, page in enumerate(reader.pages, start=1):
            page_text = page.extract_text() or ""
            pages.append(f"--- PDF PAGE {index}/{page_count} ---\n{page_text}")
    except ReportInputError:
        raise
    except (FileNotDecryptedError, PdfReadError, OSError, KeyError, TypeError, ValueError) as exc:
        raise ReportInputError(f"PDF 文本提取失败：{type(exc).__name__}") from exc
    return "\n\n".join(pages), page_count


def _normalize_text(text: str) -> str:
    """Normalize control characters while preserving report facts and paths."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    normalized = re.sub(r"[ \t]+\n", "\n", normalized)
    normalized = re.sub(r"\n{5,}", "\n\n\n\n", normalized)
    return normalized.strip()
