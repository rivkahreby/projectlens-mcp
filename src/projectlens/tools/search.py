"""Bounded filename and text searches within a configured project."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TypedDict

from projectlens.security.files import walk_project_files
from projectlens.security.paths import ProjectRootError, resolve_within_root

DEFAULT_MAX_RESULTS = 100
HARD_MAX_RESULTS = 500
DEFAULT_MAX_DEPTH = 10
HARD_MAX_DEPTH = 20
MAX_FILE_SIZE_BYTES = 1_048_576
MAX_TOTAL_SEARCH_BYTES = 16 * 1_048_576
MAX_QUERY_LENGTH = 256
MAX_PATH_FILTER_LENGTH = 512
SNIPPET_MAX_LENGTH = 240
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9])"
    r"([A-Za-z0-9_.-]*(?:password|passwd|token|access[_-]?token|refresh[_-]?token|"
    r"secret|api[_-]?key|client[_-]?secret|credential|authorization|auth|private[_-]?key)"
    r"[A-Za-z0-9_.-]*)"
    r"([\"']?\s*[:=]\s*)(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
)
_AUTH_SCHEME = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9+/=_\-.]+")
_AUTH_HEADER = re.compile(
    r"(?i)(\b(?:authorization|proxy-authorization)\s*:\s*)[^\r\n]+"
)
_URL_CREDENTIALS = re.compile(
    r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@"
)
_PRIVATE_KEY_MARKER = b"-----BEGIN "
_PRIVATE_KEY_ENDING = b" PRIVATE KEY-----"


class FileSearchResponse(TypedDict):
    results: list[str]
    truncated: bool


class CodeMatch(TypedDict):
    path: str
    line: int
    snippet: str


class CodeSearchResponse(TypedDict):
    results: list[CodeMatch]
    truncated: bool


def search_project_files(
    root: Path,
    query: str,
    extension: str | None = None,
    path_contains: str | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_results: int = DEFAULT_MAX_RESULTS,
) -> FileSearchResponse:
    """Find filenames by case-insensitive substring and optional filters."""
    _validate_query(query)
    _validate_limits(max_depth, max_results)
    extension_filter = _normalize_extension(extension)
    path_filter = _normalize_optional_filter(path_contains, "path_contains")
    files, scan_truncated = walk_project_files(root, max_depth)
    results: list[str] = []
    truncated = scan_truncated

    for path in files:
        relative_path = path.relative_to(root.resolve()).as_posix()
        if query.casefold() not in path.name.casefold():
            continue
        if extension_filter and path.suffix.casefold() != extension_filter:
            continue
        if path_filter and path_filter not in relative_path.casefold():
            continue
        if len(results) == max_results:
            truncated = True
            break
        results.append(relative_path)

    return {"results": results, "truncated": truncated}


def search_project_code(
    root: Path,
    query: str,
    extension: str | None = None,
    path_contains: str | None = None,
    case_sensitive: bool = False,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_results: int = DEFAULT_MAX_RESULTS,
) -> CodeSearchResponse:
    """Search UTF-8 text files and return safe, bounded line matches."""
    _validate_query(query)
    _validate_limits(max_depth, max_results)
    if not isinstance(case_sensitive, bool):
        raise ValueError("case_sensitive must be a boolean.")
    extension_filter = _normalize_extension(extension)
    path_filter = _normalize_optional_filter(path_contains, "path_contains")
    files, scan_truncated = walk_project_files(root, max_depth)
    results: list[CodeMatch] = []
    truncated = scan_truncated
    needle = query if case_sensitive else query.casefold()
    bytes_scanned = 0

    for path in files:
        if extension_filter and path.suffix.casefold() != extension_filter:
            continue
        relative_path = path.relative_to(root.resolve()).as_posix()
        if path_filter and path_filter not in relative_path.casefold():
            continue

        remaining_bytes = MAX_TOTAL_SEARCH_BYTES - bytes_scanned
        if remaining_bytes <= 0:
            truncated = True
            break
        content, bytes_read, byte_limit_reached = _read_searchable_text(
            root,
            path,
            remaining_bytes,
        )
        bytes_scanned += bytes_read
        if content is None:
            if byte_limit_reached:
                truncated = True
                break
            continue

        for line_number, line in enumerate(content.splitlines(), start=1):
            haystack = line if case_sensitive else line.casefold()
            if needle not in haystack:
                continue
            if len(results) == max_results:
                truncated = True
                return {"results": results, "truncated": truncated}
            results.append(
                {
                    "path": relative_path,
                    "line": line_number,
                    "snippet": _safe_snippet(line),
                }
            )
        if byte_limit_reached:
            truncated = True
            break

    return {"results": results, "truncated": truncated}


def _read_searchable_text(
    root: Path,
    path: Path,
    remaining_total_bytes: int,
) -> tuple[str | None, int, bool]:
    """Read bounded UTF-8 text and report bytes consumed and budget exhaustion."""
    try:
        safe_path = resolve_within_root(root, path)
        with safe_path.open("rb") as file:
            read_limit = min(MAX_FILE_SIZE_BYTES, remaining_total_bytes)
            probe_byte = int(remaining_total_bytes > MAX_FILE_SIZE_BYTES)
            content = file.read(read_limit + probe_byte)
    except FileNotFoundError:
        return None, 0, False
    except PermissionError as exc:
        relative_path = path.relative_to(root.resolve()).as_posix()
        raise ProjectRootError(
            f"Unable to read project file '{relative_path}': permission denied."
        ) from exc
    except (OSError, ValueError) as exc:
        relative_path = path.relative_to(root.resolve()).as_posix()
        raise ProjectRootError(
            f"Unable to read project file '{relative_path}': {exc}"
        ) from exc

    if len(content) > MAX_FILE_SIZE_BYTES or b"\0" in content[:8192]:
        return None, len(content), len(content) >= remaining_total_bytes
    if _contains_private_key(content):
        return None, len(content), len(content) >= remaining_total_bytes
    try:
        return (
            content.decode("utf-8"),
            len(content),
            len(content) >= remaining_total_bytes,
        )
    except UnicodeDecodeError:
        return None, len(content), len(content) >= remaining_total_bytes


def _contains_private_key(content: bytes) -> bool:
    marker_position = content.find(_PRIVATE_KEY_MARKER)
    while marker_position != -1:
        line_end = content.find(b"\n", marker_position)
        if line_end == -1:
            line_end = len(content)
        if content[marker_position:line_end].rstrip(b"\r").endswith(_PRIVATE_KEY_ENDING):
            return True
        marker_position = content.find(_PRIVATE_KEY_MARKER, line_end)
    return False


def _safe_snippet(line: str) -> str:
    redacted = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", line)
    redacted = _AUTH_HEADER.sub(r"\1[REDACTED]", redacted)
    redacted = _AUTH_SCHEME.sub(r"\1 [REDACTED]", redacted)
    redacted = _SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", redacted).strip()
    if len(redacted) > SNIPPET_MAX_LENGTH:
        return redacted[: SNIPPET_MAX_LENGTH - 3] + "..."
    return redacted


def _validate_query(query: str) -> None:
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be a non-empty string.")
    if len(query) > MAX_QUERY_LENGTH:
        raise ValueError(f"query must be at most {MAX_QUERY_LENGTH} characters.")


def _validate_limits(max_depth: int, max_results: int) -> None:
    if isinstance(max_depth, bool) or not isinstance(max_depth, int):
        raise ValueError("max_depth must be an integer.")
    if not 0 <= max_depth <= HARD_MAX_DEPTH:
        raise ValueError(f"max_depth must be between 0 and {HARD_MAX_DEPTH}.")
    if isinstance(max_results, bool) or not isinstance(max_results, int):
        raise ValueError("max_results must be an integer.")
    if not 1 <= max_results <= HARD_MAX_RESULTS:
        raise ValueError(f"max_results must be between 1 and {HARD_MAX_RESULTS}.")


def _normalize_extension(extension: str | None) -> str | None:
    normalized = _normalize_optional_filter(extension, "extension")
    if normalized is None:
        return None
    if any(separator in normalized for separator in ("/", "\\")):
        raise ValueError("extension must be a file extension such as '.py'.")
    return normalized if normalized.startswith(".") else f".{normalized}"


def _normalize_optional_filter(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string when provided.")
    max_length = 32 if name == "extension" else MAX_PATH_FILTER_LENGTH
    if len(value) > max_length:
        raise ValueError(f"{name} must be at most {max_length} characters.")
    return value.casefold()
