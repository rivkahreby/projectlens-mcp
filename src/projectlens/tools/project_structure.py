"""Bounded, security-conscious project tree generation."""

from __future__ import annotations

from pathlib import Path

from projectlens.security.files import (
    IGNORED_DIRECTORIES,
    is_sensitive_name,
    scan_directory_limited,
)
from projectlens.security.paths import ProjectRootError, resolve_within_root

DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_ENTRIES = 500
HARD_MAX_DEPTH = 10
HARD_MAX_ENTRIES = 1000


def build_project_structure(
    root: Path,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> str:
    """Build a readable directory tree without following links or exposing secrets."""
    canonical_root = resolve_within_root(root, root)
    _validate_limits(max_depth, max_entries)
    lines = [canonical_root.name or str(canonical_root)]
    entry_count = 0
    limit_reached = False

    def visit(directory: Path, prefix: str, depth: int) -> None:
        nonlocal entry_count, limit_reached
        if depth >= max_depth or limit_reached:
            return

        remaining = max_entries - entry_count
        if remaining <= 0:
            lines.append(f"{prefix}... (entry limit reached)")
            limit_reached = True
            return
        entries, directory_truncated = scan_directory_limited(
            canonical_root,
            directory,
            remaining,
        )

        visible_entries = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError as exc:
                if isinstance(exc, FileNotFoundError):
                    continue
                relative_path = Path(entry.name).as_posix()
                raise ProjectRootError(
                    f"Unable to inspect project entry '{relative_path}': "
                    f"{exc.strerror or exc}"
                ) from exc
            if is_directory and entry.name.casefold() in IGNORED_DIRECTORIES:
                continue
            if is_sensitive_name(entry.name, is_directory=is_directory):
                continue
            visible_entries.append((entry, is_directory))

        for index, (entry, is_directory) in enumerate(visible_entries):
            if entry_count >= max_entries:
                lines.append(f"{prefix}... (entry limit reached)")
                limit_reached = True
                return

            entry_path = Path(entry.path)
            try:
                resolve_within_root(canonical_root, entry_path)
            except ProjectRootError:
                continue

            is_last = index == len(visible_entries) - 1
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{entry.name}{'/' if is_directory else ''}")
            entry_count += 1

            if is_directory:
                child_prefix = prefix + ("    " if is_last else "│   ")
                visit(entry_path, child_prefix, depth + 1)
                if limit_reached:
                    return

        if directory_truncated:
            lines.append(f"{prefix}... (entry limit reached)")
            limit_reached = True

    visit(canonical_root, "", 0)
    return "\n".join(lines)


def _validate_limits(max_depth: int, max_entries: int) -> None:
    if isinstance(max_depth, bool) or not isinstance(max_depth, int):
        raise ValueError("max_depth must be an integer.")
    if not 0 <= max_depth <= HARD_MAX_DEPTH:
        raise ValueError(f"max_depth must be between 0 and {HARD_MAX_DEPTH}.")
    if isinstance(max_entries, bool) or not isinstance(max_entries, int):
        raise ValueError("max_entries must be an integer.")
    if not 1 <= max_entries <= HARD_MAX_ENTRIES:
        raise ValueError(f"max_entries must be between 1 and {HARD_MAX_ENTRIES}.")
