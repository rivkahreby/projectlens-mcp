"""Shared filesystem policy and bounded project file traversal."""

from __future__ import annotations

import os
import heapq
from pathlib import Path

from projectlens.security.paths import ProjectRootError, resolve_within_root

IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
}
SENSITIVE_FILE_SUFFIXES = {
    ".der",
    ".key",
    ".p8",
    ".pem",
    ".p12",
    ".pfx",
    ".ppk",
}
SENSITIVE_FILE_NAMES = {
    ".dockerconfigjson",
    ".dockercfg",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}
SENSITIVE_DIRECTORY_NAMES = {
    ".aws",
    ".kube",
    ".ssh",
}
SENSITIVE_NAME_PARTS = {
    "auth",
    "credential",
    "credentials",
    "creds",
    "password",
    "passwords",
    "passwd",
    "secret",
    "secrets",
    "token",
    "tokens",
}
SENSITIVE_DATA_SUFFIXES = {
    ".cfg",
    ".conf",
    ".ini",
    ".json",
    ".properties",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
MAX_SCANNED_ENTRIES = 10_000


def is_sensitive_name(name: str, *, is_directory: bool = False) -> bool:
    """Check whether a file or directory name may contain secrets."""
    lowered_name = name.casefold()
    name_parts = set(lowered_name.replace("_", ".").replace("-", ".").split("."))
    suffix = Path(lowered_name).suffix
    return (
        lowered_name.startswith(".env")
        or lowered_name in SENSITIVE_FILE_NAMES
        or lowered_name in SENSITIVE_DIRECTORY_NAMES
        or suffix in SENSITIVE_FILE_SUFFIXES
        or (
            bool(name_parts & SENSITIVE_NAME_PARTS)
            and (
                is_directory
                or not suffix
                or suffix in SENSITIVE_DATA_SUFFIXES
            )
        )
    )


def scan_directory_limited(
    root: Path,
    directory: Path,
    max_entries: int,
) -> tuple[list[os.DirEntry[str]], bool]:
    """Return the lexically first entries with memory bounded by the result limit."""
    relative_directory = directory.relative_to(root).as_posix() or "."
    try:
        with os.scandir(directory) as scan:
            entries = heapq.nsmallest(
                max_entries + 1,
                scan,
                key=lambda entry: (entry.name.casefold(), entry.name),
            )
    except OSError as exc:
        raise ProjectRootError(
            f"Unable to read project directory '{relative_directory}': "
            f"{exc.strerror or exc}"
        ) from exc

    truncated = len(entries) > max_entries
    if truncated:
        entries.pop()
    entries.sort(key=lambda entry: entry.name.casefold())
    return entries, truncated


def walk_project_files(
    root: Path,
    max_depth: int,
    max_entries: int = MAX_SCANNED_ENTRIES,
) -> tuple[list[Path], bool]:
    """Collect regular project files without following links or leaving root."""
    canonical_root = resolve_within_root(root, root)
    files: list[Path] = []
    entries_seen = 0
    truncated = False

    def visit(directory: Path, depth: int) -> None:
        nonlocal entries_seen, truncated
        if depth >= max_depth or truncated:
            return

        remaining = max_entries - entries_seen
        if remaining <= 0:
            truncated = True
            return
        entries, directory_truncated = scan_directory_limited(
            canonical_root,
            directory,
            remaining,
        )

        for entry in entries:
            if entries_seen >= max_entries:
                truncated = True
                return
            entries_seen += 1

            try:
                is_symlink = entry.is_symlink()
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError as exc:
                if isinstance(exc, FileNotFoundError):
                    continue
                relative_path = Path(entry.name).as_posix()
                raise ProjectRootError(
                    f"Unable to inspect project entry '{relative_path}': "
                    f"{exc.strerror or exc}"
                ) from exc

            if is_symlink or is_sensitive_name(entry.name, is_directory=is_directory):
                continue

            path = Path(entry.path)
            try:
                resolved_path = resolve_within_root(canonical_root, path)
            except ProjectRootError:
                continue
            except OSError as exc:
                if isinstance(exc, FileNotFoundError):
                    continue
                relative_path = path.relative_to(canonical_root).as_posix()
                raise ProjectRootError(
                    f"Unable to inspect project path '{relative_path}': "
                    f"{exc.strerror or exc}"
                ) from exc

            if is_directory:
                if entry.name.casefold() not in IGNORED_DIRECTORIES:
                    visit(resolved_path, depth + 1)
                    if truncated:
                        return
            else:
                files.append(resolved_path)

        if directory_truncated:
            truncated = True

    visit(canonical_root, 0)
    return files, truncated
