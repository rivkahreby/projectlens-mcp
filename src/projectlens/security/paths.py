"""Validation helpers for the configured project root and its contents."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path


class ProjectRootError(ValueError):
    """Raised when a project root or project-relative path is invalid."""


def validate_project_root(path: str | Path) -> Path:
    """Return the canonical path for an existing absolute project directory."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise ProjectRootError("The project root must be an absolute path.")

    try:
        root = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProjectRootError(f"The project root cannot be resolved: {exc}") from exc

    if not root.is_dir():
        raise ProjectRootError("The project root must be an existing directory.")
    return root


def configured_project_root(
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Read and validate the fixed project root from PROJECTLENS_ROOT."""
    environment = os.environ if environ is None else environ
    value = environment.get("PROJECTLENS_ROOT", "").strip()
    if not value:
        raise ProjectRootError(
            "PROJECTLENS_ROOT is required and must name an existing directory."
        )
    return validate_project_root(value)


def resolve_within_root(root: Path, path: str | Path) -> Path:
    """Resolve an existing path and reject it if it escapes the project root."""
    canonical_root = validate_project_root(root)
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = canonical_root / candidate

    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProjectRootError(
            f"The requested project path cannot be resolved: {exc}"
        ) from exc

    try:
        resolved.relative_to(canonical_root)
    except ValueError as exc:
        raise ProjectRootError(
            "The requested path is outside the configured project root."
        ) from exc
    return resolved
