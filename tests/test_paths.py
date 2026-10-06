from pathlib import Path

import pytest

from projectlens.security.paths import (
    ProjectRootError,
    configured_project_root,
    resolve_within_root,
    validate_project_root,
)


def test_validate_project_root_returns_resolved_directory(tmp_path: Path) -> None:
    assert validate_project_root(tmp_path) == tmp_path.resolve()


def test_validate_project_root_rejects_relative_path() -> None:
    with pytest.raises(ProjectRootError, match="absolute"):
        validate_project_root("relative/project")


def test_validate_project_root_rejects_missing_path(tmp_path: Path) -> None:
    with pytest.raises(ProjectRootError, match="cannot be resolved"):
        validate_project_root(tmp_path / "missing")


def test_validate_project_root_rejects_file(tmp_path: Path) -> None:
    file_path = tmp_path / "file.txt"
    file_path.touch()

    with pytest.raises(ProjectRootError, match="directory"):
        validate_project_root(file_path)


def test_configured_project_root_requires_environment_variable() -> None:
    with pytest.raises(ProjectRootError, match="PROJECTLENS_ROOT is required"):
        configured_project_root({})


def test_configured_project_root_uses_absolute_directory(tmp_path: Path) -> None:
    assert configured_project_root({"PROJECTLENS_ROOT": str(tmp_path)}) == tmp_path.resolve()


def test_resolve_within_root_accepts_relative_path(tmp_path: Path) -> None:
    project_file = tmp_path / "src" / "main.py"
    project_file.parent.mkdir()
    project_file.touch()

    assert resolve_within_root(tmp_path, Path("src") / "main.py") == project_file.resolve()


def test_resolve_within_root_rejects_parent_traversal(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.txt"
    outside.touch()

    with pytest.raises(ProjectRootError, match="outside"):
        resolve_within_root(tmp_path, Path("..") / outside.name)


def test_resolve_within_root_rejects_absolute_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-absolute.txt"
    outside.touch()

    with pytest.raises(ProjectRootError, match="outside"):
        resolve_within_root(tmp_path, outside)


def test_resolve_within_root_rejects_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-symlink.txt"
    outside.touch()
    link = tmp_path / "outside-link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("This platform does not permit creating symbolic links.")

    with pytest.raises(ProjectRootError, match="outside"):
        resolve_within_root(tmp_path, link)
