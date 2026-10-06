from pathlib import Path

import pytest

from projectlens.tools.project_structure import build_project_structure


def test_build_project_structure_handles_empty_project(tmp_path: Path) -> None:
    assert build_project_structure(tmp_path) == tmp_path.name


def test_build_project_structure_lists_project_files(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").touch()
    (tmp_path / "README.md").touch()

    result = build_project_structure(tmp_path)

    assert tmp_path.name in result.splitlines()[0]
    assert "src/" in result
    assert "main.py" in result
    assert "README.md" in result


def test_build_project_structure_keeps_authentication_source_files(
    tmp_path: Path,
) -> None:
    source_names = (
        "auth.py",
        "Auth.tsx",
        "token_utils.py",
        "password_reset.py",
        "secrets.py",
        "oauth.py",
        "authentication.py",
    )
    for name in source_names:
        (tmp_path / name).touch()

    result = build_project_structure(tmp_path)

    for name in source_names:
        assert name in result


def test_build_project_structure_ignores_generated_directories(tmp_path: Path) -> None:
    for name in (".git", "node_modules", "__pycache__", ".venv", "venv"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "ignored.txt").touch()

    result = build_project_structure(tmp_path)

    for name in (".git", "node_modules", "__pycache__", ".venv", "venv", "ignored.txt"):
        assert name not in result


def test_build_project_structure_hides_environment_and_private_key_files(
    tmp_path: Path,
) -> None:
    for name in (
        ".env",
        ".env.local",
        ".env-backup",
        "server.pem",
        "id_rsa.key",
        "id_ed25519",
        ".npmrc",
        ".pypirc",
        "credentials.json",
        "secrets.yaml",
    ):
        (tmp_path / name).touch()
    (tmp_path / ".env.directory").mkdir()
    (tmp_path / ".env.directory" / "nested-secret.txt").touch()

    result = build_project_structure(tmp_path)

    for name in (
        ".env",
        "server.pem",
        "id_rsa.key",
        "id_ed25519",
        ".npmrc",
        ".pypirc",
        "credentials.json",
        "secrets.yaml",
        ".env.directory",
        "nested-secret.txt",
    ):
        assert name not in result


def test_build_project_structure_does_not_follow_symlinks(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-project"
    outside.mkdir()
    (outside / "outside-file.txt").touch()
    link = tmp_path / "external-link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("This platform does not permit creating symbolic links.")

    result = build_project_structure(tmp_path)

    assert "external-link" not in result
    assert "outside-file.txt" not in result


def test_build_project_structure_obeys_depth_limit(tmp_path: Path) -> None:
    nested_file = tmp_path / "one" / "two" / "three.txt"
    nested_file.parent.mkdir(parents=True)
    nested_file.touch()

    result = build_project_structure(tmp_path, max_depth=1)

    assert "one/" in result
    assert "three.txt" not in result


def test_build_project_structure_obeys_entry_limit(tmp_path: Path) -> None:
    for name in ("a.txt", "b.txt", "c.txt"):
        (tmp_path / name).touch()

    result = build_project_structure(tmp_path, max_entries=2)

    assert "a.txt" in result
    assert "b.txt" in result
    assert "c.txt" not in result
    assert "entry limit reached" in result


@pytest.mark.parametrize(
    ("max_depth", "max_entries", "message"),
    [
        (-1, 10, "max_depth"),
        (11, 10, "max_depth"),
        (1, 0, "max_entries"),
        (1, 1001, "max_entries"),
        (True, 10, "max_depth"),
        (1, False, "max_entries"),
    ],
)
def test_build_project_structure_rejects_invalid_limits(
    tmp_path: Path,
    max_depth: int,
    max_entries: int,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        build_project_structure(tmp_path, max_depth, max_entries)
