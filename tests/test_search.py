from pathlib import Path

import pytest

import projectlens.security.files as files_module
from projectlens.security.files import walk_project_files
from projectlens.tools.search import (
    MAX_FILE_SIZE_BYTES,
    search_project_code,
    search_project_files,
)
from projectlens.tools.project_structure import build_project_structure
import projectlens.tools.search as search_module


def test_search_project_files_finds_names_case_insensitively(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Main.PY").touch()
    (tmp_path / "README.md").touch()

    result = search_project_files(tmp_path, "main")

    assert result == {"results": ["src/Main.PY"], "truncated": False}


def test_search_files_keeps_authentication_source_filenames(tmp_path: Path) -> None:
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
    (tmp_path / "auth.py").write_text(
        "def authenticate():\n    return token_utils()\n",
        encoding="utf-8",
    )

    for name in source_names:
        assert name in search_project_files(tmp_path, name)["results"]
    assert search_project_code(tmp_path, "authenticate")["results"][0]["path"] == "auth.py"


def test_search_project_files_applies_extension_and_path_filters(
    tmp_path: Path,
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "main.py").touch()
    (tmp_path / "tests" / "main.txt").touch()

    result = search_project_files(
        tmp_path,
        "main",
        extension="py",
        path_contains="SRC",
    )

    assert result["results"] == ["src/main.py"]


def test_search_project_files_skips_secrets_ignored_dirs_and_symlinks(
    tmp_path: Path,
) -> None:
    (tmp_path / ".env").touch()
    (tmp_path / "id_rsa").touch()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "match.py").touch()
    outside = tmp_path.parent / "private-match.py"
    outside.touch()
    link = tmp_path / "external-match.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("This platform does not permit creating symbolic links.")

    result = search_project_files(tmp_path, "match")

    assert result == {"results": [], "truncated": False}


def test_search_tools_skip_credential_files_and_cloud_credential_directories(
    tmp_path: Path,
) -> None:
    (tmp_path / "credentials.json").write_text(
        '{"token":"sensitive-value"}',
        encoding="utf-8",
    )
    (tmp_path / "aws_credentials").write_text(
        "aws_secret_access_key=private",
        encoding="utf-8",
    )
    (tmp_path / "token.txt").write_text("private-token", encoding="utf-8")
    (tmp_path / ".npmrc").write_text("//registry/:_authToken=private", encoding="utf-8")
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "credentials").write_text(
        "aws_secret_access_key=private",
        encoding="utf-8",
    )

    assert search_project_files(tmp_path, "credentials")["results"] == []
    assert search_project_files(tmp_path, "token")["results"] == []
    assert search_project_code(tmp_path, "sensitive-value")["results"] == []
    assert search_project_code(tmp_path, "private-token")["results"] == []


def test_search_project_files_obeys_result_limit(tmp_path: Path) -> None:
    for name in ("match-a.py", "match-b.py", "match-c.py"):
        (tmp_path / name).touch()

    result = search_project_files(tmp_path, "match", max_results=2)

    assert len(result["results"]) == 2
    assert result["truncated"] is True


def test_search_project_files_handles_empty_project(tmp_path: Path) -> None:
    assert search_project_files(tmp_path, "missing") == {
        "results": [],
        "truncated": False,
    }


def test_project_walker_caps_entries_and_marks_truncation(tmp_path: Path) -> None:
    for index in range(20):
        (tmp_path / f"file-{index:02}.txt").touch()

    files, truncated = walk_project_files(tmp_path, max_depth=1, max_entries=5)

    assert len(files) == 5
    assert truncated is True


def test_directory_entry_limit_is_deterministic_across_scandir_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("c.txt", "a.txt", "b.txt"):
        (tmp_path / name).touch()
    expected = build_project_structure(tmp_path, max_entries=2)
    real_scandir = files_module.os.scandir

    class ReverseScan:
        def __enter__(self):
            self.entries = list(real_scandir(tmp_path))
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def __iter__(self):
            return iter(reversed(self.entries))

    monkeypatch.setattr(files_module.os, "scandir", lambda _path: ReverseScan())

    actual = build_project_structure(tmp_path, max_entries=2)

    assert actual == expected
    assert "a.txt" in actual
    assert "b.txt" in actual
    assert "c.txt" not in actual
    assert "entry limit reached" in actual


def test_search_project_code_returns_relative_path_line_and_snippet(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src" / "main.py"
    source.parent.mkdir()
    source.write_text("first line\nNeedle appears here\nlast line\n", encoding="utf-8")

    result = search_project_code(tmp_path, "needle", extension=".py")

    assert result == {
        "results": [
            {"path": "src/main.py", "line": 2, "snippet": "Needle appears here"}
        ],
        "truncated": False,
    }


def test_search_project_code_can_be_case_sensitive(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("Needle\nneedle\n", encoding="utf-8")

    result = search_project_code(tmp_path, "Needle", case_sensitive=True)

    assert [match["line"] for match in result["results"]] == [1]


def test_search_project_code_ignores_binary_and_invalid_utf8(
    tmp_path: Path,
) -> None:
    (tmp_path / "binary.bin").write_bytes(b"needle\0data")
    (tmp_path / "invalid.txt").write_bytes(b"needle \xff")
    (tmp_path / "valid.txt").write_text("needle in text\n", encoding="utf-8")

    result = search_project_code(tmp_path, "needle")

    assert [match["path"] for match in result["results"]] == ["valid.txt"]


def test_search_project_code_ignores_large_files(tmp_path: Path) -> None:
    large_file = tmp_path / "large.txt"
    large_file.write_bytes(b"needle" + b" " * MAX_FILE_SIZE_BYTES)

    result = search_project_code(tmp_path, "needle")

    assert result["results"] == []


def test_search_project_code_redacts_secret_assignments(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'api_key = "super-secret-value"\n',
        encoding="utf-8",
    )

    result = search_project_code(tmp_path, "api_key")

    assert result["results"][0]["snippet"] == "api_key = [REDACTED]"
    assert "super-secret-value" not in str(result)


@pytest.mark.parametrize(
    ("line", "query", "expected"),
    [
        (
            'password = "multi word, sensitive value"',
            "password",
            "password = [REDACTED]",
        ),
        (
            "Authorization: Bearer abc.def.ghi",
            "Authorization",
            "Authorization: [REDACTED]",
        ),
        (
            'client_secret: "secret,with,commas"',
            "client_secret",
            "client_secret: [REDACTED]",
        ),
    ],
)
def test_search_project_code_redacts_quoted_secrets_and_auth_headers(
    tmp_path: Path,
    line: str,
    query: str,
    expected: str,
) -> None:
    (tmp_path / "config.txt").write_text(line + "\n", encoding="utf-8")

    result = search_project_code(tmp_path, query)

    assert result["results"][0]["snippet"] == expected
    assert "sensitive value" not in str(result)
    assert "abc.def.ghi" not in str(result)
    assert "secret,with,commas" not in str(result)


def test_search_project_code_preserves_variable_call_snippets(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "const token = getToken()\n",
        encoding="utf-8",
    )

    result = search_project_code(tmp_path, "getToken")

    assert result["results"][0]["snippet"] == "const token = getToken()"


def test_search_project_code_redacts_url_embedded_credentials(tmp_path: Path) -> None:
    (tmp_path / "config.txt").write_text(
        "DATABASE_URL = postgres://user:password123@db.example/app\n",
        encoding="utf-8",
    )

    result = search_project_code(tmp_path, "postgres://")

    assert result["results"][0]["snippet"] == (
        "DATABASE_URL = postgres://[REDACTED]@db.example/app"
    )
    assert "user:password123" not in str(result)


def test_search_project_code_redacts_bearer_authorization_values(
    tmp_path: Path,
) -> None:
    (tmp_path / "request.txt").write_text(
        "Authorization: Bearer abc.def.ghi\n",
        encoding="utf-8",
    )

    result = search_project_code(tmp_path, "Authorization")

    assert result["results"][0]["snippet"] == "Authorization: [REDACTED]"
    assert "abc.def.ghi" not in str(result)


def test_search_project_code_skips_private_key_contents(tmp_path: Path) -> None:
    (tmp_path / "data.txt").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nneedle secret\n",
        encoding="utf-8",
    )

    assert search_project_code(tmp_path, "needle")["results"] == []


def test_search_project_code_obeys_total_read_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "a.txt").write_text("needle\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("needle\n", encoding="utf-8")
    monkeypatch.setattr(search_module, "MAX_TOTAL_SEARCH_BYTES", len(b"needle\n"))

    result = search_project_code(tmp_path, "needle")

    assert len(result["results"]) == 1
    assert result["truncated"] is True


@pytest.mark.parametrize(
    ("line", "query", "expected", "secret"),
    [
        (
            'password = "multi word, sensitive value"',
            "password",
            "password = [REDACTED]",
            "sensitive value",
        ),
        (
            "Authorization: Bearer abc.def.ghi",
            "Authorization",
            "Authorization: [REDACTED]",
            "abc.def.ghi",
        ),
        (
            'client_secret: "secret,with,commas"',
            "client_secret",
            "client_secret: [REDACTED]",
            "secret,with,commas",
        ),
        (
            '{"password": "json secret"}',
            "password",
            '{"password": [REDACTED]}',
            "json secret",
        ),
        (
            "DJANGO_SECRET_KEY = 'framework secret'",
            "SECRET_KEY",
            "DJANGO_SECRET_KEY = [REDACTED]",
            "framework secret",
        ),
    ],
)
def test_search_project_code_redacts_quoted_and_authorization_secrets(
    tmp_path: Path,
    line: str,
    query: str,
    expected: str,
    secret: str,
) -> None:
    (tmp_path / "config.txt").write_text(line + "\n", encoding="utf-8")

    result = search_project_code(tmp_path, query)

    assert result["results"][0]["snippet"] == expected
    assert secret not in str(result)


def test_search_project_code_obeys_result_limit(tmp_path: Path) -> None:
    (tmp_path / "matches.txt").write_text("needle\nneedle\nneedle\n", encoding="utf-8")

    result = search_project_code(tmp_path, "needle", max_results=2)

    assert len(result["results"]) == 2
    assert result["truncated"] is True


@pytest.mark.parametrize(
    ("query", "kwargs", "message"),
    [
        (" ", {}, "query"),
        ("x" * 257, {}, "query"),
        ("x", {"max_depth": 21}, "max_depth"),
        ("x", {"max_results": 501}, "max_results"),
        ("x", {"extension": "../secret"}, "extension"),
        ("x", {"path_contains": " "}, "path_contains"),
        ("x", {"path_contains": "p" * 513}, "path_contains"),
        ("x", {"extension": "x" * 33}, "extension"),
        ("x", {"case_sensitive": 1}, "case_sensitive"),
    ],
)
def test_search_project_code_rejects_invalid_arguments(
    tmp_path: Path,
    query: str,
    kwargs: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        search_project_code(tmp_path, query, **kwargs)
