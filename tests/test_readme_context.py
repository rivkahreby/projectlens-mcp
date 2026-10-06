from pathlib import Path

import pytest

from projectlens.tools.readme_context import generate_readme_context


def test_generate_readme_context_returns_structured_project_evidence(
    tmp_path: Path,
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_main.py").touch()
    (tmp_path / "requirements.txt").write_text("fastapi>=0.100\n", encoding="utf-8")
    (tmp_path / "README.md").touch()

    result = generate_readme_context(tmp_path)

    assert result["project_name"] == tmp_path.name
    assert result["analysis"]["languages"] == {"Python": 2}
    assert "FastAPI" in result["analysis"]["frameworks"]
    assert "src/main.py" in result["analysis"]["likely_entry_points"]
    assert "src/" in result["project_structure"]
    assert "test_main.py" in str(result["suggested_sections"])
    assert "README prose" in result["note"]
    assert [section["title"] for section in result["suggested_sections"]] == [
        "Overview",
        "Features and architecture",
        "Installation",
        "Usage",
        "Testing",
        "Configuration and security",
    ]


def test_generate_readme_context_does_not_include_source_or_secret_contents(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("PRIVATE_SOURCE_TEXT\n", encoding="utf-8")
    (tmp_path / ".env").write_text("TOKEN=PRIVATE_SECRET_TEXT\n", encoding="utf-8")
    (tmp_path / "id_rsa").write_text("PRIVATE_KEY_TEXT\n", encoding="utf-8")

    result = generate_readme_context(tmp_path)

    serialized = str(result)
    assert "PRIVATE_SOURCE_TEXT" not in serialized
    assert "PRIVATE_SECRET_TEXT" not in serialized
    assert "PRIVATE_KEY_TEXT" not in serialized
    assert ".env" not in serialized
    assert "id_rsa" not in serialized


def test_generate_readme_context_handles_empty_project(tmp_path: Path) -> None:
    result = generate_readme_context(tmp_path)

    assert result["project_name"] == tmp_path.name
    assert result["analysis"]["languages"] == {}
    assert result["project_structure"] == tmp_path.name
    assert result["truncated"] == {
        "project_structure": False,
        "analysis_traversal": False,
        "dependencies": False,
        "manifests": False,
        "configuration_files": False,
        "likely_entry_points": False,
        "test_paths": False,
    }


def test_generate_readme_context_obeys_tree_limits(tmp_path: Path) -> None:
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).touch()

    result = generate_readme_context(tmp_path, max_entries=2)

    assert "entry limit reached" in result["project_structure"]
    assert result["truncated"]["project_structure"] is True


@pytest.mark.parametrize(
    ("max_depth", "max_entries", "message"),
    [
        (-1, 10, "max_depth"),
        (11, 10, "max_depth"),
        (1, 0, "max_entries"),
        (1, 501, "max_entries"),
        (True, 10, "max_depth"),
    ],
)
def test_generate_readme_context_rejects_invalid_limits(
    tmp_path: Path,
    max_depth: int,
    max_entries: int,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        generate_readme_context(tmp_path, max_depth, max_entries)
