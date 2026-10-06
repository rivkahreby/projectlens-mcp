import asyncio
from pathlib import Path

from fastmcp import Client
import pytest

from projectlens.security.paths import ProjectRootError
from projectlens.server import create_server


def test_server_exposes_all_project_tools_and_readme_context(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hello')\n", encoding="utf-8")
    server = create_server(tmp_path)

    async def exercise_client() -> None:
        async with Client(server) as client:
            tools = await client.list_tools()
            tool_names = {tool.name for tool in tools}
            assert {
                "ping",
                "project_structure",
                "search_files",
                "search_code",
                "analyze_project",
                "generate_readme_context",
            } <= tool_names

            result = await client.call_tool("generate_readme_context", {})
            assert result.is_error is False
            assert result.structured_content["project_name"] == tmp_path.name
            assert result.structured_content["analysis"]["languages"] == {"Python": 1}

    asyncio.run(exercise_client())


def test_project_analysis_and_readme_context_do_not_execute_project_code(
    tmp_path: Path,
) -> None:
    sentinel = tmp_path / "project-code-was-executed.txt"
    (tmp_path / "setup.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    server = create_server(tmp_path)

    async def inspect_project() -> None:
        async with Client(server) as client:
            analysis = await client.call_tool("analyze_project", {})
            context = await client.call_tool("generate_readme_context", {})
            assert analysis.is_error is False
            assert context.is_error is False

    asyncio.run(inspect_project())

    assert not sentinel.exists()


def test_server_rejects_invalid_project_root(tmp_path: Path) -> None:
    not_a_directory = tmp_path / "file.txt"
    not_a_directory.touch()

    with pytest.raises(ProjectRootError, match="directory"):
        create_server(not_a_directory)
