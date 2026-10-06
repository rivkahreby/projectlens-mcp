"""MCP server entry point for ProjectLens."""

from pathlib import Path

from fastmcp import FastMCP

from projectlens.analyzers.project import (
    DEFAULT_MAX_DEPTH as DEFAULT_ANALYSIS_MAX_DEPTH,
    analyze_project as analyze_project_data,
)
from projectlens.security.paths import configured_project_root, validate_project_root
from projectlens.tools.project_structure import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_ENTRIES,
    build_project_structure,
)
from projectlens.tools.readme_context import (
    DEFAULT_MAX_DEPTH as DEFAULT_README_CONTEXT_MAX_DEPTH,
    DEFAULT_MAX_ENTRIES as DEFAULT_README_CONTEXT_MAX_ENTRIES,
    generate_readme_context as generate_readme_context_data,
)
from projectlens.tools.search import (
    DEFAULT_MAX_DEPTH as DEFAULT_SEARCH_MAX_DEPTH,
    DEFAULT_MAX_RESULTS,
    search_project_code,
    search_project_files,
)


def create_server(project_root: Path) -> FastMCP:
    """Create an MCP server bound to one validated project directory."""
    root = validate_project_root(project_root)
    server = FastMCP("ProjectLens MCP")

    @server.tool
    def ping() -> str:
        """Check that the ProjectLens MCP server is responding."""
        return "ProjectLens MCP is running."

    @server.tool
    def project_structure(
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> str:
        """Show a bounded tree of the configured project directory."""
        return build_project_structure(root, max_depth, max_entries)

    @server.tool
    def search_files(
        query: str,
        extension: str | None = None,
        path_contains: str | None = None,
        max_depth: int = DEFAULT_SEARCH_MAX_DEPTH,
        max_results: int = DEFAULT_MAX_RESULTS,
    ) -> dict[str, object]:
        """Find project filenames by substring with optional extension/path filters."""
        return search_project_files(
            root, query, extension, path_contains, max_depth, max_results
        )

    @server.tool
    def search_code(
        query: str,
        extension: str | None = None,
        path_contains: str | None = None,
        case_sensitive: bool = False,
        max_depth: int = DEFAULT_SEARCH_MAX_DEPTH,
        max_results: int = DEFAULT_MAX_RESULTS,
    ) -> dict[str, object]:
        """Search safe, size-limited UTF-8 project files for literal text."""
        return search_project_code(
            root,
            query,
            extension,
            path_contains,
            case_sensitive,
            max_depth,
            max_results,
        )

    @server.tool
    def analyze_project(
        max_depth: int = DEFAULT_ANALYSIS_MAX_DEPTH,
    ) -> dict[str, object]:
        """Detect languages, dependencies, tools, configuration, entry points, and statistics."""
        return analyze_project_data(root, max_depth)

    @server.tool
    def generate_readme_context(
        max_depth: int = DEFAULT_README_CONTEXT_MAX_DEPTH,
        max_entries: int = DEFAULT_README_CONTEXT_MAX_ENTRIES,
    ) -> dict[str, object]:
        """Collect bounded project metadata for an MCP client to draft a README."""
        return generate_readme_context_data(root, max_depth, max_entries)

    return server


def main() -> None:
    """Run the server using MCP's standard input/output transport."""
    server = create_server(configured_project_root())
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
