"""Bounded, evidence-based context for a client-generated README."""

from __future__ import annotations

from pathlib import Path
from typing import TypedDict

from projectlens.analyzers.project import analyze_project
from projectlens.tools.project_structure import build_project_structure

DEFAULT_MAX_DEPTH = 4
HARD_MAX_DEPTH = 10
DEFAULT_MAX_ENTRIES = 200
HARD_MAX_ENTRIES = 500
MAX_CONTEXT_PATHS = 30
MAX_CONTEXT_DEPENDENCIES = 30


class ReadmeSection(TypedDict):
    title: str
    evidence: list[str]
    needs_confirmation: list[str]


class ReadmeContext(TypedDict):
    project_name: str
    analysis: dict[str, object]
    project_structure: str
    suggested_sections: list[ReadmeSection]
    truncated: dict[str, bool]
    note: str


def generate_readme_context(
    root: Path,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> ReadmeContext:
    """Collect concise, project-grounded context without generating README text."""
    _validate_limits(max_depth, max_entries)
    structure = build_project_structure(root, max_depth, max_entries)
    analysis = analyze_project(root, max_depth)

    dependencies = analysis["dependencies"]
    configuration_files = analysis["configuration_files"]
    entry_points = analysis["likely_entry_points"]
    statistics = analysis["statistics"]
    tests = _likely_test_paths(root, max_depth)

    bounded_analysis: dict[str, object] = {
        "languages": analysis["languages"],
        "frameworks": analysis["frameworks"],
        "package_managers": analysis["package_managers"],
        "dependencies": dependencies[:MAX_CONTEXT_DEPENDENCIES],
        "dependencies_truncated": (
            analysis["dependencies_truncated"]
            or len(dependencies) > MAX_CONTEXT_DEPENDENCIES
        ),
        "manifests_truncated": analysis["manifests_truncated"],
        "configuration_files": configuration_files[:MAX_CONTEXT_PATHS],
        "configuration_files_truncated": (
            analysis["configuration_files_truncated"]
            or len(configuration_files) > MAX_CONTEXT_PATHS
        ),
        "likely_entry_points": entry_points[:MAX_CONTEXT_PATHS],
        "likely_entry_points_truncated": (
            analysis["likely_entry_points_truncated"]
            or len(entry_points) > MAX_CONTEXT_PATHS
        ),
        "statistics": statistics,
    }

    language_names = list(analysis["languages"])
    frameworks = analysis["frameworks"]
    package_managers = analysis["package_managers"]
    overview_evidence = [f"Project directory name: {root.resolve().name}"]
    if language_names:
        overview_evidence.append(f"Detected languages: {', '.join(language_names)}")

    architecture_evidence = []
    if frameworks:
        architecture_evidence.append(f"Detected frameworks: {', '.join(frameworks)}")
    if entry_points:
        architecture_evidence.append(
            f"Likely entry points: {', '.join(entry_points[:MAX_CONTEXT_PATHS])}"
        )
    if not architecture_evidence:
        architecture_evidence.append("Use the included directory tree as structural evidence.")

    installation_evidence = []
    if package_managers:
        installation_evidence.append(
            f"Detected package managers: {', '.join(package_managers)}"
        )
    if configuration_files:
        installation_evidence.append(
            f"Relevant configuration paths: {', '.join(configuration_files[:MAX_CONTEXT_PATHS])}"
        )
    if dependencies:
        installation_evidence.append(
            f"Detected dependencies: {', '.join(dependencies[:MAX_CONTEXT_DEPENDENCIES])}"
        )
    if not installation_evidence:
        installation_evidence.append("No supported package manager or configuration was detected.")

    usage_evidence = []
    if entry_points:
        usage_evidence.append(
            f"Likely entry points: {', '.join(entry_points[:MAX_CONTEXT_PATHS])}"
        )
    if not usage_evidence:
        usage_evidence.append("No conventional entry-point filename was detected.")

    testing_evidence = [f"Likely test path: {path}" for path in tests]
    if not testing_evidence:
        testing_evidence.append("No conventional test path was detected.")

    sections: list[ReadmeSection] = [
        {
            "title": "Overview",
            "evidence": overview_evidence,
            "needs_confirmation": ["Project purpose and intended audience."],
        },
        {
            "title": "Features and architecture",
            "evidence": architecture_evidence,
            "needs_confirmation": ["Feature descriptions and runtime behavior."],
        },
        {
            "title": "Installation",
            "evidence": installation_evidence,
            "needs_confirmation": ["Supported runtime versions and verified install commands."],
        },
        {
            "title": "Usage",
            "evidence": usage_evidence,
            "needs_confirmation": ["Verified commands, options, and expected behavior."],
        },
        {
            "title": "Testing",
            "evidence": testing_evidence,
            "needs_confirmation": ["Verified test command and current test status."],
        },
        {
            "title": "Configuration and security",
            "evidence": [
                f"Configuration paths: {', '.join(configuration_files[:MAX_CONTEXT_PATHS])}"
            ]
            if configuration_files
            else ["No supported configuration files were detected."],
            "needs_confirmation": ["Required settings, security guarantees, and limitations."],
        },
    ]

    return {
        "project_name": root.resolve().name,
        "analysis": bounded_analysis,
        "project_structure": structure,
        "suggested_sections": sections,
        "truncated": {
            "project_structure": "... (entry limit reached)" in structure,
            "analysis_traversal": bool(statistics["traversal_truncated"]),
            "dependencies": bool(bounded_analysis["dependencies_truncated"]),
            "manifests": bool(bounded_analysis["manifests_truncated"]),
            "configuration_files": bool(bounded_analysis["configuration_files_truncated"]),
            "likely_entry_points": bool(bounded_analysis["likely_entry_points_truncated"]),
            "test_paths": len(tests) >= MAX_CONTEXT_PATHS,
        },
        "note": (
            "This is structured local metadata for an MCP client to use when drafting "
            "a README. It contains no generated README prose; verify inferred details "
            "before documenting them."
        ),
    }


def _likely_test_paths(root: Path, max_depth: int) -> list[str]:
    tests: list[str] = []
    for current, filenames in _walk_bounded(root, max_depth):
        relative_directory = current.relative_to(root.resolve()).as_posix()
        if relative_directory == ".":
            relative_directory = ""
        if current.name.casefold() in {"test", "tests", "spec", "specs"}:
            tests.append(relative_directory or ".")
        for filename in filenames:
            lowered = filename.casefold()
            if (
                lowered.startswith("test_")
                or lowered.endswith((".test.js", ".test.ts", ".spec.js", ".spec.ts"))
            ):
                tests.append(
                    f"{relative_directory}/{filename}".lstrip("/")
                )
            if len(tests) >= MAX_CONTEXT_PATHS:
                return sorted(set(tests), key=str.casefold)[:MAX_CONTEXT_PATHS]
    return sorted(set(tests), key=str.casefold)[:MAX_CONTEXT_PATHS]


def _walk_bounded(root: Path, max_depth: int) -> list[tuple[Path, list[str]]]:
    """Collect directories and file names using the existing safe project tree."""
    from projectlens.security.files import walk_project_files

    canonical_root = root.resolve()
    files, _ = walk_project_files(canonical_root, max_depth)
    grouped: dict[Path, list[str]] = {canonical_root: []}
    for file_path in files:
        parent = file_path.parent
        grouped.setdefault(parent, []).append(file_path.name)
        while parent != canonical_root:
            parent = parent.parent
            grouped.setdefault(parent, [])
    return [(directory, grouped[directory]) for directory in sorted(grouped)]


def _validate_limits(max_depth: int, max_entries: int) -> None:
    if isinstance(max_depth, bool) or not isinstance(max_depth, int):
        raise ValueError("max_depth must be an integer.")
    if not 0 <= max_depth <= HARD_MAX_DEPTH:
        raise ValueError(f"max_depth must be between 0 and {HARD_MAX_DEPTH}.")
    if isinstance(max_entries, bool) or not isinstance(max_entries, int):
        raise ValueError("max_entries must be an integer.")
    if not 1 <= max_entries <= HARD_MAX_ENTRIES:
        raise ValueError(f"max_entries must be between 1 and {HARD_MAX_ENTRIES}.")
