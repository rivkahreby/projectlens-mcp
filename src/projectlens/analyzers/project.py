"""Static, bounded project metadata analysis without executing project code."""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ElementTree
from collections import Counter
from pathlib import Path
from typing import TypedDict

from projectlens.security.files import walk_project_files
from projectlens.security.paths import ProjectRootError, resolve_within_root

DEFAULT_MAX_DEPTH = 10
HARD_MAX_DEPTH = 20
MAX_MANIFEST_SIZE_BYTES = 1_048_576
MAX_ANALYZABLE_MANIFESTS = 32
MAX_DEPENDENCIES = 200
MAX_REPORTED_PATHS = 200
MAX_REPORTED_EXTENSIONS = 100
ANALYZABLE_MANIFESTS = {
    "cargo.toml",
    "go.mod",
    "package.json",
    "pipfile",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
}

LANGUAGE_EXTENSIONS = {
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cs": "C#",
    ".css": "CSS",
    ".dart": "Dart",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".go": "Go",
    ".h": "C/C++ Header",
    ".hpp": "C++ Header",
    ".html": "HTML",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".lua": "Lua",
    ".php": "PHP",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".scala": "Scala",
    ".scss": "SCSS",
    ".sh": "Shell",
    ".sql": "SQL",
    ".swift": "Swift",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".vue": "Vue",
    ".xml": "XML",
    ".yaml": "YAML",
    ".yml": "YAML",
}

CONFIG_FILE_NAMES = {
    ".editorconfig",
    ".gitignore",
    ".prettierrc",
    "babel.config.js",
    "docker-compose.yml",
    "dockerfile",
    "eslint.config.js",
    "makefile",
    "pyproject.toml",
    "setup.cfg",
    "tsconfig.json",
    "webpack.config.js",
}
CONFIG_FILE_SUFFIXES = {".ini", ".toml", ".yaml", ".yml"}
ENTRY_POINT_NAMES = {
    "__main__.py",
    "app.py",
    "index.js",
    "index.ts",
    "main.go",
    "main.py",
    "main.rs",
    "manage.py",
    "server.js",
    "server.py",
}

PACKAGE_MANAGER_MARKERS = {
    "bun.lock": "bun",
    "bun.lockb": "bun",
    "cargo.lock": "cargo",
    "composer.lock": "Composer",
    "gemfile.lock": "Bundler",
    "go.sum": "Go modules",
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "poetry.lock": "Poetry",
    "pom.xml": "Maven",
    "pipfile.lock": "Pipenv",
    "requirements.txt": "pip",
    "uv.lock": "uv",
    "yarn.lock": "Yarn",
}

FRAMEWORK_DEPENDENCIES = {
    "actix-web": "Actix Web",
    "angular": "Angular",
    "axum": "Axum",
    "django": "Django",
    "express": "Express",
    "fastapi": "FastAPI",
    "flask": "Flask",
    "next": "Next.js",
    "react": "React",
    "spring-boot-starter-web": "Spring Boot",
    "vue": "Vue",
}

_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_GO_MODULE_NAME = re.compile(r"^\s*([^\s]+)(?:\s+v\S+)?\s*$")


class ProjectAnalysis(TypedDict):
    languages: dict[str, int]
    frameworks: list[str]
    package_managers: list[str]
    dependencies: list[str]
    dependencies_truncated: bool
    manifests_truncated: bool
    configuration_files: list[str]
    configuration_files_truncated: bool
    likely_entry_points: list[str]
    likely_entry_points_truncated: bool
    statistics: dict[str, int | bool]


def analyze_project(root: Path, max_depth: int = DEFAULT_MAX_DEPTH) -> ProjectAnalysis:
    """Detect common project metadata using bounded, declarative file reads."""
    _validate_max_depth(max_depth)
    canonical_root = resolve_within_root(root, root)
    files, traversal_truncated = walk_project_files(canonical_root, max_depth)
    relative_files = sorted(
        (path.relative_to(canonical_root).as_posix(), path) for path in files
    )

    language_counts: Counter[str] = Counter()
    extension_counts: Counter[str] = Counter()
    configuration_files: list[str] = []
    configuration_files_truncated = False
    entry_points: list[str] = []
    entry_points_truncated = False
    manifests: dict[str, list[Path]] = {}
    total_size = 0
    files_scanned = 0

    for relative_path, path in relative_files:
        try:
            safe_path = resolve_within_root(canonical_root, path)
            size = safe_path.stat().st_size
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            raise ProjectRootError(
                f"Unable to inspect project file '{relative_path}': permission denied."
            ) from exc
        except OSError as exc:
            raise ProjectRootError(
                f"Unable to inspect project file '{relative_path}': {exc}"
            ) from exc

        total_size += size
        files_scanned += 1
        suffix = path.suffix.casefold()
        if suffix:
            extension_counts[suffix] += 1
        language = LANGUAGE_EXTENSIONS.get(suffix)
        if language:
            language_counts[language] += 1
        lower_name = path.name.casefold()
        if _is_configuration_file(lower_name):
            if len(configuration_files) < MAX_REPORTED_PATHS + 1:
                configuration_files.append(relative_path)
            else:
                configuration_files_truncated = True
        if lower_name in ENTRY_POINT_NAMES:
            if len(entry_points) < MAX_REPORTED_PATHS + 1:
                entry_points.append(relative_path)
            else:
                entry_points_truncated = True
        manifests.setdefault(lower_name, []).append(path)

    dependency_names: set[str] = set()
    package_managers: set[str] = set()
    framework_names: set[str] = set()
    manifest_count = 0
    manifests_truncated = False

    for name in manifests:
        if name in PACKAGE_MANAGER_MARKERS:
            package_managers.add(PACKAGE_MANAGER_MARKERS[name])

    manifest_paths = sorted(
        (
            path.relative_to(canonical_root).as_posix(),
            name,
            path,
        )
        for name, paths in manifests.items()
        if name in ANALYZABLE_MANIFESTS
        for path in paths
    )
    manifest_paths.sort(key=lambda item: (len(Path(item[0]).parts), item[0].casefold()))

    for _, name, path in manifest_paths:
        if manifest_count >= MAX_ANALYZABLE_MANIFESTS:
            manifests_truncated = True
            break
        manifest_count += 1
        if name == "package.json":
            _collect_npm_metadata(
                canonical_root,
                path,
                dependency_names,
                package_managers,
                framework_names,
            )
        elif name in {"pyproject.toml", "requirements.txt", "pipfile"}:
            _collect_python_metadata(
                canonical_root,
                path,
                dependency_names,
                package_managers,
                framework_names,
            )
        else:
            _collect_native_metadata(
                canonical_root,
                path,
                name,
                dependency_names,
                package_managers,
                framework_names,
            )

    sorted_dependencies = sorted(dependency_names, key=str.casefold)
    dependencies_truncated = len(sorted_dependencies) > MAX_DEPENDENCIES
    sorted_configuration_files = sorted(configuration_files, key=str.casefold)
    sorted_entry_points = sorted(entry_points, key=str.casefold)
    sorted_extensions = sorted(extension_counts.items(), key=lambda item: (-item[1], item[0]))

    return {
        "languages": dict(sorted(language_counts.items(), key=lambda item: item[0].casefold())),
        "frameworks": sorted(framework_names, key=str.casefold),
        "package_managers": sorted(package_managers, key=str.casefold),
        "dependencies": sorted_dependencies[:MAX_DEPENDENCIES],
        "dependencies_truncated": dependencies_truncated,
        "manifests_truncated": manifests_truncated,
        "configuration_files": sorted_configuration_files[:MAX_REPORTED_PATHS],
        "configuration_files_truncated": (
            configuration_files_truncated
            or len(sorted_configuration_files) > MAX_REPORTED_PATHS
        ),
        "likely_entry_points": sorted_entry_points[:MAX_REPORTED_PATHS],
        "likely_entry_points_truncated": (
            entry_points_truncated or len(sorted_entry_points) > MAX_REPORTED_PATHS
        ),
        "statistics": {
            "files_scanned": files_scanned,
            "total_size_bytes": total_size,
            "extensions": dict(sorted_extensions[:MAX_REPORTED_EXTENSIONS]),
            "extensions_truncated": len(sorted_extensions) > MAX_REPORTED_EXTENSIONS,
            "traversal_truncated": traversal_truncated,
        },
    }


def _is_configuration_file(lower_name: str) -> bool:
    return (
        lower_name in CONFIG_FILE_NAMES
        or lower_name.endswith(".config.js")
        or Path(lower_name).suffix in CONFIG_FILE_SUFFIXES
    )


def _read_manifest(root: Path, path: Path) -> bytes | None:
    relative_path = path.relative_to(root).as_posix()
    try:
        safe_path = resolve_within_root(root, path)
        with safe_path.open("rb") as manifest:
            contents = manifest.read(MAX_MANIFEST_SIZE_BYTES + 1)
    except FileNotFoundError:
        return None
    except PermissionError as exc:
        raise ProjectRootError(
            f"Unable to read project manifest '{relative_path}': permission denied."
        ) from exc
    except OSError as exc:
        raise ProjectRootError(
            f"Unable to read project manifest '{relative_path}': {exc}"
        ) from exc
    if len(contents) > MAX_MANIFEST_SIZE_BYTES or b"\0" in contents:
        return None
    return contents


def _collect_npm_metadata(
    root: Path,
    path: Path,
    dependencies: set[str],
    package_managers: set[str],
    frameworks: set[str],
) -> None:
    if path.name.casefold() != "package.json":
        return
    contents = _read_manifest(root, path)
    if contents is None:
        return
    try:
        data = json.loads(contents)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return
    package_managers.add("npm")
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        values = data.get(section, {})
        if not isinstance(values, dict):
            continue
        for name in values:
            if isinstance(name, str):
                dependencies.add(name)
                framework = FRAMEWORK_DEPENDENCIES.get(name.casefold())
                if framework:
                    frameworks.add(framework)
def _collect_python_metadata(
    root: Path,
    path: Path,
    dependencies: set[str],
    package_managers: set[str],
    frameworks: set[str],
) -> None:
    name = path.name.casefold()
    contents = _read_manifest(root, path)
    if contents is None:
        return
    if name == "requirements.txt":
        try:
            lines = contents.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            return
        package_managers.add("pip")
        for line in lines:
            match = _REQUIREMENT_NAME.match(line)
            if not match or line.lstrip().startswith(("#", "-")):
                continue
            _add_dependency(match.group(1), dependencies, frameworks)
    elif name == "pipfile":
        try:
            data = tomllib.loads(contents.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            return
        package_managers.add("Pipenv")
        for section in ("packages", "dev-packages"):
            values = data.get(section, {})
            if isinstance(values, dict):
                for dependency in values:
                    if isinstance(dependency, str):
                        _add_dependency(dependency, dependencies, frameworks)
    else:
        try:
            data = tomllib.loads(contents.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            return
        project = data.get("project", {})
        if isinstance(project, dict):
            package_managers.add("pip")
            _add_python_requirements(project.get("dependencies", []), dependencies, frameworks)
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for values in optional.values():
                    _add_python_requirements(values, dependencies, frameworks)
        tool = data.get("tool", {})
        if isinstance(tool, dict):
            if isinstance(tool.get("poetry"), dict):
                package_managers.add("Poetry")
                poetry = tool["poetry"]
                _add_python_mapping(poetry.get("dependencies", {}), dependencies, frameworks)
                _add_python_mapping(poetry.get("dev-dependencies", {}), dependencies, frameworks)
            if isinstance(tool.get("uv"), dict):
                package_managers.add("uv")
        if "build-system" in data:
            package_managers.add("pip")


def _collect_native_metadata(
    root: Path,
    path: Path,
    name: str,
    dependencies: set[str],
    package_managers: set[str],
    frameworks: set[str],
) -> None:
    contents = _read_manifest(root, path)
    if contents is None:
        return
    try:
        text = contents.decode("utf-8")
    except UnicodeDecodeError:
        return
    if name == "cargo.toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return
        package_managers.add("Cargo")
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            _add_mapping_keys(data.get(section, {}), dependencies, frameworks)
    elif name == "go.mod":
        package_managers.add("Go modules")
        in_require_block = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require_block = True
                continue
            if in_require_block and stripped == ")":
                in_require_block = False
                continue
            if stripped.startswith("require "):
                stripped = stripped.removeprefix("require ").strip()
                in_require_block = False
            elif not in_require_block:
                continue
            match = _GO_MODULE_NAME.match(stripped)
            if match and not stripped.startswith(("//", "module ", "go ")):
                _add_dependency(match.group(1), dependencies, frameworks)
    else:
        try:
            document = ElementTree.fromstring(text)
        except ElementTree.ParseError:
            return
        package_managers.add("Maven")
        for element in document.iter():
            if not element.tag.endswith("dependency"):
                continue
            for child in element:
                if child.tag.endswith("artifactId") and child.text:
                    _add_dependency(child.text.strip(), dependencies, frameworks)


def _add_python_requirements(
    values: object,
    dependencies: set[str],
    frameworks: set[str],
) -> None:
    if not isinstance(values, list):
        return
    for value in values:
        if isinstance(value, str):
            match = _REQUIREMENT_NAME.match(value)
            if match:
                _add_dependency(match.group(1), dependencies, frameworks)


def _add_python_mapping(
    values: object,
    dependencies: set[str],
    frameworks: set[str],
) -> None:
    _add_mapping_keys(values, dependencies, frameworks)


def _add_mapping_keys(
    values: object,
    dependencies: set[str],
    frameworks: set[str],
) -> None:
    if not isinstance(values, dict):
        return
    for value in values:
        if isinstance(value, str):
            _add_dependency(value, dependencies, frameworks)


def _add_dependency(
    name: str,
    dependencies: set[str],
    frameworks: set[str],
) -> None:
    normalized = name.strip()
    if not normalized:
        return
    framework = FRAMEWORK_DEPENDENCIES.get(normalized.casefold())
    if framework:
        frameworks.add(framework)
    if normalized not in dependencies and len(dependencies) < MAX_DEPENDENCIES + 1:
        dependencies.add(normalized)


def _validate_max_depth(max_depth: int) -> None:
    if isinstance(max_depth, bool) or not isinstance(max_depth, int):
        raise ValueError("max_depth must be an integer.")
    if not 0 <= max_depth <= HARD_MAX_DEPTH:
        raise ValueError(f"max_depth must be between 0 and {HARD_MAX_DEPTH}.")
