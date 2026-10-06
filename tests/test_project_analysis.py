import json
from pathlib import Path

import pytest

from projectlens.analyzers.project import analyze_project


def test_analyze_project_detects_languages_and_statistics(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "src" / "app.ts").write_text("export const app = true;\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("Project docs\n", encoding="utf-8")

    result = analyze_project(tmp_path)

    assert result["languages"] == {"Python": 1, "TypeScript": 1}
    assert result["statistics"]["files_scanned"] == 3
    assert result["statistics"]["total_size_bytes"] > 0
    assert result["statistics"]["extensions"] == {".md": 1, ".py": 1, ".ts": 1}


def test_analyze_project_detects_python_dependencies_frameworks_and_managers(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
dependencies = ["fastapi>=0.100", "requests>=2"]

[project.optional-dependencies]
dev = ["pytest>=8"]
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("flask==3.0\n", encoding="utf-8")
    (tmp_path / "poetry.lock").touch()
    (tmp_path / "main.py").touch()

    result = analyze_project(tmp_path)

    assert {"FastAPI", "Flask"} <= set(result["frameworks"])
    assert {"fastapi", "requests", "pytest", "flask"} <= set(result["dependencies"])
    assert {"pip", "Poetry"} <= set(result["package_managers"])
    assert "main.py" in result["likely_entry_points"]


def test_analyze_project_detects_npm_metadata_and_configuration(tmp_path: Path) -> None:
    package = {
        "dependencies": {"react": "^18.0.0", "next": "^14.0.0"},
        "devDependencies": {"typescript": "^5.0.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(package), encoding="utf-8")
    (tmp_path / "package-lock.json").touch()
    (tmp_path / "tsconfig.json").touch()
    (tmp_path / "index.ts").touch()

    result = analyze_project(tmp_path)

    assert {"React", "Next.js"} <= set(result["frameworks"])
    assert {"react", "next", "typescript"} <= set(result["dependencies"])
    assert "npm" in result["package_managers"]
    assert "tsconfig.json" in result["configuration_files"]
    assert "index.ts" in result["likely_entry_points"]


def test_analyze_project_detects_cargo_dependencies(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        """
[dependencies]
axum = "0.7"
serde = { version = "1", features = ["derive"] }
""".strip(),
        encoding="utf-8",
    )

    result = analyze_project(tmp_path)

    assert {"axum", "serde"} <= set(result["dependencies"])
    assert "Axum" in result["frameworks"]
    assert "Cargo" in result["package_managers"]


def test_analyze_project_detects_maven_dependencies_not_project_artifact(
    tmp_path: Path,
) -> None:
    (tmp_path / "pom.xml").write_text(
        """
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <artifactId>sample-app</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
  </dependencies>
</project>
""".strip(),
        encoding="utf-8",
    )

    result = analyze_project(tmp_path)

    assert result["dependencies"] == ["spring-boot-starter-web"]
    assert "Spring Boot" in result["frameworks"]
    assert "Maven" in result["package_managers"]


def test_analyze_project_handles_empty_project(tmp_path: Path) -> None:
    result = analyze_project(tmp_path)

    assert result["languages"] == {}
    assert result["frameworks"] == []
    assert result["dependencies"] == []
    assert result["configuration_files"] == []
    assert result["likely_entry_points"] == []
    assert result["statistics"]["files_scanned"] == 0
    assert result["statistics"]["total_size_bytes"] == 0


def test_analyze_project_skips_malformed_and_oversized_manifests(
    tmp_path: Path,
) -> None:
    (tmp_path / "package.json").write_text("{ invalid json", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_bytes(b"x" * 1_048_577)

    result = analyze_project(tmp_path)

    assert result["dependencies"] == []


def test_analyze_project_caps_dependencies_and_manifest_reads(tmp_path: Path) -> None:
    dependencies = [f"library-{index}>=1" for index in range(250)]
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = [\n"
        + "".join(f'  "{dependency}",\n' for dependency in dependencies)
        + "]\n",
        encoding="utf-8",
    )
    for index in range(33):
        package_dir = tmp_path / f"package-{index:02d}"
        package_dir.mkdir()
        (package_dir / "requirements.txt").write_text(
            f"nested-library-{index}\n",
            encoding="utf-8",
        )

    result = analyze_project(tmp_path, max_depth=2)

    assert len(result["dependencies"]) == 200
    assert result["dependencies_truncated"] is True
    assert result["manifests_truncated"] is True


def test_analyze_project_caps_configuration_entrypoint_and_extension_results(
    tmp_path: Path,
) -> None:
    for index in range(205):
        (tmp_path / f"config-{index:03}.yaml").touch()
        service_dir = tmp_path / f"service-{index:03}"
        service_dir.mkdir()
        (service_dir / "main.py").touch()
    for index in range(105):
        (tmp_path / f"data-{index:03}.ext{index:03}").touch()

    result = analyze_project(tmp_path, max_depth=2)

    assert len(result["configuration_files"]) == 200
    assert result["configuration_files_truncated"] is True
    assert len(result["likely_entry_points"]) == 200
    assert result["likely_entry_points_truncated"] is True
    assert len(result["statistics"]["extensions"]) == 100
    assert result["statistics"]["extensions_truncated"] is True


def test_analyze_project_does_not_report_secrets_or_ignored_directories(
    tmp_path: Path,
) -> None:
    (tmp_path / ".env").write_text("TOKEN=secret", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "secret.py").touch()
    (tmp_path / "safe.py").touch()

    result = analyze_project(tmp_path)

    assert result["statistics"]["files_scanned"] == 1
    assert "secret.py" not in str(result)
    assert ".env" not in str(result)


@pytest.mark.parametrize("max_depth", [-1, 21, True])
def test_analyze_project_rejects_invalid_depth(
    tmp_path: Path,
    max_depth: int,
) -> None:
    with pytest.raises(ValueError, match="max_depth"):
        analyze_project(tmp_path, max_depth)
