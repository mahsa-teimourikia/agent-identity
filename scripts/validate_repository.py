"""Validate repository structure, documentation, and dependency consistency."""

from __future__ import annotations

import ast
import importlib.metadata
import re
import subprocess
import sys
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]


def tracked(pattern: str | None = None) -> list[Path]:
    command = ["git", "ls-files"]
    if pattern:
        command.append(pattern)
    result = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    return [Path(line) for line in result.stdout.splitlines() if line]


def markdown_targets(text: str) -> list[str]:
    matches = re.findall(r"(?:!\[[^]]*\]|\[[^]]*\])\(([^)]+)\)", text)
    return [match.strip().split()[0].strip("<>") for match in matches]


def validate() -> tuple[list[str], dict[str, int]]:
    errors: list[str] = []
    tracked_files = tracked()
    tracked_set = {path.as_posix() for path in tracked_files}
    markdown_files = [path for path in tracked_files if path.suffix.lower() == ".md"]
    python_files = [path for path in tracked_files if path.suffix == ".py"]

    course_readmes = sorted(
        path for path in tracked_files
        if re.fullmatch(r"curriculum/(beginner|intermediate|advanced)/[^/]+/README\.md", path.as_posix())
    )
    course_dirs = [path.parent for path in course_readmes]
    if len(course_dirs) != 31:
        errors.append(f"Expected 31 published courses, found {len(course_dirs)}.")

    for course in course_dirs:
        required = (course / "README.md", course / "lab.py", course / "requirements.txt")
        for path in required:
            if path.as_posix() not in tracked_set:
                errors.append(f"Missing tracked course artifact: {path}")
        notebooks = [path for path in tracked_files if path.parent == course and path.suffix == ".ipynb"]
        if len(notebooks) != 1:
            errors.append(f"{course} must have exactly one primary notebook; found {len(notebooks)}.")
        tests = [path for path in tracked_files if path.parent == course / "tests" and path.name.startswith("test") and path.suffix == ".py"]
        if not tests:
            errors.append(f"{course} has no tracked invariant tests.")

    root_readme = (ROOT / "README.md").read_text(encoding="utf-8")
    listed_courses = {
        target.rstrip("/") for target in markdown_targets(root_readme)
        if target.startswith("curriculum/") and target.count("/") >= 2
    }
    expected_courses = {course.as_posix() for course in course_dirs}
    if listed_courses != expected_courses:
        missing = sorted(expected_courses - listed_courses)
        extra = sorted(listed_courses - expected_courses)
        errors.append(f"README curriculum map drifted (missing={missing}, extra={extra}).")

    local_links = 0
    for path in markdown_files:
        text = (ROOT / path).read_text(encoding="utf-8")
        for target in markdown_targets(text):
            if not target or target.startswith(("http://", "https://", "mailto:", "#", "data:")):
                continue
            local_links += 1
            relative = target.split("#", 1)[0].split("?", 1)[0]
            if relative and not ((ROOT / path).parent / relative).resolve().exists():
                errors.append(f"Broken local link in {path}: {target}")
        if re.search(r"^(?:<{7}|={7}|>{7})(?: .*)?$", text, re.MULTILINE):
            errors.append(f"Merge marker found in {path}.")

    for path in python_files:
        try:
            ast.parse((ROOT / path).read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, UnicodeDecodeError) as error:
            errors.append(f"Python parse failed for {path}: {error}")

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    central_requirements = [Requirement(value) for value in project["project"]["dependencies"]]
    for values in project.get("dependency-groups", {}).values():
        central_requirements.extend(Requirement(value) for value in values)
    central_names = {canonicalize_name(requirement.name) for requirement in central_requirements}
    requirement_entries = 0
    for course in course_dirs:
        requirement_file = ROOT / course / "requirements.txt"
        for number, raw_line in enumerate(requirement_file.read_text(encoding="utf-8").splitlines(), start=1):
            line = raw_line.split(" #", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            requirement_entries += 1
            try:
                requirement = Requirement(line)
            except ValueError as error:
                errors.append(f"Invalid requirement at {course}/requirements.txt:{number}: {error}")
                continue
            name = canonicalize_name(requirement.name)
            if name not in central_names:
                errors.append(f"{course}/requirements.txt uses {requirement.name}, which is absent from pyproject.toml.")
                continue
            try:
                installed = importlib.metadata.version(requirement.name)
            except importlib.metadata.PackageNotFoundError:
                errors.append(f"Central environment is missing {requirement.name} required by {course}.")
                continue
            if requirement.specifier and not requirement.specifier.contains(installed, prereleases=True):
                errors.append(
                    f"{course}/requirements.txt rejects the locked {requirement.name} {installed}: {requirement.specifier}"
                )

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    make_targets = set(re.findall(r"^([a-zA-Z_-]+):", makefile, re.MULTILINE))
    documented_targets: set[str] = set()
    for path in (Path("README.md"), Path("CONTRIBUTING.md"), Path("DEPENDENCIES.md")):
        candidate = ROOT / path
        if candidate.exists():
            documented_targets.update(
                re.findall(r"^\s*make\s+([a-zA-Z_-]+)", candidate.read_text(encoding="utf-8"), re.MULTILINE)
            )
    unknown_targets = documented_targets - make_targets
    if unknown_targets:
        errors.append(f"Documentation names missing Make targets: {sorted(unknown_targets)}")

    duplicate_pattern = re.compile(r"(?:^|/)[^/]+ [23](?:\.[^/]+)?$")
    duplicates = [path.as_posix() for path in tracked_files if duplicate_pattern.search(path.as_posix())]
    if duplicates:
        errors.append(f"Tracked duplicate-suffix artifacts found: {duplicates}")

    stats = {
        "courses": len(course_dirs),
        "markdown_files": len(markdown_files),
        "local_links": local_links,
        "python_files": len(python_files),
        "requirements": requirement_entries,
    }
    return errors, stats


if __name__ == "__main__":
    failures, summary = validate()
    if failures:
        print("Repository validation failed:")
        for failure in failures:
            print(f"- {failure}")
        sys.exit(1)
    print(
        "Repository valid: "
        f"{summary['courses']} courses, {summary['markdown_files']} Markdown files, "
        f"{summary['local_links']} local links, {summary['python_files']} Python files, "
        f"{summary['requirements']} course requirements."
    )
