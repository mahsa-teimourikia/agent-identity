"""Run each course's tracked tests in its own Python process."""

from __future__ import annotations

import subprocess
import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def tracked_test_groups() -> dict[str, list[str]]:
    result = subprocess.run(
        ["git", "ls-files", "curriculum/**/tests/test*.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    groups: dict[str, list[str]] = defaultdict(list)
    for filename in result.stdout.splitlines():
        course = filename.split("/tests/", 1)[0]
        groups[course].append(filename)
    return dict(sorted(groups.items()))


def main() -> None:
    groups = tracked_test_groups()
    if not groups:
        raise SystemExit("No tracked course tests found.")
    test_files = 0
    for course, files in groups.items():
        print(f"\n== {course} ==", flush=True)
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q", *files],
            cwd=ROOT,
            check=True,
        )
        test_files += len(files)
    print(f"\nPassed {len(groups)} course suites across {test_files} tracked test files.")


if __name__ == "__main__":
    main()
