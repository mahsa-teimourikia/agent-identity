"""Build the static GitHub Pages artifact using the deployment layout."""

from __future__ import annotations

import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"


def copy_contents(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        target = destination / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True)
        else:
            shutil.copy2(item, target)


def main() -> None:
    if SITE.exists():
        shutil.rmtree(SITE)
    copy_contents(ROOT / "hub", SITE)
    copy_contents(ROOT / "quiz", SITE / "quiz")
    copy_contents(ROOT / "assets", SITE / "assets")
    required = ("index.html", "app.js", "lessons.js", "quiz/index.html", "quiz/app.js")
    missing = [name for name in required if not (SITE / name).is_file()]
    if missing:
        raise SystemExit(f"Static site build is missing: {', '.join(missing)}")
    file_count = sum(path.is_file() for path in SITE.rglob("*"))
    print(f"Built {SITE.relative_to(ROOT)}/ with {file_count} files.")


if __name__ == "__main__":
    main()
