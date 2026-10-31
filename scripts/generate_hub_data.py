"""Generate deterministic Learning Hub and quiz data from the curriculum."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from custom_questions import get_questions_for_module


ROOT = Path(__file__).resolve().parents[1]
LEVELS = ("beginner", "intermediate", "advanced")
REPO = "https://github.com/mahsa-teimourikia/agent-identity/blob/main/"


def _plain(text: str) -> str:
    text = re.sub(r"\[([^]]+)]\([^)]+\)", r"\1", text)
    text = re.sub(r"[`*_]", "", text)
    return re.sub(r"\s+", " ", text).strip(" -;.")


def _goal(content: str, title: str) -> str:
    lines = content.splitlines()
    for index, line in enumerate(lines):
        if re.search(r"\*\*Goal:\*\*", line, re.IGNORECASE):
            parts = [re.sub(r"^\s*>\s*", "", line)]
            cursor = index + 1
            while cursor < len(lines) and re.match(r"^\s*>", lines[cursor]):
                parts.append(re.sub(r"^\s*>\s*", "", lines[cursor]))
                cursor += 1
            goal = re.sub(r".*?\*\*Goal:\*\*\s*", "", " ".join(parts), flags=re.IGNORECASE)
            return _plain(goal)
    return f"Learn the concepts, controls, and practical implementation patterns in {title}"


def _section(content: str, names: Iterable[str]) -> str:
    accepted = {name.casefold() for name in names}
    lines = content.splitlines()
    for index, line in enumerate(lines):
        heading = re.match(r"^(#{1,4})\s+(.+?)\s*$", line)
        if not heading or _plain(heading.group(2)).casefold() not in accepted:
            continue
        depth = len(heading.group(1))
        collected: list[str] = []
        for candidate in lines[index + 1 :]:
            next_heading = re.match(r"^(#{1,4})\s+", candidate)
            if next_heading and len(next_heading.group(1)) <= depth:
                break
            collected.append(candidate)
        return "\n".join(collected)
    return ""


def _list_items(text: str, limit: int = 6) -> list[str]:
    items: list[str] = []
    current = ""
    for line in text.splitlines():
        marker = re.match(r"^\s*(?:[-*]|\d+[.)])\s+(.+)", line)
        if marker:
            if current:
                items.append(_plain(current))
            current = marker.group(1)
        elif current and line.strip() and not line.lstrip().startswith(("#", "```")):
            current += " " + line.strip()
        elif current:
            items.append(_plain(current))
            current = ""
    if current:
        items.append(_plain(current))
    return [item for item in items if len(item) > 12][:limit]


def _outcomes(content: str, goal: str) -> list[str]:
    section = _section(content, ("Learning outcomes", "Learning objectives", "What you will learn"))
    if not section:
        match = re.search(
            r"(?:By the end[^:]*|After this course[^:]*)\s*:\s*\n(.*?)(?=^##\s+|\Z)",
            content,
            re.IGNORECASE | re.MULTILINE | re.DOTALL,
        )
        section = match.group(1) if match else ""
    items = _list_items(section)
    if not items and section:
        narrative = _plain(section).removeprefix("You will learn to ")
        items = [item.strip() for item in re.split(r";\s*|;?\s+and\s+", narrative) if len(item.strip()) > 12][:6]
    if not items:
        items = _list_items(_section(content, ("Success criteria", "Capstone contract")))
    return items if items else [goal]


def _references(content: str) -> list[dict[str, str]]:
    reference_section = _section(content, ("References", "Sources", "Further reading"))
    haystack = reference_section or content
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for label, url in re.findall(r"\[([^]]+)]\((https?://[^)]+)\)", haystack):
        url = url.strip()
        if url in seen:
            continue
        seen.add(url)
        found.append({"label": _plain(label), "url": url})
        if len(found) == 5:
            break
    if len(found) < 5:
        for url in re.findall(r"https?://[^\s)>]+", haystack):
            url = url.rstrip(".,;]")
            if url in seen:
                continue
            seen.add(url)
            host = urlparse(url).netloc.removeprefix("www.")
            found.append({"label": host, "url": url})
            if len(found) == 5:
                break
    return found


def _rotate_question(question: tuple, target_index: int) -> dict:
    text, raw_options, answer, explanation = question
    options = list(raw_options)
    if len(options) < 2 or not 0 <= answer < len(options):
        raise ValueError(f"Invalid answer definition for question: {text}")
    shift = (target_index - answer) % len(options)
    rotated = options[-shift:] + options[:-shift] if shift else options
    return {
        "text": text.strip(),
        "options": rotated,
        "answer": target_index,
        "explanation": explanation.strip(),
    }


def parse_curriculum() -> tuple[list[dict], list[dict]]:
    lessons: list[dict] = []
    questions: list[dict] = []
    step = 1

    for level in LEVELS:
        course_dirs = sorted(path for path in (ROOT / "curriculum" / level).iterdir() if path.is_dir())
        for level_step, course_dir in enumerate(course_dirs, start=1):
            readme = course_dir / "README.md"
            if not readme.exists():
                continue
            content = readme.read_text(encoding="utf-8")
            module = course_dir.name
            course_id = f"{level}/{module}"
            relative = course_dir.relative_to(ROOT).as_posix()

            title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
            raw_title = title_match.group(1).strip() if title_match else module.replace("-", " ").title()
            title = re.sub(r"^(?:Beginner|Intermediate|Advanced)\s+\d+\s*[—:-]\s*", "", raw_title).strip()
            goal = _goal(content, title)
            outcomes = _outcomes(content, goal)
            references = _references(content)

            lab_path = course_dir / "lab.py"
            notebooks = sorted(course_dir.rglob("*.ipynb"))
            raw_questions = get_questions_for_module(module)
            if not raw_questions:
                raise ValueError(f"No quiz questions defined for {course_id}")

            normalized_questions: list[dict] = []
            for local_index, raw_question in enumerate(raw_questions, start=1):
                normalized = _rotate_question(raw_question, len(questions) % len(raw_question[1]))
                normalized.update(
                    {
                        "id": f"{course_id}/q-{local_index}",
                        "courseId": course_id,
                        "courseTitle": title,
                        "courseStep": step,
                        "level": level,
                    }
                )
                questions.append(normalized)
                normalized_questions.append(normalized)

            lesson = {
                "id": course_id,
                "module": module,
                "level": level,
                "step": step,
                "levelStep": level_step,
                "title": title,
                "summary": goal,
                "detail": goal,
                "outcomes": outcomes,
                "material": f"{REPO}{relative}/README.md",
                "references": references,
                "checkpoint": {
                    key: normalized_questions[0][key]
                    for key in ("id", "text", "options", "answer", "explanation")
                },
            }
            if lab_path.exists():
                lesson["lab"] = f"{REPO}{lab_path.relative_to(ROOT).as_posix()}"
                lesson["run"] = f"python3 {lab_path.relative_to(ROOT).as_posix()}"
            if notebooks:
                lesson["notebook"] = f"{REPO}{notebooks[0].relative_to(ROOT).as_posix()}"
            lessons.append(lesson)
            step += 1

    return lessons, questions


def _write_javascript(path: Path, declaration: str, value: object, prelude: str = "") -> None:
    payload = json.dumps(value, ensure_ascii=False, indent=2)
    path.write_text(f"{prelude}const {declaration} = {payload};\n", encoding="utf-8")


def write_lessons(lessons: list[dict]) -> None:
    _write_javascript(
        ROOT / "hub" / "lessons.js",
        "LESSONS",
        lessons,
        "const REPO = 'https://github.com/mahsa-teimourikia/agent-identity';\n",
    )


def write_questions(questions: list[dict]) -> None:
    _write_javascript(ROOT / "quiz" / "questions.js", "QUESTIONS", questions)


if __name__ == "__main__":
    lesson_data, question_data = parse_curriculum()
    write_lessons(lesson_data)
    write_questions(question_data)
    print(f"Generated {len(lesson_data)} lessons and {len(question_data)} questions.")
