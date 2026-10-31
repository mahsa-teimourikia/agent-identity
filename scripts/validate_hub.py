"""Fail CI when the Learning Hub drifts from the curriculum or quiz contract."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from generate_hub_data import ROOT, parse_curriculum


def validate() -> list[str]:
    lessons, questions = parse_curriculum()
    errors: list[str] = []
    course_dirs = sorted(
        path.relative_to(ROOT / "curriculum").as_posix()
        for path in (ROOT / "curriculum").glob("*/*")
        if path.is_dir() and (path / "README.md").exists()
    )
    lesson_ids = [lesson["id"] for lesson in lessons]

    if sorted(lesson_ids) != course_dirs:
        errors.append("Lesson registry does not exactly match curriculum course directories.")
    if len(lesson_ids) != len(set(lesson_ids)):
        errors.append("Lesson IDs must be unique.")
    if [lesson["step"] for lesson in lessons] != list(range(1, len(lessons) + 1)):
        errors.append("Lesson steps must be contiguous and start at one.")

    for lesson in lessons:
        if len(lesson["outcomes"]) < 3:
            errors.append(f"{lesson['id']} needs at least three Hub learning outcomes.")
        if len(lesson["references"]) < 3:
            errors.append(f"{lesson['id']} needs at least three selected sources.")
        for key in ("material", "lab", "notebook"):
            value = lesson.get(key)
            if not value:
                continue
            prefix = "https://github.com/mahsa-teimourikia/agent-identity/blob/main/"
            relative = value.removeprefix(prefix)
            if relative == value or not (ROOT / relative).exists():
                errors.append(f"{lesson['id']} has a missing or invalid {key} link: {value}")

    question_ids = [question["id"] for question in questions]
    if len(question_ids) != len(set(question_ids)):
        errors.append("Question IDs must be unique.")
    counts = Counter(question["courseId"] for question in questions)
    for lesson_id in lesson_ids:
        if counts[lesson_id] < 3:
            errors.append(f"{lesson_id} needs at least three quiz questions.")
    for question in questions:
        if question["courseId"] not in lesson_ids:
            errors.append(f"{question['id']} references an unknown course.")
        if len(question["options"]) != 3:
            errors.append(f"{question['id']} must have exactly three options.")
        if not 0 <= question["answer"] < len(question["options"]):
            errors.append(f"{question['id']} has an invalid answer index.")
        if not question["explanation"].strip():
            errors.append(f"{question['id']} needs an explanation.")

    positions = Counter(question["answer"] for question in questions)
    if max(positions.values()) - min(positions.values()) > 1:
        errors.append(f"Correct-answer positions are biased: {dict(positions)}")

    expected_lessons = (
        "const REPO = 'https://github.com/mahsa-teimourikia/agent-identity';\n"
        f"const LESSONS = {json.dumps(lessons, ensure_ascii=False, indent=2)};\n"
    )
    expected_questions = f"const QUESTIONS = {json.dumps(questions, ensure_ascii=False, indent=2)};\n"
    if (ROOT / "hub" / "lessons.js").read_text(encoding="utf-8") != expected_lessons:
        errors.append("hub/lessons.js is stale; run python3 scripts/generate_hub_data.py")
    if (ROOT / "quiz" / "questions.js").read_text(encoding="utf-8") != expected_questions:
        errors.append("quiz/questions.js is stale; run python3 scripts/generate_hub_data.py")
    return errors


if __name__ == "__main__":
    failures = validate()
    if failures:
        print("Learning Hub validation failed:")
        for failure in failures:
            print(f"- {failure}")
        sys.exit(1)
    lesson_data, question_data = parse_curriculum()
    print(f"Learning Hub valid: {len(lesson_data)} courses, {len(question_data)} questions.")
