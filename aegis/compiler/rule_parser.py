"""Parse RULES.md into individual rule objects."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from aegis.constants import RULES_FILENAME


@dataclass
class Rule:
    id: str
    title: str
    body: str
    raw: str

    @staticmethod
    def make_id(title: str, index: int) -> str:
        slug = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")[:40]
        h = hashlib.sha256(title.encode()).hexdigest()[:6]
        return f"rule_{index:03d}_{slug}_{h}"


def parse_rules(text: str) -> list[Rule]:
    """Split RULES.md content into individual rules.

    Supports two formats:
    1. Markdown headings (## Rule title)
    2. Numbered list (1. Rule description)
    """
    rules: list[Rule] = []

    # Try heading-based split first
    heading_pattern = re.compile(r"^#{1,3}\s+(.+)$", re.MULTILINE)
    headings = list(heading_pattern.finditer(text))

    if headings:
        for i, match in enumerate(headings):
            title = match.group(1).strip()
            start = match.end()
            end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
            body = text[start:end].strip()
            raw = text[match.start():end].strip()
            rules.append(Rule(
                id=Rule.make_id(title, i + 1),
                title=title,
                body=body,
                raw=raw,
            ))
        return rules

    # Fallback: numbered list
    numbered_pattern = re.compile(
        r"^\d+[\.\)]\s+(.+?)(?=\n\d+[\.\)]\s|\Z)", re.MULTILINE | re.DOTALL
    )
    for i, match in enumerate(numbered_pattern.finditer(text)):
        line = match.group(1).strip()
        # First sentence or line as title
        title = line.split("\n")[0].rstrip(".")
        rules.append(Rule(
            id=Rule.make_id(title, i + 1),
            title=title,
            body=line,
            raw=match.group(0).strip(),
        ))

    # Last fallback: treat entire text as one rule
    if not rules:
        title = text.split("\n")[0].strip().lstrip("#").strip()
        rules.append(Rule(
            id=Rule.make_id(title, 1),
            title=title,
            body=text.strip(),
            raw=text.strip(),
        ))

    return rules


def find_rules_file(cwd: Path) -> Path | None:
    """Find RULES.md walking up from cwd."""
    search = cwd
    while True:
        candidate = search / RULES_FILENAME
        if candidate.is_file():
            return candidate
        parent = search.parent
        if parent == search:
            return None
        search = parent
