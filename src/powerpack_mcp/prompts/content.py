"""
Prompt Content

This module provides the content behind the MCP prompts: the Snippet Framework ruleset, and the
LCE API guide sliced by topic. The ruleset is the union of two earlier copies that had drifted
apart, so neither alone was complete.

Both documents ship as packaged data under ``data/`` and are read on demand, because
``api_guide.md`` is thousands of lines of prose, tables and JSON that cannot be baked into a
constant without hard-wrapping it to the line-length limit. The read is bounded:

- No user input reaches a path. ``_DATA_DIR`` comes from ``__file__``, and ``topic`` selects
  headings from a fixed table.
- Each file is read once, through ``lru_cache``.
- Files are read at call time, not at import, so a packaging regression breaks one prompt rather
  than server start-up. ``tests/unit/test_prompts.py`` catches it by asserting both files are
  present and parse.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Final

__all__ = [
    "GUIDE_TOPICS",
    "GuideTopic",
    "MarkdownSection",
    "api_guide_topics",
    "build_guide_topic",
    "framework_rules",
]

# Packaged alongside the source tree, and shipped by ``[tool.setuptools.package-data]``.
_DATA_DIR: Final[Path] = Path(__file__).resolve().parent.parent / "data"

_RULES_FILE: Final[str] = "framework_rules.md"
_GUIDE_FILE: Final[str] = "api_guide.md"


@dataclass(frozen=True)
class MarkdownSection:
    """One heading and everything under it, up to the next heading of the same or higher level."""

    level: int
    title: str
    content: str


@dataclass(frozen=True)
class GuideTopic:
    """A named slice of the API guide: what it covers, and the headings it assembles."""

    description: str
    headings: tuple[str, ...]


# The topic table. Entries are heading prefixes, not exact titles: ``_find_section_by_prefix``
# matches on a normalised prefix so a heading that gains trailing wording still resolves.
GUIDE_TOPICS: Final[dict[str, GuideTopic]] = {
    "payload_core": GuideTopic(
        "Most-important POST payload rules, object schemas, validation, and special behaviors.",
        (
            "1) Overview",
            "3) Identifiers & request-scoped linking",
            "4) Enum values: what you can send",
            "5) Request structure (authoritative)",
            "6) Formula conventions & reference rewrites",
            "7) Application type constraints",
            "8) Collection Object field legality (exact behavior)",
            "9) Entity schemas",
            "10) Cross-object validations",
            "12) Special behaviors",
            "13) Validation & error responses",
        ),
    ),
    "post_dynamic_applications": GuideTopic(
        "Focused guidance for POST /lce/api/dynamic_applications.",
        (
            "Endpoints covered",
            "1) Overview",
            "3) Identifiers & request-scoped linking",
            "5) Request structure (authoritative)",
            "6) Formula conventions & reference rewrites",
            "7) Application type constraints",
            "8) Collection Object field legality (exact behavior)",
            "9) Entity schemas",
            "10) Cross-object validations",
            "11) Examples",
            "12) Special behaviors",
            "13) Validation & error responses",
        ),
    ),
    "get_dynamic_application": GuideTopic(
        "Focused guidance for GET /lce/api/dynamic_applications/{app_identifier}.",
        (
            "Endpoints covered",
            "Query parameters",
            "2) Authentication & Authorization",
            "11.5 Standard GET Response",
            "14) OpenAPI 3.0 Specification",
        ),
    ),
    "get_powerpack": GuideTopic(
        "Focused guidance for GET /lce/api/powerpacks/{powerpack_identifier}.",
        (
            "Endpoints covered",
            "Query parameters",
            "2) Authentication & Authorization",
            "14) OpenAPI 3.0 Specification",
        ),
    ),
    "dynamic_app_entity": GuideTopic(
        "Schema and related rules for the Dynamic Application object.",
        (
            "7) Application type constraints",
            "9.1 Dynamic Application (`dynamic_app`)",
            "10) Cross-object validations",
            "12) Special behaviors",
        ),
    ),
    "snippet_entity": GuideTopic(
        "Schema and related rules for snippet objects.",
        ("9.2 Snippet (`snippets[]`)", "10) Cross-object validations", "12) Special behaviors"),
    ),
    "collection_object_entity": GuideTopic(
        "Schema and field legality rules for collection objects.",
        (
            "6) Formula conventions & reference rewrites",
            "8) Collection Object field legality (exact behavior)",
            "9.3 Collection Object (`collection_objects[]`)",
            "10) Cross-object validations",
            "12) Special behaviors",
        ),
    ),
    "presentation_object_entity": GuideTopic(
        "Schema and related rules for presentation objects.",
        (
            "7) Application type constraints",
            "9.4 Presentation Object (`presentation_objects[]`)",
            "10) Cross-object validations",
            "12) Special behaviors",
        ),
    ),
    "threshold_object_entity": GuideTopic(
        "Schema and related rules for threshold objects.",
        ("9.5 Threshold Object (`threshold_objects[]`)", "10) Cross-object validations"),
    ),
    "alert_object_entity": GuideTopic(
        "Schema and related rules for alert objects.",
        ("9.6 Alert Object (`alert_objects[]`)", "10) Cross-object validations"),
    ),
    "examples": GuideTopic(
        "Worked examples for common create/update workflows.", ("11) Examples",)
    ),
    "openapi": GuideTopic("OpenAPI 3.0 specification section.", ("14) OpenAPI 3.0 Specification",)),
    "jsonschema": GuideTopic(
        "JSON schema specification section.", ("15) JSONSchema Specification",)
    ),
    "additional_behaviors": GuideTopic(
        "Behavioral notes not captured in schemas.",
        ("16) Additional Behaviors Not Found in Schemas",),
    ),
}


def _normalize(value: str) -> str:
    """Lowercase and collapse to single spaces, for loose heading matching."""
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


@lru_cache(maxsize=1)
def framework_rules() -> str:
    """Return the Snippet Framework ruleset as markdown, read once."""
    return (_DATA_DIR / _RULES_FILE).read_text(encoding="utf-8").strip()


@lru_cache(maxsize=1)
def _guide_text() -> str:
    return (_DATA_DIR / _GUIDE_FILE).read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def _guide_sections() -> tuple[MarkdownSection, ...]:
    """Split the guide into one section per ATX heading, each carrying its own subtree.

    A section ends at the next heading of the same or higher level, so ``9) Entity schemas``
    includes its ``9.1`` to ``9.6`` children rather than being an empty stub.
    """
    lines = _guide_text().splitlines(keepends=True)
    heading_re = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
    headings: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines):
        match = heading_re.match(line)
        if match is not None:
            headings.append((index, len(match.group(1)), match.group(2).strip()))
    sections: list[MarkdownSection] = []
    for position, (start, level, title) in enumerate(headings):
        end = len(lines)
        for next_start, next_level, _ in headings[position + 1 :]:
            if next_level <= level:
                end = next_start
                break
        sections.append(MarkdownSection(level, title, "".join(lines[start:end]).strip()))
    return tuple(sections)


def _find_section_by_prefix(prefix: str) -> MarkdownSection:
    wanted = _normalize(prefix)
    for section in _guide_sections():
        if _normalize(section.title).startswith(wanted):
            return section
    raise ValueError(f"No API guide section found for heading prefix: {prefix!r}")


def api_guide_topics() -> tuple[str, ...]:
    """Return every selectable topic key, including the pseudo-topic ``full``."""
    return ("full", *sorted(GUIDE_TOPICS))


def build_guide_topic(topic: str) -> tuple[str, str]:
    """Assemble the guide sections for one topic key, or ``"full"``.

    :param topic: A key from ``GUIDE_TOPICS``, or ``"full"`` for the whole guide.
    :return: ``(description, assembled_markdown)``.
    :raises ValueError: If the topic is unknown. The message names every available topic, because
        a prompt argument is caller-supplied text and the caller needs to know what would work.
    """
    key = _normalize(topic).replace(" ", "_")
    if key == "full":
        return ("Entire API guide.", _guide_text())
    if key not in GUIDE_TOPICS:
        raise ValueError(f"Unknown topic {topic!r}. Available: {', '.join(api_guide_topics())}")
    spec = GUIDE_TOPICS[key]
    parts: list[str] = []
    seen: set[str] = set()
    for heading in spec.headings:
        section = _find_section_by_prefix(heading)
        normalized = _normalize(section.title)
        if normalized in seen:
            continue
        seen.add(normalized)
        parts.append(section.content)
    return (spec.description, "\n\n---\n\n".join(parts))
