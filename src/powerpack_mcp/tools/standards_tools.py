"""
Content Standards Tool

This module provides the ``get_content_standards`` tool, which returns the PowerPack
content-standards catalog. It makes no network call, starts no subprocess and reads no file: it
reads an in-memory constant, and ``tests/unit/test_standards.py`` asserts that structurally.

The tool returns the whole catalog rather than a curated subset, because a partial catalog answers
"what are the rules for X" incompletely while appearing authoritative. There is no refresh tool:
refreshing would need the authenticated ``gh`` CLI and GitHub Enterprise access, which an appliance
does not have. See ``content_standards.CATALOG_SOURCE`` for the provenance a caller uses to judge
staleness.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Final

from powerpack_mcp.tools.content_standards import CATALOG_SOURCE, KNOWN_ENTITIES, RULES

__all__ = ["STANDARDS_TOOLS", "ToolFn", "get_content_standards"]


def _rule_payload(entity: str) -> list[dict[str, object]]:
    """Every rule for one entity, in catalog order. Empty list for an unknown entity."""
    return [
        {
            "rule": rule.name,
            "enforced_by_pleco": rule.enforced,
            # Distinguishes rules this service checks automatically from those only Pleco enforces
            # at build time; the two need different responses.
            "linted_in_loop": rule.linted_in_loop,
            "text": rule.text,
        }
        for rule in RULES
        if rule.entity == entity
    ]


async def get_content_standards(entity: str | None = None) -> dict[str, object]:
    """Return the PowerPack content-standards rules, optionally filtered to one entity type.

    Args:
        entity: Restrict the result to one entity type -- one of ``alert``, ``collection_object``,
            ``device_category``, ``dynamic_application``, ``event_policy``, ``powerpack`` or
            ``presentation_object``. Omit it for the whole catalog. An unrecognised value returns an
            empty rule list for that key rather than an error.

    Returns:
        The catalog, grouped by entity type, with provenance and counts.
    """
    # ``async`` with no ``await``: every tool on this server is a coroutine so the tool surface is
    # uniform.
    #
    # An unknown entity yields an empty list for that key, not an error and not the whole catalog.
    # It is most likely a typo or a newer entity type, and a stable response shape means an agent
    # parsing it does not have to handle a second error shape for a filter miss.
    if entity is not None:
        key = entity.strip().lower()
        rules: dict[str, list[dict[str, object]]] = {key: _rule_payload(key)}
    else:
        rules = {known: _rule_payload(known) for known in KNOWN_ENTITIES}

    return {
        # Provenance travels with every response. With no refresh tool it is the only signal that
        # the catalog may have drifted from upstream.
        "source": CATALOG_SOURCE,
        "counts": {
            "total": len(RULES),
            "enforced_by_pleco": sum(1 for r in RULES if r.enforced),
            "linted_in_loop": sum(1 for r in RULES if r.linted_in_loop),
            "returned": sum(len(v) for v in rules.values()),
        },
        "entities": list(KNOWN_ENTITIES),
        "rules": rules,
    }


# What ``server.tool`` accepts: a coroutine function returning the tool's payload.
ToolFn = Callable[..., Awaitable[dict[str, Any]]]

# The ``standards`` tool set, as ``(name, function)`` pairs. ``mcp_app.register_tools`` iterates
# it and takes the set's tool count from its length, so adding a tool changes only this tuple.
STANDARDS_TOOLS: Final[tuple[tuple[str, ToolFn], ...]] = (
    ("get_content_standards", get_content_standards),
)
