"""
Content Standards Tests

This module tests the content-standards catalog in ``powerpack_mcp.tools.content_standards`` and
its single tool, ``get_content_standards``: catalog completeness, provenance, filtering, and the
absence of any backend call.
"""

from __future__ import annotations

import ast
import collections
import pathlib
from typing import Any

import pytest

from powerpack_mcp.tools.content_standards import CATALOG_SOURCE, KNOWN_ENTITIES, RULES
from powerpack_mcp.tools.standards_tools import STANDARDS_TOOLS, get_content_standards

# The counts established by tabulating the source project's `RULES` tuple.
EXPECTED_TOTAL = 93
EXPECTED_BY_ENTITY = {
    "alert": 14,
    "collection_object": 1,
    "device_category": 4,
    "dynamic_application": 23,
    "event_policy": 8,
    "powerpack": 32,
    "presentation_object": 11,
}


class TestCatalogIsComplete:
    """The catalog must be a complete port of the source rules.

    A partial catalog answers incompletely while appearing authoritative, which is worse than not
    shipping the tool. So the totals are pinned, and a dropped or duplicated rule fails a gate
    rather than being noticed by a user one day.
    """

    def test_there_are_exactly_ninety_three_rules(self) -> None:
        assert len(RULES) == EXPECTED_TOTAL

    def test_the_per_entity_counts_are_exact(self) -> None:
        assert dict(collections.Counter(r.entity for r in RULES)) == EXPECTED_BY_ENTITY

    def test_there_are_seven_entity_types_not_six(self) -> None:
        """The source file's own `Rule` comment lists six, omitting ``device_category``.

        Seven is what the rules tuple beneath that comment contains.
        """
        assert len(KNOWN_ENTITIES) == 7
        assert "device_category" in KNOWN_ENTITIES
        assert set(KNOWN_ENTITIES) == set(EXPECTED_BY_ENTITY)

    def test_device_category_rules_actually_survived_the_port(self) -> None:
        """The four rules a closed six-value enum would have dropped."""
        assert len([r for r in RULES if r.entity == "device_category"]) == 4

    def test_every_known_entity_is_present_in_the_rules(self) -> None:
        """No entity is declared without rules, and none has rules without being declared."""
        assert {r.entity for r in RULES} == set(KNOWN_ENTITIES)

    def test_rule_names_are_unique(self) -> None:
        """Names are stable identifiers, so a duplicate would make drift diffing ambiguous."""
        names = [r.name for r in RULES]
        assert len(set(names)) == len(names)

    def test_every_rule_carries_non_empty_text(self) -> None:
        assert all(r.text.strip() for r in RULES)

    def test_the_enforced_and_linted_tallies_match_the_source(self) -> None:
        """Pinned because these two booleans are the ones a caller acts on, so a transcription
        slip in either would change advice rather than merely counts."""
        assert sum(1 for r in RULES if r.enforced) == 36
        assert sum(1 for r in RULES if r.linted_in_loop) == 25


class TestProvenance:
    def test_every_response_carries_provenance(self) -> None:
        """With no drift-check tool, this is the only drift signal, so a caller who cannot see it
        cannot judge how much to trust the answer."""
        for response in (
            _run(get_content_standards()),
            _run(get_content_standards("alert")),
            _run(get_content_standards("nonsense")),
        ):
            assert response["source"] == CATALOG_SOURCE
            assert CATALOG_SOURCE["synced"]

    def test_the_note_does_not_advertise_a_tool_this_server_lacks(self) -> None:
        """The source's note ends "run refresh_content_standards to detect drift".

        This server does not ship that tool, so porting the note verbatim would point every caller
        at something that does not exist. Only the 93 rules are ported verbatim.
        """
        note = CATALOG_SOURCE["note"]
        assert "refresh_content_standards" in note, "the parked tool should still be named..."
        assert "not included in this build" in note, "...but as excluded, not as an instruction"
        assert "no drift-check" in note.lower()

    def test_the_authoritative_gate_is_still_stated(self) -> None:
        """The useful half of the source's note, kept rather than discarded with the misleading
        half."""
        assert "Pleco is the authoritative gate" in CATALOG_SOURCE["note"]


class TestGetContentStandards:
    def test_the_whole_catalog_is_returned_by_default(self) -> None:
        response = _run(get_content_standards())
        assert response["counts"]["total"] == EXPECTED_TOTAL
        assert response["counts"]["returned"] == EXPECTED_TOTAL
        assert set(response["rules"]) == set(KNOWN_ENTITIES)

    @pytest.mark.parametrize(("entity", "expected"), sorted(EXPECTED_BY_ENTITY.items()))
    def test_each_entity_filter_returns_that_entitys_rules(
        self, entity: str, expected: int
    ) -> None:
        response = _run(get_content_standards(entity))
        assert list(response["rules"]) == [entity]
        assert len(response["rules"][entity]) == expected

    @pytest.mark.parametrize("raw", ["ALERT", " alert ", "Alert", "  ALERT  "])
    def test_the_filter_is_normalised(self, raw: str) -> None:
        assert len(_run(get_content_standards(raw))["rules"]["alert"]) == 14

    def test_an_unknown_entity_returns_an_empty_list_not_an_error(self) -> None:
        """The shape matters as much as the absence of an exception.

        Chosen over raising: an unrecognised entity is most likely a typo or a newer entity type,
        and an agent parsing a fixed shape should not have to handle a second error shape for a
        filter miss.
        """
        response = _run(get_content_standards("dynamic_applications"))  # note the plural typo
        assert response["rules"] == {"dynamic_applications": []}
        assert response["counts"]["returned"] == 0
        assert response["counts"]["total"] == EXPECTED_TOTAL

    def test_an_unknown_entity_does_not_return_the_whole_catalog(self) -> None:
        """Silently falling back to everything would be worse than an
        error, because the caller would believe they had filtered."""
        assert _run(get_content_standards("nope"))["counts"]["returned"] == 0

    def test_every_rule_reports_its_linted_in_loop_flag(self) -> None:
        """Each rule carries exactly these four keys, with both flags as booleans."""
        for entity_rules in _run(get_content_standards())["rules"].values():
            for rule in entity_rules:
                assert set(rule) == {"rule", "enforced_by_pleco", "linted_in_loop", "text"}
                assert isinstance(rule["linted_in_loop"], bool)
                assert isinstance(rule["enforced_by_pleco"], bool)


class TestNoBackend:
    """The standards tool makes no backend call, asserted structurally.

    Asserting that no client is constructed would test the wrong thing: the source project's
    second tool constructed no client and still made an outbound call, via the ``gh`` binary. So
    these tests assert the absence of the mechanisms, not the absence of a client.
    """

    def test_the_standards_set_ships_exactly_one_tool(self) -> None:
        """The source's drift-check tool is not ported."""
        assert len(STANDARDS_TOOLS) == 1
        assert STANDARDS_TOOLS[0][0] == "get_content_standards"

    @pytest.mark.parametrize("module", ["content_standards", "standards_tools"])
    def test_no_subprocess_or_network_import_anywhere_in_the_module(self, module: str) -> None:
        """Reintroducing an external-binary or network call fails this test."""
        path = (
            pathlib.Path(__file__).resolve().parents[2]
            / "src"
            / "powerpack_mcp"
            / "tools"
            / f"{module}.py"
        )
        tree = ast.parse(path.read_text())
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert not imported & {
            "subprocess",
            "os",
            "socket",
            "httpx",
            "urllib",
            "requests",
            "shutil",
        }

    def test_the_catalog_is_a_constant_not_a_call(self) -> None:
        """No file read at call time, no cache, no persistence. Two calls return equal
        payloads because the data never moves."""
        assert _run(get_content_standards()) == _run(get_content_standards())
        assert isinstance(RULES, tuple)


def _run(coro: object) -> dict[str, Any]:
    """Drive one coroutine to completion.

    A local helper rather than the `anyio` marker: these tools perform no I/O at all, so there is
    nothing for an event loop to interleave and no reason to pay for one.
    """
    import asyncio

    assert hasattr(coro, "__await__")
    return asyncio.run(coro)  # type: ignore[arg-type]
