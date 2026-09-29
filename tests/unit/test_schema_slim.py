"""
Schema Trimming Tests

This module tests ``powerpack_mcp.schema_slim``: removing advisory ``title`` keys, collapsing
nullable unions, and failing closed when fastmcp's internals cannot be reached.

The property test in ``tests/property/test_properties.py`` checks the general
semantics-preservation rule against a real JSON Schema validator. These examples pin the specific
traps, so a change to the generator cannot silently remove the only coverage of them.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from powerpack_mcp.errors import SchemaTrimError
from powerpack_mcp.schema_slim import (
    NAMED_SUBSCHEMA_KEYS,
    payload_bytes,
    trim,
    trim_registered_tools,
)


class _FakeTool:
    def __init__(self, name: str, parameters: Any) -> None:
        self.name = name
        self.parameters = parameters


class _FakeProvider:
    """Mirror fastmcp 3.4.7's shape: one ``_components`` dict holding every component type.

    Measured against 3.4.7: the key is ``f"{KEY_PREFIX}:{name}@{version or ''}"``, so the ``@`` is
    always present and the version segment is empty when a component is unversioned, which is every
    component this project registers. A fake with a convenient shape of its own would hide the kind
    of fastmcp internals drift this module guards against.
    """

    def __init__(self, tools: list[_FakeTool], others: dict[str, Any] | None = None) -> None:
        self._components: dict[str, Any] = {f"tool:{t.name}@": t for t in tools}
        self._components.update(others or {})


class _FakeServer:
    def __init__(self, tools: list[_FakeTool], others: dict[str, Any] | None = None) -> None:
        self._local_provider = _FakeProvider(tools, others)


class TestPurity:
    def test_the_input_is_not_modified(self) -> None:
        """Without this, the semantics-preservation property could only be checked against a copy
        the test itself makes, testing the copy rather than the function.
        """
        schema = {"title": "Widget", "properties": {"a": {"title": "A", "type": "string"}}}
        before = copy.deepcopy(schema)
        trim(schema)
        assert schema == before

    def test_the_result_is_a_new_object(self) -> None:
        schema: dict[str, Any] = {"type": "object"}
        assert trim(schema) is not schema


class TestMetadataTitleIsRemoved:
    def test_a_titles_at_every_level_are_dropped(self) -> None:
        """``title`` is advisory in JSON Schema, never semantic."""
        trimmed = trim(
            {
                "title": "OuterModel",
                "type": "object",
                "properties": {"host": {"title": "Host", "type": "string"}},
                "$defs": {"Inner": {"title": "Inner", "type": "object"}},
            }
        )
        assert "title" not in trimmed
        assert "title" not in trimmed["properties"]["host"]
        assert "title" not in trimmed["$defs"]["Inner"]

    def test_titles_inside_arrays_are_dropped(self) -> None:
        trimmed = trim({"anyOf": [{"title": "X", "type": "string", "minLength": 1}]})
        assert "title" not in trimmed["anyOf"][0]


class TestParameterNamedTitleSurvives:
    """A parameter named ``title`` must survive the ``title`` metadata removal.

    A naive "remove every key called ``title``" passes every test above and destroys a parameter
    named ``title``. The thing being searched for also occurs legitimately.
    """

    def test_a_property_called_title_is_preserved(self) -> None:
        trimmed = trim(
            {
                "title": "EventPolicy",
                "type": "object",
                "properties": {
                    "title": {"title": "Title", "type": "string"},
                    "severity": {"title": "Severity", "type": "integer"},
                },
                "required": ["title"],
            }
        )
        assert "title" in trimmed["properties"], "the parameter named title was removed"
        assert trimmed["properties"]["title"] == {"type": "string"}
        assert trimmed["required"] == ["title"]
        assert "title" not in trimmed

    @pytest.mark.parametrize("container", sorted(NAMED_SUBSCHEMA_KEYS))
    def test_every_named_subschema_position_protects_the_name(self, container: str) -> None:
        """All four positions, not just ``properties`` -- otherwise the rule holds by accident."""
        trimmed = trim({container: {"title": {"title": "meta", "type": "string"}}})
        assert "title" in trimmed[container]
        assert trimmed[container]["title"] == {"type": "string"}

    def test_a_definition_named_title_is_preserved(self) -> None:
        trimmed = trim({"$defs": {"title": {"type": "object"}}, "title": "Root"})
        assert set(trimmed) == {"$defs"}
        assert "title" in trimmed["$defs"]


class TestNullableUnionCollapse:
    def test_a_bare_nullable_union_collapses(self) -> None:
        """The compact form accepts exactly the same values."""
        trimmed = trim({"anyOf": [{"type": "string"}, {"type": "null"}], "default": None})
        assert trimmed == {"type": ["string", "null"], "default": None}

    def test_a_structured_union_is_left_alone(self) -> None:
        """A branch carrying more than ``type`` is not equivalent to a compact type list."""
        schema = {
            "anyOf": [
                {"type": "object", "additionalProperties": True},
                {"type": "null"},
            ]
        }
        assert trim(schema)["anyOf"] == schema["anyOf"]

    def test_an_any_branch_is_left_alone(self) -> None:
        schema: dict[str, Any] = {"anyOf": [{}, {"type": "null"}]}
        assert trim(schema) == schema

    def test_a_single_branch_is_left_alone(self) -> None:
        schema: dict[str, Any] = {"anyOf": [{"type": "string"}]}
        assert trim(schema) == schema

    def test_a_sibling_type_blocks_the_collapse(self) -> None:
        """A schema with both ``type`` and ``anyOf`` must not collapse.

        The schema is legal and means both constraints apply. Collapsing it would assign
        ``node["type"]`` and overwrite the sibling, silently changing the accepted input set.
        """
        schema: dict[str, Any] = {
            "type": "string",
            "anyOf": [{"type": "string"}, {"type": "null"}],
        }
        trimmed = trim(schema)
        assert trimmed["type"] == "string"
        assert trimmed["anyOf"] == [{"type": "string"}, {"type": "null"}]


class TestFailClosed:
    """Trimming fails closed: anything it cannot trim raises rather than being skipped."""

    @pytest.mark.parametrize("value", ["a string", 42, None, ["a", "list"]])
    def test_a_non_mapping_schema_raises(self, value: Any) -> None:
        with pytest.raises(SchemaTrimError):
            trim(value)

    def test_unreachable_fastmcp_internals_raise_rather_than_returning_zero(self) -> None:
        """Returning 0 here would let a fastmcp upgrade stop trimming the payload with no signal."""

        class _Opaque:
            pass

        with pytest.raises(SchemaTrimError):
            trim_registered_tools(_Opaque())

    def test_the_source_projects_accessor_would_have_silently_done_nothing(self) -> None:
        """A server exposing only the old ``_tool_manager.list_tools`` accessor must raise.

        ``_tool_manager`` is a fastmcp 2.x attribute that 3.x deleted, so this is what a stale
        accessor would find on a downgraded or mispinned environment. Returning 0 here would stop
        trimming the payload with a green suite.
        """

        class _OldShape:
            class _Manager:
                def list_tools(self) -> list[_FakeTool]:
                    return []

            _tool_manager = _Manager()

        with pytest.raises(SchemaTrimError):
            trim_registered_tools(_OldShape())

    def test_components_present_but_no_tool_prefixed_key_raises(self) -> None:
        """A renamed ``"tool:"`` prefix must raise rather than trim nothing.

        fastmcp 3.x holds tools, prompts, resources and templates in one ``_components`` dict, so
        tools are selected by their key prefix. A renamed prefix would otherwise look like "no tools
        registered": the filter yields nothing and trimming reports success having done nothing.
        """
        server = _FakeServer([], others={"prompt:greet@": object(), "resource:cfg@": object()})
        with pytest.raises(SchemaTrimError):
            trim_registered_tools(server)

    def test_a_tool_without_mapping_parameters_raises(self) -> None:
        server = _FakeServer([_FakeTool("broken", None)])
        with pytest.raises(SchemaTrimError):
            trim_registered_tools(server)


class TestRegisteredToolTrimming:
    def test_every_registered_tool_is_trimmed_and_counted(self) -> None:
        tools = [
            _FakeTool("one", {"title": "One", "properties": {"a": {"title": "A"}}}),
            _FakeTool("two", {"title": "Two", "properties": {}}),
        ]
        assert trim_registered_tools(_FakeServer(tools)) == 2
        assert all("title" not in t.parameters for t in tools)
        assert "title" not in tools[0].parameters["properties"]["a"]

    def test_non_tool_components_are_ignored(self) -> None:
        """One ``_components`` dict holds every component type.

        A prompt has no ``parameters``, so handing one to the trimmer would raise, and only
        registered tools are trimmed. Selecting by the ``"tool:"`` prefix keeps the two apart; this
        is the half of that behaviour the fail-closed guard cannot cover.
        """
        tools = [_FakeTool("one", {"title": "One", "properties": {}})]
        server = _FakeServer(tools, others={"prompt:greet@": object(), "template:cfg@": object()})
        assert trim_registered_tools(server) == 1

    def test_trimming_reduces_the_measured_payload(self) -> None:
        """The saving is measured, not assumed."""
        tools = [
            _FakeTool(
                f"tool_{i}",
                {
                    "title": f"Tool{i}Arguments",
                    "type": "object",
                    "properties": {
                        "target_host": {
                            "anyOf": [{"type": "string"}, {"type": "null"}],
                            "title": "Target Host",
                            "default": None,
                        },
                    },
                },
            )
            for i in range(8)
        ]
        server = _FakeServer(tools)
        before = payload_bytes(server)
        trim_registered_tools(server)
        after = payload_bytes(server)
        assert after < before


class TestBoundedTraversal:
    def test_deeply_nested_schemas_are_handled(self) -> None:
        """Each node is visited a bounded number of times, in one pass with no fixed point."""
        node: dict[str, Any] = {"type": "string", "title": "leaf"}
        for _ in range(50):
            node = {"title": "wrapper", "properties": {"child": node}}
        trimmed = trim(node)
        depth = 0
        cursor = trimmed
        while "properties" in cursor:
            assert "title" not in cursor
            cursor = cursor["properties"]["child"]
            depth += 1
        assert depth == 50
        assert cursor == {"type": "string"}

    def test_trimming_is_idempotent(self) -> None:
        """Checked as an example beside the property test."""
        schema = {
            "title": "T",
            "properties": {"a": {"anyOf": [{"type": "string"}, {"type": "null"}]}},
        }
        once = trim(schema)
        assert trim(once) == once
