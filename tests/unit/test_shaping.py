"""
Response Shaping Tests

This module tests ``powerpack_mcp.shaping``: which empty members are dropped, which falsy values
are kept, recursive collapse, idempotence, and that the input is never mutated.

The distinction between "empty" and "falsy" is the substance of this component, so ``0``,
``false`` and whitespace-only strings get explicit tests rather than being left to a property.
"""

from __future__ import annotations

import pytest

from powerpack_mcp.shaping import JsonValue, drop_empty, shape_response


class TestDropped:
    """Null, empty string, empty list and empty object are dropped."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ({"a": None}, {}),
            ({"a": ""}, {}),
            ({"a": []}, {}),
            ({"a": {}}, {}),
            ({"a": 1, "b": None}, {"a": 1}),
        ],
    )
    def test_empty_members_are_removed(self, value: JsonValue, expected: JsonValue) -> None:
        assert drop_empty(value) == expected

    def test_empty_members_are_removed_from_lists_too(self) -> None:
        assert drop_empty([1, None, "", [], {}, 2]) == [1, 2]


class TestKept:
    """The cases a truthiness check would wrongly drop."""

    @pytest.mark.parametrize("value", [0, 0.0, False])
    def test_zero_and_false_are_values_not_absence(self, value: JsonValue) -> None:
        """`numeric_range_low: 0` is real threshold data and `state: false` is the opposite of
        absent. Dropping them would re-type the caller's data.
        """
        assert drop_empty({"a": value}) == {"a": value}

    @pytest.mark.parametrize("value", [" ", "   ", "\t", "\n"])
    def test_whitespace_only_strings_are_kept(self, value: str) -> None:
        """Judging `"   "` empty is a judgement about *content*, and fields like
        `identifier_format` may legitimately hold whitespace.
        """
        assert drop_empty({"a": value}) == {"a": value}

    def test_zero_survives_inside_a_list(self) -> None:
        assert drop_empty([0, False, None, ""]) == [0, False]


class TestRecursiveCollapse:
    """Bottom-up until stable, achieved in a single post-order pass."""

    def test_a_container_left_empty_is_itself_dropped(self) -> None:
        assert drop_empty({"a": {"b": None}}) == {}

    def test_collapse_propagates_through_several_levels(self) -> None:
        assert drop_empty({"a": {"b": {"c": {"d": None}}}}) == {}

    def test_collapse_stops_at_the_first_non_empty_ancestor(self) -> None:
        assert drop_empty({"a": {"b": None, "keep": 1}}) == {"a": {"keep": 1}}

    def test_lists_collapse_too(self) -> None:
        assert drop_empty({"a": [{"b": None}, {}]}) == {}

    def test_a_single_pass_suffices(self) -> None:
        """No fixed-point iteration is needed: children are resolved before their
        parent is tested, so one post-order pass reaches the stable result.
        """
        deep: JsonValue = {"l1": {"l2": {"l3": {"l4": {"l5": ""}}}}}
        assert drop_empty(deep) == {}


class TestIdempotence:
    """`f(f(x)) == f(x)`, which the recursive collapse makes true."""

    @pytest.mark.parametrize(
        "value",
        [
            {"a": {"b": None}, "c": 0},
            [1, None, {"d": ""}, {"e": {"f": []}}],
            {"results": [{"guid": None, "id": 1}]},
        ],
    )
    def test_applying_twice_changes_nothing(self, value: JsonValue) -> None:
        once = drop_empty(value)
        assert drop_empty(once) == once


class TestNoMutationAndNoInvention:
    def test_returns_a_new_structure_and_leaves_the_input_alone(self) -> None:
        """Satisfied by construction, not by discipline."""
        source: JsonValue = {"a": {"b": None, "keep": 1}, "c": [None, 2]}
        before = repr(source)
        result = drop_empty(source)
        assert repr(source) == before
        assert result is not source

    def test_never_introduces_a_key(self) -> None:
        """Shaping only removes members; it never adds one."""
        result = drop_empty({"a": 1, "b": None})
        assert isinstance(result, dict)
        assert set(result) <= {"a", "b"}

    def test_never_alters_a_non_empty_leaf(self) -> None:
        """Values pass through untouched, including ones a serializer might normalise."""
        leaves: JsonValue = {"s": "text", "i": 42, "f": 1.5, "t": True, "neg": -1}
        assert drop_empty(leaves) == leaves


class TestShapeResponse:
    def test_preserves_the_top_level_container_type(self) -> None:
        assert isinstance(shape_response({"a": 1}), dict)
        assert isinstance(shape_response([{"a": 1}]), list)

    def test_applies_to_results(self) -> None:
        body = {"results": [{"id": 1, "description": "", "tags": []}]}
        assert shape_response(body) == {"results": [{"id": 1}]}

    def test_applies_to_the_expanded_entities_list(self) -> None:
        """Shaping applies to whatever LCE returned, including the `entities` list
        that `retrieve=true` adds.
        """
        body = {"results": [{"id": 1}], "entities": [{"guid": None, "name": "x"}]}
        assert shape_response(body) == {"results": [{"id": 1}], "entities": [{"name": "x"}]}

    def test_structure_is_otherwise_unchanged(self) -> None:
        """No re-keying, no re-typing, no summarising."""
        body = {"results": [{"nested": {"deep": {"value": 7}}}]}
        assert shape_response(body) == body

    def test_an_all_empty_document_reduces_to_an_empty_container(self) -> None:
        assert shape_response({"a": None, "b": {}}) == {}
        assert shape_response([None, "", {}]) == []
