"""
Query Parameter Tests

This module tests ``powerpack_mcp.query``: boolean serialisation, selector and write options,
filter serialisation and rejection, model constraints and the filter round trip.

The rejection tests assert that the rejection happens, the number of findings, the index in the
path and the absence of the offending value. They do not assert each finding's ``rule`` value.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from powerpack_mcp.errors import ValidationBlocked
from powerpack_mcp.query import (
    MAX_FILTER_CONDITIONS,
    NON_NEGATABLE,
    SINGLE_VALUE_ONLY,
    FilterCondition,
    FilterOperator,
    FilterParams,
    SelectorParams,
    WriteOptions,
    build_filter_params,
    build_selector_params,
    build_write_options,
    parse_filter_params,
    serialize_bool,
)


def _condition(**kwargs: object) -> FilterCondition:
    defaults: dict[str, object] = {
        "field": "name",
        "operator": FilterOperator.IS,
        "value": "x",
    }
    return FilterCondition.model_validate(defaults | kwargs)


class TestSerializeBool:
    def test_lowercase_wire_form(self) -> None:
        """Python's ``str(True)`` is ``"True"``, which LCE does not accept."""
        assert serialize_bool(True) == "true"
        assert serialize_bool(False) == "false"

    def test_never_emits_the_python_repr(self) -> None:
        assert serialize_bool(True) != str(True)


class TestOperatorSets:
    def test_five_operators_exactly(self) -> None:
        """Verified exhaustive against the LCE API specification."""
        assert {o.value for o in FilterOperator} == {"is", "contains", "gt", "lt", "search"}

    def test_single_value_only_set(self) -> None:
        """Verified: "gt (single value only) - lt (single value only) - search (single value
        only, not negatable)".
        """
        assert sorted(o.value for o in SINGLE_VALUE_ONLY) == ["gt", "lt", "search"]

    def test_non_negatable_set(self) -> None:
        """Verified: "search (... not negatable)" -- and only search."""
        assert sorted(o.value for o in NON_NEGATABLE) == ["search"]

    def test_an_unsupported_operator_fails_at_the_model(self) -> None:
        """Structural: it fails at the model, before the builder is ever reached."""
        with pytest.raises(ValidationError):
            _condition(operator="regex")


class TestSelectorParams:
    def test_pretty_defaults_true_and_is_serialized(self) -> None:
        assert build_selector_params(SelectorParams()) == {"pretty": "true"}

    def test_none_selectors_are_omitted_entirely(self) -> None:
        """An empty ``fields`` would be a different request from an absent one."""
        params = build_selector_params(SelectorParams(pretty=False))
        assert params == {"pretty": "false"}
        assert "fields" not in params
        assert "exclude" not in params

    def test_both_selectors_pass_through_unparsed(self) -> None:
        """Their interaction is LCE's documented behaviour, not reimplemented."""
        selector = SelectorParams(fields="dynamic_applications.*.id", exclude="results.*.guid")
        params = build_selector_params(selector)
        assert params["fields"] == "dynamic_applications.*.id"
        assert params["exclude"] == "results.*.guid"

    def test_selector_character_set_is_not_restricted(self) -> None:
        """``.``, ``,`` and ``*`` are all legitimate; only the length is limited."""
        selector = SelectorParams(fields="a.*,b.c.*,d")
        assert build_selector_params(selector)["fields"] == "a.*,b.c.*,d"

    def test_over_length_selector_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SelectorParams(fields="x" * 2049)


class TestWriteOptions:
    def test_defaults_match_the_specification(self) -> None:
        """``commit`` defaults to true and ``retrieve`` to false."""
        assert build_write_options(WriteOptions()) == {"commit": "true", "retrieve": "false"}

    def test_dry_run_serializes(self) -> None:
        """``commit=false`` is LCE's own dry run, the "safe to try" mechanism."""
        options = WriteOptions(commit=False, retrieve=True)
        assert build_write_options(options) == {"commit": "false", "retrieve": "true"}


class TestFilterSerialization:
    def test_plain_condition_key_shape(self) -> None:
        """The key shape is ``filter[<field>][<operator>]=<value>``."""
        params = build_filter_params(FilterParams(conditions=[_condition(field="id")]))
        assert params["filter[id][is]"] == "x"

    def test_negated_condition_puts_not_between_field_and_operator(self) -> None:
        """``not`` goes between field and operator, as the LCE API specification states."""
        params = build_filter_params(FilterParams(conditions=[_condition(field="id", negate=True)]))
        assert "filter[id][not][is]" in params

    def test_require_all_maps_to_the_literal_lce_parameter(self) -> None:
        """``require_all`` maps to ``require_all_filters``, default ``true``."""
        assert (
            build_filter_params(FilterParams(conditions=[_condition()]))["require_all_filters"]
            == "true"
        )
        assert (
            build_filter_params(FilterParams(conditions=[_condition()], require_all=False))[
                "require_all_filters"
            ]
            == "false"
        )

    def test_multi_value_is_passed_through_for_the_is_operator(self) -> None:
        """A comma expresses multi-value matching, and `is` supports it."""
        params = build_filter_params(
            FilterParams(conditions=[_condition(field="id", value="1,2,3")])
        )
        assert params["filter[id][is]"] == "1,2,3"

    def test_literal_null_passes_through_unchanged(self) -> None:
        """Passed through so LCE performs a SQL NULL check; not treated as absence or normalised."""
        for literal in ("null", "NULL", "Null"):
            params = build_filter_params(
                FilterParams(conditions=[_condition(field="d", value=literal)])
            )
            assert params["filter[d][is]"] == literal


class TestFilterRejections:
    """Rejected filters. See the module docstring on why the ``rule`` value is not asserted."""

    def test_negated_search_is_rejected(self) -> None:
        """The LCE API specification documents ``search`` as not negatable."""
        params = FilterParams(conditions=[_condition(operator=FilterOperator.SEARCH, negate=True)])
        with pytest.raises(ValidationBlocked) as exc:
            build_filter_params(params)
        assert len(exc.value.findings) == 1

    def test_conditions_colliding_on_one_query_key_are_rejected(self) -> None:
        """Two conditions sharing field, operator and negation are rejected, not silently halved.

        They serialize to one query parameter, and dict assembly would keep only the last, so a
        legitimate ``require_all=true`` AND query would return a plausible wrong answer with no
        error. Passing both through does not help either: LCE 3.1.0 is first-value-wins, not AND
        (``contains=SSH&contains=Zombie`` returned the SSH set, and reversed, the Zombie set), so
        repeated keys cannot express the intent at any layer.
        """
        params = FilterParams(
            conditions=[
                _condition(field="name", value="SSH"),
                _condition(field="name", value="Zombie"),
            ]
        )
        with pytest.raises(ValidationBlocked) as exc:
            build_filter_params(params)
        assert len(exc.value.findings) == 1
        # The message names indices, never the offending values.
        message = exc.value.findings[0].message
        assert "conditions[0]" in message
        assert "SSH" not in message
        assert "Zombie" not in message

    def test_every_colliding_condition_is_reported_not_just_the_first(self) -> None:
        """Findings carry every offending condition."""
        params = FilterParams(
            conditions=[_condition(value="a"), _condition(value="b"), _condition(value="c")]
        )
        with pytest.raises(ValidationBlocked) as exc:
            build_filter_params(params)
        assert len(exc.value.findings) == 2, "both duplicates must be reported"
        assert [f.path for f in exc.value.findings] == ["conditions[1]", "conditions[2]"]

    def test_negation_distinguishes_otherwise_identical_conditions(self) -> None:
        """``negate`` is part of the key, so ``is`` and ``not is`` on one field do not collide.

        The guard must reject genuine collisions without rejecting this legitimate pair.
        """
        params = FilterParams(
            conditions=[
                _condition(field="name", value="x"),
                _condition(field="name", value="y", negate=True),
            ]
        )
        assert len(build_filter_params(params)) == 3  # require_all + two distinct filter keys

    @pytest.mark.parametrize(
        "operator", [FilterOperator.GT, FilterOperator.LT, FilterOperator.SEARCH]
    )
    def test_comma_value_is_rejected_for_single_value_operators(
        self, operator: FilterOperator
    ) -> None:
        """A comma is how the LCE API expresses multi-value matching, so it is the test."""
        params = FilterParams(conditions=[_condition(operator=operator, value="1,2")])
        with pytest.raises(ValidationBlocked):
            build_filter_params(params)

    def test_negation_is_permitted_for_the_other_operators(self) -> None:
        for operator in (FilterOperator.IS, FilterOperator.CONTAINS, FilterOperator.GT):
            params = FilterParams(conditions=[_condition(operator=operator, negate=True)])
            assert build_filter_params(params)

    def test_every_offending_condition_is_reported_not_just_the_first(self) -> None:
        params = FilterParams(
            conditions=[
                _condition(operator=FilterOperator.SEARCH, negate=True),
                _condition(operator=FilterOperator.GT, value="1,2"),
                _condition(),
            ]
        )
        with pytest.raises(ValidationBlocked) as exc:
            build_filter_params(params)
        assert len(exc.value.findings) == 2

    def test_message_names_the_index_and_never_the_offending_value(self) -> None:
        secret = "s3cret,value"
        params = FilterParams(
            conditions=[_condition(), _condition(operator=FilterOperator.GT, value=secret)]
        )
        with pytest.raises(ValidationBlocked) as exc:
            build_filter_params(params)
        (finding,) = exc.value.findings
        assert finding.path == "conditions[1]"
        assert secret not in finding.message


class TestFilterModelConstraints:
    def test_at_least_one_condition_is_required(self) -> None:
        """A model constraint, so an unfiltered list request cannot be constructed at all."""
        with pytest.raises(ValidationError):
            FilterParams(conditions=[])

    def test_condition_count_is_bounded(self) -> None:
        with pytest.raises(ValidationError):
            FilterParams(conditions=[_condition() for _ in range(MAX_FILTER_CONDITIONS + 1)])

    def test_field_and_value_lengths_are_bounded(self) -> None:
        with pytest.raises(ValidationError):
            _condition(field="f" * 129)
        with pytest.raises(ValidationError):
            _condition(value="v" * 1025)

    def test_models_are_frozen(self) -> None:
        condition = _condition()
        with pytest.raises(ValidationError):
            condition.value = "mutated"  # type: ignore[misc]


class TestRoundTrip:
    """``parse_filter_params`` is the declared inverse of ``build_filter_params``."""

    def test_single_condition_round_trips(self) -> None:
        original = FilterParams(conditions=[_condition(field="id", value="7")])
        assert parse_filter_params(build_filter_params(original)) == original

    def test_negation_round_trips(self) -> None:
        original = FilterParams(conditions=[_condition(field="id", negate=True)])
        assert parse_filter_params(build_filter_params(original)) == original

    def test_require_all_false_round_trips(self) -> None:
        original = FilterParams(conditions=[_condition()], require_all=False)
        assert parse_filter_params(build_filter_params(original)) == original

    def test_condition_order_is_preserved_not_merely_the_set(self) -> None:
        original = FilterParams(
            conditions=[
                _condition(field="a", value="1"),
                _condition(field="b", operator=FilterOperator.CONTAINS, value="2"),
                _condition(field="c", operator=FilterOperator.GT, value="3"),
            ]
        )
        assert parse_filter_params(build_filter_params(original)) == original

    def test_every_operator_round_trips(self) -> None:
        for operator in FilterOperator:
            original = FilterParams(conditions=[_condition(field="f", operator=operator)])
            assert parse_filter_params(build_filter_params(original)) == original


def test_no_caller_value_is_concatenated_into_a_key() -> None:
    """Parameters are assembled as a mapping, never spliced into a key.

    So a hostile value cannot forge a second parameter.
    """
    params = build_filter_params(
        FilterParams(conditions=[_condition(field="id", value="1&injected=2")])
    )
    assert params["filter[id][is]"] == "1&injected=2"
    assert "injected" not in " ".join(params.keys())
