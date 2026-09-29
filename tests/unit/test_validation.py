"""
Payload Validation Tests

This module tests ``powerpack_mcp.validation`` with worked examples: the child-GUID and
threshold-type lints rule by rule, the three payload shapes, and the depth guard. The property
tests in ``tests/property`` cover the same rules generatively.
"""

from __future__ import annotations

import pytest

from powerpack_mcp.errors import FindingCode, LintRule
from powerpack_mcp.validation import (
    CHILD_GUID_PATTERN,
    INSPECTED_CHILD_COLLECTIONS,
    MAX_PAYLOAD_DEPTH,
    PERMITTED_THRESHOLD_TYPES,
    exceeds_depth,
    is_threshold_value_numeric,
    is_valid_child_guid,
    is_valid_threshold_type,
    validate_payload,
)

_BOTH = frozenset({LintRule.CHILD_GUID, LintRule.THRESHOLD_TYPE})
_GUID_ONLY = frozenset({LintRule.CHILD_GUID})
_VALID_GUID = "A1B2C3D4E5F6789012345678901234AB"


def _nest(depth: int) -> dict[str, object]:
    """A dict nested exactly ``depth`` levels deep."""
    root: dict[str, object] = {}
    cursor = root
    for _ in range(depth - 1):
        child: dict[str, object] = {}
        cursor["n"] = child
        cursor = child
    return root


class TestIsValidChildGuid:
    def test_accepts_uppercase_32_hex(self) -> None:
        """`definitions.GUID.pattern` is `^[A-F0-9]{32}$`."""
        assert is_valid_child_guid(_VALID_GUID)

    def test_accepts_none(self) -> None:
        """Every child `guid` is `x-nullable: true` and in no `required` array, so rejecting
        `null` would block the create workflow, which omits GUIDs.
        """
        assert is_valid_child_guid(None)

    def test_rejects_lowercase_hex(self) -> None:
        """Deliberately a finding. The likeliest near-miss, so the actionable
        message has the most value here.
        """
        assert not is_valid_child_guid(_VALID_GUID.lower())

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "A1B2",  # too short
            _VALID_GUID + "A",  # too long
            "G" * 32,  # not hex
            "A1B2C3D4E5F6789012345678901234A-",  # punctuation
        ],
    )
    def test_rejects_malformed_strings(self, value: str) -> None:
        assert not is_valid_child_guid(value)

    @pytest.mark.parametrize("value", [0, 1, 1.5, True, False, [], {}, [_VALID_GUID]])
    def test_rejects_every_wrong_type(self, value: object) -> None:
        """Takes `object`, so a non-string yields `False`, never a `TypeError`.

        `bool` is included because it subclasses `int` in Python but is never a GUID.
        """
        assert not is_valid_child_guid(value)


class TestIsValidThresholdType:
    @pytest.mark.parametrize("value", sorted(PERMITTED_THRESHOLD_TYPES))
    def test_accepts_the_three_permitted_values(self, value: str) -> None:
        """The values of `FlexibleEnumThresholdType.enum`."""
        assert is_valid_threshold_type(value)

    @pytest.mark.parametrize("value", ["percentage", "Percentage", "INTEGER "])
    def test_comparison_is_exact_and_case_sensitive(self, value: str) -> None:
        """Accepting `percentage` would invent a tolerance the API does not
        document.
        """
        assert not is_valid_threshold_type(value)

    @pytest.mark.parametrize("value", [0, 1, True, False, None, [], {}])
    def test_rejects_non_strings_including_zero(self, value: object) -> None:
        """`ThresholdObject.type` declares `default: 0` while its enum holds only
        strings, so the integer `0` is exactly the confusion this lint exists to catch.
        """
        assert not is_valid_threshold_type(value)


class TestExceedsDepth:
    def test_accepts_a_payload_at_the_limit(self) -> None:
        """The boundary, tested at exactly the limit."""
        assert not exceeds_depth(_nest(MAX_PAYLOAD_DEPTH))

    def test_accepts_one_below_the_limit(self) -> None:
        assert not exceeds_depth(_nest(MAX_PAYLOAD_DEPTH - 1))

    def test_rejects_one_above_the_limit(self) -> None:
        assert exceeds_depth(_nest(MAX_PAYLOAD_DEPTH + 1))

    def test_does_not_recursion_error_on_a_pathological_payload(self) -> None:
        """The point of the depth guard.

        A naive recursive checker raises `RecursionError` on exactly the input it exists to reject.
        Frames must be bounded by the limit, not by the input, so a 5,000-deep payload must return
        `True` rather than raising.
        """
        assert exceeds_depth(_nest(5_000)) is True

    def test_bounds_lists_as_well_as_dicts(self) -> None:
        deep_list: object = "leaf"
        for _ in range(MAX_PAYLOAD_DEPTH + 5):
            deep_list = [deep_list]
        assert exceeds_depth(deep_list)

    @pytest.mark.parametrize("scalar", [None, "", 0, False, 1.5])
    def test_scalars_are_never_too_deep(self, scalar: object) -> None:
        assert not exceeds_depth(scalar)


class TestPayloadShapes:
    """Paths address the document as the caller sent it."""

    def test_object_with_recognised_collection_key(self) -> None:
        findings = validate_payload({"dynamic_applications": [{"guid": "bad"}]}, _GUID_ONLY)
        assert [f.path for f in findings] == ["dynamic_applications[0].guid"]

    def test_single_object(self) -> None:
        findings = validate_payload({"guid": "bad"}, _GUID_ONLY)
        assert [f.path for f in findings] == ["guid"]

    def test_top_level_array(self) -> None:
        """A top-level array is accepted, which is why the payload type is `dict | list`."""
        findings = validate_payload([{"guid": "bad"}], _GUID_ONLY)
        assert [f.path for f in findings] == ["[0].guid"]

    def test_event_policies_collection_key(self) -> None:
        findings = validate_payload({"event_policies": [{"guid": "bad"}]}, _GUID_ONLY)
        assert [f.path for f in findings] == ["event_policies[0].guid"]


class TestTraversal:
    def test_finds_every_guid_suffixed_key_at_any_depth(self) -> None:
        """`DynamicApp.event_policies` is `array<EventPolicy>` and
        `EventPolicy` carries `guid`, `app_guid` and `pp_guid`, so a one-level traversal
        would miss all three.
        """
        payload = {
            "dynamic_applications": [
                {"event_policies": [{"guid": "x", "app_guid": "y", "pp_guid": "z"}]}
            ]
        }
        assert [f.path for f in validate_payload(payload, _GUID_ONLY)] == [
            "dynamic_applications[0].event_policies[0].guid",
            "dynamic_applications[0].event_policies[0].app_guid",
            "dynamic_applications[0].event_policies[0].pp_guid",
        ]

    def test_all_six_child_collections_are_traversed(self) -> None:
        """The six named child collections are the minimum inspected set, and recursive
        traversal covers every one.
        """
        payload = {name: [{"guid": "bad"}] for name in sorted(INSPECTED_CHILD_COLLECTIONS)}
        found = {f.path.split("[")[0] for f in validate_payload(payload, _GUID_ONLY)}
        assert found == INSPECTED_CHILD_COLLECTIONS

    def test_root_level_pp_guid_is_inspected(self) -> None:
        """The reason for a key-suffix rule rather than a fixed collection list: a fixed list
        would silently under-inspect the root `pp_guid`.
        """
        findings = validate_payload({"pp_guid": "bad"}, _GUID_ONLY)
        assert [f.path for f in findings] == ["pp_guid"]

    def test_findings_are_returned_in_document_order(self) -> None:
        """Deterministic ordering is what makes the response diffable."""
        payload = {"a_guid": "bad1", "b": {"c_guid": "bad2"}, "d_guid": "bad3"}
        assert [f.path for f in validate_payload(payload, _GUID_ONLY)] == [
            "a_guid",
            "b.c_guid",
            "d_guid",
        ]

    def test_every_finding_is_returned_with_no_cap(self) -> None:
        """There is no cap. The body-size guard bounds the input instead."""
        payload = {"dynamic_applications": [{"guid": "bad"} for _ in range(250)]}
        assert len(validate_payload(payload, _GUID_ONLY)) == 250


class TestThresholdScope:
    def test_applies_only_inside_threshold_objects(self) -> None:
        """`threshold_objects[].type` only. A `type` key on an unrelated object is
        not the subject of this lint.
        """
        payload = {"threshold_objects": [{"type": 0}], "type": "not-a-threshold-type"}
        findings = validate_payload(payload, _BOTH)
        assert [f.path for f in findings] == ["threshold_objects[0].type"]

    def test_absent_type_is_valid(self) -> None:
        """`type` is in no `required` array and the specification gives it a
        default.
        """
        assert validate_payload({"threshold_objects": [{}]}, _BOTH) == ()

    def test_both_lints_run_on_the_same_payload(self) -> None:
        """One round trip surfaces every problem, rather than the caller fixing
        GUIDs and then discovering threshold types.
        """
        payload = {"guid": "bad", "threshold_objects": [{"type": 0}]}
        rules = {f.rule for f in validate_payload(payload, _BOTH)}
        assert rules == {FindingCode.CHILD_GUID, FindingCode.THRESHOLD_TYPE}


class TestIsThresholdValueNumeric:
    """The predicate for whether a threshold value is numeric."""

    @pytest.mark.parametrize("value", [0, 75, -3, 0.5, 75.0, 1e3])
    def test_numbers_are_accepted(self, value: object) -> None:
        assert is_threshold_value_numeric(value)

    @pytest.mark.parametrize("value", ["75", "0.5", "-3", " 75 ", "1e3"])
    def test_numeric_strings_are_accepted(self, value: object) -> None:
        """Deliberate. Refusing "75" would reject a payload LCE accepts, turning a missing lint
        into a false refusal, which is worse because it blocks working callers."""
        assert is_threshold_value_numeric(value)

    @pytest.mark.parametrize(
        "value", ["not-a-number", "", "75%", "abc", "1,000", None, [], {}, [75], {"v": 75}]
    )
    def test_non_numbers_are_rejected(self, value: object) -> None:
        assert not is_threshold_value_numeric(value)

    @pytest.mark.parametrize("value", [True, False])
    def test_bools_are_rejected_despite_being_ints(self, value: object) -> None:
        """`bool` is an `int` in Python, so this needs its own guard: the same trap
        `is_valid_threshold_type` already handles."""
        assert not is_threshold_value_numeric(value)


class TestThresholdTypeValueConsistency:
    """A threshold value must match its declared type, within two deliberate scope limits."""

    def test_the_reported_case_is_now_refused_locally(self) -> None:
        """`PERCENTAGE` with a non-numeric value is refused before anything is sent.

        Without the check it passes the lint and LCE rejects it with a 422.
        """
        payload = {"threshold_objects": [{"type": "PERCENTAGE", "value": "not-a-number"}]}
        findings = validate_payload(payload, _BOTH)

        assert [f.path for f in findings] == ["threshold_objects[0].value"]
        assert findings[0].rule == FindingCode.THRESHOLD_TYPE

    def test_the_message_names_the_type_but_never_the_value(self) -> None:
        """The type is named because the caller chose it and it is what
        makes the value wrong; the offending value is never echoed."""
        payload = {"threshold_objects": [{"type": "PERCENTAGE", "value": "s3cr3t-ish"}]}
        message = validate_payload(payload, _BOTH)[0].message

        assert "PERCENTAGE" in message
        assert "s3cr3t-ish" not in message

    @pytest.mark.parametrize("threshold_type", sorted(PERMITTED_THRESHOLD_TYPES))
    def test_every_permitted_type_refuses_a_wrongly_shaped_value(self, threshold_type: str) -> None:
        """Over the closed vocabulary: no type may be the one that lets it through."""
        payload = {"threshold_objects": [{"type": threshold_type, "value": "not-a-number"}]}
        findings = validate_payload(payload, _BOTH)

        assert len(findings) == 1, findings
        assert findings[0].path == "threshold_objects[0].value"

    @pytest.mark.parametrize("threshold_type", sorted(PERMITTED_THRESHOLD_TYPES))
    def test_a_well_shaped_value_passes_for_every_type(self, threshold_type: str) -> None:
        payload = {"threshold_objects": [{"type": threshold_type, "value": 75}]}
        assert validate_payload(payload, _BOTH) == ()

    def test_an_invalid_type_reports_one_finding_not_two(self) -> None:
        """One mistake must not be reported twice. With the type already invalid there is
        nothing for the value to be inconsistent with, so only the type finding fires."""
        payload = {"threshold_objects": [{"type": 0, "value": "not-a-number"}]}
        findings = validate_payload(payload, _BOTH)

        assert [f.path for f in findings] == ["threshold_objects[0].type"]

    def test_a_value_with_no_declared_type_is_not_a_finding(self) -> None:
        """`ThresholdObject.type` has a default, so there is no declared type to contradict."""
        assert validate_payload({"threshold_objects": [{"value": "anything"}]}, _BOTH) == ()

    def test_range_is_deliberately_not_enforced(self) -> None:
        """`PERCENTAGE` with 500 is not flagged, even against a 0-100 range.

        500 is a number, so the type matches; it is the range that is violated, and enforcing range
        is out of scope for this lint. This test makes that a decision rather than a gap.
        """
        payload = {"threshold_objects": [{"type": "PERCENTAGE", "value": 500}]}
        assert validate_payload(payload, _BOTH) == ()

    def test_integrality_is_deliberately_not_enforced(self) -> None:
        """`INTEGER` with `75.5` is not flagged, because flagging it would be a false refusal.

        LCE accepts the value without coercing it (a `commit=False` dry run returns
        `"type": "INTEGER", "value": 75.5` unchanged), and SL1 stores it exactly because
        `master.dynamic_app_thresholds.t_value` is `decimal(13,3) unsigned`, not an integer column.
        The `INTEGER` label is semantic, not a storage constraint.

        The real limit is 3 decimal places, which would be a different lint and is not
        implemented. See `validation.py` for the evidence.
        """
        payload = {"threshold_objects": [{"type": "INTEGER", "value": 75.5}]}
        assert validate_payload(payload, _BOTH) == ()

    def test_decimal_is_a_first_class_type_not_a_workaround(self) -> None:
        """`DECIMAL` is one of the three types the LCE contract itself enumerates.

        Pinned separately because the question "what do I use for a fractional threshold?" has a
        real answer, `DECIMAL`, and a reader who only saw the integrality test above might
        conclude fractions are merely tolerated rather than properly supported.
        """
        assert "DECIMAL" in PERMITTED_THRESHOLD_TYPES
        for value in (75.5, "75.5", 75, "75"):
            payload = {"threshold_objects": [{"type": "DECIMAL", "value": value}]}
            assert validate_payload(payload, _BOTH) == (), f"DECIMAL rejected {value!r}"

    def test_findings_stay_in_document_order(self) -> None:
        """The value check fires at the `value` key, so a bad guid earlier in the
        object must still be reported first."""
        payload = {
            "threshold_objects": [{"guid": "bad", "type": "PERCENTAGE", "value": "not-a-number"}]
        }
        assert [f.path for f in validate_payload(payload, _BOTH)] == [
            "threshold_objects[0].guid",
            "threshold_objects[0].value",
        ]

    def test_the_scope_limit_still_holds(self) -> None:
        """A `type`/`value` pair on an unrelated object is not this lint's subject."""
        payload = {"type": "PERCENTAGE", "value": "not-a-number"}
        assert validate_payload(payload, _BOTH) == ()

    def test_it_runs_only_when_the_threshold_lint_is_selected(self) -> None:
        payload = {"threshold_objects": [{"type": "PERCENTAGE", "value": "not-a-number"}]}
        assert validate_payload(payload, _GUID_ONLY) == ()


class TestSelectionAndPurity:
    def test_a_read_operation_performs_no_traversal(self) -> None:
        """An empty `lint_rules` means there is nothing to do; `rules` is data selection."""
        assert validate_payload({"guid": "bad"}, frozenset()) == ()

    def test_only_the_selected_lint_runs(self) -> None:
        payload = {"guid": "bad", "threshold_objects": [{"type": 0}]}
        findings = validate_payload(payload, _GUID_ONLY)
        assert {f.rule for f in findings} == {FindingCode.CHILD_GUID}

    def test_never_mutates_its_input(self) -> None:
        """The payload sent to LCE is the caller's own, byte for byte."""
        payload = {"dynamic_applications": [{"guid": "bad", "threshold_objects": [{"type": 0}]}]}
        before = repr(payload)
        validate_payload(payload, _BOTH)
        assert repr(payload) == before

    def test_never_raises_on_hostile_content(self) -> None:
        """It returns findings. The tool layer decides they mean
        `ValidationBlocked`.
        """
        payload = {"guid": {"nested": [1, None, True]}, "threshold_objects": [{"type": []}]}
        assert len(validate_payload(payload, _BOTH)) == 2


class TestFindingMessages:
    def test_guid_message_states_both_remedies_and_never_the_value(self) -> None:
        """The message tells the caller how to fix the GUID without echoing it."""
        secret = "DEADBEEFdeadbeef"
        (finding,) = validate_payload({"guid": secret}, _GUID_ONLY)
        assert secret not in finding.message
        assert "Omit the key" in finding.message
        assert "update it" in finding.message

    def test_threshold_message_names_the_permitted_set(self) -> None:
        (finding,) = validate_payload({"threshold_objects": [{"type": "nope"}]}, _BOTH)
        assert "nope" not in finding.message
        for permitted in PERMITTED_THRESHOLD_TYPES:
            assert permitted in finding.message


def test_child_guid_pattern_is_uppercase_only() -> None:
    """Guards the constant itself: lowercase GUIDs are findings only while it is uppercase-only."""
    assert CHILD_GUID_PATTERN.pattern == r"^[A-F0-9]{32}$"
