"""
Guided Discovery Tests

This module tests the guided-discovery action resolver and the
``sl1_create_guided_discovery_session`` tool. Every fixture was read from a test appliance rather
than invented: the workflow definition, both session shapes and the action list. The resolver's
job is to cope with platform data whose shape is not declared anywhere, and an invented fixture
would only agree with whatever the resolver assumed.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from powerpack_mcp.config import Config
from powerpack_mcp.credentials import LceCredential
from powerpack_mcp.tools.sl1_guided_discovery import (
    MAX_RESULT_DEPTH,
    MAX_RESULT_STRING_CHARS,
    PendingAction,
    PlannedAction,
    ResolutionError,
    _bounded_result,
    build_action_plan,
    build_mutation_document,
    discovery_actions_of,
    make_sl1_create_guided_discovery_session,
    resolve_reference,
)

# The AWS workflow's two actions, copied from the appliance's
# "AWS Universal Assume Role Guided Discovery" definition.
_AWS_WORKFLOW: dict[str, Any] = {
    "discoveryActions": [
        {
            "mutationName": "createVirtualDevice",
            "queryVariables": {
                "name": {
                    "fieldName": {"field": "discoverySession.definition.rootDevice"},
                    "fieldType": "String!",
                },
                "organization": {
                    "fieldName": {"field": "discoverySession.organization"},
                    "fieldType": "ID!",
                },
                "collectorGroup": {
                    "fieldName": {"field": "discoverySession.definition.selectedCollectorGroupId"},
                    "fieldType": "ID!",
                },
                "deviceClass": {
                    "fieldName": {"value": "B9D0BE698EE48EE5D4217F1F3F87FDC5"},
                    "fieldType": "ID!",
                },
            },
        },
        {
            "mutationName": "alignDynamicApplicationsToDevice",
            "queryVariables": {
                "device": {
                    "fieldName": {"field": "mutation.createVirtualDevice.id"},
                    "fieldType": "ID!",
                },
                "credential": {"fieldName": {"field": "credential"}, "fieldType": "ID!"},
                "dynamicApplications": {
                    "fieldName": {"value": ["DCFF227C44200F35BFEFA7F2BC6AA41C"]},
                    "fieldType": "[ID!]!",
                },
            },
        },
    ]
}

# An API-created session: ``definition`` is a JSON string and the credential is a bare guid.
_API_SESSION: dict[str, Any] = {
    "id": "KFIEBGMURFF4N75Q6O7CNR5XT0CU9WPH",
    "organization": {"id": "1", "company": "AWS"},
    "definition": json.dumps(
        {
            "rootDevice": "ccGdProbe2eb1d4d1",
            "organization": "1",
            "selectedCollectorGroupId": "1",
            "credential": "GI7I6QDXBG75AX3C2C1BCT1SE79PWSYD",
        }
    ),
}

# A UI-created session. Same workflow, different shape: ``credentials`` is a list of full
# credential objects, and ``selectedCollectorId`` appears in no ``workflowSteps`` field.
_UI_SESSION: dict[str, Any] = {
    "id": "YKTRBOP6RRJHQ88NTYS0HBUD9966E16E",
    "organization": {"id": "1", "company": "AWS"},
    "definition": json.dumps(
        {
            "rootDevice": "AWSRootDevice",
            "selectedCollectorId": "4",
            "selectedCollectorGroupId": "2",
            "credentials": [
                {
                    "__typename": "Credential",
                    "id": "45",
                    "guid": "P80ILFEV9M8A1M8SOBIJZ90SHMZZ82JB",
                    "name": "AUTO_AWS_UniversalAssumeRole",
                    "type": "UNIVERSAL",
                    "subType": "aws assume role",
                    "allOrganizations": True,
                    "timeout": 1500,
                }
            ],
        }
    ),
}


class TestTheTwoDefinitionShapes:
    """One workflow produces two session shapes, and the resolver must handle both."""

    def test_the_api_shape_resolves_its_bare_credential_guid(self) -> None:
        plan = build_action_plan(_API_SESSION, _AWS_WORKFLOW, {"createVirtualDevice": {"id": "13"}})
        assert plan[1].variables["credential"] == "GI7I6QDXBG75AX3C2C1BCT1SE79PWSYD"

    def test_the_ui_shape_resolves_a_guid_out_of_a_credential_object_list(self) -> None:
        """Same reference, ``{"field": "credential"}``, against a list of objects, not a string.

        A resolver written from the workflow's declared ``workflowSteps`` would find neither form,
        since neither ``credential`` nor ``credentials`` is a declared field.
        """
        plan = build_action_plan(_UI_SESSION, _AWS_WORKFLOW, {"createVirtualDevice": {"id": "99"}})
        assert plan[1].variables["credential"] == "P80ILFEV9M8A1M8SOBIJZ90SHMZZ82JB"

    def test_the_singular_wins_when_a_session_somehow_carries_both(self) -> None:
        """Deterministic rather than incidental: the singular is the form the API round-trips."""
        both = {
            "organization": {"id": "1"},
            "definition": {
                "rootDevice": "r",
                "selectedCollectorGroupId": "1",
                "credential": "SINGULARWINS",
                "credentials": [{"guid": "PLURALLOSES"}],
            },
        }
        plan = build_action_plan(both, _AWS_WORKFLOW, {"createVirtualDevice": {"id": "1"}})
        assert plan[1].variables["credential"] == "SINGULARWINS"

    def test_a_session_supplying_no_credential_at_all_says_so(self) -> None:
        """The fixture supplies everything except the credential, on purpose.

        Omitting ``selectedCollectorGroupId`` too would fail on that reference first, and the test
        would pass while asserting the wrong error.
        """
        bare = {
            "organization": {"id": "1"},
            "definition": {"rootDevice": "r", "selectedCollectorGroupId": "1"},
        }
        with pytest.raises(ResolutionError, match="neither a 'credential' guid nor a"):
            build_action_plan(bare, _AWS_WORKFLOW, {"createVirtualDevice": {"id": "1"}})


class TestThePlanMatchesWhatWeRanByHand:
    """The plan must reproduce the two calls that worked when run by hand on an appliance."""

    def test_step_one_resolves_to_the_arguments_that_created_device_13(self) -> None:
        """These are the exact values that produced a device, including the device class.

        ``deviceClass`` is the workflow's literal ``B9D0BE…`` ("AWS Service"), not
        ``sl1_create_virtual_device``'s own default emissary class. Letting the default win would
        create the device against the wrong class, and the later alignment would be rejected,
        because alignment is all-or-nothing on device-class compatibility.
        """
        plan = build_action_plan(_API_SESSION, _AWS_WORKFLOW)
        assert len(plan) == 1, "with nothing executed yet, only step one is resolvable"
        assert plan[0] == PlannedAction(
            "createVirtualDevice",
            {
                "name": "ccGdProbe2eb1d4d1",
                "organization": "1",
                "collectorGroup": "1",
                "deviceClass": "B9D0BE698EE48EE5D4217F1F3F87FDC5",
            },
        )

    def test_step_two_chains_the_device_id_out_of_step_one(self) -> None:
        """The ``mutation.createVirtualDevice.id`` form is what makes this a flow, not two calls."""
        plan = build_action_plan(_API_SESSION, _AWS_WORKFLOW, {"createVirtualDevice": {"id": "13"}})
        assert plan[1] == PlannedAction(
            "alignDynamicApplicationsToDevice",
            {
                "device": "13",
                "credential": "GI7I6QDXBG75AX3C2C1BCT1SE79PWSYD",
                "dynamicApplications": ["DCFF227C44200F35BFEFA7F2BC6AA41C"],
            },
        )

    def test_the_actions_keep_the_workflows_own_order(self) -> None:
        """Order is load-bearing, not cosmetic: step two cannot resolve before step one has run."""
        plan = build_action_plan(_API_SESSION, _AWS_WORKFLOW, {"createVirtualDevice": {"id": "13"}})
        assert [action.mutation for action in plan] == [
            "createVirtualDevice",
            "alignDynamicApplicationsToDevice",
        ]


class TestTheResolvablePrefix:
    """Stopping at a forward reference is not the same as failing on a broken one."""

    def test_with_nothing_run_the_plan_is_just_the_first_action(self) -> None:
        assert [a.mutation for a in build_action_plan(_API_SESSION, _AWS_WORKFLOW)] == [
            "createVirtualDevice"
        ]

    def test_feeding_step_ones_output_back_extends_the_plan(self) -> None:
        """The intended loop: execute the prefix, pass results back, call again."""
        first = build_action_plan(_API_SESSION, _AWS_WORKFLOW)
        assert len(first) == 1
        second = build_action_plan(
            _API_SESSION, _AWS_WORKFLOW, {"createVirtualDevice": {"id": "13"}}
        )
        assert len(second) == 2
        assert second[0] == first[0], "the already-resolved prefix must not change underneath"

    def test_a_reference_to_an_action_the_workflow_never_defines_is_refused(self) -> None:
        """A reference to an action that is never defined raises rather than truncating.

        "Never" differs from "not yet", and collapsing them would turn a broken workflow into a
        silently empty run.
        """
        broken = {
            "discoveryActions": [
                {
                    "mutationName": "onlyAction",
                    "queryVariables": {
                        "x": {"fieldName": {"field": "mutation.ghostAction.id"}, "fieldType": "ID!"}
                    },
                }
            ]
        }
        with pytest.raises(ResolutionError, match="does not define"):
            build_action_plan(_API_SESSION, broken)


class TestTheRemainingEdges:
    """The defensive branches. Platform data means each one is reachable, not theoretical."""

    def test_a_definition_that_is_neither_object_nor_string_is_refused(self) -> None:
        """SL1 returns a string and callers hold dicts; anything else is a shape surprise."""
        with pytest.raises(ResolutionError, match="is int, expected an object or JSON"):
            build_action_plan({"definition": 42}, _AWS_WORKFLOW)

    def test_a_credentials_list_whose_first_entry_has_no_guid_is_refused(self) -> None:
        """The UI shape, but malformed: a list present with nothing usable in it."""
        session = {
            "organization": {"id": "1"},
            "definition": {
                "rootDevice": "r",
                "selectedCollectorGroupId": "1",
                "credentials": [{"__typename": "Credential", "id": "45"}],
            },
        }
        with pytest.raises(ResolutionError, match="no usable guid on its first entry"):
            build_action_plan(session, _AWS_WORKFLOW, {"createVirtualDevice": {"id": "1"}})

    def test_a_missing_top_level_session_field_lists_what_the_session_has(self) -> None:
        with pytest.raises(ResolutionError, match=r"has no 'organization'"):
            resolve_reference({"field": "discoverySession.organization"}, {"id": "x"}, {}, {})

    def test_a_scalar_session_field_is_returned_without_unwrapping(self) -> None:
        """Only a nested `id` is unwrapped; a plain value must pass through untouched."""
        got = resolve_reference({"field": "discoverySession.id"}, {"id": "abc"}, {}, {})
        assert got == "abc"

    def test_an_object_field_with_no_id_is_returned_as_is(self) -> None:
        """Unwrapping is conditional. An object without an `id` is not ours to reinterpret."""
        session = {"organization": {"company": "Acme"}}
        got = resolve_reference({"field": "discoverySession.organization"}, session, {}, {})
        assert got == {"company": "Acme"}

    def test_a_non_object_entry_in_discovery_actions_is_refused(self) -> None:
        with pytest.raises(ResolutionError, match=r"discoveryActions\[1\] is not an object"):
            build_action_plan(
                _API_SESSION, {"discoveryActions": [{"mutationName": "ok"}, "not an object"]}
            )

    def test_planned_action_repr_and_equality_are_usable(self) -> None:
        """``PlannedAction`` is what a caller inspects before executing, so both matter.

        Equality is compared against a non-``PlannedAction`` too, because returning
        ``NotImplemented`` rather than ``False`` lets Python fall back instead of reporting unequal.
        """
        action = PlannedAction("m", {"a": 1})
        assert "PlannedAction(mutation='m'" in repr(action)
        assert action == PlannedAction("m", {"a": 1})
        assert action != PlannedAction("m", {"a": 2})
        assert action.__eq__("not an action") is NotImplemented


class TestReferenceForms:
    """Each of the four forms, plus the failures a caller can actually act on."""

    def test_an_organization_object_is_flattened_to_its_id(self) -> None:
        """SL1 declares this ``ID!`` and returns it as an object; passing the object sends a dict.

        The mutation would then fail with a type error pointing at SL1 rather than at the mismatch,
        which is why the unwrapping happens here where the reason can be written down.
        """
        session = {"organization": {"id": "7", "company": "Acme"}, "definition": {}}
        got = resolve_reference({"field": "discoverySession.organization"}, session, {}, {})
        assert got == "7"

    def test_a_literal_is_returned_untouched_including_a_list(self) -> None:
        assert resolve_reference({"value": ["a", "b"]}, {}, {}, {}) == ["a", "b"]

    def test_a_literal_beats_a_field_when_a_reference_carries_both(self) -> None:
        """A malformed workflow, but deterministically handled rather than order-dependent."""
        assert resolve_reference({"value": "lit", "field": "credential"}, {}, {}, {}) == "lit"

    def test_referring_to_an_action_that_has_not_run_signals_pending_not_failure(self) -> None:
        """``PendingAction`` is deliberately not a ``ResolutionError`` subclass.

        At this level the resolver cannot know whether the workflow defines that action; only
        ``build_action_plan`` has the list. So the signal is raised unqualified here and classified
        one layer up.
        """
        with pytest.raises(PendingAction, match="awaits action 'createVirtualDevice'") as caught:
            resolve_reference({"field": "mutation.createVirtualDevice.id"}, {}, {}, {})
        assert caught.value.mutation == "createVirtualDevice"
        assert not isinstance(caught.value, ResolutionError), (
            "PendingAction must not be catchable as a ResolutionError, or build_action_plan's "
            "not-yet versus never distinction collapses"
        )

    def test_referring_to_a_field_the_action_did_not_return_lists_what_it_did(self) -> None:
        with pytest.raises(ResolutionError, match=r"returned no 'guid'"):
            resolve_reference(
                {"field": "mutation.createVirtualDevice.guid"},
                {},
                {},
                {"createVirtualDevice": {"id": "13", "name": "d"}},
            )

    def test_a_missing_definition_property_lists_what_the_definition_has(self) -> None:
        with pytest.raises(ResolutionError, match=r"has no 'nope'"):
            resolve_reference(
                {"field": "discoverySession.definition.nope"}, {}, {"rootDevice": "r"}, {}
            )

    def test_an_unrecognised_reference_form_is_refused_rather_than_guessed(self) -> None:
        with pytest.raises(ResolutionError, match="unrecognised reference form"):
            resolve_reference({"field": "somethingElse.entirely"}, {}, {}, {})

    def test_a_reference_with_no_value_and_no_field_is_refused(self) -> None:
        with pytest.raises(ResolutionError, match="neither a literal value nor a field"):
            resolve_reference({"fieldType": "ID!"}, {}, {}, {})


class TestMalformedPlatformData:
    """The definition is platform data, so every shape assumption needs a named failure."""

    def test_a_definition_arriving_as_an_object_works_as_well_as_a_string(self) -> None:
        """Both occur: SL1 returns a string, a caller assembling one in memory holds a dict."""
        as_object = {
            "organization": {"id": "1"},
            "definition": {
                "rootDevice": "r",
                "selectedCollectorGroupId": "1",
                "credential": "G",
            },
        }
        plan = build_action_plan(as_object, _AWS_WORKFLOW, {"createVirtualDevice": {"id": "1"}})
        assert plan[0].variables["name"] == "r"

    def test_a_definition_that_is_not_json_says_so(self) -> None:
        with pytest.raises(ResolutionError, match="not valid JSON"):
            build_action_plan({"definition": "{not json"}, _AWS_WORKFLOW)

    def test_a_definition_that_parses_to_a_non_object_says_so(self) -> None:
        with pytest.raises(ResolutionError, match="parsed to list"):
            build_action_plan({"definition": "[1, 2]"}, _AWS_WORKFLOW)

    def test_a_workflow_with_no_discovery_actions_says_there_are_no_steps(self) -> None:
        """A workflow may legitimately have none; the caller must be told rather than handed
        an empty run."""
        with pytest.raises(ResolutionError, match="no 'discoveryActions' list"):
            build_action_plan(_API_SESSION, {"workflowSteps": []})

    def test_an_action_with_no_mutation_name_is_refused(self) -> None:
        with pytest.raises(ResolutionError, match="has no mutationName"):
            build_action_plan(_API_SESSION, {"discoveryActions": [{"queryVariables": {}}]})

    def test_a_variable_spec_with_no_field_name_object_names_the_argument(self) -> None:
        broken = {
            "discoveryActions": [
                {"mutationName": "createVirtualDevice", "queryVariables": {"name": {"oops": 1}}}
            ]
        }
        with pytest.raises(ResolutionError, match=r"createVirtualDevice\.name has no fieldName"):
            build_action_plan(_API_SESSION, broken)

    def test_an_action_with_no_variables_plans_an_empty_call_rather_than_failing(self) -> None:
        """Not every mutation takes arguments, so an absent `queryVariables` is legal."""
        plan = build_action_plan(_API_SESSION, {"discoveryActions": [{"mutationName": "ping"}]})
        assert plan == [PlannedAction("ping", {})]


class TestTheMutationDocument:
    """Rendering an action as GraphQL; the names and types are platform data, by design."""

    def test_the_create_virtual_device_action_renders_a_valid_document(self) -> None:
        action = _AWS_WORKFLOW["discoveryActions"][0] | {"result": [{"field": "id"}]}
        document = build_mutation_document(action)
        assert document.startswith("mutation RunDiscoveryAction($name: String!")
        assert "$organization: ID!" in document
        assert "createVirtualDevice(name: $name" in document
        assert document.rstrip().endswith("{ id } }")

    def test_a_nested_selection_is_emitted_verbatim(self) -> None:
        """The AWS workflow contains ``active { maintenance … }``; it must not be flattened."""
        action = {
            "mutationName": "m",
            "queryVariables": {},
            "result": [{"field": "active { maintenance unavailable }"}, {"field": "id"}],
        }
        assert "{ active { maintenance unavailable } id }" in build_mutation_document(action)

    def test_an_action_with_no_variables_declares_none(self) -> None:
        got = build_mutation_document({"mutationName": "ping", "result": [{"field": "ok"}]})
        assert got == "mutation RunDiscoveryAction { ping { ok } }"

    def test_an_action_with_no_result_gets_no_selection(self) -> None:
        got = build_mutation_document({"mutationName": "ping"})
        assert got == "mutation RunDiscoveryAction { ping }"

    def test_an_argument_with_no_field_type_is_refused(self) -> None:
        """A variable used without a declaration is a GraphQL validation error.

        SL1 would report it as a bad query, sending a caller to debug our document instead of the
        workflow.
        """
        broken = {"mutationName": "m", "queryVariables": {"x": {"fieldName": {"value": 1}}}}
        with pytest.raises(ResolutionError, match=r"m\.x declares no fieldType"):
            build_mutation_document(broken)

    def test_an_action_with_no_mutation_name_is_refused(self) -> None:
        with pytest.raises(ResolutionError, match="no mutationName"):
            build_mutation_document({"queryVariables": {}})


def _gql(payloads: list[dict[str, Any]]) -> Any:
    """A handler returning each canned GraphQL body in turn, so a multi-step run can be driven."""
    remaining = list(payloads)

    def handler(_request: httpx.Request) -> httpx.Response:
        assert remaining, "the tool issued more requests than the test supplied responses for"
        return httpx.Response(200, json={"data": remaining.pop(0)})

    return handler


_WORKFLOW_ROW: dict[str, Any] = {
    "id": "803531c3406a4097912e591d5add14ar",
    "name": "AWS Universal Assume Role Guided Discovery",
    "definition": json.dumps(_AWS_WORKFLOW),
}


class TestTheToolDryRun:
    """Nothing may be created and nothing executed. That is the whole contract."""

    @pytest.mark.anyio
    async def test_a_dry_run_reads_the_workflow_and_issues_nothing_else(
        self, config: Config, credential: LceCredential
    ) -> None:
        from tests.unit.test_sl1_tools import _ctx

        context, seen, _ = _ctx(
            config, credential, _gql([{"guidedDiscoveryWorkflow": _WORKFLOW_ROW}])
        )
        result = await make_sl1_create_guided_discovery_session(context)(
            name="n",
            discovery_workflow="803531c3406a4097912e591d5add14ar",
            organization="1",
            definition={
                "rootDevice": "r",
                "selectedCollectorGroupId": "1",
                "credential": "GUID",
            },
            dry_run=True,
        )
        assert isinstance(result, dict)
        assert result["dry_run"] is True
        assert len(seen) == 1, "a dry run may read the workflow and NOTHING else"
        body = json.loads(seen[0].content)["query"]
        assert "createGuidedDiscoverySession" not in body, "a dry run must not create the session"

    @pytest.mark.anyio
    async def test_a_dry_run_plans_every_action_with_self_describing_placeholders(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The placeholder must not look like a value.

        A plan is worth reviewing only if it shows every step, but later steps depend on outputs
        that do not exist yet. A plausible-looking id would be mistaken for real exactly when
        somebody approves the plan, so the placeholder says what it is.
        """
        from tests.unit.test_sl1_tools import _ctx

        context, _, _ = _ctx(config, credential, _gql([{"guidedDiscoveryWorkflow": _WORKFLOW_ROW}]))
        result = await make_sl1_create_guided_discovery_session(context)(
            name="n",
            discovery_workflow="w",
            organization="1",
            definition={"rootDevice": "r", "selectedCollectorGroupId": "1", "credential": "G"},
            dry_run=True,
        )
        assert isinstance(result, dict)
        plan = result["plan"]
        assert [step["mutation"] for step in plan] == [
            "createVirtualDevice",
            "alignDynamicApplicationsToDevice",
        ], "every action must appear, or the plan is not reviewable"
        assert plan[1]["variables"]["device"] == "<from createVirtualDevice.id>"
        assert plan[0]["variables"]["name"] == "r", "resolvable values are real, not placeholders"


class TestTheToolExecutes:
    """The create-and-run path: create, then run the actions in order, chaining outputs."""

    @pytest.mark.anyio
    async def test_it_creates_then_runs_both_actions_chaining_the_device_id(
        self, config: Config, credential: LceCredential
    ) -> None:
        from tests.unit.test_sl1_tools import _ctx

        session_row = {
            "id": "SESSION",
            "dateRun": None,
            "organization": {"id": "1"},
            "definition": json.dumps(
                {"rootDevice": "r", "selectedCollectorGroupId": "1", "credential": "GUID"}
            ),
            "discoveryWorkflow": _WORKFLOW_ROW,
        }
        context, seen, _ = _ctx(
            config,
            credential,
            _gql(
                [
                    {"createGuidedDiscoverySession": session_row},
                    {"createVirtualDevice": {"id": "13", "name": "r"}},
                    {"alignDynamicApplicationsToDevice": {"id": "DA"}},
                ]
            ),
        )
        result = await make_sl1_create_guided_discovery_session(context)(
            name="n",
            discovery_workflow="w",
            organization="1",
            definition={"rootDevice": "r", "selectedCollectorGroupId": "1", "credential": "GUID"},
        )
        assert isinstance(result, dict)
        executed = result["executed"]
        assert [step["mutation"] for step in executed] == [
            "createVirtualDevice",
            "alignDynamicApplicationsToDevice",
        ]
        assert executed[1]["variables"]["device"] == "13", "step one's id must reach step two"
        assert len(seen) == 3, "one create plus one call per action"
        assert "discoveryWorkflow" not in result["session"], (
            "the workflow definition is bulky platform data and is not echoed back"
        )

    @pytest.mark.anyio
    async def test_it_does_not_stamp_date_run(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Mirrors the UI, which does not stamp it either.

        A session that has run still reads null, so the field is not a run indicator and writing it
        would invent one.
        """
        from tests.unit.test_sl1_tools import _ctx

        session_row = {
            "id": "S",
            "organization": {"id": "1"},
            "definition": json.dumps({"rootDevice": "r"}),
            "discoveryWorkflow": {"id": "w", "definition": json.dumps({"discoveryActions": []})},
        }
        context, seen, _ = _ctx(
            config, credential, _gql([{"createGuidedDiscoverySession": session_row}])
        )
        result = await make_sl1_create_guided_discovery_session(context)(
            name="n", discovery_workflow="w", organization="1", definition={"rootDevice": "r"}
        )
        assert isinstance(result, dict)
        assert result["executed"] == [], "a workflow with no actions runs nothing"
        assert not any(
            "updateGuidedDiscoverySession" in json.loads(r.content).get("query", "") for r in seen
        ), "dateRun must not be written"

    @pytest.mark.anyio
    async def test_a_response_missing_its_root_field_is_an_error_not_a_none(
        self, config: Config, credential: LceCredential
    ) -> None:
        """GraphQL guarantees the key on success, so its absence means a different answer came."""
        from tests.unit.test_sl1_tools import _ctx

        context, _, _ = _ctx(config, credential, _gql([{"somethingElse": {}}]))
        result = await make_sl1_create_guided_discovery_session(context)(
            name="n", discovery_workflow="w", organization="1", definition={}, dry_run=True
        )
        assert isinstance(result, dict)
        assert "error" in result, f"expected the boundary to report an error, got {result}"


class TestTheResultBoundIsOnValuesNotNames:
    """An action's echoed ``result`` is capped per string; nothing else is touched."""

    def test_a_short_string_is_returned_unchanged(self) -> None:
        """The common case. A small ``svg`` is not special-cased; it is simply not oversized."""
        small = '<svg viewBox="0 0 16 16"><circle r="7"/></svg>'
        assert len(small) < MAX_RESULT_STRING_CHARS
        assert _bounded_result({"icon": {"svg": small}}) == {"icon": {"svg": small}}

    def test_an_oversized_string_is_cut_and_marked(self) -> None:
        svg = "M" * 3000

        bounded = _bounded_result({"svg": svg})["svg"]

        assert bounded.startswith("M" * MAX_RESULT_STRING_CHARS)
        assert bounded.endswith("… [truncated]")
        assert len(bounded) == MAX_RESULT_STRING_CHARS + len("… [truncated]")
        assert svg not in bounded, "the full value must not survive anywhere in the output"

    def test_structure_keys_and_positions_all_survive(self) -> None:
        """Only text is cut. A caller's ``mutation.<name>.<field>`` path must still be walkable."""
        result = {"id": "13", "name": "r", "icon": {"id": "I", "svg": "M" * 900}, "tags": ["a", 2]}

        bounded = _bounded_result(result)

        assert set(bounded) == {"id", "name", "icon", "tags"}
        assert bounded["id"] == "13"
        assert set(bounded["icon"]) == {"id", "svg"}
        assert bounded["icon"]["id"] == "I"
        assert bounded["tags"] == ["a", 2]

    @pytest.mark.parametrize("value", [None, False, True, 0, 0.0, -1])
    def test_falsey_scalars_pass_through_as_values(self, value: object) -> None:
        """``0`` and ``false`` are values, never absence; a truthiness shortcut would drop them."""
        assert _bounded_result({"k": value}) == {"k": value}

    def test_depth_is_bounded_by_the_limit_not_by_the_input(self) -> None:
        """A naive recursion would raise ``RecursionError`` on exactly the input it must survive.

        Built 5,000 deep on purpose. The assertion is that this returns, and that the elision
        marker appears rather than the payload.
        """
        deep: Any = "bottom"
        for _ in range(5000):
            deep = {"next": deep}

        bounded = _bounded_result(deep)

        rendered = json.dumps(bounded)
        assert "**elided: nested beyond the depth limit**" in rendered
        assert "bottom" not in rendered, "the bound must stop the walk before reaching the leaf"

    def test_the_marker_replaces_the_subtree_at_the_depth_limit(self) -> None:
        """A precise statement of where the bound bites, so the 16 is not a magic number."""
        deep: Any = {"leaf": "v"}
        for _ in range(MAX_RESULT_DEPTH):
            deep = {"n": deep}

        rendered = json.dumps(_bounded_result(deep))

        assert rendered.count("**elided") == 1
        assert '"leaf"' not in rendered

    def test_a_non_json_value_is_rendered_as_a_bounded_string(self) -> None:
        """Totality: ``response.json()`` is typed ``Any``, so the fallback is reachable."""

        class Odd:
            def __repr__(self) -> str:
                return "O" * 2000

        bounded = _bounded_result({"weird": Odd()})["weird"]

        assert bounded.startswith("O" * MAX_RESULT_STRING_CHARS)
        assert bounded.endswith("… [truncated]")

    @pytest.mark.anyio
    async def test_the_echo_is_bounded_but_the_chained_value_is_not(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Bounding the chained ``outputs`` would feed SL1 a value it never issued.

        Step one's ``id`` is longer than the cap, so both halves are distinguishable in one run: the
        caller-facing echo of step one is cut, while the ``device`` argument step two sends to SL1
        carries the id in full. Bound both and this test fails; bound neither and the SVG assertion
        fails.
        """
        from tests.unit.test_sl1_tools import _ctx

        long_id = "D" * 600
        assert len(long_id) > MAX_RESULT_STRING_CHARS
        session_row = {
            "id": "SESSION",
            "organization": {"id": "1"},
            "definition": json.dumps(
                {"rootDevice": "r", "selectedCollectorGroupId": "1", "credential": "GUID"}
            ),
            "discoveryWorkflow": _WORKFLOW_ROW,
        }
        context, seen, _ = _ctx(
            config,
            credential,
            _gql(
                [
                    {"createGuidedDiscoverySession": session_row},
                    {
                        "createVirtualDevice": {
                            "id": long_id,
                            "name": "r",
                            "icon": {"id": "I", "name": "F5", "svg": "M" * 2316},
                        }
                    },
                    {"alignDynamicApplicationsToDevice": {"id": "DA"}},
                ]
            ),
        )

        result = await make_sl1_create_guided_discovery_session(context)(
            name="n",
            discovery_workflow="w",
            organization="1",
            definition={"rootDevice": "r", "selectedCollectorGroupId": "1", "credential": "GUID"},
        )

        assert isinstance(result, dict)
        echoed = result["executed"][0]["result"]
        assert echoed["icon"]["svg"].endswith("… [truncated]"), "the SVG must be capped"
        assert len(echoed["icon"]["svg"]) < 600, "2,316 characters of path data must not be echoed"
        assert echoed["icon"]["name"] == "F5", "small sibling fields are untouched"
        assert echoed["id"].endswith("… [truncated]"), "the cap is on VALUES, not on chosen names"

        # The half that matters: SL1 received the id in full.
        assert result["executed"][1]["variables"]["device"] == long_id
        sent = json.loads(seen[-1].content)
        assert long_id in json.dumps(sent), "a truncated id must never reach the platform"


class TestTheLastDefensiveBranches:
    """Reachable, not theoretical: each depends on what SL1 or a workflow actually returns."""

    def test_discovery_actions_of_a_definition_without_the_key_is_refused(self) -> None:
        """``discovery_actions_of`` has its own guard because the executor calls it directly.

        The check cannot live solely in ``build_action_plan``.
        """
        with pytest.raises(ResolutionError, match="no 'discoveryActions' list"):
            discovery_actions_of({"workflowSteps": []})

    @pytest.mark.anyio
    async def test_a_workflow_read_returning_a_non_object_is_refused(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The dry-run path reads the workflow separately, so a scalar there must not flow on."""
        from tests.unit.test_sl1_tools import _ctx

        context, _, _ = _ctx(
            config, credential, _gql([{"guidedDiscoveryWorkflow": "not an object"}])
        )
        result = await make_sl1_create_guided_discovery_session(context)(
            name="n", discovery_workflow="w", organization="1", definition={}, dry_run=True
        )
        assert isinstance(result, dict)
        assert "error" in result, f"expected a structured error, got {result}"

    @pytest.mark.anyio
    async def test_a_cyclic_action_reference_terminates_rather_than_spinning(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The action list is platform data, so a cycle is possible and must not hang a call.

        Two actions each waiting on the other resolve to nothing; the pass bound ends it and the
        dry run returns whatever prefix it had (here, empty) instead of looping forever.
        """
        from tests.unit.test_sl1_tools import _ctx

        cyclic = {
            "discoveryActions": [
                {
                    "mutationName": "a",
                    "queryVariables": {
                        "x": {"fieldName": {"field": "mutation.b.id"}, "fieldType": "ID!"}
                    },
                },
                {
                    "mutationName": "b",
                    "queryVariables": {
                        "y": {"fieldName": {"field": "mutation.a.id"}, "fieldType": "ID!"}
                    },
                },
            ]
        }
        context, _, _ = _ctx(
            config,
            credential,
            _gql([{"guidedDiscoveryWorkflow": {"id": "w", "definition": json.dumps(cyclic)}}]),
        )
        result = await make_sl1_create_guided_discovery_session(context)(
            name="n", discovery_workflow="w", organization="1", definition={}, dry_run=True
        )
        assert isinstance(result, dict)
        assert result["dry_run"] is True, "it must return, not hang"

    @pytest.mark.anyio
    async def test_a_chain_longer_than_the_pass_bound_gives_up_cleanly(
        self, config: Config, credential: LceCredential
    ) -> None:
        """A chain longer than ``_MAX_PASSES`` is the one way to reach the give-up path.

        Each pass resolves one more link, so a chain of N needs N passes. A longer workflow returns
        a partial plan rather than looping or raising, which suits a dry run whose job is to show
        what it can. Raising would make a long workflow un-previewable for a reason the caller
        could do nothing about.
        """
        from powerpack_mcp.tools.sl1_guided_discovery import _MAX_PASSES
        from tests.unit.test_sl1_tools import _ctx

        chain = {
            "discoveryActions": [
                {"mutationName": "step0", "queryVariables": {}},
                *(
                    {
                        "mutationName": f"step{i}",
                        "queryVariables": {
                            "prev": {
                                "fieldName": {"field": f"mutation.step{i - 1}.id"},
                                "fieldType": "ID!",
                            }
                        },
                    }
                    for i in range(1, _MAX_PASSES + 5)
                ),
            ]
        }
        context, _, _ = _ctx(
            config,
            credential,
            _gql([{"guidedDiscoveryWorkflow": {"id": "w", "definition": json.dumps(chain)}}]),
        )
        result = await make_sl1_create_guided_discovery_session(context)(
            name="n", discovery_workflow="w", organization="1", definition={}, dry_run=True
        )
        assert isinstance(result, dict)
        planned = len(result["plan"])
        assert 0 < planned < len(chain["discoveryActions"]), (
            f"expected a partial plan, got {planned} of {len(chain['discoveryActions'])}"
        )
