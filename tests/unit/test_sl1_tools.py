"""
SL1 Tool Tests

This module tests the SL1 tools: the signature rule, the registry, the REST passthroughs, the
typed readers and writers, the GraphQL tools, and the error codes they return.

Like ``test_sl1_client``, both transports use ``httpx.MockTransport``, so the tests need no
appliance, credential or network, and "the request was never issued" can be asserted. Some tools
use both SL1 and LCE, so the context carries two mocked clients.
"""

from __future__ import annotations

import inspect
import json
import logging
import re
from collections.abc import Callable
from typing import Any, Final

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from powerpack_mcp.config import Config
from powerpack_mcp.credentials import LceCredential
from powerpack_mcp.errors import (
    SL1_RESTRICTED_ACCESS_CODE,
    FindingCode,
    LogEvent,
    Sl1GraphQlError,
    Sl1MalformedResponse,
    ValidationBlocked,
    build_error_payload,
)
from powerpack_mcp.lce_client import LceClient
from powerpack_mcp.sl1_client import Sl1Client
from powerpack_mcp.tools import sl1_descriptors as d
from powerpack_mcp.tools import sl1_entity_tools as ent
from powerpack_mcp.tools import sl1_graphql_tools as gql
from powerpack_mcp.tools import sl1_ops_tools as ops
from powerpack_mcp.tools import sl1_rest_tools as rest
from powerpack_mcp.tools.sl1_credential_definition import (
    CRED_SECRET_KEYS,
    CRED_SUBTYPE_REST_V104,
    UNIVERSAL_DEFINITION_DEFAULTS,
    UniversalDefinitionError,
    normalize_universal_definition,
    serialize_universal_definition,
)
from powerpack_mcp.tools.sl1_pipeline import Sl1ToolContext
from powerpack_mcp.tools.sl1_registry import sl1_graphql_set_tools, sl1_rest_set_tools

# A ``fields {`` selection with no ``(includeDeprecated: true)``. Lower-case and guarded on the
# left so ``inputFields {`` is not mistaken for one.
_BARE_FIELD_SELECTION: Final = re.compile(r"(?<![A-Za-z])fields\s*\{")

Handler = Callable[[httpx.Request], httpx.Response]


def _ctx(
    config: Config,
    credential: LceCredential,
    sl1_handler: Handler,
    lce_handler: Handler | None = None,
) -> tuple[Sl1ToolContext, list[httpx.Request], list[httpx.Request]]:
    """A context whose two transports are mocked and whose requests are recorded."""
    sl1_seen: list[httpx.Request] = []
    lce_seen: list[httpx.Request] = []

    def record_sl1(request: httpx.Request) -> httpx.Response:
        sl1_seen.append(request)
        return sl1_handler(request)

    def record_lce(request: httpx.Request) -> httpx.Response:
        lce_seen.append(request)
        assert lce_handler is not None, "an LCE call was made where none was expected"
        return lce_handler(request)

    sl1 = Sl1Client(config)
    sl1._client = httpx.AsyncClient(transport=httpx.MockTransport(record_sl1))
    lce = LceClient(config)
    lce._client = httpx.AsyncClient(transport=httpx.MockTransport(record_lce))
    context = Sl1ToolContext(
        client=sl1, config=config, credential_source=lambda: credential, lce_client=lce
    )
    return context, sl1_seen, lce_seen


def _extra(record: logging.LogRecord, field: str) -> Any:
    """One field from a log record's ``extra`` mapping.

    ``extra=`` lands in ``LogRecord.__dict__``. Attribute access fails pyright, because
    ``LogRecord`` declares no such member, and a constant-name ``getattr`` is ruff ``B009``, which
    rewrites it into that attribute access.
    """
    return record.__dict__[field]


# A synthetic stand-in for a secret, so a leak assertion names something that could only have
# come from the arguments. Never a real credential.
_WRITER_CANARY: Final[str] = "cc-unit-canary-not-a-real-secret"

# A real ``UNIVERSAL`` subtype that is not the one ``UNIVERSAL_DEFINITION_DEFAULTS`` describes.
# The lowercase spelling matches SL1's ``getCredentialTypes`` payload (the AWS subtypes are
# ``aws assume role``, ``aws ec2`` and ``aws iam``). Only its difference from
# ``CRED_SUBTYPE_REST_V104`` matters here.
_AWS_ASSUME_ROLE: Final[str] = "aws assume role"


def _gql_ok(payload: dict[str, Any]) -> Handler:
    """A GraphQL 200 carrying ``data``."""
    return lambda _r: httpx.Response(200, json={"data": payload})


def _sequence(payloads: list[dict[str, Any]]) -> Handler:
    """Each ``data`` body in turn, for a tool that issues more than one call.

    The credential update reads the stored subtype before writing, so a single canned response
    would answer the read with the write's body and fail on a missing root field.
    """
    remaining = list(payloads)

    def handler(_request: httpx.Request) -> httpx.Response:
        assert remaining, "the tool issued more requests than the test supplied responses for"
        return httpx.Response(200, json={"data": remaining.pop(0)})

    return handler


def _rest_ok(body: Any) -> Handler:
    return lambda _r: httpx.Response(200, json=body)


class TestNoToolAcceptsAHostOrCredential:
    """No tool accepts a host or a credential, checked over every tool."""

    def test_no_tool_accepts_a_host_or_a_credential(
        self, config: Config, credential: LceCredential
    ) -> None:
        """No tool takes ``target_host``, ``username`` or ``password``.

        A caller-supplied or prompt-injected host would send the caller's own credential elsewhere.
        """
        context, _, _ = _ctx(config, credential, _rest_ok({}))
        forbidden = {"target_host", "username", "password"}
        offenders = {
            descriptor.tool_name: sorted(
                set(inspect.signature(make(context)).parameters) & forbidden
            )
            for descriptor, make in (*sl1_rest_set_tools(), *sl1_graphql_set_tools())
            if set(inspect.signature(make(context)).parameters) & forbidden
        }
        assert offenders == {}

    def test_the_signature_check_is_not_vacuous(
        self, config: Config, credential: LceCredential
    ) -> None:
        """``sl1_tool_boundary`` must preserve the wrapped signature.

        Without ``@wraps``, ``inspect.signature`` would report the decorator's ``*args, **kwargs``,
        which intersects nothing, so the test above would pass for every tool.
        """
        context, _, _ = _ctx(config, credential, _rest_ok({}))
        for descriptor, make in (*sl1_rest_set_tools(), *sl1_graphql_set_tools()):
            params = set(inspect.signature(make(context)).parameters)
            assert params != {"args", "kwargs"}, f"{descriptor.tool_name}: signature not preserved"
        # And at least one tool genuinely has the parameters we expect to see, so "non-empty" is not
        # satisfied by some other accident.
        request_tool = rest.make_sl1_rest_request(context)
        assert {"method", "path", "prune", "timeout"} <= set(
            inspect.signature(request_tool).parameters
        )


class TestRegistry:
    """``tools/sl1_registry.py``: the name-keyed pairing and its import-time totality check."""

    def test_every_descriptor_is_paired_and_the_counts_derive(self) -> None:
        assert len(sl1_rest_set_tools()) == len(d.SL1_REST_SET_DESCRIPTORS) == 22
        # The guided-discovery tool is grouped with the passthroughs so ENABLE_SL1_GRAPHQL_TOOLS
        # gates it: its per-step documents are built from platform data, which makes them
        # arbitrary GraphQL.
        assert len(sl1_graphql_set_tools()) == len(d.SL1_GRAPHQL_SET_DESCRIPTORS) == 3

    def test_each_pair_matches_its_own_descriptor_name(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The factory is looked up by the descriptor's name, so a transposition cannot happen.

        Pairing by ``zip`` would register every tool under the wrong name if two lists drifted.
        """
        context, _, _ = _ctx(config, credential, _rest_ok({}))
        for descriptor, make in (*sl1_rest_set_tools(), *sl1_graphql_set_tools()):
            assert make(context).__name__ == descriptor.tool_name

    def test_the_totality_check_actually_rejects_a_mismatch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The import-time guard must fail on a factory no descriptor claims.

        This is the silent direction: a stray factory never registers, the tool is absent from
        ``tools/list``, and the surface still looks complete.
        """
        from powerpack_mcp.tools import sl1_registry

        monkeypatch.setitem(
            sl1_registry._FACTORY_FOR, "sl1_not_a_real_tool", rest.make_sl1_rest_index
        )
        with pytest.raises(RuntimeError, match="sl1_not_a_real_tool"):
            sl1_registry._check_registry_is_total()


class TestRestPassthroughs:
    """The four REST passthroughs and their audit logging."""

    @pytest.mark.anyio
    async def test_a_request_is_issued_and_pruned(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, seen, _ = _ctx(config, credential, _rest_ok({"kept": 1, "dropped": ""}))
        tool = rest.make_sl1_rest_request(context)
        assert await tool(method="get", path="device") == {"kept": 1}
        assert seen[0].url.path == "/api/device"
        assert seen[0].method == "GET", "the verb is upper-cased before dispatch"

    @pytest.mark.anyio
    async def test_prune_false_keeps_the_literal_shape(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, _, _ = _ctx(config, credential, _rest_ok({"kept": 1, "empty": ""}))
        tool = rest.make_sl1_rest_request(context)
        assert await tool(method="GET", path="device", prune=False) == {"kept": 1, "empty": ""}

    @pytest.mark.anyio
    async def test_a_verb_outside_the_closed_set_is_refused_before_dispatch(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The rejection is audited too.

        An audit log of only successful passthroughs is useless against someone probing the
        surface, because the rejected calls are the interesting ones.
        """
        context, seen, _ = _ctx(config, credential, _rest_ok({}))
        tool = rest.make_sl1_rest_request(context)
        with caplog.at_level(logging.INFO):
            payload = await tool(method="TRACE", path="device")
        assert seen == [], "nothing may reach SL1 after a verb rejection"
        # An error envelope, not an escaping exception. A bare ``ValueError`` would pass straight
        # through ``sl1_tool_boundary``, which translates ``PowerPackMcpError`` only.
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"
        assert payload["error"]["details"][0]["rule"] == "tool_argument"
        audits = [
            r
            for r in caplog.records
            if getattr(r, "event", None) == LogEvent.SL1_PASSTHROUGH_INVOKED
        ]
        assert [_extra(r, "outcome") for r in audits] == ["rejected_method"]

    @pytest.mark.anyio
    async def test_the_audit_record_carries_method_path_and_no_credential(
        self,
        config: Config,
        credential: LceCredential,
        credential_value: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The record is enough to reconstruct the call, and carries no secret."""
        context, _, _ = _ctx(config, credential, _rest_ok({}))
        tool = rest.make_sl1_rest_request(context)
        with caplog.at_level(logging.INFO):
            await tool(method="POST", path="device/1", body={"x": 1})
        audit = next(
            r
            for r in caplog.records
            if getattr(r, "event", None) == LogEvent.SL1_PASSTHROUGH_INVOKED
        )
        assert _extra(audit, "sl1_method") == "POST"
        assert _extra(audit, "sl1_path") == "device/1"
        rendered = json.dumps({k: str(v) for k, v in audit.__dict__.items()})
        assert credential_value not in rendered, "the audit record carries no credential"

    @pytest.mark.anyio
    async def test_a_non_json_content_type_sends_a_raw_body(
        self, config: Config, credential: LceCredential
    ) -> None:
        """SL1's async operations take ``application/em7-resource-uri`` and a bare URI."""
        context, seen, _ = _ctx(config, credential, _rest_ok({}))
        tool = rest.make_sl1_rest_request(context)
        await tool(
            method="POST",
            path="discovery_session/1",
            body="/api/device/7",
            content_type="application/em7-resource-uri",
        )
        assert seen[0].headers["content-type"] == "application/em7-resource-uri"
        assert seen[0].content == b"/api/device/7"

    @pytest.mark.anyio
    async def test_index_describe_and_search_use_their_descriptors(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, seen, _ = _ctx(config, credential, _rest_ok({"ok": 1}))
        await rest.make_sl1_rest_index(context)()
        await rest.make_sl1_rest_describe(context)(resource="device")
        await rest.make_sl1_rest_search(context)(
            resource="device", filters={"name.contains": "core"}, order={"name": "ASC"}
        )
        assert seen[0].url.path == "/api/", "the index reaches the API root"
        assert seen[1].url.path == "/api/device"
        assert dict(seen[1].url.params) == {"limit": "0", "hide_filterinfo": "0"}
        params = dict(seen[2].url.params)
        assert params["filter.name.contains"] == "core"
        assert params["order.name"] == "ASC"
        assert params["limit"] == "20", "the source's default page size"

    @pytest.mark.anyio
    async def test_extended_fetch_lowers_the_default_page_size(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The source's own asymmetry: each row becomes a full object rather than a bare URI."""
        context, seen, _ = _ctx(config, credential, _rest_ok({}))
        await rest.make_sl1_rest_search(context)(resource="device", extended_fetch=True)
        params = dict(seen[0].url.params)
        assert params["limit"] == "10"
        assert params["extended_fetch"] == "1", "rendered as 1, not True -- SL1 cannot parse Python"

    @pytest.mark.anyio
    async def test_an_over_large_timeout_is_clamped_not_honoured(self) -> None:
        """The clamp lives at one site so it cannot be forgotten per caller."""
        from powerpack_mcp.config import READ_TIMEOUT_CEILING_SECONDS
        from powerpack_mcp.sl1_client.client import _clamp_timeout

        assert _clamp_timeout(10_000.0) == READ_TIMEOUT_CEILING_SECONDS
        assert _clamp_timeout(1.5) == 1.5
        assert _clamp_timeout(None) is None
        assert _clamp_timeout(0) is None, "'expire immediately' is not something a caller can want"
        assert _clamp_timeout(-5) is None


class TestDynamicAppReaders:
    """The Dynamic Application readers, the only typed REST tools, and SL1's quirks for them."""

    @pytest.mark.anyio
    async def test_the_lookup_path_is_used_not_the_bare_resource(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The list endpoint is ``dynamic_app/_lookup``, not ``dynamic_app``."""
        context, seen, _ = _ctx(config, credential, _rest_ok({}))
        await rest.make_sl1_list_dynamic_apps(context)()
        assert seen[0].url.path == "/api/dynamic_app/_lookup"

    @pytest.mark.anyio
    async def test_a_single_word_filter_is_applied_server_side(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, seen, _ = _ctx(config, credential, _rest_ok({"/api/dynamic_app/1": {"name": "a"}}))
        await rest.make_sl1_list_dynamic_apps(context)(name_contains="core")
        assert dict(seen[0].url.params)["filter.name.contains"] == "core"

    @pytest.mark.anyio
    async def test_a_phrase_pre_filters_on_the_longest_word_then_matches_here(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Server-side phrase filtering does not work on this resource.

        Matching is an order-independent AND of words, not a contiguous phrase, so
        ``"cisco interface"`` matches ``"Interface: Cisco"``.
        """
        pool = {
            "/api/dynamic_app/1": {"name": "Interface: Cisco Stats"},
            "/api/dynamic_app/2": {"name": "Interface: Juniper"},
        }
        context, seen, _ = _ctx(config, credential, _rest_ok(pool))
        result = await rest.make_sl1_list_dynamic_apps(context)(name_contains="cisco interface")
        assert dict(seen[0].url.params)["filter.name.contains"] == "interface", "the longest word"
        assert result == {"/api/dynamic_app/1": {"name": "Interface: Cisco Stats"}}

    @pytest.mark.anyio
    async def test_hitting_the_row_cap_is_reported_rather_than_looking_complete(
        self, config: Config, credential: LceCredential
    ) -> None:
        """A truncated result set must say so.

        A truncated result set is byte-indistinguishable from a complete one, so without this the
        caller receives a confident wrong answer rather than a partial one.
        """
        pool = {f"/api/dynamic_app/{i}": {"name": f"app {i}"} for i in range(3)}
        context, _, _ = _ctx(config, credential, _rest_ok(pool))
        result = await rest.make_sl1_list_dynamic_apps(context)(limit=3)
        assert isinstance(result, dict)
        assert result["truncated"] is True
        assert "narrow" in result["note"].lower()

    @pytest.mark.anyio
    async def test_an_exact_name_match_is_returned(
        self, config: Config, credential: LceCredential
    ) -> None:
        pool = {"/api/dynamic_app/1": {"name": "Cisco: CPU"}}
        context, _, _ = _ctx(config, credential, _rest_ok(pool))
        assert await rest.make_sl1_get_dynamic_app(context)(name="Cisco: CPU") == pool

    @pytest.mark.anyio
    async def test_loose_matches_are_reported_as_candidates_not_guessed_at(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Ambiguity is reported. A returned near-match would be a silent wrong answer."""
        pool = {"/api/dynamic_app/1": {"name": "Cisco: CPU Extended"}}
        context, _, _ = _ctx(config, credential, _rest_ok(pool))
        payload = await rest.make_sl1_get_dynamic_app(context)(name="Cisco: CPU")
        assert isinstance(payload, dict)
        detail = payload["error"]["details"][0]
        assert detail["rule"] == "tool_argument"
        assert "Cisco: CPU Extended" in detail["message"], "the candidates are the actionable part"

    @pytest.mark.anyio
    async def test_no_match_reports_the_cap_when_the_pool_was_truncated(
        self, config: Config, credential: LceCredential
    ) -> None:
        # A multi-word name, so the search takes the pre-filter path: the pool comes back full
        # (truncated) and nothing survives the client-side AND-of-words match. A single word would
        # be filtered server-side, which a mock transport cannot simulate.
        pool = {f"/api/dynamic_app/{i}": {"name": f"unrelated {i}"} for i in range(500)}
        context, _, _ = _ctx(config, credential, _rest_ok(pool))
        payload = await rest.make_sl1_get_dynamic_app(context)(name="zzz yyy")
        assert isinstance(payload, dict)
        assert "capped at 500" in json.dumps(payload), (
            "a truncated pool must say so: otherwise 'no match' is a confident wrong answer"
        )


class TestEntityToolsGraphQl:
    """The 14 typed GraphQL tools."""

    @pytest.mark.anyio
    async def test_a_relay_connection_is_unwrapped_to_nodes(
        self, config: Config, credential: LceCredential
    ) -> None:
        body = {"powerPacks": {"edges": [{"node": {"id": "1", "name": "PP"}}]}}
        context, _, _ = _ctx(config, credential, _gql_ok(body))
        assert await ent.make_sl1_list_powerpacks(context)() == [{"id": "1", "name": "PP"}]

    @pytest.mark.anyio
    async def test_a_missing_root_field_is_malformed_not_absent(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Returning ``None`` would tell the caller "no such object" about a broken response."""
        context, _, _ = _ctx(config, credential, _gql_ok({"somethingElse": {}}))
        with pytest.raises(Sl1MalformedResponse):
            await ent._run(context, d.LIST_POWERPACKS)

    def test_node_unwrapping_tolerates_every_null_the_shape_allows(self) -> None:
        assert ent._nodes(None) == []
        assert ent._nodes({}) == []
        assert ent._nodes({"edges": None}) == []
        assert ent._nodes({"edges": [{}, {"node": None}, {"node": {"id": "1"}}]}) == [{"id": "1"}]

    @pytest.mark.anyio
    async def test_verbose_selects_field_breadth(
        self, config: Config, credential: LceCredential
    ) -> None:
        """``verbose`` widens the fields rather than changing the query."""
        node = {"id": "1", "class": "Virtual", "description": "d", "virtualType": "virtual"}
        body = {"deviceClasses": {"edges": [{"node": node}]}}
        context, _, _ = _ctx(config, credential, _gql_ok(body))
        tool = ent.make_sl1_list_virtual_device_classes(context)
        assert await tool() == [{"id": "1", "class": "Virtual", "description": "d"}]
        assert await tool(verbose=True) == [node]

    @pytest.mark.anyio
    async def test_create_virtual_device_defaults_are_the_sources(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Only ``name`` is required; the other three inputs have defaults."""
        context, seen, _ = _ctx(config, credential, _gql_ok({"createVirtualDevice": {"id": "9"}}))
        await ent.make_sl1_create_virtual_device(context)(name="vdev")
        variables = json.loads(seen[0].content)["variables"]
        assert variables["organization"] == "0", "System"
        assert variables["collectorGroup"] == "1", "the CUG"
        assert variables["deviceClass"] == ent.VDEV_CLASS_DYNAMIC_APP_EMISSARY

    @pytest.mark.anyio
    async def test_delete_device_echoes_the_id_beside_the_boolean(
        self, config: Config, credential: LceCredential
    ) -> None:
        """A lone ``true`` gives the caller no way to confirm what was deleted."""
        context, _, _ = _ctx(config, credential, _gql_ok({"deleteDevice": True}))
        assert await ent.make_sl1_delete_device(context)(device_id="7") == {
            "deleted": True,
            "id": "7",
        }

    @pytest.mark.anyio
    async def test_the_event_policy_readers_are_read_only(
        self, config: Config, credential: LceCredential
    ) -> None:
        """No event policy create or update is exposed by these tools, deliberately."""
        exported = set(ent.__all__)
        assert not {n for n in exported if "event_polic" in n and ("create" in n or "update" in n)}
        body = {"eventPolicies": {"edges": [{"node": {"id": "3"}}]}}
        context, _, _ = _ctx(config, credential, _gql_ok(body))
        assert await ent.make_sl1_list_event_policies(context)() == [{"id": "3"}]


class TestCredentialTools:
    """The credential tools, including replace's delete-then-recreate ordering."""

    def test_the_definition_is_completed_from_sl1s_full_shape(self) -> None:
        merged = normalize_universal_definition({"url": "https://example"})
        assert merged["url"] == "https://example"
        assert set(merged) == set(UNIVERSAL_DEFINITION_DEFAULTS), "no key may be dropped"

    def test_booleans_are_coerced_and_the_selector_is_never_empty(self) -> None:
        merged = normalize_universal_definition(
            {"proxy": "yes", "sslverifypeer": 1, "tokenExpiresInSelector": ""}
        )
        assert merged["proxy"] is True
        assert merged["sslverifypeer"] is True
        assert merged["tokenExpiresInSelector"] == "expires_in", (
            "required even under static refresh"
        )

    @pytest.mark.parametrize("key", CRED_SECRET_KEYS)
    def test_a_buffer_read_wrapper_is_rejected_rather_than_stringified(self, key: str) -> None:
        """Rejected, not coerced.

        ``str()`` of ``{"type": "Buffer", ...}`` would store that literal text as the password. SL1
        accepts it, and the credential then fails at collection time, far from the cause.
        """
        with pytest.raises(UniversalDefinitionError, match=key):
            normalize_universal_definition({key: {"type": "Buffer", "data": [1, 2]}})

    def test_the_error_names_the_key_and_not_the_value(self) -> None:
        """Secret values are never echoed, and this field was just identified as secret."""
        with pytest.raises(UniversalDefinitionError) as caught:
            normalize_universal_definition({"password": {"type": "Buffer", "data": [115, 101]}})
        assert "115" not in str(caught.value)

    def test_the_definition_is_serialised_as_a_json_string(self) -> None:
        """SL1's ``$definition: JSON`` argument takes a string, not an object."""
        rendered = serialize_universal_definition({"url": "https://x"})
        assert isinstance(rendered, str)
        assert json.loads(rendered)["url"] == "https://x"

    # ---- The defaults table is REST v104's shape, not UNIVERSAL's ----
    #
    # Merging ``UNIVERSAL_DEFINITION_DEFAULTS`` into another subtype's definition makes SL1 reject
    # it, for example for ``aws assume role``:
    #
    #     ValidationError: "value" failed custom validation because "authType" is not allowed
    #
    # The same definition sent unmodified through ``createCredential`` is accepted, so the
    # defaults may only be applied to REST v104.

    def test_the_rest_subtype_is_completed_when_it_is_named_explicitly_too(self) -> None:
        """Completion also applies when the REST v104 subtype is named explicitly.

        ``test_the_definition_is_completed_from_sl1s_full_shape`` covers the omitted subtype. This
        covers what the create tool passes, so the two ways of asking for REST v104 cannot drift.
        """
        merged = normalize_universal_definition({"url": "https://example"}, CRED_SUBTYPE_REST_V104)
        assert set(merged) == set(UNIVERSAL_DEFINITION_DEFAULTS), "no key may be dropped"
        assert merged["url"] == "https://example"
        assert merged["authType"] == "AuthToken", "the REST subtype still gets its own default"

    def test_another_subtypes_definition_is_passed_through_key_for_key(self) -> None:
        """Another subtype's definition is neither completed nor coerced.

        The defaults table is REST v104's field list, and SL1 rejects those fields on a subtype
        that does not have them. ``proxy`` stays a string because bool-coercing it is a fact about
        the REST field; rewriting a value in an unknown subtype would be accepted by SL1 and
        mis-stored, surfacing at collection time instead of here.
        """
        definition: dict[str, Any] = {
            "awsAccountId": "1",
            "roleName": "r",
            "proxy": "leave-me-alone",
            "unmeasuredFlag": 0,
        }
        assert normalize_universal_definition(definition, _AWS_ASSUME_ROLE) == definition

    def test_the_rest_only_auth_type_key_is_never_injected_into_another_subtype(self) -> None:
        """The key SL1's ``ValidationError`` named, asserted on its own.

        The pass-through test above would survive an edit that injected a default and loosened the
        comparison. ``url`` is included because it is the default most likely to look harmless.
        """
        shaped = normalize_universal_definition({"awsAccountId": "1"}, _AWS_ASSUME_ROLE)
        assert "authType" not in shaped
        assert "url" not in shaped
        assert set(shaped) == {"awsAccountId"}, "not one key more than was supplied"

    def test_the_subtype_gate_tolerates_a_case_or_whitespace_slip(self) -> None:
        """``_is_rest_v104`` matches loosely, unlike the read allowlist.

        ``_DEFINITION_ALLOWLIST`` matches exactly because a loose match there could admit a
        re-cased secret. Here a loose match admits the completion, and the alternative is quietly
        sending a partial definition. The caller's own spelling is what gets sent.
        """
        merged = normalize_universal_definition({}, "  low-code tools: rest v104 ")
        assert set(merged) == set(UNIVERSAL_DEFINITION_DEFAULTS)

    @pytest.mark.parametrize("key", CRED_SECRET_KEYS)
    def test_a_buffer_wrapper_is_rejected_on_another_subtype_as_well(self, key: str) -> None:
        """The Buffer rejection holds on the pass-through path too.

        It catches SL1's read shape being fed back as a write, which is how SL1 renders secrets on
        the way out, not a fact about one subtype's field list.
        """
        with pytest.raises(UniversalDefinitionError, match=key):
            normalize_universal_definition(
                {key: {"type": "Buffer", "data": [1, 2]}}, _AWS_ASSUME_ROLE
            )

    def test_a_buffer_wrapper_is_rejected_on_a_key_the_secret_tuple_does_not_name(self) -> None:
        """``CRED_SECRET_KEYS`` is REST v104's list, so on another subtype it names nothing.

        A non-REST subtype's secret field has some other name, so the rejection matches the read
        shape rather than the key. The message still must not echo the value.
        """
        with pytest.raises(UniversalDefinitionError, match="awsSecretAccessKey") as caught:
            normalize_universal_definition(
                {"awsSecretAccessKey": {"type": "Buffer", "data": [115, 101]}}, _AWS_ASSUME_ROLE
            )
        assert "115" not in str(caught.value)

    def test_a_nested_object_that_is_not_a_read_shape_still_passes_through(self) -> None:
        """The shape match is narrow on purpose: an unmeasured subtype may nest a real object.

        Refusing every dict outside ``CRED_SECRET_KEYS`` would refuse definitions SL1 accepts.
        """
        definition: dict[str, Any] = {"assumeRole": {"arn": "a", "externalId": "b"}}
        assert normalize_universal_definition(definition, _AWS_ASSUME_ROLE) == definition

    def test_pass_through_stringifies_a_supplied_secret_and_invents_no_absent_one(self) -> None:
        """A supplied secret is stored as a plain string, and absent REST secret keys are not added.

        A key not known for this subtype must not appear, empty or otherwise.
        """
        assert normalize_universal_definition({"apikey": 1234}, _AWS_ASSUME_ROLE) == {
            "apikey": "1234"
        }

    @pytest.mark.anyio
    async def test_create_sends_another_subtype_without_the_rest_defaults(
        self, config: Config, credential: LceCredential
    ) -> None:
        """End to end, ``subType`` and ``definition`` must agree.

        Testing the normaliser alone would miss the tool sending ``subType: "aws assume role"``
        alongside a REST-shaped definition, which SL1 rejects.
        """
        context, seen, _ = _ctx(config, credential, _gql_ok({"createCredential": {"guid": "G1"}}))
        await ent.make_sl1_create_universal_credential(context)(
            name="c", definition={"awsAccountId": "1"}, sub_type=_AWS_ASSUME_ROLE
        )
        variables = json.loads(seen[0].content)["variables"]
        assert variables["subType"] == _AWS_ASSUME_ROLE
        sent = json.loads(variables["definition"])
        assert "authType" not in sent, "the key SL1's ValidationError named"
        assert sent == {"awsAccountId": "1"}

    @pytest.mark.anyio
    async def test_replace_recreates_with_the_subtype_it_was_given(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Replace's recreate is a create, so it has the same subtype pairing.

        Replace also shapes the definition before the delete, and that pre-check has to take the
        same branch as the write. Otherwise a definition could be refused after the credential was
        already deleted.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            if "deleteCredential" in json.loads(request.content)["query"]:
                return httpx.Response(200, json={"data": {"deleteCredential": True}})
            return httpx.Response(200, json={"data": {"createCredential": {"guid": "NEW"}}})

        context, seen, _ = _ctx(config, credential, handler)
        await ent.make_sl1_replace_universal_credential(context)(
            guid="OLD", name="c", definition={"awsAccountId": "1"}, sub_type=_AWS_ASSUME_ROLE
        )
        variables = json.loads(seen[1].content)["variables"]
        assert variables["subType"] == _AWS_ASSUME_ROLE
        assert json.loads(variables["definition"]) == {"awsAccountId": "1"}

    @pytest.mark.anyio
    async def test_update_passes_a_supplied_subtype_through_to_the_normalisation(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The complement of ``test_updates_definition_is_completed_from_sl1s_full_shape...``.

        Omitting ``sub_type`` on an update still completes from the REST defaults. Supplying it is
        the only way an update can touch a non-REST credential's definition, which is why the
        tool's Args entry says to pass it.
        """
        context, seen, _ = _ctx(config, credential, _gql_ok({"updateCredential": {"guid": "G"}}))
        await ent.make_sl1_update_universal_credential(context)(
            guid="G", definition={"awsAccountId": "1"}, sub_type=_AWS_ASSUME_ROLE
        )
        variables = json.loads(seen[0].content)["variables"]
        assert variables["subType"] == _AWS_ASSUME_ROLE
        assert json.loads(variables["definition"]) == {"awsAccountId": "1"}

    @pytest.mark.anyio
    async def test_create_sends_the_stringified_definition_and_the_enum_type(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, seen, _ = _ctx(config, credential, _gql_ok({"createCredential": {"guid": "G1"}}))
        await ent.make_sl1_create_universal_credential(context)(
            name="c", definition={"url": "https://x"}
        )
        variables = json.loads(seen[0].content)["variables"]
        assert variables["type"] == "UNIVERSAL"
        assert isinstance(variables["definition"], str)
        assert variables["alignedOrganizations"] == [0], "the source's default, not an empty list"

    @pytest.mark.anyio
    async def test_update_sends_only_what_was_supplied(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Built by presence: an explicit ``False`` or ``0`` must not be dropped as "falsy"."""
        context, seen, _ = _ctx(config, credential, _gql_ok({"updateCredential": {"guid": "G"}}))
        await ent.make_sl1_update_universal_credential(context)(
            guid="G", timeout=0, all_organizations=False
        )
        variables = json.loads(seen[0].content)["variables"]
        assert variables == {"guid": "G", "timeout": 0, "allOrganizations": False}
        assert "definition" not in variables

    @pytest.mark.anyio
    async def test_the_update_resolver_crash_becomes_guidance_naming_replace(
        self, config: Config, credential: LceCredential
    ) -> None:
        """SL1's update resolver crash, a raw JavaScript ``TypeError``, becomes actionable guidance.

        The caller must learn two things SL1's message does not say: that nothing was modified, so
        there is no half-written credential to repair, and which tool does work.
        """
        crash = {
            "errors": [{"message": "Cannot read properties of undefined (reading 'reduce')"}],
            "data": None,
        }
        # Not ``_gql_ok``: that nests its argument under ``data``, and ``errors`` must be top level
        # for ``Sl1Client.graphql`` to raise at all. Otherwise this would pass on a
        # malformed-response error.
        context, _, _ = _ctx(config, credential, lambda _r: httpx.Response(200, json=crash))
        payload = await ent.make_sl1_update_universal_credential(context)(guid="G", name="n")
        assert isinstance(payload, dict)
        # The guidance surfaces under ``graphql_errors``, not ``error.message``: the boundary
        # renders one fixed sentence per error type and carries SL1's per-entry text separately.
        (reported,) = payload["error"]["graphql_errors"]
        assert "known SL1-side defect" in reported
        assert "byte-for-byte unchanged" in reported
        assert "sl1_replace_universal_credential" in reported
        assert "changes the GUID" in reported, "the replace caveat travels with the suggestion"
        assert len(reported) < 2048, "under MAX_LCE_BODY_CHARS, so the constructor cannot truncate"

    @pytest.mark.anyio
    async def test_an_unrelated_graphql_error_is_not_rewritten_by_the_crash_mapper(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The mapper matches narrowly, so a permission denial still reads as one.

        A broad ``except`` here would tell a caller lacking rights to use the destructive tool
        instead, which would fail the same way.
        """
        denial = {
            "errors": [
                {
                    "message": "User does not have required permissions.",
                    "extensions": {"code": SL1_RESTRICTED_ACCESS_CODE},
                }
            ]
        }
        context, _, _ = _ctx(config, credential, lambda _r: httpx.Response(200, json=denial))
        payload = await ent.make_sl1_update_universal_credential(context)(guid="G", name="n")
        assert isinstance(payload, dict)
        assert payload["error"]["graphql_errors"] == ["User does not have required permissions."]
        assert payload["error"]["graphql_error_codes"] == [SL1_RESTRICTED_ACCESS_CODE]

    def test_the_crash_mapper_rewrites_one_entry_and_keeps_the_codes_aligned(self) -> None:
        """Only the matching message changes, and the tuple length is preserved.

        ``Sl1GraphQlError.codes`` is positional with ``messages``, so appending rather than
        replacing would shift every later code onto the wrong message.
        """
        exc = Sl1GraphQlError(
            ["harmless", "Cannot read properties of undefined (reading 'reduce')", "also harmless"],
            ["", "", SL1_RESTRICTED_ACCESS_CODE],
        )
        mapped = ent._mapped_update_crash(exc)
        assert mapped is not exc
        assert len(mapped.messages) == len(exc.messages) == len(mapped.codes)
        assert mapped.messages[0] == "harmless"
        assert mapped.messages[2] == "also harmless"
        assert "known SL1-side defect" in mapped.messages[1]
        assert mapped.codes == exc.codes, "alignment preserved"

    def test_the_crash_mapper_returns_the_same_object_when_nothing_matches(self) -> None:
        """Identity, not equality: the tool branches on ``is`` to decide whether to bare-``raise``,
        which preserves the original traceback for every unrelated error."""
        exc = Sl1GraphQlError(["something else entirely"], [""])
        assert ent._mapped_update_crash(exc) is exc

    @pytest.mark.anyio
    async def test_replace_aborts_the_recreate_when_the_delete_fails(
        self, config: Config, credential: LceCredential
    ) -> None:
        """A failed delete stops the replace before the create.

        A create issued after a failed delete leaves two credentials where the caller asked for
        one, which is worse than the edit not happening.
        """
        context, seen, _ = _ctx(config, credential, _gql_ok({"deleteCredential": False}))
        payload = await ent.make_sl1_replace_universal_credential(context)(
            guid="G", name="c", definition={}
        )
        assert isinstance(payload, dict)
        assert payload["recreated"] is None
        assert len(seen) == 1, "only the delete was issued"

    @pytest.mark.anyio
    async def test_replace_returns_the_new_guid_and_warns_about_alignments(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Dynamic Apps align by credential GUID, so the new GUID comes with a warning."""
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            if "deleteCredential" in body["query"]:
                calls.append("delete")
                return httpx.Response(200, json={"data": {"deleteCredential": True}})
            calls.append("create")
            return httpx.Response(200, json={"data": {"createCredential": {"guid": "NEW"}}})

        context, _, _ = _ctx(config, credential, handler)
        payload = await ent.make_sl1_replace_universal_credential(context)(
            guid="OLD", name="c", definition={}
        )
        assert calls == ["delete", "create"], "delete first, and only then create"
        assert isinstance(payload, dict)
        assert payload["deleted_guid"] == "OLD"
        assert payload["recreated"]["guid"] == "NEW"
        assert "OLD" in payload["warning"]
        assert "re-pointed" in payload["warning"]

    @pytest.mark.anyio
    async def test_delete_sends_only_the_guid_and_echoes_it_back(
        self, config: Config, credential: LceCredential
    ) -> None:
        """``sl1_delete_credential`` invoked directly.

        The signature sweeps build the closure without invoking it, and replace covers only the
        mutation, so this is the one test of the destructive tool's own body.
        """
        context, seen, _ = _ctx(config, credential, _gql_ok({"deleteCredential": True}))
        payload = await ent.make_sl1_delete_credential(context)(guid="G")
        assert json.loads(seen[0].content)["variables"] == {"guid": "G"}
        assert payload == {"deleted": True, "guid": "G"}

    @pytest.mark.anyio
    async def test_delete_reports_a_refused_delete_as_false_rather_than_raising(
        self, config: Config, credential: LceCredential
    ) -> None:
        """``bool(deleted)`` is load-bearing.

        SL1 answers ``deleteCredential`` with a boolean, so a refused delete is a 200 carrying
        ``false``, not an error. ``sl1_replace_universal_credential`` reads this value to decide
        whether to abort its recreate; a truthy payload here would make replace delete nothing and
        then create a duplicate.
        """
        context, _, _ = _ctx(config, credential, _gql_ok({"deleteCredential": False}))
        payload = await ent.make_sl1_delete_credential(context)(guid="G")
        assert payload == {"deleted": False, "guid": "G"}

    @pytest.mark.anyio
    async def test_update_sends_every_field_it_was_given(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The four presence branches ``test_update_sends_only_what_was_supplied`` never takes.

        These are ``name``, ``subType``, ``alignedOrganizations`` and ``definition``, the last
        being the one line on the update path that touches secret material.
        """
        context, seen, _ = _ctx(config, credential, _gql_ok({"updateCredential": {"guid": "G"}}))
        await ent.make_sl1_update_universal_credential(context)(
            guid="G",
            name="renamed",
            sub_type=CRED_SUBTYPE_REST_V104,
            aligned_organizations=[0, 7],
            definition={"url": "https://x"},
        )
        variables = json.loads(seen[0].content)["variables"]
        assert variables["name"] == "renamed"
        assert variables["subType"] == CRED_SUBTYPE_REST_V104
        assert variables["alignedOrganizations"] == [0, 7]
        assert isinstance(variables["definition"], str), "stringified scalar, exactly as on create"

    @pytest.mark.anyio
    async def test_updates_definition_is_completed_from_sl1s_full_shape_as_on_create(
        self, config: Config, credential: LceCredential
    ) -> None:
        """A partial definition is completed on the update path too, exactly as on create.

        An update that sent the caller's one key alone would be rejected or silently mis-stored
        by SL1, and the failure would surface only on an appliance.
        """
        context, seen, _ = _ctx(
            config,
            credential,
            _sequence(
                [
                    {"credential": {"guid": "G", "subType": CRED_SUBTYPE_REST_V104}},
                    {"updateCredential": {"guid": "G"}},
                ]
            ),
        )
        await ent.make_sl1_update_universal_credential(context)(
            guid="G", definition={"url": "https://x"}
        )
        # ``seen[1]``, not ``seen[0]``: the update reads the stored subtype first so it can
        # normalise against the right shape, so the write is the second request.
        assert len(seen) == 2, "one read for the stored subtype, then the write"
        sent = json.loads(json.loads(seen[1].content)["variables"]["definition"])
        assert set(sent) == set(UNIVERSAL_DEFINITION_DEFAULTS), "completed, not passed through"
        assert sent["url"] == "https://x"

    @pytest.mark.anyio
    async def test_a_non_rest_credentials_definition_is_not_given_rest_keys(
        self, config: Config, credential: LceCredential
    ) -> None:
        """An update of a non-REST credential sends its definition unchanged.

        An update carries no subtype, so the stored subtype is read first. Defaulting to REST v104
        would inject ``authType``, which SL1 rejects ("authType is not allowed"). The caller does
        not have to restate a subtype they are not changing.
        """
        aws = "aws assume role"
        context, seen, _ = _ctx(
            config,
            credential,
            _sequence(
                [
                    {"credential": {"guid": "G", "subType": aws}},
                    {"updateCredential": {"guid": "G"}},
                ]
            ),
        )
        await ent.make_sl1_update_universal_credential(context)(
            guid="G", definition={"AwsAccessKeyId": "ZZTESTONLYNOTREAL000"}
        )
        assert len(seen) == 2
        read = json.loads(seen[0].content)
        assert "GetCredential" in read["query"], "the first call must be the subtype read"
        sent = json.loads(json.loads(seen[1].content)["variables"]["definition"])
        assert sent == {"AwsAccessKeyId": "ZZTESTONLYNOTREAL000"}, (
            f"a non-REST definition must pass through unchanged, got {sorted(sent)}"
        )
        assert "authType" not in sent, "the exact key SL1 rejected"

    @pytest.mark.anyio
    async def test_an_explicit_sub_type_wins_over_the_stored_one(
        self, config: Config, credential: LceCredential
    ) -> None:
        """No read at all when the caller supplies ``sub_type``.

        A caller passing ``sub_type`` is changing it, so the definition is shaped for the new
        subtype. Reading the old value would normalise against the shape being replaced.
        """
        context, seen, _ = _ctx(config, credential, _gql_ok({"updateCredential": {"guid": "G"}}))
        await ent.make_sl1_update_universal_credential(context)(
            guid="G",
            definition={"AwsAccessKeyId": "ZZTESTONLYNOTREAL000"},
            sub_type="aws assume role",
        )
        assert len(seen) == 1, "an explicit sub_type must not trigger a read"
        sent = json.loads(json.loads(seen[0].content)["variables"]["definition"])
        assert "authType" not in sent

    @pytest.mark.anyio
    async def test_a_credential_read_that_returns_no_object_stops_the_update(
        self, config: Config, credential: LceCredential
    ) -> None:
        """A failed subtype read is not swallowed, and the write does not proceed.

        The GUID is probably wrong, and "no such credential" is a more useful answer than SL1
        rejecting REST keys. Falling back to the REST defaults on a failed read would bring back
        the ``authType`` rejection for non-REST credentials.
        """
        context, seen, _ = _ctx(config, credential, _gql_ok({"credential": None}))
        payload = await ent.make_sl1_update_universal_credential(context)(
            guid="MISSING", definition={"url": "https://x"}
        )
        assert isinstance(payload, dict)
        assert "error" in payload, f"expected a structured error, got {payload}"
        assert len(seen) == 1, "the write must not be issued after a failed read"

    @pytest.mark.anyio
    async def test_no_definition_means_no_read(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The read is on the definition path only; renaming a credential must not cost a call."""
        context, seen, _ = _ctx(config, credential, _gql_ok({"updateCredential": {"guid": "G"}}))
        await ent.make_sl1_update_universal_credential(context)(guid="G", name="renamed")
        assert len(seen) == 1, "no definition supplied, so nothing to normalise and nothing to read"

    def test_the_defaults_table_is_pinned_key_for_key(self) -> None:
        """A literal key set, because the completion test cannot catch a trimmed table.

        ``test_the_definition_is_completed_from_sl1s_full_shape`` reads the table on both sides,
        so deleting a key still passes. A key omitted from the table is a defect that only appears
        on an appliance, since SL1 rejects or silently mis-stores a partial definition. A
        deliberate change to SL1's shape means editing the list below, visibly in review.
        """
        assert set(UNIVERSAL_DEFINITION_DEFAULTS) == {
            "apikey",
            "authEndpoint",
            "authHeader",
            "authOverride",
            "authType",
            "ca_path",
            "debug",
            "httpHeader1",
            "httpHeader2",
            "httpHeaders",
            "oauth2AuthType",
            "oauth2ClientCredentialsScope",
            "oauth2ClientId",
            "oauth2ClientSecret",
            "oauth2ResourceOwnerAdditionalParams",
            "oauth2ResourceOwnerPassword",
            "oauth2ResourceOwnerScope",
            "oauth2ResourceOwnerUsername",
            "oauth2TokenFormat",
            "oauth2TokenKey",
            "oauth2TokenLabel",
            "oauth2TokenURL",
            "oauth2Type",
            "opts",
            "password",
            "prefix",
            "proxy",
            "proxyHost",
            "proxyPasswd",
            "proxyPort",
            "proxyUser",
            "proxy_scheme",
            "sslverifypeer",
            "suffix",
            "timeToNextRequest",
            "tokenAuthRefresh",
            "tokenExpiresInSelector",
            "tokenFormat",
            "tokenKey",
            "tokenRefreshTTL",
            "url",
            "username",
        }

    def test_every_secret_key_is_a_key_of_the_table_it_guards(self) -> None:
        """``CRED_SECRET_KEYS`` names fields that must actually exist to be checked.

        A mistyped or renamed entry would make the Buffer-wrapper rejection silently vacuous for
        that field, and the parametrised rejection test would still pass because it supplies the
        key itself.
        """
        assert set(CRED_SECRET_KEYS) <= set(UNIVERSAL_DEFINITION_DEFAULTS)

    @pytest.mark.anyio
    async def test_a_failing_transport_gives_a_writer_an_envelope_and_no_secret(
        self, config: Config, credential: LceCredential
    ) -> None:
        """A credential writer returns an error envelope that does not contain the secret.

        The failing-transport path is where a tool that has just received a secret builds a
        caller-facing string.
        """
        context, _, _ = _ctx(config, credential, lambda _r: httpx.Response(404, json={"e": 1}))
        payload = await ent.make_sl1_create_universal_credential(context)(
            name="c", definition={"password": _WRITER_CANARY}
        )
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "sl1_http_error"
        assert _WRITER_CANARY not in json.dumps(payload)

    @pytest.mark.anyio
    async def test_a_buffer_wrapper_reaches_the_caller_as_a_refusal_envelope(
        self, config: Config, credential: LceCredential
    ) -> None:
        """``UniversalDefinitionError`` is translated into a refusal envelope.

        The class subclasses ``ValueError``, and ``sl1_tool_boundary`` catches only
        ``ValidationBlocked`` and ``PowerPackMcpError`` with no catch-all, so without
        ``_definition_argument``'s translation the caller would get a framework-level error.
        """
        context, seen, _ = _ctx(config, credential, _gql_ok({"createCredential": {"guid": "G"}}))
        payload = await ent.make_sl1_create_universal_credential(context)(
            name="c", definition={"password": {"type": "Buffer", "data": [115, 101]}}
        )
        assert seen == [], "the request must never be issued"
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"
        detail = payload["error"]["details"][0]
        assert detail["rule"] == "tool_argument"
        assert detail["path"] == "definition"
        # The key is named so the mistake is fixable, but the bytes of the wrapped value are not
        # echoed, because ``str()`` of a Buffer wrapper carries them.
        assert "password" in json.dumps(payload)
        assert "115" not in json.dumps(payload)

    @pytest.mark.anyio
    async def test_replace_refuses_a_bad_definition_before_it_deletes_anything(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Replace validates the definition before it deletes anything.

        ``_credential_write`` serialises the definition after the delete has succeeded, so without
        the pre-check a Buffer-wrapped secret would delete the credential and only then fail. Two
        credentials can be reconciled and a deleted one cannot, so no request of any kind may be
        made.
        """
        context, seen, _ = _ctx(config, credential, _gql_ok({"deleteCredential": True}))
        payload = await ent.make_sl1_replace_universal_credential(context)(
            guid="G", name="c", definition={"apikey": {"type": "Buffer", "data": [1, 2]}}
        )
        assert seen == [], "not even the delete may be issued"
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"


class TestCredentialWritersAndTheirSecretInput:
    """``carries_secret_input`` and the never-log rule it documents.

    The flag is documentary. The guarantee is that ``sl1_tool_boundary`` never logs arguments for
    any tool, because a per-tool allowlist would fail by silently disclosing secrets. The readers'
    flag is covered in ``test_credential_definition_filter.py``; these cover the writers.
    """

    def test_every_writer_that_receives_a_definition_declares_it(self) -> None:
        for descriptor in (
            d.CREATE_UNIVERSAL_CREDENTIAL,
            d.UPDATE_UNIVERSAL_CREDENTIAL,
            d.REPLACE_UNIVERSAL_CREDENTIAL,
        ):
            assert descriptor.carries_secret_input is True, descriptor.tool_name

    def test_delete_does_not_claim_to_carry_a_secret(self) -> None:
        """A GUID is not secret material, and a flag that is true everywhere says nothing.

        The set stays exactly the tools that take a ``definition``. Delete is the tool most likely
        to be edited alongside the three that do.
        """
        assert d.DELETE_CREDENTIAL.carries_secret_input is False

    @pytest.mark.anyio
    async def test_a_writers_arguments_never_reach_the_logs_on_either_path(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The never-log guarantee itself, on both the success and the failure path.

        The failure path builds a caller-facing string from a call whose arguments held a secret,
        and takes a different branch of ``sl1_tool_boundary``, so each path needs checking.
        """
        for handler, level in (
            (_gql_ok({"createCredential": {"guid": "G"}}), logging.INFO),
            (lambda _r: httpx.Response(404, json={"e": 1}), logging.WARNING),
        ):
            caplog.clear()
            context, _, _ = _ctx(config, credential, handler)
            with caplog.at_level(level):
                await ent.make_sl1_create_universal_credential(context)(
                    name="c", definition={"password": _WRITER_CANARY}
                )
            records = [r for r in caplog.records if getattr(r, "tool", None) is not None]
            assert records, "the boundary must log something, or this asserts nothing"
            for record in records:
                assert _WRITER_CANARY not in record.getMessage()
                assert _WRITER_CANARY not in json.dumps(record.__dict__, default=repr)


class TestAlignmentAndGuidResolution:
    """The two alignment tools, which use both SL1 and LCE."""

    @pytest.mark.anyio
    async def test_a_guid_is_used_directly_with_no_lce_call(
        self, config: Config, credential: LceCredential
    ) -> None:
        guid = "A1B2C3D4E5F6789012345678901234AB"
        context, sl1_seen, lce_seen = _ctx(
            config, credential, _gql_ok({"alignDynamicApplicationsToDevice": {"id": "1"}})
        )
        await ent.make_sl1_align_dynamic_apps_to_device(context)(
            device_id="7", credential_guid="C", dynamic_apps=[guid]
        )
        assert lce_seen == [], "an identifier already a guid needs no resolution"
        assert json.loads(sl1_seen[0].content)["variables"]["dynamicApplications"] == [guid]

    @pytest.mark.anyio
    async def test_a_lowercase_guid_is_still_recognised_as_a_guid(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Routing is case-insensitive; validation is not.

        Reusing ``CHILD_GUID_PATTERN`` (uppercase-only, for LCE validation) would send this string
        to LCE as a name, find nothing, and report "could not resolve a guid" about a GUID.
        """
        lower = "a1b2c3d4e5f6789012345678901234ab"
        context, sl1_seen, lce_seen = _ctx(
            config, credential, _gql_ok({"unalignDynamicApplicationsFromDevice": {"id": "1"}})
        )
        await ent.make_sl1_unalign_dynamic_apps_from_device(context)(
            device_id="7", dynamic_apps=[lower]
        )
        assert lce_seen == []
        assert json.loads(sl1_seen[0].content)["variables"]["dynamicApplications"] == [lower]

    @pytest.mark.anyio
    async def test_a_name_is_resolved_through_lce_first(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, sl1_seen, lce_seen = _ctx(
            config,
            credential,
            _gql_ok({"alignDynamicApplicationsToDevice": {"id": "1"}}),
            lce_handler=lambda _r: httpx.Response(
                200, json={"dynamic_application": {"guid": "RESOLVED", "name": "n"}}
            ),
        )
        await ent.make_sl1_align_dynamic_apps_to_device(context)(
            device_id="7", credential_guid="C", dynamic_apps=["Cisco: CPU"]
        )
        assert len(lce_seen) == 1
        assert dict(lce_seen[0].url.params) == {"fields": "guid,id,name"}
        assert json.loads(sl1_seen[0].content)["variables"]["dynamicApplications"] == ["RESOLVED"]

    @pytest.mark.anyio
    async def test_a_bare_document_shape_is_also_accepted(
        self, config: Config, credential: LceCredential
    ) -> None:
        """LCE wraps a single object under its singular key on some paths and not others."""
        context, _, _ = _ctx(
            config,
            credential,
            _gql_ok({"unalignDynamicApplicationsFromDevice": {}}),
            lce_handler=lambda _r: httpx.Response(200, json={"guid": "BARE"}),
        )
        assert await ent._resolve_dynamic_app_guid(context, "some-name") == "BARE"

    @pytest.mark.anyio
    async def test_an_unresolvable_identifier_names_itself(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Echoed because it is the caller's own and not secret, and a batch failure needs it."""
        context, _, _ = _ctx(
            config,
            credential,
            _gql_ok({}),
            lce_handler=lambda _r: httpx.Response(200, json={"dynamic_application": {}}),
        )
        # ``ValidationBlocked``, so the boundary can translate it into an envelope.
        with pytest.raises(ValidationBlocked) as caught:
            await ent._resolve_dynamic_app_guid(context, "Cisco: CPU")
        assert "Cisco: CPU" in caught.value.findings[0].message
        assert caught.value.findings[0].rule is FindingCode.TOOL_ARGUMENT

    @pytest.mark.anyio
    async def test_an_empty_insert_becomes_a_device_class_explanation(
        self, config: Config, credential: LceCredential
    ) -> None:
        """SL1 reports "nothing inserted" as a raw MySQL fragment an agent cannot act on."""
        marker = ent._EMPTY_INSERT_MARKER

        def handler(_r: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"errors": [{"message": f"boom {marker} boom"}]})

        context, _, _ = _ctx(config, credential, handler)
        payload = await ent.make_sl1_align_dynamic_apps_to_device(context)(
            device_id="7", credential_guid="C", dynamic_apps=["A" * 32]
        )
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"
        assert "device class" in payload["error"]["details"][0]["message"]

    @pytest.mark.anyio
    async def test_an_unrelated_graphql_error_is_not_swallowed(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The marker match must not become a catch-all for every alignment failure."""

        def handler(_r: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"errors": [{"message": "unrelated failure"}]})

        context, _, _ = _ctx(config, credential, handler)
        payload = await ent.make_sl1_align_dynamic_apps_to_device(context)(
            device_id="7", credential_guid="C", dynamic_apps=["A" * 32]
        )
        assert json.loads(json.dumps(payload))["error"]["type"] == "sl1_graphql_error"


class TestGraphQlPassthroughs:
    """The GraphQL passthrough tools."""

    @pytest.mark.anyio
    async def test_a_query_is_posted_to_gql_with_the_operation_name(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, seen, _ = _ctx(config, credential, _gql_ok({"x": 1}))
        await gql.make_sl1_graphql(context)(query="{x}", operation_name="Op", variables={"v": 1})
        assert seen[0].url.path == "/gql"
        envelope = json.loads(seen[0].content)
        assert envelope["operationName"] == "Op"
        assert envelope["variables"] == {"v": 1}

    @pytest.mark.anyio
    async def test_the_operation_name_is_omitted_when_absent(
        self, config: Config, credential: LceCredential
    ) -> None:
        """A single-operation document with ``operationName: null`` is rejected by some servers."""
        context, seen, _ = _ctx(config, credential, _gql_ok({"x": 1}))
        await gql.make_sl1_graphql(context)(query="{x}")
        assert "operationName" not in json.loads(seen[0].content)

    @pytest.mark.anyio
    async def test_a_passthrough_is_audited_without_its_document(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The call is audited, but the document stays out of the log: it may carry secrets."""
        context, _, _ = _ctx(config, credential, _gql_ok({"x": 1}))
        with caplog.at_level(logging.INFO):
            await gql.make_sl1_graphql(context)(
                query="{secretShapedQuery}", variables={"password": "hunter2"}
            )
        audit = next(
            r
            for r in caplog.records
            if getattr(r, "event", None) == LogEvent.SL1_PASSTHROUGH_INVOKED
        )
        assert _extra(audit, "sl1_path") == "/gql"
        rendered = json.dumps({k: str(v) for k, v in audit.__dict__.items()})
        assert "hunter2" not in rendered
        assert "secretShapedQuery" not in rendered

    @pytest.mark.anyio
    async def test_introspect_describes_one_type(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, seen, _ = _ctx(config, credential, _gql_ok({"__type": {"name": "Device"}}))
        result = await gql.make_sl1_graphql_introspect(context)(type_name="Device")
        assert result == {"__type": {"name": "Device"}}
        assert json.loads(seen[0].content)["variables"] == {"name": "Device"}

    @pytest.mark.anyio
    async def test_introspect_search_filters_type_names(
        self, config: Config, credential: LceCredential, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(gql, "_type_names_cache", None)
        types = [{"name": "Device"}, {"name": "DeviceClass"}, {"name": "Organization"}]
        context, seen, _ = _ctx(config, credential, _gql_ok({"__schema": {"types": types}}))
        result = await gql.make_sl1_graphql_introspect(context)(search="device")
        assert result == {"count": 2, "matches": ["Device", "DeviceClass"]}
        # The cache means a second search issues no further request.
        await gql.make_sl1_graphql_introspect(context)(search="organ")
        assert len(seen) == 1, "the type list is fetched once per process"

    @pytest.mark.anyio
    async def test_introspect_default_summarises_with_counts_and_a_preview(
        self, config: Config, credential: LceCredential
    ) -> None:
        schema = {
            "__schema": {
                "queryType": {"fields": [{"name": f"q{i:03d}"} for i in range(30)]},
                "mutationType": {"fields": [{"name": "mA"}, {"name": "mB"}]},
            }
        }
        context, _, _ = _ctx(config, credential, _gql_ok(schema))
        result = await gql.make_sl1_graphql_introspect(context)()
        assert isinstance(result, dict)
        assert result["query_count"] == 30
        assert result["mutation_count"] == 2
        assert len(result["query_preview"]) == gql._ROOT_PREVIEW_COUNT
        assert result["query_preview"][0] == "q000", "alphabetical"

    @pytest.mark.anyio
    async def test_list_all_returns_the_uncapped_root_surface_with_stability(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Each field carries ``stability`` instead of SL1's boilerplate deprecation reason."""
        body = {
            "__schema": {
                "queryType": {
                    "fields": [
                        {"name": "q", "description": "d"},
                        {
                            "name": "guidedDiscoverySession",
                            "description": "d",
                            "isDeprecated": True,
                            "deprecationReason": "Experimental. Still under active development.",
                        },
                    ]
                }
            }
        }
        context, _, _ = _ctx(config, credential, _gql_ok(body))
        result = await gql.make_sl1_graphql_introspect(context)(list_all=True)
        assert isinstance(result, dict)
        listed = result["__schema"]["queryType"]["fields"]
        assert listed[0] == {"name": "q", "description": "d", "stability": "stable"}
        assert listed[1]["stability"] == "experimental"
        assert "deprecationReason" not in listed[1], "boilerplate reason is not echoed"
        assert "isDeprecated" not in listed[1]

    def test_root_field_names_tolerates_every_null_the_shape_allows(self) -> None:
        """All three nulls are real: a null root type, a null ``fields``, a nameless entry."""
        assert gql._root_field_names(None, "queryType") == []
        assert gql._root_field_names({}, "mutationType") == []
        assert gql._root_field_names({"mutationType": None}, "mutationType") == []
        assert gql._root_field_names({"queryType": {"fields": None}}, "queryType") == []
        assert gql._root_field_names(
            {"queryType": {"fields": [{}, {"name": "b"}, {"name": "a"}]}}, "queryType"
        ) == ["a", "b"]

    @pytest.mark.parametrize(
        ("document", "label"),
        [
            (gql._ROOT_INTROSPECT, "_ROOT_INTROSPECT"),
            (gql._ROOT_NAMES, "_ROOT_NAMES"),
            (gql._TYPE_INTROSPECT, "_TYPE_INTROSPECT"),
            (ops._ROOTS_QUERY, "_ROOTS_QUERY"),
        ],
    )
    def test_no_document_selects_fields_without_including_deprecated(
        self, document: str, label: str
    ) -> None:
        """Every ``fields`` selection passes ``includeDeprecated: true``.

        GraphQL defaults ``includeDeprecated`` to false, and SL1 marks its experimental features
        ``@deprecated``, so a bare ``fields {`` hides 202 of 359 root queries and 197 of 458
        mutations, guided discovery among them.

        This checks for the absence of a bare selection rather than the presence of the flag,
        which a newly added selection set without the flag would still satisfy.
        """
        assert _BARE_FIELD_SELECTION.search(document) is None, (
            f"{label} selects `fields` without includeDeprecated: true"
        )
        assert "includeDeprecated: true" in document

    @pytest.mark.parametrize(
        ("field", "expected"),
        [
            ({"name": "n"}, "stable"),
            ({"name": "n", "isDeprecated": False}, "stable"),
            (
                {"name": "n", "isDeprecated": True, "deprecationReason": "Experimental. Still..."},
                "experimental",
            ),
            (
                {
                    "name": "n",
                    "isDeprecated": True,
                    "deprecationReason": "This is experimental; only for testing poll frequency",
                },
                "experimental",
            ),
            (
                {
                    "name": "n",
                    "isDeprecated": True,
                    "deprecationReason": "Deprecated. This feature is known to be problematic",
                },
                "problematic",
            ),
            ({"name": "n", "isDeprecated": True}, "problematic"),
            ({"name": "n", "isDeprecated": True, "deprecationReason": None}, "problematic"),
        ],
    )
    def test_stability_separates_a_feature_arriving_from_one_leaving(
        self, field: dict[str, object], expected: str
    ) -> None:
        """The mid-sentence "experimental" cases are real values seen on SL1.

        A ``startswith`` test would call them problematic, which inverts the meaning: 156 of the
        202 hidden root queries are features arriving, and only 46 are features leaving.
        """
        assert gql._stability(field) == expected

    def test_stability_counts_keep_their_zeroes(self) -> None:
        """An absent key would read as "not measured", which is not "none of these exist"."""
        assert gql._stability_counts([{"name": "a"}]) == {
            "stable": 1,
            "experimental": 0,
            "problematic": 0,
        }

    def test_relabelling_passes_through_every_shape_it_cannot_read(self) -> None:
        """Like ``_root_field_names``, relabelling must not raise on an unexpected shape.

        A schema we do not control can present a non-dict entry, a null ``fields``, or no
        ``fields`` key at all, and none of those is a reason to fail the call an agent makes first.
        """
        assert gql._labelled(None) is None
        assert gql._labelled("not a field") is None
        assert gql._with_stability(None) is None
        assert gql._with_stability({"name": "T"}) == {"name": "T"}, "no fields key"
        assert gql._with_stability({"fields": None}) == {"fields": None}, "present-but-null"
        assert gql._with_stability({"fields": [None, {"name": "a"}]}) == {
            "fields": [{"name": "a", "stability": "stable"}]
        }, "the unusable entry is dropped, not propagated as None"

    @pytest.mark.anyio
    async def test_list_all_passes_through_a_schema_it_cannot_read(
        self, config: Config, credential: LceCredential
    ) -> None:
        """A null ``__schema`` is returned as-is, not reshaped into a misleading empty one."""
        body: dict[str, Any] = {"__schema": None}
        context, _, _ = _ctx(config, credential, _gql_ok(body))
        assert await gql.make_sl1_graphql_introspect(context)(list_all=True) == body


class TestDenialAndBadQueryCodes:
    """An authorization denial and a bad query arrive as the same error type, with codes to tell
    them apart."""

    @pytest.mark.anyio
    async def test_a_restricted_access_denial_is_distinguished_from_a_bad_query(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The two error shapes SL1 returns, end to end through a tool.

        A test asserting only that non-empty ``errors`` raises would pass while conflating a
        permission denial with a typo.
        """
        denial = {
            "errors": [
                {
                    "message": "User does not have required permissions.",
                    "extensions": {"code": SL1_RESTRICTED_ACCESS_CODE},
                }
            ],
            "data": {"credentials": None},
        }
        validation = {
            "errors": [
                {
                    "message": 'Cannot query field "name" on type "Organization".',
                    "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"},
                }
            ]
        }
        for body, expect_denial in ((denial, True), (validation, False)):

            def handler(_r: httpx.Request, envelope: dict[str, Any] = body) -> httpx.Response:
                return httpx.Response(200, json=envelope)

            context, _, _ = _ctx(config, credential, handler)
            payload = await gql.make_sl1_graphql(context)(query="{credentials{id}}")
            assert isinstance(payload, dict)
            error = payload["error"]
            assert error["type"] == "sl1_graphql_error", "one typed error for both"
            if expect_denial:
                assert error["graphql_error_codes"] == [SL1_RESTRICTED_ACCESS_CODE]
                assert "retrying will not help" in error["message"]
            else:
                assert "correct the query" in error["message"]

    def test_codes_stay_positional_with_messages(self) -> None:
        """An entry with no `extensions.code` yields ``""`` rather than being dropped.

        Dropping it would shift every later code onto the wrong message.
        """
        exc = Sl1GraphQlError(["a", "b", "c"], ["", SL1_RESTRICTED_ACCESS_CODE, ""])
        assert len(exc.codes) == len(exc.messages)
        assert exc.codes[1] == SL1_RESTRICTED_ACCESS_CODE
        assert exc.is_authorization_denial, "any, not all: a partial denial is still a denial"

    def test_an_unknown_code_degrades_to_the_generic_guidance(self) -> None:
        """The generic guidance is the fallback, not a guess at SL1's meaning."""
        exc = Sl1GraphQlError(["odd"], ["SOMETHING_NEW"])
        assert not exc.is_authorization_denial
        assert "correct the query" in str(build_error_payload(exc)["error"]["message"])

    def test_a_missing_extensions_block_yields_an_empty_code(self) -> None:
        from powerpack_mcp.sl1_client.client import _error_code

        assert _error_code({"message": "m"}) == ""
        assert _error_code({"extensions": "not-a-dict"}) == ""
        assert _error_code({"extensions": {"code": 7}}) == "", "a non-string code is not a code"
        assert _error_code("not-a-dict") == ""
        assert _error_code({"extensions": {"code": "X"}}) == "X"


class TestGraphQlEnvelopeProperty:
    """A property test that the GraphQL request envelope round-trips the caller's input.

    Config and credential are built inline rather than injected. Hypothesis re-runs the body many
    times against one fixture setup, so a function-scoped fixture would be shared across examples
    and a failure could depend on example order.
    """

    @settings(max_examples=75, deadline=None)
    @given(
        query=st.text(min_size=1, max_size=60),
        variables=st.dictionaries(
            st.text(min_size=1, max_size=8),
            st.one_of(st.integers(), st.booleans(), st.text(max_size=8)),
            max_size=4,
        ),
        operation_name=st.one_of(st.none(), st.text(min_size=1, max_size=8)),
    )
    def test_the_envelope_round_trips_whatever_the_caller_supplied(
        self,
        query: str,
        variables: dict[str, Any],
        operation_name: str | None,
    ) -> None:
        """For any query, variables and operation name, what SL1 receives is what was supplied.

        The envelope is where a transport could quietly re-key, coerce or drop caller input, and a
        passthrough must send it as-is. Optional members are absent when not supplied rather than
        null, because some servers reject a single-operation document with
        ``operationName: null``.
        """
        import anyio
        from pydantic import SecretStr

        async def exercise() -> None:
            config = Config()
            credential = LceCredential(SecretStr("Basic dXNlcjpwYXNz"))
            context, seen, _ = _ctx(config, credential, _gql_ok({"ok": 1}))
            await gql.make_sl1_graphql(context)(
                query=query, variables=variables, operation_name=operation_name
            )
            envelope = json.loads(seen[0].content)
            assert envelope["query"] == query
            if variables:
                assert envelope["variables"] == variables
            else:
                assert "variables" not in envelope
            if operation_name:
                assert envelope["operationName"] == operation_name
            else:
                assert "operationName" not in envelope

        anyio.run(exercise)


class TestEmptyFieldDropping:
    """The SL1 tools drop empty fields, as the LCE tools do.

    Without this the two surfaces disagree: an LCE tool returns only the populated fields, while
    ``sl1_get_powerpack`` would return ``"supportedVersions": ""``, ``"vendors": ""`` and
    ``"models": ""``.
    """

    @pytest.mark.anyio
    async def test_the_reported_empty_strings_are_gone(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The empty strings SL1 returns for a PowerPack, field for field."""
        context, _, _ = _ctx(
            config,
            credential,
            _gql_ok(
                {
                    "powerPack": {
                        "guid": "ABC",
                        "name": "Microsoft: Windows Server",
                        "supportedVersions": "",
                        "vendors": "",
                        "models": "",
                    }
                }
            ),
        )

        payload = await ent.make_sl1_get_powerpack(context)(powerpack_guid="G")

        assert payload == {"guid": "ABC", "name": "Microsoft: Windows Server"}

    @pytest.mark.anyio
    async def test_zero_and_false_survive(self, config: Config, credential: LceCredential) -> None:
        """``0`` and ``false`` are kept, which is the most important assertion here.

        A truthiness-based implementation would drop them, but they are values, not absence:
        ``numeric_range_low: 0`` is real threshold data. Whitespace-only strings are kept too.
        """
        context, _, _ = _ctx(
            config,
            credential,
            _gql_ok(
                {
                    "powerPack": {
                        "guid": "ABC",
                        "revision": 0,
                        "installed": False,
                        "notes": "   ",
                        "vendors": "",
                    }
                }
            ),
        )

        payload = await ent.make_sl1_get_powerpack(context)(powerpack_guid="G")

        assert payload == {
            "guid": "ABC",
            "revision": 0,
            "installed": False,
            "notes": "   ",
        }

    @pytest.mark.anyio
    async def test_nested_empties_are_dropped_bottom_up(
        self, config: Config, credential: LceCredential
    ) -> None:
        """If dropping members leaves a container empty, the container goes too."""
        context, _, _ = _ctx(
            config,
            credential,
            _gql_ok({"powerPack": {"guid": "ABC", "meta": {"a": None, "b": ""}, "tags": []}}),
        )

        payload = await ent.make_sl1_get_powerpack(context)(powerpack_guid="G")

        assert payload == {"guid": "ABC"}

    def test_there_is_one_pruning_mechanism_not_three(self) -> None:
        """Both SL1 passthrough modules use ``shaping.shape_response``, as the LCE pipeline does.

        Separate copies of one rule let the surfaces drift apart. This asserts identity, not
        equivalence, so a future copy-paste fails here.
        """
        from powerpack_mcp.shaping import shape_response
        from powerpack_mcp.tools import sl1_graphql_tools, sl1_rest_tools

        assert sl1_rest_tools._pruned is shape_response
        assert sl1_graphql_tools._pruned is shape_response


class TestBoundaryLogging:
    """``sl1_tool_boundary`` logs the same fields as the LCE tool boundary."""

    @pytest.mark.anyio
    async def test_a_success_logs_tool_outcome_and_duration(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        context, _, _ = _ctx(config, credential, _gql_ok({"powerPack": {"id": "1"}}))
        with caplog.at_level(logging.INFO):
            await ent.make_sl1_get_powerpack(context)(powerpack_guid="G")
        record = next(r for r in caplog.records if getattr(r, "outcome", None) == "success")
        assert _extra(record, "tool") == "sl1_get_powerpack"
        assert isinstance(_extra(record, "duration_ms"), float)

    @pytest.mark.anyio
    async def test_a_failure_is_translated_once_and_logged_with_its_type(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        context, _, _ = _ctx(config, credential, lambda _r: httpx.Response(404, json={"e": 1}))
        with caplog.at_level(logging.WARNING):
            payload = await ent.make_sl1_get_powerpack(context)(powerpack_guid="G")
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "sl1_http_error"
        record = next(r for r in caplog.records if getattr(r, "tool", None) == "sl1_get_powerpack")
        assert _extra(record, "outcome") == "Sl1HttpError"
