"""
LCE Tool Pipeline Tests

This module tests the LCE tools in ``powerpack_mcp.tools``: the guard order, the event
emissions, error translation and the tool descriptors.

Every test uses a mocked `LceClient` transport, so the default run needs no appliance, no
credential and no network. The mock transport also makes "the request was never issued to LCE"
assertable, and it is asserted explicitly for every guard rather than inferred from the ordering.
"""

from __future__ import annotations

import inspect
import json
import logging
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from powerpack_mcp.errors import CredentialMissing, FindingCode, LogEvent
from powerpack_mcp.query import FilterCondition, FilterOperator, FilterParams, WriteOptions
from powerpack_mcp.tools import (
    ALL_DESCRIPTORS,
    CREATE_OR_UPDATE_DYNAMIC_APPLICATIONS,
    CREATE_OR_UPDATE_EVENT_POLICIES,
    GET_POWERPACK,
    LIST_DYNAMIC_APPLICATIONS,
    TOOL_FACTORIES,
    ToolContext,
    make_create_or_update_dynamic_applications,
    make_get_powerpack,
    make_list_dynamic_applications,
)
from powerpack_mcp.validation import MAX_PAYLOAD_DEPTH

if TYPE_CHECKING:
    from collections.abc import Callable

    from powerpack_mcp.config import Config
from powerpack_mcp.credentials import LceCredential
from powerpack_mcp.lce_client import LceClient

_VALID_GUID = "A1B2C3D4E5F6789012345678901234AB"


def _context(
    config: Config,
    credential: LceCredential,
    handler: Callable[[httpx.Request], httpx.Response] | None = None,
) -> tuple[ToolContext, list[httpx.Request]]:
    """A `ToolContext` whose client has a recording mock transport."""
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if handler is not None:
            return handler(request)
        return httpx.Response(200, json={"results": [{"id": 1}]})

    client = LceClient(config)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(recording))

    def _credential_source() -> LceCredential:
        # A synthetic credential, injected. A test calls tool functions directly, outside any HTTP
        # context, so production's `credential_for_request` would fail closed here.
        return credential

    return (
        ToolContext(client=client, config=config, credential_source=_credential_source),
        seen,
    )


def _nest(depth: int) -> dict[str, Any]:
    root: dict[str, Any] = {}
    cursor = root
    for _ in range(depth - 1):
        child: dict[str, Any] = {}
        cursor["n"] = child
        cursor = child
    return root


def _codes(envelope: object) -> list[str]:
    assert isinstance(envelope, dict)
    return [d["rule"] for d in envelope["error"]["details"]]


class TestThePayloadReachesLceUnaltered:
    """The service never alters the payload it forwards to LCE.

    LCE rewrites a child ``reference`` itself: its own guide documents this, and SL1 has no column
    to store the value. These tests pin the other half of that attribution, that this code never
    touches the key, by asserting the bytes on the wire so a refactor cannot quietly break it.
    """

    @pytest.mark.anyio
    async def test_a_child_reference_reaches_the_wire_verbatim(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The caller's own ``reference`` is what LCE receives; we neither strip nor rewrite it.

        Asserted against the request body actually issued, not a return value. A tool that dropped
        the key and one that forwarded it can produce identical responses, because LCE substitutes
        its own value either way. Only the outbound bytes distinguish them.
        """
        sentinel = "cc-caller-supplied-reference-7f3a"
        context, seen = _context(config, credential)
        payload = {
            "guid": _VALID_GUID,
            "threshold_objects": [
                {"guid": _VALID_GUID, "reference": sentinel, "type": "PERCENTAGE", "value": 75}
            ],
        }
        await make_create_or_update_dynamic_applications(context)(payload=payload)

        assert len(seen) == 1, f"expected exactly one request, got {len(seen)}"
        body = json.loads(seen[0].content)
        sent = body["threshold_objects"][0]
        assert sent["reference"] == sentinel, (
            "the caller's reference did not reach LCE unaltered; the service must pass it "
            f"through untouched: {sent}"
        )
        # The sentinel must survive as raw bytes too, not merely as a re-serialised equal value.
        assert sentinel.encode() in seen[0].content

    @pytest.mark.anyio
    async def test_no_key_is_added_removed_or_renamed_anywhere_in_the_payload(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The whole document round-trips, not just the one key we care about.

        A test pinning only ``reference`` would pass a tool that dropped ``value``, or one that
        injected a default. The tool description promises the payload is sent exactly as supplied,
        so this asserts structural equality of the whole payload.
        """
        context, seen = _context(config, credential)
        payload: dict[str, Any] = {
            "guid": _VALID_GUID,
            "name": "cc-unit-da",
            "threshold_objects": [
                {
                    "guid": _VALID_GUID,
                    "reference": "t_should_not_be_touched",
                    "type": "DECIMAL",
                    "value": 75.5,
                    "numeric_range_low": 0,
                    "numeric_range_high": 100,
                }
            ],
        }
        await make_create_or_update_dynamic_applications(context)(payload=payload)

        assert len(seen) == 1
        assert json.loads(seen[0].content) == payload, (
            "the payload was altered in flight; the tool promises it is sent exactly as supplied"
        )

    @pytest.mark.anyio
    async def test_a_reference_on_a_child_with_no_guid_is_also_untouched(
        self, config: Config, credential: LceCredential
    ) -> None:
        """A child with ``reference`` present and ``guid`` omitted.

        This is the shape that produced duplicate thresholds: a caller identifying a child by
        ``reference`` alone. Omitting ``guid`` is legal (the lint permits it so LCE can assign one),
        so the tool must neither synthesise a GUID nor drop the reference in its place.
        """
        context, seen = _context(config, credential)
        payload = {"guid": _VALID_GUID, "threshold_objects": [{"reference": "t_269"}]}
        await make_create_or_update_dynamic_applications(context)(payload=payload)

        assert len(seen) == 1
        sent = json.loads(seen[0].content)["threshold_objects"][0]
        assert sent == {"reference": "t_269"}, f"a guid-less child was altered in flight: {sent}"


class TestGuardsNeverReachLce:
    """Every guard returns before the first I/O."""

    @pytest.mark.anyio
    async def test_a_lint_finding_issues_no_request(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, seen = _context(config, credential)
        tool = make_create_or_update_dynamic_applications(context)
        result = await tool(payload={"guid": "not-a-guid"})
        assert _codes(result) == [FindingCode.CHILD_GUID.value]
        assert seen == [], "no request may be issued once a lint has produced a finding"

    @pytest.mark.anyio
    async def test_a_depth_violation_issues_no_request(
        self, config: Config, credential: LceCredential
    ) -> None:
        """`ValidationBlocked` naming the limit, not `RecursionError` and not a 500."""
        context, seen = _context(config, credential)
        tool = make_create_or_update_dynamic_applications(context)
        result = await tool(payload=_nest(MAX_PAYLOAD_DEPTH + 5))
        assert _codes(result) == [FindingCode.PAYLOAD_DEPTH.value]
        assert seen == []

    @pytest.mark.anyio
    async def test_an_oversized_body_issues_no_request(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, seen = _context(config, credential)
        tool = make_create_or_update_dynamic_applications(context)
        result = await tool(payload={"x": "y" * (config.MAX_REQUEST_BODY_BYTES + 1)})
        assert _codes(result) == [FindingCode.REQUEST_BODY_SIZE.value]
        assert seen == []

    @pytest.mark.anyio
    async def test_a_missing_required_filter_issues_no_request(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The model forbids an empty condition list; this covers the omitted parameter."""
        context, seen = _context(config, credential)
        tool = make_list_dynamic_applications(context)
        result = await tool(filters=None)
        assert _codes(result) == [FindingCode.FILTER_CONSTRAINT.value]
        assert seen == []

    @pytest.mark.anyio
    async def test_a_filter_constraint_violation_issues_no_request(
        self, config: Config, credential: LceCredential
    ) -> None:
        """`search` is not negatable."""
        context, seen = _context(config, credential)
        tool = make_list_dynamic_applications(context)
        filters = FilterParams(
            conditions=[
                FilterCondition(
                    field="name", operator=FilterOperator.SEARCH, value="x", negate=True
                )
            ]
        )
        result = await tool(filters=filters)
        assert _codes(result) == [FindingCode.FILTER_CONSTRAINT.value]
        assert seen == []


class TestStepZeroCredential:
    """The credential check runs first, and no signature advertises a credential."""

    @pytest.mark.anyio
    async def test_a_missing_credential_refuses_before_any_validation(self, config: Config) -> None:
        """The credential check precedes validation, and not merely for efficiency.

        The payload here is also invalid (a bad child GUID). A caller with no credential must
        receive `credential_missing`, not the lint finding: validation feedback to an
        unauthenticated party is information disclosure, and would let them use the lints as an
        oracle against a payload.
        """
        seen: list[httpx.Request] = []

        def recording(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"ok": True})

        client = LceClient(config)
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(recording))

        def _no_credential() -> LceCredential:
            raise CredentialMissing

        context = ToolContext(client=client, config=config, credential_source=_no_credential)
        result = await make_create_or_update_dynamic_applications(context)(
            payload={"guid": "not-a-guid"}
        )
        assert isinstance(result, dict)
        assert result["error"]["type"] == "credential_missing"
        assert "details" not in result["error"], (
            "an unauthenticated caller must not receive lint findings"
        )
        assert seen == [], "no request may reach LCE without a credential"

    @pytest.mark.anyio
    async def test_the_error_envelope_discloses_nothing_about_the_credential(
        self, config: Config
    ) -> None:
        """Not the value, not the length, not the scheme, and not presence versus malformation.

        Naming the `Authorization` header is not a leak, and the assertion below permits it: telling
        a caller where to put a credential is actionable guidance and discloses nothing about what
        was presented. The scheme must not appear, because it would confirm to an attacker that
        their probe was well-formed.
        """
        client = LceClient(config)
        client._client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={}))
        )

        def _no_credential() -> LceCredential:
            raise CredentialMissing

        context = ToolContext(client=client, config=config, credential_source=_no_credential)
        result = await make_get_powerpack(context)(powerpack_identifier="7")
        assert isinstance(result, dict)
        rendered = str(result).lower()
        # Scheme disclosure would confirm a probe was well-formed; a value or length is a direct
        # leak.
        for leak in ("basic", "bearer", "password", "dgvzdhvz", "length", "characters"):
            assert leak not in rendered, f"the envelope leaked {leak!r}"
        assert not any(char.isdigit() for char in rendered), "a digit could imply a length"

    @pytest.mark.anyio
    async def test_the_credential_reaches_lce_verbatim(
        self, config: Config, credential: LceCredential, credential_value: str
    ) -> None:
        """Forwarded verbatim, on every request, with no unauthenticated path."""
        context, seen = _context(config, credential)
        await make_get_powerpack(context)(powerpack_identifier="7")
        assert seen[0].headers["Authorization"] == credential_value


class TestGuardOrdering:
    """The order of the checks is asserted.

    Bounds before lints is a performance choice; every check before the LCE request is the
    security guarantee.
    """

    @pytest.mark.anyio
    async def test_bounds_short_circuit_before_the_lints(
        self, config: Config, credential: LceCredential
    ) -> None:
        """A payload that is both too deep and has a bad GUID reports only the bound violation.

        Linting input already known to be pathological is the expense the ordering avoids.
        """
        context, _ = _context(config, credential)
        tool = make_create_or_update_dynamic_applications(context)
        payload = _nest(MAX_PAYLOAD_DEPTH + 5)
        payload["guid"] = "bad"
        assert _codes(await tool(payload=payload)) == [FindingCode.PAYLOAD_DEPTH.value]

    @pytest.mark.anyio
    async def test_all_lint_findings_are_reported_together(
        self, config: Config, credential: LceCredential
    ) -> None:
        """One round trip surfaces every problem."""
        context, _ = _context(config, credential)
        tool = make_create_or_update_dynamic_applications(context)
        payload = {"guid": "bad", "threshold_objects": [{"type": 0}]}
        assert sorted(_codes(await tool(payload=payload))) == [
            FindingCode.CHILD_GUID.value,
            FindingCode.THRESHOLD_TYPE.value,
        ]


class TestSuccessPath:
    @pytest.mark.anyio
    async def test_response_is_shaped(self, config: Config, credential: LceCredential) -> None:
        """Shaping applied through the pipeline: empty members removed, `0` kept."""
        context, _ = _context(
            config,
            credential,
            lambda _r: httpx.Response(200, json={"results": [{"id": 0, "note": "", "tags": []}]}),
        )
        tool = make_get_powerpack(context)
        assert await tool(powerpack_identifier="7") == {"results": [{"id": 0}]}

    @pytest.mark.anyio
    async def test_path_and_query_are_built_from_the_descriptor(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, seen = _context(config, credential)
        tool = make_get_powerpack(context)
        await tool(powerpack_identifier="A1B2", pretty=False, fields="id", exclude="guid")
        assert seen[0].url.path.endswith("/powerpacks/A1B2")
        assert dict(seen[0].url.params) == {
            "pretty": "false",
            "fields": "id",
            "exclude": "guid",
        }

    @pytest.mark.anyio
    async def test_write_options_are_sent_for_writes_only(
        self, config: Config, credential: LceCredential
    ) -> None:
        """`commit` and `retrieve` appear on no GET."""
        context, seen = _context(config, credential)
        await make_create_or_update_dynamic_applications(context)(payload={"guid": _VALID_GUID})
        assert dict(seen[-1].url.params)["commit"] == "true"

        await make_get_powerpack(context)(powerpack_identifier="7")
        assert "commit" not in dict(seen[-1].url.params)

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "payload",
        [
            {"name": "single"},
            [{"name": "a"}, {"name": "b"}],
            {"dynamic_applications": [{"name": "c"}]},
        ],
    )
    async def test_every_payload_shape_is_transmitted_unchanged(
        self, config: Config, credential: LceCredential, payload: object
    ) -> None:
        """The top-level array form must reach LCE, not only validate.

        The client's `json_body` must accept a list as well as a dict, or an array payload would
        pass validation and then be silently dropped.
        """
        import json

        context, seen = _context(config, credential)
        await make_create_or_update_dynamic_applications(context)(payload=payload)
        assert json.loads(seen[-1].content) == payload


class TestEventEmissions:
    """The four LCE monitoring events and the per-invocation record."""

    @pytest.mark.anyio
    async def test_validation_blocked_is_emitted_at_warning(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        context, _ = _context(config, credential)
        with caplog.at_level(logging.WARNING):
            await make_create_or_update_dynamic_applications(context)(payload={"guid": "bad"})
        events = [getattr(r, "event", None) for r in caplog.records]
        assert LogEvent.VALIDATION_BLOCKED in events

    @pytest.mark.anyio
    @pytest.mark.parametrize("status", [401, 403])
    async def test_lce_auth_denied_is_emitted_for_401_and_403(
        self,
        config: Config,
        credential: LceCredential,
        caplog: pytest.LogCaptureFixture,
        status: int,
    ) -> None:
        """Also the fastest signal that `LCE_CREDENTIAL_HEADER` is misconfigured, which nothing
        else detects.
        """
        context, _ = _context(
            config, credential, lambda _r: httpx.Response(status, json={"detail": "no"})
        )
        with caplog.at_level(logging.WARNING):
            await make_get_powerpack(context)(powerpack_identifier="7")
        events = [getattr(r, "event", None) for r in caplog.records]
        assert LogEvent.LCE_AUTH_DENIED in events

    @pytest.mark.anyio
    @pytest.mark.parametrize("status", [400, 404, 422, 500, 502])
    async def test_other_statuses_do_not_emit_auth_denied(
        self,
        config: Config,
        credential: LceCredential,
        caplog: pytest.LogCaptureFixture,
        status: int,
    ) -> None:
        context, _ = _context(
            config, credential, lambda _r: httpx.Response(status, json={"detail": "no"})
        )
        with caplog.at_level(logging.INFO):
            await make_get_powerpack(context)(powerpack_identifier="7")
        events = [getattr(r, "event", None) for r in caplog.records]
        assert LogEvent.LCE_AUTH_DENIED not in events

    @pytest.mark.anyio
    async def test_write_committed_is_emitted_only_when_commit_is_true(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The event name asserts a commit, so emitting it for a dry run would make every audit
        query keying on it wrong unless it also read `outcome`.
        """
        context, _ = _context(config, credential)
        tool = make_create_or_update_dynamic_applications(context)

        with caplog.at_level(logging.INFO):
            await tool(payload={"guid": _VALID_GUID}, commit=True)
        assert LogEvent.WRITE_COMMITTED in [getattr(r, "event", None) for r in caplog.records]

        caplog.clear()
        with caplog.at_level(logging.INFO):
            await tool(payload={"guid": _VALID_GUID}, commit=False)
        assert LogEvent.WRITE_COMMITTED not in [getattr(r, "event", None) for r in caplog.records]

    @pytest.mark.anyio
    async def test_write_committed_is_not_emitted_when_lce_rejects(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        context, _ = _context(
            config, credential, lambda _r: httpx.Response(500, json={"detail": "no"})
        )
        with caplog.at_level(logging.INFO):
            await make_create_or_update_dynamic_applications(context)(payload={"guid": _VALID_GUID})
        assert LogEvent.WRITE_COMMITTED not in [getattr(r, "event", None) for r in caplog.records]

    @pytest.mark.anyio
    async def test_reads_never_emit_write_committed(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        context, _ = _context(config, credential)
        with caplog.at_level(logging.INFO):
            await make_get_powerpack(context)(powerpack_identifier="7")
        assert LogEvent.WRITE_COMMITTED not in [getattr(r, "event", None) for r in caplog.records]

    @pytest.mark.anyio
    async def test_the_per_invocation_record_carries_the_required_fields(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        """`tool`, `target_host`, `lce_operation`, `outcome`, `duration_ms`."""
        context, _ = _context(config, credential)
        with caplog.at_level(logging.INFO):
            await make_get_powerpack(context)(powerpack_identifier="7")
        record = next(r for r in caplog.records if getattr(r, "outcome", None) == "success")
        for field in ("tool", "target_host", "lce_operation", "outcome", "duration_ms"):
            assert hasattr(record, field), f"the invocation record requires {field}"
        assert getattr(record, "tool", None) == GET_POWERPACK.tool_name

    @pytest.mark.anyio
    async def test_effective_target_host_is_the_resolved_configured_host(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The record carries the resolved host, not a sentinel.

        Tools take no ``target_host`` argument, so the value is the configured destination. Every
        create/update record must name the real target host, which a ``"<default>"`` sentinel would
        not.
        """
        context, _ = _context(config, credential)
        with caplog.at_level(logging.INFO):
            await make_get_powerpack(context)(powerpack_identifier="7")
        record = next(r for r in caplog.records if getattr(r, "outcome", None) == "success")
        assert getattr(record, "target_host", None) == config.LCE_DEFAULT_TARGET_HOST
        # The sentinel must be gone, not merely unused.
        assert getattr(record, "target_host", None) != "<default>"

    @pytest.mark.anyio
    async def test_no_tool_exposes_a_target_host_parameter(
        self, config: Config, credential: LceCredential
    ) -> None:
        """No tool accepts a per-call host override.

        `is_valid_target_host` validates hostname syntax, not an allowlist. Under credential
        pass-through, a caller-supplied or prompt-injected ``target_host`` would send the caller's
        own Skylar One credential to an arbitrary host.

        The override may return only alongside a configured destination allowlist that fails
        closed when empty. `is_valid_target_host` still looks like an allowlist, so re-wiring the
        parameter to it would silently reopen the hole. If this fails, implement the allowlist or
        do not re-add the parameter.
        """
        context, _ = _context(config, credential)
        # `TOOL_FACTORIES` rather than a hand-listed tuple: it is the same sequence
        # `mcp_app.register_tools` iterates, so an eighth LCE operation added later is covered by
        # this guard automatically instead of silently escaping it.
        assert len(TOOL_FACTORIES) == 7, "all seven tools must be covered by this guard"
        for descriptor, factory in zip(ALL_DESCRIPTORS, TOOL_FACTORIES, strict=True):
            parameters = inspect.signature(factory(context)).parameters
            assert "target_host" not in parameters, (
                f"{descriptor.tool_name} exposes target_host again. "
                "The override may only return together with a configured allowlist that fails "
                "closed when empty; re-wiring it to is_valid_target_host would let a caller "
                "send its credential to any host."
            )

    @pytest.mark.anyio
    async def test_no_payload_body_is_ever_logged(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Neither the payload nor any value from it appears in a log record."""
        marker = "supersecret-payload-marker"
        context, _ = _context(config, credential)
        with caplog.at_level(logging.DEBUG):
            await make_create_or_update_dynamic_applications(context)(
                payload={"guid": _VALID_GUID, "note": marker}
            )
        assert marker not in caplog.text

    @pytest.mark.anyio
    async def test_actor_is_omitted_when_unavailable(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Omitted entirely rather than set to a placeholder.

        `unknown` would be indistinguishable from a principal genuinely named `unknown`. Outside an
        HTTP request there is no forwarded identity to read.
        """
        context, _ = _context(config, credential)
        with caplog.at_level(logging.INFO):
            await make_get_powerpack(context)(powerpack_identifier="7")
        record = next(r for r in caplog.records if getattr(r, "outcome", None) == "success")
        assert not hasattr(record, "actor")


class TestErrorTranslation:
    """Errors are translated in one place, which calls `build_error_payload`."""

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("handler", "expected"),
        [
            (lambda _r: httpx.Response(404, json={"detail": "gone"}), "lce_http_error"),
            (lambda _r: httpx.Response(200, text="not json"), "lce_malformed_response"),
        ],
    )
    async def test_lce_failures_become_the_closed_error_vocabulary(
        self,
        config: Config,
        credential: LceCredential,
        handler: Callable[[httpx.Request], httpx.Response],
        expected: str,
    ) -> None:
        context, _ = _context(config, credential, handler)
        result = await make_get_powerpack(context)(powerpack_identifier="7")
        assert isinstance(result, dict)
        assert result["error"]["type"] == expected

    @pytest.mark.anyio
    async def test_unreachable_lce_becomes_lce_unreachable(
        self, config: Config, credential: LceCredential
    ) -> None:
        def refuse(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        context, _ = _context(config, credential, refuse)
        result = await make_get_powerpack(context)(powerpack_identifier="7")
        assert isinstance(result, dict)
        assert result["error"]["type"] == "lce_unreachable"

    @pytest.mark.anyio
    async def test_an_error_envelope_never_leaks_internal_detail(
        self, config: Config, credential: LceCredential
    ) -> None:
        """No stack trace, path, framework version or credential."""

        def refuse(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("[Errno 61] refused to 127.0.0.1:8443")

        context, _ = _context(config, credential, refuse)
        result = await make_get_powerpack(context)(powerpack_identifier="7")
        rendered = repr(result)
        for leak in ("Errno", "8443", "Traceback", "site-packages", "Bearer"):
            assert leak not in rendered


class TestDescriptors:
    def test_seven_descriptors_with_unique_lce_prefixed_names(self) -> None:
        """Tool names are unique and share the ``lce_`` prefix."""
        names = [d.tool_name for d in ALL_DESCRIPTORS]
        assert len(names) == len(set(names)) == 7
        assert all(n.startswith("lce_") for n in names)

    def test_lint_selection_is_data_and_asymmetric(self) -> None:
        """`EventPolicy` has no threshold collection, so it carries one lint, not two."""
        assert CREATE_OR_UPDATE_DYNAMIC_APPLICATIONS.lint_rules == frozenset(
            {FindingCode.CHILD_GUID.value, FindingCode.THRESHOLD_TYPE.value}
        )
        assert len(CREATE_OR_UPDATE_EVENT_POLICIES.lint_rules) == 1

    def test_only_reads_have_no_lints(self) -> None:
        for descriptor in ALL_DESCRIPTORS:
            if descriptor.is_write:
                assert descriptor.lint_rules, f"{descriptor.tool_name} is a write with no lints"
            else:
                assert not descriptor.lint_rules

    def test_write_options_only_on_writes(self) -> None:
        """`commit`/`retrieve` appear on no GET."""
        for descriptor in ALL_DESCRIPTORS:
            assert descriptor.supports_write_options == descriptor.is_write

    def test_requires_filter_only_on_the_two_lists(self) -> None:
        requiring = [d.tool_name for d in ALL_DESCRIPTORS if d.requires_filter]
        assert requiring == [
            LIST_DYNAMIC_APPLICATIONS.tool_name,
            "lce_list_event_policies",
        ]

    def test_path_rendering_rejects_a_mismatched_identifier(self) -> None:
        with pytest.raises(AssertionError):
            LIST_DYNAMIC_APPLICATIONS.path_for("unexpected")
        with pytest.raises(AssertionError):
            GET_POWERPACK.path_for(None)

    def test_no_tool_hardcodes_a_path_or_method(self) -> None:
        """Every path and method lives in a descriptor, not in the tool code."""
        from pathlib import Path

        source = Path("src/powerpack_mcp/tools/lce_tools.py").read_text()
        for descriptor in ALL_DESCRIPTORS:
            assert descriptor.path_template not in source
        assert '"GET"' not in source
        assert '"POST"' not in source


class TestWriteOptionDefaults:
    def test_defaults_are_the_specification_defaults(self) -> None:
        options = WriteOptions()
        assert options.commit is True
        assert options.retrieve is False
