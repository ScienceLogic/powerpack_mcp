"""
Authorization Gate Tests

This module tests ``mcp_app.authz_gate``: which tools are gated, the allow path, and the four
deny branches. It uses real ``MiddlewareContext`` and ``CallToolRequestParams`` objects, so the
tests exercise the hook fastmcp actually calls. The hook source is injected, so no appliance,
credential or network is needed.

Every refusal test also asserts that ``call_next`` was not invoked. A denial makes no transport
call of any kind, so a refused caller cannot use the gate to probe which devices or jobs exist.
"""

from __future__ import annotations

import logging

import mcp.types as mt
import pytest
from fastmcp.server.middleware import MiddlewareContext
from fastmcp.tools.base import ToolResult
from pydantic import SecretStr

from powerpack_mcp.authz import TOOL_REGISTRY, ToolTransport, sql_tool_names
from powerpack_mcp.credentials import LceCredential
from powerpack_mcp.errors import LogEvent, Sl1Unreachable
from powerpack_mcp.hook_source import HookCache
from powerpack_mcp.mcp_app.authz_gate import (
    ActorUnresolvable,
    AuthorizationGate,
    ToolNotMapped,
    is_gated,
)

pytestmark = pytest.mark.anyio

# A tool whose real mapping is a single hook, so the tests read clearly.
GATED_TOOL = "sl1_create_device_class"
GATED_HOOK = "SYS_CUSTOM_DEV_CLASS_PAGE"


class _Source:
    """An injected `HookSource`. Never opens a socket."""

    def __init__(self, hooks: frozenset[str], failure: Exception | None = None) -> None:
        self.hooks = hooks
        self.failure = failure

    async def hooks_for(self, credential: LceCredential) -> frozenset[str]:  # noqa: ARG002
        if self.failure is not None:
            raise self.failure
        return self.hooks


class _Dispatch:
    """Stands in for ``call_next``, and records whether it ran."""

    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, context: object) -> ToolResult:  # noqa: ARG002
        self.calls += 1
        return ToolResult(structured_content={"ok": True})


def _ctx(
    tool: str, arguments: dict[str, object] | None = None
) -> MiddlewareContext[mt.CallToolRequestParams]:
    return MiddlewareContext(
        message=mt.CallToolRequestParams(name=tool, arguments=arguments or {}),
        method="tools/call",
    )


def _gate(
    hooks: frozenset[str],
    *,
    failure: Exception | None = None,
    actor: int | None = 4,
    gated: object = is_gated,
    monkeypatch: pytest.MonkeyPatch | None = None,
) -> AuthorizationGate:
    if monkeypatch is not None:
        from powerpack_mcp.tools import sl1_db_pipeline

        monkeypatch.setattr(sl1_db_pipeline, "actor_user_id", lambda: actor)
    return AuthorizationGate(
        cache=HookCache(_Source(hooks, failure), clock=lambda: 0.0),
        credential_source=lambda: LceCredential(SecretStr("Basic dXNlcjpwYXNz")),
        gated=gated,  # type: ignore[arg-type]
    )


# ---- Deny branches first: the deny path is the security-relevant one ----


class TestDenyBranches:
    async def test_an_absent_hook_refuses_and_dispatches_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ``calls == 0`` assertion is the load-bearing half."""
        gate = _gate(frozenset({"DEV_VIEW"}), monkeypatch=monkeypatch)
        dispatch = _Dispatch()
        result = await gate.on_call_tool(_ctx(GATED_TOOL), dispatch)
        assert dispatch.calls == 0, "a denial must make no transport call"
        error = (result.structured_content or {})["error"]
        assert error["type"] == "authorization_denied"
        assert error["required_hooks"] == [GATED_HOOK]

    async def test_an_empty_grant_set_refuses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An account granted nothing is denied -- deny-by-default, not a parse failure."""
        gate = _gate(frozenset(), monkeypatch=monkeypatch)
        dispatch = _Dispatch()
        result = await gate.on_call_tool(_ctx(GATED_TOOL), dispatch)
        assert dispatch.calls == 0
        assert (result.structured_content or {})["error"]["type"] == "authorization_denied"

    async def test_an_unresolvable_actor_refuses_as_internal_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``internal_error``, not ``authorization_denied``, is deliberate.

        No caller can reach this in a correct deployment, because nginx sets ``X-User-ID`` from its
        own subrequest, so it is our defect. Telling the caller to ask for a hook would send them
        somewhere that cannot help.
        """
        gate = _gate(frozenset({GATED_HOOK}), actor=None, monkeypatch=monkeypatch)
        dispatch = _Dispatch()
        result = await gate.on_call_tool(_ctx(GATED_TOOL), dispatch)
        assert dispatch.calls == 0
        assert (result.structured_content or {})["error"]["type"] == "internal_error"

    async def test_a_failed_hook_fetch_refuses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A hook fetch failure must never become permission."""
        gate = _gate(frozenset(), failure=Sl1Unreachable("sl1"), monkeypatch=monkeypatch)
        dispatch = _Dispatch()
        result = await gate.on_call_tool(_ctx(GATED_TOOL), dispatch)
        assert dispatch.calls == 0
        assert (result.structured_content or {})["error"]["type"] == "sl1_unreachable"

    async def test_a_gated_tool_with_no_mapping_refuses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Widening the gated scope to an unmapped tool is the change this fails closed on."""
        gate = _gate(
            frozenset({GATED_HOOK}),
            gated=lambda name: name == "sl1_get_recent_events",
            monkeypatch=monkeypatch,
        )
        dispatch = _Dispatch()
        result = await gate.on_call_tool(_ctx("sl1_get_recent_events"), dispatch)
        assert dispatch.calls == 0
        assert (result.structured_content or {})["error"]["type"] == "internal_error"

    async def test_the_refusal_never_names_the_granted_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The refusal names the required hooks, which is safe, but never the granted set.

        A caller must not learn what they do hold from a refusal, including by difference.
        """
        secret_grant = "CRED_VIEW_PASSWORDS"
        gate = _gate(frozenset({"DEV_VIEW", secret_grant}), monkeypatch=monkeypatch)
        result = await gate.on_call_tool(_ctx(GATED_TOOL), _Dispatch())
        assert secret_grant not in repr(result.structured_content)
        assert "DEV_VIEW" not in repr(result.structured_content)


class TestAllowPath:
    async def test_sufficient_hooks_dispatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        gate = _gate(frozenset({GATED_HOOK}), monkeypatch=monkeypatch)
        dispatch = _Dispatch()
        result = await gate.on_call_tool(_ctx(GATED_TOOL), dispatch)
        assert dispatch.calls == 1
        assert (result.structured_content or {}) == {"ok": True}

    async def test_a_superset_of_hooks_dispatches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`issubset`, not equality: holding more than required is normal."""
        gate = _gate(frozenset({GATED_HOOK, "DEV_VIEW", "EVT_VIEW"}), monkeypatch=monkeypatch)
        dispatch = _Dispatch()
        await gate.on_call_tool(_ctx(GATED_TOOL), dispatch)
        assert dispatch.calls == 1

    async def test_an_ungated_tool_is_not_touched(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A REST tool dispatches with no hook fetch at all.

        The injected source would raise if consulted, so this asserts the gate did not consult it.
        """
        gate = _gate(frozenset(), failure=Sl1Unreachable("sl1"), monkeypatch=monkeypatch)
        dispatch = _Dispatch()
        await gate.on_call_tool(_ctx("sl1_get_recent_events"), dispatch)
        assert dispatch.calls == 1

    async def test_an_unknown_tool_is_not_gated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A tool outside ``TOOL_REGISTRY`` passes through; SL1 enforces access for the rest."""
        gate = _gate(frozenset(), failure=Sl1Unreachable("sl1"), monkeypatch=monkeypatch)
        dispatch = _Dispatch()
        await gate.on_call_tool(_ctx("get_content_standards"), dispatch)
        assert dispatch.calls == 1


class TestEnvelopeShape:
    async def test_the_refusal_matches_a_tool_dict_return_exactly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One envelope shape, whether the refusal came from here or from a tool.

        The gate sits outside ``sl1_tool_boundary``, so nothing downstream normalises its output.
        This builds both and compares them, rather than relying on how the framework is read.
        """
        from fastmcp.tools.base import Tool

        gate = _gate(frozenset(), monkeypatch=monkeypatch)
        refusal = await gate.on_call_tool(_ctx(GATED_TOOL), _Dispatch())
        payload = refusal.structured_content

        async def returns_the_same_dict() -> dict[str, object]:
            return payload  # type: ignore[return-value]

        tool_shaped = await Tool.from_function(returns_the_same_dict, name="probe").run({})
        assert refusal.structured_content == tool_shaped.structured_content
        assert [c.text for c in refusal.content] == [  # type: ignore[union-attr]
            c.text  # type: ignore[union-attr]
            for c in tool_shaped.content
        ]


class TestTheRefusalRecord:
    async def test_it_is_event_keyed_and_carries_no_grants(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Monitoring keys on ``event``, and the granted set is never logged.

        The granted set is a named person's entitlement profile. ``RedactingFilter`` matches
        attribute names, so a ``granted_hooks`` extra would pass through untouched; the only
        reliable rule is to never attach it.
        """
        gate = _gate(frozenset({"CRED_VIEW_PASSWORDS"}), monkeypatch=monkeypatch)
        with caplog.at_level(logging.WARNING):
            await gate.on_call_tool(_ctx(GATED_TOOL), _Dispatch())
        (record,) = [r for r in caplog.records if r.__dict__.get("event")]
        assert record.__dict__["event"] == str(LogEvent.AUTHORIZATION_DENIED)
        assert record.__dict__["tool"] == GATED_TOOL
        assert record.__dict__["required_hooks"] == [GATED_HOOK]
        assert "CRED_VIEW_PASSWORDS" not in str(record.__dict__)
        assert "Basic" not in str(record.__dict__), "no credential in the record"

    @pytest.mark.parametrize(
        ("actor", "failure", "expected"),
        [
            pytest.param(None, None, "ActorUnresolvable", id="unresolvable-actor"),
            pytest.param(4, Sl1Unreachable("sl1"), "Sl1Unreachable", id="failed-fetch"),
        ],
    )
    async def test_the_reason_field_distinguishes_the_branches(
        self,
        actor: int | None,
        failure: Exception | None,
        expected: str,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """An operator chasing a burst of refusals needs to know *which* branch fired -- a dropped
        nginx include line and an unreachable SL1 look identical without this.
        """
        gate = _gate(frozenset(), failure=failure, actor=actor, monkeypatch=monkeypatch)
        with caplog.at_level(logging.WARNING):
            await gate.on_call_tool(_ctx(GATED_TOOL), _Dispatch())
        (record,) = [r for r in caplog.records if r.__dict__.get("event")]
        assert record.__dict__["reason"] == expected


class TestGatedScopeIsDerived:
    def test_exactly_the_sql_surface_is_gated(self) -> None:
        """Derived from the registry rather than listed here."""
        gated = {name for name in TOOL_REGISTRY if is_gated(name)}
        assert gated == sql_tool_names()
        assert len(gated) == 8

    def test_no_non_sql_tool_is_gated(self) -> None:
        for entry in TOOL_REGISTRY.values():
            if entry.transport is not ToolTransport.SQL:
                assert not is_gated(entry.name)

    def test_an_unknown_name_is_not_gated(self) -> None:
        assert not is_gated("nothing_by_this_name")

    def test_the_two_internal_error_types_are_distinct(self) -> None:
        """They render identically to a caller and must not therefore be merged: the log's `reason`
        field is what tells *our mapping is incomplete* from *our perimeter is misconfigured*.
        """
        assert ActorUnresolvable is not ToolNotMapped
        assert issubclass(ActorUnresolvable, Exception)
        assert issubclass(ToolNotMapped, Exception)
