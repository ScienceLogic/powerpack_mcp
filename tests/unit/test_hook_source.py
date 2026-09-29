"""
Hook Source Tests

This module tests ``powerpack_mcp.hook_source``: parsing SL1's access-hook answer, fetching it
from the self-scoped endpoint, and the per-account TTL cache. Like ``test_sl1_client`` it uses
``httpx.MockTransport`` throughout, so no appliance, credential or network is needed, and "the
request was never issued" or "one request across two calls" can be asserted directly.

Refusal cases come first, because the deny path is the security-relevant one, and each also
asserts what did not reach SL1.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from powerpack_mcp.config import Config
from powerpack_mcp.credentials import LceCredential
from powerpack_mcp.errors import Sl1HttpError, Sl1MalformedResponse, Sl1Unreachable
from powerpack_mcp.hook_source import (
    ACCESS_HOOKS_PATH,
    HOOK_SET_TTL_SECONDS,
    MAX_HOOK_ID_CHARS,
    MAX_HOOK_PAYLOAD_ENTRIES,
    HookCache,
    Sl1HookSource,
    parse_hook_payload,
)
from powerpack_mcp.sl1_client import Sl1Client


def _client_with(
    config: Config, handler: Callable[[httpx.Request], httpx.Response]
) -> tuple[Sl1Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    client = Sl1Client(config)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(recording))
    return client, seen


def _cred() -> LceCredential:
    return LceCredential(SecretStr("Basic dXNlcjpwYXNz"))


def _ok(body: Any) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _r: httpx.Response(200, json=body)


class _FakeClock:
    """A clock a test advances by hand, so no test sleeps.

    A real sleep with ``deadline=None`` would be slow and flaky, and would hide the slowness rather
    than remove it.
    """

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _RecordingSource:
    """A `HookSource` that counts calls and can be told to fail. Never opens a socket."""

    def __init__(self, hooks: frozenset[str], failure: Exception | None = None) -> None:
        self.hooks = hooks
        self.failure = failure
        self.calls = 0

    async def hooks_for(self, credential: LceCredential) -> frozenset[str]:  # noqa: ARG002
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return self.hooks


# ---- The pure half. Refusals first. ----


class TestParseHookPayloadRefuses:
    """Every malformed answer raises. None becomes an empty set."""

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({"error": "nope"}, id="dict-error-envelope"),
            pytest.param(None, id="null"),
            pytest.param("ACT_MY_PAGE", id="bare-string"),
            pytest.param(42, id="integer"),
        ],
    )
    def test_a_non_list_body_is_refused(self, body: object) -> None:
        """A dict is the realistic case, not theoretical: it is SL1's error-envelope shape."""
        with pytest.raises(Sl1MalformedResponse):
            parse_hook_payload(body)

    @pytest.mark.parametrize(
        "element",
        [
            pytest.param("", id="empty-string"),
            pytest.param(123, id="not-a-string"),
            pytest.param(None, id="null-element"),
            pytest.param("X" * (MAX_HOOK_ID_CHARS + 1), id="over-long"),
        ],
    )
    def test_an_implausible_element_refuses_the_whole_answer(self, element: object) -> None:
        """Refused, not skipped, and the difference is the point.

        Skipping would silently narrow the caller's entitlement, producing a denial that looks like
        a permissions problem and sends someone to the wrong place to fix it.
        """
        with pytest.raises(Sl1MalformedResponse):
            parse_hook_payload(["DEV_VIEW", element])

    def test_an_over_long_answer_is_refused(self) -> None:
        """The answer is bounded before anything can be cached."""
        with pytest.raises(Sl1MalformedResponse):
            parse_hook_payload(["DEV_VIEW"] * (MAX_HOOK_PAYLOAD_ENTRIES + 1))

    def test_no_refusal_path_returns_a_value(self) -> None:
        """Every malformed shape raises rather than returning anything at all.

        Reading "no hooks retrieved" as "no restrictions apply" would turn a transient network error
        into a complete authorization bypass. A future edit that replaced one ``raise`` with
        ``return frozenset()`` fails here.
        """
        malformed: list[object] = [
            {},
            None,
            "",
            0,
            ["ok", ""],
            ["ok", 1],
            ["Y" * (MAX_HOOK_ID_CHARS + 1)],
            ["ok"] * (MAX_HOOK_PAYLOAD_ENTRIES + 1),
        ]
        for body in malformed:
            with pytest.raises(Sl1MalformedResponse):
                parse_hook_payload(body)


class TestParseHookPayloadAccepts:
    def test_the_bag_is_deduplicated(self) -> None:
        """A restricted account's live answer was 96 entries for 81 unique ids.

        ``lce_service``'s bare ``set(...)`` reads as a type conversion and is in fact load-bearing.
        """
        assert parse_hook_payload(["A", "B", "A", "C", "B"]) == frozenset({"A", "B", "C"})

    def test_an_empty_list_is_a_legitimate_answer_meaning_no_grants(self) -> None:
        """Not a failure. An account granted nothing gets an empty set, which then denies every
        gated tool because the gate is deny-by-default, not because parsing failed.
        """
        assert parse_hook_payload([]) == frozenset()

    def test_it_is_idempotent_over_its_own_output(self) -> None:
        once = parse_hook_payload(["DEV_VIEW", "DEV_VIEW", "EVT_VIEW"])
        assert parse_hook_payload(sorted(once)) == once

    def test_a_hook_at_exactly_the_length_bound_is_accepted(self) -> None:
        """The bound is inclusive. ``hook_id`` is ``varchar(32)``; the cap is extra headroom."""
        assert parse_hook_payload(["Z" * MAX_HOOK_ID_CHARS]) == frozenset({"Z" * MAX_HOOK_ID_CHARS})


# ---- The I/O half ----


class TestSl1HookSource:
    @pytest.mark.anyio
    async def test_it_asks_the_self_scoped_endpoint(self, config: Config) -> None:
        """``_self``, and no account id anywhere in the URL.

        A path carrying an id can be aimed at another account, and the id would have to come from
        the request, which is the shape of a privilege-minting bug. This asserts the URL contains
        ``_self`` and no digits, so a future edit interpolating a uid fails here.
        """
        client, seen = _client_with(config, _ok(["DEV_VIEW"]))
        await Sl1HookSource(client, timeout=5.0).hooks_for(_cred())
        (request,) = seen
        assert request.method == "GET"
        assert request.url.path.endswith("/api/account/_self/access_hooks")
        assert ACCESS_HOOKS_PATH == "account/_self/access_hooks"
        account_segment = request.url.path.split("/api/account/")[1].split("/")[0]
        assert account_segment == "_self"
        assert not any(c.isdigit() for c in account_segment)

    @pytest.mark.anyio
    async def test_a_non_2xx_propagates_and_yields_no_hooks(self, config: Config) -> None:
        client, seen = _client_with(config, lambda _r: httpx.Response(403, json={"e": "denied"}))
        with pytest.raises(Sl1HttpError):
            await Sl1HookSource(client, timeout=5.0).hooks_for(_cred())
        assert len(seen) == 1

    @pytest.mark.anyio
    async def test_a_transport_failure_propagates(self, config: Config) -> None:
        def refuse(_r: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        client, _ = _client_with(config, refuse)
        with pytest.raises(Sl1Unreachable):
            await Sl1HookSource(client, timeout=5.0).hooks_for(_cred())

    @pytest.mark.anyio
    async def test_a_dict_body_is_refused_rather_than_interpreted(self, config: Config) -> None:
        client, _ = _client_with(config, _ok({"access_hooks": ["DEV_VIEW"]}))
        with pytest.raises(Sl1MalformedResponse):
            await Sl1HookSource(client, timeout=5.0).hooks_for(_cred())

    def test_the_timeout_is_required(self) -> None:
        """A guard that cannot fail is not a guard.

        ``lce_service``'s equivalent lookup has no timeout at all, so an unresponsive oracle hangs
        its worker rather than denying. A default here would let a call site inherit that.
        """
        with pytest.raises(TypeError):
            Sl1HookSource(client=None)  # type: ignore[call-arg, arg-type]


# ---- The cache ----


class TestHookCache:
    @pytest.mark.anyio
    async def test_a_second_call_inside_the_ttl_does_not_refetch(self) -> None:
        """The call count is the assertion: a cache that re-fetches is not a cache."""
        source = _RecordingSource(frozenset({"DEV_VIEW"}))
        clock = _FakeClock()
        cache = HookCache(source, clock=clock)
        assert await cache.hooks_for_account(4, _cred()) == frozenset({"DEV_VIEW"})
        clock.advance(HOOK_SET_TTL_SECONDS / 2)
        assert await cache.hooks_for_account(4, _cred()) == frozenset({"DEV_VIEW"})
        assert source.calls == 1

    @pytest.mark.anyio
    async def test_an_expired_entry_is_refetched(self) -> None:
        source = _RecordingSource(frozenset({"DEV_VIEW"}))
        clock = _FakeClock()
        cache = HookCache(source, clock=clock)
        await cache.hooks_for_account(4, _cred())
        clock.advance(HOOK_SET_TTL_SECONDS + 0.001)
        await cache.hooks_for_account(4, _cred())
        assert source.calls == 2

    @pytest.mark.anyio
    async def test_the_revocation_window_is_at_most_the_ttl(self) -> None:
        """A revoked hook is still honoured until the entry expires, and no longer.

        This asserts the accepted revocation window rather than pretending hooks are validated on
        every request.
        """
        source = _RecordingSource(frozenset({"DEV_CLASS_EDIT"}))
        clock = _FakeClock()
        cache = HookCache(source, clock=clock)
        await cache.hooks_for_account(4, _cred())
        source.hooks = frozenset()  # revoked in SL1
        clock.advance(HOOK_SET_TTL_SECONDS - 0.001)
        assert await cache.hooks_for_account(4, _cred()) == frozenset({"DEV_CLASS_EDIT"})
        clock.advance(0.002)
        assert await cache.hooks_for_account(4, _cred()) == frozenset()


class TestHookCacheIsolation:
    """One caller's grants can never authorize another's call."""

    @pytest.mark.anyio
    async def test_two_principals_do_not_share_an_entry(self) -> None:
        calls: list[int] = []

        class PerAccountSource:
            def __init__(self) -> None:
                self.next: frozenset[str] = frozenset()

            async def hooks_for(self, credential: LceCredential) -> frozenset[str]:  # noqa: ARG002
                calls.append(1)
                return self.next

        source = PerAccountSource()
        cache = HookCache(source, clock=_FakeClock())

        source.next = frozenset({"DEV_CLASS_EDIT"})
        privileged = await cache.hooks_for_account(1, _cred())
        source.next = frozenset({"DEV_VIEW"})
        restricted = await cache.hooks_for_account(4, _cred())

        assert privileged == frozenset({"DEV_CLASS_EDIT"})
        assert restricted == frozenset({"DEV_VIEW"})
        assert "DEV_CLASS_EDIT" not in restricted
        assert len(calls) == 2, "each principal must be resolved on its own, never inherited"

    @pytest.mark.anyio
    async def test_a_populated_cache_does_not_answer_for_an_unseen_principal(self) -> None:
        """The absence assertion: uid 1 being cached must not make uid 4 a hit."""
        source = _RecordingSource(frozenset({"DEV_CLASS_EDIT"}))
        cache = HookCache(source, clock=_FakeClock())
        await cache.hooks_for_account(1, _cred())
        await cache.hooks_for_account(4, _cred())
        assert source.calls == 2


class TestHookCacheFailsClosed:
    @pytest.mark.anyio
    async def test_a_failing_fetch_propagates(self) -> None:
        source = _RecordingSource(frozenset(), failure=Sl1Unreachable("sl1"))
        cache = HookCache(source, clock=_FakeClock())
        with pytest.raises(Sl1Unreachable):
            await cache.hooks_for_account(4, _cred())

    @pytest.mark.anyio
    async def test_a_failure_after_expiry_does_not_serve_the_stale_entry(self) -> None:
        """Falling back to an expired set on a failed refresh is as bad as the empty-set bypass.

        It would decide authorization on out-of-date data. The entry is dropped before the fetch,
        so a raise cannot leave it reachable for a later call either.
        """
        source = _RecordingSource(frozenset({"DEV_CLASS_EDIT"}))
        clock = _FakeClock()
        cache = HookCache(source, clock=clock)
        await cache.hooks_for_account(4, _cred())

        source.failure = Sl1Unreachable("sl1")
        clock.advance(HOOK_SET_TTL_SECONDS + 0.001)
        with pytest.raises(Sl1Unreachable):
            await cache.hooks_for_account(4, _cred())

        # And it is gone, not merely unserved this once.
        source.failure = None
        source.hooks = frozenset({"DEV_VIEW"})
        assert await cache.hooks_for_account(4, _cred()) == frozenset({"DEV_VIEW"})

    @pytest.mark.anyio
    async def test_invalidate_forces_a_refetch(self) -> None:
        source = _RecordingSource(frozenset({"DEV_VIEW"}))
        cache = HookCache(source, clock=_FakeClock())
        await cache.hooks_for_account(4, _cred())
        cache.invalidate(4)
        await cache.hooks_for_account(4, _cred())
        assert source.calls == 2

    @pytest.mark.anyio
    async def test_the_cache_holds_no_credential(self) -> None:
        """An ``LceCredential`` does not outlive its request, so none is stored.

        Asserted by inspecting what the entry holds: an expiry and a set of plain strings, and
        nothing else.
        """
        source = _RecordingSource(frozenset({"DEV_VIEW"}))
        cache = HookCache(source, clock=_FakeClock())
        await cache.hooks_for_account(4, _cred())
        (expires_at, hooks) = cache._entries[4]
        assert isinstance(expires_at, float)
        assert isinstance(hooks, frozenset)
        assert all(isinstance(h, str) for h in hooks)
        assert not any(isinstance(v, LceCredential) for v in cache._entries.values())
