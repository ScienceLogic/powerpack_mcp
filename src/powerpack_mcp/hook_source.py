"""
Caller Access-Hook Resolution

This module resolves the SL1 access hooks granted to a caller and caches them briefly. It answers
"what may this caller do"; ``authz`` holds each tool's hook requirement, and
``mcp_app.authz_gate`` makes the decision. SL1 answers ``/api/account/_self/access_hooks`` for the
credential that asks, so the result is the caller's own entitlement, not a service account's.

The cache is bounded in three ways: entries expire after ``HOOK_SET_TTL_SECONDS``, the key is the
numeric account uid nginx forwards rather than anything derived from the credential, and
``MAX_HOOK_PAYLOAD_ENTRIES`` caps what one answer may contribute. No credential material is held,
hashed or copied.

The cache key comes from the ``X-User-ID`` header and the cached value from the credential. If
they could disagree, one caller's hooks would be filed under another's key. In a supported
deployment they cannot: nginx derives ``X-User-ID`` from its own ``auth_request`` subrequest
against the same credential and sets it with ``proxy_set_header``, overwriting anything the client
sent, and ``authz_gate`` refuses a request with no id. Also fetching ``/api/account/_self`` and
comparing its ``user`` field would close this fully, but was not built because it doubles the
load the TTL exists to bound.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Final, Protocol

from powerpack_mcp.errors import Sl1MalformedResponse

if TYPE_CHECKING:
    from collections.abc import Callable

    from powerpack_mcp.credentials import LceCredential
    from powerpack_mcp.sl1_client import Sl1Client

__all__ = [
    "ACCESS_HOOKS_PATH",
    "HOOK_SET_TTL_SECONDS",
    "MAX_HOOK_ID_CHARS",
    "MAX_HOOK_PAYLOAD_ENTRIES",
    "HookCache",
    "HookSource",
    "Sl1HookSource",
    "parse_hook_payload",
]

logger = logging.getLogger(__name__)

# SL1's self-scoped entitlement endpoint, relative to ``sl1_client``'s ``/api`` base.
#
# Always ``_self``, never ``account/{id}/access_hooks``. A path carrying an id can be aimed at
# another account, and the id would have to come from the request, which is how a caller could
# redirect the lookup and mint privileges. ``_self`` is scoped to whoever presents the credential,
# so there is no id to forge.
ACCESS_HOOKS_PATH: Final[str] = "account/_self/access_hooks"

# Stricter than the platform itself: SL1 caches an account's access keys for 86400 seconds
# (``deepcache::write(..., 86400)`` in ``access_hooks.inc``), so it already honours a revoked key
# for up to 24 hours.
HOOK_SET_TTL_SECONDS: Final[float] = 60.0

# A cap on payload entries before deduplication, not on the resulting hook set. The payload is a
# bag, not a set: one restricted account's answer carried 96 entries for 81 unique hooks. The full
# vocabulary (575 rows in ``master_access.hooks``) plus duplication sits well inside this cap.
MAX_HOOK_PAYLOAD_ENTRIES: Final[int] = 8192

# ``master_access.hooks.hook_id`` is ``varchar(32) PRIMARY KEY``. Doubled so a schema widening on
# SL1's side cannot take the whole gate down: any malformed answer is refused, so an over-tight
# bound here would be an outage, not a control.
MAX_HOOK_ID_CHARS: Final[int] = 64


def parse_hook_payload(body: object) -> frozenset[str]:
    """Parse SL1's ``/access_hooks`` answer into a set of hook ids.

    Every rejection raises. Reading "no hooks retrieved" as "no restrictions apply" would turn a
    transient network error into a complete authorization bypass, so there is no path on which a
    malformed answer becomes an empty set. An empty set is a legitimate answer meaning the account
    is granted nothing, which denies everything.

    Deduplication matters: the endpoint returns a bag, and keeping the list would carry duplicates
    into every comparison and every log record.

    The result is always a ``frozenset[str]`` no longer than the input, containing exactly the
    input's elements; the function is idempotent over its own output and returns an empty set
    only for an empty input list.

    :param body: The decoded JSON body.
    :return: The granted hook ids.
    :raises Sl1MalformedResponse: If the body is not a list, is longer than
        ``MAX_HOOK_PAYLOAD_ENTRIES``, or holds an element that is not a plausible hook id. The
        answer came from SL1, so SL1's malformed-response type is reused.
    """
    if not isinstance(body, list):
        # A dict is the shape SL1 uses for an error envelope, so this is the likely real-world case.
        # No salvage is attempted.
        logger.warning(
            "Access-hook answer was not a list; refusing.",
            extra={"body_type": type(body).__name__},
        )
        raise Sl1MalformedResponse
    if len(body) > MAX_HOOK_PAYLOAD_ENTRIES:
        logger.warning(
            "Access-hook answer exceeded the entry cap; refusing.",
            extra={"entries": len(body), "cap": MAX_HOOK_PAYLOAD_ENTRIES},
        )
        raise Sl1MalformedResponse

    hooks: set[str] = set()
    for element in body:
        if not isinstance(element, str) or not element or len(element) > MAX_HOOK_ID_CHARS:
            # Refused rather than skipped. Skipping would silently narrow the caller's entitlement,
            # producing a denial that looks like a permission problem.
            logger.warning("Access-hook answer held an implausible element; refusing.")
            raise Sl1MalformedResponse
        hooks.add(element)
    return frozenset(hooks)


class HookSource(Protocol):
    """Where a caller's granted hooks come from.

    A Protocol so the authorization gate can be tested with no appliance, network or credential: a
    test substitutes a source that never opens a socket.
    """

    async def hooks_for(self, credential: LceCredential) -> frozenset[str]:
        """Return the hook ids SL1 grants the account presenting ``credential``."""
        ...


class Sl1HookSource:
    """The production ``HookSource``, which reuses the shared ``Sl1Client``.

    A separate client would break the one-shared-SL1-client rule and double the connection pool
    against the unit's ``MemoryMax``. Reuse also inherits ``LCE_VERIFY_TLS``, the 85s timeout
    ceiling, and ``_warn_if_tls_relaxed``, which warns on every affected request; a second client
    that omitted that warning would hide relaxed TLS on exactly the traffic that decides
    authorization. With TLS verification relaxed, every uncached fetch therefore logs a WARNING,
    and the TTL keeps that bounded.

    This object holds no credential. One arrives per call and applies itself to the outbound
    headers.
    """

    __slots__ = ("_client", "_timeout")

    def __init__(self, client: Sl1Client, timeout: float) -> None:
        """Create a hook source over the shared SL1 client.

        :param client: The shared SL1 client.
        :param timeout: Request timeout in seconds. Required, with no default, so no call site can
            get an unbounded wait: an unresponsive SL1 must produce a denial, not a hung worker.
        """
        self._client = client
        self._timeout = timeout

    async def hooks_for(self, credential: LceCredential) -> frozenset[str]:
        """Fetch and parse the caller's hooks, or raise. Never returns a default.

        :param credential: The caller's forwarded credential.
        :return: The granted hook ids.
        :raises Sl1HttpError: If SL1 returns a non-2xx status.
        :raises Sl1Unreachable: On a connect failure or timeout.
        :raises Sl1MalformedResponse: If the body cannot be parsed.
        """
        body = await self._client.request(
            credential=credential,
            method="GET",
            path=ACCESS_HOOKS_PATH,
            timeout=self._timeout,
        )
        return parse_hook_payload(body)


class HookCache:
    """Cache each account's hook set for a short TTL, in process memory only.

    Nothing is written anywhere: entries live in a dict for at most ``HOOK_SET_TTL_SECONDS`` and
    die with the process, so no encryption at rest is needed.

    Keyed on the numeric ``master_access.accounts.uid`` that nginx forwards. The username parsed
    from the ``Authorization`` header would not work: it is ``None`` for every non-Basic scheme,
    and API keys authenticate as ``Authorization: Bearer``, so every API-key caller would share one
    entry. nginx sets the forwarded id with ``proxy_set_header``, so a caller cannot choose their
    own key. See the module docstring for the one residual this leaves.

    A revoked hook stays honoured for up to ``HOOK_SET_TTL_SECONDS``. That is an accepted deviation
    from validating on every request; SL1 itself caches the same keys for 24 hours.

    ``clock`` is injected so expiry tests need no real sleeps. It defaults to ``time.monotonic``,
    not ``time.time``: a wall-clock step backwards would extend an entry's life, and a step forwards
    would expire it early.
    """

    __slots__ = ("_clock", "_entries", "_source", "_ttl")

    def __init__(
        self,
        source: HookSource,
        *,
        ttl_seconds: float = HOOK_SET_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._source = source
        self._ttl = ttl_seconds
        self._clock = clock
        self._entries: dict[int, tuple[float, frozenset[str]]] = {}

    async def hooks_for_account(self, account_id: int, credential: LceCredential) -> frozenset[str]:
        """Return ``account_id``'s hooks, from cache if fresh, else fetched.

        A failed fetch propagates and the stale entry is not served. Falling back to an expired set
        would turn a network failure into an authorization decision made on out-of-date data.

        :param account_id: The account uid forwarded by nginx.
        :param credential: The caller's forwarded credential, used only on a cache miss.
        :return: The granted hook ids.
        """
        now = self._clock()
        cached = self._entries.get(account_id)
        if cached is not None:
            expires_at, hooks = cached
            if now < expires_at:
                return hooks
            # Dropped before the fetch, so a raising fetch cannot leave a stale entry behind for a
            # later call to hit.
            del self._entries[account_id]

        hooks = await self._source.hooks_for(credential)
        self._entries[account_id] = (self._clock() + self._ttl, hooks)
        return hooks

    def invalidate(self, account_id: int) -> None:
        """Forget ``account_id``'s entry. Present for tests and for an operator-triggered flush.

        Deliberately not wired to anything in the request path: an endpoint that flushed another
        account's entry would be a denial-of-service primitive.
        """
        self._entries.pop(account_id, None)
