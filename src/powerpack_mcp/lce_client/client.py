"""
LCE HTTP Client

This module provides ``LceClient``, which issues one authenticated, timed, TLS-verified, pooled
request against the LCE API and translates failure into three distinguishable exceptions. It knows
nothing about PowerPacks, Dynamic Applications or Event Policies.

The client holds no credential. One is supplied per call, so the shared connection pool carries no
credential affinity and each request travels with the credential of the user who made it.

Nothing is retried. Some operations are writes whose idempotency this service cannot establish,
so an automatic retry could double-apply a change LCE already committed. The caller decides
whether to retry.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Literal

import httpx

from powerpack_mcp.config import (
    POOL_KEEPALIVE_EXPIRY_SECONDS,
    POOL_MAX_CONNECTIONS,
    POOL_MAX_KEEPALIVE_CONNECTIONS,
    Config,
)
from powerpack_mcp.errors import (
    LceHttpError,
    LceMalformedResponse,
    LceUnreachable,
    LogEvent,
)
from powerpack_mcp.lce_client.target_host import TargetHost, is_valid_target_host

if TYPE_CHECKING:
    from powerpack_mcp.credentials import LceCredential

__all__ = [
    "LCE_BASE_PATH",
    "LceClient",
    "LceResponse",
]

logger = logging.getLogger(__name__)

# The LCE API's Swagger 2.0 ``basePath``. HTTPS only; there is no way to configure plain HTTP.
LCE_BASE_PATH: Final[str] = "/lce/api"


@dataclass(frozen=True, slots=True)
class LceResponse:
    """One successful LCE reply.

    Frozen, so nothing downstream can mutate it. Only constructed for a 2xx response: a non-2xx
    becomes ``LceHttpError`` first, so a caller holding one never has to check the status.

    :ivar status_code: The HTTP status code.
    :ivar body: The decoded JSON object or array.
    """

    status_code: int
    body: dict[str, Any] | list[Any]


class LceClient:
    """Send requests to LCE over a shared connection pool.

    Construction does not open connections: ``httpx.AsyncClient`` builds its pool lazily, so
    ``__init__`` has no side effects.
    """

    __slots__ = ("_client", "_closed", "_config")

    def __init__(self, config: Config) -> None:
        self._config = config
        self._closed = False
        self._client = httpx.AsyncClient(
            # Verification is on by default; relaxing it is explicit.
            verify=config.LCE_VERIFY_TLS,
            # Every timeout is explicit, including write and pool, so nothing inherits an implicit
            # or unbounded value.
            timeout=httpx.Timeout(
                connect=config.LCE_CONNECT_TIMEOUT_SECONDS,
                read=config.LCE_READ_TIMEOUT_SECONDS,
                write=config.LCE_READ_TIMEOUT_SECONDS,
                pool=config.LCE_CONNECT_TIMEOUT_SECONDS,
            ),
            # Deliberately small. The library default is sized for a high-traffic web service; this
            # is a disabled-by-default appliance service with a small memory footprint.
            limits=httpx.Limits(
                max_connections=POOL_MAX_CONNECTIONS,
                max_keepalive_connections=POOL_MAX_KEEPALIVE_CONNECTIONS,
                keepalive_expiry=POOL_KEEPALIVE_EXPIRY_SECONDS,
            ),
        )

    def _resolve_target_host(self, target_host: TargetHost | None) -> str:
        """Pick the destination and validate it again.

        Pydantic already rejected an invalid value at the tool signature; this catches anything
        reaching the client by another route.

        :raises LceUnreachable: If the host is invalid. The message never echoes the value.
        """
        host = target_host if target_host is not None else self._config.LCE_DEFAULT_TARGET_HOST
        if not is_valid_target_host(host):
            # Name the rule that was broken; never echo the offending value back.
            raise LceUnreachable(_safe_host_label(host))
        return host

    def _build_url(self, host: str, path: str, query: dict[str, str] | None) -> httpx.URL:
        """Compose the URL through httpx's own construction.

        The host is never concatenated into a URL string, and query parameters go through the
        library's encoder rather than being formatted in.
        """
        url = httpx.URL(scheme="https", host=host, path=f"{LCE_BASE_PATH}{path}")
        if query:
            url = url.copy_merge_params(query)
        return url

    def _headers(self, credential: LceCredential) -> dict[str, str]:
        """Build outbound headers with the caller's credential attached.

        Applied to every request, so there is no unauthenticated outbound path. The credential
        writes itself into the headers; this module never handles the plaintext. It is a parameter
        rather than state, so nothing outlives the request that supplied it.
        """
        headers: dict[str, str] = {"Accept": "application/json"}
        credential.apply_to_headers(headers)
        return headers

    def _warn_if_tls_relaxed(self) -> None:
        """Log a WARNING on every request made while TLS verification is relaxed.

        A single warning at startup would scroll away; one per request keeps it visible for as
        long as the control is off.
        """
        if not self._config.LCE_VERIFY_TLS:
            logger.warning(
                "TLS certificate verification is DISABLED for LCE requests.",
                extra={"event": LogEvent.TLS_VERIFICATION_RELAXED},
            )

    async def request(
        self,
        *,
        credential: LceCredential,
        method: Literal["GET", "POST"],
        path: str,
        query: dict[str, str] | None = None,
        # A list as well as a dict: LCE documents top-level array payloads, and a dict-only type
        # would leave the caller nothing to pass one as.
        json_body: dict[str, Any] | list[Any] | None = None,
        target_host: TargetHost | None = None,
    ) -> LceResponse:
        """Issue one authenticated, timed, TLS-verified, pooled request against ``/lce/api``.

        Connections are released on every outcome. httpx returns each connection to the pool when
        the response is read, and it reads eagerly for a non-streaming request, so success, 4xx,
        5xx, timeout and malformed-body paths have all released by the time they return or raise.

        :param credential: The caller's forwarded credential.
        :param method: The HTTP method.
        :param path: The path below ``LCE_BASE_PATH``, starting with ``/``.
        :param query: Query parameters, encoded by httpx.
        :param json_body: The JSON request body.
        :param target_host: The LCE host; defaults to ``LCE_DEFAULT_TARGET_HOST``.
        :return: The successful response.
        :raises LceHttpError: On a non-2xx status.
        :raises LceUnreachable: On a connect failure, DNS failure or timeout, or an invalid host.
        :raises LceMalformedResponse: If the body is not a JSON object or array.
        """
        host = self._resolve_target_host(target_host)
        self._warn_if_tls_relaxed()
        url = self._build_url(host, path, query)

        try:
            response = await self._client.request(
                method, url, headers=self._headers(credential), json=json_body
            )
        except (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.PoolTimeout,
        ) as exc:
            # Carries the target host name only: not the resolved IP, not the port, and not the
            # library's exception text.
            raise LceUnreachable(host) from exc
        except httpx.TransportError as exc:
            # Every remaining transport-level failure is a reachability failure by another name.
            # Catching the base class rather than enumerating subclasses means a new httpx error
            # type cannot leak out as an unhandled exception carrying library detail.
            raise LceUnreachable(host) from exc

        if not response.is_success:
            # Preserve the LCE status and the LCE-supplied body, and nothing else.
            raise LceHttpError(response.status_code, _read_error_body(response))

        try:
            # The stdlib JSON parser only. Embedded YAML argument strings and snippet source stay
            # opaque strings and are never deserialised by this service.
            body = response.json()
        except (ValueError, RecursionError) as exc:
            # No attempt is made to salvage a partial document.
            #
            # ``RecursionError`` inherits from ``RuntimeError``, not ``ValueError``, so it must be
            # caught explicitly or a deeply nested response surfaces as a generic 500. CPython's C
            # JSON scanner refuses beyond 9,997 nesting levels with its own guard, independent of
            # ``sys.getrecursionlimit()``, so this is reachable from a response we do not control.
            raise LceMalformedResponse from exc

        if not isinstance(body, dict | list):
            # LCE is specified to return objects and arrays. A bare scalar is malformed for our
            # purposes, and saying so here keeps LceResponse.body's type honest rather than widening
            # it.
            raise LceMalformedResponse
        return LceResponse(status_code=response.status_code, body=body)

    async def aclose(self) -> None:
        """Release the connection pool. Idempotent.

        Idempotence matters because a repeated or duplicated ``SIGTERM`` must be harmless.
        """
        if self._closed:
            return
        self._closed = True
        await self._client.aclose()


def _read_error_body(response: httpx.Response) -> dict[str, Any] | list[Any] | str:
    """Extract the LCE-supplied error body, falling back to text.

    An error body that is not JSON is still useful to a caller, so unlike the success path this
    does not raise ``LceMalformedResponse``; discarding LCE's own explanation of a 4xx would help
    nobody.

    This function does not sanitise, and must not start. ``LceHttpError.__init__`` applies
    redaction and length capping through ``errors.sanitize_lce_body`` once, at construction, so no
    call site can bypass it. A second pass here would double-truncate and double-mark elisions.

    :return: The parsed JSON object or array, or the raw text.
    """
    try:
        parsed = response.json()
    except (ValueError, RecursionError):
        # ``RecursionError`` too, as on the success path: otherwise a deeply nested error body
        # escapes as a generic 500 and the caller loses the LCE status.
        return response.text
    if isinstance(parsed, dict | list):
        return parsed
    return response.text


def _safe_host_label(host: str) -> str:
    """Describe an invalid host without echoing it.

    Echoing caller-supplied input into an error message is a small reflection surface, and naming
    the rule that was broken is more actionable anyway.
    """
    del host
    return "<rejected target_host>"
