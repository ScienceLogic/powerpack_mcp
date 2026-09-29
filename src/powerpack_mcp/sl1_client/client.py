"""
SL1 HTTP Client

This module provides ``Sl1Client``, one shared client for both SL1's REST API and its GraphQL
endpoint, with two accessors: ``request`` and ``graphql``. It mirrors ``lce_client.client``:
configuration in, no connections opened at construction, the credential applied per request, and
the URL composed structurally. GraphQL is the same host, scheme, credential and pool, so a second
``httpx.AsyncClient`` would double the pool against ``MemoryMax=512M`` for nothing.

What this client deliberately does not do:

- Retry. SL1 locks an account after three failed logins, after which every password, including
  the correct one, returns ``403``. A retry would spend a real person's remaining attempts.
- Cache clients per credential. Under credential forwarding that cache is per person, unbounded
  and never evicted: both a memory-growth and a privacy problem.
- Circuit-break. nginx's ``auth_request`` checks the credential against SL1 first, so a wrong
  credential is rejected before it reaches this client, and a breaker could not observe the
  failures it exists to stop. A tool that took its own host and credential would need this
  revisited; none does.
- Hold a credential. There is no SL1 credential in ``Config``; the caller's forwarded credential
  is a per-call parameter.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, Literal

import httpx

from powerpack_mcp.config import (
    POOL_KEEPALIVE_EXPIRY_SECONDS,
    POOL_MAX_CONNECTIONS,
    POOL_MAX_KEEPALIVE_CONNECTIONS,
    READ_TIMEOUT_CEILING_SECONDS,
)
from powerpack_mcp.errors import (
    LogEvent,
    Sl1EmptyResponse,
    Sl1GraphQlError,
    Sl1HttpError,
    Sl1MalformedResponse,
    Sl1Unreachable,
)
from powerpack_mcp.lce_client.target_host import is_valid_target_host
from powerpack_mcp.sl1_client.bounded_read import read_json_within_limit
from powerpack_mcp.sl1_client.paths import ensure_relative_path

if TYPE_CHECKING:
    import logging as _logging

    from powerpack_mcp.config import Config
    from powerpack_mcp.credentials import LceCredential

import logging

logger: _logging.Logger = logging.getLogger(__name__)

__all__ = ["GRAPHQL_PATH", "SL1_API_BASE_PATH", "Sl1Client"]

# SL1's REST base. Tools supply paths relative to this.
SL1_API_BASE_PATH: Final[str] = "/api"

# The GraphQL endpoint. SL1 mounts it at the root, not under ``SL1_API_BASE_PATH``, which is why
# ``graphql`` composes its own URL.
GRAPHQL_PATH: Final[str] = "/gql"

# The two statuses where an empty body is the correct shape rather than a defect. Deliberately not
# "any 2xx": a ``200 OK`` promises a representation, so an empty one really is malformed, and
# widening this would turn a broken ``200`` into a silent success. ``202`` means accepted with
# nothing to return yet; ``204`` is defined as bodyless.
_EMPTY_BODY_STATUSES: Final[frozenset[int]] = frozenset({202, 204})

# Cap on the SL1 status message echoed back. Long enough for real ones, such as
# ``event seq:<id> deleted`` and ``Discovery session queued for discovery``, and short enough that
# a hostile or broken header cannot bloat a tool result.
_STATUS_MESSAGE_MAX_CHARS: Final[int] = 200


def _sanitised_status_message(raw: str | None) -> str:
    """Make SL1's ``x-em7-status-message`` safe to put in a tool result and a log record.

    This header is foreign content, and it flows into both a caller-visible payload and the
    journal, so it gets the same treatment as other untrusted text in this codebase. Control
    characters are dropped, not escaped: a newline would forge a log line, and nothing worth
    keeping in a status message depends on one. An overlong value is truncated rather than
    rejected, because it is still evidence of what happened.
    """
    if not raw:
        return ""
    cleaned = "".join(ch for ch in raw if ch.isprintable())
    return cleaned[:_STATUS_MESSAGE_MAX_CHARS].strip()


class Sl1Client:
    """Send REST and GraphQL requests to SL1 over one shared connection pool.

    Construction opens no connections: ``httpx.AsyncClient`` builds its pool lazily, so
    ``__init__`` has no side effects.
    """

    __slots__ = ("_client", "_closed", "_config")

    def __init__(self, config: Config) -> None:
        self._config = config
        self._closed = False
        self._client = httpx.AsyncClient(
            # Shared with LCE deliberately. ``_build_url`` uses ``https`` to the same
            # appliance-local host, so both backends present the same certificate, and a separate
            # ``SL1_VERIFY_TLS`` would describe a distinction that does not exist.
            verify=config.LCE_VERIFY_TLS,
            # The LCE timeouts are reused rather than adding SL1 keys. That also inherits the 85s
            # ceiling, which the request deadline and the systemd stop timeout rely on.
            timeout=httpx.Timeout(
                connect=config.LCE_CONNECT_TIMEOUT_SECONDS,
                read=config.LCE_READ_TIMEOUT_SECONDS,
                write=config.LCE_READ_TIMEOUT_SECONDS,
                pool=config.LCE_CONNECT_TIMEOUT_SECONDS,
            ),
            # The shared pool constants; one pool serves both accessors.
            limits=httpx.Limits(
                max_connections=POOL_MAX_CONNECTIONS,
                max_keepalive_connections=POOL_MAX_KEEPALIVE_CONNECTIONS,
                keepalive_expiry=POOL_KEEPALIVE_EXPIRY_SECONDS,
            ),
        )

    # ---- internals ------------------------------------------------------------------------------

    def _resolve_host(self) -> str:
        """Return the configured SL1 host, validated again.

        Startup validation already rejected a malformed value; this is the second layer, mirroring
        ``LceClient._resolve_target_host``. There is deliberately no per-call override: no tool
        accepts a target host, so a caller cannot redirect a request to another host.
        """
        host = self._config.SL1_DEFAULT_TARGET_HOST
        if not is_valid_target_host(host):  # pragma: no cover - unreachable via validated Config
            raise Sl1Unreachable("sl1")
        return host

    def _build_url(self, host: str, path: str, query: dict[str, str] | None) -> httpx.URL:
        """Compose the URL through httpx's own construction.

        The host is never concatenated into a string, and query parameters go through the
        library's encoder. That is why ``SL1_DEFAULT_TARGET_HOST`` holds a host rather than a base
        URL.
        """
        url = httpx.URL(scheme="https", host=host, path=path)
        if query:
            url = url.copy_merge_params(query)
        return url

    def _headers(self, credential: LceCredential) -> dict[str, str]:
        """Build outbound headers with the caller's credential attached.

        The credential writes itself into the headers. This client never handles the plaintext and
        holds no credential, so the shared pool carries no credential affinity.
        """
        headers: dict[str, str] = {"Accept": "application/json"}
        credential.apply_to_headers(headers)
        return headers

    def _warn_if_tls_relaxed(self) -> None:
        """Log a WARNING on every SL1 request made while TLS verification is relaxed.

        ``LceClient`` warns for its own traffic, but the flag is shared, so without this SL1
        traffic would run with verification off and no warning at all. Per request rather than
        once at startup: a startup line scrolls away, and the control stays off until someone
        changes it.
        """
        if not self._config.LCE_VERIFY_TLS:
            logger.warning(
                "TLS certificate verification is DISABLED for SL1 requests.",
                extra={"event": LogEvent.TLS_VERIFICATION_RELAXED},
            )

    async def _send(
        self,
        *,
        method: str,
        url: httpx.URL,
        headers: dict[str, str],
        json_body: object | None,
        raw_body: str | bytes | None = None,
        # Forwarded to httpx as a transport timeout, not used to race a task, so ASYNC109's advice
        # to prefer ``asyncio.timeout`` does not apply. The request deadline in the gate is the
        # racing mechanism, deliberately at one site rather than per call.
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> dict[str, Any] | list[Any]:
        """Issue one request and read the body under the response size cap.

        Uses ``client.stream`` rather than ``client.request``: a non-streaming call has already
        read the whole body into memory by the time it returns, so a cap applied afterwards would
        protect nothing.

        :param raw_body: A non-JSON body, sent as content. Mutually exclusive with ``json_body``;
            SL1's async operations take ``application/em7-resource-uri``.
        :param timeout: Overrides the pool timeout for this call. Already clamped by the caller and
            never clamped here, so one site decides the ceiling.
        :return: The parsed JSON body, or an ``accepted`` summary for an empty ``202``/``204``.
        :raises Sl1HttpError: On a status of 400 or above.
        :raises Sl1Unreachable: On a connect failure, timeout or protocol error.
        :raises Sl1ResponseTooLarge: If the body exceeds ``MAX_RESPONSE_BODY_BYTES``.
        :raises Sl1MalformedResponse: If a success body is empty or not a JSON object or array.
        """
        extra: dict[str, Any] = {}
        if raw_body is not None:
            extra["content"] = raw_body
        else:
            extra["json"] = json_body
        if timeout is not None:
            extra["timeout"] = timeout
        try:
            async with self._client.stream(method, url, headers=headers, **extra) as response:
                if response.status_code >= 400:
                    # The error body must be read to be reported, and it is foreign content, so it
                    # goes through the same cap. ``Sl1HttpError`` sanitises it in its constructor.
                    try:
                        body: dict[str, Any] | list[Any] | str = await read_json_within_limit(
                            response, limit_bytes=self._config.MAX_RESPONSE_BODY_BYTES
                        )
                    except Sl1MalformedResponse:
                        # A non-JSON error body is common and is not a new failure: the status is
                        # what the caller needs, and a parse complaint would hide a useful 404.
                        body = ""
                    raise Sl1HttpError(response.status_code, body)
                if response.status_code in _EMPTY_BODY_STATUSES:
                    # SL1 answers some writes, such as clearing an event or starting a discovery
                    # session, with ``202``, an empty body and a success message in
                    # ``x-em7-status-message``. That is correct REST; reporting it as malformed
                    # would make every successful write look like a failure.
                    #
                    # A ``202`` with a real JSON body still parses normally, so this wraps the
                    # normal read rather than replacing it.
                    try:
                        return await read_json_within_limit(
                            response, limit_bytes=self._config.MAX_RESPONSE_BODY_BYTES
                        )
                    except Sl1EmptyResponse:
                        return {
                            "status": "accepted",
                            "http_status": response.status_code,
                            "message": _sanitised_status_message(
                                response.headers.get("x-em7-status-message")
                            ),
                        }
                return await read_json_within_limit(
                    response, limit_bytes=self._config.MAX_RESPONSE_BODY_BYTES
                )
        except (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.WriteTimeout,
            httpx.PoolTimeout,
            httpx.RemoteProtocolError,
        ) as exc:
            # Report the host only, and nothing of the library's exception text.
            raise Sl1Unreachable(url.host) from exc

    # ---- public accessors -----------------------------------------------------------------------

    async def request(
        self,
        *,
        credential: LceCredential,
        method: Literal["GET", "POST", "PUT", "DELETE"],
        path: str,
        query: dict[str, str] | None = None,
        json_body: object | None = None,
        raw_body: str | bytes | None = None,
        content_type: str = "application/json",
        # ASYNC109: see `_send`; a transport timeout, not a race.
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> dict[str, Any] | list[Any]:
        """Issue one authenticated, timed, size-capped SL1 REST call.

        ``path`` is validated before anything is sent, so a bad request is rejected before any
        work is done.

        :param credential: The caller's forwarded credential.
        :param method: The HTTP method.
        :param path: A path relative to ``SL1_API_BASE_PATH``.
        :param query: Query parameters, encoded by httpx.
        :param json_body: The JSON request body.
        :param raw_body: A non-JSON body, sent with ``content_type``.
        :param content_type: The ``Content-Type`` for ``raw_body``. SL1's async operations (starting
            a discovery session, applying a device template) take ``application/em7-resource-uri``
            with a bare URI as the body, and do not work when sent as JSON.
        :param timeout: Per-call timeout in seconds. Clamped here to
            ``READ_TIMEOUT_CEILING_SECONDS``, so a larger value is never honoured for any caller.
        :return: The parsed JSON body.
        :raises ValidationBlocked: If ``path`` is not a safe relative path.
        """
        relative = ensure_relative_path(path)
        host = self._resolve_host()
        self._warn_if_tls_relaxed()
        url = self._build_url(
            host, f"{SL1_API_BASE_PATH}/{relative.lstrip('/')}".replace("//", "/"), query
        )
        headers = self._headers(credential)
        if raw_body is not None:
            headers["Content-Type"] = content_type
        return await self._send(
            method=method,
            url=url,
            headers=headers,
            json_body=json_body,
            raw_body=raw_body,
            timeout=_clamp_timeout(timeout),
        )

    async def graphql(
        self,
        *,
        credential: LceCredential,
        query: str,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
        # ASYNC109: see `_send`; a transport timeout.
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> dict[str, Any]:
        """Issue one GraphQL call.

        HTTP 200 can mean failure: GraphQL reports query errors inside a successful response, so a
        status check alone would hand the caller ``{"data": null}`` as success. That case gets its
        own error, because the transport succeeded (so it is not an HTTP error) and this service
        did not refuse the input (so it is not a validation error).

        :param credential: The caller's forwarded credential.
        :param query: The GraphQL document.
        :param variables: GraphQL variables.
        :param operation_name: The operation to run, when the document holds several.
        :param timeout: Per-call timeout in seconds, clamped as for ``request``.
        :return: The response object.
        :raises Sl1GraphQlError: If ``errors`` is present and non-empty.
        :raises Sl1MalformedResponse: If the response is not a JSON object.
        """
        host = self._resolve_host()
        self._warn_if_tls_relaxed()
        url = self._build_url(host, GRAPHQL_PATH, None)
        envelope: dict[str, Any] = {"query": query}
        if variables:
            envelope["variables"] = variables
        if operation_name:
            # Only sent when given: some servers reject ``operationName: null`` for a document with
            # one operation, so omitting it is safer.
            envelope["operationName"] = operation_name
        body = await self._send(
            method="POST",
            url=url,
            headers=self._headers(credential),
            json_body=envelope,
            timeout=_clamp_timeout(timeout),
        )
        if not isinstance(body, dict):
            # A GraphQL response is a JSON object by specification. A list is not something to
            # interpret.
            raise Sl1MalformedResponse
        errors = body.get("errors")
        if isinstance(errors, list) and errors:
            # Messages and codes come from the same list in the same order, so they stay
            # positional.
            raise Sl1GraphQlError(
                [_error_message(item) for item in errors],
                [_error_code(item) for item in errors],
            )
        return body

    async def aclose(self) -> None:
        """Release the pool. Idempotent, so shutdown ordering cannot double-close."""
        if not self._closed:
            self._closed = True
            await self._client.aclose()


def _clamp_timeout(timeout: float | None) -> float | None:
    """Bound a caller-supplied timeout by the validated read-timeout ceiling.

    Clamped, not rejected: an over-large timeout is a caller misjudging how long to wait, not an
    attack. A non-positive value would mean "time out immediately", which no caller can want, so it
    falls back to the pool default. Reuses ``READ_TIMEOUT_CEILING_SECONDS`` so the SL1 path cannot
    drift from the ceiling applied to ``LCE_READ_TIMEOUT_SECONDS``.

    :return: The clamped timeout, or ``None`` to use the pool default.
    """
    if timeout is None or timeout <= 0:
        return None
    return min(timeout, READ_TIMEOUT_CEILING_SECONDS)


def _error_code(item: object) -> str:
    """Pull ``extensions.code`` out of one GraphQL error entry, or ``""``.

    ``""`` rather than ``None`` or omission, because the result is positional with the messages:
    dropping an entry would shift every later code onto the wrong message.

    Observed codes include ``RESTRICTED_ACCESS`` (a permission denial; retrying cannot help) and
    ``GRAPHQL_VALIDATION_FAILED`` (a bad query the caller can fix). Anything unexpected returns
    ``""`` and gets generic handling, rather than guessing at a meaning SL1 did not send.
    """
    if isinstance(item, dict):
        extensions = item.get("extensions")
        if isinstance(extensions, dict):
            code = extensions.get("code")
            if isinstance(code, str):
                return code
    return ""


def _error_message(item: object) -> str:
    """Pull a message out of one GraphQL error entry, whatever shape it arrives in.

    A dict with ``message`` is the specified form; anything else is stringified rather than
    dropped. Dropping would leave the caller with "N errors" and nothing to act on.
    """
    if isinstance(item, dict):
        message = item.get("message")
        if isinstance(message, str):
            return message
    return str(item)
