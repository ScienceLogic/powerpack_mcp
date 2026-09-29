"""
LCE Tool Pipeline

This module provides the generic pipeline every LCE tool runs through (``run_operation``) and
the ``tool_boundary`` decorator that turns exceptions into caller-visible error payloads and
writes the per-call log record. It is the only part of the LCE tool path that performs I/O or
logging, which keeps ``validation``, ``query`` and ``shaping`` pure and testable without fakes.

Every guard returns or raises before the LCE request, the first I/O. No guard sets a flag and
continues, so a create or update can never reach LCE after an earlier step produced a finding.
"""

from __future__ import annotations

import contextlib
import json
import logging
import time
from functools import wraps
from typing import TYPE_CHECKING, Any, ParamSpec, TypeVar

from fastmcp.server.dependencies import get_http_request

from powerpack_mcp import credentials
from powerpack_mcp.errors import (
    FindingCode,
    LceHttpError,
    LogEvent,
    PowerPackMcpError,
    ValidationBlocked,
    ValidationFinding,
    build_error_payload,
)
from powerpack_mcp.mcp_app.correlation import forwarded_actor, identity_or_none
from powerpack_mcp.query import (
    FilterParams,
    SelectorParams,
    WriteOptions,
    build_filter_params,
    build_selector_params,
    build_write_options,
)
from powerpack_mcp.shaping import shape_response
from powerpack_mcp.validation import MAX_PAYLOAD_DEPTH, PayloadRoot, exceeds_depth, validate_payload

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from powerpack_mcp.config import Config
    from powerpack_mcp.credentials import LceCredential
    from powerpack_mcp.lce_client import LceClient
    from powerpack_mcp.tools.descriptors import OperationDescriptor

__all__ = ["ToolContext", "run_operation", "tool_boundary"]

logger = logging.getLogger(__name__)

_LCE_AUTH_DENIED_STATUSES: frozenset[int] = frozenset({401, 403})

_P = ParamSpec("_P")
_R = TypeVar("_R")


class ToolContext:
    """What every tool function needs: the injected client and the configuration.

    ``LceClient`` is injected, never constructed here, so a test can substitute the transport and
    assert that a request was never issued to LCE.

    :ivar client: The shared LCE client.
    :ivar config: The service configuration.
    :ivar credential_source: Returns the current caller's LCE credential.
    """

    __slots__ = ("client", "config", "credential_source")

    def __init__(
        self,
        client: LceClient,
        config: Config,
        credential_source: Callable[[], LceCredential],
    ) -> None:
        self.client = client
        self.config = config
        # A callable, not a credential: ``ToolContext`` is process-scoped and cannot hold a
        # request-scoped value. Injecting it also lets a test supply a synthetic credential.
        self.credential_source = credential_source


def _current_actor() -> str | None:
    """Return the caller's identity for the log record, when there is an HTTP request.

    ``get_http_request()`` raises ``RuntimeError`` outside an HTTP context (for example when a unit
    test calls a tool function directly), so the lookup is suppressed and ``actor`` is omitted.

    The header is read through ``forwarded_actor`` so the sanitising rule lives in one place: the
    value lands in a log record, and an unsanitised newline would forge a log line.

    :return: The username or forwarded identity, or ``None`` if neither is available.
    """
    with contextlib.suppress(RuntimeError):
        scope = get_http_request().scope
        # Resolution order: the credential's username, then nginx's ``X-User-ID``, then omitted.
        # The credential is the identity LCE actually authorises, so it is more reliable than a
        # proxy-asserted header.
        #
        # This is an independent second read that shares no state with the pipeline's credential;
        # passing a credential-bearing object to the logging layer would weaken its containment.
        # The username is not secret, and the cost is one extra parse per call.
        #
        # Use ``identity_or_none``, not ``sanitize_correlation_id``. The latter replaces a
        # non-conforming value with a fresh UUID, which is right for a correlation id and wrong for
        # an identity: any username outside ``[A-Za-z0-9._-]`` (every email-form login) would
        # appear as a different fake principal in each audit record, which is worse than omission.
        #
        # A rejected username falls through to ``X-User-ID``, which nginx asserts and is still
        # trustworthy.
        username = identity_or_none(credentials.username_from_scope(scope))
        if username is not None:
            return username
        return forwarded_actor(scope)
    return None


def _log_extra(**fields: object) -> dict[str, object]:
    """Assemble a log record's structured fields, omitting ``actor`` when it is unavailable.

    A placeholder such as ``unknown`` would be indistinguishable from a principal genuinely named
    ``unknown``, so the field is omitted instead.
    """
    actor = _current_actor()
    if actor is not None:
        fields["actor"] = actor
    return fields


def _body_size_finding(payload: PayloadRoot, limit: int) -> ValidationFinding | None:
    """Check the payload against the request body size limit.

    This is the cheapest check and runs first. It measures the serialized JSON in UTF-8 bytes, the
    same unit as nginx's ``client_max_body_size``. With both at 10 MiB nginx may answer first with
    an HTML 413; this check is the intended rejection path because it returns a parseable JSON
    envelope.

    :param payload: The write payload.
    :param limit: The limit in bytes.
    :return: A finding if the payload is too large, otherwise ``None``.
    """
    encoded = len(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    if encoded <= limit:
        return None
    return ValidationFinding(
        path="",
        rule=FindingCode.REQUEST_BODY_SIZE,
        message=(
            f"The request payload is {encoded} bytes when serialized, which exceeds the "
            f"{limit}-byte limit. Split the payload into smaller batches and resubmit."
        ),
    )


def _depth_finding(payload: PayloadRoot) -> ValidationFinding | None:
    """Check the payload against the nesting depth limit.

    This walks the structure, so it runs only on payloads already known to be within size. An
    over-deep payload produces an actionable finding naming the limit rather than a
    ``RecursionError`` or a generic 500.

    :return: A finding if the payload nests too deeply, otherwise ``None``.
    """
    if not exceeds_depth(payload):
        return None
    return ValidationFinding(
        path="",
        rule=FindingCode.PAYLOAD_DEPTH,
        message=(
            f"The request payload nests deeper than the {MAX_PAYLOAD_DEPTH}-level limit. "
            f"Legitimate payloads are far shallower; flatten the structure and resubmit."
        ),
    )


async def run_operation(
    context: ToolContext,
    descriptor: OperationDescriptor,
    *,
    identifier: str | None = None,
    selector: SelectorParams | None = None,
    filters: FilterParams | None = None,
    write_options: WriteOptions | None = None,
    payload: PayloadRoot | None = None,
) -> dict[str, Any] | list[Any]:
    """Run one LCE operation through the shared pipeline.

    The order is fixed::

        0  resolve the caller's credential
        1  enforce the filter requirement      pure
        2a enforce body size, UTF-8 bytes      pure
        2b enforce payload depth               pure
        3  run the descriptor's lints          pure
        4  build query parameters              pure
        5  issue the LCE request               <-- the first I/O
        6  shape the response                  pure

    Steps 1 to 4 are pure, so a rejection cannot have already reached LCE.

    :param context: The client, configuration and credential source.
    :param descriptor: The operation to run.
    :param identifier: The path identifier, for item operations.
    :param selector: Field selection and paging parameters.
    :param filters: Filter conditions, required by the list operations.
    :param write_options: ``commit`` and ``retrieve``, for the write operations.
    :param payload: The request body, for the write operations.
    :return: The shaped LCE response body.
    :raises CredentialMissing: If the request carries no LCE credential.
    :raises ValidationBlocked: If any guard or lint rejects the request.
    """
    # ---- 0. The caller's credential --------------------------------------------------------
    # First, not merely before the LCE request, for two reasons:
    #
    #   1. Validation feedback to an unauthenticated caller would disclose which of their GUIDs
    #      was malformed.
    #   2. The size, depth and lint work would otherwise be spent on a caller who will be refused.
    #
    # This reads the inbound scope and issues no outbound call. ``credential_source`` raises
    # ``CredentialMissing``; there is no fallback to any other credential source.
    credential = context.credential_source()

    selector = selector if selector is not None else SelectorParams()

    # ---- 1. The filter requirement ---------------------------------------------------------
    # `FilterParams` enforces "at least one condition" as a model constraint, so an unfiltered list
    # request cannot even be constructed. This guard covers the remaining case: the parameter being
    # omitted entirely for an operation that requires it.
    if descriptor.requires_filter and filters is None:
        raise ValidationBlocked(
            [
                ValidationFinding(
                    path="filters",
                    rule=FindingCode.FILTER_CONSTRAINT,
                    message=(
                        "This operation requires at least one filter condition. Supply filters "
                        "with one or more conditions."
                    ),
                )
            ]
        )

    # ---- 2a, 2b, 3. The write guards ------------------------------------------------------
    if payload is not None:
        bound_findings = [
            finding
            for finding in (
                _body_size_finding(payload, context.config.MAX_REQUEST_BODY_BYTES),
                _depth_finding(payload),
            )
            if finding is not None
        ]
        if bound_findings:
            # Bound violations short-circuit before the lints: linting a payload already known to be
            # oversized or pathologically deep is the expense this ordering avoids.
            raise ValidationBlocked(bound_findings)

        # The lints: the most expensive check, on input already twice bounded.
        lint_findings = validate_payload(payload, descriptor.lint_rules)
        if lint_findings:
            raise ValidationBlocked(lint_findings)

    # ---- 4. Build query parameters (pure) --------------------------------------------------
    query: dict[str, str] = build_selector_params(selector)
    if filters is not None:
        query.update(build_filter_params(filters))
    if descriptor.supports_write_options:
        query.update(
            build_write_options(write_options if write_options is not None else WriteOptions())
        )

    # ---- 5. The LCE request -- the first I/O in the pipeline --------------------------------
    # ``target_host`` is deliberately not passed. There is no per-call host override, so the
    # client sends every request to ``Config.LCE_DEFAULT_TARGET_HOST`` via ``_resolve_target_host``,
    # which re-validates it. Nothing is retried here.
    #
    # Do not wire a caller-supplied value to ``LceClient.request``'s ``target_host`` keyword. A
    # per-call override is only safe alongside a configured destination allowlist that fails
    # closed when empty; wiring it to the syntactic host validator alone would let a caller send
    # their credential to any host.
    response = await context.client.request(
        # Passed per call. The client holds no credential, so the shared pool carries no
        # credential affinity and nothing outlives this request.
        credential=credential,
        method=descriptor.method,
        path=descriptor.path_for(identifier),
        query=query,
        # Whatever shape the caller sent, byte for byte. Narrowing to ``dict`` here would silently
        # discard the top-level array form.
        json_body=payload,
    )

    # ---- 6. Shape the response (pure) ------------------------------------------------------
    # Structure is never re-keyed, re-typed or summarised.
    return shape_response(response.body)


def _emit_write_committed(descriptor: OperationDescriptor, *, commit: bool) -> None:
    """Log ``write_committed``, but only for a write with ``commit=true`` that LCE accepted.

    The event name asserts a commit, so emitting it for ``commit=false`` would make every audit
    query keyed on it wrong unless it also read ``outcome``. A dry run gets only the ordinary INFO
    record.

    The flag is passed directly rather than as ``WriteOptions`` because the tools expose ``commit``
    and ``retrieve`` flattened onto their signatures; there is no ``write_options`` keyword to read,
    and looking for one would fall back to the ``commit=True`` default for every dry run.

    :param descriptor: The operation that ran.
    :param commit: The caller's ``commit`` flag.
    """
    if not descriptor.is_write or not commit:
        return
    logger.info(
        "Write committed to LCE.",
        extra=_log_extra(event=LogEvent.WRITE_COMMITTED, tool=descriptor.tool_name),
    )


def tool_boundary(
    descriptor: OperationDescriptor,
    config: Config,
) -> Callable[
    [Callable[_P, Awaitable[dict[str, Any] | list[Any]]]], Callable[_P, Awaitable[object]]
]:
    """Wrap an LCE tool so its expected errors become caller-visible error payloads.

    This is the one place the exception hierarchy is translated for callers; it uses
    ``build_error_payload`` rather than building the payload shape itself. It sits beneath
    ``mcp_app.global_error_handler``: this decorator handles expected errors with actionable
    messages, and the ASGI handler catches anything unexpected, generically.

    Each invocation emits exactly one INFO record carrying ``tool``, ``target_host``,
    ``lce_operation``, ``outcome`` and ``duration_ms``, matching the declared log schema. Payload
    bodies are never logged.

    :param descriptor: The operation the wrapped tool runs.
    :param config: The service configuration, read for the target host.
    :return: The decorator.
    """

    def decorate(
        func: Callable[_P, Awaitable[dict[str, Any] | list[Any]]],
    ) -> Callable[_P, Awaitable[object]]:
        @wraps(func)
        async def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> object:
            started = time.monotonic()
            # Log the resolved destination, not a sentinel: the audit trail needs the target host
            # on every create or update. Each record carries it itself because log retention is
            # size-driven (``minsize 5M``), so a startup record naming the host can rotate away
            # while write records survive.
            effective_host = config.LCE_DEFAULT_TARGET_HOST
            # ``commit`` is a flattened parameter, defaulting to True as the LCE specification
            # does. Absent for reads, where it is irrelevant.
            commit = kwargs.get("commit", True)
            try:
                result = await func(*args, **kwargs)
            except ValidationBlocked as exc:
                # Expected in normal use; a sudden rise suggests a misbehaving client. The finding
                # paths and codes are logged, never the payload.
                logger.warning(
                    "Request blocked before reaching LCE.",
                    extra=_log_extra(
                        event=LogEvent.VALIDATION_BLOCKED,
                        tool=descriptor.tool_name,
                        target_host=effective_host,
                        lce_operation=descriptor.path_template,
                        outcome="validation_blocked",
                        finding_count=len(exc.findings),
                        finding_codes=sorted({str(f.rule) for f in exc.findings}),
                        duration_ms=round((time.monotonic() - started) * 1000, 3),
                    ),
                )
                return build_error_payload(exc)
            except LceHttpError as exc:
                if exc.status_code in _LCE_AUTH_DENIED_STATUSES:
                    # The caller's own credential was rejected by LCE: a caller-facing condition,
                    # not an operator misconfiguration. A burst suggests a user problem or
                    # credential stuffing rather than a bad deployment.
                    logger.warning(
                        "LCE rejected the caller's credential.",
                        extra=_log_extra(
                            event=LogEvent.LCE_AUTH_DENIED,
                            tool=descriptor.tool_name,
                            target_host=effective_host,
                            lce_status=exc.status_code,
                        ),
                    )
                logger.info(
                    "Tool invocation failed at LCE.",
                    extra=_log_extra(
                        tool=descriptor.tool_name,
                        target_host=effective_host,
                        lce_operation=descriptor.path_template,
                        outcome="lce_http_error",
                        lce_status=exc.status_code,
                        duration_ms=round((time.monotonic() - started) * 1000, 3),
                    ),
                )
                return build_error_payload(exc)
            except PowerPackMcpError as exc:
                # ``CredentialMissing`` is a ``PowerPackMcpError``, so it lands here and
                # ``build_error_payload`` maps it to ``type = credential_missing``. ``outcome``
                # carries the class name, so a refused call still produces an audit record. Letting
                # it reach the ASGI boundary as a transport 401 would lose that record.
                logger.info(
                    "Tool invocation failed.",
                    extra=_log_extra(
                        tool=descriptor.tool_name,
                        target_host=effective_host,
                        lce_operation=descriptor.path_template,
                        outcome=type(exc).__name__,
                        duration_ms=round((time.monotonic() - started) * 1000, 3),
                    ),
                )
                return build_error_payload(exc)

            _emit_write_committed(descriptor, commit=bool(commit))
            logger.info(
                "Tool invocation succeeded.",
                extra=_log_extra(
                    tool=descriptor.tool_name,
                    target_host=effective_host,
                    lce_operation=descriptor.path_template,
                    outcome="success",
                    duration_ms=round((time.monotonic() - started) * 1000, 3),
                ),
            )
            return result

        return wrapper

    return decorate
