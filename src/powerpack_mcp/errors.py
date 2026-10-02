"""
Exceptions, Error Payloads and Event Vocabulary

This module provides the service's exception hierarchy, the closed caller-facing error vocabulary
(``ErrorType``), the alertable log-event vocabulary (``LogEvent``), the validation finding types,
and ``build_error_payload``, which translates any internal exception into the payload a caller
receives.

It imports nothing from this package, so ``config``, ``lce_client`` and ``mcp_app`` can all depend
on it without an import cycle. That is also why ``LogEvent`` and the secret-field denylist live
here: they are shared by modules that must not import each other.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, Literal

__all__ = [
    "CONCURRENCY_LIMITED_PAYLOAD",
    "ERROR_TYPE_AUTHORIZATION_DENIED",
    "ERROR_TYPE_CONCURRENCY_LIMITED",
    "ERROR_TYPE_CREDENTIAL_MISSING",
    "ERROR_TYPE_INTERNAL",
    "ERROR_TYPE_REQUEST_DEADLINE_EXCEEDED",
    "MAX_LCE_BODY_CHARS",
    "MAX_LCE_BODY_DEPTH",
    "REDACTED",
    "REQUEST_DEADLINE_EXCEEDED_PAYLOAD",
    "SECRET_FIELD_DENYLIST",
    "AuthorizationDenied",
    "CollectionJobNotOwned",
    "ConfigurationError",
    "CredentialMissing",
    "DbDeadlineExceeded",
    "DbError",
    "DbQueryTimeout",
    "DbUnreachable",
    "ErrorType",
    "FindingCode",
    "LceHttpError",
    "LceMalformedResponse",
    "LceUnreachable",
    "LintRule",
    "LogEvent",
    "PowerPackMcpError",
    "SchemaTrimError",
    "Sl1EmptyResponse",
    "Sl1GraphQlError",
    "Sl1HttpError",
    "Sl1MalformedResponse",
    "Sl1ResponseTooLarge",
    "Sl1Unreachable",
    "ToolSetDisabledReason",
    "ValidationBlocked",
    "ValidationFinding",
    "build_error_payload",
    "finding_code_for",
    "sanitize_lce_body",
]


class LintRule(StrEnum):
    """Name the blocking lints an operation descriptor can select.

    This is the type ``OperationDescriptor.lint_rules`` holds. It has only the lints a descriptor
    can actually run, so a descriptor cannot select anything else; ``FindingCode`` is the wider
    caller-facing vocabulary.
    """

    CHILD_GUID = "child_guid"
    THRESHOLD_TYPE = "threshold_type"


class FindingCode(StrEnum):
    """Identify the kind of problem a ``ValidationFinding`` reports.

    This is the caller-facing vocabulary. It is kept separate from ``LintRule`` because some
    rejections (filter constraints, body size, nesting depth, bad tool arguments) are not lints,
    and a descriptor must not be able to select a rule it can never run. The lint codes carry the
    same string values as their ``LintRule`` members.

    These codes are a published contract: monitoring and agent recovery key on them, never on
    message text. Adding a member is backward-compatible; renaming one is a breaking change.
    """

    # The blocking lints. Values match ``LintRule`` exactly.
    CHILD_GUID = "child_guid"
    THRESHOLD_TYPE = "threshold_type"
    # Guard rejections that are not lints.
    FILTER_CONSTRAINT = "filter_constraint"
    REQUEST_BODY_SIZE = "request_body_size"
    PAYLOAD_DEPTH = "payload_depth"
    # A tool argument the caller can correct: a verb outside the allowed set, an ambiguous or
    # absent name lookup, an unresolvable Dynamic Application identifier, or an alignment SL1
    # refuses on device-class grounds. Not ``FILTER_CONSTRAINT``, because these are not filter
    # operators and the published code would misdescribe the failure.
    TOOL_ARGUMENT = "tool_argument"


def finding_code_for(rule: LintRule) -> FindingCode:
    """Map a selectable lint to its caller-facing code.

    The mapping is total because ``FindingCode`` declares a member with an identical value for
    every ``LintRule`` member; a test asserts that.
    """
    return FindingCode(rule.value)


@dataclass(frozen=True, slots=True)
class ValidationFinding:
    """One rejection, addressed by its path in the payload.

    :ivar path: Location of the offending value in the payload.
    :ivar rule: The caller-facing code for the problem.
    :ivar message: Human-readable explanation.
    """

    path: str
    rule: FindingCode
    message: str


class LogEvent(StrEnum):
    """The closed vocabulary of alertable log events.

    Monitoring keys on the ``event`` field, never on message text, so wording can change without
    breaking an alert. The vocabulary is declared in one place so modules cannot diverge. Every
    member must have at least one emission site; a member nothing emits is an alert that can never
    fire.
    """

    VALIDATION_BLOCKED = "validation_blocked"
    LCE_AUTH_DENIED = "lce_auth_denied"
    TLS_VERIFICATION_RELAXED = "tls_verification_relaxed"
    STARTUP_FAILED = "startup_failed"
    UNHANDLED_EXCEPTION = "unhandled_exception"
    WRITE_COMMITTED = "write_committed"
    # Emitted by the concurrency gate. Sustained occurrence means the bound is too low for real
    # traffic, or a client is misbehaving.
    CONCURRENCY_LIMITED = "concurrency_limited"
    # Emitted once per tool set at startup, ``lce`` included, so the log is a complete inventory of
    # the tool surface. An upgrade can widen that surface with no operator action, and this record
    # is how an operator detects it, which is why it is a keyed event rather than a plain INFO line.
    TOOL_SETS_REGISTERED = "tool_sets_registered"
    # Emitted when the request deadline aborts a request. Without it an operator sees only a
    # truncated or absent response, with nothing to tell "the backend was slow" from "the backend
    # failed". Distinct from ``CONCURRENCY_LIMITED``, which means the bound was hit: this means one
    # request held its slot until the deadline, which is what causes the other.
    REQUEST_DEADLINE_EXCEEDED = "request_deadline_exceeded"
    # Two members, because the distinction matters to an operator. A client-side deadline abandons
    # the await while the query keeps running, so the slot is released but the thread and
    # connection are not; that leak surfaces later as an unrelated-looking failure. MariaDB error
    # 1969 means the server stopped the query itself. So ``DB_QUERY_TIMEOUT`` is bounded and
    # recovered (a capacity signal), while ``DB_AWAIT_ABANDONED`` is still running (a leak).
    DB_QUERY_TIMEOUT = "db_query_timeout"
    DB_AWAIT_ABANDONED = "db_await_abandoned"
    # No query was issued, because the inbound deadline was already spent when the statement was
    # reached. Not ``DB_QUERY_TIMEOUT``, which means the server stopped a running query: reporting
    # this case as a timeout is accurate in every field and still misleading, since nothing was
    # slow. Not ``REQUEST_DEADLINE_EXCEEDED`` either, which means the whole request was aborted;
    # here the request is live and only its database budget is gone, because the work before the
    # statement consumed it. ``db_client``'s pre-flight check is the emission site.
    DB_DEADLINE_EXCEEDED = "db_deadline_exceeded"

    # The audit record for every ``master.*`` write, carrying the tool, the actor and the outcome.
    # It is emitted on every outcome, including refusal. Attribution is the remaining
    # accountability mechanism for these writes, so a missing record should mean the tool did not
    # run. One event with an ``outcome`` field, rather than one event per outcome, so a single key
    # always fires and is easy to find.
    MASTER_WRITE_AUDITED = "master_write_audited"
    # The audit record for the SL1 REST passthrough tools. Those tools can issue arbitrary requests,
    # are registered by default and are bounded only by SL1's own authorization, so this audit
    # trail is the whole compensating control. It is emitted whether the call succeeds or fails,
    # including when validation rejects it, because rejected calls are what reveal someone probing
    # paths. It records enough to reconstruct what was called and never carries a credential.
    SL1_PASSTHROUGH_INVOKED = "sl1_passthrough_invoked"
    # Emitted by the access-hook gate on every refusal. It has its own key rather than reusing
    # ``VALIDATION_BLOCKED`` so that authorization failures can be alerted on without matching
    # message text. The record carries the tool, the required hooks, the actor and the outcome. It
    # must never carry the caller's granted hooks: that is a person's entitlement profile, and
    # ``RedactingFilter`` matches attribute names, so it would not catch a ``granted_hooks`` extra.
    # Log volume under sustained refusals has not been measured against log retention.
    AUTHORIZATION_DENIED = "authorization_denied"


class ToolSetDisabledReason(StrEnum):
    """Why a tool set is not registered.

    "Disabled" alone is not enough: "the operator turned it off" and "a prerequisite is missing"
    call for opposite responses, so the reason is reported explicitly. The vocabulary is closed at
    these three values and lives beside ``LogEvent`` because monitoring keys on it too.
    """

    # The set's own ``ENABLE_*`` flag is false: the operator's direct instruction.
    DISABLED_BY_CONFIGURATION = "disabled_by_configuration"
    # ``ENABLE_DB_TOOLS`` is false, so the nested write set is off as a consequence rather than as
    # an instruction. This lets an operator who set one key and lost two sets see which was which.
    DISABLED_BY_NESTING = "disabled_by_nesting"
    # A build-time or configuration prerequisite is absent, for example the platform database
    # driver or ``libem7._crypt`` is not importable from the service venv. This is never a runtime
    # reachability check; reachability is deliberately not a registration input.
    PREREQUISITE_MISSING = "prerequisite_missing"


# The closed caller-facing error vocabulary. Decoupled from exception class names so renaming a
# class is an internal refactor, not a breaking change for callers. Each member exists because a
# caller must be able to branch on it without matching message text.
ErrorType = Literal[
    "validation_blocked",
    "lce_http_error",
    "lce_unreachable",
    "lce_malformed_response",
    "internal_error",
    # Returned with HTTP 503 by the concurrency gate. ``internal_error`` would tell the caller to
    # report a bug, when the right advice for this transient condition is to retry shortly.
    "concurrency_limited",
    # Returned with HTTP 504 by the concurrency gate when a request reaches the inbound deadline
    # before its response has started. Shares its name with the ``LogEvent`` the gate emits. Not
    # ``internal_error``, whose advice is to report a bug: the right advice is to retry, perhaps
    # with a narrower query. Unlike ``concurrency_limited`` the work may have begun, so the message
    # tells a caller to check a write before repeating it.
    "request_deadline_exceeded",
    # Separate from ``validation_blocked`` because "you did not authenticate" and "your payload is
    # invalid" call for different client behaviour.
    "credential_missing",
    # ---- SL1 REST and GraphQL ------------------------------------------------------------------
    #
    # A GraphQL failure that arrives as HTTP 200 with an ``errors`` array. Not ``sl1_http_error``,
    # because the transport succeeded, and not ``validation_blocked``, which means this service
    # refused the caller's input.
    "sl1_graphql_error",
    # SL1-specific members, because an ``lce_*`` member on an SL1 failure would tell the caller
    # that LCE failed when SL1 did. The payload shape, builder and redaction path are shared with
    # the LCE members, so this is one taxonomy, not two mechanisms. The ``lce_*`` members are not
    # renamed to be backend-neutral because they are a published contract.
    "sl1_http_error",
    "sl1_unreachable",
    "sl1_malformed_response",
    # The outbound size cap. The transport did not fail and the input was fine, so neither
    # ``sl1_http_error`` nor ``validation_blocked`` fits, and the advice differs: narrow the query.
    "sl1_response_too_large",
    # ---- SL1 database ---------------------------------------------------------------------------
    #
    # Database-specific members, for the same reason as the SL1 ones. The timeout is separate from
    # the generic error because MariaDB error 1969 means the server ended the query and left the
    # connection clean and reusable, so the advice is "narrow the query or raise the deadline".
    # Any other database failure leaves the connection suspect and it is discarded.
    "db_query_timeout",
    "db_unreachable",
    "db_error",
    # ---- the authorization gate -----------------------------------------------------------------
    #
    # The caller authenticated but is not entitled. No existing member fits:
    #
    # * not ``credential_missing``: the credential is correct, and the caller would be told to fix
    #   it anyway.
    # * not ``validation_blocked``: the payload may be flawless. The remedy is "ask an administrator
    #   for a hook", and retrying cannot help.
    # * not ``internal_error``, for a hook shortfall. A tool that is gated but unmapped is a
    #   mis-registration on this side that no caller can trigger, and that does stay
    #   ``internal_error``, as ``DbToolNotRegistered`` in ``authz`` does.
    #
    # Raised as ``AuthorizationDenied`` and translated in ``build_error_payload``.
    "authorization_denied",
]

# SL1's GraphQL ``extensions.code`` for an authorization denial. Observed, not documented: a
# restricted account querying ``credentials`` receives HTTP 200 with
# ``errors[0].extensions.code == "RESTRICTED_ACCESS"``. SL1 owns this vocabulary. If SL1 renames
# the code, ``is_authorization_denial`` stops matching and falls back to the generic GraphQL
# message, which is the safe direction.
SL1_RESTRICTED_ACCESS_CODE: Final[str] = "RESTRICTED_ACCESS"

ERROR_TYPE_INTERNAL: Final[ErrorType] = "internal_error"
ERROR_TYPE_CONCURRENCY_LIMITED: Final[ErrorType] = "concurrency_limited"
ERROR_TYPE_REQUEST_DEADLINE_EXCEEDED: Final[ErrorType] = "request_deadline_exceeded"
ERROR_TYPE_CREDENTIAL_MISSING: Final[ErrorType] = "credential_missing"
ERROR_TYPE_AUTHORIZATION_DENIED: Final[ErrorType] = "authorization_denied"

# The concurrency gate's caller-facing payload. Built here so the message lives beside the
# vocabulary it belongs to, and returned inline by the middleware rather than raised as an
# exception.
CONCURRENCY_LIMITED_PAYLOAD: Final[dict[str, dict[str, object]]] = {
    "error": {
        "type": ERROR_TYPE_CONCURRENCY_LIMITED,
        "message": (
            "The service is handling its maximum number of concurrent requests. This is transient "
            "and clears on its own -- retry shortly."
        ),
    }
}

# The gate's payload for a request that reached the inbound deadline before it began responding.
# Like the one above, returned inline by the middleware rather than raised.
REQUEST_DEADLINE_EXCEEDED_PAYLOAD: Final[dict[str, dict[str, object]]] = {
    "error": {
        "type": ERROR_TYPE_REQUEST_DEADLINE_EXCEEDED,
        "message": (
            "The request exceeded the service's time limit and was stopped, possibly after some "
            "of its work was done. A read can be retried, ideally with a narrower query; check "
            "whether a write took effect before you retry it."
        ),
    }
}


# --------------------------------------------------------------------------------------------------
# LCE error-body sanitisation
#
# ``RedactingFilter`` in ``mcp_app.logging_setup`` is a ``logging.Filter`` that flat-scans a
# LogRecord's attribute names; it neither recurses nor accepts a JSON value, so only its denylist is
# reusable here. This module cannot import ``logging_setup`` (that would create an import cycle), so
# ``REDACTED`` and ``SECRET_FIELD_DENYLIST`` are defined here and ``logging_setup`` imports them.
# ``validation.exceeds_depth`` is unreachable for the same reason, so the depth bound is declared
# here too.
# --------------------------------------------------------------------------------------------------

REDACTED: Final[str] = "**redacted**"

# Matched case-insensitively on the field name, not the value. Matching on values would require
# knowing what a secret looks like, which is impossible for an opaque token.
SECRET_FIELD_DENYLIST: Final[frozenset[str]] = frozenset(
    {"authorization", "token", "secret", "credential", "password", "api_key", "cookie"}
)

# Per-string cap. LCE's error bodies are descriptive sentences; anything approaching this is not an
# explanation a caller can act on.
MAX_LCE_BODY_CHARS: Final = 2048

# The walk stops descending at this depth, so stack use is bounded by the limit rather than by the
# input. An error body is a document this service does not control, and deeply nested ones do
# arrive.
MAX_LCE_BODY_DEPTH: Final = 16

_TRUNCATED: Final[str] = "...[truncated]"
_TOO_DEEP: Final[str] = "**elided: nested beyond the depth limit**"

type _LceBodyValue = dict[str, Any] | list[Any] | str | int | float | bool | None


def _is_secret_key(key: object) -> bool:
    """Return whether a mapping key names a field whose value must not be rendered."""
    return isinstance(key, str) and key.lower() in SECRET_FIELD_DENYLIST


def _truncate(text: str) -> str:
    """Cap one string, marking the elision explicitly rather than silently shortening."""
    if len(text) <= MAX_LCE_BODY_CHARS:
        return text
    return text[:MAX_LCE_BODY_CHARS] + _TRUNCATED


def _sanitize_value(value: object, depth: int) -> _LceBodyValue:
    """Sanitise one nested value of an error body.

    The parameter is typed ``object`` rather than ``_LceBodyValue`` on purpose. The body comes from
    ``response.json()``, whose static type is ``Any``; that only JSON types arrive is a property of
    the parser, not of this function. With the narrower type, mypy would treat the final fallback
    as unreachable, and removing it would leave the walk not total.

    :param value: The value to sanitise.
    :param depth: Nesting depth of ``value`` in the body.
    :return: The value with secrets redacted, strings capped and deep nesting elided.
    """
    if depth >= MAX_LCE_BODY_DEPTH:
        # Return without descending. This is the bound itself.
        return _TOO_DEEP
    if isinstance(value, str):
        return _truncate(value)
    if value is None or isinstance(value, bool):
        # ``0`` and ``false`` are values, never absence, so they pass through untouched.
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, dict):
        return {
            key: REDACTED if _is_secret_key(key) else _sanitize_value(item, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_value(item, depth + 1) for item in value]
    # Anything the JSON parser could not have produced is rendered as a capped string rather than
    # passed through unexamined.
    return _truncate(str(value))


def sanitize_lce_body(
    body: dict[str, Any] | list[Any] | str,
) -> dict[str, Any] | list[Any] | str:
    """Redact denylisted fields and cap string lengths in an LCE-supplied error body.

    ``LceHttpError.__init__`` applies this, not the renderer, so no construction site can bypass it
    and the raw body is never retained on the exception. The three top-level shapes are handled
    explicitly so the return type matches the input type without a cast.

    A denylist cannot know about a field named ``x_auth_blob``. This is a safety net layered with
    the length and depth bounds, not a guarantee that nothing sensitive can appear.

    :param body: The parsed error body.
    :return: The sanitised body, of the same top-level type.
    """
    if isinstance(body, str):
        return _truncate(body)
    if isinstance(body, dict):
        return {
            key: REDACTED if _is_secret_key(key) else _sanitize_value(item, 1)
            for key, item in body.items()
        }
    return [_sanitize_value(item, 1) for item in body]


class PowerPackMcpError(Exception):
    """Base for every error this service raises internally.

    A single base means the tool boundary has one ``except`` clause to catch.
    """


class ValidationBlocked(PowerPackMcpError):  # noqa: N818 - public name
    """A request rejected before it reached a backend, carrying every finding at once.

    :ivar findings: Every rejection found, one per offending path.
    """

    findings: tuple[ValidationFinding, ...]

    def __init__(self, findings: tuple[ValidationFinding, ...] | list[ValidationFinding]) -> None:
        self.findings = tuple(findings)
        super().__init__(f"{len(self.findings)} validation finding(s)")


class LceHttpError(PowerPackMcpError):
    """A non-2xx LCE response. Preserves the status and the LCE-supplied body, and nothing else.

    ``lce_body`` is always sanitised. ``sanitize_lce_body`` runs in the constructor, so the
    attribute never holds the raw body, no new construction site can bypass it, and logging the
    exception cannot leak what rendering would have redacted.

    :ivar status_code: The HTTP status LCE returned.
    :ivar lce_body: The sanitised response body.
    """

    status_code: int
    lce_body: dict[str, Any] | list[Any] | str

    def __init__(self, status_code: int, lce_body: dict[str, Any] | list[Any] | str) -> None:
        self.status_code = status_code
        self.lce_body = sanitize_lce_body(lce_body)
        # The message carries the status only. No stack trace, path, version or configuration
        # value is bound at construction, not merely withheld when rendering.
        super().__init__(f"LCE returned HTTP {status_code}")


class LceUnreachable(PowerPackMcpError):  # noqa: N818 - public name
    """Connect failure, DNS failure or timeout reaching LCE.

    Carries the target host name and nothing else: not the resolved IP, not the port, and not the
    underlying library's exception text.
    """

    target_host: str

    def __init__(self, target_host: str) -> None:
        self.target_host = target_host
        super().__init__(f"LCE at {target_host} is unreachable")


class LceMalformedResponse(PowerPackMcpError):  # noqa: N818 - public name
    """LCE returned a body that is not parseable JSON. No attempt is made to salvage it."""


# ---- SL1 transport failures ----------------------------------------------------------------------
#
# These subclass the LCE exceptions on purpose. ``sanitize_lce_body`` still runs in the base
# constructor, ``build_error_payload`` needs no new logic for the shape, and ``tool_boundary``'s
# single ``except PowerPackMcpError`` still catches everything. Only the caller-facing ``type``
# changes, so the caller is told which backend failed.


class Sl1HttpError(LceHttpError):
    """A non-2xx SL1 REST response. The body is sanitised by the base constructor."""

    def __init__(self, status_code: int, body: dict[str, Any] | list[Any] | str) -> None:
        super().__init__(status_code, body)
        # Restated so the message names the right service. Still the status only.
        self.args = (f"SL1 returned HTTP {status_code}",)


class Sl1Unreachable(LceUnreachable):
    """Connect failure, DNS failure or timeout reaching SL1. Carries the host and nothing else."""

    def __init__(self, target_host: str) -> None:
        super().__init__(target_host)
        self.args = (f"SL1 at {target_host} is unreachable",)


class Sl1MalformedResponse(LceMalformedResponse):
    """SL1 returned a body that is not parseable JSON. No attempt is made to salvage it."""


class Sl1EmptyResponse(Sl1MalformedResponse):
    """SL1 returned a completely empty body.

    An empty body is malformed unless the status says otherwise: ``202 Accepted`` and
    ``204 No Content`` are the cases where emptiness is correct. Only ``client.py`` can see the
    status, so ``bounded_read`` raises this and the client decides.

    It is a subclass rather than a sibling so that the ``>= 400`` path's
    ``except Sl1MalformedResponse`` still catches it, and a caller that never distinguishes the two
    behaves as before.

    It stays malformed for ``200 OK``, which promises a representation. Accepting an empty body
    for any 2xx would turn a genuinely malformed ``200`` into a silent success.
    """


class Sl1ResponseTooLarge(PowerPackMcpError):  # noqa: N818 - symmetry with the SL1 siblings
    """The outbound SL1 response body exceeded ``MAX_RESPONSE_BODY_BYTES``.

    Carries the limit, not the number of bytes seen: the read stops at the cap, so the true total
    is never known. The caller's remedy is to narrow the query.

    Not a subclass of the LCE errors, because it is not a transport failure: the connection was
    fine and this service stopped reading.

    :ivar limit_bytes: The cap that was exceeded.
    """

    limit_bytes: int

    def __init__(self, limit_bytes: int) -> None:
        self.limit_bytes = limit_bytes
        super().__init__(f"SL1 response exceeded the {limit_bytes} byte limit")


class DbQueryTimeout(PowerPackMcpError):  # noqa: N818 - house naming of the hierarchy
    """MariaDB ended the query at ``max_statement_time`` (error 1969).

    For example, ``SET SESSION max_statement_time=0.5`` then ``SELECT SLEEP(3)`` aborts at 0.5 s
    with ``OperationalError(1969, 'Query execution was interrupted (max_statement_time
    exceeded)')``.

    The connection is not discarded when this is raised. The server ended the query and drained its
    result, so the connection is immediately reusable; discarding it would throw away a healthy
    connection on every slow query. See ``DbError`` for the case that does discard.

    :ivar timeout_seconds: The timeout the statement was given. The elapsed time is not carried,
        because the query was cut off and no true duration was observed.
    """

    timeout_seconds: float

    def __init__(self, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds
        super().__init__(f"DB query exceeded the {timeout_seconds}s statement timeout")


class DbDeadlineExceeded(PowerPackMcpError):  # noqa: N818 - house naming of the hierarchy
    """The inbound deadline was already spent before a statement could be issued.

    This is a refusal, not a timeout. ``max_statement_time`` is derived from the remaining request
    deadline. When nothing remains, clamping to ``MIN_STATEMENT_TIME_SECONDS`` and issuing the
    statement would give MariaDB a 1 ms budget, and the result would be reported as
    ``DbQueryTimeout`` even though nothing was slow and narrowing the query could not help.

    Do not remove ``MIN_STATEMENT_TIME_SECONDS``. MariaDB reads ``max_statement_time = 0`` as no
    limit, so the floor is what stops a tiny positive remainder becoming an unbounded query. This
    class covers only the case where there is no remainder at all.

    A deadline of ``None`` means no deadline is in force (health checks and startup work) and runs
    under the platform default; it does not raise this.

    :ivar remaining_seconds: The measured remainder that triggered the refusal. No statement ran,
        so there is no duration to report.
    """

    remaining_seconds: float

    def __init__(self, remaining_seconds: float) -> None:
        self.remaining_seconds = remaining_seconds
        super().__init__("the request deadline was spent before the database statement was issued")


class DbUnreachable(PowerPackMcpError):  # noqa: N818 - house naming of the hierarchy
    """The platform database could not be reached, or the platform driver is absent.

    Both cases share one error because the caller's remedy is the same (this appliance cannot serve
    database tools right now), and distinguishing them would disclose whether the platform tree is
    installed.

    An absent driver should normally never reach a caller: a failed ``import sl_mysql`` at startup
    disables the database tool sets with ``ToolSetDisabledReason.PREREQUISITE_MISSING``. This covers
    the case where the import succeeded and a later connection did not.
    """


class DbError(PowerPackMcpError):
    """Any other database failure, after which the connection is treated as suspect.

    Unlike ``DbQueryTimeout``, nothing here says the connection is in a known state, so
    ``db_client`` closes it and clears the thread-local slot instead of reusing it. Losing reuse on
    an error path costs performance; handing the next caller a connection with another caller's
    rows pending would be a confidentiality failure.

    No driver message is carried. MySQLdb exception text can embed connection parameters, and the
    platform's own connection-cache key holds the plaintext password, so the driver's message never
    reaches a caller or a log record.
    """


class Sl1GraphQlError(PowerPackMcpError):
    """GraphQL failed inside an HTTP 200 response.

    SL1 returns HTTP 200 with a non-empty ``errors`` array both when the query is wrong and when the
    caller is not permitted the data:

    * ``RESTRICTED_ACCESS`` ("User does not have required permissions."): like a 403. Retrying or
      editing the query cannot help.
    * ``GRAPHQL_VALIDATION_FAILED`` ("Cannot query field `name` on type `Organization`."): like a
      400. The caller can correct the query.

    The envelopes are otherwise identical, so ``codes`` is the only thing that separates them. A
    caller told to "correct the query" after a permission denial would retry forever.

    :ivar messages: The ``errors`` array's messages, sanitised with ``sanitize_lce_body`` because
        SL1 authors them.
    :ivar codes: Each entry's ``extensions.code``, positional with ``messages``. An entry with no
        code yields ``""`` rather than being dropped, which would misalign the two tuples.
    """

    messages: tuple[str, ...]
    codes: tuple[str, ...]

    def __init__(
        self,
        messages: list[str] | tuple[str, ...],
        codes: list[str] | tuple[str, ...] = (),
    ) -> None:
        sanitised = tuple(str(sanitize_lce_body(m)) for m in messages)
        self.messages = sanitised
        # Codes are SL1's enum-like identifiers, not free text, so they are not put through
        # ``sanitize_lce_body``, whose redaction and length cap could only damage the token a caller
        # branches on. They are still coerced to ``str`` because they come from foreign JSON.
        self.codes = tuple(str(code) for code in codes)
        super().__init__(f"SL1 GraphQL returned {len(sanitised)} error(s)")

    @property
    def is_authorization_denial(self) -> bool:
        """Return whether any entry reports ``RESTRICTED_ACCESS``.

        Any, not all: SL1 can answer one field and refuse another in the same envelope, and a
        partial denial is still a denial.
        """
        return SL1_RESTRICTED_ACCESS_CODE in self.codes


class CredentialMissing(PowerPackMcpError):  # noqa: N818 - house naming of the hierarchy
    """No usable credential accompanied the request.

    Carries nothing beyond the class: not whether the header was absent or malformed, its length,
    or the scheme presented, because any of those would report on credential material. There is
    deliberately no ``__init__``.

    Reaching this means something is wrong upstream. nginx's ``auth_request`` should already have
    rejected an unauthenticated request, so this implies a misconfigured nginx fragment (for
    example, a platform upgrade dropped the include line) or a direct call to the loopback
    listener. It is defence in depth, not the primary control, and must exist even though it
    should be unreachable in a correct deployment.
    """


class AuthorizationDenied(PowerPackMcpError):  # noqa: N818 - house naming of the hierarchy
    """The caller authenticated, but lacks an access hook the invoked tool requires.

    Carries the required hooks and never the granted set. Naming what is missing is actionable,
    since the caller can ask an administrator for it; listing what they hold would disclose a
    person's entitlement profile to whoever asked.

    It subclasses only ``PowerPackMcpError`` so that no class-pattern ordering in
    ``build_error_payload`` can shadow it.

    This is not the error for a gated tool with no mapping. That is a mis-registration no caller
    can trigger, and it stays ``internal_error``, as ``DbToolNotRegistered`` does in ``authz``.

    Do not let a raised instance reach the caller directly. fastmcp's ``mask_error_details``
    defaults to false, so an exception escaping the middleware shows its message to the caller
    unfiltered. The gate returns the built payload instead of raising across that boundary.

    :ivar tool_name: The tool the caller invoked.
    :ivar required_hooks: The hooks the tool requires.
    """

    required_hooks: frozenset[str]
    tool_name: str

    def __init__(self, tool_name: str, required_hooks: frozenset[str]) -> None:
        self.tool_name = tool_name
        self.required_hooks = required_hooks
        # The message is internal only and reaches logs, never a caller; ``build_error_payload``
        # composes the caller-facing text from ``required_hooks``.
        super().__init__(f"{tool_name} requires access hook(s) {', '.join(sorted(required_hooks))}")


class CollectionJobNotOwned(PowerPackMcpError):  # noqa: N818 - house naming of the hierarchy
    """The caller holds the hook, but the collection job belongs to another account.

    This is the object-level authorization check: a request that references a resource by ID must
    verify the caller may access that resource. It shares the ``authorization_denied`` error type
    with ``AuthorizationDenied`` but has its own class because the remedy differs; "ask for a hook"
    is useless when the caller already holds it.

    This is stricter than SL1's own viewer on purpose and must not be relaxed to match it.
    ``device_tools_log.inc`` checks ``DEV_TOOLS_RUN`` and then does no ownership check or
    ``tool_id`` scoping, so any holder of that hook can read any ``proc_id``'s output by iterating
    ids. That output can include plaintext SNMP community strings and v3 passwords.

    Only the requested ``proc_id`` is carried. Naming the owning account would disclose who runs
    collections to someone not entitled to know.

    A job with no ownership row is refused too. ``_record_correlation`` writes no row when the actor
    is unknown, so an unattributable job is unreadable by anyone, including whoever started it. That
    only happens for a request that bypassed nginx.

    :ivar proc_id: The collection job the caller asked for.
    """

    proc_id: int

    def __init__(self, proc_id: int) -> None:
        self.proc_id = proc_id
        super().__init__(f"collection job {proc_id} is not attributable to the calling account")


class ConfigurationError(PowerPackMcpError):
    """Raised at startup only. Never reaches a caller.

    Its message names the offending configuration key, which a production error response must not
    disclose. That is safe because it is raised before any caller exists, so it can only be logged
    or printed to the operator's console. No code path may raise this after startup completes.
    """


class SchemaTrimError(PowerPackMcpError):
    """Raised at startup only, by ``schema_slim``. Never reaches a caller.

    fastmcp has no public accessor for a registered tool's schema, so ``schema_slim`` reads a
    private attribute. If an upgrade changes it, trimming must fail loudly rather than silently
    leave the schemas untrimmed, which would undo the size budget with no signal.

    It has no ``ErrorType`` member, because like ``ConfigurationError`` it is raised before a caller
    exists. It is not a ``ConfigurationError`` because that maps to exit status 78 ("configuration
    error"), and a broken fastmcp internal is not a configuration mistake; reporting it as one would
    mislead an operator reading ``systemctl status``.
    """


def _authorization_error_payload(exc: PowerPackMcpError) -> dict[str, object] | None:
    """Build the payload for an authorization refusal.

    Kept out of ``build_error_payload``'s ``match`` to hold that function under the ``C901``
    complexity limit.

    The required hooks are named; the granted set is absent and must never be added.

    :param exc: The exception to translate.
    :return: The error object, or ``None`` if ``exc`` is not an authorization refusal.
    """
    if isinstance(exc, AuthorizationDenied):
        return {
            "type": ERROR_TYPE_AUTHORIZATION_DENIED,
            "message": (
                "Your Skylar One account is not granted the access hook(s) this tool requires. "
                "Ask an administrator to grant them, then retry."
            ),
            "required_hooks": sorted(exc.required_hooks),
        }
    if isinstance(exc, CollectionJobNotOwned):
        # No ``required_hooks`` key: the caller holds the hook, so listing it would suggest a
        # remedy that does not apply.
        return {
            "type": ERROR_TYPE_AUTHORIZATION_DENIED,
            "message": (
                "That collection job was not started by your account, so its output is not "
                "available to you. Fetch a job you started."
            ),
            "proc_id": exc.proc_id,
        }
    return None


def _sl1_error_payload(exc: PowerPackMcpError) -> dict[str, object] | None:
    """Build the payload for an SL1 failure.

    These cases are kept out of ``build_error_payload``'s ``match`` because ``Sl1HttpError``
    subclasses ``LceHttpError`` and class patterns are first-match-wins. Inside that ``match``,
    reordering the cases would silently render every SL1 transport failure as ``lce_http_error``,
    and tests would still pass. Checking these first makes the ordering a property of the code's
    shape rather than of line order.

    :param exc: The exception to translate.
    :return: The error object, or ``None`` if ``exc`` is not an SL1 failure.
    """
    error: dict[str, object]
    match exc:
        # ---- SL1 cases must precede their LCE base classes ------------------------------------
        #
        # ``Sl1HttpError`` subclasses ``LceHttpError``, so ``case LceHttpError()`` would match it
        # too. ``test_sl1_errors_are_not_shadowed_by_their_base_classes`` pins this.
        case Sl1ResponseTooLarge():
            error = {
                "type": "sl1_response_too_large",
                "message": (
                    "The SL1 response exceeded this service's outbound size limit and was not "
                    "read. Narrow the query -- reduce the requested fields, add filters, lower "
                    "limit, or disable extended_fetch -- and retry."
                ),
                "limit_bytes": exc.limit_bytes,
            }
        case Sl1GraphQlError():
            error = {
                "type": "sl1_graphql_error",
                # The guidance branches on the code. After a permission denial the query is fine
                # and will never stop being denied, so "correct the query" would cause a retry loop.
                "message": (
                    "SL1 refused this request because the calling account lacks permission for "
                    "the requested data. The query is not at fault and retrying will not help -- "
                    "the credential needs broader rights in SL1."
                    if exc.is_authorization_denial
                    else "SL1 returned GraphQL errors. The HTTP request itself succeeded, so "
                    "inspect graphql_errors and correct the query."
                ),
                # The caller needs the messages to act. They are sanitised in the constructor.
                "graphql_errors": list(exc.messages),
                # Positional with ``graphql_errors``. Emitted even when empty, so a caller can rely
                # on the key existing.
                "graphql_error_codes": list(exc.codes),
            }
        case Sl1HttpError():
            error = {
                "type": "sl1_http_error",
                "message": (
                    "SL1 rejected the request. Inspect sl1_status and the SL1-supplied body, "
                    "correct the request, and retry if appropriate."
                ),
                "sl1_status": exc.status_code,
                # Already sanitised in the base constructor. The key is ``sl1_``-prefixed so a
                # caller does not have to guess which backend produced the body.
                "sl1_body": exc.lce_body,
            }
        case Sl1Unreachable():
            error = {
                "type": "sl1_unreachable",
                "message": (
                    "SL1 could not be reached. Confirm the SL1 API is responding on the configured "
                    "host, then retry."
                ),
            }
        case Sl1MalformedResponse():
            error = {
                "type": "sl1_malformed_response",
                "message": (
                    "SL1 returned a response that was not valid JSON. Retry; if it persists, "
                    "check the SL1 service logs."
                ),
            }
        case _:
            return None
    return error


def _db_deadline_error_payload(exc: PowerPackMcpError) -> dict[str, object] | None:
    """Build the payload for a database statement refused because the deadline was spent.

    Kept out of ``build_error_payload``'s ``match`` to hold that function under the ``C901``
    complexity limit.

    The message does not say "narrow the query". That is ``db_query_timeout``'s advice and it is
    wrong here: no query ran, and a smaller one would have been refused the same way. The caller
    can retry with a fresh deadline.

    :param exc: The exception to translate.
    :return: The error object, or ``None`` if ``exc`` is not a ``DbDeadlineExceeded``.
    """
    if isinstance(exc, DbDeadlineExceeded):
        return {
            "type": "db_deadline_exceeded",
            "message": (
                "The request's time budget was already spent before the database statement could "
                "be issued, so it was refused rather than attempted. Retry as a new request."
            ),
        }
    return None


def _specialised_error_payload(exc: PowerPackMcpError) -> dict[str, object] | None:
    """Translate the error families handled ahead of ``build_error_payload``'s ``match``.

    This indirection keeps ``build_error_payload`` under the ``C901`` complexity limit without a
    ``noqa``. ``_sl1_error_payload`` runs first; see its docstring for why that ordering matters.
    The other families derive directly from ``PowerPackMcpError`` and cannot conflict with it.

    :param exc: The exception to translate.
    :return: The error object, or ``None`` if no family here handles ``exc``.
    """
    sl1 = _sl1_error_payload(exc)
    if sl1 is not None:
        return sl1
    authorization = _authorization_error_payload(exc)
    if authorization is not None:
        return authorization
    return _db_deadline_error_payload(exc)


def build_error_payload(exc: PowerPackMcpError) -> dict[str, dict[str, object]]:
    """Translate an internal exception into the caller-facing payload shape.

    This is the only place errors are translated; ``tool_boundary`` calls it. It is total over the
    hierarchy, and its properties are tested: ``type`` is always in the closed vocabulary; the
    output never contains a stack trace, file path, framework version or the credential;
    ``lce_status`` and ``lce_body`` are present if and only if the input is an ``LceHttpError``;
    ``details`` is present if and only if the input is a ``ValidationBlocked``.

    ``lce_body`` carries LCE's own explanation of the failure, already redacted and length-capped by
    ``LceHttpError.__init__``. Probing a live appliance found no credential or header echo, but only
    two error shapes could be observed (no validation-error or 5xx body), so the sanitisation is
    unconditional.

    :param exc: The exception to translate.
    :return: ``{"error": {...}}`` with at least ``type`` and ``message``.
    """
    special = _specialised_error_payload(exc)
    if special is not None:
        # Checked first; see ``_sl1_error_payload`` for why the ordering matters.
        return {"error": special}

    error: dict[str, object]
    match exc:
        case ValidationBlocked():
            error = {
                "type": "validation_blocked",
                "message": (
                    "The request was rejected before it reached Skylar One. Correct every path "
                    "listed in details and resubmit."
                ),
                # Every finding, one entry per offending path.
                "details": [
                    {"path": f.path, "rule": str(f.rule), "message": f.message}
                    for f in exc.findings
                ],
            }
        case LceHttpError():
            error = {
                "type": "lce_http_error",
                "message": (
                    "LCE rejected the request. Inspect lce_status and the LCE-supplied body, "
                    "correct "
                    "the request, and retry if appropriate."
                ),
                "lce_status": exc.status_code,
                # LCE's own explanation of the failure, which the message tells the caller to
                # inspect. ``LceHttpError.__init__`` has already redacted and capped it.
                "lce_body": exc.lce_body,
            }
        case LceUnreachable():
            error = {
                "type": "lce_unreachable",
                "message": (
                    "LCE could not be reached. Confirm the LCE service is running and that the "
                    "target "
                    "host is correct, then retry."
                ),
            }
        case LceMalformedResponse():
            error = {
                "type": "lce_malformed_response",
                "message": (
                    "LCE returned a response that was not valid JSON. Retry; if it persists, "
                    "check the "
                    "LCE service logs."
                ),
            }
        case DbQueryTimeout():
            error = {
                "type": "db_query_timeout",
                "message": (
                    "The database query exceeded its statement timeout and was stopped by the "
                    "server. Narrow the query and retry."
                ),
            }
        case DbUnreachable():
            error = {
                "type": "db_unreachable",
                "message": (
                    "The appliance database could not be reached. Confirm the platform database is "
                    "running, then retry."
                ),
            }
        case DbError():
            error = {
                "type": "db_error",
                "message": (
                    "The database rejected or failed the request. Retry; if it persists, check the "
                    "appliance database logs."
                ),
            }
        case CredentialMissing():
            error = {
                "type": ERROR_TYPE_CREDENTIAL_MISSING,
                "message": (
                    "The request carried no usable credential. Present your Skylar One credential "
                    "in the Authorization header and retry."
                ),
            }
        case _:
            # Any other PowerPackMcpError, including ConfigurationError (which should never arrive
            # here), degrades to the generic internal_error rather than leaking a class name or a
            # message.
            error = {
                "type": ERROR_TYPE_INTERNAL,
                "message": (
                    "An internal error occurred. Quote the correlation identifier from the "
                    "response "
                    "headers when reporting this."
                ),
            }
    return {"error": error}
