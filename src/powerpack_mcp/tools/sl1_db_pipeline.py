"""
SL1 Platform Tool Context and Shared Helpers

This module provides the context object the SL1 platform tools receive, the ``master.*`` write
audit decorator, and the lookups and coercions those tools share.

``Sl1DbToolContext`` is separate from ``sl1_pipeline.Sl1ToolContext`` rather than an extension of
it. Adding a database handle there would put it on every SL1 tool, and a context's fields are a
claim about what its tools may touch; most SL1 tools must never reach the database.
"""

from __future__ import annotations

import functools
import logging
from typing import TYPE_CHECKING, Final

from powerpack_mcp.errors import FindingCode, LogEvent, ValidationBlocked, ValidationFinding

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from sl_mysql.silo_cursor import Row

    from powerpack_mcp.config import Config
    from powerpack_mcp.credentials import LceCredential
    from powerpack_mcp.db_client import DbClient
    from powerpack_mcp.lce_client.client import LceClient
    from powerpack_mcp.sl1_client import Sl1Client
    from powerpack_mcp.tools.sl1_db_descriptors import DbToolDescriptor

__all__ = [
    "SEVERITY_IN",
    "SEVERITY_OUT",
    "SOURCE_IN",
    "SOURCE_OUT",
    "Sl1DbToolContext",
    "actor_user_id",
    "as_int",
    "coded",
    "master_write_audit",
    "one_value",
    "refuse",
    "resolve_device",
]


class Sl1DbToolContext:
    """What the SL1 platform tools need. Mirrors ``Sl1ToolContext`` and adds ``db``.

    ``db`` is ``None`` when the platform database is unavailable or the DB tool sets are disabled.
    Every SQL tool must check it (see ``require_db``). The context cannot refuse to be built without
    a database, because the non-SQL tools must keep working in exactly that state.

    ``credential_source`` is a callable because this object is process-scoped and a credential is
    request-scoped, so it cannot hold one.
    """

    __slots__ = ("client", "config", "credential_source", "db", "lce_client")

    def __init__(
        self,
        client: Sl1Client,
        config: Config,
        credential_source: Callable[[], LceCredential],
        lce_client: LceClient,
        db: DbClient | None = None,
    ) -> None:
        self.client = client
        self.config = config
        self.credential_source = credential_source
        self.lce_client = lce_client
        self.db = db

    def require_db(self) -> DbClient:
        """Return the ``DbClient``, or refuse the call if there is none.

        Raises ``ValidationBlocked`` rather than a builtin, because ``sl1_tool_boundary`` translates
        only ``PowerPackMcpError``; a builtin would reach the caller as an unhandled exception
        instead of an error payload.

        :raises ValidationBlocked: If the appliance database is not available.
        """
        if self.db is None:
            raise ValidationBlocked(
                (
                    ValidationFinding(
                        path="",
                        rule=FindingCode.TOOL_ARGUMENT,
                        message=(
                            "This tool needs the appliance database, which is not available in "
                            "this deployment."
                        ),
                    ),
                )
            )
        return self.db


def master_write_audit[R](
    descriptor: DbToolDescriptor,
) -> Callable[[Callable[..., Awaitable[R]]], Callable[..., Awaitable[R]]]:
    """Audit every ``master.*`` write with the tool, the actor and the outcome.

    Attribution is the accountability mechanism for these writes, so every outcome is recorded,
    including refusal. The decorator must sit inside ``sl1_tool_boundary``, which translates
    exceptions into payloads; outside it, every path would look like a returned dict and success,
    refusal and failure could not be told apart::

        @sl1_tool_boundary(d.SIMULATE_EVENT)     # outer: exception -> payload
        @master_write_audit(d.SIMULATE_EVENT)    # inner: sees the raise
        async def sl1_simulate_event(...): ...

    The record deliberately carries no SQL, bound parameters, argument values, connection material
    or credential. It answers only who invoked which write and how the call ended.

    ``outcome="failed"`` does not mean nothing changed. Autocommit is on and there is no
    transaction, so a failure part-way through a statement sequence has already applied the
    statements before it.

    The decorator is generic over the return type so it stays invisible to the boundary's payload
    type, and ``functools.wraps`` keeps ``__doc__`` and the signature, which FastMCP needs for the
    tool description and JSON schema. ``test_sl1_db_tools.py`` asserts both.

    :param descriptor: The descriptor of the tool being wrapped.
    :return: A decorator for the tool function.
    """

    def decorate(tool: Callable[..., Awaitable[R]]) -> Callable[..., Awaitable[R]]:
        @functools.wraps(tool)
        async def audited(*args: object, **kwargs: object) -> R:
            outcome = "failed"
            try:
                result = await tool(*args, **kwargs)
            except ValidationBlocked:
                outcome = "refused"
                raise
            else:
                outcome = "success"
                return result
            finally:
                # Runs for any ``BaseException``, so a cancellation is audited too, as "failed": a
                # cancelled write may already have committed, which is when the trail matters most.
                logger.info(
                    "master.* write attempted.",
                    extra={
                        "event": str(LogEvent.MASTER_WRITE_AUDITED),
                        "tool": descriptor.tool_name,
                        "actor": _audit_actor(),
                        "outcome": outcome,
                    },
                )

        return audited

    return decorate


def _audit_actor() -> str | None:
    """Return the forwarded caller identity, through ``sl1_pipeline``'s accessor.

    The import is function-local to break the cycle ``sl1_pipeline`` documents. Returns ``None``
    when no identity was forwarded, because a placeholder like ``"unknown"`` would be
    indistinguishable from a real actor with that name.
    """
    from powerpack_mcp.tools.sl1_pipeline import _actor

    return _actor()


# Upper bound for a forwarded account id: ``master_logs.device_tools.user_edit`` is
# ``int(11) unsigned``. Checked here so an absurd header yields ``None`` rather than an
# ``OperationalError`` that discards a pooled connection to establish the same thing.
_MAX_ACCOUNT_ID: Final[int] = 4_294_967_295


def actor_user_id() -> int | None:
    """Return the authenticated SL1 account id of the caller, or ``None``.

    Used for the ``master_logs.device_tools`` audit row. Deliberately not ``_audit_actor``, which
    prefers the credential username and so returns ``"em7admin"`` rather than ``1``. This needs the
    numeric id, and the trustworthy one: nginx writes ``X-User-ID`` from its own ``auth_request``
    subrequest with ``proxy_set_header``, overwriting anything the client sent, whereas the username
    comes from the client-supplied ``Authorization`` header.

    The caller must not back-fill ``None``. ``user_edit`` is ``NOT NULL DEFAULT 1``, so omitting the
    column or substituting a placeholder attributes the run to uid 1, ``em7admin``, a real account.
    Skip the audit row instead, as ``sl1_run_dynamic_collection`` does. ``None`` occurs in normal
    operation, for example when a request reaches the loopback port without going through nginx.

    The range check is needed because the header sanitiser permits ``0`` and up to 128 digits.
    ``0`` is not an account, and an out-of-range value would fail the ``int(11) unsigned`` column
    and cost a discarded pooled connection.
    """
    import contextlib

    from fastmcp.server.dependencies import get_http_request

    from powerpack_mcp.mcp_app.correlation import forwarded_actor

    with contextlib.suppress(RuntimeError):
        # ``RuntimeError`` outside an HTTP context, e.g. a unit test calling the tool directly.
        actor = forwarded_actor(get_http_request().scope)
        if actor is not None and actor.isdecimal():
            # ``isdecimal``, never ``isdigit``: "\u00b2".isdigit() is True and int() raises.
            user_id = int(actor)
            if 0 < user_id <= _MAX_ACCOUNT_ID:
                return user_id
    return None


def refuse(path: str, message: str) -> ValidationBlocked:
    """Build the standard caller-facing refusal.

    One constructor for every refusal, so no tool accidentally raises a builtin that
    ``sl1_tool_boundary`` would not translate.

    :param path: The argument the refusal is about, or ``""``.
    :param message: The caller-facing message.
    :return: The exception, for the caller to raise.
    """
    return ValidationBlocked(
        (ValidationFinding(path=path, rule=FindingCode.TOOL_ARGUMENT, message=message),)
    )


async def resolve_device(context: Sl1DbToolContext, device: str) -> tuple[int, str]:
    """Resolve a device id or name to ``(did, name)`` through REST.

    Unlike the reference implementation, this raises rather than returning an error string, so a
    forgotten check cannot read as success, and it returns ``did`` as an ``int`` so SQL tools bind
    an integer parameter without each remembering the cast.

    The name search deliberately omits ``extended_fetch``: only the id is needed, and
    ``extended_fetch=1`` would fetch full records for up to five devices per resolution.

    :param context: The tool context.
    :param device: A numeric device id or a device name substring.
    :return: ``(did, name)``.
    :raises ValidationBlocked: If ``device`` is empty or does not resolve.
    """
    value = device.strip()
    if not value:
        raise refuse("device", "device must not be empty.")

    credential = context.credential_source()
    # ``isdecimal()``, not ``isdigit()``; see ``coded()``.
    if value.isdecimal():
        found = await context.client.request(
            credential=credential, method="GET", path=f"device/{int(value)}"
        )
        name = found.get("name") if isinstance(found, dict) else None
        return int(value), str(name or value)

    index = await context.client.request(
        credential=credential,
        method="GET",
        path="device",
        query={"filter.name.contains": value, "hide_filterinfo": "1", "limit": "5"},
    )
    matched = _first_indexed_device(index, value)
    if matched is not None:
        return matched
    raise refuse("device", f"Could not resolve device {device!r} through the SL1 REST API.")


def _first_indexed_device(index: object, value: str) -> tuple[int, str] | None:
    """Return ``(did, name)`` for the first device link in a REST ``device`` index, if any.

    :param index: The decoded ``GET device`` response.
    :param value: The stripped search text, used as the name when a link has no description.
    :return: ``(did, name)``, or ``None`` when the index holds no device link.
    """
    if not isinstance(index, dict):
        return None
    for uri, link in index.items():
        candidate = uri.rstrip("/").split("/")[-1]
        # ``isdecimal()``, as at every other numeric-branch selector; see ``coded()``.
        if "/device/" in uri and candidate.isdecimal():
            described = link.get("description") if isinstance(link, dict) else None
            return int(candidate), str(described or value)
    return None


def one_value(rows: tuple[Row, ...]) -> object | None:
    """Return the first column of the first row, or ``None`` when there are no rows.

    The empty case is the point of this helper. Several SQL tools resolve an identifier through a
    statement whose empty result means "that thing does not exist", which the reference
    implementation turned into a silent no-op through ``COALESCE`` (see ``sl1_db_statements``).
    Typed ``object | None`` rather than ``Any`` so every caller must narrow explicitly instead of
    letting an absent row flow onward as a usable value.
    """
    if not rows or not rows[0]:
        return None
    return rows[0][0]


def as_int(value: object, *, argument: str) -> int:
    """Coerce a resolved database value to ``int``, refusing rather than raising a builtin.

    A bare ``int()`` on an unexpected column type raises ``TypeError`` or ``ValueError``, which
    ``sl1_tool_boundary`` does not translate, so it would reach the caller as an unhandled
    exception. ``bool`` is refused even though it is an ``int`` subclass: a boolean where an id was
    expected means the statement selected the wrong column, and ``True`` would become a
    plausible-looking id of ``1``.

    :param value: The value from ``one_value``.
    :param argument: The argument name to report in the refusal.
    :return: The integer value.
    :raises ValidationBlocked: If the value is not an integer identifier.
    """
    if isinstance(value, bool):
        raise refuse(
            argument, f"{argument} resolved to a boolean, which is not a usable identifier."
        )
    if isinstance(value, int):
        return value
    # ``isdecimal()``, not ``isdigit()``, or ``int()`` could raise a builtin; see ``coded()``.
    if isinstance(value, str) and value.strip().isdecimal():
        return int(value.strip())
    raise refuse(
        argument,
        f"{argument} resolved to a value that is not an integer identifier "
        f"(got {type(value).__name__}).",
    )


# ---- Event vocabularies, from the reference implementation's ``events.py`` ----------------------
#
# The input and output tables are not inverses. ``SOURCE_OUT`` has two more entries than
# ``SOURCE_IN``: ``Rules Engine`` (11) and ``Skylar`` (15) can be reported by SL1 but not supplied
# by a caller. Deriving one table from the other would silently widen the accepted input.

SEVERITY_IN: dict[str, int] = {"healthy": 0, "notice": 1, "minor": 2, "major": 3, "critical": 4}
SEVERITY_OUT: dict[int, str] = {0: "Healthy", 1: "Notice", 2: "Minor", 3: "Major", 4: "Critical"}
SOURCE_IN: dict[str, int] = {
    "syslog": 1,
    "internal": 2,
    "trap": 3,
    "dynamic": 4,
    "api": 6,
    "email": 7,
    "agent": 10,
}
SOURCE_OUT: dict[int, str] = {
    1: "Syslog",
    2: "Internal",
    3: "Trap",
    4: "Dynamic",
    6: "API",
    7: "Email",
    10: "Agent",
    11: "Rules Engine",
    15: "Skylar",
}


def coded(value: str, table: dict[str, int], *, argument: str) -> int:
    """Accept a name or its numeric code from ``table``.

    Every numeric-branch selector in the SL1 tools uses ``isdecimal()``, never ``isdigit()``, and
    this is the note that explains why. ``str.isdigit()`` is ``True`` for 128 characters that
    ``int()`` rejects, such as superscripts (``²``) and the digit forms of several scripts; a sweep
    of every code point found ``isdecimal()`` implies ``isdigit()`` with no exceptions. With
    ``isdigit()``, ``category="²"`` reached ``int("²")`` and raised a bare ``ValueError`` that
    ``sl1_tool_boundary`` does not translate.

    Because ``isdecimal`` is a strict subset of ``isdigit``, the swap only removes inputs that
    previously crashed. It diverges deliberately from the reference implementation, which uses
    ``isdigit()``; do not put it back.

    An unrecognised value is refused, never ignored: falling through to no filter would give the
    caller unfiltered results they believe are filtered.

    :param value: The caller-supplied name or numeric code.
    :param table: Name-to-code mapping, such as ``SEVERITY_IN``.
    :param argument: The argument name to report in a refusal.
    :return: The numeric code.
    :raises ValidationBlocked: If the value is not a known name or code.
    """
    text = value.strip().lower()
    if text.isdecimal():
        code = int(text)
        if code not in set(table.values()):
            allowed = sorted(table.values())
            raise refuse(argument, f"{argument} code {code} is not one of {allowed}.")
        return code
    if text not in table:
        raise refuse(argument, f"{argument} must be one of: {', '.join(sorted(table))}.")
    return table[text]
