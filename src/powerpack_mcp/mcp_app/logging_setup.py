"""
Logging Configuration

This module installs the service's log format and filter chain on the root logger. The format is
``config.LOG_FORMAT``, the standard appliance log format, which has no slot for ``correlation_id``,
``event``, ``tool`` or ``duration_ms``::

    %(asctime)s::%(levelname)s::%(process)d::%(name)s.%(lineno)d:::%(message)s

Those fields are appended to the message as deterministic ``key=value`` pairs, so every existing
``::``-delimited appliance log parser still works. The trade-off is that ``event`` is a stable
greppable token inside the message rather than a first-class field; a JSON formatter would have
broken the existing parsers.

The module also reroutes the ``fastmcp`` logger into this chain. fastmcp 3.4.7 logs a rejected
tool call's argument values, and its logger ships with ``propagate = False`` and its own stderr
handlers, so those records would otherwise bypass redaction. See ``PydanticErrorInputFilter`` and
``_reroute_fastmcp_logging``.
"""

from __future__ import annotations

import logging
import sys
from typing import ClassVar, Final

from powerpack_mcp.config import LOG_FORMAT

# ``REDACTED`` and ``SECRET_FIELD_DENYLIST`` live in ``errors`` because ``errors`` needs them for
# ``sanitize_lce_body`` and, as the dependency graph's leaf, cannot import this module. They are
# re-exported here so existing imports keep working.
from powerpack_mcp.errors import REDACTED, SECRET_FIELD_DENYLIST
from powerpack_mcp.mcp_app.correlation import current_correlation_id

__all__ = [
    "REDACTED",
    "SECRET_FIELD_DENYLIST",
    "CorrelationIdFilter",
    "SlConfigExtraFormatter",
    "configure_logging",
]

# Marks handlers this module installed, so `configure_logging` replaces its own and leaves others
# alone.
_OWNED_MARKER: Final[str] = "_powerpack_mcp_handler"

# One upstream path would silently undo the fastmcp reroute. ``fastmcp/server/mixins/transport.py``
# wraps its ``FastMCP.run*`` entry points in ``temporary_log_level(...)``, which calls fastmcp's own
# ``configure_logging``, re-adding its ``RichHandler``s and resetting ``propagate = False``. Every
# later record would bypass this chain, unredacted, and nothing would fail.
#
# That path is not reachable today: nothing in ``src/`` calls ``run``, ``run_async``,
# ``run_http``, ``run_stdio`` or ``temporary_log_level``, and ``main.py`` drives the ASGI app
# through ``uvicorn.run``. This is a constraint on future changes. Switching the service to
# ``FastMCP.run()`` would reopen the leak with no test failing, because the reroute runs once at
# startup; if that switch is made, the reroute must move after it.
#
# The logger name is a string on purpose. This module imports nothing from fastmcp:
# ``configure_logging`` runs before configuration is read, and pulling a server framework in here
# would make a configuration failure harder to log. A logger name is a stable public coupling.
_FASTMCP_LOGGER_NAME: Final[str] = "fastmcp"

# Keys of one ``pydantic.ValidationError.errors()`` entry. ``input`` holds the offending value
# verbatim and untruncated, which is the leak. The other three are the diagnostic, so scrubbing
# ``input`` is not equivalent to deleting the log line.
_PYDANTIC_ERROR_VALUE_KEY: Final[str] = "input"
_PYDANTIC_ERROR_SHAPE: Final[frozenset[str]] = frozenset({"type", "loc", "msg"})

# Fields appended in this order first, then anything else alphabetically. A deterministic order
# matters because log assertions and appliance grep patterns both depend on it.
_PREFERRED_FIELD_ORDER: Final[tuple[str, ...]] = (
    "correlation_id",
    "event",
    "tool",
    "lce_operation",
    "target_host",
    "outcome",
    "duration_ms",
    "actor",
)

# Everything the stdlib puts on a LogRecord. Any other attribute arrived through ``extra=`` and is
# rendered by the formatter.
_STANDARD_RECORD_ATTRS: Final[frozenset[str]] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


class CorrelationIdFilter(logging.Filter):
    """Inject the correlation identifier onto every record.

    A filter rather than a format placeholder: ``%(correlation_id)s`` in the format string would
    make ``logging`` raise on any record lacking the attribute, including records from third-party
    libraries.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "correlation_id"):
            record.correlation_id = current_correlation_id()
        return True


class RedactingFilter(logging.Filter):
    """Replace the value of any denylisted field name with a fixed marker.

    Runs last in the chain, so it also covers anything an earlier filter added.

    Structural isolation of secrets in ``config`` is the primary control; this is a safety net, so
    that no single control is the only defence. It catches a secret arriving from elsewhere, most
    plausibly a request header logged by accident while debugging.

    A denylist cannot know about a field named ``x_auth_blob``. Do not treat this as the primary
    control.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        for key in list(vars(record)):
            if key.lower() in SECRET_FIELD_DENYLIST:
                setattr(record, key, REDACTED)
        return True


def _scrub_pydantic_errors(value: object) -> object:
    """Return ``value`` with ``input`` removed from every pydantic error entry inside it.

    Returns the argument itself when there is nothing to strip, which is how
    ``PydanticErrorInputFilter`` decides whether to touch the record. It compares by identity, not
    equality, so no third-party ``__eq__`` is invoked on a value this service does not control.

    A mapping is rewritten only if it carries ``input`` and all of ``type``, ``loc`` and ``msg``,
    that is, only if it is a pydantic error entry. A dict that merely has an ``input`` key is left
    alone.
    """
    if isinstance(value, dict):
        if _PYDANTIC_ERROR_VALUE_KEY in value and value.keys() >= _PYDANTIC_ERROR_SHAPE:
            return {key: entry for key, entry in value.items() if key != _PYDANTIC_ERROR_VALUE_KEY}
        return value
    if isinstance(value, list):
        # ``errors()`` returns a list of entries. Recursion stops at one level of list with
        # mappings inside, which is pydantic's documented shape; an unbounded walk over arbitrary
        # log arguments is what ``errors.MAX_LCE_BODY_DEPTH`` guards against elsewhere.
        scrubbed = [_scrub_pydantic_errors(item) for item in value]
        if all(new is old for new, old in zip(scrubbed, value, strict=True)):
            return value
        return scrubbed
    return value


class PydanticErrorInputFilter(logging.Filter):
    """Strip the offending value out of a pydantic validation-error record.

    fastmcp 3.4.7 logs a rejected tool call at WARNING with the argument values included
    (``fastmcp/server/server.py``)::

        logger.warning("Invalid arguments for tool %r: %s", name, cause.errors(include_url=False))

    Every ``errors()`` entry carries ``input``, the offending value verbatim and untruncated. A
    canary secret placed in a wrongly typed ``sl1_graphql.query`` argument came back out of the log
    word for word. fastmcp 2.14.7 logged nothing at this site. The systemd unit sends stderr to
    syslog, so such a record is persisted to appliance logs. ``global_error_handler`` logs only
    ``type(exc).__name__`` for the same reason: an exception's text can carry the value that caused
    it.

    ``RedactingFilter`` cannot cover this: it matches denylisted attribute names, and this secret
    is an opaque string in a value position inside ``record.args``.

    The filter scrubs ``record.args`` rather than the message text. A filter sees the record
    unformatted, with ``record.msg`` still the template and the values in ``record.args`` (for
    this call, a 2-tuple of ``(tool_name, list[dict])``), so the value is removed before any
    handler renders it and the diagnostic survives.

    Known gap: ``msg`` and ``ctx`` are kept. For a ``value_error`` entry, ``msg`` is the
    validator's own message, so a validator that interpolates its input would still leak.
    Dropping ``msg`` would lose the whole diagnostic; that fix belongs in the validator. This is a
    safety net for a known dependency behaviour, not a guarantee about all log arguments.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        # A non-tuple ``args`` is ``logging``'s mapping form (``logger.info("%(k)s", {...})``).
        # Removing a key from it would make ``record.getMessage()`` raise ``KeyError`` and lose
        # the record, so it is left untouched; the leak being fixed never takes that form.
        if not isinstance(args, tuple):
            return True
        scrubbed = tuple(_scrub_pydantic_errors(arg) for arg in args)
        if any(new is not old for new, old in zip(scrubbed, args, strict=True)):
            # Mutating in place is deliberate: a filter cannot hand a modified copy onward, and
            # because the record is shared, the scrub protects every handler on the root logger.
            # It cannot break formatting, because the template renders the whole list through a
            # single ``%s``.
            record.args = scrubbed
        return True


class SlConfigExtraFormatter(logging.Formatter):
    """Render the appliance log format exactly, then append extra fields as ``key=value`` pairs.

    The prefix is unchanged, so an appliance parser splitting on ``:::`` still finds the message it
    expects, with the structured fields trailing inside it.
    """

    # Values containing whitespace or '=' are quoted so the appended section stays unambiguously
    # parseable.
    _NEEDS_QUOTING: ClassVar[frozenset[str]] = frozenset({" ", "\t", "=", '"'})

    def __init__(self) -> None:
        super().__init__(fmt=LOG_FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = self._collect_extras(record)
        if not extras:
            return base
        rendered = " ".join(f"{key}={self._render(value)}" for key, value in extras)
        return f"{base} {rendered}"

    def _collect_extras(self, record: logging.LogRecord) -> list[tuple[str, object]]:
        present = {
            key: value
            for key, value in vars(record).items()
            if key not in _STANDARD_RECORD_ATTRS and not key.startswith("_")
        }
        ordered: list[tuple[str, object]] = [
            (key, present.pop(key)) for key in _PREFERRED_FIELD_ORDER if key in present
        ]
        ordered.extend(sorted(present.items()))
        return ordered

    def _render(self, value: object) -> str:
        # Newlines are escaped rather than quoted: a real newline would forge a second log record,
        # the same log-injection concern the correlation-id rules address.
        text = str(value).replace("\r", "\\r").replace("\n", "\\n")
        if any(ch in text for ch in self._NEEDS_QUOTING) or text == "":
            escaped = text.replace('"', '\\"')
            return f'"{escaped}"'
        return text


def _reroute_fastmcp_logging() -> bool:
    """Send fastmcp's records to the root logger, where this module's chain and format live.

    Measured on fastmcp 3.4.7:

    * The leaking record comes from the ``fastmcp.server.server`` logger. ``logging`` runs a
      logger's filters only on the originating logger; ancestors contribute handlers, not
      filters, so a filter on the ``fastmcp`` logger never runs for this record. Filtering must
      happen on a handler, which is why ``PydanticErrorInputFilter`` is on the handler that
      ``configure_logging`` installs, and why this function only has to make the record reach it.
    * The ``fastmcp`` logger ships with ``propagate = False``, level INFO and two ``RichHandler``s
      writing to stderr, so its records bypassed correlation, redaction and the appliance log
      format.

    Clearing those handlers and propagating fixes that. It is idempotent, because
    ``configure_logging`` runs twice at startup and both settings are absolute.

    fastmcp's own level (INFO) is left alone, so ``LOG_LEVEL`` does not govern fastmcp's records,
    as before. Making fastmcp inherit the root level would change log volume in both directions,
    which is a separate decision.

    Ordering matters. fastmcp configures its logger at import time (``fastmcp/__init__.py`` calls
    its own ``configure_logging`` when ``settings.log_enabled``), so if this ran before fastmcp was
    imported, fastmcp would re-add its handlers and silently undo the reroute. Today
    ``configure_logging`` is called only from ``start_up``, and ``app.py`` imports ``fastmcp`` at
    module level, so the order holds. Rather than rely on that, this checks ``sys.modules`` and
    ``configure_logging`` logs a WARNING if fastmcp is not yet loaded.

    :return: ``True`` if fastmcp was already imported, so the reroute is durable.
    """
    already_imported = _FASTMCP_LOGGER_NAME in sys.modules
    logger = logging.getLogger(_FASTMCP_LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    logger.propagate = True
    return already_imported


def configure_logging(log_level: str = "INFO") -> None:
    """Install the appliance log format and the filter chain on the root logger.

    Also reroutes the ``fastmcp`` logger into the chain; see ``_reroute_fastmcp_logging`` for the
    import-order dependency that carries.

    Called first at startup, before configuration is loaded, so a configuration failure is itself
    logged in the structured format. That is why it takes a level string rather than a ``Config``.

    The service is granted no log-management permission, so it cannot delete or rewrite its own
    history; the systemd unit enforces that, not this function.

    :param log_level: A ``logging`` level name, such as ``"INFO"``.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(SlConfigExtraFormatter())
    # Order matters:
    #
    #   1. ``PydanticErrorInputFilter`` first. It is the only filter that removes data, and it works
    #      on ``record.args`` rather than attributes, so it is placed first so the value is gone
    #      before a later filter could copy it onto an attribute, where only the denylist would
    #      govern it.
    #   2. ``CorrelationIdFilter`` injects, then
    #   3. ``RedactingFilter`` runs last, so it also covers anything injected.
    handler.addFilter(PydanticErrorInputFilter())
    handler.addFilter(CorrelationIdFilter())
    handler.addFilter(RedactingFilter())
    setattr(handler, _OWNED_MARKER, True)

    root = logging.getLogger()
    # Replace only our own previous handler, so repeated calls (``start_up`` calls this twice)
    # do not duplicate every record. Removing every handler would also remove handlers this
    # service does not own, such as pytest's log capture.
    for existing in list(root.handlers):
        if getattr(existing, _OWNED_MARKER, False):
            root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(log_level.strip().upper())

    # Reroute after the handler is on the root logger, so fastmcp's records have somewhere to land
    # as soon as they propagate, and the warning below (which fires exactly when the reroute is not
    # durable) goes through the chain.
    if not _reroute_fastmcp_logging():
        # No ``event=`` key: ``LogEvent`` is a closed vocabulary. The message is greppable
        # instead.
        logging.getLogger(__name__).warning(
            "fastmcp is not imported, so its logger may be reconfigured after this call and "
            "bypass the redaction chain. Import fastmcp before "
            "configure_logging.",
        )
