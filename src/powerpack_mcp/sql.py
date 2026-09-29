"""
SQL Statement Construction

This module provides pure construction of the parameterized SQL statements used by the SL1
database tools. Every statement is a ``(sql, params)`` pair; caller values are always bound as
driver parameters and never interpolated into statement text. Identifiers, which cannot be
parameters, come only from closed allowlists in code.

It depends only on ``errors``, so the injection controls can be tested without an appliance.

``Statement`` validates rather than just holding two fields because MySQLdb applies ``sql % args``
whenever ``args`` is not ``None``, so a literal ``%`` in statement text is a format specifier. On
this platform the resulting error is not propagated; the call simply returns no rows::

    execute("... WHERE name LIKE '%Event%'", ())     ->  ()          <-- empty, no exception
    execute("... WHERE name LIKE '%Event%'")         ->  ((41,),)
    execute("... WHERE name LIKE %s", ("%Event%",))  ->  ((41,),)

A mocked test cannot catch that, since the mock never interpolates, so the guard lives in the
constructor where no statement can skip it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from powerpack_mcp.errors import FindingCode, ValidationBlocked, ValidationFinding

__all__ = [
    "LIKE_ESCAPE_CHAR",
    "PLACEHOLDER",
    "Statement",
    "checked_identifier",
    "escape_like_operand",
    "like_contains",
    "like_prefix",
    "placeholders",
]

# The only parameter placeholder MySQLdb accepts in this codebase's statements.
PLACEHOLDER: Final[str] = "%s"

# Escape character for ``LIKE`` operands. MariaDB's default is backslash, but stating it in the
# statement with ``ESCAPE`` makes the behaviour independent of ``NO_BACKSLASH_ESCAPES``.
LIKE_ESCAPE_CHAR: Final[str] = "\\"

# Matches a '%' that is not the start of a '%s' placeholder. ``s\b`` makes '%sfoo' bad too: with a
# word character after the 's' there is no boundary, so the lookahead fails and the '%' is flagged.
# This also rejects '%%' on purpose: patterns are bound as parameters, and escaping is not a
# permitted second route.
_BAD_PERCENT: Final[re.Pattern[str]] = re.compile(r"%(?!s\b)")

_PLACEHOLDER_COUNT: Final[re.Pattern[str]] = re.compile(r"%s\b")

# An identifier we are willing to interpolate: plain ASCII word characters, optionally one dot for
# a schema qualifier. Deliberately stricter than MariaDB allows: anything needing backticks is a
# sign the value came from somewhere it should not have.
_SAFE_IDENTIFIER: Final[re.Pattern[str]] = re.compile(
    r"\A[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?\Z"
)


@dataclass(frozen=True, slots=True)
class Statement:
    """A validated ``(sql, params)`` pair.

    Frozen and slotted so a statement cannot be mutated after its invariants are checked. Two
    invariants are enforced at construction:

    1. No literal ``%`` except as the ``%s`` placeholder. A stray one silently returns no rows
       rather than raising (see the module docstring).
    2. Placeholder count equals parameter count. MySQLdb's failure for a mismatch is a
       ``TypeError`` from ``%``-formatting, which this platform's cursor also swallows, so an
       off-by-one would present as an empty result set too.

    Both raise ``ValueError``, not ``ValidationBlocked``, because a violation is a defect in this
    code, never caller input. Caller-derived values go through ``checked_identifier`` or become
    parameters.

    :ivar sql: Statement text containing ``%s`` placeholders.
    :ivar params: Values bound to the placeholders, in order.
    """

    sql: str
    params: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        bad = _BAD_PERCENT.search(self.sql)
        if bad is not None:
            raise ValueError(
                "literal '%' in statement text at offset "
                f"{bad.start()}: MySQLdb treats it as a format specifier and this platform "
                "returns an empty result set rather than raising. Bind the pattern as a "
                "parameter -- see like_contains()."
            )
        expected = len(_PLACEHOLDER_COUNT.findall(self.sql))
        if expected != len(self.params):
            raise ValueError(
                f"statement has {expected} placeholder(s) but {len(self.params)} parameter(s); "
                "a mismatch is swallowed by the platform cursor and presents as no rows"
            )

    @property
    def placeholder_count(self) -> int:
        """Number of ``%s`` placeholders. Exposed so tests can assert it without re-parsing."""
        return len(_PLACEHOLDER_COUNT.findall(self.sql))


def placeholders(count: int) -> str:
    """Render ``count`` comma-separated placeholders for an ``IN`` list.

    The number of placeholders is structural and cannot itself be a parameter, so it is computed
    from a length rather than taken from caller input.

    :raises ValueError: If ``count`` is less than 1. ``IN ()`` would be a MariaDB syntax error
        reported far from the cause.
    """
    if count < 1:
        raise ValueError(f"placeholders(count) requires count >= 1, got {count}")
    return ", ".join([PLACEHOLDER] * count)


def escape_like_operand(value: str) -> str:
    """Neutralise ``LIKE`` wildcards inside a caller-supplied operand.

    Without this, a caller passing ``%`` would get wildcard semantics they did not ask for,
    widening the rows a statement touches. The operand is still passed as a parameter; this only
    stops it acting as a pattern. The escape character is escaped first, or escaping ``%`` would
    double-escape.
    """
    return (
        value.replace(LIKE_ESCAPE_CHAR, LIKE_ESCAPE_CHAR * 2)
        .replace("%", LIKE_ESCAPE_CHAR + "%")
        .replace("_", LIKE_ESCAPE_CHAR + "_")
    )


def like_contains(value: str) -> str:
    """Build a ``%value%`` parameter value for a substring match.

    The wildcards live in the parameter, never in the statement text. Pair with
    ``LIKE %s ESCAPE '\\\\'`` in the statement.
    """
    return f"%{escape_like_operand(value)}%"


def like_prefix(value: str) -> str:
    """Build a ``value%`` parameter value for a prefix match. See `like_contains`."""
    return f"{escape_like_operand(value)}%"


def checked_identifier(value: str, allowed: frozenset[str], *, argument: str) -> str:
    """Return ``value`` only if it is in ``allowed``.

    A table or column name cannot be a driver parameter, so the only safe source is a closed
    allowlist in code. The membership test is the control. The shape check after it guards against
    a carelessly built allowlist, where a constant containing a backtick or a space would otherwise
    be trusted just for being a constant.

    :param value: The caller-supplied identifier.
    :param allowed: The permitted identifiers.
    :param argument: The tool argument name, used as the finding path.
    :return: ``value``, unchanged.
    :raises ValidationBlocked: If ``value`` is not allowed. This is caller input, so the caller
        gets a finding they can act on.
    :raises ValueError: If an allowlisted value is not a plain identifier, which is a defect here.
    """
    if value not in allowed:
        raise ValidationBlocked(
            (
                ValidationFinding(
                    path=argument,
                    rule=FindingCode.TOOL_ARGUMENT,
                    message=f"{argument!r} must be one of: {', '.join(sorted(allowed))}",
                ),
            )
        )
    if _SAFE_IDENTIFIER.match(value) is None:
        raise ValueError(
            f"allowlisted identifier {value!r} is not a plain identifier; the allowlist is wrong"
        )
    return value
