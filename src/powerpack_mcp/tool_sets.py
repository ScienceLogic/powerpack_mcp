"""
Tool-Set Flag Resolution

This module turns the parsed ``ENABLE_*`` flag values into a registration plan: which tool sets
register, how many tools each has, and why a disabled set is off. It is pure, with no I/O, clock
or environment access; ``mcp_app`` executes the plan. Keeping the decision a function from values
to values makes determinism, the nesting rule and the disabled reasons directly testable.

Backend reachability is deliberately not an input. Registering a set only if its backend answers
at startup would make ``tools/list`` differ between restarts, let a transient network blip shrink
the tool surface, and couple startup to every backend's availability. A tool whose backend is down
registers and fails when called, with a clear error. A deployment prerequisite, such as whether
``import sl_mysql`` succeeds, is an input, because it is fixed for the installed service and so
keeps the plan deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol

from powerpack_mcp.errors import ToolSetDisabledReason

if TYPE_CHECKING:
    from collections.abc import Mapping

# ---- set identifiers -------------------------------------------------------------------------
#
# A closed set. These strings appear in the startup log and monitoring keys on them, so they are
# stable identifiers, not display text.

LCE: Final = "lce"
SL1_REST: Final = "sl1_rest"
SL1_GRAPHQL: Final = "sl1_graphql"
DB_READ: Final = "db_read"
DB_WRITE: Final = "db_write"
OPS: Final = "ops"
STANDARDS: Final = "standards"

# Every set, in the order the startup log reports them. ``lce`` comes first so the log reads as a
# complete inventory rather than a list of the optional parts.
ALL_TOOL_SET_IDS: Final[tuple[str, ...]] = (
    LCE,
    SL1_REST,
    SL1_GRAPHQL,
    DB_READ,
    DB_WRITE,
    OPS,
    STANDARDS,
)

# The env-file key gating each set, or ``None`` for ``lce``, which has no key and is reported as
# always-on. Every value is a fixed key name or ``None``; nothing operator-supplied reaches it.
FLAG_KEY_FOR: Final[Mapping[str, str | None]] = {
    LCE: None,
    SL1_REST: "ENABLE_SL1_REST_TOOLS",
    SL1_GRAPHQL: "ENABLE_SL1_GRAPHQL_TOOLS",
    DB_READ: "ENABLE_DB_TOOLS",
    DB_WRITE: "ENABLE_DB_WRITE_TOOLS",
    OPS: "ENABLE_OPS_TOOLS",
    STANDARDS: "ENABLE_STANDARDS_TOOLS",
}


class ToolSetFlagSource(Protocol):
    """Anything carrying the ``ENABLE_*`` flags: in practice ``Config``, in tests a stub.

    A ``Protocol`` rather than a concrete type, so this module stays a pure function of booleans
    and does not depend on the configuration model.
    """

    ENABLE_SL1_REST_TOOLS: bool
    ENABLE_SL1_GRAPHQL_TOOLS: bool
    ENABLE_DB_TOOLS: bool
    ENABLE_DB_WRITE_TOOLS: bool
    ENABLE_OPS_TOOLS: bool
    ENABLE_STANDARDS_TOOLS: bool


@dataclass(frozen=True, slots=True)
class ToolSetFlags:
    """The resolved flag values. The ``lce`` set has no flag, so it is absent here.

    Every flag defaults to enabled, which is the shipped default.
    """

    sl1_rest: bool = True
    sl1_graphql: bool = True
    db_tools: bool = True
    db_write_tools: bool = True
    ops_tools: bool = True
    standards_tools: bool = True

    @classmethod
    def from_config(cls, config: ToolSetFlagSource) -> ToolSetFlags:
        """Read the ``ENABLE_*`` fields off anything that carries them.

        :param config: The configuration, typed structurally as ``ToolSetFlagSource``.
        :return: The resolved flags.
        """
        return cls(
            sl1_rest=bool(config.ENABLE_SL1_REST_TOOLS),
            sl1_graphql=bool(config.ENABLE_SL1_GRAPHQL_TOOLS),
            db_tools=bool(config.ENABLE_DB_TOOLS),
            db_write_tools=bool(config.ENABLE_DB_WRITE_TOOLS),
            ops_tools=bool(config.ENABLE_OPS_TOOLS),
            standards_tools=bool(config.ENABLE_STANDARDS_TOOLS),
        )


@dataclass(frozen=True, slots=True)
class ToolSetRecord:
    """One set's resolved state, which is also its startup log record.

    One type serving both uses means the log cannot drift from the decision it reports. There is
    no free-text field, so there is no field a secret could occupy: every value is a fixed
    identifier, a boolean, an integer or a closed-enum member. ``tests/unit/test_tool_sets.py``
    asserts this field set exactly, so adding a field fails a test.

    :ivar set_id: The tool-set identifier.
    :ivar registered: Whether the set registers.
    :ivar tool_count: Tools registered for the set; 0 when not registered.
    :ivar flag: The env-file key gating the set, or ``None`` for an always-on set.
    :ivar reason: Why the set is disabled, or ``None`` when registered.
    """

    set_id: str
    registered: bool
    tool_count: int
    flag: str | None
    reason: ToolSetDisabledReason | None

    @property
    def always_on(self) -> bool:
        """Whether the set is always on, derived from ``flag``."""
        return self.flag is None


@dataclass(frozen=True, slots=True)
class RegistrationPlan:
    """What ``mcp_app`` should register, and what it should log. Data only.

    Covers every set, including ``lce``, so the startup log is a complete inventory.
    """

    records: tuple[ToolSetRecord, ...]

    @property
    def registered_ids(self) -> tuple[str, ...]:
        """Return the sets to register, in ``ALL_TOOL_SET_IDS`` order.

        The order is fixed so ``tools/list`` is deterministic for identical configuration across
        restarts.
        """
        return tuple(r.set_id for r in self.records if r.registered)

    @property
    def total_tools(self) -> int:
        return sum(r.tool_count for r in self.records if r.registered)

    def record_for(self, set_id: str) -> ToolSetRecord:
        for record in self.records:
            if record.set_id == set_id:
                return record
        raise KeyError(set_id)


def resolve(
    flags: ToolSetFlags,
    tool_counts: Mapping[str, int],
    prerequisites_met: Mapping[str, bool] | None = None,
) -> RegistrationPlan:
    """Turn flag values into a registration plan.

    A deployment prerequisite is an input to the decision rather than a condition applied after
    it. Otherwise an appliance with no working database driver would log a DB set as registered
    with a non-zero tool count while registering nothing. This does not make backend reachability
    an input: a missing driver is fixed for a given deployment, so the plan stays deterministic.

    :param flags: The resolved flag values.
    :param tool_counts: How many tools each set has available in the shipped code. A missing set
        counts as 0.
    :param prerequisites_met: Whether each set's build-time or deployment prerequisite holds. A
        set absent from the mapping has no prerequisite.
    :return: The registration plan for every set.
    """
    records: list[ToolSetRecord] = []
    prerequisites = prerequisites_met or {}
    for set_id in ALL_TOOL_SET_IDS:
        registered, reason = _decide(set_id, flags, prerequisites)
        records.append(
            ToolSetRecord(
                set_id=set_id,
                registered=registered,
                # A set that is not registered reports 0, not the count it would have had: its tools
                # are never constructed.
                tool_count=tool_counts.get(set_id, 0) if registered else 0,
                flag=FLAG_KEY_FOR[set_id],
                reason=reason,
            )
        )
    return RegistrationPlan(records=tuple(records))


def _decide(
    set_id: str, flags: ToolSetFlags, prerequisites: Mapping[str, bool]
) -> tuple[bool, ToolSetDisabledReason | None]:
    """Apply the registration rule for one set.

    ``db_write`` is the only set with two flag inputs, because it is nested under
    ``ENABLE_DB_TOOLS``.

    The flags are checked first and the prerequisite only after, and the order matters. With
    ``ENABLE_DB_TOOLS=false`` on a machine with no driver, checking the prerequisite first would
    report ``PREREQUISITE_MISSING`` and hide that the operator's own instruction took effect. With
    the flag on and the driver missing, flag-first still reports ``PREREQUISITE_MISSING``.

    :return: ``(registered, reason_if_not)``.
    """
    if set_id == LCE:
        # No flag, always registered. No configuration turns the LCE tools off; the service
        # shipping disabled is the control at that level.
        return True, None

    registered, reason = _decide_from_flags(set_id, flags)
    if not registered:
        return registered, reason

    # Only reached when configuration would otherwise register the set.
    #
    # ``ops`` is deliberately absent from every caller's mapping: its tools need no driver, no
    # ``libem7`` and no ``silo.conf``, so a driver failure must not touch them.
    if prerequisites.get(set_id, True) is False:
        return False, ToolSetDisabledReason.PREREQUISITE_MISSING
    return True, None


def _decide_from_flags(
    set_id: str, flags: ToolSetFlags
) -> tuple[bool, ToolSetDisabledReason | None]:
    """Apply the configuration half of the decision."""
    if set_id == DB_WRITE:
        if not flags.db_tools:
            # Resolved, not an error, and reported distinguishably. An operator who disabled DB
            # tools wholesale expressed a clear intent; refusing to start because the nested key
            # still says true would punish the safe direction. Startup fails only for a value that
            # cannot be understood, and this one can.
            return False, ToolSetDisabledReason.DISABLED_BY_NESTING
        if not flags.db_write_tools:
            return False, ToolSetDisabledReason.DISABLED_BY_CONFIGURATION
        return True, None

    enabled = {
        SL1_REST: flags.sl1_rest,
        SL1_GRAPHQL: flags.sl1_graphql,
        DB_READ: flags.db_tools,
        OPS: flags.ops_tools,
        STANDARDS: flags.standards_tools,
    }[set_id]
    return (True, None) if enabled else (False, ToolSetDisabledReason.DISABLED_BY_CONFIGURATION)
