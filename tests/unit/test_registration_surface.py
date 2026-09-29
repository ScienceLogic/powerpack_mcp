"""
Registration Surface Tests

This module tests the registered tool surface, and every gate-off combination, by building a
server through ``register_tools``. ``authz.REGISTERED_TOOL_COUNT`` is derived from the registry
and pinned in ``test_authz.py``, but that only proves the inventory agrees with itself. It cannot
prove that ``register_tools`` reaches every entry, that no name collides with another tool set's,
or that a flag actually removes tools from ``tools/list``.

There are two real surfaces: 55 tools with the platform DB driver present (an appliance), and 47
without it, where ``db_read`` and ``db_write`` are disabled with ``PREREQUISITE_MISSING`` while
the 14 ``ops`` tools keep working. A developer machine has no driver, so both are asserted, each
with its prerequisite stated.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from fastmcp import FastMCP

from powerpack_mcp import authz
from powerpack_mcp.config import TOOL_SET_FLAG_KEYS, Config
from powerpack_mcp.db_client import DbClient
from powerpack_mcp.errors import ToolSetDisabledReason
from powerpack_mcp.lce_client import LceClient
from powerpack_mcp.mcp_app.app import register_tools
from powerpack_mcp.schema_slim import registered_tools
from powerpack_mcp.sl1_client import Sl1Client
from powerpack_mcp.tools.sl1_db_registry import WITHHELD_TOOLS, db_read_tools, db_write_tools

if TYPE_CHECKING:
    from powerpack_mcp.tool_sets import RegistrationPlan

# The whole surface with every flag at its shipped default and the DB driver present.
FULL_SURFACE = 55

# The tools outside the authz registry: 7 LCE + 22 ``sl1_rest`` + 3 SL1 GraphQL + 1 standards.
#
# The ``sl1_rest`` set's name does not describe its transport: it holds 6 REST and 16 GraphQL
# tools. The guided-discovery tool is in the SL1 GraphQL set with the two passthroughs, so the same
# ``ENABLE_SL1_GRAPHQL_TOOLS`` flag gates it, because its per-step documents are built from
# platform data and are arbitrary GraphQL by construction.
NON_REGISTRY_SURFACE = 33

# The authz registry's contribution: ``db_read`` 3 + ``db_write`` 5 + ``ops`` 14.
REGISTRY_CONTRIBUTION = 22

_ALL_OFF: dict[str, bool] = dict.fromkeys(TOOL_SET_FLAG_KEYS, False)

# Every flag gating a registry tool set, off. Annotated ``dict[str, bool]`` because
# ``dict.fromkeys`` over a literal tuple infers ``dict[Literal[...], bool]``, and dict key types
# are invariant, so pyright rejects it where ``dict[str, bool]`` is wanted.
REGISTRY_OFF: dict[str, bool] = dict.fromkeys(
    ("ENABLE_DB_TOOLS", "ENABLE_DB_WRITE_TOOLS", "ENABLE_OPS_TOOLS"), False
)


def _build(
    overrides: dict[str, bool] | None = None, *, db: bool = True
) -> tuple[list[str], RegistrationPlan]:
    """Return ``(registered_tool_names, plan)`` for one flag configuration.

    Goes through ``register_tools``, the real composition-root seam, rather than the registry
    accessors; that is the point of this file.

    ``db=`` injects the client rather than patching ``platform_available``. The composition root
    constructs the ``DbClient`` and passes it in, so the lifespan can release it, and
    ``db_client is None`` is the one source of truth for the prerequisite. Constructing a
    ``DbClient`` off-appliance opens nothing: it builds a bounded executor and a thread-local store.
    Only executing a statement needs the platform.
    """
    config = Config.model_validate(overrides or {})
    server: FastMCP = FastMCP(name="powerpack-mcp-surface-probe")
    db_client = DbClient(config.MAX_CONCURRENT_REQUESTS) if db else None
    plan = register_tools(server, LceClient(config), config, Sl1Client(config), db_client)
    # Names, not tool objects. ``server.tool`` registers by name and silently overwrites a
    # duplicate, so counting objects would hide a collision behind an unchanged total. The name is
    # also what a client sees in ``tools/list``.
    return sorted(tool.name for tool in registered_tools(server)), plan


class TestTheFullSurface:
    def test_the_full_surface_is_fifty_five_tools(self) -> None:
        names, plan = _build()
        assert len(names) == FULL_SURFACE
        # Asserted two ways on purpose: ``plan.total_tools`` is what the startup log reports, and it
        # must match the tools that actually registered.
        assert plan.total_tools == FULL_SURFACE

    def test_the_registry_contributes_exactly_twenty_two(self) -> None:
        with_registry, _ = _build()
        without_registry, _ = _build(dict(REGISTRY_OFF))
        assert len(without_registry) == NON_REGISTRY_SURFACE
        assert (
            len(with_registry) - len(without_registry)
            == REGISTRY_CONTRIBUTION
            == authz.REGISTERED_TOOL_COUNT
        )

    def test_no_registry_tool_collides_with_another_tool(self) -> None:
        """A collision would silently replace a tool, because ``server.tool`` overwrites by name.

        The count assertion above cannot see this: if one registry tool overwrote an LCE tool, the
        inventory and the surface would both still agree while one earlier tool had vanished.
        """
        earlier, _ = _build(dict(REGISTRY_OFF))
        registry_names = {e.name for e in authz.TOOL_REGISTRY.values() if e.registers}
        assert registry_names & set(earlier) == set()

    def test_every_registering_inventory_entry_actually_reached_the_server(
        self,
    ) -> None:
        """The inventory's claim, checked from the caller's side rather than the data's."""
        names, _ = _build()
        expected = {e.name for e in authz.TOOL_REGISTRY.values() if e.registers}
        assert expected <= set(names)

    def test_neither_withheld_tool_is_registered(self) -> None:
        """Observed at ``tools/list`` rather than in ``_FACTORY_FOR``."""
        names, _ = _build()
        assert WITHHELD_TOOLS & set(names) == set()


class TestEveryGateOffCombination:
    """A disabled set's tools are never constructed, so they cannot appear here."""

    @pytest.mark.parametrize(
        ("flag", "set_id", "expected_removed"),
        [
            ("ENABLE_OPS_TOOLS", "ops", 14),
            ("ENABLE_DB_WRITE_TOOLS", "db_write", 5),
            ("ENABLE_STANDARDS_TOOLS", "standards", 1),
            ("ENABLE_SL1_REST_TOOLS", "sl1_rest", 22),
            ("ENABLE_SL1_GRAPHQL_TOOLS", "sl1_graphql", 3),
        ],
    )
    def test_turning_one_flag_off_removes_exactly_that_set(
        self, flag: str, set_id: str, expected_removed: int
    ) -> None:
        names, plan = _build({flag: False})
        assert len(names) == FULL_SURFACE - expected_removed
        record = plan.record_for(set_id)
        assert record.registered is False
        assert record.reason is ToolSetDisabledReason.DISABLED_BY_CONFIGURATION
        assert record.tool_count == 0

    def test_disabling_db_tools_takes_the_writes_with_it_by_nesting(self) -> None:
        """Eight tools go, not three, and the write set records why distinguishably.

        An operator who disabled DB tools wholesale expressed a clear intent, so the nested write
        flag still reading ``true`` is resolved rather than treated as an error.
        """
        names, plan = _build({"ENABLE_DB_TOOLS": False})
        assert len(names) == FULL_SURFACE - 8
        # The operator's instruction wins over the environment (see ``_decide``'s ordering note), so
        # this holds on a machine without a driver too.
        assert plan.record_for("db_read").reason is ToolSetDisabledReason.DISABLED_BY_CONFIGURATION
        assert plan.record_for("db_write").reason is ToolSetDisabledReason.DISABLED_BY_NESTING

    def test_the_lce_set_has_no_flag_that_can_remove_it(self) -> None:
        """With every flag off, the 7 LCE tools remain."""
        names, plan = _build(dict(_ALL_OFF))
        assert len(names) == 7
        assert plan.record_for("lce").registered is True
        assert plan.record_for("lce").always_on is True

    def test_all_flags_off_removes_every_registry_tool(self) -> None:
        names, _ = _build(dict(_ALL_OFF))
        registry_names = {e.name for e in authz.TOOL_REGISTRY.values() if e.registers}
        assert registry_names & set(names) == set()


class TestTheDriverlessAppliance:
    """Without the DB driver, the service starts with a stated reason and 14 working tools."""

    def test_the_db_sets_are_disabled_with_prerequisite_missing(self) -> None:
        names, plan = _build(db=False)
        for set_id in ("db_read", "db_write"):
            record = plan.record_for(set_id)
            assert record.registered is False
            assert record.reason is ToolSetDisabledReason.PREREQUISITE_MISSING
            assert record.tool_count == 0
        assert len(names) == FULL_SURFACE - 8 == 47

    def test_the_ops_tools_survive_a_missing_driver(self) -> None:
        """Gating these on the driver would disable tools that do not need it.

        The ``ops`` tools use GraphQL and REST, and need no driver, no ``libem7`` and no
        ``silo.conf``.
        """
        names, plan = _build(db=False)
        assert plan.record_for("ops").registered is True
        assert plan.record_for("ops").tool_count == 14
        ops_names = {
            e.name for e in authz.TOOL_REGISTRY.values() if e.registers and e.tool_set == "ops"
        }
        assert ops_names <= set(names)

    def test_no_sql_tool_registers_without_a_driver(self) -> None:
        """The mirror assertion: a SQL tool registering here would fail at first use instead."""
        names, _ = _build(db=False)
        assert authz.sql_tool_names() & set(names) == set()

    def test_startup_does_not_raise(self) -> None:
        names, _ = _build(db=False)
        assert names

    def test_the_sql_tools_are_exactly_the_eight_that_the_driver_gates(self) -> None:
        """Ties the disabled 8 to ``authz``'s derived SQL set, so neither can drift alone."""
        gated = {desc.tool_name for desc, _ in db_read_tools() + db_write_tools()}
        assert gated == authz.sql_tool_names()
        assert len(gated) == authz.SQL_TOOL_COUNT == 8
