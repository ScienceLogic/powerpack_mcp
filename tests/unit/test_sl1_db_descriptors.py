"""
Tool Descriptor Tests

This module tests ``powerpack_mcp.tools.sl1_db_descriptors`` against the tool registry in
``authz``: inventory, backends, statement lists, transports and the import-time cross-check.

The assertions check agreement between two sources that could drift, not values this file also
states. Counts are compared against ``authz``'s derivation rather than written out a second time.
"""

from __future__ import annotations

import re
from typing import ClassVar

import pytest

from powerpack_mcp import authz
from powerpack_mcp.authz import TOOL_REGISTRY, ToolTransport
from powerpack_mcp.tools import sl1_db_descriptors as dd


class TestInventoryAgreesWithTheRegistry:
    """The registry is the source; this module must not be a second, drifting copy of it."""

    def test_every_registry_row_has_exactly_one_descriptor(self) -> None:
        names = [d.tool_name for d in dd.ALL_DB_DESCRIPTORS]
        assert sorted(names) == sorted(TOOL_REGISTRY)
        assert len(names) == len(set(names)), "a tool described twice"

    def test_the_counts_are_derived_from_the_registry_not_restated(self) -> None:
        assert len(dd.ALL_DB_DESCRIPTORS) == authz.DB_TOOL_COUNT
        assert len(dd.REGISTERING_DB_DESCRIPTORS) == authz.REGISTERED_TOOL_COUNT
        assert len(dd.SQL_DESCRIPTORS) == authz.SQL_TOOL_COUNT
        assert sum(1 for d in dd.ALL_DB_DESCRIPTORS if d.writes) == authz.WRITE_TOOL_COUNT

    def test_writes_is_taken_from_the_registry_for_every_tool(self) -> None:
        # `_d` reads it rather than accepting it, so this can only fail if someone reintroduces a
        # hand-maintained copy.
        for d in dd.ALL_DB_DESCRIPTORS:
            assert d.writes is TOOL_REGISTRY[d.tool_name].writes


class TestDbGating:
    """Only the SQL tools may be gated on the database prerequisite."""

    def test_only_sql_tools_declare_the_db_backend(self) -> None:
        needs_db = {d.tool_name for d in dd.ALL_DB_DESCRIPTORS if dd.DB in d.backends}
        assert needs_db == authz.sql_tool_names()

    def test_the_sixteen_non_sql_tools_never_touch_the_database(self) -> None:
        non_sql = [d for d in dd.ALL_DB_DESCRIPTORS if dd.DB not in d.backends]
        assert len(non_sql) == authz.DB_TOOL_COUNT - authz.SQL_TOOL_COUNT == 16
        # Gating any of these on the DB prerequisite would disable GraphQL tools that need no
        # driver, no libem7 and no silo.conf.
        for d in non_sql:
            assert dd.DB not in d.backends

    # The one SQL tool that resolves nothing before issuing SQL, and therefore does not need
    # REST. See `test_every_sql_tool_that_resolves_a_name_also_needs_rest`.
    SQL_TOOLS_WITHOUT_REST: ClassVar[dict[str, str]] = {
        "sl1_fetch_collection_output": (
            "Takes a proc_id minted by sl1_run_dynamic_collection and an integer row id. It "
            "resolves no device and no class, so it reaches no REST endpoint; declaring REST "
            "would be the bookkeeping this assertion exists to rule out."
        ),
    }

    def test_every_sql_tool_that_resolves_a_name_also_needs_rest(self) -> None:
        """Each of these resolves a device or class before issuing SQL.

        A tool wired to `db_client` alone would fail on its first argument, so this is a real
        dependency rather than bookkeeping. A tool whose arguments are ids this service minted
        resolves nothing, so it is exempt. Exemptions are listed with reasons rather than inferred,
        so a tool cannot drift out of this check by accident, and
        `test_the_rest_exemption_list_is_not_stale` keeps the list current.
        """
        for d in dd.SQL_DESCRIPTORS:
            if d.tool_name in self.SQL_TOOLS_WITHOUT_REST:
                continue
            assert dd.REST in d.backends, d.tool_name

    def test_the_rest_exemption_list_is_not_stale(self) -> None:
        """An exemption for a tool that no longer exists, or that now declares REST, is a lie."""
        sql_names = {d.tool_name for d in dd.SQL_DESCRIPTORS}
        for name, reason in self.SQL_TOOLS_WITHOUT_REST.items():
            assert name in sql_names, f"{name} is exempted but is not a SQL tool"
            assert dd.REST not in dd.DB_DESCRIPTORS_BY_NAME[name].backends, (
                f"{name} now declares REST, so its exemption is stale and must be deleted"
            )
            assert len(reason) >= 60, f"{name}'s exemption reason is too vague to review"


class TestStatementsIndex:
    """Every rewritten statement is reviewable against the original it replaces."""

    def test_only_sql_tools_declare_statements(self) -> None:
        for d in dd.ALL_DB_DESCRIPTORS:
            is_sql = TOOL_REGISTRY[d.tool_name].transport is ToolTransport.SQL
            assert bool(d.statements) is is_sql, d.tool_name

    def test_every_descriptor_names_the_source_symbol_it_came_from(self) -> None:
        # A row that names no source symbol cannot be reviewed against the original code.
        for d in dd.ALL_DB_DESCRIPTORS:
            assert d.source_symbol.startswith("tools/"), d.tool_name
            assert "::" in d.source_symbol, d.tool_name

    def test_statement_names_are_unique_within_a_tool(self) -> None:
        for d in dd.SQL_DESCRIPTORS:
            assert len(d.statements) == len(set(d.statements)), d.tool_name


class TestMultiTransportTools:
    """The three multi-transport tools, which are easy to mislabel as a single transport."""

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("server_health", frozenset({dd.REST, dd.GRAPHQL, dd.LCE})),
            ("sl1_check_capabilities", frozenset({dd.REST, dd.GRAPHQL, dd.LCE})),
            ("refresh_capability_map", frozenset({dd.REST, dd.GRAPHQL})),
        ],
    )
    def test_the_multi_transport_tools_declare_every_client_they_use(
        self, name: str, expected: frozenset[dd.Backend]
    ) -> None:
        assert dd.DB_DESCRIPTORS_BY_NAME[name].backends == expected
        assert TOOL_REGISTRY[name].transport is ToolTransport.MULTI

    def test_no_descriptor_declares_an_ssh_backend(self) -> None:
        """There is no SSH in this service, and this asserts it rather than trusting it.

        `sl1_run_dynamic_app_single` ran an operator-controlled command over SSH with a sudo
        password, and `server_health` has no SSH probe because the service holds no SSH
        credentials. A backend named "ssh" appearing here means one of those was undone.
        """
        every_backend = {b for d in dd.ALL_DB_DESCRIPTORS for b in d.backends}
        assert not any("ssh" in b.lower() for b in every_backend)

    def test_the_excluded_ssh_tool_is_absent_entirely(self) -> None:
        # Deleted rather than withheld, so configuration cannot re-enable it. Absence from the
        # descriptor set is half of that; absence from the registry is the other half.
        assert "sl1_run_dynamic_app_single" not in dd.DB_DESCRIPTORS_BY_NAME
        assert "sl1_run_dynamic_app_single" not in TOOL_REGISTRY
        assert "sl1_ssh_exec" not in dd.DB_DESCRIPTORS_BY_NAME
        assert "sl1_ssh_exec" not in TOOL_REGISTRY


class TestListCapabilitiesStaysWithheld:
    """`list_capabilities` has a characterised transport and still does not register."""

    def test_it_is_in_the_inventory_but_not_in_the_registering_set(self) -> None:
        assert "list_capabilities" in dd.DB_DESCRIPTORS_BY_NAME
        registering = {d.tool_name for d in dd.REGISTERING_DB_DESCRIPTORS}
        assert "list_capabilities" not in registering

    def test_its_transport_is_now_characterised_as_local(self) -> None:
        # It reads mcp._tool_manager.list_tools() and never leaves the process. It stays
        # unregistered because it duplicates MCP's tools/list and would read private FastMCP
        # internals.
        assert TOOL_REGISTRY["list_capabilities"].transport is ToolTransport.LOCAL
        assert dd.DB_DESCRIPTORS_BY_NAME["list_capabilities"].backends == frozenset({dd.NONE})

    def test_the_registering_set_is_derived_from_the_registry_flag(self) -> None:
        for d in dd.REGISTERING_DB_DESCRIPTORS:
            assert TOOL_REGISTRY[d.tool_name].registers


class TestImportTimeCrossCheck:
    """The check runs at import, so it cannot be skipped. These prove it actually catches things."""

    def test_a_db_backend_on_a_non_sql_tool_is_rejected(self) -> None:
        original = dd.ALL_DB_DESCRIPTORS
        # Replace one row in place rather than truncating the tuple: a short tuple trips the
        # missing-descriptor check first, and the test would then pass for the wrong reason.
        broken = dd.DbToolDescriptor(
            tool_name="sl1_clear_event",
            backends=frozenset({dd.DB, dd.REST}),
            summary="deliberately mis-wired",
            writes=True,
            source_symbol="tools/events.py::sl1_clear_event",
        )
        try:
            dd.ALL_DB_DESCRIPTORS = tuple(  # type: ignore[misc]
                broken if d.tool_name == "sl1_clear_event" else d for d in original
            )
            with pytest.raises(AssertionError, match=re.escape("Only SQL tools may be DB-gated")):
                dd._check_against_registry()
        finally:
            dd.ALL_DB_DESCRIPTORS = original  # type: ignore[misc]

    def test_a_statement_list_on_a_non_sql_tool_is_rejected(self) -> None:
        original = dd.ALL_DB_DESCRIPTORS
        broken = dd.DbToolDescriptor(
            tool_name="sl1_clear_event",
            backends=frozenset({dd.REST}),
            summary="deliberately mis-wired",
            writes=True,
            statements=("some_statement",),
            source_symbol="tools/events.py::sl1_clear_event",
        )
        try:
            dd.ALL_DB_DESCRIPTORS = tuple(  # type: ignore[misc]
                broken if d.tool_name == "sl1_clear_event" else d for d in original
            )
            with pytest.raises(AssertionError, match="only SQL tools issue statements"):
                dd._check_against_registry()
        finally:
            dd.ALL_DB_DESCRIPTORS = original  # type: ignore[misc]

    def test_a_missing_descriptor_is_rejected(self) -> None:
        """A registry row with no descriptor fails the check rather than passing unnoticed."""
        original = dd.ALL_DB_DESCRIPTORS
        try:
            dd.ALL_DB_DESCRIPTORS = original[:-1]  # type: ignore[misc]
            with pytest.raises(AssertionError, match="no descriptor"):
                dd._check_against_registry()
        finally:
            dd.ALL_DB_DESCRIPTORS = original  # type: ignore[misc]

    def test_a_descriptor_for_an_unregistered_tool_cannot_be_built(self) -> None:
        with pytest.raises(KeyError):
            dd._d("sl1_not_a_real_tool", frozenset({dd.REST}), "nope")
