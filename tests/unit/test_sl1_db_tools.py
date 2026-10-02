"""
SL1 Database and Ops Tool Tests

This module tests the SL1 DB-read, DB-write and ops tools against fake DB, SL1 and LCE clients:
which statements a tool issues and in what order, that a refusal is a ``ValidationBlocked``
rather than a builtin exception, that a partial write is not reported as "nothing happened", and
that the registry, the descriptors and the tool-set assignment cannot drift apart.

The fakes do not interpolate SQL, so a statement that renders to something silently empty is
invisible here. That guard lives in ``sql.Statement.__post_init__`` and is tested against the
rendered statement in ``test_sl1_db_statements.py``. Nothing here reaches a real SL1 or MariaDB.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
from typing import TYPE_CHECKING, Any, ClassVar
from unittest.mock import patch

import pytest

from powerpack_mcp import authz
from powerpack_mcp.db_client import StatementResult
from powerpack_mcp.errors import (
    DbError,
    DbQueryTimeout,
    LceHttpError,
    LceUnreachable,
    LogEvent,
    PowerPackMcpError,
    Sl1GraphQlError,
    Sl1HttpError,
    Sl1MalformedResponse,
    Sl1ResponseTooLarge,
    Sl1Unreachable,
    ValidationBlocked,
)
from powerpack_mcp.tools import sl1_db_descriptors as d
from powerpack_mcp.tools import sl1_db_registry as reg
from powerpack_mcp.tools import sl1_ops_tools as ops
from powerpack_mcp.tools.sl1_db_pipeline import (
    Sl1DbToolContext,
    as_int,
    coded,
    one_value,
    resolve_device,
)
from powerpack_mcp.tools.sl1_db_pipeline import (
    actor_user_id as pipeline_actor_user_id,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

pytestmark = pytest.mark.anyio


# ---- Fakes ---------------------------------------------------------------------------------------


class FakeDb:
    """Records every statement, in order, and replays queued results."""

    def __init__(
        self,
        fetch_results: Sequence[tuple[tuple[Any, ...], ...]] | None = None,
        unit_results: Sequence[tuple[StatementResult, ...]] | None = None,
        raises: BaseException | None = None,
    ) -> None:
        self.statements: list[tuple[str, tuple[Any, ...]]] = []
        self.units: list[list[str]] = []
        self._fetch = list(fetch_results or [])
        self._units = list(unit_results or [])
        self._raises = raises
        self.worker_count = 4

    async def fetch_all(self, statement: Any) -> tuple[tuple[Any, ...], ...]:
        self.statements.append((statement.sql, statement.params))
        if self._raises is not None:
            raise self._raises
        return self._fetch.pop(0) if self._fetch else ()

    async def run_unit(self, *statements: Any) -> tuple[StatementResult, ...]:
        self.units.append([s.sql for s in statements])
        for statement in statements:
            self.statements.append((statement.sql, statement.params))
        if self._raises is not None:
            raise self._raises
        if self._units:
            return self._units.pop(0)
        return tuple(StatementResult(rows=(), rowcount=1, lastrowid=0) for _ in statements)


class FakeSl1:
    """Records REST and GraphQL calls and replays queued responses."""

    def __init__(
        self,
        rest_results: Sequence[Any] | None = None,
        graphql_results: Sequence[Any] | None = None,
    ) -> None:
        self.rest_calls: list[dict[str, Any]] = []
        self.graphql_calls: list[dict[str, Any]] = []
        self._rest = list(rest_results or [])
        self._graphql = list(graphql_results or [])

    async def request(self, **kwargs: Any) -> Any:
        self.rest_calls.append(kwargs)
        return self._rest.pop(0) if self._rest else {}

    async def graphql(self, **kwargs: Any) -> Any:
        self.graphql_calls.append(kwargs)
        return self._graphql.pop(0) if self._graphql else {}


class FakeLce:
    def __init__(self, status_code: int = 200) -> None:
        self.calls: list[dict[str, Any]] = []
        self._status = status_code

    async def request(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return type("R", (), {"status_code": self._status, "body": {}})()


# A healthy answer for each of `_probe`'s four calls, so `RaisingSl1` can fail exactly one arm
# and a test can read the log without the other three adding records of their own.
_HEALTHY_REST_INDEX: list[dict[str, str]] = [{"URI": "/api/device"}]
_HEALTHY_ROOTS: dict[str, Any] = {"__schema": {"queryType": {"fields": [{"name": "devices"}]}}}
_HEALTHY_VERSION: dict[str, Any] = {"systemInformation": {"em7Version": "12.5.1"}}


class RaisingSl1(FakeSl1):
    """A `Sl1Client` double that raises the real exception classes.

    `FakeSl1` and `FakeLce` cannot fail the way the real clients do. `FakeSl1` never raises, and
    `FakeLce` returns a stub with whatever status it was given, whereas the real `LceClient` raises
    `LceHttpError` on any non-2xx. Tests built on those fakes never enter `_probe`'s ``except``
    arms; these doubles do.
    """

    def __init__(
        self,
        rest_error: PowerPackMcpError | None = None,
        roots_error: PowerPackMcpError | None = None,
        version_error: PowerPackMcpError | None = None,
    ) -> None:
        super().__init__()
        self._rest_error = rest_error
        self._roots_error = roots_error
        self._version_error = version_error

    async def request(self, **kwargs: Any) -> Any:
        self.rest_calls.append(kwargs)
        if self._rest_error is not None:
            raise self._rest_error
        return _HEALTHY_REST_INDEX

    async def graphql(self, **kwargs: Any) -> Any:
        self.graphql_calls.append(kwargs)
        is_version = "systemInformation" in kwargs["query"]
        error = self._version_error if is_version else self._roots_error
        if error is not None:
            raise error
        return _HEALTHY_VERSION if is_version else _HEALTHY_ROOTS


class RaisingLce(FakeLce):
    """An `LceClient` double that raises, which `FakeLce` cannot -- see `RaisingSl1`."""

    def __init__(self, error: PowerPackMcpError) -> None:
        super().__init__()
        self._error = error

    async def request(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        raise self._error


def make_context(
    db: FakeDb | None = None,
    sl1: FakeSl1 | None = None,
    lce: FakeLce | None = None,
) -> Sl1DbToolContext:
    return Sl1DbToolContext(
        client=sl1 or FakeSl1(),  # type: ignore[arg-type]
        config=object(),  # type: ignore[arg-type]
        credential_source=lambda: object(),  # type: ignore[arg-type,return-value]
        lce_client=lce or FakeLce(),  # type: ignore[arg-type]
        db=db,  # type: ignore[arg-type]
    )


def assert_refused(result: Any, fragment: str = "") -> None:
    """Assert a tool returned a caller-facing refusal payload.

    Tools do not raise: `sl1_tool_boundary` catches `PowerPackMcpError` and returns
    `build_error_payload(exc)`. This checks the envelope, which is what a caller receives.
    """
    assert isinstance(result, dict), result
    assert "error" in result, result
    assert result["error"]["type"] == "validation_blocked", result["error"]
    if fragment:
        rendered = str(result["error"].get("details", "")) + str(result["error"].get("message", ""))
        assert fragment.lower() in rendered.lower(), rendered


def assert_finding(excinfo: Any, fragment: str) -> None:
    """Assert a directly called helper raised with ``fragment`` in its finding message.

    `ValidationBlocked.__str__` is ``"N validation finding(s)"``; the text lives in `findings`, so
    `pytest.raises(match=...)` cannot see it.
    """
    messages = " ".join(f.message for f in excinfo.value.findings)
    assert fragment.lower() in messages.lower(), messages


async def call(tool: Any, /, **kwargs: Any) -> Any:
    """Invoke a built tool and return its payload as `Any`.

    The factories are typed ``Callable[..., Awaitable[object]]`` because a tool's return shape is
    its own business. The cast happens here once rather than as many inline ``# type: ignore``
    comments, each of which would also suppress real errors.
    """
    result: Any = await tool(**kwargs)
    return result


# A device index response shaped as SL1 returns one, so `resolve_device`'s name branch works.
_DEVICE_INDEX = {"/api/device/77": {"description": "edge-01"}}


# ---- The registry, the descriptors and the sets cannot drift -------------------------------------


class TestRegistryTotality:
    async def test_every_registering_tool_has_a_factory_and_builds(self) -> None:
        context = make_context(db=FakeDb())
        built = 0
        for set_id in authz.REGISTRY_TOOL_SETS:
            for descriptor, factory in reg.tools_for_set(set_id):
                tool = factory(context)
                # `__doc__` must survive. An f-string docstring leaves it None and silently
                # strips every description from the schema the client reads.
                assert tool.__doc__, descriptor.tool_name
                assert callable(tool)
                built += 1
        assert built == authz.REGISTERED_TOOL_COUNT == 22

    def test_the_three_sets_partition_the_registering_surface(self) -> None:
        # `ops` is 14, not 15, because `refresh_capability_map` is withheld.
        sizes = {s: len(reg.tools_for_set(s)) for s in authz.REGISTRY_TOOL_SETS}
        assert sizes == {"db_read": 3, "db_write": 5, "ops": 14}
        assert sum(sizes.values()) == authz.REGISTERED_TOOL_COUNT

    def test_no_tool_appears_in_two_sets(self) -> None:
        seen: list[str] = []
        for set_id in authz.REGISTRY_TOOL_SETS:
            seen.extend(desc.tool_name for desc, _ in reg.tools_for_set(set_id))
        assert len(seen) == len(set(seen))

    def test_only_sql_tools_are_in_the_db_sets(self) -> None:
        """Asserted through the registry rather than the registry data alone."""
        db_tools = {desc.tool_name for desc, _ in reg.db_read_tools() + reg.db_write_tools()}
        assert db_tools == authz.sql_tool_names()

    def test_every_db_write_tool_writes_and_every_db_read_tool_does_not(self) -> None:
        # A write in the read set would escape ENABLE_DB_WRITE_TOOLS, the flag that gates writes.
        assert all(desc.writes for desc, _ in reg.db_write_tools())
        assert not any(desc.writes for desc, _ in reg.db_read_tools())


class TestListCapabilitiesWithheld:
    """The exclusion is structural: a missing factory, not a guard."""

    def test_it_is_in_no_set(self) -> None:
        for set_id in authz.REGISTRY_TOOL_SETS:
            names = [desc.tool_name for desc, _ in reg.tools_for_set(set_id)]
            assert "list_capabilities" not in names

    def test_it_has_no_factory(self) -> None:
        assert "list_capabilities" not in reg._FACTORY_FOR

    def test_giving_it_a_factory_fails_the_import_check(self) -> None:
        """The exclusion is enforced, not merely intended.

        A comment or an ``if name != …`` guard could be deleted in one line and nothing would
        notice. The ``match`` pins which check fired, since more than one message names the tool.
        """
        original = reg._FACTORY_FOR
        try:
            reg._FACTORY_FOR = {  # type: ignore[misc]
                **original,
                "list_capabilities": reg.make_server_health,
            }
            with pytest.raises(RuntimeError, match="no registering descriptor claims") as excinfo:
                reg._check_registry_is_total()
            assert "list_capabilities" in str(excinfo.value)
        finally:
            reg._FACTORY_FOR = original  # type: ignore[misc]

    def test_removing_a_real_factory_fails_the_import_check(self) -> None:
        original = reg._FACTORY_FOR
        try:
            reg._FACTORY_FOR = {  # type: ignore[misc]
                k: v for k, v in original.items() if k != "server_health"
            }
            with pytest.raises(RuntimeError, match="no factory"):
                reg._check_registry_is_total()
        finally:
            reg._FACTORY_FOR = original  # type: ignore[misc]


class TestRefreshCapabilityMapWithheld:
    """`refresh_capability_map` is withheld.

    It cannot report the diff its name promises without a writable state directory, which the
    service does not have, and a caller reads the tool's name before the payload. The assertions
    mirror the `list_capabilities` ones so that each withheld tool is tested at the same depth.
    """

    def test_it_is_in_no_set(self) -> None:
        for set_id in authz.REGISTRY_TOOL_SETS:
            names = [desc.tool_name for desc, _ in reg.tools_for_set(set_id)]
            assert "refresh_capability_map" not in names

    def test_it_has_no_factory(self) -> None:
        assert "refresh_capability_map" not in reg._FACTORY_FOR

    def test_its_maker_is_deleted_from_the_module_entirely(self) -> None:
        """Deleted, not merely unwired.

        An unregistered factory left in place is dead code the totality check cannot see: it
        inspects `_FACTORY_FOR`, not the module, so it would sit one line from being re-wired.
        """
        from powerpack_mcp.tools import sl1_ops_tools

        assert not hasattr(sl1_ops_tools, "make_refresh_capability_map")
        assert "make_refresh_capability_map" not in sl1_ops_tools.__all__

    def test_giving_it_a_factory_fails_the_import_check(self) -> None:
        original = reg._FACTORY_FOR
        try:
            reg._FACTORY_FOR = {  # type: ignore[misc]
                **original,
                "refresh_capability_map": reg.make_server_health,
            }
            with pytest.raises(RuntimeError, match="no registering descriptor claims") as excinfo:
                reg._check_registry_is_total()
            assert "refresh_capability_map" in str(excinfo.value)
        finally:
            reg._FACTORY_FOR = original  # type: ignore[misc]

    def test_widening_the_surface_so_both_sides_agree_is_still_rejected(self) -> None:
        """The case the totality check cannot see, which is why the withheld-set check exists.

        Every withheld tool is made to register and given a factory, so the set comparison passes.
        Only the explicit withheld-set assertion is left to refuse. `WITHHELD_TOOLS` is spelled as
        literals for this reason: a value derived from `authz` would agree with the change.
        """
        original_desc = d.REGISTERING_DB_DESCRIPTORS
        original_fac = reg._FACTORY_FOR
        try:
            d.REGISTERING_DB_DESCRIPTORS = d.ALL_DB_DESCRIPTORS  # type: ignore[misc]
            reg._FACTORY_FOR = {  # type: ignore[misc]
                **original_fac,
                **dict.fromkeys(reg.WITHHELD_TOOLS, reg.make_server_health),
            }
            with pytest.raises(RuntimeError, match="to be withheld") as excinfo:
                reg._check_registry_is_total()
            # The message must carry the reason: someone reading this failure is one commit away
            # from widening the surface.
            assert "writable state directory" in str(excinfo.value)
            assert "tools/list" in str(excinfo.value)
        finally:
            d.REGISTERING_DB_DESCRIPTORS = original_desc  # type: ignore[misc]
            reg._FACTORY_FOR = original_fac  # type: ignore[misc]

    def test_the_withheld_set_is_exactly_the_two(self) -> None:
        assert {"list_capabilities", "refresh_capability_map"} == reg.WITHHELD_TOOLS
        withheld = {e.name for e in authz.TOOL_REGISTRY.values() if not e.registers}
        assert withheld == reg.WITHHELD_TOOLS


# ---- The SQL tools ------------------------------------------------------------------------------


class TestSimulateEvent:
    async def test_it_reports_the_new_id_from_lastrowid(self) -> None:
        """No second ``SELECT LAST_INSERT_ID()`` statement is issued."""
        db = FakeDb(unit_results=[(StatementResult(rows=(), rowcount=1, lastrowid=4242),)])
        sl1 = FakeSl1(rest_results=[{"name": "edge-01"}])
        tool = reg._FACTORY_FOR["sl1_simulate_event"](make_context(db=db, sl1=sl1))
        result = await call(tool, device="77", message="disk full")
        assert result["event_id"] == 4242
        assert result["device_id"] == 77
        # One statement in the unit, not two.
        assert len(db.units) == 1
        assert len(db.units[0]) == 1
        assert "LAST_INSERT_ID" not in db.units[0][0].upper()

    async def test_the_note_states_the_engine_did_not_run(self) -> None:
        # The note is in the payload because the model reads the result, not the tool definition,
        # when deciding what a call proved.
        db = FakeDb(unit_results=[(StatementResult(rows=(), rowcount=1, lastrowid=1),)])
        tool = reg._FACTORY_FOR["sl1_simulate_event"](
            make_context(db=db, sl1=FakeSl1(rest_results=[{"name": "d"}]))
        )
        result = await call(tool, device="1", message="m")
        assert "no policy matching" in result["note"].lower()

    @pytest.mark.parametrize("bad", ["nope", "9", "-1"])
    async def test_an_unrecognised_severity_is_refused_not_ignored(self, bad: str) -> None:
        """An unrecognised filter must not fall through to no filter."""
        tool = reg._FACTORY_FOR["sl1_simulate_event"](make_context(db=FakeDb()))
        result = await call(tool, device="1", message="m", severity=bad)
        assert_refused(result)

    async def test_an_unrecognised_source_is_refused(self) -> None:
        tool = reg._FACTORY_FOR["sl1_simulate_event"](make_context(db=FakeDb()))
        result = await call(tool, device="1", message="m", source="carrier-pigeon")
        assert_refused(result)

    async def test_a_missing_database_refuses_with_a_caller_facing_error(self) -> None:
        """`ValidationBlocked`, never a builtin: the boundary translates only our errors."""
        tool = reg._FACTORY_FOR["sl1_simulate_event"](make_context(db=None))
        result = await call(tool, device="1", message="m")
        assert_refused(result)


# A component `read_component_map` withheld: out of the root's organization, or with no device
# row, active or vanished. The SQL masks every column, so this is all a withheld row ever carries.
_WITHHELD_ROW: tuple[None, ...] = (None,) * 8


class TestGetComponentTree:
    async def test_a_numeric_root_is_confirmed_through_rest_before_any_sql(self) -> None:
        """A numeric root is not trusted because no lookup is needed to learn the number.

        The database connection sees every organization, so skipping REST for a digit string let a
        caller walk any organization's tree. `GET device/<id>` with the caller's credential is what
        applies SL1's organization ACL.
        """
        sl1 = FakeSl1(rest_results=[{"name": "vcenter"}])
        db = FakeDb(fetch_results=[(("vcenter", "VMware | vCenter"),), ()])
        tool = reg._FACTORY_FOR["sl1_get_component_tree"](make_context(db=db, sl1=sl1))
        result = await call(tool, root="42")
        assert [c["path"] for c in sl1.rest_calls] == ["device/42"]
        # Two statements: summary and map, both bound to the REST-confirmed id.
        assert [params for _, params in db.statements] == [(42, 42), (42,)]
        assert result["root"]["did"] == 42

    async def test_a_named_root_resolves_through_rest_not_sql(self) -> None:
        sl1 = FakeSl1(rest_results=[{"/api/device/42": {"description": "vcenter-1"}}])
        db = FakeDb(fetch_results=[(("vcenter-1", "VMware | vCenter"),), ()])
        tool = reg._FACTORY_FOR["sl1_get_component_tree"](make_context(db=db, sl1=sl1))
        result = await call(tool, root="vcenter-1")
        assert sl1.rest_calls[0]["path"] == "device"
        assert sl1.rest_calls[0]["query"]["filter.name.contains"] == "vcenter-1"
        # No SQL name lookup: the name never reaches a statement.
        assert len(db.statements) == 2
        assert all("vcenter-1" not in params for _, params in db.statements)
        assert result["root"]["did"] == 42

    async def test_an_unresolvable_root_is_refused_before_any_sql(self) -> None:
        db = FakeDb()
        tool = reg._FACTORY_FOR["sl1_get_component_tree"](
            make_context(db=db, sl1=FakeSl1(rest_results=[{}]))
        )
        result = await call(tool, root="does-not-exist")
        assert_refused(result, "no device named")
        assert db.statements == []

    async def test_a_name_that_only_contains_the_root_is_refused(self) -> None:
        """`root` has always meant an exact name; a substring match walks someone else's tree."""
        sl1 = FakeSl1(rest_results=[{"/api/device/43": {"description": "vcenter-1-old"}}])
        db = FakeDb()
        tool = reg._FACTORY_FOR["sl1_get_component_tree"](make_context(db=db, sl1=sl1))
        result = await call(tool, root="vcenter-1")
        assert_refused(result, "no device named")
        assert db.statements == []

    @pytest.mark.parametrize("status", [403, 404])
    @pytest.mark.parametrize("root", ["42", "vcenter-1"])
    async def test_a_root_rest_refuses_stops_the_tool_with_no_sql(
        self, status: int, root: str
    ) -> None:
        """SL1 answers 403 or 404 for a device in an organization the caller cannot see.

        That error is the access decision, so it must reach the caller as SL1's own and no
        statement may run for the root, whichever form the root was given in.
        """
        db = FakeDb(fetch_results=[(("vcenter", "VMware | vCenter"),), ()])
        sl1 = RaisingSl1(rest_error=Sl1HttpError(status, {"message": "denied"}))
        tool = reg._FACTORY_FOR["sl1_get_component_tree"](make_context(db=db, sl1=sl1))
        result = await call(tool, root=root)
        assert result["error"]["type"] == "sl1_http_error", result
        assert result["error"]["sl1_status"] == status
        assert db.statements == []

    async def test_truncation_is_reported_rather_than_silent(self) -> None:
        """A truncated answer otherwise looks exactly like a complete one."""
        components = tuple((i, 42, f"c{i}", "Class", "active", f"u{i}", "7", "0") for i in range(5))
        db = FakeDb(fetch_results=[(("root", "Class"),), components])
        tool = reg._FACTORY_FOR["sl1_get_component_tree"](make_context(db=db))
        result = await call(tool, root="42", max_nodes=2)
        assert result["truncated"] is True
        assert result["total_components"] == 5
        assert len(result["components"]) == 2

    async def test_states_and_classes_are_counted(self) -> None:
        components = (
            (1, 42, "a", "Class A", "active", "u1", "7", "0"),
            (2, 42, "b", "Class A", "active", "u2", "7", "0"),
            (3, 42, "c", "Class B", "active", "u3", "8", "0"),
        )
        db = FakeDb(fetch_results=[(("root", "Class"),), components])
        tool = reg._FACTORY_FOR["sl1_get_component_tree"](make_context(db=db))
        result = await call(tool, root="42")
        assert result["by_state"] == {"active": 3}
        assert result["counts_by_class"] == {"Class A": 2, "Class B": 1}
        assert result["discovering_dynamic_apps"] == ["7", "8"]
        assert result["withheld_components"] == 0

    async def test_withheld_components_are_counted_and_nothing_else(self) -> None:
        """An out-of-organization or unregistered component affects only the count.

        It must not appear in `components`, and must not move `total_components`, `by_state`,
        `counts_by_class` or `discovering_dynamic_apps` either: a count keyed by class or a
        Dynamic Application id would itself disclose something about it.
        """
        components = (
            (1, 42, "a", "Class A", "active", "u1", "7", "0"),
            _WITHHELD_ROW,
            (3, 42, "c", "Class B", "active", "u3", "8", "0"),
            _WITHHELD_ROW,
        )
        db = FakeDb(fetch_results=[(("root", "Class"),), components])
        tool = reg._FACTORY_FOR["sl1_get_component_tree"](make_context(db=db))
        result = await call(tool, root="42", max_nodes=1)
        assert result["withheld_components"] == 2
        assert result["total_components"] == 2
        assert result["by_state"] == {"active": 2}
        assert result["counts_by_class"] == {"Class A": 1, "Class B": 1}
        assert result["discovering_dynamic_apps"] == ["7", "8"]
        # Truncation is judged against the in-scope components only.
        assert result["truncated"] is True
        assert [c["did"] for c in result["components"]] == [1]

    async def test_a_tree_of_only_withheld_components_reads_as_empty_with_a_count(self) -> None:
        db = FakeDb(fetch_results=[(("root", "Class"),), (_WITHHELD_ROW,)])
        tool = reg._FACTORY_FOR["sl1_get_component_tree"](make_context(db=db))
        result = await call(tool, root="42")
        assert result["components"] == []
        assert result["total_components"] == 0
        assert result["by_state"] == {}
        assert result["withheld_components"] == 1
        assert result["truncated"] is False

    async def test_an_out_of_scope_parent_reads_as_null_and_the_component_stays(self) -> None:
        """`read_component_map` masks a parent outside the root's organization to NULL.

        The component itself is in scope, so it is listed and counted; only its parent's id is
        unknown to the caller, and it is not counted as withheld.
        """
        components = (
            (1, 42, "a", "Class A", "active", "u1", "7", "0"),
            (2, None, "b", "Class A", "active", "u2", "7", "0"),
            (3, 0, "c", "Class B", "vanished", "u3", "8", "0"),
        )
        db = FakeDb(fetch_results=[(("root", "Class"),), components])
        tool = reg._FACTORY_FOR["sl1_get_component_tree"](make_context(db=db))
        result = await call(tool, root="42")
        assert [(c["did"], c["parent_did"]) for c in result["components"]] == [
            (1, 42),
            (2, None),
            (3, 0),
        ]
        assert result["total_components"] == 3
        assert result["withheld_components"] == 0

    async def test_an_in_scope_vanished_component_is_listed_not_withheld(self) -> None:
        # `legend_device_vanished` carries `roa_id`, so a vanished component is scoped like an
        # active one rather than withheld for want of an organization.
        components = (
            (1, 42, "a", "Class A", "active", "u1", "7", "0"),
            (2, 42, "b", "Class A", "vanished", "u2", "7", "0"),
        )
        db = FakeDb(fetch_results=[(("root", "Class"),), components])
        tool = reg._FACTORY_FOR["sl1_get_component_tree"](make_context(db=db))
        result = await call(tool, root="42")
        assert result["by_state"] == {"active": 1, "vanished": 1}
        assert result["withheld_components"] == 0
        assert [c["state"] for c in result["components"]] == ["active", "vanished"]


class TestCreateDeviceClass:
    async def test_it_inserts_then_reads_back_in_one_unit(self) -> None:
        created = (("1", "A" * 32, "Acme", "Widget", 9, 2, 5, None, "", "", "Servers"),)
        db = FakeDb(
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=1, lastrowid=1),
                    StatementResult(rows=created, rowcount=1, lastrowid=0),
                )
            ]
        )
        tool = reg._FACTORY_FOR["sl1_create_device_class"](make_context(db=db))
        result = await call(tool, class_name="Acme", description="Widget", category="Servers")
        # One unit, so the write and its read-back share a connection.
        assert len(db.units) == 1
        assert len(db.units[0]) == 2
        assert result["created"]["class"] == "Acme"

    async def test_an_unresolved_category_is_reported_as_nothing_inserted(self) -> None:
        """Judged on row count, not on whether the GUID appears in the output.

        A GUID can appear inside an error message; an empty read-back cannot be mistaken for
        success.
        """
        db = FakeDb(
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=0, lastrowid=0),
                    StatementResult(rows=(), rowcount=0, lastrowid=0),
                )
            ]
        )
        tool = reg._FACTORY_FOR["sl1_create_device_class"](make_context(db=db))
        result = await call(tool, class_name="Acme", description="W", category="Nonexistent")
        assert_refused(result, "NOT created")

    async def test_an_unknown_powerpack_name_is_refused(self) -> None:
        # A sub-select would silently yield NULL and unown the class, so the name is resolved first.
        db = FakeDb(fetch_results=[()])
        tool = reg._FACTORY_FOR["sl1_create_device_class"](make_context(db=db))
        result = await call(tool, class_name="A", description="B", ppguid="No Such Pack")
        assert_refused(result, "No PowerPack")

    async def test_a_bad_device_type_is_refused(self) -> None:
        tool = reg._FACTORY_FOR["sl1_create_device_class"](make_context(db=FakeDb()))
        result = await call(tool, class_name="A", description="B", device_type="quantum")
        assert_refused(result)


class TestUpdateDeviceClass:
    async def test_an_empty_update_is_refused(self) -> None:
        tool = reg._FACTORY_FOR["sl1_update_device_class"](make_context(db=FakeDb()))
        result = await call(tool, device_class_guid="A" * 32)
        assert_refused(result, "at least one field")

    async def test_a_non_guid_key_is_refused(self) -> None:
        tool = reg._FACTORY_FOR["sl1_update_device_class"](make_context(db=FakeDb()))
        result = await call(tool, device_class_guid="not-a-guid", class_name="X")
        assert_refused(result, "hexadecimal GUID")

    async def test_a_named_category_is_refused_on_update(self) -> None:
        """A deliberate narrowing; see `_category_fid`'s docstring for why.

        Resolving a name would force a choice between removing the documented
        no-op-on-bad-category safety property and adding a statement that cannot be rolled back.
        """
        tool = reg._FACTORY_FOR["sl1_update_device_class"](make_context(db=FakeDb()))
        result = await call(tool, device_class_guid="A" * 32, category="Servers")
        assert_refused(result, "numeric device-category id")

    async def test_a_missing_class_is_refused_after_the_update_ran(self) -> None:
        """The UPDATE has already been issued when the read-back comes back empty.

        The refusal says the class does not exist; it does not claim nothing happened, because with
        autocommit on that is a claim the tool cannot make.
        """
        db = FakeDb(
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=0, lastrowid=0),
                    StatementResult(rows=(), rowcount=0, lastrowid=0),
                )
            ]
        )
        tool = reg._FACTORY_FOR["sl1_update_device_class"](make_context(db=db))
        result = await call(tool, device_class_guid="A" * 32, class_name="X")
        assert_refused(result, "No device class")
        assert len(db.units) == 1  # the unit really did run


class TestAlignment:
    async def test_an_unknown_class_guid_is_refused_before_any_write(self) -> None:
        """An unknown class is refused and no unit runs at all.

        ``UPDATE … SET class_type = COALESCE(@ct, class_type)`` assigns the column to itself when
        the GUID resolves to nothing, so a caller aligning to a nonexistent class would receive
        success.
        """
        db = FakeDb(fetch_results=[()])
        tool = reg._FACTORY_FOR["sl1_align_dynamic_app_to_device_class"](make_context(db=db))
        result = await call(tool, dynamic_app="11", device_class="B" * 32)
        assert_refused(result, "No device class")
        assert db.units == []

    async def test_unaligning_with_zero_needs_no_class_lookup(self) -> None:
        aligned = ((11, "Cisco: CPU", 0, None),)
        db = FakeDb(
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=1, lastrowid=0),
                    StatementResult(rows=aligned, rowcount=1, lastrowid=0),
                )
            ]
        )
        tool = reg._FACTORY_FOR["sl1_align_dynamic_app_to_device_class"](make_context(db=db))
        result = await call(tool, dynamic_app="11", device_class="0")
        assert result["unaligned"] is True
        assert result["aligned"]["aid"] == 11

    async def test_a_missing_dynamic_app_is_refused(self) -> None:
        db = FakeDb(
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=0, lastrowid=0),
                    StatementResult(rows=(), rowcount=0, lastrowid=0),
                )
            ]
        )
        tool = reg._FACTORY_FOR["sl1_align_dynamic_app_to_device_class"](make_context(db=db))
        result = await call(tool, dynamic_app="999", device_class="0")
        assert_refused(result, "No Dynamic Application")

    async def test_get_alignment_reports_the_class_and_its_apps(self) -> None:
        db = FakeDb(fetch_results=[(("Acme | Widget",),), ((11, "A"), (12, "B"))])
        tool = reg._FACTORY_FOR["sl1_get_device_class_alignment"](make_context(db=db))
        result = await call(tool, device_class="9")
        assert result["class_type"] == 9
        assert result["device_class"] == "Acme | Widget"
        assert result["aligned_dynamic_apps"] == [
            {"aid": 11, "name": "A"},
            {"aid": 12, "name": "B"},
        ]

    async def test_get_alignment_refuses_a_junk_identifier(self) -> None:
        tool = reg._FACTORY_FOR["sl1_get_device_class_alignment"](make_context(db=FakeDb()))
        result = await call(tool, device_class="not-a-guid-or-a-number")
        assert_refused(result, "class GUID or a numeric")


class TestDbErrorsReachTheCallerAsOurs:
    async def test_a_db_error_becomes_an_envelope_not_a_traceback(self) -> None:
        """The boundary translates a `DbError` exactly once, and never leaks it.

        It does not propagate. The caller gets an envelope whose type is ours, and the driver's own
        message never appears in it.
        """
        db = FakeDb(raises=DbError("the database failed the request"))
        tool = reg._FACTORY_FOR["sl1_get_device_class_alignment"](make_context(db=db))
        result = await call(tool, device_class="9")
        assert isinstance(result, dict)
        assert "error" in result
        assert result["error"]["type"] != "validation_blocked"
        # No traceback, no /opt/em7 path, no driver internals.
        rendered = str(result)
        assert "Traceback" not in rendered
        assert "/opt/em7" not in rendered


# ---- The non-SQL tools --------------------------------------------------------------------------


class TestEventTools:
    async def test_clear_event_uses_rest_delete_not_sql(self) -> None:
        """Clearing goes through SL1's REST endpoint, not a ``master_events.*`` SQL write."""
        sl1 = FakeSl1(rest_results=[{}])
        db = FakeDb()
        tool = reg._FACTORY_FOR["sl1_clear_event"](make_context(db=db, sl1=sl1))
        await call(tool, event_id=99)
        assert sl1.rest_calls[0]["method"] == "DELETE"
        assert sl1.rest_calls[0]["path"] == "event/99"
        # It must not touch the database at all.
        assert db.statements == []

    async def test_clear_event_refuses_a_non_positive_id(self) -> None:
        tool = reg._FACTORY_FOR["sl1_clear_event"](make_context())
        result = await call(tool, event_id=0)
        assert_refused(result)

    async def test_inject_alert_posts_to_the_engine_queue(self) -> None:
        sl1 = FakeSl1(rest_results=[{"name": "edge-01"}, {"ok": True}])
        tool = reg._FACTORY_FOR["sl1_inject_alert"](make_context(sl1=sl1))
        result = await call(tool, device="77", message="cpu high", value="99")
        alert = sl1.rest_calls[-1]
        assert alert["method"] == "POST"
        assert alert["path"] == "alert"
        assert alert["json_body"]["aligned_resource"] == "/api/device/77"
        assert alert["json_body"]["value"] == "99"
        # `threshold` was not supplied, so it must be absent rather than empty.
        assert "threshold" not in alert["json_body"]
        assert result["queued"] is True

    async def test_recent_events_refuses_an_unrecognised_filter(self) -> None:
        tool = reg._FACTORY_FOR["sl1_get_recent_events"](make_context())
        result = await call(tool, min_severity="extremely-bad")
        assert_refused(result)

    async def test_recent_events_filters_client_side_and_reports_the_window(self) -> None:
        events = {
            f"/api/event/{i}": {
                "severity": sev,
                "source": 6,
                "aligned_resource": "/api/device/77",
                "message": "m",
                "date_last": "1700000000",
            }
            for i, sev in enumerate([0, 2, 4])
        }
        sl1 = FakeSl1(rest_results=[events])
        tool = reg._FACTORY_FOR["sl1_get_recent_events"](make_context(sl1=sl1))
        result = await call(tool, min_severity="minor", limit=10)
        assert result["matched"] == 2  # severities 2 and 4 clear a floor of 2
        assert result["min_severity"] == "Minor"
        assert "scan_window" in result

    async def test_recent_events_renders_an_aware_utc_timestamp(self) -> None:
        events = {
            "/api/event/1": {
                "severity": 4,
                "source": 6,
                "aligned_resource": "",
                "message": "m",
                "date_last": "1700000000",
            }
        }
        sl1 = FakeSl1(rest_results=[events])
        tool = reg._FACTORY_FOR["sl1_get_recent_events"](make_context(sl1=sl1))
        result = await call(tool)
        stamp = result["events"][0]["last_seen"]
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", stamp)

    async def test_collected_values_caps_the_apps_it_fetches(self) -> None:
        config = {f"/api/x/{i}": {"name": f"App {i}"} for i in range(5)}
        sl1 = FakeSl1(rest_results=[{"name": "d"}, config, {}, {}, []])
        tool = reg._FACTORY_FOR["sl1_get_collected_values"](make_context(sl1=sl1))
        result = await call(tool, device="1", max_apps=2)
        assert result["config"]["total_applications"] == 5
        assert len(result["config"]["fetched"]) == 2
        # No data is lost: the rest are named.
        assert len(result["config"]["not_fetched"]) == 3


class TestGraphQlTools:
    async def test_create_icon_sends_the_descriptor_document(self) -> None:
        sl1 = FakeSl1(graphql_results=[{"createIcon": {"id": "7"}}])
        tool = reg._FACTORY_FOR["sl1_create_icon"](make_context(sl1=sl1))
        result = await call(tool, name="disk", svg="<svg/>")
        assert sl1.graphql_calls[0]["query"] == d.CREATE_ICON.document
        assert sl1.graphql_calls[0]["variables"] == {"name": "disk", "svg": "<svg/>"}
        assert result["createIcon"] == {"id": "7"}

    async def test_no_graphql_tool_contains_its_own_document(self) -> None:
        """The document lives in the descriptor, never in the tool body."""
        for name in ("sl1_create_icon", "sl1_list_icons", "sl1_set_device_class"):
            descriptor = d.DB_DESCRIPTORS_BY_NAME[name]
            assert descriptor.document, name
            assert descriptor.root_field, name

    async def test_set_device_class_icon_confirms_with_a_second_read(self) -> None:
        """The mutation's own return can be stale, so a second read confirms it."""
        sl1 = FakeSl1(graphql_results=[{}, {"deviceClass": {"id": "9", "hasIcon": True}}])
        tool = reg._FACTORY_FOR["sl1_set_device_class_icon"](make_context(sl1=sl1))
        result = await call(tool, device_class_guid="A" * 32, icon_id="7")
        assert len(sl1.graphql_calls) == 2
        assert sl1.graphql_calls[1]["query"] == d.READ_DEVICE_CLASS_DOCUMENT
        assert result["device_class"]["hasIcon"] is True

    async def test_list_icons_refuses_a_non_positive_first(self) -> None:
        tool = reg._FACTORY_FOR["sl1_list_icons"](make_context())
        result = await call(tool, first=0)
        assert_refused(result)


def _appliance_payload(appliances: dict[int, str]) -> dict[str, Any]:
    """A REST ``appliance`` search payload, shaped as SL1 actually returns one.

    Keyed by URI with the `type` string inside each row. That nesting is the part a hand-written
    fake gets wrong, and it is what `eligible_discovery_collectors` has to walk.
    """
    return {
        "result_set": {
            f"/api/appliance/{i}": {"type": t, "name": f"box-{i}", "ip": f"10.0.0.{i}"}
            for i, t in appliances.items()
        }
    }


class TestDiscoveryCollectorResolution:
    """A discovery session must never be aligned to the Central Database.

    The defect is silent. ``master.policies_discovery.pid`` defaults to 1, so omitting the
    collector lands the session on appliance 1, which on a distributed stack is the CDB and does
    not collect. The session is created successfully and then hangs. On a test appliance, both
    existing sessions carried ``/api/appliance/1`` and neither had ever run.
    """

    async def test_it_never_selects_the_central_database(self) -> None:
        """`db` is present and must lose to the collectors."""
        sl1 = FakeSl1(rest_results=[_appliance_payload({1: "db", 3: "cu", 4: "cu"}), {}])
        tool = reg._FACTORY_FOR["sl1_create_discovery_session"](make_context(sl1=sl1))

        await call(tool, name="scan")

        sent = next(c for c in sl1.rest_calls if c["path"] == "discovery_session")
        assert sent["json_body"]["aligned_collector"] == "/api/appliance/3"
        assert sent["json_body"]["aligned_collector"] != "/api/appliance/1"

    async def test_an_all_in_one_is_eligible_and_is_chosen(self) -> None:
        """`ao` must not be treated as a database, even though an AIO is one.

        A rule written as "exclude the db" would break this: on an AIO stack the sole appliance is
        the collector. An AIO reports ``type: "ao"``, and sessions on a live AIO run on appliance 1.
        """
        sl1 = FakeSl1(rest_results=[_appliance_payload({1: "ao"}), {}])
        tool = reg._FACTORY_FOR["sl1_create_discovery_session"](make_context(sl1=sl1))

        await call(tool, name="scan")

        sent = next(c for c in sl1.rest_calls if c["path"] == "discovery_session")
        assert sent["json_body"]["aligned_collector"] == "/api/appliance/1"

    async def test_it_refuses_when_nothing_on_the_stack_collects(self) -> None:
        """A database-only stack has no valid target, so refuse rather than pick the CDB."""
        sl1 = FakeSl1(rest_results=[_appliance_payload({1: "db"})])
        tool = reg._FACTORY_FOR["sl1_create_discovery_session"](make_context(sl1=sl1))

        result = await call(tool, name="scan")

        assert_refused(result, "no appliance on this stack can run a discovery session")
        assert not any(c["path"] == "discovery_session" for c in sl1.rest_calls), (
            "nothing may be created when no collector is eligible"
        )

    async def test_the_choice_is_deterministic_and_numeric(self) -> None:
        """Lowest id, compared as an integer; a string sort puts 10 before 3."""
        sl1 = FakeSl1(rest_results=[_appliance_payload({10: "cu", 3: "cu", 20: "cu"}), {}])
        tool = reg._FACTORY_FOR["sl1_create_discovery_session"](make_context(sl1=sl1))

        await call(tool, name="scan")

        sent = next(c for c in sl1.rest_calls if c["path"] == "discovery_session")
        assert sent["json_body"]["aligned_collector"] == "/api/appliance/3"

    async def test_the_auto_selection_is_reported_not_silent(self) -> None:
        """The caller must be able to see that a choice was made for them."""
        sl1 = FakeSl1(rest_results=[_appliance_payload({1: "db", 3: "cu", 4: "cu"}), {"id": 7}])
        tool = reg._FACTORY_FOR["sl1_create_discovery_session"](make_context(sl1=sl1))

        result = await call(tool, name="scan")

        assert result["collector_auto_selected"] is True
        assert result["collector_candidates"] == [
            {"id": 3, "name": "box-3"},
            {"id": 4, "name": "box-4"},
        ]
        assert "central database is never eligible" in str(result["note"]).lower()
        assert result["id"] == 7, "SL1's own response must survive the merge"

    async def test_an_explicit_collector_skips_the_lookup_entirely(self) -> None:
        """An operator's explicit choice is honoured, and costs no extra REST call."""
        sl1 = FakeSl1(rest_results=[{}])
        tool = reg._FACTORY_FOR["sl1_create_discovery_session"](make_context(sl1=sl1))

        result = await call(tool, name="scan", aligned_collector="/api/appliance/9")

        assert [c["path"] for c in sl1.rest_calls] == ["discovery_session"]
        assert sl1.rest_calls[0]["json_body"]["aligned_collector"] == "/api/appliance/9"
        assert "collector_auto_selected" not in result

    async def test_a_collector_injected_via_session_also_counts_as_explicit(self) -> None:
        """`session` is merged into the body, so it can carry `aligned_collector` too.

        Checking the named parameter alone would let a caller reintroduce the CDB, and would make
        us overwrite a collector they had in fact supplied.
        """
        sl1 = FakeSl1(rest_results=[{}])
        tool = reg._FACTORY_FOR["sl1_create_discovery_session"](make_context(sl1=sl1))

        result = await call(tool, name="scan", session={"aligned_collector": "/api/appliance/8"})

        assert [c["path"] for c in sl1.rest_calls] == ["discovery_session"]
        assert sl1.rest_calls[0]["json_body"]["aligned_collector"] == "/api/appliance/8"
        assert "collector_auto_selected" not in result

    async def test_it_does_not_clobber_a_field_sl1_returned(self) -> None:
        """The advisory merges into SL1's response and must not overwrite its fields.

        Otherwise a caller could not tell whose value they were reading.
        """
        sl1 = FakeSl1(
            rest_results=[_appliance_payload({3: "cu"}), {"note": "SL1 said this", "id": 1}]
        )
        tool = reg._FACTORY_FOR["sl1_create_discovery_session"](make_context(sl1=sl1))

        result = await call(tool, name="scan")

        assert result["note"] == "SL1 said this"
        assert result["collector_auto_selected"] is True


class TestEligibleDiscoveryCollectors:
    """The pure selection rule, exercised without a client."""

    def test_it_is_an_allowlist_not_a_db_exclusion(self) -> None:
        """An unmodelled appliance type must not become a discovery target.

        `ap` (Administration Portal) and `mc` (Message Collector) do not collect. A rule written as
        `type != "db"` would silently admit both.
        """
        payload = _appliance_payload({1: "db", 2: "ap", 3: "cu", 4: "mc", 5: "ao"})
        assert [e["id"] for e in ops.eligible_discovery_collectors(payload)] == [3, 5]

    def test_malformed_rows_are_skipped_not_guessed(self) -> None:
        payload: dict[str, Any] = {
            "result_set": {
                "/api/appliance/3": {"type": "cu", "name": "good"},
                "/api/appliance/4": "not a mapping",
                "/api/appliance/5": {"name": "no type at all"},
                "/api/appliance/6": {"type": 5, "name": "type is not a string"},
                "/api/appliance/notanumber": {"type": "cu", "name": "unparseable id"},
            }
        }
        assert [e["id"] for e in ops.eligible_discovery_collectors(payload)] == [3]

    def test_a_non_decimal_id_is_skipped_rather_than_raising(self) -> None:
        """`isdigit()` is True for 128 characters `int()` rejects.

        The obvious spelling would raise `ValueError` here instead of skipping the row.
        """
        payload = {"result_set": {"/api/appliance/\u00b2": {"type": "cu", "name": "superscript"}}}
        assert ops.eligible_discovery_collectors(payload) == []

    def test_an_unusable_payload_is_empty_not_an_error(self) -> None:
        assert ops.eligible_discovery_collectors({}) == []
        assert ops.eligible_discovery_collectors([]) == []
        assert ops.eligible_discovery_collectors({"result_set": "nonsense"}) == []


class TestDiscoveryTools:
    async def test_run_uses_the_uri_apply_pattern(self) -> None:
        """A plain JSON POST does not start discovery: it returns success and nothing happens."""
        sl1 = FakeSl1(rest_results=[{}])
        tool = reg._FACTORY_FOR["sl1_run_discovery_session"](make_context(sl1=sl1))
        await call(tool, session_id="12")
        sent = sl1.rest_calls[0]
        assert sent["content_type"] == "application/em7-resource-uri"
        assert sent["raw_body"] == "/api/discovery_session/12"
        assert "json_body" not in sent

    async def test_run_accepts_a_full_uri_unchanged(self) -> None:
        sl1 = FakeSl1(rest_results=[{}])
        tool = reg._FACTORY_FOR["sl1_run_discovery_session"](make_context(sl1=sl1))
        await call(tool, session_id="/api/discovery_session/34")
        assert sl1.rest_calls[0]["raw_body"] == "/api/discovery_session/34"

    async def test_create_does_not_start_the_session(self) -> None:
        """Selects the call by path, not index, because the appliance lookup comes first."""
        sl1 = FakeSl1(rest_results=[_appliance_payload({3: "cu"}), {}])
        tool = reg._FACTORY_FOR["sl1_create_discovery_session"](make_context(sl1=sl1))
        await call(tool, name="scan", session={"ip_lists": "10.0.0.0/24"})

        sent = next(c for c in sl1.rest_calls if c["path"] == "discovery_session")
        assert sent["json_body"]["ip_lists"] == "10.0.0.0/24"
        assert sent["json_body"]["organization"] == "0"
        assert not any("start" in str(c["path"]) for c in sl1.rest_calls)

    async def test_create_refuses_an_empty_name(self) -> None:
        tool = reg._FACTORY_FOR["sl1_create_discovery_session"](make_context())
        result = await call(tool, name="   ")
        assert_refused(result)

    async def test_list_applies_the_name_filter(self) -> None:
        sl1 = FakeSl1(rest_results=[{}])
        tool = reg._FACTORY_FOR["sl1_list_discovery_sessions"](make_context(sl1=sl1))
        await call(tool, name_contains="prod", limit=5)
        query = sl1.rest_calls[0]["query"]
        assert query["filter.name.contains"] == "prod"
        assert query["limit"] == "5"
        assert query["extended_fetch"] == "1"

    async def test_status_reads_the_active_resource(self) -> None:
        sl1 = FakeSl1(rest_results=[{}])
        tool = reg._FACTORY_FOR["sl1_get_discovery_status"](make_context(sl1=sl1))
        await call(tool)
        assert sl1.rest_calls[0]["path"] == "discovery_session_active"


class TestOpsTools:
    async def test_server_health_probes_all_three_transports(self) -> None:
        sl1 = FakeSl1(
            rest_results=[[{"URI": "/api/device"}]],
            graphql_results=[
                {"__schema": {"queryType": {"fields": [{"name": "devices"}]}}},
                {"systemInformation": {"em7Version": "12.5.1"}},
            ],
        )
        lce = FakeLce(status_code=200)
        tool = reg._FACTORY_FOR["server_health"](make_context(sl1=sl1, lce=lce, db=FakeDb()))
        result = await call(tool)
        assert result["rest"]["reachable"] is True
        assert result["graphql"]["reachable"] is True
        assert result["lce"]["reachable"] is True
        assert result["em7_version"] == "12.5.1"
        assert result["database"]["configured"] is True

    async def test_server_health_never_queries_the_database(self) -> None:
        """A DB call is blocking I/O, and a health check must not queue behind a slow query.

        Otherwise it could restart a service that is merely busy, turning a capacity condition into
        an outage.
        """
        db = FakeDb()
        tool = reg._FACTORY_FOR["server_health"](make_context(db=db))
        await call(tool)
        assert db.statements == []
        assert db.units == []

    async def test_server_health_states_ssh_is_not_applicable(self) -> None:
        # SSH is not checked because the service has no SSH credentials, not as a security
        # judgement. An operator must see that it was not checked rather than infer it from silence.
        tool = reg._FACTORY_FOR["server_health"](make_context())
        result = await call(tool)
        assert "no SSH credentials" in result["ssh"]

    async def test_a_failed_probe_reads_as_unreachable_not_as_a_crash(self) -> None:
        class Failing(FakeSl1):
            async def request(self, **kwargs: Any) -> Any:  # noqa: ARG002 - signature match
                raise DbError("down")

            async def graphql(self, **kwargs: Any) -> Any:  # noqa: ARG002 - signature match
                raise DbError("down")

        tool = reg._FACTORY_FOR["server_health"](make_context(sl1=Failing()))
        result = await call(tool)
        assert result["rest"]["reachable"] is False
        assert result["graphql"]["reachable"] is False

    async def test_check_capabilities_reports_only_tools_this_server_has(self) -> None:
        """Derived from our registry, so it cannot name a tool we do not ship."""
        tool = reg._FACTORY_FOR["sl1_check_capabilities"](make_context(db=FakeDb()))
        result = await call(tool)
        reported = {entry["tool"] for entry in result["tools"]}
        assert reported == {desc.tool_name for desc in d.REGISTERING_DB_DESCRIPTORS}
        assert len(reported) == authz.REGISTERED_TOOL_COUNT
        assert "list_capabilities" not in reported

    async def test_check_capabilities_warns_that_introspection_is_not_authorization(self) -> None:
        # Introspection is not authorization; the payload has to say so.
        tool = reg._FACTORY_FOR["sl1_check_capabilities"](make_context())
        result = await call(tool)
        assert any("not permission-gated" in note for note in result["notes"])

    async def test_a_multi_backend_tool_is_unavailable_unless_every_backend_is(self) -> None:
        """Reporting available because the first backend answered would over-claim."""
        sl1 = FakeSl1(rest_results=[[{"URI": "/api/device"}]])  # REST up, GraphQL down
        tool = reg._FACTORY_FOR["sl1_check_capabilities"](make_context(sl1=sl1, lce=FakeLce(500)))
        result = await call(tool)
        health = next(e for e in result["tools"] if e["tool"] == "server_health")
        assert health["status"] == "unavailable"


# ---- The shared helpers -------------------------------------------------------------------------


# ---- A degraded probe leaves a record -----------------------------------------------------------

# The keys `server_health` returns. The reason for a failed probe goes to the log, not the payload,
# so this is a tripwire on the payload shape.
_SERVER_HEALTH_KEYS = frozenset(
    {"rest", "graphql", "lce", "em7_version", "ssh", "database"},
)


def _probe_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    """The WARNING lines `_probe` emitted, rendered as a handler would see them.

    Filtered by logger name so an unrelated warning from the pipeline or the boundary cannot make
    one of these tests pass by accident.
    """
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and r.name.endswith("sl1_ops_tools")
    ]


class TestADegradedProbeIsRecorded:
    """Each failed `_probe` arm logs which probe failed and why.

    An unreachable host, a 401, a 403, a 404, a 5xx, an unparseable or oversized body, a GraphQL
    error envelope and a TLS failure all read as ``reachable: false`` in the payload. Without a log
    record there is nowhere to look for the reason. The payload shape is pinned too.
    """

    async def test_a_failed_rest_probe_records_which_probe_and_which_failure(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        sl1 = RaisingSl1(rest_error=Sl1Unreachable("sl1.example"))
        tool = reg._FACTORY_FOR["server_health"](make_context(sl1=sl1))
        with caplog.at_level(logging.WARNING):
            result = await call(tool)
        assert result["rest"]["reachable"] is False
        warnings = _probe_warnings(caplog)
        assert len(warnings) == 1, warnings
        assert "rest probe failed" in warnings[0]
        assert "Sl1Unreachable" in warnings[0]

    async def test_a_failed_graphql_probe_records_which_probe_and_which_failure(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        sl1 = RaisingSl1(roots_error=Sl1GraphQlError(["denied"], ["RESTRICTED_ACCESS"]))
        tool = reg._FACTORY_FOR["server_health"](make_context(sl1=sl1))
        with caplog.at_level(logging.WARNING):
            result = await call(tool)
        assert result["graphql"]["reachable"] is False
        warnings = _probe_warnings(caplog)
        assert len(warnings) == 1, warnings
        assert "graphql probe failed" in warnings[0]
        assert "Sl1GraphQlError" in warnings[0]

    async def test_a_failed_version_probe_records_itself_separately(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The version read is a second GraphQL call, and its failure is not the roots'.

        The log must say which of the two failed, or "graphql failed" would be ambiguous between a
        dead transport and a version field this appliance does not expose.
        """
        sl1 = RaisingSl1(version_error=Sl1ResponseTooLarge(4096))
        tool = reg._FACTORY_FOR["server_health"](make_context(sl1=sl1))
        with caplog.at_level(logging.WARNING):
            result = await call(tool)
        assert result["em7_version"] is None
        assert result["graphql"]["reachable"] is True
        warnings = _probe_warnings(caplog)
        assert len(warnings) == 1, warnings
        assert "graphql_version probe failed" in warnings[0]
        assert "Sl1ResponseTooLarge" in warnings[0]

    async def test_a_failed_lce_probe_records_which_probe_and_which_failure(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A malformed probe path makes the real client raise, and the log must say so."""
        lce = RaisingLce(LceUnreachable("lce.example"))
        tool = reg._FACTORY_FOR["server_health"](make_context(sl1=RaisingSl1(), lce=lce))
        with caplog.at_level(logging.WARNING):
            result = await call(tool)
        assert result["lce"]["reachable"] is False
        warnings = _probe_warnings(caplog)
        assert len(warnings) == 1, warnings
        assert "lce probe failed" in warnings[0]
        assert "LceUnreachable" in warnings[0]

    async def test_an_http_failure_records_the_backend_status(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A 401 is retryable with a fixed credential, a 404 is not; the payload shows neither."""
        lce = RaisingLce(LceHttpError(401, {"message": "denied"}))
        tool = reg._FACTORY_FOR["server_health"](make_context(sl1=RaisingSl1(), lce=lce))
        with caplog.at_level(logging.WARNING):
            await call(tool)
        assert "401" in _probe_warnings(caplog)[0]

    async def test_every_arm_can_fail_at_once_without_the_tool_raising(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """All four down: four records, and a well-formed payload with the usual keys.

        The key assertion is a tripwire. Adding a per-probe ``status`` or ``error`` field should be
        a deliberate change, not a side effect.
        """
        sl1 = RaisingSl1(
            rest_error=Sl1Unreachable("sl1.example"),
            roots_error=Sl1HttpError(500, {"message": "boom"}),
            version_error=Sl1MalformedResponse(),
        )
        lce = RaisingLce(LceUnreachable("lce.example"))
        tool = reg._FACTORY_FOR["server_health"](make_context(sl1=sl1, lce=lce))
        with caplog.at_level(logging.WARNING):
            result = await call(tool)
        assert set(result) == _SERVER_HEALTH_KEYS
        assert set(result["graphql"]) == {"reachable", "queries", "mutations"}
        assert result["rest"] == {"reachable": False, "resources": 0}
        assert result["lce"] == {"reachable": False}
        assert "error" not in result
        assert len(_probe_warnings(caplog)) == 4, _probe_warnings(caplog)

    async def test_no_probe_record_carries_foreign_text(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Only the exception's class name and the numeric status reach the log.

        Neither `str(exc)` nor any payload attribute is interpolated, so an SL1- or LCE-authored
        string, here carrying a credential-shaped value, cannot reach the log through this path.
        """
        sl1 = RaisingSl1(
            roots_error=Sl1GraphQlError(["Cannot query field tok-s3cr3t-abc on type Device"]),
        )
        lce = RaisingLce(LceHttpError(403, {"detail": "authorization tok-s3cr3t-abc rejected"}))
        tool = reg._FACTORY_FOR["server_health"](make_context(sl1=sl1, lce=lce))
        with caplog.at_level(logging.WARNING):
            await call(tool)
        rendered = " ".join(_probe_warnings(caplog))
        assert "s3cr3t" not in rendered, rendered
        assert "Cannot query field" not in rendered, rendered
        assert "detail" not in rendered, rendered
        assert "Sl1GraphQlError" in rendered
        assert "403" in rendered

    async def test_a_rest_index_that_is_not_an_array_records_why(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A succeeding REST call that still reads as unreachable.

        SL1 answering ``/`` with an object (a login redirect body, an error envelope with a 2xx)
        leaves ``rest_ok`` false, correctly, but the log must distinguish it from a connect failure.
        """
        sl1 = FakeSl1(
            rest_results=[{"message": "login required"}],
            graphql_results=[_HEALTHY_ROOTS, _HEALTHY_VERSION],
        )
        tool = reg._FACTORY_FOR["server_health"](make_context(sl1=sl1))
        with caplog.at_level(logging.WARNING):
            result = await call(tool)
        assert result["rest"]["reachable"] is False
        warnings = _probe_warnings(caplog)
        assert len(warnings) == 1, warnings
        assert "rest probe answered" in warnings[0]
        assert "not a JSON array" in warnings[0]

    async def test_an_introspection_naming_no_fields_records_why(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Introspection succeeded and ``graphql_ok`` still reads false.

        The transport answered, authenticated and parsed, yet ``graphql_ok = bool(queries or
        mutations)`` reports the surface as unreachable. The log must distinguish that from a dead
        appliance.
        """
        sl1 = FakeSl1(
            rest_results=[_HEALTHY_REST_INDEX],
            graphql_results=[{"__schema": {}}, _HEALTHY_VERSION],
        )
        tool = reg._FACTORY_FOR["server_health"](make_context(sl1=sl1))
        with caplog.at_level(logging.WARNING):
            result = await call(tool)
        assert result["graphql"]["reachable"] is False
        warnings = _probe_warnings(caplog)
        assert len(warnings) == 1, warnings
        assert "graphql probe answered" in warnings[0]
        assert "no query or mutation fields" in warnings[0]

    async def test_a_healthy_probe_records_nothing(self, caplog: pytest.LogCaptureFixture) -> None:
        """If these lines fired unconditionally the tests above would still pass.

        `RaisingSl1` with no errors is the all-green surface.
        """
        tool = reg._FACTORY_FOR["server_health"](make_context(sl1=RaisingSl1()))
        with caplog.at_level(logging.WARNING):
            result = await call(tool)
        assert result["rest"]["reachable"] is True
        assert result["graphql"]["reachable"] is True
        assert result["lce"]["reachable"] is True
        assert _probe_warnings(caplog) == []

    @pytest.mark.parametrize("status", [200, 201, 202, 204])
    async def test_any_2xx_lce_response_reads_as_reachable(self, status: int) -> None:
        """A healthy LCE answering ``201``, ``202`` or ``204`` is reachable.

        `LceClient.request` raises `LceHttpError` on any non-2xx, so the success branch only ever
        sees a 2xx. A check for exactly ``200`` would report a healthy LCE as unreachable.
        """
        tool = reg._FACTORY_FOR["server_health"](
            make_context(sl1=RaisingSl1(), lce=FakeLce(status_code=status))
        )
        result = await call(tool)
        assert result["lce"]["reachable"] is True


# ---- The write audit ----------------------------------------------------------------------------

# Minimal required arguments per `master.*` write tool, so each can be called rather than merely
# inspected. The values are irrelevant because every case below fails fast (no database, or an
# empty `FakeDb`): what is under test is the record, not the write.
_WRITE_TOOL_ARGS: dict[str, dict[str, str]] = {
    "sl1_simulate_event": {"device": "7", "message": "m"},
    "sl1_create_device_class": {"class_name": "c", "description": "d"},
    "sl1_update_device_class": {"device_class_guid": "0" * 32},
    "sl1_align_dynamic_app_to_device_class": {"dynamic_app": "a", "device_class": "0" * 32},
    "sl1_run_dynamic_collection": {"device": "7", "app_id": "526"},
}


def _audit_records(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    """The `MASTER_WRITE_AUDITED` records as plain dicts, keyed on `event` as monitoring does.

    Returns `vars(record)`, not the `LogRecord`. The audit fields arrive through `extra=`, so they
    are dynamic attributes and `record.outcome` is a static type error. The record's `__dict__` is
    also closer to what a log handler sees.
    """
    return [
        vars(r)
        for r in caplog.records
        if getattr(r, "event", None) == str(LogEvent.MASTER_WRITE_AUDITED)
    ]


class TestMasterWriteAudit:
    """Every `master.*` write is audit-logged with tool, actor and outcome.

    The audit is what makes a `master.*` write attributable. The tests are parametrised per tool
    rather than looped, so a tool missing the decorator is named in the failure.
    """

    WRITE_TOOLS = tuple(desc.tool_name for desc, _ in reg.db_write_tools())

    def test_the_write_set_is_the_five_master_writes(self) -> None:
        """Derived, never listed. Also pins that `_WRITE_TOOL_ARGS` covers them all."""
        assert len(self.WRITE_TOOLS) == 5
        assert set(self.WRITE_TOOLS) <= authz.write_tool_names()
        assert set(self.WRITE_TOOLS) == set(_WRITE_TOOL_ARGS)

    @pytest.mark.parametrize("tool_name", WRITE_TOOLS)
    def test_every_write_tool_keeps_its_docstring_through_the_wrapper(self, tool_name: str) -> None:
        """The schema is built from `__doc__`, so a wrapper that loses it strips the description.

        Checking for `__wrapped__` instead would prove nothing: `sl1_tool_boundary` also uses
        `functools.wraps`, so every tool has it, audited or not.
        """
        tool = reg._FACTORY_FOR[tool_name](make_context(db=FakeDb()))
        assert tool.__doc__, f"{tool_name} lost its docstring through the audit wrapper"

    @pytest.mark.parametrize("tool_name", WRITE_TOOLS)
    async def test_a_refused_write_is_audited(
        self, tool_name: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A refused write is exactly what an audit trail exists for: someone tried.

        Driven with no database, so `require_db()` refuses before any statement is built.
        """
        tool = reg._FACTORY_FOR[tool_name](make_context(db=None))
        with caplog.at_level(logging.INFO):
            await call(tool, **_WRITE_TOOL_ARGS[tool_name])
        records = _audit_records(caplog)
        assert len(records) == 1, f"{tool_name}: expected exactly one audit record"
        assert records[0]["outcome"] == "refused"
        assert records[0]["tool"] == tool_name

    @pytest.mark.parametrize("tool_name", WRITE_TOOLS)
    async def test_a_failed_write_is_audited_as_failed(
        self, tool_name: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """``outcome="failed"`` records how the call ended, never what the database retained.

        ``@@autocommit = 1`` and there is no transaction, so a failure part-way through a
        `run_unit` sequence has already applied the statements before it. The field does not mean
        "nothing happened".
        """
        db = FakeDb(raises=DbError("the connection dropped"))
        tool = reg._FACTORY_FOR[tool_name](make_context(db=db))
        # `sl1_update_device_class` refuses before reaching the database when no field is
        # supplied, which would record "refused" instead of "failed". The arguments here must get
        # past each tool's own guards to reach the DB.
        kwargs = dict(_WRITE_TOOL_ARGS[tool_name])
        if tool_name == "sl1_update_device_class":
            kwargs["class_name"] = "renamed"
        with caplog.at_level(logging.INFO):
            await call(tool, **kwargs)
        records = _audit_records(caplog)
        assert len(records) == 1, f"{tool_name}: a failure must still be audited"
        assert records[0]["outcome"] == "failed"

    async def test_a_cancellation_is_audited_and_re_raised(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Why the audit catches `BaseException`, not `Exception`.

        `CancelledError` inherits `BaseException`, and a cancelled write may already have
        committed, so a cancellation is when the trail matters most. The exception is re-raised
        untouched: swallowing a cancellation would break structured concurrency.
        """
        db = FakeDb(raises=asyncio.CancelledError())
        tool = reg._FACTORY_FOR["sl1_simulate_event"](make_context(db=db))
        with caplog.at_level(logging.INFO), pytest.raises(asyncio.CancelledError):
            await tool(**_WRITE_TOOL_ARGS["sl1_simulate_event"])
        records = _audit_records(caplog)
        assert len(records) == 1, "a cancelled write must still be audited"
        assert records[0]["outcome"] == "failed"

    async def test_the_record_carries_the_forwarded_actor(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The forwarded identity reaches the record's ``actor`` field.

        Patches `_current_actor`, the seam this audit reads, rather than the header parsing, which
        is tested where it lives.
        """
        tool = reg._FACTORY_FOR["sl1_simulate_event"](make_context(db=None))
        with (
            patch(
                "powerpack_mcp.tools.pipeline._current_actor", return_value="someone@example.com"
            ),
            caplog.at_level(logging.INFO),
        ):
            await call(tool, **_WRITE_TOOL_ARGS["sl1_simulate_event"])
        assert _audit_records(caplog)[0]["actor"] == "someone@example.com"

    async def test_an_absent_actor_is_none_not_a_placeholder(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """`None`, never `"unknown"`.

        There may genuinely be no forwarded identity, and a placeholder would be indistinguishable
        from a real actor with that name.
        """
        tool = reg._FACTORY_FOR["sl1_simulate_event"](make_context(db=None))
        with caplog.at_level(logging.INFO):
            await call(tool, **_WRITE_TOOL_ARGS["sl1_simulate_event"])
        assert _audit_records(caplog)[0]["actor"] is None

    @pytest.mark.parametrize("tool_name", WRITE_TOOLS)
    async def test_the_record_leaks_no_sql_and_no_argument_values(
        self, tool_name: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The record says who invoked which write and how it ended, and nothing else.

        Statement text is never assembled for logging, so a record containing SQL is a breach even
        without a credential in it.
        """
        tool = reg._FACTORY_FOR[tool_name](make_context(db=None))
        with caplog.at_level(logging.INFO):
            await call(tool, **_WRITE_TOOL_ARGS[tool_name])
        rendered = repr(_audit_records(caplog)[0]).lower()
        for forbidden in ("select ", "insert ", "update ", "delete ", "%s", "passwd", "password"):
            assert forbidden not in rendered, f"{tool_name}: audit record leaked {forbidden!r}"

    @pytest.mark.parametrize(
        ("tool_name", "kwargs"),
        [
            ("sl1_get_component_tree", {"root": "7"}),
            ("sl1_get_device_class_alignment", {"device_class": "0" * 32}),
            ("sl1_fetch_collection_output", {"proc_id": "4429"}),
        ],
    )
    async def test_the_read_tools_emit_no_audit_record(
        self, tool_name: str, kwargs: dict[str, str], caplog: pytest.LogCaptureFixture
    ) -> None:
        """Only `master.*` writes are audited, pinned by calling so the scope cannot quietly widen.

        Auditing reads would bury the writes in volume. The non-SQL writes are out of scope too:
        they reach SL1's own audited API. Structure cannot tell audited from unaudited, because the
        boundary sets `__wrapped__` on every tool; only the record can.
        """
        tool = reg._FACTORY_FOR[tool_name](make_context(db=None))
        with caplog.at_level(logging.INFO):
            await call(tool, **kwargs)
        assert _audit_records(caplog) == [], f"{tool_name} is a read; it must not be audited"

    def test_the_read_parametrisation_covers_every_read_tool(self) -> None:
        """A read tool added later must not slip past the test above."""
        covered = {
            "sl1_get_component_tree",
            "sl1_get_device_class_alignment",
            "sl1_fetch_collection_output",
        }
        assert {desc.tool_name for desc, _ in reg.db_read_tools()} == covered


class TestResolveDevice:
    async def test_a_numeric_id_is_confirmed_and_returns_an_int(self) -> None:
        sl1 = FakeSl1(rest_results=[{"name": "edge-01"}])
        context = make_context(sl1=sl1)
        assert await resolve_device(context, "77") == (77, "edge-01")
        assert sl1.rest_calls[0]["path"] == "device/77"

    async def test_a_name_is_searched_without_extended_fetch(self) -> None:
        """Only the id is needed, so the response stays small."""
        sl1 = FakeSl1(rest_results=[_DEVICE_INDEX])
        context = make_context(sl1=sl1)
        assert await resolve_device(context, "edge") == (77, "edge-01")
        assert "extended_fetch" not in sl1.rest_calls[0]["query"]

    async def test_an_unresolvable_name_raises_rather_than_returning_an_error_string(self) -> None:
        """An error value would need every caller to remember to check it.

        A forgotten check reads as success. Raising puts the refusal on the one path the boundary
        already translates.
        """
        context = make_context(sl1=FakeSl1(rest_results=[{}]))
        with pytest.raises(ValidationBlocked):
            await resolve_device(context, "nothing-matches")

    async def test_an_empty_device_is_refused(self) -> None:
        with pytest.raises(ValidationBlocked):
            await resolve_device(make_context(), "   ")

    async def test_an_exact_name_is_preferred_over_the_first_link(self) -> None:
        """A contains search returns `edge-01-old` for `edge-01`, possibly first."""
        index = {
            "/api/device/76": {"description": "edge-01-old"},
            "/api/device/77": {"description": "edge-01"},
        }
        context = make_context(sl1=FakeSl1(rest_results=[index]))
        assert await resolve_device(context, "edge-01") == (77, "edge-01")

    async def test_a_case_insensitive_exact_name_beats_a_substring(self) -> None:
        # The SQL lookup this replaced compared under MariaDB's case-insensitive collation.
        index = {
            "/api/device/76": {"description": "Edge-01-old"},
            "/api/device/77": {"description": "Edge-01"},
        }
        context = make_context(sl1=FakeSl1(rest_results=[index]))
        assert await resolve_device(context, "edge-01") == (77, "Edge-01")

    async def test_a_substring_match_is_still_accepted_by_default(self) -> None:
        """Existing callers keep resolving a partial name to the first device SL1 returns."""
        index = {"/api/device/76": {"description": "edge-01-old"}}
        context = make_context(sl1=FakeSl1(rest_results=[index]))
        assert await resolve_device(context, "edge-01") == (76, "edge-01-old")

    async def test_exact_refuses_a_substring_match_under_the_given_argument(self) -> None:
        index = {"/api/device/76": {"description": "edge-01-old"}}
        context = make_context(sl1=FakeSl1(rest_results=[index]))
        with pytest.raises(ValidationBlocked) as excinfo:
            await resolve_device(context, "edge-01", exact=True, argument="root")
        assert excinfo.value.findings[0].path == "root"
        assert_finding(excinfo, "no device named")

    async def test_a_link_without_a_description_is_never_an_exact_match(self) -> None:
        """Its name would only be the search text echoed back, which proves nothing."""
        context = make_context(sl1=FakeSl1(rest_results=[{"/api/device/76": {}}]))
        with pytest.raises(ValidationBlocked):
            await resolve_device(context, "edge-01", exact=True)

    async def test_an_index_that_is_not_a_mapping_resolves_nothing(self) -> None:
        context = make_context(sl1=FakeSl1(rest_results=[["/api/device/76"]]))
        with pytest.raises(ValidationBlocked):
            await resolve_device(context, "edge-01")


class TestOneValue:
    def test_no_rows_is_none_so_the_caller_must_decide(self) -> None:
        # The empty case is the point: an absent row must not flow on silently through COALESCE.
        assert one_value(()) is None
        assert one_value(((),)) is None

    def test_the_first_column_of_the_first_row(self) -> None:
        assert one_value(((7, "x"), (8, "y"))) == 7


class TestAsInt:
    """`as_int` converts a column value without letting a builtin exception escape.

    A bare ``int()`` on an unexpected column type raises `TypeError` or `ValueError`, which
    `sl1_tool_boundary` does not translate, so the caller would get an unhandled exception rather
    than an error payload. `one_value` returns ``object | None`` rather than `Any` so the type
    checker flags a bare ``int()``.
    """

    def test_an_int_passes_through(self) -> None:
        assert as_int(42, argument="root") == 42

    def test_a_numeric_string_is_accepted(self) -> None:
        """MySQLdb returns ints for integer columns, but a `DECIMAL` or `CHAR` id is text."""
        assert as_int(" 42 ", argument="root") == 42

    def test_a_bool_is_refused_even_though_it_is_an_int(self) -> None:
        """`True` would coerce to `1` and look like a plausible device id.

        A boolean where an id belongs means the statement selected the wrong column. The
        `isinstance(value, bool)` check must come before the `int` check, since `bool` is a
        subclass.
        """
        with pytest.raises(ValidationBlocked) as excinfo:
            as_int(True, argument="root")
        assert_finding(excinfo, "boolean")

    def test_a_non_numeric_value_is_refused_through_the_boundary_type(self) -> None:
        """`ValidationBlocked`, never `TypeError`."""
        for bad in (None, "not-a-number", 3.5, object(), b"7"):
            with pytest.raises(ValidationBlocked):
                as_int(bad, argument="device_class")

    def test_the_refusal_names_the_argument_and_the_type_it_got(self) -> None:
        with pytest.raises(ValidationBlocked) as excinfo:
            as_int(3.5, argument="device_class")
        assert_finding(excinfo, "device_class")
        assert_finding(excinfo, "float")

    def test_it_never_raises_a_builtin(self) -> None:
        """A future edit reintroducing a bare `int()` fails here.

        `ValidationBlocked` is caught while anything else propagates, so this asserts the type of
        every failure rather than merely that failures happen.
        """
        for bad in (None, "x", 3.5, [], {}, object(), b"1", ()):
            with contextlib.suppress(ValidationBlocked):
                as_int(bad, argument="root")


class TestCoded:
    def test_a_name_maps_to_its_code(self) -> None:
        assert coded("major", {"major": 3}, argument="severity") == 3

    def test_a_numeric_code_passes_through_when_valid(self) -> None:
        assert coded("3", {"major": 3}, argument="severity") == 3

    def test_case_and_whitespace_are_tolerated(self) -> None:
        assert coded("  MAJOR ", {"major": 3}, argument="severity") == 3

    def test_an_out_of_range_code_is_refused(self) -> None:
        with pytest.raises(ValidationBlocked):
            coded("99", {"major": 3}, argument="severity")


class TestDigitLikeButNotDecimal:
    """A numeric branch selected by ``isdigit()`` must not crash in ``int()``.

    The Hypothesis ``ci`` profile found this: ``int('²')`` raises `ValueError`, a builtin the
    boundary does not translate. Unlike `TestAsInt`, the fault is in the branch selector, so
    `as_int`'s own guard never runs. ``²`` and ``³`` appear in ordinary text ("m²", footnote
    markers), so a name carrying one is a plausible input.
    """

    # isdigit() is True and int() raises for every one of these. 128 such characters exist.
    DIGIT_NOT_DECIMAL = ("²", "³", "¹", "፩", "①", "⑵", "1²")

    def test_the_premise_holds_for_every_case(self) -> None:
        """Asserts the language behaviour the fix depends on, so the cases cannot go stale.

        If a future Python made ``int()`` accept these, or made ``isdigit()`` reject them, the tests
        below would still pass while asserting nothing. This pins the reason they exist.
        """
        for text in self.DIGIT_NOT_DECIMAL:
            assert text.isdigit(), f"{text!r} is not isdigit; it is the wrong sort of case"
            assert not text.isdecimal(), f"{text!r} is isdecimal; it would not have crashed"
            with pytest.raises(ValueError, match="invalid literal for int"):
                int(text)

    def test_isdecimal_is_a_strict_subset_of_isdigit(self) -> None:
        """Using ``isdecimal()`` can only narrow the numeric branch.

        Swept over every code point: the only inputs the selector stops treating as numeric are
        ones that would have raised.
        """
        for cp in range(0x110000):
            ch = chr(cp)
            if ch.isdecimal():
                assert ch.isdigit(), f"U+{cp:04X} breaks the subset claim the fix relies on"

    def test_as_int_refuses_instead_of_raising_a_builtin(self) -> None:
        for text in self.DIGIT_NOT_DECIMAL:
            with pytest.raises(ValidationBlocked):
                as_int(text, argument="root")

    def test_coded_refuses_instead_of_raising_a_builtin(self) -> None:
        """It falls through to the name branch and is refused there, which is correct.

        ``"²"`` is not a vocabulary name either, so the caller gets the "must be one of" refusal,
        the same answer any other unrecognised string gets.
        """
        for text in self.DIGIT_NOT_DECIMAL:
            with pytest.raises(ValidationBlocked):
                coded(text, {"major": 3}, argument="severity")

    def test_a_real_decimal_still_takes_the_numeric_branch(self) -> None:
        """The fix must not break the working path."""
        assert coded("3", {"major": 3}, argument="severity") == 3
        assert as_int("42", argument="root") == 42
        assert as_int(" 7 ", argument="root") == 7


class TestRequireDb:
    def test_it_returns_the_client_when_present(self) -> None:
        db = FakeDb()
        assert make_context(db=db).require_db() is db

    def test_it_raises_a_caller_facing_refusal_when_absent(self) -> None:
        # Called directly rather than through a tool, so it does raise here.
        with pytest.raises(ValidationBlocked) as excinfo:
            make_context(db=None).require_db()
        assert_finding(excinfo, "appliance database")


# ---- The branches the happy paths do not reach ---------------------------------------------------


class TestDeviceClassChangeCollection:
    """`_device_class_changes`, the pure part of the update tool, tested directly.

    Every branch tests ``is not None``, not truthiness, and these cases are why:
    ``is_snmp=False`` and ``class_name=""`` are values a caller may legitimately want to set, and a
    truthiness test would silently drop both.
    """

    def test_nothing_supplied_produces_no_changes(self) -> None:
        assert _changes() == {}

    def test_false_and_empty_string_are_real_values(self) -> None:
        result = _changes(is_snmp=False, root_device=False, class_name="", class_identifier_1="")
        assert result == {
            "is_snmp": 0,
            "root_device": 0,
            "class_name": "",
            "class_identifier_1": "",
        }

    def test_every_key_is_an_updatable_column(self) -> None:
        from powerpack_mcp.tools.sl1_db_statements import _UPDATABLE_COLUMNS

        result = _changes(
            class_name="a",
            description="b",
            device_type="virtual",
            is_snmp=True,
            root_device=True,
            class_identifier_1="c",
            class_identifier_2="d",
        )
        assert set(result) <= set(_UPDATABLE_COLUMNS)
        assert len(result) == 7
        assert result["device_type"] == 1  # virtual

    def test_a_bad_device_type_is_refused(self) -> None:
        with pytest.raises(ValidationBlocked) as excinfo:
            _changes(device_type="quantum")
        assert_finding(excinfo, "device_type must be one of")


class TestCategoryFid:
    def test_none_means_leave_it_alone(self) -> None:
        from powerpack_mcp.tools.sl1_db_tools import _category_fid

        assert _category_fid(None) is None

    def test_a_numeric_id_is_accepted(self) -> None:
        from powerpack_mcp.tools.sl1_db_tools import _category_fid

        assert _category_fid(" 42 ") == 42

    def test_a_name_is_refused_with_guidance(self) -> None:
        from powerpack_mcp.tools.sl1_db_tools import _category_fid

        with pytest.raises(ValidationBlocked) as excinfo:
            _category_fid("Servers")
        assert_finding(excinfo, "numeric device-category id")


class TestPowerpackResolution:
    """`_powerpack_guid`: clear, leave alone, or resolve, decided in Python."""

    @pytest.mark.parametrize("spelling", ["0", "null", "none", "", "  NULL  "])
    async def test_the_clear_spellings_all_mean_unown(self, spelling: str) -> None:
        from powerpack_mcp.tools.sl1_db_tools import _powerpack_guid

        assert await _powerpack_guid(make_context(db=FakeDb()), spelling) == (None, True)

    async def test_none_means_leave_it_alone_not_clear_it(self) -> None:
        from powerpack_mcp.tools.sl1_db_tools import _powerpack_guid

        # The distinction matters: (None, False) leaves ppguid alone, (None, True) NULLs it.
        assert await _powerpack_guid(make_context(db=FakeDb()), None) == (None, False)

    async def test_a_guid_is_used_directly_with_no_lookup(self) -> None:
        from powerpack_mcp.tools.sl1_db_tools import _powerpack_guid

        db = FakeDb()
        assert await _powerpack_guid(make_context(db=db), "C" * 32) == ("C" * 32, False)
        assert db.statements == []

    async def test_a_name_is_resolved_through_the_database(self) -> None:
        from powerpack_mcp.tools.sl1_db_tools import _powerpack_guid

        db = FakeDb(fetch_results=[(("D" * 32,),)])
        assert await _powerpack_guid(make_context(db=db), "Cisco: Base") == ("D" * 32, False)
        assert db.statements[0][1] == ("Cisco: Base",)


class TestUpdateDeviceClassPaths:
    async def test_clearing_the_powerpack_reaches_the_statement(self) -> None:
        updated = (("1", "A" * 32, "n", "d", 9, 0, 5, None, "", "", "Servers"),)
        db = FakeDb(
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=1, lastrowid=0),
                    StatementResult(rows=updated, rowcount=1, lastrowid=0),
                )
            ]
        )
        tool = reg._FACTORY_FOR["sl1_update_device_class"](make_context(db=db))
        result = await call(tool, device_class_guid="A" * 32, ppguid="0")
        assert "ppguid = NULL" in db.units[0][0]
        assert result["updated"]["devtype_guid"] == "A" * 32

    async def test_a_numeric_category_reaches_the_coalesce(self) -> None:
        updated = (("1", "A" * 32, "n", "d", 9, 0, 5, None, "", "", "Servers"),)
        db = FakeDb(
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=1, lastrowid=0),
                    StatementResult(rows=updated, rowcount=1, lastrowid=0),
                )
            ]
        )
        tool = reg._FACTORY_FOR["sl1_update_device_class"](make_context(db=db))
        await call(tool, device_class_guid="A" * 32, category="7")
        assert "family = COALESCE(%s, family)" in db.units[0][0]

    async def test_every_optional_field_can_be_set_at_once(self) -> None:
        updated = (("1", "A" * 32, "n", "d", 9, 2, 5, None, "i1", "i2", "Servers"),)
        db = FakeDb(
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=1, lastrowid=0),
                    StatementResult(rows=updated, rowcount=1, lastrowid=0),
                )
            ]
        )
        tool = reg._FACTORY_FOR["sl1_update_device_class"](make_context(db=db))
        await call(
            tool,
            device_class_guid="A" * 32,
            class_name="n",
            description="d",
            device_type="component",
            is_snmp=True,
            root_device=False,
            class_identifier_1="i1",
            class_identifier_2="i2",
        )
        assert "identifyer_3 = %s" in db.units[0][0]


class TestAlignmentByName:
    async def test_a_named_dynamic_app_uses_the_name_fragment(self) -> None:
        aligned = ((11, "Cisco: CPU", 9, "Acme | Widget"),)
        db = FakeDb(
            fetch_results=[((9,),)],
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=1, lastrowid=0),
                    StatementResult(rows=aligned, rowcount=1, lastrowid=0),
                )
            ],
        )
        tool = reg._FACTORY_FOR["sl1_align_dynamic_app_to_device_class"](make_context(db=db))
        result = await call(tool, dynamic_app="Cisco: CPU", device_class="B" * 32)
        assert "WHERE name = %s" in db.units[0][0]
        assert result["unaligned"] is False

    async def test_an_empty_dynamic_app_is_refused(self) -> None:
        tool = reg._FACTORY_FOR["sl1_align_dynamic_app_to_device_class"](make_context(db=FakeDb()))
        result = await call(tool, dynamic_app="  ", device_class="0")
        assert_refused(result, "must not be empty")


class TestEventHelperFallbacks:
    """The defensive paths: SL1 does not always send what its documentation implies."""

    def test_a_non_numeric_severity_becomes_zero_rather_than_raising(self) -> None:
        from powerpack_mcp.tools.sl1_event_tools import _as_int

        assert _as_int("not a number") == 0
        assert _as_int(None) == 0
        assert _as_int("4") == 4

    def test_a_non_numeric_timestamp_passes_through_unchanged(self) -> None:
        from powerpack_mcp.tools.sl1_event_tools import _as_timestamp

        assert _as_timestamp("never") == "never"
        assert _as_timestamp("") == ""

    def test_an_aware_utc_stamp_is_produced_for_epoch_seconds(self) -> None:
        from powerpack_mcp.tools.sl1_event_tools import _as_timestamp

        # `fromtimestamp(..., tz=UTC)`, not the deprecated `utcfromtimestamp`, which returns a
        # naive datetime that reads as local time downstream.
        assert _as_timestamp("0") == "1970-01-01T00:00:00Z"

    def test_config_groups_tolerates_a_non_dict(self) -> None:
        from powerpack_mcp.tools.sl1_event_tools import _config_groups

        assert _config_groups(None) == []
        assert _config_groups([1, 2]) == []

    def test_config_groups_resolves_object_names(self) -> None:
        from powerpack_mcp.tools.sl1_event_tools import _config_groups

        values = {
            "1": {
                "group_label": "eth0",
                "object_info": {"55": {"name": "ifDescr"}},
                "data": {"55": {"0": "up"}},
            }
        }
        groups = _config_groups(values)
        assert groups[0]["label"] == "eth0"
        # The name, not the bare object id: the reason this endpoint beats a direct DB read.
        assert "ifDescr" in groups[0]["objects"]

    def test_config_groups_falls_back_to_the_object_id(self) -> None:
        from powerpack_mcp.tools.sl1_event_tools import _config_groups

        groups = _config_groups({"1": {"data": {"55": "v"}}})
        assert "obj 55" in groups[0]["objects"]

    def test_performance_summary_tolerates_a_non_list(self) -> None:
        from powerpack_mcp.tools.sl1_event_tools import _performance_summary

        assert _performance_summary({}, None) == {"applications": []}

    def test_performance_summary_reports_data_found_per_presentation(self) -> None:
        from powerpack_mcp.tools.sl1_event_tools import _performance_summary

        payload = [
            {
                "appname": "Cisco: CPU",
                "presentations": [
                    {"presname": "Utilisation", "data_found": "1"},
                    {"presname": "Errors", "data_found": "0"},
                ],
            }
        ]
        result = _performance_summary(payload, None)
        found = {p["name"]: p["data_found"] for p in result["applications"][0]["presentations"]}
        # This field separates "collection is configured" from "collection produced
        # something", and a caller verifying a Dynamic Application needs the second.
        assert found == {"Utilisation": True, "Errors": False}

    def test_performance_summary_applies_the_name_filter(self) -> None:
        from powerpack_mcp.tools.sl1_event_tools import _performance_summary

        payload = [{"appname": "Cisco: CPU", "presentations": []}, {"appname": "Other"}]
        result = _performance_summary(payload, "cisco")
        assert [a["name"] for a in result["applications"]] == ["Cisco: CPU"]

    def test_the_graphql_root_reader_handles_both_envelope_shapes(self) -> None:
        from powerpack_mcp.tools.sl1_event_tools import _root

        assert _root({"createIcon": 1}, "createIcon") == 1
        assert _root({"data": {"createIcon": 2}}, "createIcon") == 2
        assert _root({"data": None}, "createIcon") is None
        assert _root({}, "createIcon") is None


class TestRecentEventsEdges:
    async def test_a_non_dict_index_is_refused(self) -> None:
        tool = reg._FACTORY_FOR["sl1_get_recent_events"](
            make_context(sl1=FakeSl1(rest_results=[[]]))
        )
        result = await call(tool)
        assert_refused(result, "unexpected shape")

    async def test_a_non_positive_limit_is_refused(self) -> None:
        tool = reg._FACTORY_FOR["sl1_get_recent_events"](make_context())
        result = await call(tool, limit=0)
        assert_refused(result, "at least 1")

    async def test_a_device_filter_excludes_other_devices(self) -> None:
        events = {
            "/api/event/1": {
                "severity": 4,
                "source": 6,
                "aligned_resource": "/api/device/77",
                "date_last": "1",
            },
            "/api/event/2": {
                "severity": 4,
                "source": 6,
                "aligned_resource": "/api/device/88",
                "date_last": "2",
            },
        }
        sl1 = FakeSl1(rest_results=[{"name": "edge"}, events])
        tool = reg._FACTORY_FOR["sl1_get_recent_events"](make_context(sl1=sl1))
        result = await call(tool, device="77")
        assert result["matched"] == 1
        assert result["events"][0]["id"] == "1"

    async def test_a_source_filter_excludes_other_sources(self) -> None:
        events = {
            "/api/event/1": {"severity": 4, "source": 6, "aligned_resource": "", "date_last": "1"},
            "/api/event/2": {"severity": 4, "source": 1, "aligned_resource": "", "date_last": "2"},
        }
        sl1 = FakeSl1(rest_results=[events])
        tool = reg._FACTORY_FOR["sl1_get_recent_events"](make_context(sl1=sl1))
        result = await call(tool, source="api")
        assert result["matched"] == 1
        assert result["source"] == "API"


class TestCollectedValuesEdges:
    async def test_a_non_positive_max_apps_is_refused(self) -> None:
        tool = reg._FACTORY_FOR["sl1_get_collected_values"](make_context())
        result = await call(tool, device="1", max_apps=0)
        assert_refused(result, "at least 1")

    async def test_the_dynamic_app_filter_narrows_the_applications(self) -> None:
        config = {"/api/x/1": {"name": "Cisco: CPU"}, "/api/x/2": {"name": "Other"}}
        sl1 = FakeSl1(rest_results=[{"name": "d"}, config, {}, []])
        tool = reg._FACTORY_FOR["sl1_get_collected_values"](make_context(sl1=sl1))
        result = await call(tool, device="1", dynamic_app="cisco")
        assert result["config"]["total_applications"] == 1


class TestComponentTreeEdges:
    async def test_a_non_positive_max_nodes_is_refused(self) -> None:
        tool = reg._FACTORY_FOR["sl1_get_component_tree"](make_context(db=FakeDb()))
        result = await call(tool, root="1", max_nodes=0)
        assert_refused(result, "at least 1")

    async def test_a_vanished_root_is_refused(self) -> None:
        # The id resolved, then the summary read came back empty: the row went away between the
        # two statements. Refused rather than reported with a null name.
        db = FakeDb(fetch_results=[()])
        tool = reg._FACTORY_FOR["sl1_get_component_tree"](make_context(db=db))
        result = await call(tool, root="42")
        assert_refused(result, "no longer exists")


class TestOpsEdges:
    async def test_the_database_verdict_reports_why_it_is_absent(self) -> None:
        tool = reg._FACTORY_FOR["server_health"](make_context(db=None))
        result = await call(tool)
        assert result["database"]["configured"] is False
        assert result["database"]["reason"]

    async def test_a_failed_lce_probe_reads_as_unreachable(self) -> None:
        """A non-2xx status on a returned response reads as unreachable.

        The real `LceClient` raises on any non-2xx, so this does not cover the exception arm; see
        `TestADegradedProbeIsRecorded` for that. `_probe` still checks the 2xx band rather than
        assuming it, so its verdict does not depend on an invariant in another module, and this is
        the only test that exercises the false side of that check.
        """
        tool = reg._FACTORY_FOR["server_health"](make_context(lce=FakeLce(status_code=503)))
        result = await call(tool)
        assert result["lce"]["reachable"] is False

    async def test_probe_reads_the_graphql_and_rest_surfaces(self) -> None:
        """`_probe` is shared by `sl1_check_capabilities` and `server_health`."""
        from powerpack_mcp.tools.sl1_ops_tools import _probe

        sl1 = FakeSl1(
            rest_results=[[{"URI": "/api/device"}, {"URI": "/api/event"}]],
            graphql_results=[
                {
                    "__schema": {
                        "queryType": {"fields": [{"name": "devices"}]},
                        "mutationType": {"fields": [{"name": "createIcon"}]},
                    }
                },
                {"systemInformation": {"em7Version": "12.5.1"}},
            ],
        )
        signals = await _probe(make_context(sl1=sl1))
        assert signals["rest_resources"] == ["device", "event"]
        assert signals["graphql_queries"] == ["devices"]
        assert signals["graphql_mutations"] == ["createIcon"]

    def test_field_names_tolerates_a_missing_root_type(self) -> None:
        from powerpack_mcp.tools.sl1_ops_tools import _field_names

        assert _field_names(None) == set()
        assert _field_names({}) == set()
        assert _field_names({"fields": "not a list"}) == set()


class TestSetAssignmentEnforcement:
    """`_check_set_assignment`: the tool-set rules, enforced at import."""

    def test_a_non_sql_tool_in_a_db_set_is_rejected(self) -> None:
        original = authz._ENTRIES
        try:
            authz._ENTRIES = tuple(  # type: ignore[misc]
                (
                    authz.ToolRegistryEntry(
                        name=e.name,
                        transport=e.transport,
                        writes=e.writes,
                        tool_set=authz.DB_READ_SET,
                        registers=e.registers,
                    )
                    if e.name == "sl1_clear_event"
                    else e
                )
                for e in original
            )
            with pytest.raises(AssertionError, match="Only SQL tools may be in a DB set"):
                authz._check_set_assignment()
        finally:
            authz._ENTRIES = original  # type: ignore[misc]

    def test_a_write_in_the_read_set_is_rejected(self) -> None:
        original = authz._ENTRIES
        try:
            authz._ENTRIES = tuple(  # type: ignore[misc]
                (
                    authz.ToolRegistryEntry(
                        name=e.name,
                        transport=e.transport,
                        writes=e.writes,
                        tool_set=authz.DB_READ_SET,
                        registers=e.registers,
                    )
                    if e.name == "sl1_simulate_event"
                    else e
                )
                for e in original
            )
            with pytest.raises(AssertionError, match="ENABLE_DB_WRITE_TOOLS"):
                authz._check_set_assignment()
        finally:
            authz._ENTRIES = original  # type: ignore[misc]

    def test_an_unknown_set_identifier_is_rejected(self) -> None:
        original = authz._ENTRIES
        try:
            authz._ENTRIES = (  # type: ignore[misc]
                authz.ToolRegistryEntry(
                    name="x", transport=authz.ToolTransport.REST, writes=False, tool_set="typo"
                ),
            )
            with pytest.raises(AssertionError, match="not one of"):
                authz._check_set_assignment()
        finally:
            authz._ENTRIES = original  # type: ignore[misc]


def _changes(**kwargs: Any) -> dict[str, object]:
    from powerpack_mcp.tools.sl1_db_tools import _device_class_changes

    defaults: dict[str, Any] = {
        "class_name": None,
        "description": None,
        "device_type": None,
        "is_snmp": None,
        "root_device": None,
        "class_identifier_1": None,
        "class_identifier_2": None,
    }
    return _device_class_changes(**{**defaults, **kwargs})


class TestRemainingBranches:
    """The last uncovered paths. Small, but each is a real behaviour someone could break."""

    async def test_inject_alert_forwards_a_threshold_when_given(self) -> None:
        sl1 = FakeSl1(rest_results=[{"name": "d"}, {}])
        tool = reg._FACTORY_FOR["sl1_inject_alert"](make_context(sl1=sl1))
        await call(tool, device="1", message="m", threshold="90")
        assert sl1.rest_calls[-1]["json_body"]["threshold"] == "90"

    async def test_simulate_event_refuses_a_negative_policy_id(self) -> None:
        tool = reg._FACTORY_FOR["sl1_simulate_event"](make_context(db=FakeDb()))
        result = await call(tool, device="1", message="m", event_policy=-1)
        assert_refused(result, "non-negative")

    async def test_recent_events_skips_non_dict_entries(self) -> None:
        # SL1's index has occasionally carried a scalar alongside the event objects.
        events = {"/api/event/1": "not an event", "/api/event/2": {"severity": 4, "date_last": "1"}}
        sl1 = FakeSl1(rest_results=[events])
        tool = reg._FACTORY_FOR["sl1_get_recent_events"](make_context(sl1=sl1))
        result = await call(tool)
        assert result["matched"] == 1

    async def test_collected_values_skips_entries_without_a_name(self) -> None:
        config = {"/api/x/1": {"name": "Real"}, "/api/x/2": {}, "/api/x/3": "scalar"}
        sl1 = FakeSl1(rest_results=[{"name": "d"}, config, {}, []])
        tool = reg._FACTORY_FOR["sl1_get_collected_values"](make_context(sl1=sl1))
        result = await call(tool, device="1")
        assert result["config"]["total_applications"] == 1

    async def test_list_icons_passes_the_filter_and_limit(self) -> None:
        sl1 = FakeSl1(graphql_results=[{"icons": {"edges": []}}])
        tool = reg._FACTORY_FOR["sl1_list_icons"](make_context(sl1=sl1))
        result = await call(tool, name_contains="disk", first=5)
        assert sl1.graphql_calls[0]["variables"] == {"first": 5, "contains": "disk"}
        assert "icons" in result

    async def test_set_device_class_sends_both_variables(self) -> None:
        sl1 = FakeSl1(graphql_results=[{"updateDevice": {"id": "9"}}])
        tool = reg._FACTORY_FOR["sl1_set_device_class"](make_context(sl1=sl1))
        result = await call(tool, device_id="9", device_class_guid="A" * 32)
        assert sl1.graphql_calls[0]["variables"] == {"id": "9", "deviceClass": "A" * 32}
        assert result["updateDevice"] == {"id": "9"}

    async def test_a_failed_version_probe_leaves_the_version_unknown(self) -> None:
        """Each probe degrades independently: a version read failing must not blank the rest."""

        class VersionFails(FakeSl1):
            async def graphql(self, **kwargs: Any) -> Any:
                self.graphql_calls.append(kwargs)
                if "systemInformation" in kwargs["query"]:
                    raise DbError("down")
                return {"__schema": {"queryType": {"fields": [{"name": "devices"}]}}}

        tool = reg._FACTORY_FOR["server_health"](make_context(sl1=VersionFails()))
        result = await call(tool)
        assert result["em7_version"] is None
        assert result["graphql"]["reachable"] is True

    async def test_discovery_list_refuses_a_non_positive_limit(self) -> None:
        tool = reg._FACTORY_FOR["sl1_list_discovery_sessions"](make_context())
        result = await call(tool, limit=0)
        assert_refused(result, "at least 1")

    async def test_discovery_create_forwards_an_aligned_collector(self) -> None:
        sl1 = FakeSl1(rest_results=[{}])
        tool = reg._FACTORY_FOR["sl1_create_discovery_session"](make_context(sl1=sl1))
        await call(tool, name="scan", aligned_collector="/api/appliance/3")
        assert sl1.rest_calls[0]["json_body"]["aligned_collector"] == "/api/appliance/3"

    async def test_discovery_run_refuses_an_empty_session_id(self) -> None:
        tool = reg._FACTORY_FOR["sl1_run_discovery_session"](make_context())
        result = await call(tool, session_id="  ")
        assert_refused(result, "must not be empty")

    def test_ops_tools_returns_the_fourteen(self) -> None:
        assert len(reg.ops_tools()) == 14

    def test_a_mismatched_factory_table_reports_both_directions(self) -> None:
        """The message must name which way it diverged; one direction is otherwise silent."""
        original = reg._FACTORY_FOR
        try:
            reg._FACTORY_FOR = {  # type: ignore[misc]
                **original,
                "sl1_not_a_tool": reg.make_server_health,
            }
            with pytest.raises(RuntimeError) as excinfo:
                reg._check_registry_is_total()
            assert "no registering descriptor claims" in str(excinfo.value)
        finally:
            reg._FACTORY_FOR = original  # type: ignore[misc]

    def test_moving_one_withheld_tool_trips_the_totality_check_first(self) -> None:
        """Moving one withheld tool leaves the sides inconsistent, so the totality check fires.

        It names the tool that lacks a factory. The case where both sides agree and only the
        withheld-set assertion refuses is covered by
        `TestRefreshCapabilityMapWithheld.test_widening_the_surface_so_both_sides_agree_is_still_rejected`.
        """
        original_desc = d.REGISTERING_DB_DESCRIPTORS
        original_fac = reg._FACTORY_FOR
        try:
            d.REGISTERING_DB_DESCRIPTORS = d.ALL_DB_DESCRIPTORS  # type: ignore[misc]
            reg._FACTORY_FOR = {  # type: ignore[misc]
                **original_fac,
                "list_capabilities": reg.make_server_health,
            }
            with pytest.raises(RuntimeError, match="no factory") as excinfo:
                reg._check_registry_is_total()
            assert "refresh_capability_map" in str(excinfo.value)
        finally:
            d.REGISTERING_DB_DESCRIPTORS = original_desc  # type: ignore[misc]
            reg._FACTORY_FOR = original_fac  # type: ignore[misc]


# ---- The DB-only device-collection route --------------------------------------------------------

# A terminated collection's log page, as `proc_remote_logs` returns it: `msg` is a ``BLOB``, the
# two streams are interleaved by id, and the run ends with a `msg_type=3` row. Shaped from a
# 412-row run measured on a test appliance (`proc_id` 4429), reduced to one row per stream.
_COLLECTION_ROWS = (
    (1950, 1, b"Process Started on Collector"),
    (1951, 2, b"Collecting for App ID: 526 from Device ID: 209\n"),
    (1952, 4, b"2026-09-02 19:45:34,238 - Starting the collection process\n"),
    (1953, 3, b"Process Completed on Collector"),
)


def _dispatch_context(
    *,
    collector: int = 4,
    rows: tuple[tuple[Any, ...], ...] = _COLLECTION_ROWS,
    job: tuple[Any, ...] = (0, 0, 125, 20),
    drains: bool = True,
) -> tuple[Any, FakeDb]:
    """A context whose DB answers the reads and the dispatch unit, in call order.

    ``job`` is parameterised so the in-flight row, where ``returncode`` is ``NULL``, can be
    exercised.

    ``drains`` exists because the output read only happens when the caller waits. `FakeDb` answers
    in sequence, so on the default no-wait path the job-row read would land on the entry the drain
    would have consumed, and the tool would parse a log row as a spool row. Pass ``drains=False``
    for any test that does not supply ``wait_seconds``.
    """
    fetches: list[Any] = [((collector,),)]
    if drains:
        fetches.append(rows)
    fetches.append((job,))
    db = FakeDb(
        fetch_results=fetches,
        unit_results=[
            (
                StatementResult(rows=(), rowcount=1, lastrowid=0),
                StatementResult(rows=((4429,),), rowcount=1, lastrowid=0),
            )
        ],
    )
    return make_context(db=db, sl1=FakeSl1(rest_results=[{"name": "edge-01"}])), db


class TestRunDynamicCollection:
    """A DB-only equivalent of SL1's lightning-bolt "run collection now" action."""

    async def test_it_dispatches_then_reads_the_id_on_the_same_connection(self) -> None:
        """The procedure returns nothing and `lastrowid` reads 0 after a ``CALL``.

        The id is only available from a second ``SELECT LAST_INSERT_ID()`` on the same connection,
        which is what `run_unit` guarantees. Split into two `fetch_all` calls, they would land on
        different workers and sessions, and the tool would return `proc_id` 0 and poll forever. A
        single-threaded test would not notice.
        """
        context, db = _dispatch_context(drains=False)
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526)

        assert result["proc_id"] == 4429
        assert len(db.units) == 1, "the CALL and LAST_INSERT_ID must be ONE unit"
        assert db.units[0][0].startswith("CALL master.process_admin_remote_policy")
        assert "LAST_INSERT_ID" in db.units[0][1].upper()

    async def test_the_queued_command_carries_the_siloproc_sentinel(self) -> None:
        """A regression here fails silently on the collector.

        Without the sentinel at offset 0 the Remote Toolbox raises "Unauthorized Process for
        Toolbox" and the job lands at ``state=4, returncode=99``. Nothing on this side errors, so
        only this assertion stands between a working tool and one that queues rejects.
        """
        context, db = _dispatch_context(drains=False)
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        await call(tool, device="77", app_id=526)

        dispatch = next(s for s in db.statements if s[0].startswith("CALL "))
        command = dispatch[1][0]
        assert command.startswith("SILOPROC "), command
        assert "/opt/em7/backend/sf_app_detailed_collect.py" in command, command
        assert "-p 77 526" in command, command

    async def test_a_parsed_collection_outcome_rides_alongside_the_raw_lines(self) -> None:
        """The parsed outcome is added; the raw trace is not replaced or filtered.

        The debug trace is what this tool exists to return, so the summary is additive. A change
        that started filtering `lines` would break callers iterating on snippet code.
        """
        document = (
            b'__CLIJSONOUTPUT__{"success": true, "dev_app_pairs": [["77", "526"]], '
            b'"results": {"77_526": {"1234": {"name": "cobj", "result": '
            b'{"result": {"did": 77, "snapshots": [], "processed_result": null}, '
            b'"logs": [{"messages": ["authentication failed"]}]}}}}}'
        )
        rows = (
            (1950, 1, b"Process Started on Collector"),
            (1951, 2, document),
            (1952, 3, b"Process Completed on Collector"),
        )
        context, _ = _dispatch_context(rows=rows)
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526, wait_seconds=5.0)

        # success: true, yet every object was empty. The outcome must contradict the flag.
        collection = result["collection"]
        assert collection["outcome"] == "failed"
        assert collection["dispatch_reported_success"] is True
        assert "authentication failed" in collection["messages"]
        # The raw lines are untouched, and the note points at the field to read.
        assert len(result["lines"]) == 3
        assert "collection.outcome" in result["note"]

    async def test_a_collection_with_no_document_carries_no_summary_block(self) -> None:
        """A missing `collection` key means "nothing to parse", not "failed"."""
        context, _ = _dispatch_context()
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526, wait_seconds=5.0)

        assert "collection" not in result
        assert len(result["lines"]) == 4

    async def test_a_sentinel_on_stderr_is_not_treated_as_the_document(self) -> None:
        """The document comes from stdout; stderr is where the framework's debug text goes."""
        rows = (
            (1950, 1, b"Process Started on Collector"),
            (1951, 4, b'__CLIJSONOUTPUT__{"success": true, "results": {}}'),
            (1952, 3, b"Process Completed on Collector"),
        )
        context, _ = _dispatch_context(rows=rows)
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526, wait_seconds=5.0)

        assert "collection" not in result

    async def test_it_reports_both_streams_interleaved_and_terminated(self) -> None:
        """Both streams, in emission order. The debug trace is on stderr and is the deliverable."""
        context, _ = _dispatch_context()
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526, wait_seconds=5.0)

        assert result["terminated"] is True
        assert result["last_id"] == 1953
        assert [line["stream"] for line in result["lines"]] == [
            "started",
            "stdout",
            "stderr",
            "completed",
        ]
        assert result["line_counts"] == {"started": 1, "stdout": 1, "stderr": 1, "completed": 1}
        assert result["lines"][1]["text"].endswith("Device ID: 209"), "trailing newline is stripped"

    async def test_it_claims_no_outcome(self) -> None:
        """Why this tool reports `terminated` and not `success`.

        A collection against a non-existent device was measured with ``state=0``, ``returncode=0``
        and a `msg_type=3` terminal row, identical to a good run in every structural field. So no
        key may read as a verdict, and the note must say so.
        """
        context, _ = _dispatch_context()
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526, wait_seconds=5.0)

        # The real risk is an inference from state==0, so assert the payload cannot support one:
        # `terminated` is the only boolean, and it is true for a failed collection too.
        assert result["terminated"] is True
        assert not any(
            key in result for key in ("succeeded", "success", "ok", "failed", "outcome", "status")
        ), sorted(result)
        assert "does not mean the collection SUCCEEDED" in result["note"]
        assert result["toolbox"] == {"state": 0, "returncode": 0}
        # The discriminators are used internally for the scope gate and must not be echoed as
        # though they described the collection's outcome.
        assert set(result["toolbox"]) == {"state", "returncode"}

    async def test_a_device_with_no_collector_is_refused_before_anything_is_queued(self) -> None:
        """The refusal must come before the dispatch, because a dispatch cannot be recalled."""
        db = FakeDb(fetch_results=[()])
        context = make_context(db=db, sl1=FakeSl1(rest_results=[{"name": "edge-01"}]))
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526)

        assert_refused(result, "no collector is recorded")
        assert db.units == [], "nothing may be queued when the collector did not resolve"

    @pytest.mark.parametrize("collector", [0, -1])
    async def test_a_non_positive_collector_id_is_refused_rather_than_broadcast(
        self, collector: int
    ) -> None:
        """A falsy collector id would broadcast the collection rather than fail.

        `master.process_async` branches on ``module_id``: 0 spools the command to every All-In-One
        and every collector, and NULL to every appliance in the licence table. So a falsy id here
        would fan the collection out across the estate.
        """
        db = FakeDb(fetch_results=[((collector,),)])
        context = make_context(db=db, sl1=FakeSl1(rest_results=[{"name": "edge-01"}]))
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526)

        assert_refused(result, "broadcasting")
        assert db.units == [], "a broadcast must never be queued"

    @pytest.mark.parametrize("app_id", [0, -3])
    async def test_a_non_positive_app_id_is_refused_before_any_database_call(
        self, app_id: int
    ) -> None:
        db = FakeDb()
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](make_context(db=db))

        result = await call(tool, device="77", app_id=app_id)

        assert_refused(result, "positive dynamic application id")
        assert db.statements == []

    async def test_it_refuses_without_a_database(self) -> None:
        """Fragment asserted, because `assert_refused` with none matches any refusal.

        This tool resolves the device over REST first, so a bare `assert_refused` here would be
        satisfied identically by a device-resolution refusal and could not show the refusal came
        from `require_db()`.
        """
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](make_context(db=None))
        assert_refused(await call(tool, device="77", app_id=526), "database")

    async def test_the_correlation_row_is_written_for_an_authenticated_caller(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The run appears in the platform's own Device Tools log.

        Every column is named explicitly. ``user_edit`` is ``NOT NULL DEFAULT 1``, so an omitted
        column would attribute the run to uid 1 rather than record that we did not know.
        """
        import powerpack_mcp.tools.sl1_db_tools as tools_module

        monkeypatch.setattr(tools_module, "actor_user_id", lambda: 42)
        context, db = _dispatch_context(drains=False)
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526)

        assert result["correlation_recorded"] is True
        insert = next(s for s in db.statements if s[0].startswith("INSERT INTO master_logs.device"))
        assert "user_edit" in insert[0]
        assert insert[1] == (77, 4, 4429, 20, 42)

    async def test_no_correlation_row_is_written_when_the_caller_is_unknown(self) -> None:
        """Writing uid 1 instead would attribute an MCP run to a real person.

        `actor_user_id()` is `None` outside an HTTP context, which is exactly this test, and is
        also `None` for any request that reaches the loopback port without traversing nginx.
        """
        context, db = _dispatch_context(drains=False)
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526)

        assert result["correlation_recorded"] is False
        assert not any(s[0].startswith("INSERT INTO master_logs.device") for s in db.statements)

    async def test_a_failed_correlation_row_does_not_fail_the_collection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The collection is already queued and cannot be recalled.

        Failing the whole call would report failure for work that is running, and throw away the
        `proc_id` the caller needs to read it. There is no transaction to make the pair atomic, so
        the partial state is reported rather than hidden.
        """
        import powerpack_mcp.tools.sl1_db_tools as tools_module

        monkeypatch.setattr(tools_module, "actor_user_id", lambda: 42)

        class AuditFailsDb(FakeDb):
            async def run_unit(self, *statements: Any) -> tuple[StatementResult, ...]:
                if statements[0].sql.startswith("INSERT INTO master_logs.device"):
                    self.units.append([s.sql for s in statements])
                    raise DbError("the database failed the request")
                return await super().run_unit(*statements)

        db = AuditFailsDb(
            fetch_results=[((4,),), _COLLECTION_ROWS, ((0, 0, 125, 20),)],
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=1, lastrowid=0),
                    StatementResult(rows=((4429,),), rowcount=1, lastrowid=0),
                )
            ],
        )
        context = make_context(db=db, sl1=FakeSl1(rest_results=[{"name": "edge-01"}]))
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526)

        assert "error" not in result
        assert result["proc_id"] == 4429
        assert result["correlation_recorded"] is False

    async def test_a_running_job_has_no_returncode_and_that_is_not_an_error(self) -> None:
        """``spool_process.returncode`` is ``NULL`` while the job runs.

        That is the most common state a caller polls in, so it must not produce a ``read_error`` or
        a note claiming the output read failed part-way. ``state`` is still readable and still
        reported.
        """
        context, _ = _dispatch_context(job=(0, None, 125, 20), drains=False)
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526)

        assert "read_error" not in result, result.get("read_error_detail")
        assert result["toolbox"] == {"state": 0, "returncode": None}
        assert "failed part-way" not in result["note"]

    async def test_a_missing_job_discriminator_still_fails_closed(self) -> None:
        """A ``NULL`` job discriminator is still reported, unlike a ``NULL`` returncode.

        ``process_id`` and ``toolbox_id`` are a security predicate, so they stay on
        `_platform_int`. A ``NULL`` there is corruption, not an answer, and must not read as
        "unknown and therefore fine".
        """
        context, _ = _dispatch_context(job=(0, 0, None, 20), drains=False)
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526)

        # Reported, not raised: the dispatch already committed, so the receipt must survive.
        assert result["read_error"] == "DbError"
        assert result["proc_id"] == 4429

    async def test_the_default_dispatches_and_returns_a_receipt_without_reading(self) -> None:
        """By default, dispatch returns immediately, having read nothing.

        Measured on a Central Database, dispatch-to-termination was 12-27 s and grew with queue
        depth, while the collection itself was 1-10 s of that, so waiting is nearly always futile.
        ``last_id=0`` is the honest resume point when nothing was read, and the note has to say so:
        a caller must not read ``terminated: false`` as a timeout.
        """
        context, _ = _dispatch_context(rows=_COLLECTION_ROWS[:2], drains=False)
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526)

        assert result["terminated"] is False
        assert result["last_id"] == 0
        assert result["lines"] == []
        assert "error" not in result
        # `error` and `read_error` are different keys; asserting only the former would let a
        # spurious DbError through.
        assert "read_error" not in result, result.get("read_error_detail")
        assert "sl1_fetch_collection_output" in result["note"]
        assert "STILL RUNNING" in result["note"]
        assert "MINUTES" in result["note"]

    async def test_an_unfinished_collection_returns_a_resume_handle_not_an_error(self) -> None:
        """A caller that waited and still did not see termination gets a resume handle.

        It gets partial lines plus the handle, never an error.
        """
        rows = _COLLECTION_ROWS[:2]  # no msg_type 3
        context, _ = _dispatch_context(rows=rows)
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526, wait_seconds=5.0)

        assert result["terminated"] is False
        assert result["last_id"] == 1951
        assert "error" not in result
        assert "sl1_fetch_collection_output" in result["note"]


class TestFetchCollectionOutput:
    """The read-only continuation of a dispatched collection."""

    async def test_it_resumes_after_a_row_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``id > %s``, so a resumed read never re-returns the row the caller already has.

        The actor and the owner row are not scaffolding. The ownership check sits between the
        scope gate and the read, so every fetch test stages an owner, and a test that forgets to is
        refused.
        """
        import powerpack_mcp.tools.sl1_db_tools as tools_module

        monkeypatch.setattr(tools_module, "actor_user_id", lambda: 42)
        db = FakeDb(fetch_results=[((0, 0, 125, 20),), ((42,),), _COLLECTION_ROWS[2:]])
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        result = await call(tool, proc_id=4429, after_id=1951)

        assert result["terminated"] is True
        assert result["last_id"] == 1953
        assert [line["stream"] for line in result["lines"]] == ["stderr", "completed"]
        page = next(s for s in db.statements if "proc_remote_logs" in s[0])
        assert page[1] == (4429, 1951)

    async def test_an_unknown_job_is_refused(self) -> None:
        """A `proc_id` with no spool row was never queued, or has since been pruned."""
        db = FakeDb(fetch_results=[()])
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        assert_refused(await call(tool, proc_id=99999), "no spool row 99999 exists")

    @pytest.mark.parametrize(("proc_id", "after_id"), [(0, 0), (-1, 0)])
    async def test_a_non_positive_job_id_is_refused(self, proc_id: int, after_id: int) -> None:
        db = FakeDb()
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        assert_refused(await call(tool, proc_id=proc_id, after_id=after_id), "positive job id")
        assert db.statements == []

    async def test_a_negative_resume_point_is_refused(self) -> None:
        db = FakeDb()
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        assert_refused(await call(tool, proc_id=4429, after_id=-1), "must not be negative")
        assert db.statements == []

    async def test_it_writes_nothing(self) -> None:
        """It is in `db_read`, so it must not reach the write path at all."""
        db = FakeDb(fetch_results=[((0, 0, 125, 20),), _COLLECTION_ROWS])
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        await call(tool, proc_id=4429)

        assert db.units == []

    async def test_it_refuses_without_a_database(self) -> None:
        """Fragment asserted for the same reason as the write tool's equivalent."""
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=None))
        assert_refused(await call(tool, proc_id=4429), "database")


class TestCollectionOutputDecoding:
    """`msg` is a ``BLOB``, so the decode path is where a whole page of output can be lost."""

    def test_undecodable_bytes_cost_one_character_not_the_page(self) -> None:
        """``errors="replace"``, because the trace is whatever the collected device emitted.

        A device that emits one invalid byte must not make the entire collection unreadable. A
        strict decode would, and would surface as an unhandled builtin escaping the tool boundary.
        """
        import powerpack_mcp.tools.sl1_db_tools as tools_module

        assert tools_module._decode_line(b"ok\xffbad\n") == "ok�bad"

    def test_a_str_or_other_value_is_passed_through(self) -> None:
        """Defensive: the stub types the column `object`, so neither branch is unreachable."""
        import powerpack_mcp.tools.sl1_db_tools as tools_module

        assert tools_module._decode_line("already text\r\n") == "already text"
        assert tools_module._decode_line(1950) == "1950"


class TestCollectionPollingLoop:
    async def test_it_polls_again_when_the_first_page_is_not_terminal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The 60-second tail, inside one request. Interval patched to keep the test instant.

        `THROTTLE_LINES` is 10 on the collector, and a 412-row run was measured arriving in a
        single batch, so a real second poll is uncommon. It is still the reason the loop exists,
        and an unexercised loop has never been shown to terminate.
        """
        import powerpack_mcp.tools.sl1_db_tools as tools_module

        monkeypatch.setattr(tools_module, "_POLL_INTERVAL_SECONDS", 0.0)
        db = FakeDb(
            fetch_results=[((4,),), _COLLECTION_ROWS[:2], _COLLECTION_ROWS[2:], ((0, 0, 125, 20),)],
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=1, lastrowid=0),
                    StatementResult(rows=((4429,),), rowcount=1, lastrowid=0),
                )
            ],
        )
        context = make_context(db=db, sl1=FakeSl1(rest_results=[{"name": "edge-01"}]))
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526, wait_seconds=5)

        assert result["terminated"] is True
        assert result["last_id"] == 1953
        assert len(result["lines"]) == 4, "both pages, in id order"
        pages = [s for s in db.statements if "proc_remote_logs" in s[0]]
        assert [s[1] for s in pages] == [(4429, 0), (4429, 1951)], (
            "second poll resumes, not re-reads"
        )

    async def test_a_dispatch_that_yields_no_job_id_is_a_database_error(self) -> None:
        """Not a refusal: the caller's arguments were fine, the platform did not do its part.

        Not seen in measured dispatches, but `LAST_INSERT_ID()` returning 0 would otherwise leave
        the tool polling a job that does not exist. Reported as `db_error` rather than raising a
        builtin, which would escape the boundary entirely.
        """
        db = FakeDb(
            fetch_results=[((4,),)],
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=1, lastrowid=0),
                    StatementResult(rows=((0,),), rowcount=1, lastrowid=0),
                )
            ],
        )
        context = make_context(db=db, sl1=FakeSl1(rest_results=[{"name": "edge-01"}]))
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526)

        assert result["error"]["type"] == "db_error", result["error"]


class TestActorUserId:
    """The identity source that decides whether a run is attributed at all."""

    @staticmethod
    def _with_scope(monkeypatch: pytest.MonkeyPatch, headers: list[tuple[bytes, bytes]]) -> None:
        """Stand in for an HTTP request, since the accessor reads a request-scoped contextvar."""

        class _Request:
            scope: ClassVar[dict[str, list[tuple[bytes, bytes]]]] = {"headers": headers}

        monkeypatch.setattr(
            "fastmcp.server.dependencies.get_http_request", lambda: _Request(), raising=True
        )

    def test_it_returns_the_numeric_id_nginx_forwarded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``X-User-ID`` is set by nginx from its own `auth_request`, so it cannot be forged.

        `powerpack-mcp.fragment` captures it with `auth_request_set` and forwards it with
        `proxy_set_header`, which overwrites anything the client sent.
        """
        self._with_scope(monkeypatch, [(b"x-user-id", b"42")])
        assert pipeline_actor_user_id() == 42

    def test_a_non_numeric_identity_is_rejected_rather_than_coerced(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The alternative is worse than `None`.

        `_current_actor` would hand back the username here, and `int("em7admin")` raises a bare
        `ValueError` that escapes the tool boundary. Returning `None` makes the caller skip the
        correlation row, which is the honest outcome.
        """
        self._with_scope(monkeypatch, [(b"x-user-id", b"em7admin")])
        assert pipeline_actor_user_id() is None

    def test_a_missing_header_is_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Reachable in normal operation: a request that never traversed nginx has no header."""
        self._with_scope(monkeypatch, [(b"x-request-id", b"abc")])
        assert pipeline_actor_user_id() is None

    def test_no_http_context_is_none_not_an_error(self) -> None:
        """`get_http_request()` raises outside a request, which is every unit test."""
        assert pipeline_actor_user_id() is None


class TestCollectionScopeGate:
    """The `tool_id 20` scope, enforced on the read path as well as the write path."""

    @pytest.mark.parametrize(
        ("process_id", "toolbox_id", "what"),
        [
            (125, 10, "an snmpwalk job -- the one that carries decrypted credentials"),
            (125, 3, "a ping job"),
            (7, 20, "a non-toolbox process that happens to carry Xtype 20"),
        ],
    )
    async def test_it_refuses_a_job_this_server_did_not_start(
        self, process_id: int, toolbox_id: int, what: str
    ) -> None:
        """Without this, iterating `proc_id` harvests other tools' output.

        `proc_remote_logs` is shared by every Remote Toolbox job, and `device_tools_run.inc` has 22
        `tool_id` branches. `tool_id 10` builds its command from `credential_crypt::decode` output,
        and a rejected payload is echoed verbatim into that table, so a reader gated only on
        ``proc_id > 0`` would hand plaintext SNMP community strings and v3 passwords to any
        authenticated caller. The write path pins ``Xtype = 20``; the read path re-derives it
        rather than trusting that.
        """
        db = FakeDb(fetch_results=[((0, 0, process_id, toolbox_id),), _COLLECTION_ROWS])
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        result = await call(tool, proc_id=4429)

        assert_refused(result, "not a dynamic application collection")
        assert not any("proc_remote_logs" in s[0] for s in db.statements), (
            f"{what}: no output may be read before the scope check passes"
        )

    async def test_the_refusal_is_not_an_enumeration_oracle(self) -> None:
        """It must not say what the job is, only that this tool does not read it."""
        db = FakeDb(fetch_results=[((0, 0, 125, 10),)])
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        result = await call(tool, proc_id=4429)
        rendered = str(result["error"]).lower()

        for leak in ("snmp", "tool_id 10", "toolbox 10", "ping", "nmap"):
            assert leak not in rendered, rendered


class TestPostDispatchFailuresKeepTheReceipt:
    """A queued collection cannot be recalled, so the caller must keep the handle to read it."""

    @staticmethod
    def _db_failing_on(fragment: str) -> FakeDb:
        class SelectiveFailure(FakeDb):
            async def fetch_all(self, statement: Any) -> tuple[tuple[Any, ...], ...]:
                if fragment in statement.sql:
                    self.statements.append((statement.sql, statement.params))
                    raise DbQueryTimeout(1.0)
                return await super().fetch_all(statement)

        return SelectiveFailure(
            fetch_results=[((4,),), _COLLECTION_ROWS, ((0, 0, 125, 20),)],
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=1, lastrowid=0),
                    StatementResult(rows=((4429,),), rowcount=1, lastrowid=0),
                )
            ],
        )

    async def test_a_failed_spool_read_does_not_discard_the_proc_id_or_the_lines(self) -> None:
        """The job row is metadata the tool's own docstring calls non-diagnostic.

        Losing the whole payload for it would be the worst trade: the collection is running, its
        output was already fetched, and the caller would get an error envelope with no way to reach
        either.
        """
        db = self._db_failing_on("spool_process")
        context = make_context(db=db, sl1=FakeSl1(rest_results=[{"name": "edge-01"}]))
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526, wait_seconds=5.0)

        assert "error" not in result, result
        assert result["proc_id"] == 4429
        assert len(result["lines"]) == 4
        assert result["toolbox"] is None
        assert result["read_error"] == "DbQueryTimeout"

    async def test_a_failed_output_read_still_returns_the_proc_id(self) -> None:
        """Contract at the top of the tool: an unfinished read returns a handle, not an error."""
        db = self._db_failing_on("proc_remote_logs")
        context = make_context(db=db, sl1=FakeSl1(rest_results=[{"name": "edge-01"}]))
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        result = await call(tool, device="77", app_id=526, wait_seconds=5.0)

        assert "error" not in result, result
        assert result["proc_id"] == 4429
        assert result["terminated"] is False
        assert result["read_error"] == "DbQueryTimeout"
        assert "may be incomplete" in result["note"]

    async def test_the_read_tool_raises_instead_because_it_started_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The asymmetry is deliberate: with no side effect, a read failure is the result."""
        import powerpack_mcp.tools.sl1_db_tools as tools_module

        monkeypatch.setattr(tools_module, "actor_user_id", lambda: 42)

        class OutputFails(FakeDb):
            async def fetch_all(self, statement: Any) -> tuple[tuple[Any, ...], ...]:
                if "proc_remote_logs" in statement.sql:
                    raise DbQueryTimeout(1.0)
                return await super().fetch_all(statement)

        db = OutputFails(fetch_results=[((0, 0, 125, 20),), ((42,),)])
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        result = await call(tool, proc_id=4429)

        assert result["error"]["type"] == "db_query_timeout", result["error"]


class TestPlatformValuesAreNotCallerErrors:
    """`_platform_int`: a bad value from the DB must not be reported as a bad argument."""

    async def test_an_empty_last_insert_id_row_is_a_db_error_audited_as_failed(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An empty ``LAST_INSERT_ID()`` row is a DB error, and the audit records "failed".

        `as_int(None)` would raise `ValidationBlocked`, telling the caller to fix a `proc_id`
        argument the tool does not accept, and making the audit record ``outcome="refused"`` for a
        `master.*` write that had already committed. "Refused" reads as nothing was attempted.
        """
        db = FakeDb(
            fetch_results=[((4,),)],
            unit_results=[
                (
                    StatementResult(rows=(), rowcount=1, lastrowid=0),
                    StatementResult(rows=(), rowcount=1, lastrowid=0),
                )
            ],
        )
        context = make_context(db=db, sl1=FakeSl1(rest_results=[{"name": "edge-01"}]))
        tool = reg._FACTORY_FOR["sl1_run_dynamic_collection"](context)

        with caplog.at_level(logging.INFO):
            result = await call(tool, device="77", app_id=526)

        assert result["error"]["type"] == "db_error", result["error"]
        assert db.units[0][0].startswith("CALL "), "the dispatch DID run"
        assert [r["outcome"] for r in _audit_records(caplog)] == ["failed"]

    async def test_a_null_msg_type_is_a_db_error_not_an_argument_refusal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same shape mid-drain: `path: "msg_type"` named an argument no caller supplies."""
        import powerpack_mcp.tools.sl1_db_tools as tools_module

        monkeypatch.setattr(tools_module, "actor_user_id", lambda: 42)
        db = FakeDb(fetch_results=[((0, 0, 125, 20),), ((42,),), ((1951, None, b"x"),)])
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        result = await call(tool, proc_id=4429)

        assert result["error"]["type"] == "db_error", result["error"]


class TestPollBudgetIsNotOverspent:
    async def test_the_sleep_is_bounded_by_the_remaining_budget(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unconditional `sleep(_POLL_INTERVAL_SECONDS)` overspends by a full interval.

        That eats into `_DEADLINE_MARGIN_SECONDS` and issues one more read after expiry, the
        spurious `DbQueryTimeout` the margin exists to prevent: `db_client` clamps every statement
        to the deadline remainder, and a 0.0 remainder becomes ``max_statement_time = 0.001``
        (errno 1969).

        Interval is 1.0 s and the budget here is 0.3 s, so an unbounded sleep takes >= 1.0 s.
        """
        import powerpack_mcp.tools.sl1_db_tools as tools_module

        monkeypatch.setattr(tools_module, "actor_user_id", lambda: 42)
        db = FakeDb(
            fetch_results=[
                ((0, 0, 125, 20),),
                ((42,),),
                _COLLECTION_ROWS[:2],
                _COLLECTION_ROWS[:2],
            ]
        )
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        started = time.monotonic()
        result = await call(tool, proc_id=4429, wait_seconds=0.3)
        elapsed = time.monotonic() - started

        assert result["terminated"] is False
        assert elapsed < 1.0, f"slept past the budget: {elapsed:.3f}s"


class TestCollectionOwnership:
    """Object-level ownership: a caller may read only collections they started.

    This complements the scope gate; neither is redundant. `_is_collection_job` answers "is this
    one of our collections"; this answers "is it yours". A caller holding `DEV_TOOLS_RUN` passes
    the hook check and the scope gate, and without this could read every other account's
    collection output by iterating `proc_id`.
    """

    _JOB: ClassVar[tuple[tuple[int, ...], ...]] = ((0, 0, 125, 20),)

    async def test_a_job_owned_by_another_account_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`em7admin` (uid 1) started it, uid 42 asks for it."""
        import powerpack_mcp.tools.sl1_db_tools as tools_module

        monkeypatch.setattr(tools_module, "actor_user_id", lambda: 42)
        db = FakeDb(fetch_results=[self._JOB, ((1,),), _COLLECTION_ROWS[:1]])
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        result = await call(tool, proc_id=4439)

        assert result["error"]["type"] == "authorization_denied", result["error"]
        assert result["error"]["proc_id"] == 4439
        # The real owner is never named. Doing so would disclose who runs collections to someone
        # not entitled to know.
        assert "1" not in str(result["error"].get("owner", ""))
        assert "owner" not in result["error"]
        # And the output query never ran.
        assert not any("proc_remote_logs" in s[0] for s in db.statements)

    async def test_a_job_with_no_ownership_row_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No row means no access, including for whoever started it.

        `_record_correlation` skips the row when the actor is unknown rather than defaulting
        ``user_edit``, so an unattributable job is unreadable by anyone. That only arises for a
        request that bypassed nginx.
        """
        import powerpack_mcp.tools.sl1_db_tools as tools_module

        monkeypatch.setattr(tools_module, "actor_user_id", lambda: 42)
        db = FakeDb(fetch_results=[self._JOB, (), _COLLECTION_ROWS[:1]])
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        result = await call(tool, proc_id=4439)

        assert result["error"]["type"] == "authorization_denied", result["error"]
        assert not any("proc_remote_logs" in s[0] for s in db.statements)

    async def test_an_unresolvable_caller_is_refused_without_a_query(self) -> None:
        """No actor means no ownership question to ask, so it refuses before touching the DB.

        Reject before spending: the absence of the ownership query is the assertion.
        """
        db = FakeDb(fetch_results=[self._JOB, ((42,),), _COLLECTION_ROWS[:1]])
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        result = await call(tool, proc_id=4439)

        assert result["error"]["type"] == "authorization_denied", result["error"]
        assert not any("device_tools" in s[0] for s in db.statements)

    async def test_the_owner_may_read_their_own_job(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The allow path, so the refusals above are not passing because everything refuses."""
        import powerpack_mcp.tools.sl1_db_tools as tools_module

        monkeypatch.setattr(tools_module, "actor_user_id", lambda: 42)
        db = FakeDb(fetch_results=[self._JOB, ((42,),), _COLLECTION_ROWS[:1]])
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        result = await call(tool, proc_id=4439)

        assert "error" not in result, result
        owner_query = next(s for s in db.statements if "device_tools" in s[0])
        assert owner_query[1] == (4439,)

    async def test_the_ownership_query_runs_after_the_scope_gate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Reject on the cheaper, broader test before spending a second query.

        A job that fails the scope gate must cost no ownership query at all.
        """
        import powerpack_mcp.tools.sl1_db_tools as tools_module

        monkeypatch.setattr(tools_module, "actor_user_id", lambda: 42)
        # `proc 999` is not the Remote Toolbox process, so `_is_collection_job` refuses first.
        # Toolbox id is the correct 20 on purpose: the wrong `proc` must be the only defect,
        # or this test would pass for two reasons and stop testing the process-id gate.
        db = FakeDb(fetch_results=[((0, 0, 999, 20),), ((42,),)])
        tool = reg._FACTORY_FOR["sl1_fetch_collection_output"](make_context(db=db))

        result = await call(tool, proc_id=4439)

        assert result["error"]["type"] == "validation_blocked", result["error"]
        assert not any("device_tools" in s[0] for s in db.statements)
