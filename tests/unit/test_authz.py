"""
Tool Registry Tests

This module tests ``powerpack_mcp.authz``: the inventory counts, deny-by-default lookup, the
refusal error and its log record, the hook mappings, and the import-time checks that keep the
registry consistent.
"""

from __future__ import annotations

import inspect
from types import ModuleType
from typing import Final

import pytest

from powerpack_mcp import authz, validation
from powerpack_mcp import authz as authz_module
from powerpack_mcp.authz import (
    _ENTRIES,
    DB_READ_SET,
    DB_TOOL_COUNT,
    REGISTERED_TOOL_COUNT,
    SQL_TOOL_COUNT,
    TOOL_REGISTRY,
    WRITE_TOOL_COUNT,
    DbToolNotRegistered,
    ToolTransport,
    _entry,
    registry_entry,
    sql_tool_names,
    write_tool_names,
)
from powerpack_mcp.errors import ERROR_TYPE_INTERNAL, LogEvent, build_error_payload
from powerpack_mcp.tools import pipeline


class TestInventoryCounts:
    """The registry's counts are derived from its entries; these pin the expected values."""

    def test_the_inventory_holds_every_tool(self) -> None:
        assert DB_TOOL_COUNT == 24
        assert len(TOOL_REGISTRY) == 24

    def test_only_eight_tools_touch_sql(self) -> None:
        """Pinned because the SQL count decides which tools the DB prerequisite can disable."""
        assert SQL_TOOL_COUNT == 8
        assert len(sql_tool_names()) == 8

    def test_clear_event_is_rest_and_the_ssh_tool_is_absent(self) -> None:
        # sl1_clear_event uses SL1's supported REST endpoint rather than a SQL write.
        assert TOOL_REGISTRY["sl1_clear_event"].transport is ToolTransport.REST
        # sl1_run_dynamic_app_single ran an operator-controlled shell command over SSH. It is left
        # out of the registry entirely, rather than withheld, so configuration cannot re-enable it.
        assert "sl1_run_dynamic_app_single" not in TOOL_REGISTRY

    def test_twelve_tools_write(self) -> None:
        assert WRITE_TOOL_COUNT == 12
        assert len(write_tool_names()) == 12

    def test_exactly_two_tools_are_withheld_so_twenty_two_register(self) -> None:
        """The full server surface is asserted by building a server in
        ``test_registration_surface.py``; this pins the registry's share of it.
        """
        withheld = [e for e in TOOL_REGISTRY.values() if not e.registers]
        assert sorted(e.name for e in withheld) == [
            "list_capabilities",
            "refresh_capability_map",
        ]
        assert REGISTERED_TOOL_COUNT == 22
        assert REGISTERED_TOOL_COUNT == DB_TOOL_COUNT - 2

    def test_every_transport_is_an_explicit_enum_member(self) -> None:
        # Transport must be data the code can check, not a description in a comment.
        for entry in TOOL_REGISTRY.values():
            assert isinstance(entry.transport, ToolTransport)

    def test_the_transport_split_covers_the_whole_inventory(self) -> None:
        counts = {
            t: sum(1 for e in TOOL_REGISTRY.values() if e.transport is t) for t in ToolTransport
        }
        assert sum(counts.values()) == DB_TOOL_COUNT
        assert counts[ToolTransport.SQL] == 8
        # list_capabilities only introspects the local server and never leaves the process.
        assert counts[ToolTransport.LOCAL] == 1
        # The three tools that probe several transports in one call. Easy to mislabel as GRAPHQL.
        assert counts[ToolTransport.MULTI] == 3


class TestDenyByDefault:
    """No wildcard, no fallback, no "allow if unmapped"."""

    def test_an_unknown_tool_name_is_refused(self) -> None:
        with pytest.raises(DbToolNotRegistered):
            registry_entry("sl1_definitely_not_a_tool")

    def test_a_withheld_tool_is_refused_even_though_it_is_in_the_inventory(self) -> None:
        # Being in the inventory is not permission to run.
        assert "list_capabilities" in TOOL_REGISTRY
        with pytest.raises(DbToolNotRegistered):
            registry_entry("list_capabilities")

    @pytest.mark.parametrize(
        "candidate", ["", "*", "sl1_*", "SL1_SIMULATE_EVENT", " sl1_clear_event"]
    )
    def test_there_is_no_wildcard_and_no_normalisation_shortcut(self, candidate: str) -> None:
        # An uppercase or space-padded near-miss must NOT be helpfully resolved: a lenient match is
        # how an "allow if unmapped" branch reappears without anyone writing one.
        with pytest.raises(DbToolNotRegistered):
            registry_entry(candidate)

    def test_a_registered_tool_returns_its_entry(self) -> None:
        entry = registry_entry("sl1_simulate_event")
        assert entry.name == "sl1_simulate_event"
        assert entry.transport is ToolTransport.SQL
        assert entry.writes is True


class TestRefusalError:
    """The refusal is a distinct exception type in code, but generic to the caller."""

    def test_the_exception_carries_the_tool_name(self) -> None:
        with pytest.raises(DbToolNotRegistered) as exc:
            registry_entry("mystery")
        assert exc.value.tool_name == "mystery"

    def test_it_surfaces_to_a_caller_as_internal_error_because_it_is_our_defect(self) -> None:
        """Tools register from this registry, so reaching this means a service defect."""
        payload = build_error_payload(DbToolNotRegistered("mystery"))
        assert payload["error"]["type"] == ERROR_TYPE_INTERNAL

    def test_the_caller_facing_payload_does_not_leak_the_tool_name_or_a_class_name(self) -> None:
        payload = build_error_payload(DbToolNotRegistered("mystery"))
        assert "mystery" not in repr(payload)
        assert "DbToolNotRegistered" not in repr(payload)


class TestRefusalLogging:
    """A refusal logs an ``event``-keyed record with the tool name and no hook field."""

    def test_a_refusal_emits_an_event_keyed_record_with_the_tool_name(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"), pytest.raises(DbToolNotRegistered):
            registry_entry("mystery")
        (record,) = [r for r in caplog.records if r.__dict__.get("event")]
        assert record.__dict__["event"] == str(LogEvent.VALIDATION_BLOCKED)
        assert record.__dict__["tool_name"] == "mystery"

    def test_the_record_distinguishes_withheld_from_unknown(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Operationally different causes: "someone withheld this deliberately" vs "this name is
        # wrong". Collapsing them would send an operator hunting for a typo that does not exist.
        with caplog.at_level("WARNING"), pytest.raises(DbToolNotRegistered):
            registry_entry("list_capabilities")
        with caplog.at_level("WARNING"), pytest.raises(DbToolNotRegistered):
            registry_entry("mystery")
        flags = [r.__dict__["withheld"] for r in caplog.records if r.__dict__.get("event")]
        assert flags == [True, False]

    def test_no_record_carries_a_required_hook_field(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The lookup itself checks no hooks, so its record must not suggest that it did."""
        with caplog.at_level("WARNING"), pytest.raises(DbToolNotRegistered):
            registry_entry("mystery")
        for record in caplog.records:
            assert "required_hook" not in record.__dict__
            assert "hook" not in record.__dict__


class TestTheModuleNowAuthorizes:
    """The registry carries the hook mapping that the authorization gate enforces."""

    def test_the_module_now_carries_a_hook_concept(self) -> None:
        """The per-tool hook mapping lives in this module."""
        assert any("hook" in name.lower() for name in vars(authz))
        assert registry_entry("sl1_create_device_class").required_hooks

    def test_the_registry_entry_has_exactly_one_privilege_field(self) -> None:
        """Any new field has to be added here deliberately.

        ``role``, ``permission`` and ``grant`` would each be a second, differently named privilege
        concept alongside ``required_hooks``.
        """
        entry = registry_entry("sl1_create_device_class")
        fields = set(entry.__dataclass_fields__)
        assert fields == {"name", "transport", "writes", "tool_set", "registers", "required_hooks"}
        assert sum("hook" in field for field in fields) == 1, "exactly one hook field, not two"
        for forbidden in ("privilege", "role", "permission", "grant"):
            assert not any(forbidden in field for field in fields), forbidden


class TestGatingInputs:
    """Which tools the DB prerequisite and the write flag apply to."""

    def test_only_sql_tools_are_eligible_for_the_db_prerequisite_gate(self) -> None:
        # Gating the non-SQL tools on the DB prerequisite would disable GraphQL tools that need no
        # driver, no libem7 and no silo.conf.
        for name in sql_tool_names():
            assert TOOL_REGISTRY[name].transport is ToolTransport.SQL
        non_sql = {e.name for e in TOOL_REGISTRY.values() if e.transport is not ToolTransport.SQL}
        assert not (sql_tool_names() & non_sql)
        assert len(non_sql) == 16

    def test_write_names_are_exactly_the_entries_flagged_as_writes(self) -> None:
        assert write_tool_names() == {e.name for e in TOOL_REGISTRY.values() if e.writes}

    def test_five_of_the_eight_sql_tools_write(self) -> None:
        """``sl1_simulate_event``, ``sl1_create_device_class``, ``sl1_update_device_class``,
        ``sl1_align_dynamic_app_to_device_class`` and ``sl1_run_dynamic_collection``.
        """
        sql_writes = [
            e for e in TOOL_REGISTRY.values() if e.transport is ToolTransport.SQL and e.writes
        ]
        assert len(sql_writes) == 5

    def test_the_withheld_tool_is_not_a_write_so_nothing_depends_on_gating_it(self) -> None:
        assert TOOL_REGISTRY["list_capabilities"].writes is False


# The pipeline steps that parse or validate a caller payload, named at the module attribute the
# code resolves at call time so a test can intercept them: the body-size check (serialises the
# payload), the depth check (walks it) and ``validate_payload`` (the most expensive check). The
# filter-presence check and query-string building are left out because neither parses a payload.
#
# Both binding sites of each shared function are listed. ``pipeline`` imports ``exceeds_depth``
# and ``validate_payload`` from ``validation`` at load time, so it holds its own references, and
# patching only one module would miss calls made through the other.
_PIPELINE_EXPENSE: Final[tuple[tuple[ModuleType, str], ...]] = (
    (pipeline, "_body_size_finding"),
    (pipeline, "_depth_finding"),
    (pipeline, "validate_payload"),
    (pipeline, "exceeds_depth"),
    (validation, "validate_payload"),
    (validation, "exceeds_depth"),
)


def _watch_pipeline_expense(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace every pipeline expense with a spy, and return the list it records calls into.

    The spy records the call and then raises. Recording catches a caller that swallows the error;
    raising makes a caller that ignores it fail at the offending call. ``monkeypatch.setattr``
    raises on a missing attribute, so a renamed function fails here instead of going unwatched.

    :param monkeypatch: The pytest fixture used to install the spies.
    :return: The list of spied functions that were called.
    """
    called: list[str] = []

    for module, attr in _PIPELINE_EXPENSE:
        label = f"{module.__name__}.{attr}"

        def spy(*_args: object, _label: str = label, **_kwargs: object) -> object:
            called.append(_label)
            raise AssertionError(f"the gate spent {_label} before refusing")

        monkeypatch.setattr(module, attr, spy)

    return called


class TestGuardBeforeExpense:
    """The registry lookup refuses a tool without doing any parse or validation work.

    No production path runs the lookup and the pipeline in sequence, so these tests do not compose
    the two. They assert the stronger property of the shipped code: reaching a refusal (or an
    accept) spends none of the pipeline's expense. Adding any parse or validation call ahead of the
    ``raise`` in ``registry_entry`` makes them fail.
    """

    def test_the_watched_names_are_the_ones_the_pipeline_actually_calls(self) -> None:
        """Without this check, every ``called == []`` below could pass vacuously.

        ``run_operation`` reads its guards from module globals, so its code object names them. If a
        guard is renamed, inlined or moved, this fails instead of the spies watching functions
        nothing calls.
        """
        names = set(pipeline.run_operation.__code__.co_names)
        assert {"_body_size_finding", "_depth_finding", "validate_payload"} <= names
        # Step 2b's traversal is reached *through* `_depth_finding`, not from `run_operation`.
        assert "exceeds_depth" in pipeline._depth_finding.__code__.co_names
        # The two binding sites are still the same object, so patching both is sufficient as well as
        # necessary. If the pipeline ever wraps or re-exports one, this fails and says so.
        assert pipeline.validate_payload is validation.validate_payload
        assert pipeline.exceeds_depth is validation.exceeds_depth

    @pytest.mark.parametrize(
        ("tool_name", "why"),
        [
            ("sl1_definitely_not_a_tool", "unknown name"),
            ("list_capabilities", "withheld name that IS in the inventory"),
            ("refresh_capability_map", "withheld name"),
            ("SL1_SIMULATE_EVENT", "case-only near-miss of a real name"),
            ("", "empty name"),
        ],
    )
    def test_a_refused_call_spends_no_parse_or_validation_cost(
        self, monkeypatch: pytest.MonkeyPatch, tool_name: str, why: str
    ) -> None:
        """Every kind of refusal, not just an unknown name.

        Withheld names matter most: they are present in the registry, so a lookup that did work
        before checking ``registers`` would still refuse while spending the expense.
        """
        called = _watch_pipeline_expense(monkeypatch)
        with pytest.raises(DbToolNotRegistered):
            registry_entry(tool_name)
        assert called == [], f"expense spent for an {why}: {called}"

    def test_the_accept_path_spends_none_of_it_either(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The lookup is a dictionary lookup whichever way it decides."""
        called = _watch_pipeline_expense(monkeypatch)
        assert registry_entry("sl1_simulate_event").name == "sl1_simulate_event"
        assert called == []

    def test_a_refusal_is_still_logged_without_spending_the_expense(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Skipping the expense must not mean skipping the refusal's log record."""
        called = _watch_pipeline_expense(monkeypatch)
        with caplog.at_level("WARNING"), pytest.raises(DbToolNotRegistered):
            registry_entry("mystery")
        assert called == []
        (record,) = [r for r in caplog.records if r.__dict__.get("event")]
        assert record.__dict__["tool_name"] == "mystery"

    def test_the_gate_is_handed_nothing_it_could_parse(self) -> None:
        """``registry_entry`` takes only a name, so it has no caller payload it could parse.

        Adding a payload, request or context parameter is the ordinary-looking change that could
        break the tests above, so it should be reconsidered here first.
        """
        parameters = inspect.signature(registry_entry).parameters
        assert list(parameters) == ["tool_name"]
        # A string, because authz uses ``from __future__ import annotations``.
        assert parameters["tool_name"].annotation == "str"


class TestRequiredHooksTotality:
    """Every SQL tool has a hook mapping and no other tool does, enforced at import.

    Each negative test builds a registry that breaks one rule and asserts the import-time check
    fires, so the check is known to work.
    """

    def test_every_sql_tool_carries_a_non_empty_mapping(self) -> None:
        """Checked over the real registry, deriving the SQL tools rather than listing them."""
        for name in sql_tool_names():
            entry = registry_entry(name)
            assert entry.required_hooks, f"{name} is a SQL tool with no required_hooks"

    def test_no_non_sql_tool_carries_a_mapping(self) -> None:
        """Hooks on a non-SQL tool would imply a check that nothing enforces."""
        offenders = [
            e.name
            for e in TOOL_REGISTRY.values()
            if e.required_hooks and e.transport is not ToolTransport.SQL
        ]
        assert not offenders, offenders

    def test_the_mapping_keys_on_hook_id_shape_not_on_the_name_column(self) -> None:
        """Hook values must be ``hook_id`` keys (``EVT_CLEAR``), not names (``Event:Clear``).

        ``hook_id`` is uppercase snake case with no colon, so a value copied from the display
        column is detectable by shape.
        """
        for name in sql_tool_names():
            for hook in registry_entry(name).required_hooks:
                assert ":" not in hook, f"{name}: {hook!r} looks like a `name`, not a `hook_id`"
                assert hook == hook.upper(), f"{name}: {hook!r} is not upper-case"
                assert hook.replace("_", "").isalnum(), f"{name}: {hook!r} is not a hook_id shape"

    def test_an_unmapped_sql_tool_fails_at_import(self, monkeypatch: pytest.MonkeyPatch) -> None:
        entries = (*_ENTRIES, _entry("ninth_sql_tool", ToolTransport.SQL, tool_set=DB_READ_SET))
        monkeypatch.setattr(authz_module, "_ENTRIES", entries)
        with pytest.raises(AssertionError, match="Every SQL tool must carry"):
            authz_module._check_set_assignment()

    def test_a_non_sql_tool_with_hooks_fails_at_import(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        entries = (
            *_ENTRIES,
            _entry("resty", ToolTransport.REST, required_hooks=frozenset({"DEV_VIEW"})),
        )
        monkeypatch.setattr(authz_module, "_ENTRIES", entries)
        with pytest.raises(AssertionError, match="Every SQL tool must carry"):
            authz_module._check_set_assignment()

    @pytest.mark.parametrize("bad", ["", " DEV_VIEW", "DEV_VIEW "])
    def test_a_blank_or_padded_hook_id_fails_at_import(
        self, bad: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A lenient value is how an "allow if unmapped" branch reappears unnoticed."""
        entries = tuple(
            _entry(
                e.name,
                e.transport,
                writes=e.writes,
                tool_set=e.tool_set,
                registers=e.registers,
                required_hooks=(
                    frozenset({bad}) if e.name == "sl1_get_component_tree" else e.required_hooks
                ),
            )
            for e in _ENTRIES
        )
        monkeypatch.setattr(authz_module, "_ENTRIES", entries)
        with pytest.raises(AssertionError, match="blank or space-padded"):
            authz_module._check_set_assignment()

    def test_the_shipped_registry_passes_its_own_check(self) -> None:
        """The negative tests above must not pass merely because the check rejects everything."""
        authz_module._check_set_assignment()
