"""
SL1 Database Statement Tests

This module tests the SQL builders in ``powerpack_mcp.tools.sl1_db_statements`` by asserting on
the rendered ``statement.sql`` and ``statement.params``.

A literal ``%`` in the SQL makes the driver return empty rows rather than raise, so a mocked test
or an exception-based test would pass while the tool silently reports nothing found. No test here
is of the form "it did not raise". Statement construction is pure, so every builder is testable
with no appliance and no database.
"""

from __future__ import annotations

import re
import shlex

import pytest

from powerpack_mcp.sql import Statement
from powerpack_mcp.tools import sl1_db_statements as st

# Any `%` that is not the start of a `%s` placeholder. Mirrors `sql._BAD_PERCENT`, deliberately
# re-derived: if the production regex were wrong, importing it would make every test agree with
# the bug. A silent empty result is costly enough to justify one duplicated regex.
_BAD_PERCENT = re.compile(r"%(?!s\b)")

ALL_BUILDERS = (
    lambda: st.insert_active_event(
        device_id=7,
        device_name="edge-01",
        source=6,
        message="disk usage high",
        sub_message="",
        threshold="",
        severity=3,
        event_policy=0,
    ),
    lambda: st.resolve_root_did_by_name("vcenter-1"),
    lambda: st.read_root_summary(42),
    lambda: st.read_component_map(42),
    lambda: st.resolve_powerpack_guid_by_name("Cisco: Base Pack"),
    lambda: st.insert_device_class(
        class_guid="A" * 32,
        family_guid="B" * 32,
        class_name="Acme Widget",
        description="Widget",
        category="Servers",
        device_type="component",
        is_snmp=False,
        root_device=False,
        powerpack_guid=None,
        class_identifier_1="",
        class_identifier_2="",
    ),
    lambda: st.read_device_class_by_guid("A" * 32),
    lambda: st.update_device_class(
        class_guid="A" * 32,
        changes={"class_name": "New"},
        category_fid=None,
        clear_powerpack=False,
        powerpack_guid=None,
    ),
    lambda: st.resolve_class_type_by_guid("A" * 32),
    lambda: st.align_dynamic_app(class_type=5, dynamic_app_id=11, name=None),
    lambda: st.read_dynamic_app_alignment(dynamic_app_id=11, name=None),
    lambda: st.read_class_alignment(5),
    lambda: st.read_aligned_dynamic_apps(5),
    # The collection route. Realistic ids: device 209 on collector 4, Dynamic Application 526,
    # spool row 4429, actor uid 1, as measured against a test appliance.
    lambda: st.resolve_device_collector(device_id=209),
    lambda: st.dispatch_dynamic_collection(device_id=209, dynamic_app_id=526, module_id=4),
    st.last_insert_id,
    lambda: st.record_device_tool_run(device_id=209, module_id=4, proc_id=4429, user_id=1),
    lambda: st.read_collection_output(proc_id=4429, after_id=0),
    lambda: st.read_collection_job(proc_id=4429),
)


class TestNoLiteralPercentAnywhere:
    """A literal ``%`` returns empty rows with no exception, so this asserts on rendered text."""

    @pytest.mark.parametrize("build", ALL_BUILDERS)
    def test_no_builder_renders_a_literal_percent(self, build: object) -> None:
        statement = build()  # type: ignore[operator]
        assert _BAD_PERCENT.search(statement.sql) is None, statement.sql

    @pytest.mark.parametrize("build", ALL_BUILDERS)
    def test_placeholder_count_equals_parameter_count(self, build: object) -> None:
        statement = build()  # type: ignore[operator]
        assert statement.placeholder_count == len(statement.params)

    def test_a_percent_in_a_caller_value_stays_in_the_parameter(self) -> None:
        """A `%` in free-text caller input lands in ``params``, never in ``sql``.

        ``message`` is arbitrary text, so a caller will eventually send one. Both halves are
        asserted, because checking only ``params`` would pass even if it were also interpolated.
        """
        statement = st.insert_active_event(
            device_id=1,
            device_name="d",
            source=6,
            message="disk at 95% capacity",
            sub_message="100%",
            threshold="%",
            severity=4,
            event_policy=0,
        )
        assert "95%" not in statement.sql
        assert "disk at 95% capacity" in statement.params
        assert "100%" in statement.params
        assert "%" in statement.params
        assert _BAD_PERCENT.search(statement.sql) is None

    def test_a_quote_in_a_caller_value_stays_a_parameter(self) -> None:
        """Quotes are made safe by not interpolating at all, rather than by escaping."""
        statement = st.insert_active_event(
            device_id=1,
            device_name="O'Brien's box",
            source=6,
            message="it's broken",
            sub_message="",
            threshold="",
            severity=2,
            event_policy=0,
        )
        assert "O'Brien" not in statement.sql
        assert "O'Brien's box" in statement.params


class TestInsertActiveEvent:
    """35 columns, 35 values, 8 of them parameters -- ``events.py::sl1_simulate_event``."""

    def test_the_column_and_value_lists_are_the_same_length(self) -> None:
        """If the lists drifted, a message would be written into a date column.

        MariaDB's error would name neither field, so the two lists are counted here.
        """
        columns = [c.strip() for c in st._EVENT_COLUMNS.split(",")]
        values = _split_top_level(st._EVENT_VALUES)
        assert len(columns) == 35
        assert len(values) == 35

    def test_it_targets_events_active_and_inserts_exactly_once(self) -> None:
        statement = _event()
        assert statement.sql.startswith("INSERT INTO master_events.events_active (")
        assert statement.sql.count("INSERT") == 1

    def test_the_eight_parameters_are_in_column_order(self) -> None:
        # Order matters and is invisible at runtime: a swapped severity and source would insert a
        # valid row with the wrong meaning, which no error would report.
        statement = st.insert_active_event(
            device_id=7,
            device_name="edge-01",
            source=6,
            message="msg",
            sub_message="sub",
            threshold="thr",
            severity=3,
            event_policy=99,
        )
        assert statement.params == (7, "edge-01", 6, "msg", "sub", "thr", 3, 99)

    def test_now_and_the_zero_date_stay_in_the_statement(self) -> None:
        """``NOW()`` must be the *server's* clock, so it cannot become a bound parameter."""
        statement = _event()
        assert statement.sql.count("NOW()") == 4
        assert statement.sql.count("'0000-00-00 00:00:00'") == 2

    def test_it_does_not_carry_a_second_last_insert_id_statement(self) -> None:
        """``lastrowid`` supplies the id, so the unit needs no second statement.

        In a sequence that cannot be rolled back, fewer statements is a smaller blast radius
        rather than a tidier script.
        """
        statement = _event()
        assert "LAST_INSERT_ID" not in statement.sql.upper()
        assert ";" not in statement.sql


class TestInsertDeviceClassFragments:
    """A placeholder cannot stand where a fragment goes."""

    def test_a_numeric_category_compares_on_fid_and_binds_an_int(self) -> None:
        statement = _create(category="42")
        assert "dc.Fid = %s" in statement.sql
        assert "dc.cat_name" not in statement.sql
        assert 42 in statement.params

    def test_a_named_category_compares_on_cat_name_and_binds_the_name(self) -> None:
        statement = _create(category="Servers")
        assert "dc.cat_name = %s" in statement.sql
        assert "dc.Fid = %s" not in statement.sql
        assert "Servers" in statement.params

    def test_a_digit_like_but_non_decimal_category_takes_the_name_branch(self) -> None:
        """A value like ``"²"`` takes the ``cat_name`` branch and is bound.

        ``"²".isdigit()`` is ``True`` but ``int("²")`` raises ``ValueError``. Selecting the
        ``dc.Fid`` branch would crash on a builtin exception that `sl1_tool_boundary` does not
        translate. Binding it as a name is correct: an unmatched category name selects no row, and
        `INSERT … SELECT … LIMIT 1` inserts nothing. No exception, no partial write.
        """
        for category in ("²", "³", "1²"):
            statement = _create(category=category)
            assert "dc.cat_name = %s" in statement.sql, category
            assert "dc.Fid = %s" not in statement.sql, category
            assert category in statement.params, category
            assert statement.placeholder_count == len(statement.params), category

    def test_an_unowned_class_renders_a_literal_null_and_binds_nothing_for_it(self) -> None:
        with_pp = _create(powerpack_guid="C" * 32)
        without = _create(powerpack_guid=None)
        # The fragment differs, and the parameter count differs by exactly one.
        assert "NULL, %s, %s," in without.sql
        assert ("C" * 32) in with_pp.params
        assert with_pp.placeholder_count == without.placeholder_count + 1

    def test_the_insert_select_shape_is_preserved(self) -> None:
        """The ``INSERT ... SELECT`` shape is load-bearing, because of a race.

        ``INSERT ... SELECT FROM definitions_dev_cats`` guarantees ``family`` is a real Fid, or
        nothing is inserted. Resolving the category in Python first would open a
        time-of-check-to-time-of-use gap with no transaction to close it.
        """
        statement = _create()
        assert "INSERT INTO master.definitions_dev_classes" in statement.sql
        assert "SELECT" in statement.sql
        assert "FROM master.definitions_dev_cats dc WHERE" in statement.sql
        assert "LIMIT 1" in statement.sql

    def test_the_column_count_matches_the_source(self) -> None:
        statement = _create()
        columns = statement.sql.split("(", 1)[1].split(")", 1)[0]
        assert len(columns.split(",")) == 20

    def test_an_unknown_device_type_is_refused(self) -> None:
        with pytest.raises(ValueError, match="device_type must be one of"):
            _create(device_type="quantum")

    @pytest.mark.parametrize(
        ("name", "expected"), [("physical", 0), ("virtual", 1), ("component", 2)]
    )
    def test_the_type_map_matches_the_source(self, name: str, expected: int) -> None:
        assert st.DEVICE_CLASS_TYPES[name] == expected


class TestUpdateDeviceClass:
    """The ``SET`` clause's column names come from a closed allowlist."""

    def test_only_the_supplied_fields_appear(self) -> None:
        statement = st.update_device_class(
            class_guid="A" * 32,
            changes={"class_name": "N"},
            category_fid=None,
            clear_powerpack=False,
            powerpack_guid=None,
        )
        assert "class = %s" in statement.sql
        assert "descript" not in statement.sql
        assert "is_snmp" not in statement.sql
        assert statement.params == ("N", "A" * 32)

    def test_the_guid_is_always_the_last_parameter(self) -> None:
        # The WHERE clause is appended after the SET list, so its parameter must be too. Getting
        # this wrong would update the wrong row -- and silently, since the statement is valid.
        statement = st.update_device_class(
            class_guid="Z" * 32,
            changes={"class_name": "N", "description": "D", "is_snmp": 1},
            category_fid=9,
            clear_powerpack=False,
            powerpack_guid="C" * 32,
        )
        assert statement.params[-1] == "Z" * 32
        assert statement.sql.rstrip().endswith("WHERE devtype_guid = %s")

    def test_class_identifier_2_maps_to_identifyer_3(self) -> None:
        """SL1's asymmetry, preserved. ``identifyer_2`` would be the wrong column."""
        statement = st.update_device_class(
            class_guid="A" * 32,
            changes={"class_identifier_2": "x"},
            category_fid=None,
            clear_powerpack=False,
            powerpack_guid=None,
        )
        assert "identifyer_3 = %s" in statement.sql
        assert "identifyer_2" not in statement.sql

    def test_a_column_outside_the_allowlist_is_refused(self) -> None:
        # Without the allowlist this would be interpolated column text.
        with pytest.raises(ValueError, match="not an updatable device-class field"):
            st.update_device_class(
                class_guid="A" * 32,
                changes={"class = 'x' --": "y"},
                category_fid=None,
                clear_powerpack=False,
                powerpack_guid=None,
            )

    def test_the_category_coalesce_is_preserved(self) -> None:
        """Kept, where the align COALESCE was removed: same SQL, opposite intent.

        This one is a safety property: a bad category name is a COALESCE no-op and never nulls the
        category. Turning it into an error would remove a guard. The align case's COALESCE hid a
        bug. Both are written down so neither is inferred from the other.
        """
        statement = st.update_device_class(
            class_guid="A" * 32,
            changes={},
            category_fid=7,
            clear_powerpack=False,
            powerpack_guid=None,
        )
        assert "family = COALESCE(%s, family)" in statement.sql

    def test_clearing_the_powerpack_renders_a_literal_null(self) -> None:
        statement = st.update_device_class(
            class_guid="A" * 32,
            changes={},
            category_fid=None,
            clear_powerpack=True,
            powerpack_guid=None,
        )
        assert "ppguid = NULL" in statement.sql
        assert statement.params == ("A" * 32,)

    def test_an_empty_update_is_refused(self) -> None:
        # An update with nothing to set cannot be built at all.
        with pytest.raises(ValueError, match="at least one change"):
            st.update_device_class(
                class_guid="A" * 32,
                changes={},
                category_fid=None,
                clear_powerpack=False,
                powerpack_guid=None,
            )

    def test_date_edit_is_always_set(self) -> None:
        statement = st.update_device_class(
            class_guid="A" * 32,
            changes={"class_name": "N"},
            category_fid=None,
            clear_powerpack=False,
            powerpack_guid=None,
        )
        assert "date_edit = NOW()" in statement.sql


class TestAlignmentStatements:
    """Alignment statements, including where they deliberately differ from the original SQL."""

    def test_the_update_no_longer_coalesces_the_class_type(self) -> None:
        """No silent no-op for an unresolved class.

        ``COALESCE(@ct, class_type)`` would assign the column to itself when the class guid did not
        resolve, so a caller aligning to a nonexistent class would get success. The class is
        resolved and checked first, so the guard has nothing to guard, and keeping it would
        re-introduce the no-op.
        """
        statement = st.align_dynamic_app(class_type=5, dynamic_app_id=11, name=None)
        assert "COALESCE" not in statement.sql
        assert "class_type = %s" in statement.sql
        assert statement.params == (5, 11)

    def test_the_da_selector_is_a_fragment_choice_not_a_parameter(self) -> None:
        by_id = st.align_dynamic_app(class_type=5, dynamic_app_id=11, name=None)
        by_name = st.align_dynamic_app(class_type=5, dynamic_app_id=None, name="Cisco: CPU")
        assert "WHERE aid = %s" in by_id.sql
        assert "WHERE name = %s" in by_name.sql
        assert "Cisco: CPU" in by_name.params

    def test_the_readback_selector_matches_the_update_selector(self) -> None:
        """A read-back matching different rows than the write would report someone else's data."""
        assert "da.aid = %s" in st.read_dynamic_app_alignment(dynamic_app_id=11, name=None).sql
        assert "da.name = %s" in st.read_dynamic_app_alignment(dynamic_app_id=None, name="x").sql

    @pytest.mark.parametrize(
        "call",
        [
            lambda: st.align_dynamic_app(class_type=1, dynamic_app_id=None, name=None),
            lambda: st.align_dynamic_app(class_type=1, dynamic_app_id=1, name="both"),
            lambda: st.read_dynamic_app_alignment(dynamic_app_id=None, name=None),
            lambda: st.read_dynamic_app_alignment(dynamic_app_id=1, name="both"),
        ],
    )
    def test_exactly_one_selector_is_required(self, call: object) -> None:
        with pytest.raises(ValueError, match="exactly one of"):
            call()  # type: ignore[operator]

    def test_the_aligned_apps_query_drops_the_redundant_null_guard(self) -> None:
        """No ``IS NOT NULL`` guard on the class type, which is this code's own value.

        As ``AND %s IS NOT NULL`` it would read like a real check while testing a value this code
        chose itself. An unresolved guid never reaches this statement.
        """
        statement = st.read_aligned_dynamic_apps(5)
        assert "IS NOT NULL" not in statement.sql
        assert statement.sql == (
            "SELECT aid, name FROM master.dynamic_app WHERE class_type = %s ORDER BY name"
        )


class TestComponentTreeStatements:
    def test_the_root_lookup_is_its_own_statement_with_no_session_variable(self) -> None:
        statement = st.resolve_root_did_by_name("vcenter-1")
        assert "SET @" not in statement.sql
        assert statement.params == ("vcenter-1",)

    def test_no_statement_in_this_module_uses_a_session_variable(self) -> None:
        """Session variables are designed out rather than worked around.

        `run_unit` makes a same-connection sequence safe, but a sequence needing no shared session
        state cannot be broken by a future refactor that splits it.
        """
        for build in ALL_BUILDERS:
            sql = build().sql  # type: ignore[operator]
            assert "SET @" not in sql, sql
            assert "@ct" not in sql
            assert "@root" not in sql

    def test_both_outer_joins_are_preserved(self) -> None:
        """An inner join would silently drop every vanished component."""
        sql = st.read_component_map(42).sql
        assert sql.count("LEFT JOIN") == 2
        assert "legend_device_vanished" in sql
        assert "'vanished'" in sql
        assert "'unknown'" in sql

    def test_the_component_column_order_is_the_source_order(self) -> None:
        # The caller unpacks by position, so order is behaviour.
        sql = st.read_component_map(42).sql
        # Split on the OUTER from-clause, not the first " FROM " -- that one is inside the nested
        # class-name sub-select, and splitting there truncates the projection before unique_id.
        projection = sql.split(" FROM master_dev.component_dev_map ", 1)[0]
        for earlier, later in (
            ("m.component_did", "m.parent_did"),
            ("m.parent_did", "m.unique_id"),
            ("m.unique_id", "m.discovered_by_aid"),
            ("m.discovered_by_aid", "m.last_seen"),
        ):
            assert projection.index(earlier) < projection.index(later), f"{earlier} vs {later}"

    def test_the_tree_is_scoped_to_the_root(self) -> None:
        assert "WHERE m.root_did = %s" in st.read_component_map(42).sql


class TestResolveDeviceCollector:
    """The first step of the collection route: which appliance collects for a device."""

    def test_it_selects_the_collector_pid_and_binds_the_device_id(self) -> None:
        statement = st.resolve_device_collector(device_id=209)
        assert statement.sql == "SELECT pid FROM collector_state.V_device WHERE did = %s LIMIT 1"
        assert statement.params == (209,)

    def test_the_projection_is_pid_so_the_callers_greater_than_zero_check_means_something(
        self,
    ) -> None:
        """The value returned must be the collector id, not the device id.

        ``master.process_async`` branches on ``module_id``: ``NULL`` spools the command to every
        appliance and ``0`` to every ``function IN (1, 5)`` box. Only ``> 0`` targets one, so the
        caller's ``> 0`` check is only a control if this statement projects ``pid``. Projecting
        ``did`` would return an equally plausible small positive int, pass that check, and dispatch
        to the wrong appliance with nothing raised anywhere.
        """
        statement = st.resolve_device_collector(device_id=209)
        assert statement.sql.startswith("SELECT pid FROM")
        assert "WHERE did = %s" in statement.sql
        assert statement.placeholder_count == 1


class TestDispatchDynamicCollection:
    """The one builder whose first parameter is a constructed command string.

    ``master.process_admin_remote_policy`` takes a command line, so the two ids are formatted into
    ``params[0]`` rather than bound individually. Every assertion below is a measured property of
    the platform's own decoder rather than a style preference.
    """

    def test_the_sentinel_is_present_and_at_offset_zero(self) -> None:
        """A payload failing this lands at ``state=4, returncode=99``.

        ``admin_toolbox.py::_decode_siloproc`` does ``rpartition("SILOPROC ")`` and requires
        ``ok and not junk``: the separator present and nothing before it. So this replays that
        decode rather than asserting ``"SILOPROC " in command``, which would also pass for a
        prefixed payload the toolbox refuses with ``Unauthorized Process for Toolbox``.
        """
        command = _dispatch_command()
        assert command.startswith("SILOPROC ")
        junk, separator, remainder = command.rpartition("SILOPROC ")
        assert separator == "SILOPROC "
        assert junk == ""
        assert remainder

    def test_the_command_is_the_debug_entry_point_with_both_ids_in_argv_order(self) -> None:
        """Tokenised the way the far side tokenises it: ``shlex.split`` into an argv list.

        There is no shell on the collector, so argv is the interface. Asserting the token list
        pins what a substring check cannot: that ``device_id`` precedes ``dynamic_app_id``. A swap
        builds a perfectly valid command that collects a different Dynamic Application on a
        different device and reports success.
        """
        assert shlex.split(_dispatch_command()) == [
            "SILOPROC",
            "env",
            "SILO_DEBUG=1",
            "SF_DEBUG=1",
            "/opt/em7/backend/sf_app_detailed_collect.py",
            "--allow-non-sf-app-type",
            "--standard-format",
            "-p",
            "209",
            "526",
        ]

    def test_the_command_carries_the_two_flags_whose_absence_degrades_silently(self) -> None:
        """Both flags whose absence produces a plausible-looking but wrong result are present.

        * ``--allow-non-sf-app-type``: without it ``job_scheduler.py:253`` silently drops classic
          non-Snippet-Framework apps and the run returns ``"No jobs scheduled"``.
        * ``--standard-format``: without it the platform's ``--web-ui-format`` renders JSON
          ``null`` as the string ``"None"``, which parses fine and means something else.

        ``-d`` is deliberately absent and must stay absent. ``extra_args`` filters it out on this
        path, so it would be inert; debug comes from ``SILO_DEBUG``/``SF_DEBUG``.
        """
        command = _dispatch_command()
        assert "--allow-non-sf-app-type" in command
        assert "--standard-format" in command
        assert not command.endswith(" -d")
        assert "--web-ui-format" not in command

    def test_the_parameters_are_in_procedure_argument_order(self) -> None:
        # Three of the five are ints, so a transposition is invisible: the CALL succeeds and the
        # job is spooled to the wrong appliance or against the wrong policy.
        statement = _dispatch()
        assert statement.sql == (
            "CALL master.process_admin_remote_policy(AES_ENCRYPT(%s, %s), %s, %s, %s)"
        )
        assert statement.params == (_dispatch_command(), "SILO1138", 4, 20, 526)
        assert statement.params[3] == st.COLLECTION_TOOLBOX_ID
        assert statement.params[4] == 526
        assert statement.placeholder_count == 5

    def test_the_toolbox_id_is_the_platforms_snippet_framework_detailed_collection(self) -> None:
        """``device_tools_run.inc:294`` branches on ``$tool_id`` to build the command just built."""
        assert st.COLLECTION_TOOLBOX_ID == 20

    def test_the_obfuscation_key_is_bound_and_never_reaches_statement_text(self) -> None:
        """Not a secret (a fixed platform-wide constant), but it is still bound, not embedded.

        Following ``admin_toolbox.py::run_command_on_module`` rather than
        ``device_tools_run.inc``: binding keeps the value out of `Statement.sql`, so it cannot
        reach a future log line or a ``repr`` of the statement.
        """
        statement = _dispatch()
        assert "AES_ENCRYPT(%s, %s)" in statement.sql
        assert "SILO1138" not in statement.sql
        assert statement.params[1] == "SILO1138"


class TestLastInsertId:
    """The dispatch `run_unit`'s second statement, and the only route to a proc_id."""

    def test_it_is_a_zero_parameter_statement(self) -> None:
        statement = st.last_insert_id()
        assert statement.sql == "SELECT LAST_INSERT_ID()"
        assert statement.params == ()
        assert statement.placeholder_count == 0

    def test_it_reintroduces_no_session_variable(self) -> None:
        """``LAST_INSERT_ID()`` is a function call, not a ``SET @var``.

        The statements module uses no ``SET @var``, because two ``local_db()`` handles do not share
        session state. A ``@`` anywhere in this statement would mean that coupling had come back in
        disguise, so the assertion is on the character itself, which is stricter than the
        ``SET @`` prefix the module-wide sweep looks for.
        """
        assert "@" not in st.last_insert_id().sql


class TestRecordDeviceToolRun:
    """Six columns named explicitly, because two of them have dangerous defaults."""

    def test_the_insert_names_all_six_columns_including_user_edit(self) -> None:
        """Dropping ``user_edit`` from the statement must fail here.

        ``master_logs.device_tools.user_edit`` is ``NOT NULL DEFAULT 1``. An INSERT that omitted
        the column would not error and would not record "unknown"; it would attribute the run to
        uid 1, `em7admin`, a real human account, in the platform's own Device Tools log viewer.
        ``pid`` carries the same hazard at lower stake (``DEFAULT 1`` is the Database node, which
        never collects).

        A statement that dropped either column would still be valid SQL and would still INSERT
        successfully, so nothing at runtime distinguishes it. Comparing the rendered column list
        exactly, in order, is the only check that does.
        """
        statement = _tool_run()
        columns = statement.sql.split("(", 1)[1].split(")", 1)[0]
        assert [column.strip() for column in columns.split(",")] == [
            "did",
            "pid",
            "proc_id",
            "tool_id",
            "date_edit",
            "user_edit",
        ]

    def test_the_five_parameters_are_in_column_order(self) -> None:
        # All five are ints, so a transposition inserts a clean row that attributes the run to the
        # wrong device, the wrong appliance or the wrong user. Order is behaviour.
        statement = _tool_run()
        assert statement.params == (209, 4, 4429, st.COLLECTION_TOOLBOX_ID, 1)
        assert statement.placeholder_count == 5

    def test_it_targets_the_platforms_own_device_tools_log(self) -> None:
        """Without this row the device is recoverable only by decrypting ``X_message``."""
        assert _tool_run().sql.startswith("INSERT INTO master_logs.device_tools (")

    def test_date_edit_stays_the_servers_clock(self) -> None:
        """``NOW()`` is a function call, not a value: binding it would send the client's clock."""
        statement = _tool_run()
        assert statement.sql.endswith("VALUES (%s, %s, %s, %s, NOW(), %s)")
        assert statement.sql.count("NOW()") == 1


class TestReadCollectionOutput:
    """The poll statement. Both of its shape decisions come from one measured 412-row run."""

    def test_the_cursor_is_strictly_greater_than_the_last_seen_id(self) -> None:
        """``>=`` would re-return the last row on every poll, forever.

        The caller advances ``after_id`` to the highest id it has seen, so ``>=`` would repeat that
        row on the next poll. Because the loop terminates on the ``msg_type=3`` terminal row, a
        duplicated tail is a duplicated terminal row: output that never stops arriving.
        """
        statement = _output()
        assert "id > %s" in statement.sql
        assert "id >= %s" not in statement.sql

    def test_the_rows_are_ordered_by_id_and_by_nothing_else(self) -> None:
        """``ORDER BY id`` is the interleaving of the two output streams.

        Measured on a 412-row run: stdout (2) spanned ids 1951-2360 with 214 stderr (4) rows
        interleaved inside that range. Ordering by ``msg_type``, or descending, or reading the
        streams as two queries, returns every row intact but in a sequence the collector never
        emitted, and for a debug log the emission sequence is the content.
        """
        statement = _output()
        assert statement.sql.rstrip().endswith("ORDER BY id")
        assert "DESC" not in statement.sql.upper()
        assert "ORDER BY msg_type" not in statement.sql

    def test_it_does_not_filter_by_msg_type(self) -> None:
        """Both streams come back from one query, the other half of the interleaving property."""
        statement = _output()
        assert "msg_type = %s" not in statement.sql
        assert "msg_type IN" not in statement.sql
        assert statement.sql.startswith(
            "SELECT id, msg_type, msg FROM master_logs.proc_remote_logs"
        )

    def test_the_two_parameters_are_proc_id_then_after_id(self) -> None:
        # Both are ints. Swapped, the statement is valid and selects the wrong job's tail.
        statement = st.read_collection_output(proc_id=4429, after_id=0)
        assert "WHERE proc_id = %s AND id > %s" in statement.sql
        assert statement.params == (4429, 0)

    def test_the_msg_type_constants_match_the_platform(self) -> None:
        """2 and 4 are ``admin_toolbox.py``'s own ``MSG_TYPE_OUT``/``MSG_TYPE_ERR``.

        1 and 3 were measured instead of read (the collector writes ``Process Started on
        Collector`` and ``Process Completed on Collector``), and 3 is what the poll loop
        terminates on, so a wrong value here is a loop that never ends.
        """
        assert (st.MSG_TYPE_STARTED, st.MSG_TYPE_STDOUT) == (1, 2)
        assert (st.MSG_TYPE_COMPLETED, st.MSG_TYPE_STDERR) == (3, 4)


class TestReadCollectionJob:
    """This answers "did the request reach the toolbox intact", nothing more."""

    def test_it_reads_state_and_returncode_for_one_spool_row(self) -> None:
        statement = st.read_collection_job(proc_id=4429)
        assert statement.sql == (
            "SELECT state, returncode, proc, Xtype FROM master_logs.spool_process "
            "WHERE id = %s LIMIT 1"
        )
        assert statement.params == (4429,)

    def test_the_parameter_matches_the_primary_key_column(self) -> None:
        """The same int is ``spool_process.id`` here and ``proc_remote_logs.proc_id`` there.

        ``LAST_INSERT_ID()`` returns the spool row's primary key, so this statement filters on
        ``id`` while `read_collection_output` filters on a ``proc_id`` column. The two tables name
        one value two ways, which makes a copy-pasted WHERE clause the obvious mistake, and
        ``LIMIT 1`` keeps a mistaken filter to one row.
        """
        statement = st.read_collection_job(proc_id=4429)
        assert "WHERE id = %s" in statement.sql
        assert statement.sql.endswith("LIMIT 1")


class TestNoStatementCarriesMoreThanOneStatement:
    """`run_unit` sends one ``execute()`` per statement, so a builder must produce exactly one."""

    @pytest.mark.parametrize("build", ALL_BUILDERS)
    def test_no_embedded_semicolon(self, build: object) -> None:
        statement = build()  # type: ignore[operator]
        assert ";" not in statement.sql


class TestGuidRouting:
    @pytest.mark.parametrize("value", ["a" * 32, "A" * 32, "0123456789abcdefABCDEF0123456789"])
    def test_a_32_char_hex_string_is_a_guid(self, value: str) -> None:
        assert st.looks_like_class_guid(value)

    @pytest.mark.parametrize("value", ["", "5", "z" * 32, "a" * 31, "a" * 33, "Cisco: Base Pack"])
    def test_anything_else_is_not(self, value: str) -> None:
        assert not st.looks_like_class_guid(value)

    def test_lowercase_guids_route_as_guids(self) -> None:
        """Case-insensitive on purpose. LCE's validator is uppercase-only and is not reused.

        Using the strict validator would misroute a lowercase guid into the name branch, where it
        would fail as "not found", a confusing error for a correct input.
        """
        assert st.looks_like_class_guid("deadbeef" * 4)
        assert st.looks_like_class_guid("DEADBEEF" * 4)


def _split_top_level(values: str) -> list[str]:
    """Split a SQL value list on commas that are not inside parentheses or quotes."""
    out: list[str] = []
    depth = 0
    in_quote = False
    current: list[str] = []
    for char in values:
        if char == "'":
            in_quote = not in_quote
        if not in_quote:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char == "," and depth == 0:
                out.append("".join(current).strip())
                current = []
                continue
        current.append(char)
    if current:
        out.append("".join(current).strip())
    return out


def _event() -> Statement:
    return st.insert_active_event(
        device_id=7,
        device_name="edge-01",
        source=6,
        message="m",
        sub_message="",
        threshold="",
        severity=3,
        event_policy=0,
    )


def _create(
    *,
    category: str = "Servers",
    device_type: str = "component",
    powerpack_guid: str | None = None,
) -> Statement:
    return st.insert_device_class(
        class_guid="A" * 32,
        family_guid="B" * 32,
        class_name="Acme Widget",
        description="Widget",
        category=category,
        device_type=device_type,
        is_snmp=False,
        root_device=False,
        powerpack_guid=powerpack_guid,
        class_identifier_1="",
        class_identifier_2="",
    )


def _dispatch() -> Statement:
    return st.dispatch_dynamic_collection(device_id=209, dynamic_app_id=526, module_id=4)


def _dispatch_command() -> str:
    """Return the constructed command line, ``params[0]``, narrowed to ``str`` for the checkers."""
    command = _dispatch().params[0]
    assert isinstance(command, str)
    return command


def _tool_run() -> Statement:
    return st.record_device_tool_run(device_id=209, module_id=4, proc_id=4429, user_id=1)


def _output() -> Statement:
    return st.read_collection_output(proc_id=4429, after_id=0)


class TestTheJobRowProjectsItsDiscriminators:
    """The two columns that confine the read path to `tool_id 20`, a security projection."""

    def test_it_projects_proc_and_xtype(self) -> None:
        """Without these the caller cannot tell our job from any other Remote Toolbox job.

        `proc_remote_logs` is shared by all 22 `tool_id` branches of `device_tools_run.inc`, and a
        rejected `tool_id 10` payload echoes decrypted SNMP credentials into it. Dropping either
        column from this projection would make `_is_collection_job` unable to gate, so a reader
        could page other tools' output by id.
        """
        statement = st.read_collection_job(proc_id=4429)

        assert "proc" in statement.sql
        assert "Xtype" in statement.sql
        assert st.REMOTE_TOOLBOX_PROCESS_ID == 125
        assert st.COLLECTION_TOOLBOX_ID == 20
