"""
Tool Set Registration Tests

This module tests ``powerpack_mcp.tool_sets.resolve``, which decides which tool sets register and
why the others do not.

Every test here calls a pure function. No application is built, no client constructed, no network
touched, which is why registration is decided by a pure function rather than observed through
``tools/list`` on a constructed app.
"""

from __future__ import annotations

import dataclasses

import pytest

from powerpack_mcp.errors import ToolSetDisabledReason
from powerpack_mcp.tool_sets import (
    ALL_TOOL_SET_IDS,
    DB_READ,
    DB_WRITE,
    FLAG_KEY_FOR,
    LCE,
    OPS,
    SL1_GRAPHQL,
    SL1_REST,
    STANDARDS,
    RegistrationPlan,
    ToolSetFlags,
    ToolSetRecord,
    resolve,
)
from powerpack_mcp.tools import ALL_DESCRIPTORS

# Tool counts for the LCE operations and the one standards tool. The SL1 and DB sets are left out,
# so they resolve with 0 tools in these tests.
#
# `LCE` is derived from `ALL_DESCRIPTORS`, never written as a literal. A hard-coded count would
# feed straight into `resolve()` and let the test pass against a surface that no longer matches.
SHIPPED_COUNTS = {LCE: len(ALL_DESCRIPTORS), STANDARDS: 1}


def plan_for(**overrides: bool) -> RegistrationPlan:
    return resolve(ToolSetFlags(**overrides), SHIPPED_COUNTS)


class TestRecordShape:
    def test_the_record_carries_exactly_these_five_fields(self) -> None:
        """The record is safe by construction.

        A set identifier, a boolean, an integer, a fixed key name and a closed enum leave no field
        a secret could occupy. That guarantee decays the moment someone adds a free-text field, so
        the field set is pinned here and adding one fails a test.

        ``flag`` is what marks ``lce`` as always on.
        """
        assert {f.name for f in dataclasses.fields(ToolSetRecord)} == {
            "set_id",
            "registered",
            "tool_count",
            "flag",
            "reason",
        }

    def test_records_are_immutable(self) -> None:
        record = plan_for().records[0]
        with pytest.raises(dataclasses.FrozenInstanceError):
            record.set_id = "tampered"  # type: ignore[misc]

    def test_asking_for_an_unknown_set_raises_rather_than_returning_none(self) -> None:
        """`record_for` refuses an unknown identifier instead of answering ``None``.

        A `None` return would be read as "that set is not registered", which is a different and
        much more plausible-looking answer than a raise.
        """
        with pytest.raises(KeyError):
            plan_for().record_for("no_such_set")


class TestCompleteInventory:
    def test_every_set_is_reported_even_when_disabled(self) -> None:
        """A complete inventory, not a list of the optional parts."""
        plan = plan_for(sl1_rest=False, db_tools=False)
        assert tuple(r.set_id for r in plan.records) == ALL_TOOL_SET_IDS

    def test_lce_is_always_registered_and_marked_always_on(self) -> None:
        """There is no flag value that turns the LCE tools off."""
        for flags in (ToolSetFlags(), ToolSetFlags(*[False] * 6)):
            record = resolve(flags, SHIPPED_COUNTS).record_for(LCE)
            assert record.registered
            assert record.reason is None
            assert record.flag is None
            assert record.always_on

    def test_every_other_set_names_the_key_that_gates_it(self) -> None:
        """The question an operator actually has is *which key do I set*."""
        plan = plan_for()
        for record in plan.records:
            assert record.flag == FLAG_KEY_FOR[record.set_id]
            if record.set_id != LCE:
                assert record.flag is not None
                assert record.flag.startswith("ENABLE_")
                assert not record.always_on


class TestDefaultsAreOn:
    def test_absent_configuration_registers_everything(self) -> None:
        """All sets on is the permanent shipped default, not a development posture."""
        plan = plan_for()
        assert plan.registered_ids == ALL_TOOL_SET_IDS
        assert all(r.reason is None for r in plan.records)

    def test_the_registered_surface_is_the_shipped_tool_count(self) -> None:
        """The LCE tools plus the one standards tool; the sets absent from the counts contribute 0.

        The expected value is derived, not written down, so it cannot pass against the wrong
        surface.
        """
        assert plan_for().total_tools == len(ALL_DESCRIPTORS) + 1


class TestNesting:
    def test_disabling_db_tools_disables_writes_whatever_the_write_key_says(self) -> None:
        """The load-bearing nesting rule: writes cannot outlive reads."""
        plan = plan_for(db_tools=False, db_write_tools=True)
        assert DB_READ not in plan.registered_ids
        assert DB_WRITE not in plan.registered_ids

    def test_nesting_is_reported_distinguishably_from_plain_configuration(self) -> None:
        """A bare "disabled" cannot distinguish two situations that demand
        opposite responses. Here the operator set one key and got two sets off -- the log must say
        which of those was their instruction and which was a consequence."""
        plan = plan_for(db_tools=False, db_write_tools=True)
        assert plan.record_for(DB_READ).reason is ToolSetDisabledReason.DISABLED_BY_CONFIGURATION
        assert plan.record_for(DB_WRITE).reason is ToolSetDisabledReason.DISABLED_BY_NESTING

    def test_nesting_is_not_an_error(self) -> None:
        """It resolves rather than refusing.

        An operator disabling DB tools wholesale expressed a clear intent, and refusing to start
        because a nested key still says true would punish the safe direction.
        """
        plan = plan_for(db_tools=False, db_write_tools=True)
        assert plan.registered_ids  # the service still has a tool surface
        assert LCE in plan.registered_ids

    def test_writes_off_with_reads_on_is_plain_configuration(self) -> None:
        plan = plan_for(db_write_tools=False)
        assert DB_READ in plan.registered_ids
        assert plan.record_for(DB_WRITE).reason is (ToolSetDisabledReason.DISABLED_BY_CONFIGURATION)


class TestDisabledSetsReportZero:
    def test_a_disabled_set_reports_no_tools(self) -> None:
        """Its tools are never constructed, so any other number would describe something
        that does not exist."""
        plan = resolve(ToolSetFlags(standards_tools=False), SHIPPED_COUNTS)
        record = plan.record_for(STANDARDS)
        assert not record.registered
        assert record.tool_count == 0

    def test_all_optional_sets_off_leaves_the_lce_tools_only(self) -> None:
        """A valid configuration, not an error."""
        plan = resolve(ToolSetFlags(*[False] * 6), SHIPPED_COUNTS)
        assert plan.registered_ids == (LCE,)
        assert plan.total_tools == len(ALL_DESCRIPTORS)


class TestPrerequisiteMissingIsDefinedButUnused:
    def test_resolve_never_emits_it(self) -> None:
        """Configuration alone never produces ``PREREQUISITE_MISSING``.

        The value exists for the DB sets, which are unavailable for a reason that is neither
        configuration nor nesting when the database driver cannot be loaded. Only the
        ``prerequisites_met`` argument produces it; the flags never do.
        """
        for combination in range(64):
            flags = ToolSetFlags(*[bool(combination >> i & 1) for i in range(6)])
            reasons = {r.reason for r in resolve(flags, SHIPPED_COUNTS).records}
            assert ToolSetDisabledReason.PREREQUISITE_MISSING not in reasons


class TestDeterminism:
    def test_identical_flags_give_an_identical_plan(self) -> None:
        """Exhaustive over all 64 combinations here; the property test in
        `tests/property/` covers the same rule generatively."""
        for combination in range(64):
            flags = ToolSetFlags(*[bool(combination >> i & 1) for i in range(6)])
            assert resolve(flags, SHIPPED_COUNTS) == resolve(flags, SHIPPED_COUNTS)

    def test_registration_order_is_fixed(self) -> None:
        """Order is part of the plan's determinism, not an incidental property of iteration."""
        assert plan_for(sl1_graphql=False).registered_ids == (
            LCE,
            SL1_REST,
            DB_READ,
            DB_WRITE,
            OPS,
            STANDARDS,
        )
        assert SL1_GRAPHQL in ALL_TOOL_SET_IDS


class TestReachabilityIsNotAnInput:
    def test_resolve_takes_only_flags_counts_and_deployment_prerequisites(self) -> None:
        """Registration never depends on backend reachability.

        Registering on reachability would make ``tools/list`` non-deterministic across restarts,
        let a transient blip silently shrink the tool surface, and couple startup to four
        backends. Pinned as a signature assertion because the tempting change is small and the
        consequence is not.

        The third parameter is not a reachability input. The DB sets must be disabled with reason
        ``PREREQUISITE_MISSING`` when ``import sl_mysql`` fails, and applying that after
        ``resolve`` returned would leave the plan claiming a set registered that did not. The
        distinction is when the answer can change: whether the backend is answering varies between
        restarts, but whether ``import sl_mysql`` succeeded is fixed for the installed service, so
        ``test_resolve_is_deterministic_with_prerequisites`` below still holds.

        The pin stays an exact list so a fourth parameter has to be argued for here too.
        """
        import inspect

        assert list(inspect.signature(resolve).parameters) == [
            "flags",
            "tool_counts",
            "prerequisites_met",
        ]

    def test_resolve_is_deterministic_with_prerequisites(self) -> None:
        """The property the third parameter must not break.

        A reachability probe was rejected because it makes this false, so any new input owes this
        test.
        """
        flags = ToolSetFlags()
        counts = {"lce": 7, "db_read": 3, "db_write": 5, "ops": 14}
        prerequisites = {"db_read": False, "db_write": False}
        assert resolve(flags, counts, prerequisites) == resolve(flags, counts, prerequisites)

    def test_an_unmet_prerequisite_reports_its_own_reason_and_no_tools(self) -> None:
        """Disabled with a stated reason, and the count is 0, not 3.

        A set that is not registered constructs no tools, so any number other than 0 would
        describe something that does not exist.
        """
        plan = resolve(ToolSetFlags(), {"db_read": 3, "ops": 14}, {"db_read": False})
        db_read = plan.record_for("db_read")
        assert db_read.registered is False
        assert db_read.reason is ToolSetDisabledReason.PREREQUISITE_MISSING
        assert db_read.tool_count == 0
        # `ops` needs no driver, so it is untouched by the DB prerequisite.
        assert plan.record_for("ops").registered is True
        assert plan.record_for("ops").tool_count == 14

    def test_the_flag_outranks_the_prerequisite(self) -> None:
        """Ordering is load-bearing, so it is pinned.

        With the flag off and the driver missing, the reason reported is
        ``DISABLED_BY_CONFIGURATION``: the operator's own instruction, not the environment.
        Reporting the prerequisite first would tell an operator who explicitly disabled the set
        that their driver is missing, hiding that their key took effect.
        """
        plan = resolve(ToolSetFlags(db_tools=False), {"db_read": 3}, {"db_read": False})
        record = plan.record_for("db_read")
        assert record.reason is ToolSetDisabledReason.DISABLED_BY_CONFIGURATION
        assert record.registered is False

    def test_a_nested_disable_still_wins_over_the_prerequisite(self) -> None:
        """`db_write` with its parent off reports ``DISABLED_BY_NESTING``, driver or no driver."""
        plan = resolve(
            ToolSetFlags(db_tools=False),
            {"db_write": 5},
            {"db_write": False},
        )
        assert plan.record_for("db_write").reason is ToolSetDisabledReason.DISABLED_BY_NESTING

    def test_the_prerequisite_applies_when_configuration_would_have_registered(self) -> None:
        """The prerequisite's actual case: flags on, driver missing."""
        plan = resolve(ToolSetFlags(), {"db_read": 3, "db_write": 5}, {"db_read": False})
        assert plan.record_for("db_read").reason is ToolSetDisabledReason.PREREQUISITE_MISSING
        # Not in the mapping, so unaffected -- the nesting parent's *flag* is still on.
        assert plan.record_for("db_write").registered is True

    def test_a_set_absent_from_the_mapping_has_no_prerequisite(self) -> None:
        """The default must be "no prerequisite", so a set is never disabled by omission."""
        plan = resolve(ToolSetFlags(), {"ops": 14}, {"db_read": False})
        assert plan.record_for("ops").registered is True
        assert plan.record_for("standards").registered is True
