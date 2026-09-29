"""
Property-Based Tests

This module tests the pure functions and security-relevant invariants with Hypothesis: target-host
validation, correlation-ID sanitising, error payloads and LCE body redaction, schema trimming,
tool-set resolution, the tool registry, SQL construction, and the hook-based authorization gate.

Each of these also has example-based tests in ``tests/unit``; property tests are never the only
coverage.
"""

from __future__ import annotations

import asyncio
import copy
import json
import re
import shlex
from collections.abc import Callable, Mapping
from typing import ClassVar, Final

import mcp.types as mt
import pytest
from fastmcp.server.middleware import MiddlewareContext
from fastmcp.tools.base import ToolResult
from hypothesis import assume, given
from hypothesis import strategies as st
from jsonschema import Draft202012Validator
from pydantic import SecretStr

from powerpack_mcp import authz, tool_sets
from powerpack_mcp.credentials import LceCredential
from powerpack_mcp.errors import (
    MAX_LCE_BODY_CHARS,
    MAX_LCE_BODY_DEPTH,
    REDACTED,
    SECRET_FIELD_DENYLIST,
    AuthorizationDenied,
    ConfigurationError,
    FindingCode,
    LceHttpError,
    LceMalformedResponse,
    LceUnreachable,
    PowerPackMcpError,
    Sl1MalformedResponse,
    ToolSetDisabledReason,
    ValidationBlocked,
    ValidationFinding,
    build_error_payload,
    sanitize_lce_body,
)
from powerpack_mcp.hook_source import HookCache, parse_hook_payload
from powerpack_mcp.lce_client import MAX_TARGET_HOST_LENGTH, is_valid_target_host
from powerpack_mcp.mcp_app import sanitize_correlation_id
from powerpack_mcp.mcp_app.authz_gate import AuthorizationGate, is_gated
from powerpack_mcp.schema_slim import trim
from powerpack_mcp.sql import (
    LIKE_ESCAPE_CHAR,
    Statement,
    checked_identifier,
    like_contains,
    placeholders,
)
from powerpack_mcp.tools import sl1_db_statements as dbst
from tests.property.test_generators import (
    hook_deny_branches,
    hook_ids,
    hook_payloads,
    hostile_correlation_ids,
    hostile_sql_operands,
    instances_for,
    invalid_target_hosts,
    json_bodies,
    json_schemas,
    lce_error_bodies,
    principals,
    rejection_reasons,
    required_hook_sets,
    tool_set_flags,
    valid_target_hosts,
)

_CORRELATION_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FORBIDDEN_IN_HOST = (":", "/", "?", "#", "@", "%", " ", "\t", "\n", "\r")


class TestIsValidTargetHost:
    @given(valid_target_hosts())
    def test_accepts_every_valid_hostname_and_ipv4_literal(self, host: str) -> None:
        assert is_valid_target_host(host) is True

    @given(invalid_target_hosts())
    def test_rejects_every_generated_invalid_form(self, host: str) -> None:
        assert is_valid_target_host(host) is False

    @given(st.text())
    def test_rejects_every_string_containing_a_forbidden_character(self, value: str) -> None:
        """Reject any string containing a forbidden character.

        `re.match` with a ``$`` anchor also matches before a trailing newline in Python, so the
        predicate must use ``fullmatch`` or ``"host\\n"`` is accepted.
        """
        if any(ch in value for ch in _FORBIDDEN_IN_HOST):
            assert is_valid_target_host(value) is False

    @given(st.text())
    def test_is_total(self, value: str) -> None:
        """Never raises for any ``str`` input, including the empty string."""
        assert isinstance(is_valid_target_host(value), bool)

    @given(st.text())
    def test_is_case_insensitive(self, value: str) -> None:
        """Hostnames are case-insensitive, so the predicate must be too."""
        assert is_valid_target_host(value) == is_valid_target_host(value.lower())

    @given(st.text())
    def test_is_idempotent(self, value: str) -> None:
        assert is_valid_target_host(value) == is_valid_target_host(value)

    @given(st.text(min_size=254))
    def test_rejects_anything_over_the_length_bound(self, value: str) -> None:
        assert len(value) > MAX_TARGET_HOST_LENGTH
        assert is_valid_target_host(value) is False


class TestSanitizeCorrelationId:
    """The correlation ID stored in the `ContextVar` must satisfy the character rule whatever
    arrived on the wire.
    """

    @given(hostile_correlation_ids())
    def test_output_always_matches_the_character_rule(self, value: str | None) -> None:
        assert _CORRELATION_RE.match(sanitize_correlation_id(value)) is not None

    @given(hostile_correlation_ids())
    def test_is_total(self, value: str | None) -> None:
        """Never raises, for any input including ``None``."""
        assert isinstance(sanitize_correlation_id(value), str)

    @given(hostile_correlation_ids())
    def test_never_returns_empty(self, value: str | None) -> None:
        assert len(sanitize_correlation_id(value)) >= 1

    @given(hostile_correlation_ids())
    def test_output_never_exceeds_the_length_bound(self, value: str | None) -> None:
        """Unbounded length would let a caller flood the journal."""
        assert len(sanitize_correlation_id(value)) <= 128

    @given(hostile_correlation_ids())
    def test_is_idempotent_on_its_own_output(self, value: str | None) -> None:
        once = sanitize_correlation_id(value)
        assert sanitize_correlation_id(once) == once

    @given(hostile_correlation_ids())
    def test_output_never_contains_a_newline(self, value: str | None) -> None:
        """The log-forging property, stated directly rather than inferred from the class."""
        result = sanitize_correlation_id(value)
        assert "\n" not in result
        assert "\r" not in result

    @given(st.from_regex(_CORRELATION_RE, fullmatch=True))
    def test_valid_values_pass_through_unchanged(self, value: str) -> None:
        assert sanitize_correlation_id(value) == value


def _errors() -> st.SearchStrategy[PowerPackMcpError]:
    findings = st.lists(
        st.builds(
            ValidationFinding,
            path=st.text(max_size=40),
            rule=st.sampled_from(list(FindingCode)),
            message=st.text(max_size=60),
        ),
        max_size=5,
    )
    bodies = st.one_of(
        st.dictionaries(st.text(max_size=10), st.integers(), max_size=3),
        st.lists(st.integers(), max_size=3),
        st.text(max_size=40),
    )
    return st.one_of(
        findings.map(ValidationBlocked),
        st.builds(LceHttpError, status_code=st.integers(400, 599), lce_body=bodies),
        st.builds(LceUnreachable, target_host=st.text(max_size=30)),
        st.builds(LceMalformedResponse),
        st.builds(ConfigurationError, st.text(max_size=40)),
        # Hook IDs come from a hook-shaped alphabet rather than `st.text()`: a random string does
        # not resemble a `master_access.hooks.hook_id`, and the disclosure properties below are only
        # meaningful against values that do.
        st.builds(
            AuthorizationDenied,
            tool_name=st.sampled_from(sorted(authz.sql_tool_names())),
            required_hooks=st.frozensets(
                st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ_", min_size=3, max_size=32),
                min_size=1,
                max_size=4,
            ),
        ),
    )


# ---- Disclosure checking by attribution ----
#
# A disclosure marker may appear in an error payload only if the input put it there; anything not
# attributable is this service disclosing its own internals. An exclusion list of field names does
# not work: it grows with every pass-through field, and it exempts a field entirely, so a marker
# this service added to an exempt field (a real `.py` path appended to a caller's message) goes
# unseen.
#
# Attribution is by occurrence, not by stripping supplied substrings out first. Stripping would let
# a one-character supplied string mask a real leak: removing a supplied "p" from an authored ".py"
# leaves ".y" and the check passes. Requiring that some supplied string which itself contains the
# marker is present in the same leaf has no such hole.

_DISCLOSURE_MARKERS = (".py", "Traceback", "/opt/em7")


def _harvest_strings(value: object, into: set[str]) -> None:
    """Collect every string reachable in ``value``, keys included, into ``into``."""
    if isinstance(value, str):
        into.add(value)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            _harvest_strings(key, into)
            _harvest_strings(item, into)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _harvest_strings(item, into)


def supplied_strings(exc: PowerPackMcpError) -> set[str]:
    """Return every string the input contributed to ``exc``, flattened.

    ``lce_body`` is read from the attribute rather than the constructor argument because
    `LceHttpError.__init__` runs `sanitize_lce_body`; the attribute is what reaches the payload, so
    it is what attribution must be measured against.
    """
    supplied: set[str] = set()
    if isinstance(exc, ValidationBlocked):
        for finding in exc.findings:
            _harvest_strings(finding.path, supplied)
            _harvest_strings(finding.message, supplied)
    elif isinstance(exc, LceHttpError):
        _harvest_strings(exc.lce_body, supplied)
    elif isinstance(exc, LceUnreachable):
        _harvest_strings(exc.target_host, supplied)
    elif isinstance(exc, ConfigurationError):
        _harvest_strings(str(exc), supplied)
    return supplied


def payload_leaves(value: object) -> list[str]:
    """Return every leaf of a payload as a string, keys included.

    Keys matter: a field name carrying an internal path would disclose just as much as a value.
    Non-string leaves are rendered with `str` so an enum or an int is still inspected.
    """
    leaves: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, str):
            leaves.append(node)
        elif isinstance(node, Mapping):
            for key, item in node.items():
                walk(key)
                walk(item)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item)
        else:
            leaves.append(str(node))

    walk(value)
    return leaves


def unattributable_disclosures(payload: object, supplied: set[str]) -> list[tuple[str, str]]:
    """Return ``(marker, leaf)`` for every marker occurrence the input cannot account for."""
    offences: list[tuple[str, str]] = []
    for leaf in payload_leaves(payload):
        for marker in _DISCLOSURE_MARKERS:
            if marker not in leaf:
                continue
            if any(marker in source and source in leaf for source in supplied):
                continue
            offences.append((marker, leaf))
    return offences


class TestBuildErrorPayload:
    _VOCABULARY: ClassVar[set[str]] = {
        "validation_blocked",
        "lce_http_error",
        "lce_unreachable",
        "lce_malformed_response",
        "internal_error",
        # Hand-maintained deliberately: this set is the assertion, so deriving it from `ErrorType`
        # would make the test agree with whatever the code does.
        "authorization_denied",
    }

    @given(_errors())
    def test_type_is_always_in_the_closed_vocabulary(self, exc: PowerPackMcpError) -> None:
        assert build_error_payload(exc)["error"]["type"] in self._VOCABULARY

    @given(_errors())
    def test_is_total_over_the_hierarchy(self, exc: PowerPackMcpError) -> None:
        payload = build_error_payload(exc)
        assert set(payload) == {"error"}
        assert "message" in payload["error"]

    @given(_errors())
    def test_lce_status_present_iff_lce_http_error(self, exc: PowerPackMcpError) -> None:
        has_status = "lce_status" in build_error_payload(exc)["error"]
        assert has_status is isinstance(exc, LceHttpError)

    @given(_errors())
    def test_details_present_iff_validation_blocked(self, exc: PowerPackMcpError) -> None:
        has_details = "details" in build_error_payload(exc)["error"]
        assert has_details is isinstance(exc, ValidationBlocked)

    @given(_errors())
    def test_lce_body_present_iff_lce_http_error(self, exc: PowerPackMcpError) -> None:
        """The same `iff` discipline `lce_status` has, asserted in both directions."""
        has_body = "lce_body" in build_error_payload(exc)["error"]
        assert has_body is isinstance(exc, LceHttpError)

    @given(_errors())
    def test_never_leaks_a_traceback_or_internal_path(self, exc: PowerPackMcpError) -> None:
        """No disclosure marker appears anywhere in the payload unless the input put it there.

        Attribution exempts only the marker occurrences the input accounts for, so authored content
        is checked in every field, pass-through fields such as `lce_body` and `details[].message`
        included. A new pass-through field needs no edit here, and a newly authored field is covered
        as soon as it exists.
        """
        payload = build_error_payload(exc)
        offences = unattributable_disclosures(payload, supplied_strings(exc))
        assert not offences, (
            f"payload discloses internals the input cannot account for: {offences!r}"
        )

    @given(_errors())
    def test_the_check_is_not_vacuous(self, exc: PowerPackMcpError) -> None:
        """Attribution must not be so permissive that a real leak passes.

        The risk in an attribution rule is that everything looks attributable. This injects a
        marker the input demonstrably did not supply and asserts it is caught, on every generated
        exception, so the guard runs against the same inputs the test above uses.
        """
        supplied = supplied_strings(exc)
        planted = {"error": {"code": "internal_error", "detail": "/opt/em7/services/x.py line 4"}}
        offences = unattributable_disclosures(planted, supplied)
        assert offences, f"a planted disclosure was not caught; supplied={supplied!r}"

    @given(_errors())
    def test_no_payload_field_leaks_a_stack_trace(self, exc: PowerPackMcpError) -> None:
        """Check ``Traceback`` and ``/opt/em7`` over the whole payload, `lce_body` included.

        Kept as a separate test because it is the strongest of the three signals and deserves to
        fail on its own. It is attributed too: an LCE that echoes a request back, or generated
        `st.text()`, can legitimately supply either marker.
        """
        supplied = supplied_strings(exc)
        offences = [
            (marker, leaf)
            for marker, leaf in unattributable_disclosures(build_error_payload(exc), supplied)
            if marker in ("Traceback", "/opt/em7")
        ]
        assert not offences, f"payload leaks a stack trace or an appliance path: {offences!r}"

    @given(findings=st.lists(st.text(max_size=20), min_size=1, max_size=6))
    def test_details_carries_every_finding(self, findings: list[str]) -> None:
        """Every offending path appears, not just the first."""
        blocked = ValidationBlocked(
            [ValidationFinding(path, FindingCode.CHILD_GUID, "m") for path in findings]
        )
        details = build_error_payload(blocked)["error"]["details"]
        assert isinstance(details, list)
        assert len(details) == len(findings)


def test_every_rejection_reason_is_covered() -> None:
    """The invalid-host generator covers each rejection reason.

    Asserted rather than assumed: a reason silently dropped from the table would weaken the suite
    without failing anything.
    """
    expected = {
        "scheme",
        "port",
        "path",
        "query",
        "fragment",
        "userinfo",
        "percent_encoding",
        "whitespace",
        "control_character",
        "empty",
        "trailing_dot",
        "leading_hyphen",
        "trailing_hyphen",
        "ipv6",
        "too_long",
        "empty_label",
    }
    assert set(rejection_reasons) == expected


class TestSanitizeLceBody:
    """Invariants of `sanitize_lce_body`.

    There is no round-trip property: redaction and truncation destroy information on purpose, so
    the sanitiser has no inverse.
    """

    @given(json_bodies())
    def test_no_denylisted_key_keeps_its_value(self, body: object) -> None:
        """Checked recursively, at every depth."""

        def walk(node: object, depth: int) -> None:
            if depth >= MAX_LCE_BODY_DEPTH:
                return
            if isinstance(node, dict):
                for key, value in node.items():
                    if isinstance(key, str) and key.lower() in SECRET_FIELD_DENYLIST:
                        assert value == REDACTED
                    else:
                        walk(value, depth + 1)
            elif isinstance(node, list):
                for item in node:
                    walk(item, depth + 1)

        walk(sanitize_lce_body({"root": body}), 0)

    @given(json_bodies())
    def test_no_string_exceeds_the_cap(self, body: object) -> None:
        limit = MAX_LCE_BODY_CHARS + len("...[truncated]")

        def walk(node: object) -> None:
            if isinstance(node, str):
                assert len(node) <= limit
            elif isinstance(node, dict):
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(sanitize_lce_body({"root": body}))

    @given(lce_error_bodies())
    def test_top_level_type_is_preserved(
        self, body: dict[str, object] | list[object] | str
    ) -> None:
        """`LceHttpError.lce_body`'s declared type must survive the walk.

        ``dict`` -> ``dict``, ``list`` -> ``list``, ``str`` -> ``str``.
        """
        assert type(sanitize_lce_body(body)) is type(body)

    @given(lce_error_bodies())
    def test_is_total_and_json_serialisable(
        self, body: dict[str, object] | list[object] | str
    ) -> None:
        """Totality, and the property that matters downstream: the result can be rendered."""
        json.dumps(sanitize_lce_body(body))

    @given(lce_error_bodies())
    def test_falsy_values_are_never_dropped(
        self, body: dict[str, object] | list[object] | str
    ) -> None:
        """`0`, `false` and `""` are values, and are never dropped.

        Asserted structurally (container sizes are preserved) because this sanitiser redacts and
        truncates but must never remove a member the way `drop_empty` deliberately does.

        Two exceptions are mirrored in the helper:

        1. A denylisted key has its entire value replaced by the marker, whatever that value's
           type, so a container under such a key legitimately disappears. A
           ``credential: {"user": ..., "pass": ...}`` subtree must vanish whole, not have its leaves
           individually redacted, so the helper skips those keys on both sides.
        2. At `MAX_LCE_BODY_DEPTH` the walk substitutes a marker string without descending, so
           nothing below the bound is comparable.
        """

        def sizes(node: object, depth: int) -> list[int]:
            if depth >= MAX_LCE_BODY_DEPTH:
                return []
            if isinstance(node, dict):
                counted = [len(node)]
                for key, value in node.items():
                    if isinstance(key, str) and key.lower() in SECRET_FIELD_DENYLIST:
                        continue
                    counted.extend(sizes(value, depth + 1))
                return counted
            if isinstance(node, list):
                return [len(node), *[n for item in node for n in sizes(item, depth + 1)]]
            return []

        assert sizes(sanitize_lce_body(body), 0) == sizes(body, 0)

    @given(st.integers(min_value=1, max_value=600))
    def test_terminates_on_arbitrarily_deep_nesting(self, depth: int) -> None:
        """Frames are bounded by the limit, not the input. No `RecursionError` at any depth."""
        node: dict[str, object] = {}
        cursor = node
        for _ in range(depth):
            child: dict[str, object] = {}
            cursor["next"] = child
            cursor = child
        json.dumps(sanitize_lce_body(node))

    @given(lce_error_bodies())
    def test_is_idempotent(self, body: dict[str, object] | list[object] | str) -> None:
        """Sanitising twice changes nothing, so a second pass cannot double-mark an elision."""
        once = sanitize_lce_body(body)
        assert sanitize_lce_body(once) == once


# ---- Schema trimming oracle (`schema_slim`) ----
#
# A trimmed schema must accept exactly the input set the untrimmed schema accepts. This is checked
# against a real validator, `jsonschema`, which `pyproject.toml` declares in the `dev` group for
# this test only.
#
# The verdicts are compared for equality rather than `if original_ok: assert trimmed_ok`. Trimming
# removes keys, and removing the wrong key widens what validates; one-directional agreement would
# let a more permissive schema pass. That is also why `instances_for` produces invalid instances:
# with only valid ones, a widened schema could never be observed.


# A schema paired with a corpus of candidate instances, so each generated schema is probed
# several times per example.
_SCHEMA_WITH_CORPUS: st.SearchStrategy[tuple[dict[str, object], list[dict[str, object]]]] = (
    json_schemas().flatmap(
        lambda schema: st.tuples(
            st.just(schema), st.lists(instances_for(schema), min_size=1, max_size=6)
        )
    )
)


# Values chosen because they distinguish schemas, `None` above all: catching a widened schema needs
# an instance the untrimmed schema rejects while the trimmed one accepts it, and for the
# nullable-union traps in `_LEAF_SCHEMAS` that instance is `{param: None}` specifically.
_PROBE_VALUES: Final[tuple[object, ...]] = (None, "", "x", 0, False, [], {})


def _probe_instances(schema: dict[str, object]) -> list[dict[str, object]]:
    """Return one instance per (declared property x probe value), plus empty and extra-key cases.

    The random corpus alone is too weak. With `instances_for` as the only source, deleting
    `_collapse_nullable_union`'s sibling-`type` guard (so a node with both `type` and `anyOf` has
    its `type` overwritten and silently accepts `null`) left this property passing at the `dev`
    profile's 50 examples. The oracle's power comes from covering the distinguishing instances
    systematically; Hypothesis supplies the breadth.
    """
    properties = schema.get("properties")
    names = sorted(properties) if isinstance(properties, dict) else []
    instances: list[dict[str, object]] = [{}, {"unexpected_extra": "x"}]
    instances.extend({name: value} for name in names for value in _PROBE_VALUES)
    return instances


class TestSchemaTrimmingPreservesSemantics:
    @given(_SCHEMA_WITH_CORPUS)
    def test_trimmed_and_untrimmed_agree_on_every_instance(
        self, case: tuple[dict[str, object], list[dict[str, object]]]
    ) -> None:
        """The accepted input set is identical, in both directions."""
        schema, corpus = case
        before = copy.deepcopy(schema)
        trimmed = trim(schema)

        # Purity is load-bearing for this oracle: the comparison below validates against `schema`
        # after trimming, so if `trim` mutated its argument both validators would read the same
        # object and the property would pass vacuously.
        assert schema == before

        # A trimmed schema that is no longer a valid schema would make `is_valid` meaningless rather
        # than merely false, so establish that first and fail legibly if trimming broke it.
        Draft202012Validator.check_schema(trimmed)

        original = Draft202012Validator(schema)
        slim = Draft202012Validator(trimmed)
        for instance in [*corpus, *_probe_instances(schema)]:
            assert original.is_valid(instance) == slim.is_valid(instance), (
                f"verdicts diverged for {instance!r}: trimming changed what validates, which "
                f"trimming must never do. Trimmed schema: {trimmed!r}"
            )

    @given(json_schemas())
    def test_trimming_is_idempotent(self, schema: dict[str, object]) -> None:
        """Catch a walk that re-collapses an already-compact union incorrectly.

        The example-based version is in ``tests/unit/test_schema_slim.py``.
        """
        once = trim(schema)
        assert trim(once) == once


# ---- Tool-set resolution (`tool_sets`) ----
#
# Resolution is a pure function from flag values to a plan, so these rules are testable here
# without building an application and diffing `tools/list`.


class TestToolSetResolution:
    _COUNTS: ClassVar[dict[str, int]] = {tool_sets.LCE: 8, tool_sets.STANDARDS: 1}

    @given(tool_set_flags())
    def test_resolution_is_deterministic(self, flags: tool_sets.ToolSetFlags) -> None:
        """``tools/list`` must be identical for identical configuration across restarts,
        and a restart is a fresh `resolve` call."""
        assert tool_sets.resolve(flags, self._COUNTS) == tool_sets.resolve(flags, self._COUNTS)

    @given(tool_set_flags())
    def test_disabling_db_tools_always_disables_writes(self, flags: tool_sets.ToolSetFlags) -> None:
        """The generator forces this combination one draw in four; otherwise the property would
        hold vacuously most of the time.
        """
        plan = tool_sets.resolve(flags, self._COUNTS)
        if not flags.db_tools:
            assert tool_sets.DB_READ not in plan.registered_ids
            assert tool_sets.DB_WRITE not in plan.registered_ids

    @given(tool_set_flags())
    def test_lce_is_registered_under_every_configuration(
        self, flags: tool_sets.ToolSetFlags
    ) -> None:
        """No flag combination removes the LCE tools."""
        plan = tool_sets.resolve(flags, self._COUNTS)
        assert tool_sets.LCE in plan.registered_ids
        assert plan.record_for(tool_sets.LCE).always_on

    @given(tool_set_flags())
    def test_the_inventory_is_always_complete(self, flags: tool_sets.ToolSetFlags) -> None:
        """Every set is reported, whatever its state."""
        plan = tool_sets.resolve(flags, self._COUNTS)
        assert tuple(r.set_id for r in plan.records) == tool_sets.ALL_TOOL_SET_IDS

    @given(tool_set_flags())
    def test_registered_exactly_when_no_reason_is_given(
        self, flags: tool_sets.ToolSetFlags
    ) -> None:
        """The two fields cannot disagree: a reason is present precisely when the set is off."""
        for record in tool_sets.resolve(flags, self._COUNTS).records:
            assert record.registered == (record.reason is None)

    @given(tool_set_flags())
    def test_a_disabled_set_never_reports_tools(self, flags: tool_sets.ToolSetFlags) -> None:
        """Its tools are never constructed, so it cannot have a count."""
        for record in tool_sets.resolve(flags, self._COUNTS).records:
            if not record.registered:
                assert record.tool_count == 0

    @given(tool_set_flags())
    def test_resolve_never_emits_prerequisite_missing(self, flags: tool_sets.ToolSetFlags) -> None:
        """The value is reserved for the DB prerequisite check; `resolve` depends on
        configuration only."""
        for record in tool_sets.resolve(flags, self._COUNTS).records:
            assert record.reason is not ToolSetDisabledReason.PREREQUISITE_MISSING

    @given(tool_set_flags())
    def test_no_record_field_can_carry_free_text(self, flags: tool_sets.ToolSetFlags) -> None:
        """Every value is a fixed identifier, a boolean, an integer or a closed-enum member.

        Nothing operator-supplied reaches a record, so there is no channel a secret could travel
        down.
        """
        for record in tool_sets.resolve(flags, self._COUNTS).records:
            assert record.set_id in tool_sets.ALL_TOOL_SET_IDS
            assert record.flag == tool_sets.FLAG_KEY_FOR[record.set_id]
            assert isinstance(record.registered, bool)
            assert isinstance(record.tool_count, int)
            assert record.reason is None or isinstance(record.reason, ToolSetDisabledReason)


class TestAuthzDenyByDefault:
    """For any tool name, a tool absent from the registry is refused.

    `test_authz.py::TestDenyByDefault` covers five hand-picked strings (`""`, `"*"`, `"sl1_*"`,
    `"SL1_SIMULATE_EVENT"`, `" sl1_clear_event"`). An example table only contains the attempts
    someone thought of, so the universal claim is generated here.
    """

    @given(st.text(max_size=60))
    def test_any_name_outside_the_registry_is_refused(self, candidate: str) -> None:
        """The universal claim, generated rather than enumerated.

        `assume` excludes the real names, so the property is about everything else, and Hypothesis
        reports the seed on failure, which an example table cannot.
        """
        assume(candidate not in authz.TOOL_REGISTRY)
        with pytest.raises(authz.DbToolNotRegistered) as excinfo:
            authz.registry_entry(candidate)
        # The refusal must name what was refused, or an operator cannot diagnose a mis-registration.
        assert excinfo.value.tool_name == candidate

    @given(st.sampled_from(sorted(authz.TOOL_REGISTRY)))
    def test_a_registered_name_is_accepted_and_a_withheld_one_is_not(self, name: str) -> None:
        """Being in the inventory is not permission to run.

        A withheld tool (``registers=False``, such as `list_capabilities` and
        `refresh_capability_map`) must be refused just as an unknown one is. A deny-everything
        registry would pass the property above, so registered names must also be accepted.
        """
        entry = authz.TOOL_REGISTRY[name]
        if entry.registers:
            assert authz.registry_entry(name) is entry
        else:
            with pytest.raises(authz.DbToolNotRegistered):
                authz.registry_entry(name)

    @given(st.text(min_size=1, max_size=30))
    def test_case_and_whitespace_variants_of_real_names_are_refused(self, noise: str) -> None:
        """The near-miss class, which is where a permissive registry would actually fail.

        A wildcard, a fallback, or a casefolded lookup would all pass a test using entirely random
        strings while admitting ``SL1_SIMULATE_EVENT`` or `` sl1_simulate_event``. Generating
        perturbations of real names attacks the lookup rather than the vocabulary.
        """
        real = next(iter(authz.TOOL_REGISTRY))
        for variant in (real.upper(), f"{noise}{real}", f"{real}{noise}", f" {real} "):
            assume(variant not in authz.TOOL_REGISTRY)
            with pytest.raises(authz.DbToolNotRegistered):
                authz.registry_entry(variant)

    @given(st.text(max_size=40))
    def test_the_refusal_type_is_stable_for_every_input(self, candidate: str) -> None:
        """One distinguishable typed error, never a builtin and never a bare `Exception`.

        `sl1_tool_boundary` translates `PowerPackMcpError` and nothing else, so a `KeyError`
        escaping from here would reach the caller unhandled.
        """
        assume(candidate not in authz.TOOL_REGISTRY)
        try:
            authz.registry_entry(candidate)
        except authz.DbToolNotRegistered:
            pass
        except Exception as exc:  # noqa: BLE001 - the assertion IS that this never happens
            pytest.fail(f"registry_entry raised {type(exc).__name__}, not DbToolNotRegistered")


class TestSqlConstruction:
    """Properties of SQL statement construction, the primary control against injection.

    Nothing between these statements and `master.*` inspects a value again. Statement construction
    is kept dependency-free so these can run without an appliance.

    The load-bearing property is `test_no_operand_can_reach_statement_text`: it asserts the
    separation, not the escaping. Escaping can be got subtly wrong; separation is structural.
    """

    _ALLOWED_COLUMNS = frozenset({"device_name", "device_id", "class_name"})

    @given(hostile_sql_operands())
    def test_no_operand_can_reach_statement_text(self, operand: str) -> None:
        """A caller's value lands in ``params``, never in ``sql``.

        Asserted by holding the statement text constant across every generated operand. An
        implementation that concatenated would vary the text and fail here immediately, however
        careful its quoting was.
        """
        sql = "SELECT device_id FROM master.device WHERE device_name LIKE %s ESCAPE '\\'"
        stmt = Statement(sql, (like_contains(operand),))
        assert stmt.sql == sql
        assert len(stmt.params) == 1

    @given(hostile_sql_operands())
    def test_the_rendered_statement_never_carries_a_bare_percent(self, operand: str) -> None:
        """No generated operand can introduce a bare ``%`` into statement text.

        A bare ``%`` in statement text returns empty rows rather than an error on this platform.
        """
        stmt = Statement("SELECT a FROM t WHERE n LIKE %s", (like_contains(operand),))
        assert re.sub(r"%s\b", "", stmt.sql).count("%") == 0

    @given(hostile_sql_operands())
    def test_like_wildcards_in_an_operand_are_always_escaped(self, operand: str) -> None:
        """A caller's ``%`` or ``_`` must not widen the rows matched.

        Checked by counting: every wildcard surviving in the operand body is preceded by the escape
        character. Counting rather than pattern-matching, because a regex here would re-implement
        the very escaping it is meant to audit.
        """
        body = like_contains(operand)[1:-1]
        for index, char in enumerate(body):
            if char in "%_":
                preceding = len(body[:index]) - len(body[:index].rstrip(LIKE_ESCAPE_CHAR))
                assert preceding % 2 == 1, f"unescaped {char!r} at {index} in {body!r}"

    @given(hostile_sql_operands())
    def test_checked_identifier_never_returns_a_value_outside_the_allowlist(
        self, candidate: str
    ) -> None:
        """An identifier cannot be parameterised, so membership is the only control."""
        try:
            returned = checked_identifier(candidate, self._ALLOWED_COLUMNS, argument="sort_by")
        except (ValidationBlocked, ValueError):
            return
        assert returned in self._ALLOWED_COLUMNS

    @given(st.lists(hostile_sql_operands(), min_size=1, max_size=6))
    def test_placeholder_count_always_equals_parameter_count(self, operands: list[str]) -> None:
        """The ``(sql, params)`` pair stays internally consistent.

        MySQLdb's ``%``-format failure for a mismatch is swallowed by the platform cursor, so an
        off-by-one presents as no rows.
        """
        stmt = Statement(
            f"SELECT a FROM t WHERE b IN ({placeholders(len(operands))})", tuple(operands)
        )
        assert stmt.placeholder_count == len(operands) == len(stmt.params)

    @given(hostile_sql_operands())
    def test_an_operand_is_carried_verbatim_apart_from_escaping(self, operand: str) -> None:
        """Escaping must not lose data.

        A rewrite that silently stripped characters would match different rows than the original,
        which is scope drift in the narrowing direction and just as wrong.
        """
        unescaped = like_contains(operand)[1:-1].replace(LIKE_ESCAPE_CHAR * 2, LIKE_ESCAPE_CHAR)
        for char in ("%", "_"):
            unescaped = unescaped.replace(LIKE_ESCAPE_CHAR + char, char)
        assert unescaped == operand


class TestStatementBuilders:
    """Properties of the statement builders in `sl1_db_statements`, over hostile input.

    `TestSqlConstruction` verifies `sql.Statement` and its helpers; these verify the builders that
    call them. There is no downstream check: if a builder renders a caller's `%` into statement
    text, the tool reports "nothing found" with no exception anywhere. The exhaustive sweep of every
    builder is `ALL_BUILDERS` in `tests/unit/test_sl1_db_statements.py`.

    Every property asserts on the rendered statement. `Statement`'s constructor already raises on a
    literal `%`, so a test that merely called the builder would test the constructor again.
    """

    # Same regex as `sql._BAD_PERCENT`, re-derived deliberately: importing it would make these
    # properties agree with the production regex even if that regex were wrong.
    BAD_PERCENT: ClassVar[re.Pattern[str]] = re.compile(r"%(?!s\b)")

    @given(hostile_sql_operands(), hostile_sql_operands(), hostile_sql_operands())
    def test_no_hostile_event_text_ever_reaches_statement_text(
        self, message: str, sub_message: str, device_name: str
    ) -> None:
        """The caller-controlled event text in `sl1_simulate_event` is never interpolated.

        ``message`` is free text a caller supplies, so this is the realistic attack surface.
        """
        statement = dbst.insert_active_event(
            device_id=1,
            device_name=device_name,
            source=6,
            message=message,
            sub_message=sub_message,
            threshold="",
            severity=3,
            event_policy=0,
        )
        assert self.BAD_PERCENT.search(statement.sql) is None
        assert statement.placeholder_count == len(statement.params)
        # The values are present as parameters. Asserting only the absence above would also pass if
        # the builder silently dropped them.
        assert message in statement.params
        assert sub_message in statement.params
        assert device_name in statement.params

    @given(hostile_sql_operands())
    def test_a_hostile_category_name_stays_a_parameter(self, category: str) -> None:
        """A hostile category name takes the `cat_name` branch and is bound.

        `insert_device_class` chooses between two column comparisons (a shape decision) and then
        binds the value.
        """
        statement = dbst.insert_device_class(
            class_guid="A" * 32,
            family_guid="B" * 32,
            class_name="c",
            description="d",
            category=category,
            device_type="physical",
            is_snmp=False,
            root_device=False,
            powerpack_guid=None,
            class_identifier_1="",
            class_identifier_2="",
        )
        assert self.BAD_PERCENT.search(statement.sql) is None
        assert statement.placeholder_count == len(statement.params)
        stripped = category.strip()
        # `isdecimal()`, not `isdigit()`: the predicate must mirror the builder's branch selector or
        # it asserts nothing. Characters such as "²" pass `isdigit()` but crash `int()`, and with
        # `isdigit()` here both assertions would be skipped for exactly those inputs. Change the two
        # together.
        if not stripped.isdecimal():
            assert "dc.cat_name = %s" in statement.sql
            assert stripped in statement.params

    @given(hostile_sql_operands())
    def test_a_hostile_dynamic_app_name_stays_a_parameter(self, name: str) -> None:
        for statement in (
            dbst.align_dynamic_app(class_type=1, dynamic_app_id=None, name=name),
            dbst.read_dynamic_app_alignment(dynamic_app_id=None, name=name),
        ):
            assert self.BAD_PERCENT.search(statement.sql) is None
            assert name in statement.params

    @given(hostile_sql_operands())
    def test_a_hostile_class_guid_stays_a_parameter(self, guid: str) -> None:
        for statement in (
            dbst.resolve_class_type_by_guid(guid),
            dbst.read_device_class_by_guid(guid),
        ):
            assert self.BAD_PERCENT.search(statement.sql) is None
            assert statement.params == (guid,)

    @given(hostile_sql_operands(), hostile_sql_operands())
    def test_hostile_update_values_never_reach_statement_text(
        self, class_name: str, description: str
    ) -> None:
        """In the dynamic ``SET`` list, columns come from the allowlist and values are bound."""
        statement = dbst.update_device_class(
            class_guid="A" * 32,
            changes={"class_name": class_name, "description": description},
            category_fid=None,
            clear_powerpack=False,
            powerpack_guid=None,
        )
        assert self.BAD_PERCENT.search(statement.sql) is None
        # The rendered SET list contains only allowlisted column names and placeholders, no caller
        # text at all.
        set_clause = statement.sql.split(" SET ", 1)[1].split(" WHERE ", 1)[0]
        assert set_clause == "class = %s, descript = %s, date_edit = NOW()"
        assert class_name in statement.params
        assert description in statement.params

    @given(hostile_sql_operands())
    def test_an_unallowlisted_column_is_always_refused(self, column: str) -> None:
        """No generated column name outside the allowlist is ever accepted.

        Without the allowlist this argument would be interpolated into the ``SET`` clause. The
        `assume` only skips the seven legitimate names.
        """
        assume(column not in dbst._UPDATABLE_COLUMNS)
        with pytest.raises(ValueError, match="not an updatable device-class field"):
            dbst.update_device_class(
                class_guid="A" * 32,
                changes={column: "v"},
                category_fid=None,
                clear_powerpack=False,
                powerpack_guid=None,
            )

    @given(hostile_sql_operands())
    def test_no_generated_input_produces_a_multi_statement_string(self, operand: str) -> None:
        """`run_unit` sends one ``execute()`` per statement, so a builder must yield exactly one.

        A caller-supplied `;` reaching statement text would turn one statement into two, and with
        ``CLIENT_MULTI_STATEMENTS`` set on this platform the second would run.
        """
        statements = (
            dbst.resolve_root_did_by_name(operand),
            dbst.resolve_powerpack_guid_by_name(operand),
            dbst.resolve_class_type_by_guid(operand),
            dbst.read_device_class_by_guid(operand),
        )
        for statement in statements:
            assert ";" not in statement.sql
            assert statement.params == (operand,)

    @given(st.integers(min_value=-(2**63), max_value=2**63 - 1))
    def test_integer_identifiers_are_always_bound_never_formatted(self, value: int) -> None:
        """Even an int is bound, because "it is only a number" is how an int becomes a string.

        The value must appear in ``params`` and the SQL text must be the same for every input; a
        builder that formatted the int would produce varying text. (Checking
        ``str(value) not in sql`` would be wrong: ``LIMIT 1`` makes ``1`` a false hit.)
        """
        builders: tuple[tuple[Callable[[int], Statement], tuple[int, ...]], ...] = (
            (dbst.read_root_summary, (value, value)),
            (dbst.read_component_map, (value,)),
            (dbst.read_class_alignment, (value,)),
            (dbst.read_aligned_dynamic_apps, (value,)),
            # The dynamic-collection builders. Keyword-only, so adapted to the same one-int shape.
            # `dispatch_dynamic_collection` is the exemption and has its own property below.
            (lambda identifier: dbst.resolve_device_collector(device_id=identifier), (value,)),
            (lambda _identifier: dbst.last_insert_id(), ()),
            (
                lambda identifier: dbst.record_device_tool_run(
                    device_id=identifier,
                    module_id=identifier,
                    proc_id=identifier,
                    user_id=identifier,
                ),
                (value, value, value, dbst.COLLECTION_TOOLBOX_ID, value),
            ),
            (
                lambda identifier: dbst.read_collection_output(
                    proc_id=identifier, after_id=identifier
                ),
                (value, value),
            ),
            (lambda identifier: dbst.read_collection_job(proc_id=identifier), (value,)),
        )
        for build, expected_params in builders:
            statement = build(value)
            reference = build(0)
            assert statement.params == expected_params
            assert statement.sql == reference.sql, "statement text varies with the parameter value"
            assert self.BAD_PERCENT.search(statement.sql) is None

    @given(
        st.integers(min_value=1, max_value=2**31 - 1),
        st.integers(min_value=1, max_value=2**31 - 1),
        st.integers(min_value=1, max_value=2**31 - 1),
    )
    def test_the_dispatch_command_string_is_the_one_exemption_and_stays_well_formed(
        self, device_id: int, dynamic_app_id: int, module_id: int
    ) -> None:
        """The single exemption from "every int is a bound parameter", and why it is safe.

        `dispatch_dynamic_collection` formats ``device_id`` and ``dynamic_app_id`` into the command
        string that becomes ``params[0]``. ``master.process_admin_remote_policy`` takes a command
        line, so those two IDs cannot be separate placeholders. ``module_id``, which the procedure
        takes as an argument, is bound.

        It is safe for two reasons, neither of which is "ints are harmless":

        * There is no shell on the far side. The Remote Toolbox ``shlex.split``s the payload into
          an argv list and execs it, so a metacharacter would be a literal argv element.
        * No caller-supplied string can reach it. Every argument is an ``int`` this service
          resolved: the device via REST, the collector from ``collector_state.V_device``, the actor
          from nginx.

        Asserted over generated ints: the statement text never varies, the sentinel stays at
        offset 0, both IDs survive into the command in argv order, the argv length is fixed (an int
        cannot add a token), and the placeholder/parameter pair stays balanced.
        """
        statement = dbst.dispatch_dynamic_collection(
            device_id=device_id, dynamic_app_id=dynamic_app_id, module_id=module_id
        )
        reference = dbst.dispatch_dynamic_collection(device_id=0, dynamic_app_id=0, module_id=0)
        assert statement.sql == reference.sql, "statement text varies with the parameter value"
        assert self.BAD_PERCENT.search(statement.sql) is None
        assert statement.placeholder_count == len(statement.params) == 5
        assert statement.params[1:] == (
            "SILO1138",
            module_id,
            dbst.COLLECTION_TOOLBOX_ID,
            dynamic_app_id,
        )

        command = statement.params[0]
        assert isinstance(command, str)
        # The toolbox's decode, replayed: ``rpartition`` with ``ok and not junk``. A "contains the
        # sentinel" check would pass a prefixed payload, which the toolbox refuses with
        # ``state=4, returncode=99``.
        junk, separator, _ = command.rpartition("SILOPROC ")
        assert separator == "SILOPROC "
        assert junk == ""
        argv = shlex.split(command)
        # The argv length and trailing tokens are literals here, not read from the command
        # constant, so update them if the command changes. 10 tokens: SILOPROC, env, two
        # SILO_/SF_DEBUG assignments, the script, two flags, then ``-p <did> <app_id>``.
        assert len(argv) == 10, argv
        assert argv[-3:] == ["-p", str(device_id), str(dynamic_app_id)]


# ---- The authorization gate: invariants and stateful properties ----
#
# The pure decision function is the part least likely to be wrong; the dangerous behaviours are
# stateful: TTL expiry, and cross-principal isolation across a call sequence. Both are covered.
#
# The coroutines are driven with `asyncio.run` inside sync `@given` tests. Mixing `anyio` with
# Hypothesis buys nothing here, and each example gets a fresh loop, which is what the isolation
# properties want anyway.


class _MutableClock:
    """A clock a property advances by hand, so no test sleeps."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _FixedSource:
    def __init__(self, hooks: frozenset[str]) -> None:
        self.hooks = hooks
        self.calls = 0

    async def hooks_for(self, credential: object) -> frozenset[str]:  # noqa: ARG002
        self.calls += 1
        return self.hooks


class TestParseHookPayloadProperties:
    """Invariants of the pure, total function `hook_source.parse_hook_payload`."""

    @given(hook_payloads())
    def test_the_result_is_always_a_frozenset_of_strings(self, payload: list[str]) -> None:
        result = parse_hook_payload(payload)
        assert isinstance(result, frozenset)
        assert all(isinstance(h, str) for h in result)

    @given(hook_payloads())
    def test_deduplication_never_grows_the_answer(self, payload: list[str]) -> None:
        """Size bound. The payload is a bag, so ``<=`` rather than ``==`` is the true relation."""
        assert len(parse_hook_payload(payload)) <= len(payload)

    @given(hook_payloads())
    def test_elements_are_preserved_in_both_directions(self, payload: list[str]) -> None:
        """Element preservation. Nothing is invented and nothing valid is dropped."""
        result = parse_hook_payload(payload)
        assert result == frozenset(payload)

    @given(hook_payloads())
    def test_it_is_idempotent_over_its_own_output(self, payload: list[str]) -> None:
        once = parse_hook_payload(payload)
        assert parse_hook_payload(sorted(once)) == once

    @given(hook_payloads())
    def test_an_empty_result_only_ever_means_an_empty_input(self, payload: list[str]) -> None:
        """An empty result is legitimate only for an empty input.

        Reading "no hooks retrieved" as "no restrictions apply" would turn a transient network error
        into a complete authorization bypass. Every other route to empty must raise, which
        `test_every_deny_branch_raises` covers.
        """
        if not parse_hook_payload(payload):
            assert payload == []

    @pytest.mark.parametrize("branch", sorted(hook_deny_branches))
    def test_every_deny_branch_raises(self, branch: str) -> None:
        """Checked per named branch, so a failure says which one regressed."""

        @given(hook_deny_branches[branch])
        def check(body: object) -> None:
            with pytest.raises(Sl1MalformedResponse):
                parse_hook_payload(body)

        check()

    def test_the_deny_branch_table_is_complete(self) -> None:
        """Every rejection `parse_hook_payload` can perform appears in the generator table.

        A branch silently dropped from the table would weaken the suite without failing anything,
        so its membership is asserted rather than assumed.
        """
        assert set(hook_deny_branches) == {
            "not_a_list",
            "blank_element",
            "non_string_element",
            "over_long_element",
            "over_cap",
        }


class TestTheDecisionProperties:
    """Properties of the gate's decision. Monotonicity is the half an example table misses."""

    _TOOL: ClassVar[str] = "sl1_create_device_class"

    def _allows(self, granted: frozenset[str]) -> bool:
        gate = AuthorizationGate(
            cache=HookCache(_FixedSource(granted), clock=lambda: 0.0),
            credential_source=lambda: LceCredential(SecretStr("Basic dXNlcjpwYXNz")),
        )

        class _Dispatch:
            """`CallNext` is a callable class, so a bare ``async def`` does not match it
            structurally under `mypy --strict`. Same shape `test_authz_gate` uses.
            """

            def __init__(self) -> None:
                self.calls = 0

            async def __call__(self, context: object) -> ToolResult:  # noqa: ARG002
                self.calls += 1
                return ToolResult(structured_content={"ok": True})

        dispatch = _Dispatch()

        async def run() -> None:
            import powerpack_mcp.tools.sl1_db_pipeline as pipeline_module

            original = pipeline_module.actor_user_id
            pipeline_module.actor_user_id = lambda: 4  # type: ignore[assignment]
            try:
                await gate.on_call_tool(
                    MiddlewareContext(
                        message=mt.CallToolRequestParams(name=self._TOOL, arguments={}),
                        method="tools/call",
                    ),
                    dispatch,  # type: ignore[arg-type]
                )
            finally:
                pipeline_module.actor_user_id = original  # type: ignore[assignment]

        asyncio.run(run())
        return dispatch.calls == 1

    @given(st.frozensets(hook_ids(), max_size=6))
    def test_it_allows_exactly_when_the_requirement_is_a_subset(
        self, granted: frozenset[str]
    ) -> None:
        required = authz.TOOL_REGISTRY[self._TOOL].required_hooks
        assert self._allows(granted) == (required <= granted)

    @given(st.frozensets(hook_ids(), max_size=6), hook_ids())
    def test_granting_an_extra_hook_never_turns_allow_into_deny(
        self, granted: frozenset[str], extra: str
    ) -> None:
        """Monotone in ``granted``: a caller given more rights must not lose access.

        This catches a comparison written backwards or as an equality, both of which an example
        table using the exact required set would pass.
        """
        if self._allows(granted):
            assert self._allows(granted | {extra})

    @given(st.frozensets(hook_ids(), max_size=6))
    def test_removing_a_required_hook_never_turns_deny_into_allow(
        self, granted: frozenset[str]
    ) -> None:
        """Monotone in ``required``: narrowing the grant can only ever deny more."""
        required = authz.TOOL_REGISTRY[self._TOOL].required_hooks
        for hook in required:
            assert not self._allows(granted - {hook})


class TestTheMappingProperties:
    """Totality and deny-by-default of the tool-to-hook mapping, in the shape of
    `TestAuthzDenyByDefault`.
    """

    def test_the_mapping_is_total_over_the_gated_surface(self) -> None:
        for name in authz.sql_tool_names():
            assert authz.TOOL_REGISTRY[name].required_hooks

    def test_no_mapping_is_empty(self) -> None:
        """``set().issubset(anything)`` is always ``True``: `lce_service`'s one fail-open."""
        for entry in authz.TOOL_REGISTRY.values():
            if is_gated(entry.name):
                assert entry.required_hooks != frozenset()

    @given(required_hook_sets())
    def test_an_empty_requirement_would_allow_everyone(self, granted: frozenset[str]) -> None:
        """Assert the hazard that the non-empty mapping guards against.

        This tests the set-theoretic fact that makes an empty requirement dangerous, which is why
        `_check_set_assignment` rejects one at import.
        """
        assert frozenset() <= granted

    @given(st.text(min_size=1, max_size=40))
    def test_a_name_outside_the_registry_is_never_gated(self, name: str) -> None:
        assume(name not in authz.TOOL_REGISTRY)
        assert not is_gated(name)


class TestTheRefusalDisclosesNothing:
    """A refusal names the required hooks and nothing the caller holds, with a non-vacuity guard."""

    @given(st.frozensets(hook_ids(), min_size=1, max_size=8))
    def test_the_payload_discloses_exactly_the_required_set_and_nothing_else(
        self, granted: frozenset[str]
    ) -> None:
        """Compare disclosed values, not rendered text.

        A substring check over ``repr(payload)`` gives false positives: ``DEV_CLASS`` is a
        substring of the required ``SYS_CUSTOM_DEV_CLASS_PAGE``, and the ``ci`` profile's larger
        example count finds that.
        """
        required = authz.TOOL_REGISTRY["sl1_create_device_class"].required_hooks
        assume(not required <= granted)
        error = build_error_payload(AuthorizationDenied("sl1_create_device_class", required))[
            "error"
        ]
        raw = error.get("required_hooks")
        disclosed = set(raw) if isinstance(raw, list) else set()
        assert disclosed == set(required), "only the required set is named"
        assert not (granted - required) & disclosed, "nothing the caller merely holds is named"
        for key, value in error.items():
            if key != "required_hooks" and isinstance(value, list):
                assert not set(value) & granted, f"{key} smuggled a granted hook out"

    @given(st.frozensets(hook_ids(), min_size=1, max_size=4))
    def test_the_check_is_not_vacuous(self, required: frozenset[str]) -> None:
        """The risk in an absence property is that everything is absent.

        If the payload never contained any hook, the property above would pass while proving
        nothing. This asserts the required set is present, so the absence of the granted set is a
        real distinction rather than an empty payload.
        """
        payload = repr(build_error_payload(AuthorizationDenied("t", required)))
        for hook in required:
            assert hook in payload


class TestHookCacheStatefulProperties:
    """Stateful properties of `HookCache` that the pure tests cannot reach."""

    @given(principals(), hook_payloads(), st.floats(min_value=0.0, max_value=59.0))
    def test_a_fresh_entry_is_served_without_a_second_fetch(
        self, principal: tuple[int, str], payload: list[str], elapsed: float
    ) -> None:
        """Checked over the whole freshness interval rather than one chosen instant."""
        account_id, header = principal
        source = _FixedSource(frozenset(payload))
        clock = _MutableClock()
        cache = HookCache(source, clock=clock)
        cred = LceCredential(SecretStr(header))

        async def run() -> None:
            first = await cache.hooks_for_account(account_id, cred)
            clock.now += elapsed
            second = await cache.hooks_for_account(account_id, cred)
            assert first == second

        asyncio.run(run())
        assert source.calls == 1

    @given(principals(), st.floats(min_value=60.0, max_value=600.0))
    def test_a_stale_entry_is_never_served_past_the_ttl(
        self, principal: tuple[int, str], elapsed: float
    ) -> None:
        """Checked over the whole staleness interval.

        The revoked set is empty, so a stale hit would be visible as the old grant surviving.
        """
        account_id, header = principal
        source = _FixedSource(frozenset({"DEV_CLASS_EDIT"}))
        clock = _MutableClock()
        cache = HookCache(source, clock=clock)
        cred = LceCredential(SecretStr(header))

        async def run() -> None:
            await cache.hooks_for_account(account_id, cred)
            source.hooks = frozenset()  # revoked in SL1
            clock.now += elapsed
            assert await cache.hooks_for_account(account_id, cred) == frozenset()

        asyncio.run(run())
        assert source.calls == 2

    @given(principals(), principals())
    def test_no_call_sequence_lets_one_principal_use_anothers_grants(
        self, first: tuple[int, str], second: tuple[int, str]
    ) -> None:
        """Checked over generated pairs of principals.

        `principals()` draws Basic and Bearer credentials, so the case that rules out
        `username_from_authorization` as a cache key (it returns ``None`` for every non-Basic
        scheme, collapsing all API-key callers onto one entry) is generated rather than reasoned
        about.
        """
        (id_a, header_a), (id_b, header_b) = first, second
        assume(id_a != id_b)
        privileged = frozenset({"SYS_CUSTOM_DEV_CLASS_PAGE", "DEV_CLASS_EDIT"})

        class PerAccount:
            def __init__(self) -> None:
                self.next: frozenset[str] = frozenset()
                self.calls = 0

            async def hooks_for(self, credential: object) -> frozenset[str]:  # noqa: ARG002
                self.calls += 1
                return self.next

        source = PerAccount()
        cache = HookCache(source, clock=_MutableClock())

        async def run() -> None:
            source.next = privileged
            assert await cache.hooks_for_account(id_a, LceCredential(SecretStr(header_a))) == (
                privileged
            )
            source.next = frozenset()
            restricted = await cache.hooks_for_account(id_b, LceCredential(SecretStr(header_b)))
            assert restricted == frozenset(), "the second principal inherited the first's grants"

        asyncio.run(run())
        assert source.calls == 2, "each principal must be resolved on its own"

    @given(principals(), hook_payloads())
    def test_the_cache_never_holds_credential_material(
        self, principal: tuple[int, str], payload: list[str]
    ) -> None:
        """The key is a public account ID and the value is hook IDs.

        Keying on a credential fingerprint such as ``sha256(password)`` is ruled out. Asserted by
        inspecting the stored entry against the credential's own bytes.
        """
        account_id, header = principal
        cache = HookCache(_FixedSource(frozenset(payload)), clock=_MutableClock())

        async def run() -> None:
            await cache.hooks_for_account(account_id, LceCredential(SecretStr(header)))

        asyncio.run(run())
        stored = repr(cache._entries)
        assert header not in stored
        assert "Bearer" not in stored
        assert "Basic" not in stored
        assert list(cache._entries) == [account_id]
