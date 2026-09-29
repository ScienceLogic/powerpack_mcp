"""
Error Hierarchy Tests

This module tests ``powerpack_mcp.errors``: the single exception hierarchy, the closed
vocabularies that monitoring and callers key on, error payload rendering, and the rule that no
error discloses a stack trace, path, version or configuration value.
"""

from __future__ import annotations

import json

import pytest

from powerpack_mcp.errors import (
    MAX_LCE_BODY_CHARS,
    REDACTED,
    ConfigurationError,
    DbDeadlineExceeded,
    ErrorType,
    FindingCode,
    LceHttpError,
    LceMalformedResponse,
    LceUnreachable,
    LintRule,
    LogEvent,
    PowerPackMcpError,
    SchemaTrimError,
    Sl1GraphQlError,
    Sl1HttpError,
    Sl1MalformedResponse,
    Sl1ResponseTooLarge,
    Sl1Unreachable,
    ToolSetDisabledReason,
    ValidationBlocked,
    ValidationFinding,
    build_error_payload,
    finding_code_for,
    sanitize_lce_body,
)


class TestHierarchy:
    @pytest.mark.parametrize(
        "exc",
        [
            ValidationBlocked([]),
            LceHttpError(500, {}),
            LceUnreachable("localhost"),
            LceMalformedResponse(),
            ConfigurationError("bad"),
        ],
    )
    def test_every_error_shares_one_base(self, exc: Exception) -> None:
        """A single base means the tool boundary has one `except` clause to catch."""
        assert isinstance(exc, PowerPackMcpError)

    def test_the_three_lce_failures_are_distinguishable(self) -> None:
        """A caller can branch on the failure kind programmatically."""
        classes = {LceHttpError, LceUnreachable, LceMalformedResponse}
        for cls in classes:
            others = classes - {cls}
            assert not any(issubclass(cls, other) for other in others)


class TestConstructionTimeRedaction:
    """No error carries a stack trace, path, version or configuration value at construction."""

    def test_lce_http_error_message_carries_only_the_status(self) -> None:
        error = LceHttpError(404, {"detail": "an internal /opt/em7 path and secret"})
        assert str(error) == "LCE returned HTTP 404"
        # The body is preserved as data, but is not rendered into the message.
        assert "opt/em7" not in str(error)
        assert error.lce_body == {"detail": "an internal /opt/em7 path and secret"}

    def test_lce_unreachable_carries_the_host_and_nothing_else(self) -> None:
        """Not the resolved IP, not the port, not the library's exception text."""
        error = LceUnreachable("lce-01.example.internal")
        assert error.target_host == "lce-01.example.internal"
        assert str(error) == "LCE at lce-01.example.internal is unreachable"

    def test_validation_blocked_preserves_every_finding(self) -> None:
        """Every finding is reported, not just the first."""
        findings = [
            ValidationFinding("a[0].guid", FindingCode.CHILD_GUID, "bad guid"),
            ValidationFinding("a[1].type", FindingCode.THRESHOLD_TYPE, "bad type"),
        ]
        error = ValidationBlocked(findings)
        assert len(error.findings) == 2
        assert isinstance(error.findings, tuple), "must be immutable"


class TestBuildErrorPayload:
    """Example-based coverage of the payload builder."""

    def test_validation_blocked_carries_details_and_no_lce_status(self) -> None:
        payload = build_error_payload(
            ValidationBlocked([ValidationFinding("a.guid", FindingCode.CHILD_GUID, "not hex")])
        )
        error = payload["error"]
        assert error["type"] == "validation_blocked"
        assert error["details"] == [{"path": "a.guid", "rule": "child_guid", "message": "not hex"}]
        assert "lce_status" not in error

    def test_lce_http_error_carries_lce_status_and_no_details(self) -> None:
        error = build_error_payload(LceHttpError(422, {"x": 1}))["error"]
        assert error["type"] == "lce_http_error"
        assert error["lce_status"] == 422
        assert "details" not in error

    def test_lce_http_error_carries_the_lce_supplied_body(self) -> None:
        """The message tells the caller to inspect the LCE-supplied body, so it must be present."""
        error = build_error_payload(
            LceHttpError(404, {"error": "Dynamic Application Not Found", "matches": []})
        )["error"]
        assert error["lce_body"] == {"error": "Dynamic Application Not Found", "matches": []}
        assert "the LCE-supplied body" in str(error["message"])

    @pytest.mark.parametrize(
        ("exc", "expected"),
        [
            (LceUnreachable("localhost"), "lce_unreachable"),
            (LceMalformedResponse(), "lce_malformed_response"),
            (ConfigurationError("LISTEN_HOST must be loopback"), "internal_error"),
        ],
    )
    def test_remaining_types_map_to_the_closed_vocabulary(
        self, exc: PowerPackMcpError, expected: str
    ) -> None:
        error = build_error_payload(exc)["error"]
        assert error["type"] == expected
        assert "lce_status" not in error
        assert "details" not in error

    def test_configuration_error_message_is_never_echoed(self) -> None:
        """It can never legitimately reach a caller, and if it did it must not name the key."""
        error = build_error_payload(ConfigurationError("LCE_CREDENTIAL is not set"))["error"]
        assert "LCE_CREDENTIAL" not in str(error["message"])

    def test_every_message_states_what_to_do(self) -> None:
        """A message that only states what was wrong is incomplete."""
        for exc in (
            ValidationBlocked([]),
            LceHttpError(500, ""),
            LceUnreachable("h"),
            LceMalformedResponse(),
        ):
            message = str(build_error_payload(exc)["error"]["message"])
            assert any(
                word in message.lower() for word in ("correct", "retry", "confirm", "inspect")
            )

    def test_no_payload_contains_a_traceback_or_path(self) -> None:
        """The service must not disclose its own internals.

        ``lce_body`` is surfaced as LCE sent it, so a path LCE itself returned may appear there.
        The fields this service authors are checked strictly; the LCE-supplied field is checked
        only for a traceback, which could not originate at LCE.
        """
        for exc in (LceHttpError(500, "/opt/em7/services/x"), LceUnreachable("h")):
            payload = build_error_payload(exc)
            authored = dict(payload["error"])
            authored.pop("lce_body", None)
            assert "Traceback" not in repr(authored)
            assert "/opt/em7" not in repr(authored)
            # A stack trace could not originate at LCE, so this holds over the whole payload.
            assert "Traceback" not in repr(payload)


class TestClosedVocabularies:
    def test_log_event_vocabulary_is_exactly_the_fifteen_designed_values(self) -> None:
        """Monitoring keys on ``event``, never on message text, so the set is pinned.

        A rename or an unreviewed addition fails here. Some members look redundant but are not:

        - ``db_query_timeout`` and ``db_await_abandoned`` are separate because a client-side
          deadline abandons the await while the query keeps running. The first is a capacity
          signal; the second means a thread and a connection are still busy.
        - ``master_write_audited`` is one event with an ``outcome`` field, not a reuse of
          ``write_committed``. A key that fires only on success cannot cover every outcome, and
          sibling keys would make a missing record ambiguous.
        """
        assert {e.value for e in LogEvent} == {
            "validation_blocked",
            "lce_auth_denied",
            "tls_verification_relaxed",
            "startup_failed",
            "unhandled_exception",
            "write_committed",
            "concurrency_limited",
            "tool_sets_registered",
            "request_deadline_exceeded",
            "sl1_passthrough_invoked",
            "db_query_timeout",
            "db_await_abandoned",
            # A third DB event: ``db_query_timeout`` means the server stopped a running query,
            # this means no query was issued because the deadline was already spent. A single key
            # would send an operator to tune the statement timeout, which is the wrong knob.
            "db_deadline_exceeded",
            "master_write_audited",
            # The authorization gate's refusal. Authorization failures need their own key so they
            # can be alerted on; this is the only event that is one.
            "authorization_denied",
        }

    def test_lint_rule_vocabulary(self) -> None:
        assert {r.value for r in LintRule} == {"child_guid", "threshold_type"}


class TestFindingCode:
    """The caller-facing finding vocabulary."""

    def test_is_a_published_contract_with_six_codes(self) -> None:
        """Monitoring and agent recovery key on these codes, never on message text.

        Adding a member is backward-compatible; renaming one is breaking, so this makes any change
        visible in review. Rename the test with its assertion if the count changes.
        """
        assert {c.value for c in FindingCode} == {
            "child_guid",
            "threshold_type",
            "filter_constraint",
            "request_body_size",
            "payload_depth",
            # A tool argument the caller can correct.
            "tool_argument",
        }

    def test_every_lint_rule_has_an_identically_valued_code(self) -> None:
        """`LintRule` and `FindingCode` share string values, so the wire format is stable."""
        for rule in LintRule:
            assert finding_code_for(rule).value == rule.value

    def test_finding_code_for_is_total_over_lint_rule(self) -> None:
        assert {finding_code_for(r) for r in LintRule} == {
            FindingCode.CHILD_GUID,
            FindingCode.THRESHOLD_TYPE,
        }

    def test_the_three_guard_codes_are_not_selectable_as_lints(self) -> None:
        """A descriptor cannot name a guard as a lint, because guards have no `LintRule`."""
        lint_values = {r.value for r in LintRule}
        for code in (
            FindingCode.FILTER_CONSTRAINT,
            FindingCode.REQUEST_BODY_SIZE,
            FindingCode.PAYLOAD_DEPTH,
        ):
            assert code.value not in lint_values

    def test_error_types_are_decoupled_from_class_names(self) -> None:
        """Renaming a class must not break a caller."""
        assert build_error_payload(LceHttpError(500, ""))["error"]["type"] != "LceHttpError"


def test_validation_finding_is_frozen() -> None:
    finding = ValidationFinding("p", FindingCode.CHILD_GUID, "m")
    with pytest.raises(AttributeError):
        finding.path = "other"  # type: ignore[misc]


class TestSanitizeLceBody:
    """Example-based coverage of LCE body sanitising, alongside the property tests."""

    def test_a_denylisted_key_is_redacted_at_the_top_level(self) -> None:
        assert sanitize_lce_body({"Authorization": "Basic c2VjcmV0"}) == {"Authorization": REDACTED}

    def test_a_denylisted_key_is_redacted_when_nested(self) -> None:
        """The property `RedactingFilter` could not provide: it flat-scans, this recurses."""
        result = sanitize_lce_body({"outer": {"inner": {"password": "hunter2"}}})
        assert result == {"outer": {"inner": {"password": REDACTED}}}

    def test_redaction_is_case_insensitive(self) -> None:
        """Matching is on the field name, so LCE's casing must not decide whether a secret leaks."""
        result = sanitize_lce_body({"TOKEN": "a", "Secret": "b", "api_key": "c"})
        assert result == {"TOKEN": REDACTED, "Secret": REDACTED, "api_key": REDACTED}

    def test_a_denylisted_key_loses_its_whole_value_not_just_its_leaves(self) -> None:
        """A container under a denylisted key vanishes entirely -- structure included.

        Redacting only the leaves would still disclose the shape of the secret, and for
        ``credential: {"user": ..., "pass": ...}`` the whole subtree is what must go.
        """
        assert sanitize_lce_body({"credential": {"user": "u", "pass": "p"}}) == {
            "credential": REDACTED
        }

    def test_denylisted_keys_inside_lists_are_redacted(self) -> None:
        assert sanitize_lce_body([{"cookie": "x"}, {"ok": 1}]) == [{"cookie": REDACTED}, {"ok": 1}]

    def test_an_over_long_string_is_truncated_with_an_explicit_marker(self) -> None:
        result = sanitize_lce_body("x" * (MAX_LCE_BODY_CHARS + 500))
        assert isinstance(result, str)
        assert result.startswith("x" * MAX_LCE_BODY_CHARS)
        assert result.endswith("...[truncated]")
        assert "x" * (MAX_LCE_BODY_CHARS + 1) not in result

    def test_a_string_at_the_cap_is_left_alone(self) -> None:
        """Boundary: the cap is inclusive, so an exactly-at-limit body is not marked as elided."""
        exact = "y" * MAX_LCE_BODY_CHARS
        assert sanitize_lce_body(exact) == exact

    def test_deep_nesting_is_elided_rather_than_raising(self) -> None:
        """A deeply nested body must not raise ``RecursionError``."""
        node: dict[str, object] = {}
        cursor = node
        for _ in range(500):
            child: dict[str, object] = {}
            cursor["next"] = child
            cursor = child
        rendered = json.dumps(sanitize_lce_body(node))
        assert "elided" in rendered

    def test_zero_false_and_empty_string_survive(self) -> None:
        """These are values, not absence.

        `drop_empty` removes the empty string; this sanitiser must not. The two walks have opposite
        obligations over the same data.
        """
        body = {"count": 0, "enabled": False, "note": "", "missing": None, "ratio": 0.0}
        assert sanitize_lce_body(body) == body

    def test_a_non_json_value_is_stringified_rather_than_passed_through(self) -> None:
        """The fallback branch looks unreachable to a type checker but is not.

        The body arrives from ``response.json()``, typed ``Any``, so "only JSON types appear" is a
        property of the parser, not a guarantee of this function. This test keeps the branch alive.
        """
        result = sanitize_lce_body({"weird": {1, 2}})  # type: ignore[dict-item]
        assert isinstance(result, dict)
        assert isinstance(result["weird"], str), "must be rendered, not emitted as a set"

    def test_the_top_level_type_is_preserved(self) -> None:
        assert isinstance(sanitize_lce_body({"a": 1}), dict)
        assert isinstance(sanitize_lce_body([1, 2]), list)
        assert isinstance(sanitize_lce_body("text"), str)

    def test_lce_http_error_sanitises_at_construction(self) -> None:
        """The attribute never holds the raw body, so logging the exception cannot leak it."""
        exc = LceHttpError(500, {"token": "leaked", "detail": "boom"})
        assert exc.lce_body == {"token": REDACTED, "detail": "boom"}

    @pytest.mark.parametrize(
        "exc",
        [
            LceUnreachable("localhost"),
            LceMalformedResponse(),
            ConfigurationError("bad value"),
            ValidationBlocked([ValidationFinding("p", FindingCode.CHILD_GUID, "m")]),
        ],
    )
    def test_no_other_error_type_carries_an_lce_body(self, exc: PowerPackMcpError) -> None:
        """Only an LCE HTTP error carries ``lce_body``."""
        assert "lce_body" not in build_error_payload(exc)["error"]


class TestClosedVocabulariesAreClosed:
    """`LogEvent` and `ToolSetDisabledReason` counts and members.

    Appliance monitoring keys on these stable fields rather than on message text. The counts are
    pinned so that adding a member fails here and has to be made deliberately.
    """

    def test_log_event_has_exactly_fifteen_values(self) -> None:
        """Bumping this count is meant to be deliberate; each member must earn its place.

        - ``db_deadline_exceeded`` exists because ``db_query_timeout`` alone is misleading when the
          deadline was spent before the statement was issued. MariaDB kills the query at a
          1 ms floor, the record looks true, and an operator tunes the wrong knob.
        - ``master_write_audited`` records every ``master.*`` write with actor and outcome. It
          stays alongside the authorization gate: an over-permissive mapping fails silently, and
          the write audit is the only record that it did.
        - ``authorization_denied`` is kept out of ``validation_blocked`` so that "is anyone being
          refused access they expected?" does not need message-text matching.
        """
        assert len(list(LogEvent)) == 15

    def test_the_master_write_audit_event_exists(self) -> None:
        """One event carrying an ``outcome`` field, not three events.

        A single key that always fires means a missing record says the tool did not run, rather
        than that it took a branch nobody keyed on.
        """
        assert LogEvent.MASTER_WRITE_AUDITED == "master_write_audited"

    def test_the_passthrough_audit_event_exists(self) -> None:
        """The audit trail is the only control on the arbitrary-request tool, so must be keyable."""
        assert LogEvent.SL1_PASSTHROUGH_INVOKED == "sl1_passthrough_invoked"

    def test_the_request_deadline_event_exists(self) -> None:
        """Without it a request deadline abort would be an unobservable failure."""
        assert LogEvent.REQUEST_DEADLINE_EXCEEDED == "request_deadline_exceeded"

    def test_the_tool_sets_registered_event_exists(self) -> None:
        """The only record of a tool surface widened by an upgrade, so it must be keyable."""
        assert LogEvent.TOOL_SETS_REGISTERED == "tool_sets_registered"

    def test_the_disabled_reason_vocabulary_has_exactly_three_values(self) -> None:
        assert [r.value for r in ToolSetDisabledReason] == [
            "disabled_by_configuration",
            "disabled_by_nesting",
            "prerequisite_missing",
        ]

    def test_the_three_reasons_are_distinguishable(self) -> None:
        """Operator-disabled and prerequisite-missing demand opposite responses."""
        assert len({r.value for r in ToolSetDisabledReason}) == 3

    def test_reasons_serialise_as_their_string_value(self) -> None:
        """A `StrEnum`, so a log record carries the stable string rather than ``ReasonEnum.FOO``."""
        assert json.dumps({"reason": ToolSetDisabledReason.DISABLED_BY_NESTING}) == (
            '{"reason": "disabled_by_nesting"}'
        )


class TestDbDeadlineExceededPayload:
    """The caller-facing payload for a DB deadline spent before any query was issued."""

    def test_it_has_its_own_type(self) -> None:
        error = build_error_payload(DbDeadlineExceeded(0.0))["error"]
        assert error["type"] == "db_deadline_exceeded"

    def test_it_does_not_advise_narrowing_the_query(self) -> None:
        """No query ran, so a smaller one would have been refused identically."""
        message = str(build_error_payload(DbDeadlineExceeded(0.0))["error"]["message"])
        assert "narrow" not in message.lower()
        # It must still say what to do.
        assert "retry" in message.lower()

    def test_it_is_not_shadowed_by_a_match_arm(self) -> None:
        """It is translated in `_specialised_error_payload`, ahead of the `match`.

        That ordering is load-bearing: if a broader arm caught it first, the type would silently
        become `db_error`.
        """
        assert build_error_payload(DbDeadlineExceeded(0.0))["error"]["type"] != "db_error"

    def test_no_payload_leaks_the_remainder(self) -> None:
        """The remainder is for the log record, not the caller; it is always ``0.0`` anyway."""
        error = build_error_payload(DbDeadlineExceeded(0.0))["error"]
        assert set(error.keys()) == {"type", "message"}


class TestSchemaTrimError:
    """The schema trim error; see the class docstring for why it exists."""

    def test_it_is_part_of_the_one_hierarchy(self) -> None:
        assert isinstance(SchemaTrimError("x"), PowerPackMcpError)

    def test_it_is_not_a_configuration_error(self) -> None:
        """`ConfigurationError` maps to exit 78 ("configuration error").

        A broken fastmcp internal is not an operator mistake, and reporting it as one would mislead
        whoever reads ``systemctl status``.
        """
        assert not isinstance(SchemaTrimError("x"), ConfigurationError)

    def test_it_has_no_caller_facing_error_type(self) -> None:
        """It is raised only at startup, before any caller exists, like `ConfigurationError`."""
        payload = build_error_payload(SchemaTrimError("x"))
        assert payload["error"]["type"] == "internal_error"


class TestRequestDeadlineExceededEvent:
    """The event logged when a request reaches its deadline."""

    def test_the_deadline_event_exists(self) -> None:
        """Without it a deadline abort would be an unobservable failure."""
        assert LogEvent.REQUEST_DEADLINE_EXCEEDED == "request_deadline_exceeded"

    def test_it_is_distinct_from_the_concurrency_bound_event(self) -> None:
        """`CONCURRENCY_LIMITED` means a request was turned away at the bound.

        `REQUEST_DEADLINE_EXCEEDED` means one request held its slot to the limit, which is what
        produces the other. An operator seeing only the first would tune the wrong knob.
        """
        assert LogEvent.REQUEST_DEADLINE_EXCEEDED is not LogEvent.CONCURRENCY_LIMITED

    def test_every_member_value_is_snake_case_and_unique(self) -> None:
        """Derived from the enum, so a new member is checked without updating this test."""
        values = [member.value for member in LogEvent]
        assert len(values) == len(set(values))
        for value in values:
            assert value == value.lower()
            assert " " not in value
            assert "-" not in value


class TestSl1ErrorPayloads:
    """The five SL1 failures rendering through `build_error_payload`."""

    def test_sl1_errors_are_not_shadowed_by_their_base_classes(self) -> None:
        """The assertion `_sl1_error_payload`'s docstring refers to.

        The SL1 errors subclass their LCE counterparts, and a class-pattern match is
        first-match-wins. With the SL1 cases after their bases, every SL1 failure would render as
        an LCE error and tell the caller the wrong backend broke.
        """
        assert issubclass(Sl1HttpError, LceHttpError)
        assert issubclass(Sl1Unreachable, LceUnreachable)
        assert issubclass(Sl1MalformedResponse, LceMalformedResponse)

        assert build_error_payload(Sl1HttpError(404, {}))["error"]["type"] == "sl1_http_error"
        assert build_error_payload(Sl1Unreachable("h"))["error"]["type"] == "sl1_unreachable"
        assert (
            build_error_payload(Sl1MalformedResponse())["error"]["type"] == "sl1_malformed_response"
        )

    def test_the_lce_types_are_unchanged(self) -> None:
        """Adding the SL1 members must not have changed what the LCE errors render as."""
        assert build_error_payload(LceHttpError(500, {}))["error"]["type"] == "lce_http_error"
        assert build_error_payload(LceUnreachable("h"))["error"]["type"] == "lce_unreachable"
        assert (
            build_error_payload(LceMalformedResponse())["error"]["type"] == "lce_malformed_response"
        )

    def test_the_http_error_payload_uses_sl1_prefixed_keys(self) -> None:
        """A caller branching on `lce_body` would otherwise have to guess which backend sent it."""
        payload = build_error_payload(Sl1HttpError(422, {"detail": "bad"}))["error"]
        assert payload["sl1_status"] == 422
        assert payload["sl1_body"] == {"detail": "bad"}
        assert "lce_status" not in payload
        assert "lce_body" not in payload

    def test_the_too_large_payload_reports_the_limit_and_advises_narrowing(self) -> None:
        """It carries the limit, not the bytes seen: the read aborted, so no total was known.

        Its advice differs from every other error, which is why it has its own type.
        """
        payload = build_error_payload(Sl1ResponseTooLarge(1024))["error"]
        assert payload["type"] == "sl1_response_too_large"
        assert payload["limit_bytes"] == 1024
        assert "narrow" in str(payload["message"]).lower()

    def test_the_graphql_payload_carries_the_messages(self) -> None:
        """HTTP 200 was a success, so the caller needs the errors to act on."""
        payload = build_error_payload(Sl1GraphQlError(["no field 'x'", "syntax"]))["error"]
        assert payload["type"] == "sl1_graphql_error"
        assert payload["graphql_errors"] == ["no field 'x'", "syntax"]

    def test_graphql_messages_are_sanitised(self) -> None:
        """SL1 authors these strings, so they are foreign content like any other body."""
        long_message = "z" * (MAX_LCE_BODY_CHARS + 500)
        exc = Sl1GraphQlError([long_message])
        assert len(exc.messages[0]) < len(long_message)

    def test_every_sl1_type_is_in_the_closed_vocabulary(self) -> None:
        """Derived from the `ErrorType` Literal rather than a hand-written list, so a future member
        is checked automatically."""
        from typing import get_args

        vocabulary = set(get_args(ErrorType))
        for exc in (
            Sl1HttpError(404, {}),
            Sl1Unreachable("h"),
            Sl1MalformedResponse(),
            Sl1ResponseTooLarge(1),
            Sl1GraphQlError(["e"]),
        ):
            assert build_error_payload(exc)["error"]["type"] in vocabulary
