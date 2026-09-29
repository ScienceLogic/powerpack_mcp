"""
Payload Validation

This module provides the blocking lints run on a write payload before it reaches LCE: child GUID
format, threshold type, and threshold value against its type. It also provides the bounded depth
guard, ``exceeds_depth``, which runs before any traversal.

The module is pure: no I/O, no global state and no logging. ``validate_payload`` returns findings
and raises nothing; the caller decides that findings mean ``ValidationBlocked``. The scope is
deliberately narrow. This is not a general schema validator, and the operation descriptor selects
which lints run through a ``frozenset[LintRule]`` rather than a rule registry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from powerpack_mcp.errors import FindingCode, LintRule, ValidationFinding

__all__ = [
    "CHILD_GUID_PATTERN",
    "INSPECTED_CHILD_COLLECTIONS",
    "MAX_PAYLOAD_DEPTH",
    "PERMITTED_THRESHOLD_TYPES",
    "PayloadRoot",
    "exceeds_depth",
    "validate_payload",
]

# ``definitions.GUID.pattern`` from the LCE API specification. Uppercase only: lowercase hex is a
# finding on purpose, because it is the likeliest near-miss and an actionable message helps most
# there.
CHILD_GUID_PATTERN: Final = re.compile(r"^[A-F0-9]{32}$")

# ``FlexibleEnumThresholdType.enum`` from the LCE API specification. Comparison is exact and
# case-sensitive; accepting ``percentage`` would invent a tolerance the API does not document.
PERMITTED_THRESHOLD_TYPES: Final[frozenset[str]] = frozenset({"PERCENTAGE", "INTEGER", "DECIMAL"})

# The child collections whose items carry a ``guid``, kept as an asserted constant so the minimum
# coverage stays verifiable. Traversal does not consult this set: it recurses over the whole
# document, which is strictly broader.
INSPECTED_CHILD_COLLECTIONS: Final[frozenset[str]] = frozenset(
    {
        "snippets",
        "collection_objects",
        "presentation_objects",
        "threshold_objects",
        "alert_objects",
        "event_policies",
    }
)

# Maximum payload nesting depth. Legitimate payloads nest 5-6 levels, 20-30 at most, so 100 leaves
# ample headroom. The bound also keeps the walker total: without it, deeply nested input would
# drive the recursion past CPython's 1,000-frame limit.
MAX_PAYLOAD_DEPTH: Final = 100

# A payload is an object or a top-level array, both of which LCE accepts. The ``Any`` is the
# inbound JSON boundary; the predicates below take ``object`` instead, which forces explicit
# narrowing.
PayloadRoot = dict[str, Any] | list[Any]

_THRESHOLD_COLLECTION_KEY: Final = "threshold_objects"


def exceeds_depth(node: object, limit: int = MAX_PAYLOAD_DEPTH) -> bool:
    """Return whether ``node`` nests deeper than ``limit``.

    The walk returns as soon as the limit is exceeded and does not descend further, so stack use is
    bounded by the limit rather than by the input. A naive recursive checker raises
    ``RecursionError`` on exactly the input it exists to reject (for example a 5,000-deep payload).

    This runs before any traversal and before any LCE call. It is total over every JSON value.

    :param node: The value to measure.
    :param limit: The maximum permitted depth.
    """

    def walk(value: object, depth: int) -> bool:
        if depth > limit:
            # Stop without descending. This is what bounds the recursion.
            return True
        if isinstance(value, dict):
            return any(walk(member, depth + 1) for member in value.values())
        if isinstance(value, list):
            return any(walk(member, depth + 1) for member in value)
        return False

    return walk(node, 1)


def is_valid_child_guid(value: object) -> bool:
    """Return whether ``value`` is acceptable at a ``guid``-suffixed key.

    Takes ``object`` rather than ``str`` so that arbitrary JSON values return ``False`` instead of
    raising ``TypeError``.

    ``None`` is valid: every child ``guid`` is ``x-nullable: true`` and is never required, and
    omitting it is how a caller creates a new child object. A non-string is a finding, since it can
    never be a GUID and passing it through would trade an actionable message for an opaque LCE
    error. ``bool`` is excluded explicitly because it is a subclass of ``int``.
    """
    if value is None:
        return True
    if isinstance(value, bool) or not isinstance(value, str):
        return False
    # ``fullmatch``, not ``match``: Python's ``$`` also matches before a trailing newline, so
    # ``match`` would accept a 32-hex GUID with ``\n`` appended. ``target_host.py`` does the same.
    return CHILD_GUID_PATTERN.fullmatch(value) is not None


def is_valid_threshold_type(value: object) -> bool:
    """Return whether ``value`` is acceptable at ``threshold_objects[].type``.

    Takes ``object`` for the same reason as ``is_valid_child_guid``. A non-string, notably the
    integer ``0``, is a finding: ``ThresholdObject.type`` declares ``default: 0`` while its enum
    holds only strings, which is exactly the confusion this lint exists to catch.
    """
    if isinstance(value, bool) or not isinstance(value, str):
        return False
    return value in PERMITTED_THRESHOLD_TYPES


def is_threshold_value_numeric(value: object) -> bool:
    """Return whether a ``threshold_objects[].value`` can be read as a number.

    Module-internal by convention: ``validate_payload`` is the single public entry point, so this
    is excluded from ``__all__`` but stays visible to tests.

    A numeric string is accepted on purpose. The lint exists to stop values such as
    ``"not-a-number"`` reaching LCE and coming back 422; refusing ``"75"`` too would reject a
    payload LCE accepts and block working callers. ``bool`` is rejected even though it is an
    ``int``, because ``True`` is not a threshold value.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        try:
            float(value)
        except ValueError:
            return False
        return True
    return False


_GUID_REMEDY: Final = (
    "Omit the key to create a new child object and let LCE assign a GUID, or supply the existing "
    "object's uppercase 32-character hexadecimal GUID to update it"
)


def _is_guid_key(key: str) -> bool:
    """Return whether ``key`` is named ``guid`` or ends in ``_guid``.

    In practice these are ``guid``, ``pp_guid`` and ``app_guid``, the only such keys in
    ``DynamicApp`` and ``EventPolicy``.
    """
    return key == "guid" or key.endswith("_guid")


def _join(prefix: str, key: str) -> str:
    """Join a path prefix and a key.

    Paths use dotted keys with bracketed zero-based indices, such as
    ``dynamic_applications[0].guid``. JSON Pointer was not used because it reads worse for a
    caller recovering from an error message.
    """
    return f"{prefix}.{key}" if prefix else key


def _guid_finding(key: str, value: object, path: str) -> tuple[ValidationFinding, ...]:
    """Run the ``CHILD_GUID`` check at one site.

    Extracted from the walker to keep it within the ruff ``C901`` complexity limit.

    :return: Zero or one finding.
    """
    if not _is_guid_key(key) or is_valid_child_guid(value):
        return ()
    return (
        ValidationFinding(
            path=path,
            rule=FindingCode.CHILD_GUID,
            # State both remedies and the path, never the offending value.
            message=(
                f"{key} is not a valid child GUID. Expected an uppercase 32-character "
                f"hexadecimal string matching ^[A-F0-9]{{32}}$. {_GUID_REMEDY}."
            ),
        ),
    )


def _threshold_finding(key: str, value: object, path: str) -> tuple[ValidationFinding, ...]:
    """Run the ``THRESHOLD_TYPE`` check at one site of a ``threshold_objects`` member.

    :return: Zero or one finding.
    """
    if key != "type" or is_valid_threshold_type(value):
        return ()
    permitted = ", ".join(sorted(PERMITTED_THRESHOLD_TYPES))
    return (
        ValidationFinding(
            path=path,
            rule=FindingCode.THRESHOLD_TYPE,
            message=(
                f"type is not a permitted threshold type. Expected exactly one of "
                f"{permitted}, matched case-sensitively."
            ),
        ),
    )


def _threshold_value_finding(
    key: str, value: object, path: str, sibling_type: object
) -> tuple[ValidationFinding, ...]:
    """Check that a threshold ``value`` is consistent with its sibling ``type``.

    The check runs at the ``value`` key and reads the sibling ``type``. A per-key visitor cannot
    otherwise see the pair, and a check run once per object would append its finding after the
    object's nested findings, breaking document order.

    It is silent when ``type`` is absent (there is nothing to be inconsistent with, and
    ``ThresholdObject.type`` has a default) or invalid (``_threshold_finding`` already reports it,
    and one mistake should be one finding).

    Two things are deliberately not checked:

    - Range. ``PERCENTAGE`` with ``value: 500`` is accepted by LCE; the type matches and only the
      range is violated, which is outside this lint's scope.
    - Integrality. ``INTEGER`` with ``75.5`` is accepted by LCE unchanged, and SL1 stores it
      exactly because ``master.dynamic_app_thresholds.t_value`` is ``decimal(13,3) unsigned``. The
      ``INTEGER`` label is semantic, not a storage constraint, so refusing a fraction would be a
      false refusal. The real limits are three decimal places (``75.5555`` should be expected to
      round) and no negative values; neither is linted.

    :param sibling_type: The ``type`` value from the same threshold object.
    :return: Zero or one finding.
    """
    if key != "value" or is_threshold_value_numeric(value):
        return ()
    if not is_valid_threshold_type(sibling_type):
        return ()
    return (
        ValidationFinding(
            path=path,
            rule=FindingCode.THRESHOLD_TYPE,
            # Name the rule and the path, never the offending value. The type is named because the
            # caller supplied it and it is what makes the value wrong.
            message=(
                f"value is not consistent with the declared threshold type "
                f"{sibling_type}. Expected a number, or a string that parses as one."
            ),
        ),
    )


@dataclass(frozen=True, slots=True)
class _Selection:
    """Which lints are active for this traversal.

    Passed down rather than closed over, so the walker can live at module level and
    ``validate_payload`` stays within the ruff ``C901`` complexity limit.
    """

    guid: bool
    threshold: bool


def _walk_value(
    value: object,
    path: str,
    findings: list[ValidationFinding],
    selection: _Selection,
    *,
    in_threshold_objects: bool,
) -> None:
    if isinstance(value, dict):
        _walk_object(value, path, findings, selection, in_threshold_objects=in_threshold_objects)
    elif isinstance(value, list):
        for index, member in enumerate(value):
            _walk_value(
                member,
                f"{path}[{index}]",
                findings,
                selection,
                in_threshold_objects=in_threshold_objects,
            )


def _walk_object(
    # ``dict[str, object]`` rather than ``dict[str, Any]``: this is an internal walker, so the
    # narrower type costs nothing and keeps ``Any`` at the boundary.
    obj: dict[str, object],
    path: str,
    findings: list[ValidationFinding],
    selection: _Selection,
    *,
    in_threshold_objects: bool,
) -> None:
    """Walk one object in a single pass, in document order, running every applicable rule."""
    for key, value in obj.items():
        child_path = _join(path, key)

        if selection.guid:
            findings.extend(_guid_finding(key, value, child_path))
        if selection.threshold and in_threshold_objects:
            findings.extend(_threshold_finding(key, value, child_path))
            # ``obj.get("type")`` is the sibling of this ``value`` key; the rule is about the pair.
            findings.extend(_threshold_value_finding(key, value, child_path, obj.get("type")))

        # Traversal is recursive. ``DynamicApp.event_policies`` is ``array<EventPolicy>`` and
        # ``EventPolicy`` itself carries ``guid``, ``app_guid`` and ``pp_guid``, so a one-level
        # walk would miss all three.
        #
        # The threshold lints apply only to members of ``threshold_objects``, so the flag is set
        # for that array and cleared everywhere else, including a ``type`` key on an unrelated
        # object.
        _walk_value(
            value,
            child_path,
            findings,
            selection,
            in_threshold_objects=(key == _THRESHOLD_COLLECTION_KEY),
        )


def validate_payload(
    payload: PayloadRoot,
    rules: frozenset[LintRule],
) -> tuple[ValidationFinding, ...]:
    """Return every finding for the selected rules, in document order.

    Never raises on bad content and never mutates its input; the payload sent to LCE is the
    caller's own, byte for byte. Every finding is returned with no cap, so one round trip surfaces
    every problem. The body-size guard already bounds the input, so the list is bounded too. The
    order is deterministic, which makes responses diffable.

    :param payload: The caller's payload, as an object or a top-level array.
    :param rules: The lints to run, as selected by the operation descriptor.
    :return: The findings, empty when the payload is clean or no rules are selected.
    """
    selection = _Selection(
        guid=LintRule.CHILD_GUID in rules,
        threshold=LintRule.THRESHOLD_TYPE in rules,
    )
    if not selection.guid and not selection.threshold:
        # A read operation: the descriptor selects no lints, so no traversal is performed.
        return ()

    findings: list[ValidationFinding] = []
    # Paths address the document as the caller sent it, so the same logical object has different
    # paths under different shapes: a top-level array yields ``[i]...``, a single object yields
    # ``guid``, and an object with a collection key yields ``dynamic_applications[0].guid``. Plain
    # path building produces all three, so no special case is needed.
    _walk_value(payload, "", findings, selection, in_threshold_objects=False)
    return tuple(findings)
