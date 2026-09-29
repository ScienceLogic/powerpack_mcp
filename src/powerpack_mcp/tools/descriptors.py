"""
LCE Operation Descriptors

This module defines the seven ``OperationDescriptor`` constants, one per LCE operation. Each
descriptor names the tool, HTTP method, path and validation rules, so adding an LCE operation
adds a descriptor here and one ``register_tools`` entry without touching ``lce_client``,
``validation``, ``query`` or ``shaping``. No tool function contains a path, method or lint
selection as a literal.

Every descriptor was checked against the LCE API specification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Literal

from powerpack_mcp.errors import LintRule

__all__ = [
    "ALL_DESCRIPTORS",
    "CREATE_OR_UPDATE_DYNAMIC_APPLICATIONS",
    "CREATE_OR_UPDATE_EVENT_POLICIES",
    "GET_DYNAMIC_APPLICATION",
    "GET_EVENT_POLICY",
    "GET_POWERPACK",
    "IDENTIFIER_FORMS",
    "LIST_DYNAMIC_APPLICATIONS",
    "LIST_EVENT_POLICIES",
    "OperationDescriptor",
]

# LCE documents ``powerpack_identifier``, ``app_identifier`` and ``event_identifier`` identically,
# and every tool docstring states all three forms so a client can pick the tool without reading
# the LCE reference.
#
# Identifiers are typed ``str`` on the signatures, not a union: LCE accepts all three forms in one
# path segment, so a union would misrepresent the API and complicate the JSON schema.
IDENTIFIER_FORMS: Final[str] = (
    "Accepts any of three forms: a numeric ID (12345), a 32-character uppercase hexadecimal GUID "
    "(A1B2C3D4E5F6789012345678901234AB), or a name (my-powerpack)."
)


@dataclass(frozen=True, slots=True)
class OperationDescriptor:
    """One LCE operation, described as data.

    Instances are frozen module-level constants. ``lint_rules`` is data rather than code, so the
    two write operations differ only in which lints they carry.

    :ivar tool_name: The MCP tool name.
    :ivar method: The HTTP method.
    :ivar path_template: The LCE path, with at most one ``{identifier}`` placeholder.
    :ivar is_write: Whether the operation writes.
    :ivar lint_rules: The pre-write lints to run; empty for reads.
    :ivar requires_filter: Whether the operation needs at least one filter (the list operations).
    :ivar supports_write_options: Whether ``commit`` and ``retrieve`` apply (the two POSTs).
    """

    tool_name: str
    method: Literal["GET", "POST"]
    path_template: str
    is_write: bool
    # Empty for reads. A ``frozenset`` so a descriptor cannot be mutated after definition.
    lint_rules: frozenset[LintRule] = field(default_factory=frozenset)
    # True for the two list operations only.
    requires_filter: bool = False
    # ``commit``/``retrieve`` appear on the two POSTs and on no GET.
    supports_write_options: bool = False

    def path_for(self, identifier: str | None = None) -> str:
        """Render the path, substituting the single identifier placeholder when there is one.

        Collection paths carry no placeholder, so passing an identifier for one is a programming
        error rather than a caller error, hence ``AssertionError`` and not ``ValidationBlocked``.

        :param identifier: The value for the path placeholder, or ``None`` for collection paths.
        :return: The rendered path.
        :raises AssertionError: If ``identifier`` is given for a collection path or missing for an
            item path.
        """
        if "{" not in self.path_template:
            if identifier is not None:
                raise AssertionError(f"{self.tool_name} takes no path identifier")
            return self.path_template
        if identifier is None:
            raise AssertionError(f"{self.tool_name} requires a path identifier")
        opening = self.path_template.index("{")
        closing = self.path_template.index("}")
        placeholder = self.path_template[opening : closing + 1]
        return self.path_template.replace(placeholder, identifier)


GET_POWERPACK: Final = OperationDescriptor(
    tool_name="lce_get_powerpack",
    method="GET",
    path_template="/powerpacks/{powerpack_identifier}",
    is_write=False,
)

GET_DYNAMIC_APPLICATION: Final = OperationDescriptor(
    tool_name="lce_get_dynamic_application",
    method="GET",
    path_template="/dynamic_applications/{app_identifier}",
    is_write=False,
)

LIST_DYNAMIC_APPLICATIONS: Final = OperationDescriptor(
    tool_name="lce_list_dynamic_applications",
    method="GET",
    path_template="/dynamic_applications",
    is_write=False,
    requires_filter=True,
)

CREATE_OR_UPDATE_DYNAMIC_APPLICATIONS: Final = OperationDescriptor(
    tool_name="lce_create_or_update_dynamic_applications",
    method="POST",
    path_template="/dynamic_applications",
    is_write=True,
    # Both lints: ``DynamicApp`` has a ``threshold_objects`` array.
    lint_rules=frozenset({LintRule.CHILD_GUID, LintRule.THRESHOLD_TYPE}),
    supports_write_options=True,
)

GET_EVENT_POLICY: Final = OperationDescriptor(
    tool_name="lce_get_event_policy",
    method="GET",
    path_template="/event_policies/{event_identifier}",
    is_write=False,
)

LIST_EVENT_POLICIES: Final = OperationDescriptor(
    tool_name="lce_list_event_policies",
    method="GET",
    path_template="/event_policies",
    is_write=False,
    requires_filter=True,
)

CREATE_OR_UPDATE_EVENT_POLICIES: Final = OperationDescriptor(
    tool_name="lce_create_or_update_event_policies",
    method="POST",
    path_template="/event_policies",
    is_write=True,
    # ``CHILD_GUID`` only: ``EventPolicy`` has no threshold collection in the LCE specification.
    lint_rules=frozenset({LintRule.CHILD_GUID}),
    supports_write_options=True,
)

ALL_DESCRIPTORS: Final[tuple[OperationDescriptor, ...]] = (
    GET_POWERPACK,
    GET_DYNAMIC_APPLICATION,
    LIST_DYNAMIC_APPLICATIONS,
    CREATE_OR_UPDATE_DYNAMIC_APPLICATIONS,
    GET_EVENT_POLICY,
    LIST_EVENT_POLICIES,
    CREATE_OR_UPDATE_EVENT_POLICIES,
)
