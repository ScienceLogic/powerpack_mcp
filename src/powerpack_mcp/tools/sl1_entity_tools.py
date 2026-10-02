"""
SL1 Entity Tools

This module defines the 16 typed SL1 tools that use GraphQL: 5 for devices, 6 for credentials,
3 for PowerPacks and 2 for Event Policies. The two Dynamic Application readers use REST and live
in ``sl1_rest_tools``. Every GraphQL document comes from ``sl1_descriptors``, and no tool takes
``target_host``, ``username`` or ``password``.

``sl1_align_dynamic_apps_to_device`` and its unalign sibling resolve Dynamic Application
identifiers through LCE before issuing the GraphQL mutation, so one tool call spans both
backends; see ``Sl1ToolContext``.

The credential readers are the security-sensitive part of this module: read the section above
``_DEFINITION_ALLOWLIST`` before editing them. Tool docstrings are written out in full because an
f-string is not a docstring and would leave ``__doc__`` as ``None``.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, Final

from powerpack_mcp.errors import (
    FindingCode,
    Sl1GraphQlError,
    Sl1MalformedResponse,
    ValidationBlocked,
    ValidationFinding,
)
from powerpack_mcp.shaping import drop_empty
from powerpack_mcp.tools import sl1_descriptors as d
from powerpack_mcp.tools.sl1_credential_definition import (
    CRED_SUBTYPE_REST_V104,
    CRED_TYPE_UNIVERSAL,
    UniversalDefinitionError,
    serialize_universal_definition,
)
from powerpack_mcp.tools.sl1_pipeline import sl1_tool_boundary

if TYPE_CHECKING:
    from collections.abc import Mapping

    from powerpack_mcp.tools.sl1_pipeline import Sl1ToolContext
    from powerpack_mcp.tools.sl1_rest_tools import Sl1ToolFactory

__all__ = [
    "make_sl1_align_dynamic_apps_to_device",
    "make_sl1_create_universal_credential",
    "make_sl1_create_virtual_device",
    "make_sl1_delete_credential",
    "make_sl1_delete_device",
    "make_sl1_get_credential",
    "make_sl1_get_event_policy",
    "make_sl1_get_powerpack",
    "make_sl1_list_credentials",
    "make_sl1_list_event_policies",
    "make_sl1_list_powerpacks",
    "make_sl1_list_uploaded_powerpacks",
    "make_sl1_list_virtual_device_classes",
    "make_sl1_replace_universal_credential",
    "make_sl1_unalign_dynamic_apps_from_device",
    "make_sl1_update_universal_credential",
]

# ``sl1_create_virtual_device``'s default device class, the generic "Virtual Device | Dynamic App
# Emissary". Three of the four inputs have defaults, and they are meaningful: organization ``"0"``
# is System and collector group ``"1"`` is the CUG. A caller forced to supply a device-class GUID by
# hand is likely to supply the wrong one.
VDEV_CLASS_DYNAMIC_APP_EMISSARY = "7e47194488701776e0be374089134232"

_DEFAULT_ORGANIZATION = "0"
_DEFAULT_COLLECTOR_GROUP = "1"

# The fields ``sl1_list_virtual_device_classes`` returns when ``verbose`` is false. Returned as data
# rather than a text summary, because the tools return JSON.
_VDEV_CLASS_SUMMARY_FIELDS = ("id", "class", "description")


async def _run(
    context: Sl1ToolContext,
    descriptor: d.GraphQlDescriptor,
    variables: dict[str, Any] | None = None,
) -> Any:
    """Issue one descriptor's GraphQL document and return its ``root_field`` from ``data``.

    ``Sl1Client.graphql`` has already raised ``Sl1GraphQlError`` if ``errors`` was non-empty and
    discarded any partial ``data``, so anything reaching here is a success envelope.

    A missing ``root_field`` raises rather than returning ``None``. GraphQL guarantees the key when
    the operation succeeded, so its absence means the response is not what the document asked for,
    and ``None`` would present that to the caller as "no such object".

    :param descriptor: The operation to run.
    :param variables: The GraphQL variables.
    :return: The root field's value, with empty fields dropped.
    :raises Sl1MalformedResponse: If ``data`` lacks the descriptor's root field.
    """
    body = await context.client.graphql(
        credential=context.credential_source(),
        query=descriptor.document,
        variables=variables,
    )
    data = body.get("data")
    if not isinstance(data, dict) or descriptor.root_field not in data:
        raise Sl1MalformedResponse
    # Drop empty fields, as the LCE surface does, so the two surfaces agree (for example
    # ``sl1_get_powerpack`` would otherwise return ``"vendors": ""``). ``drop_empty`` is the same
    # function the LCE pipeline uses through ``shape_response``: ``null``, ``""``, ``[]`` and ``{}``
    # are dropped, while ``0``, ``false`` and whitespace-only strings are kept, because ``0`` is
    # real threshold data and ``false`` is the opposite of absent.
    #
    # Applied here, the single exit point every entity tool shares, rather than per tool. It applies
    # to SL1's response only; payloads this service builds itself (collection ``lines``, health
    # verdicts, audit records) are not pruned, because there an empty value is a measurement.
    #
    # Removal is recursive, so an object whose every field is empty reduces to ``{}`` and is dropped
    # from its connection, and a Relay ``edges`` list can come back shorter. A node always carries
    # an ``id`` or ``guid`` in practice, so this is theoretical.
    return drop_empty(data[descriptor.root_field])


def _nodes(connection: Any) -> list[dict[str, Any]]:
    """Unwrap a Relay ``{edges: [{node: {...}}]}`` connection into a list of nodes.

    Tolerant by design: SL1 authors this shape, and a missing ``edges`` or a null ``node`` yields a
    shorter list rather than an exception. "None" is a truthful answer to which objects matched; a
    ``KeyError`` is not an answer at all.
    """
    if not isinstance(connection, dict):
        return []
    edges = connection.get("edges")
    if not isinstance(edges, list):
        return []
    return [
        edge["node"]
        for edge in edges
        if isinstance(edge, dict) and isinstance(edge.get("node"), dict)
    ]


# ---- Devices: 5 tools ---------------------------------------------------------------------------
#
# Virtual device create and delete work on every SL1 version tested.
# ``alignDynamicApplicationsToDevice`` and ``unalignDynamicApplicationsFromDevice`` are absent on
# 12.1.2 and 12.2.1 and present on 12.5.1 and 12.5.20. Both tool descriptions say so, because the
# failure is otherwise indistinguishable from a permissions problem.


def make_sl1_list_virtual_device_classes(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_list_virtual_device_classes`` tool bound to ``context``."""

    @sl1_tool_boundary(d.LIST_VIRTUAL_DEVICE_CLASSES)
    async def sl1_list_virtual_device_classes(
        first: int = 100, verbose: bool = False
    ) -> dict[str, Any] | list[Any]:
        """List virtual-capable device classes.

        Returns the device classes whose virtualType is 'virtual'. Use a returned id as the
        device_class argument to sl1_create_virtual_device.

        Args:
            first: Maximum classes to return.
            verbose: When false, each class is reduced to id, class and description. When true, the
                full node is returned, including virtualType.
        """
        nodes = _nodes(await _run(context, d.LIST_VIRTUAL_DEVICE_CLASSES, {"first": int(first)}))
        if verbose:
            return nodes
        return [
            {field: node[field] for field in _VDEV_CLASS_SUMMARY_FIELDS if field in node}
            for node in nodes
        ]

    return sl1_list_virtual_device_classes


# Case-insensitive 32-hex, for routing an identifier as "already a guid" versus "a name or numeric
# id that needs resolving".
#
# Deliberately not ``validation.CHILD_GUID_PATTERN``, which is uppercase-only because it validates
# against LCE's ``^[A-F0-9]{32}$``. Reusing it here would send a lowercase guid to LCE as a name,
# find nothing, and report "could not resolve a guid" about a string that was already a guid.
# Routing is case-insensitive; validation is not.
_GUID_ROUTING_PATTERN: Final = re.compile(r"^[A-Fa-f0-9]{32}$")

# The LCE path that resolves one Dynamic Application: the only LCE call the SL1 entity tools make.
#
# The leading slash is required. ``LceClient._build_url`` composes ``f"{LCE_BASE_PATH}{path}"``
# with no separator, so an LCE path must be absolute; without it the URL becomes
# ``/lce/apidynamic_applications/<id>`` and the align and unalign tools cannot accept a Dynamic
# Application by name or numeric id at all.
_LCE_DYNAMIC_APP_PATH = "/dynamic_applications"

# The singular key LCE wraps a single Dynamic Application under. Stated explicitly rather than
# derived by slicing ``_LCE_DYNAMIC_APP_PATH``: with the leading slash, a slice would produce
# ``"/dynamic_application"``, which matches nothing, and every name and numeric-id resolution would
# fail. The URL segment and the JSON key must not move together by accident.
_LCE_DYNAMIC_APP_KEY = "dynamic_application"


async def _resolve_dynamic_app_guid(context: Sl1ToolContext, identifier: str) -> str:
    """Resolve a Dynamic Application identifier (guid, numeric LCE id or name) to its 32-hex guid.

    ``alignDynamicApplicationsToDevice`` accepts guids and nothing else, so without this the tools
    would only work for callers who already had the guid.

    The LCE call uses the same credential the SL1 call will, which is correct under credential
    forwarding: one caller identity reaches both backends. A ``fields`` allowlist keeps the
    response small, because resolving an identifier does not need the authoring-shape document.

    :param identifier: The caller's Dynamic Application identifier.
    :return: The 32-hex guid.
    :raises ValidationBlocked: If LCE returns no guid for the identifier.
    """
    candidate = identifier.strip()
    if _GUID_ROUTING_PATTERN.fullmatch(candidate):
        return candidate

    response = await context.lce_client.request(
        credential=context.credential_source(),
        method="GET",
        path=f"{_LCE_DYNAMIC_APP_PATH}/{candidate}",
        query={"fields": "guid,id,name"},
    )
    body = response.body
    # LCE wraps a single object under its singular key on some paths and returns it bare on others.
    # Both shapes are accepted; guessing wrong here would fail a write that has passed every other
    # check.
    document = body.get(_LCE_DYNAMIC_APP_KEY, body) if isinstance(body, dict) else body
    guid = document.get("guid") if isinstance(document, dict) else None
    if not isinstance(guid, str) or not guid:
        # The identifier is echoed because the caller supplied it and it is not secret, and
        # without it a batch failure gives no clue which entry was at fault.
        raise ValidationBlocked(
            [
                ValidationFinding(
                    path="dynamic_apps",
                    rule=FindingCode.TOOL_ARGUMENT,
                    message=(
                        f"Could not resolve a Dynamic Application guid for {identifier!r}. "
                        "Pass a guid, a numeric LCE id, or an exact name."
                    ),
                )
            ]
        )
    return guid


def make_sl1_create_virtual_device(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_create_virtual_device`` tool bound to ``context``.

    :param context: The clients, configuration and credential source the tool uses.
    :return: The tool function to register with the MCP server.
    """

    @sl1_tool_boundary(d.CREATE_VIRTUAL_DEVICE)
    async def sl1_create_virtual_device(
        name: str,
        device_class: str = VDEV_CLASS_DYNAMIC_APP_EMISSARY,
        organization: str = _DEFAULT_ORGANIZATION,
        collector_group: str = _DEFAULT_COLLECTOR_GROUP,
    ) -> dict[str, Any] | list[Any]:
        """Create an SL1 virtual device.

        Args:
            name: The device name.
            device_class: Device class id, as returned by sl1_list_virtual_device_classes. Defaults
                to the generic 'Virtual Device | Dynamic App Emissary' class.
            organization: Organization id. Defaults to "0", which is System.
            collector_group: Collector group id. Defaults to "1", which is the CUG.
        """
        created = await _run(
            context,
            d.CREATE_VIRTUAL_DEVICE,
            {
                "name": name,
                # Every id is stringified: the GraphQL variables are declared ``ID!``, and SL1
                # rejects an integer where it wants an ID.
                "organization": str(organization),
                "deviceClass": str(device_class),
                "collectorGroup": str(collector_group),
            },
        )
        return created if isinstance(created, dict) else {"created": created}

    return sl1_create_virtual_device


def make_sl1_delete_device(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_delete_device`` tool bound to ``context``."""

    @sl1_tool_boundary(d.DELETE_DEVICE)
    async def sl1_delete_device(device_id: str) -> dict[str, Any] | list[Any]:
        """Delete an SL1 device, physical or virtual, by its NUMERIC device id. Permanent.

        Args:
            device_id: The numeric device id. Not a name and not a GUID.
        """
        deleted = await _run(context, d.DELETE_DEVICE, {"id": str(device_id)})
        # ``deleteDevice`` answers with a bare boolean, so the id is echoed back alongside it: a
        # lone ``true`` gives the caller no way to confirm what was deleted.
        return {"deleted": bool(deleted), "id": str(device_id)}

    return sl1_delete_device


# SL1's error text when an alignment inserts nothing.
#
# Matched as a substring of the message, which is fragile, and kept anyway: the alternative is
# surfacing a raw MySQL fragment the client cannot act on. If SL1 changes the text this degrades to
# the generic error rather than misreporting, so the fragility costs a good message, never a wrong
# one.
_EMPTY_INSERT_MARKER = "ON DUPLICATE KEY UPDATE collect=1"


def make_sl1_align_dynamic_apps_to_device(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_align_dynamic_apps_to_device`` tool bound to ``context``."""

    @sl1_tool_boundary(d.ALIGN_DYNAMIC_APPS)
    async def sl1_align_dynamic_apps_to_device(
        device_id: str,
        credential_guid: str,
        dynamic_apps: list[str],
    ) -> dict[str, Any] | list[Any]:
        """Align one or more Dynamic Applications to a device, binding a collection credential.

        Each Dynamic App must be compatible with the device's device class, or SL1 rejects the whole
        batch -- alignment is all-or-nothing, not per-app.

        Args:
            device_id: The numeric device id.
            credential_guid: The credential's GUID -- required, and shared by every Dynamic App in
                this call. Every credential tool keys on guid, never the numeric id. Note that
                sl1_replace_universal_credential changes the guid, so an alignment made before a
                replace must be re-made after it.
            dynamic_apps: Dynamic App identifiers. Each may be a guid, a numeric LCE id, or a name;
                names and ids are resolved to guids first, because SL1 accepts only guids here.

        Not available on every SL1 version: this mutation is absent on 12.1.2 and 12.2.1.
        """
        guids = [await _resolve_dynamic_app_guid(context, entry) for entry in dynamic_apps]
        try:
            aligned = await _run(
                context,
                d.ALIGN_DYNAMIC_APPS,
                {
                    "device": str(device_id),
                    "credential": str(credential_guid),
                    "dynamicApplications": guids,
                },
            )
        except Sl1GraphQlError as exc:
            # SL1 reports "nothing was inserted" as a raw MySQL fragment. The real cause is almost
            # always device-class incompatibility, and saying so lets a client retry usefully
            # rather than identically.
            if any(_EMPTY_INSERT_MARKER in message for message in exc.messages):
                raise ValidationBlocked(
                    [
                        ValidationFinding(
                            path="dynamic_apps",
                            rule=FindingCode.TOOL_ARGUMENT,
                            message=(
                                "None of the given Dynamic Applications are compatible with this "
                                "device's device class. Align Dynamic Apps whose class matches it."
                            ),
                        )
                    ]
                ) from exc
            raise
        return aligned if isinstance(aligned, dict) else {"aligned": aligned}

    return sl1_align_dynamic_apps_to_device


def make_sl1_unalign_dynamic_apps_from_device(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_unalign_dynamic_apps_from_device`` tool bound to ``context``."""

    @sl1_tool_boundary(d.UNALIGN_DYNAMIC_APPS)
    async def sl1_unalign_dynamic_apps_from_device(
        device_id: str,
        dynamic_apps: list[str],
    ) -> dict[str, Any] | list[Any]:
        """Unalign one or more Dynamic Applications from a device. No credential is needed.

        Args:
            device_id: The numeric device id.
            dynamic_apps: Dynamic App identifiers -- guid, numeric LCE id, or name. Names and ids
                are resolved to guids first, because SL1 accepts only guids here.

        Not available on every SL1 version: this mutation is absent on 12.1.2 and 12.2.1.
        """
        guids = [await _resolve_dynamic_app_guid(context, entry) for entry in dynamic_apps]
        unaligned = await _run(
            context,
            d.UNALIGN_DYNAMIC_APPS,
            {"device": str(device_id), "dynamicApplications": guids},
        )
        return unaligned if isinstance(unaligned, dict) else {"unaligned": unaligned}

    return sl1_unalign_dynamic_apps_from_device


# ---- Credentials: 4 writers (the 2 readers follow in their own section) -------------------------
#
# These three mutations were absent on one SL1 12.2.1 system while present on 12.1.2, 12.5.1 and
# 12.5.20. The gap is not monotonic, so a version comparison cannot gate them. The REST
# ``/api/credential`` endpoint exists on every version tested but cannot create UNIVERSAL
# credentials: its read shape differs from its write shape and the endpoint returns 500. GraphQL is
# the only working path.


def make_sl1_create_universal_credential(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_create_universal_credential`` tool bound to ``context``."""

    @sl1_tool_boundary(d.CREATE_UNIVERSAL_CREDENTIAL)
    async def sl1_create_universal_credential(
        name: str,
        definition: dict[str, Any],
        sub_type: str = CRED_SUBTYPE_REST_V104,
        # ASYNC109: SL1 credential timeout (ms), not a deadline.
        timeout: int = 600000,  # noqa: ASYNC109
        all_organizations: bool = True,
        aligned_organizations: list[int] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Create a UNIVERSAL credential -- Low-code REST by default, or another subtype.

        Normalisation depends on sub_type, because SL1's subtypes do not share a definition shape.
        For the Low-code REST v104 default the definition is completed against SL1's full expected
        shape: absent keys are defaulted, proxy and sslverifypeer are coerced to booleans, and
        tokenExpiresInSelector is given a value even under static refresh. For ANY OTHER sub_type
        the definition is sent as you supply it, because those defaults are REST-specific and SL1
        rejects them elsewhere -- so supply a complete definition for the subtype you name. Either
        way the definition goes as a JSON string, because that is what SL1's resolver expects.

        Args:
            name: Credential name.
            definition: The credential definition. Secret fields -- password, proxyPasswd,
                oauth2ClientSecret, oauth2ResourceOwnerPassword, apikey -- must be plain strings. A
                {"type": "Buffer"} read wrapper is rejected for any field, because storing SL1's
                read shape produces a credential that authenticates against nothing.
            sub_type: Credential subtype, spelled exactly as SL1 spells it -- the AWS subtypes are
                lowercase, for example "aws assume role". Defaults to the Low-code REST v104
                subtype. Naming a different one also switches off the REST defaulting above.
            timeout: Credential timeout in milliseconds.
            all_organizations: When true, the credential is available to every organization.
            aligned_organizations: Organization ids to align when all_organizations is false.
        """
        return await _credential_write(
            context,
            d.CREATE_UNIVERSAL_CREDENTIAL,
            name=name,
            definition=definition,
            sub_type=sub_type,
            timeout=timeout,
            all_organizations=all_organizations,
            aligned_organizations=aligned_organizations,
        )

    return sl1_create_universal_credential


def _definition_argument(definition: dict[str, Any] | None, sub_type: str | None) -> str:
    """Serialize a credential definition, turning a shaping error into a refusal.

    ``sub_type`` is required here, though optional on ``serialize_universal_definition``, because
    normalisation is subtype-aware (the defaults table is REST v104's shape and SL1 rejects
    ``authType`` on other subtypes). Every call site must say which subtype it is shaping for, so
    a forgotten argument is a type error rather than a silently REST-shaped payload. ``None`` means
    "unspecified" and is read as the REST default; only the update tool passes it.

    ``UniversalDefinitionError`` subclasses ``ValueError``, and ``sl1_tool_boundary`` catches only
    ``ValidationBlocked`` and ``PowerPackMcpError``. Without this translation a Buffer-wrapped
    secret would escape the boundary: the caller would get a framework-level error instead of an
    envelope, and the failure would be absent from the service's logs. ``ValidationBlocked`` is the
    right target because the definition is refused before dispatch.

    The error message is forwarded verbatim. That is safe only because it names the key and never
    the value (``str()`` of a Buffer wrapper would carry the secret's bytes);
    ``test_the_error_names_the_key_and_not_the_value`` enforces this at the raise site.

    :param definition: The caller's definition.
    :param sub_type: The subtype to shape for, or ``None`` for the REST default.
    :return: The definition as the JSON string SL1 expects.
    :raises ValidationBlocked: If the definition cannot be serialized.
    """
    try:
        return serialize_universal_definition(definition, sub_type)
    except UniversalDefinitionError as exc:
        raise ValidationBlocked(
            [ValidationFinding(path="definition", rule=FindingCode.TOOL_ARGUMENT, message=str(exc))]
        ) from exc


async def _credential_write(
    context: Sl1ToolContext,
    descriptor: d.GraphQlDescriptor,
    *,
    name: str,
    definition: dict[str, Any],
    sub_type: str,
    # ASYNC109: credential timeout (ms), not a deadline.
    timeout: int,  # noqa: ASYNC109
    all_organizations: bool,
    aligned_organizations: list[int] | None,
) -> dict[str, Any] | list[Any]:
    """Create a UNIVERSAL credential; shared by create and the recreate half of replace.

    Replace is a create, so sharing the variable construction keeps one set of SL1 constraints in
    one place. ``alignedOrganizations`` defaults to ``[0]`` rather than ``[]``, which is not
    equivalent: organization ``0`` is System.

    :return: The created credential.
    """
    created = await _run(
        context,
        descriptor,
        {
            "name": name,
            "type": CRED_TYPE_UNIVERSAL,
            "subType": sub_type,
            "timeout": int(timeout),
            "allOrganizations": bool(all_organizations),
            "alignedOrganizations": list(
                aligned_organizations if aligned_organizations is not None else [0]
            ),
            # Shaped for the subtype being sent, not for the REST default. Normalising against a
            # subtype other than the one in ``subType`` would make ``sub_type`` a non-functional
            # parameter.
            "definition": _definition_argument(definition, sub_type),
        },
    )
    return created if isinstance(created, dict) else {"created": created}


def make_sl1_delete_credential(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_delete_credential`` tool bound to ``context``."""

    @sl1_tool_boundary(d.DELETE_CREDENTIAL)
    async def sl1_delete_credential(guid: str) -> dict[str, Any] | list[Any]:
        """Delete a credential by GUID. Permanent.

        Every credential tool keys on the credential's GUID, never its numeric id.

        Args:
            guid: The credential GUID, as returned by sl1_create_universal_credential.
        """
        deleted = await _run(context, d.DELETE_CREDENTIAL, {"guid": guid})
        return {"deleted": bool(deleted), "guid": guid}

    return sl1_delete_credential


# SL1's own text when ``updateCredential``'s merge resolver crashes, matched as a substring.
#
# Every argument shape fails identically (name only, definition only, empty
# ``alignedOrganizations``, explicit ``allOrganizations``), and the raw mutation sent through
# ``sl1_graphql`` gives the same crash, so the defect is SL1's. ``updateCredential`` is not marked
# deprecated, so this is a defect on a supported mutation.
_UPDATE_RESOLVER_CRASH: Final = "Cannot read properties of undefined (reading 'reduce')"

# What the caller gets instead of SL1's raw JavaScript ``TypeError``. The "nothing was modified"
# clause matters most: after a failed write the safe assumption is partial application, which is
# wrong here. The mutation does not execute at all (verified by read-back), and saying so prevents
# a needless repair.
_UPDATE_CRASH_GUIDANCE: Final = (
    "SL1's updateCredential resolver crashed. This is a known SL1-side defect, not a problem with "
    "the arguments you sent: every argument shape fails identically, and the credential is left "
    "byte-for-byte unchanged -- nothing was modified, so there is nothing to undo. Use "
    "sl1_replace_universal_credential instead, but read its description first: it deletes and "
    "recreates, which changes the GUID, and any device alignment referencing the old GUID must be "
    f"re-pointed. SL1's own message was: {_UPDATE_RESOLVER_CRASH}"
)


def _mapped_update_crash(exc: Sl1GraphQlError) -> Sl1GraphQlError:
    """Return ``exc`` with the known-crash message replaced by guidance, or ``exc`` unchanged.

    Only the entry carrying SL1's crash text is replaced, so an unrelated resolver error (a
    permission denial, a validation failure) reaches the caller exactly as SL1 wrote it. The tuple
    keeps its length because ``Sl1GraphQlError.codes`` is positional with ``messages``: appending a
    message without a code would misalign every entry after it.
    """
    if not any(_UPDATE_RESOLVER_CRASH in message for message in exc.messages):
        return exc
    return Sl1GraphQlError(
        tuple(
            _UPDATE_CRASH_GUIDANCE if _UPDATE_RESOLVER_CRASH in message else message
            for message in exc.messages
        ),
        exc.codes,
    )


def _update_variables_by_presence(
    guid: str,
    name: str | None,
    sub_type: str | None,
    timeout: int | None,
    all_organizations: bool | None,
    aligned_organizations: list[int] | None,
) -> dict[str, Any]:
    """Build the update's variables by presence rather than by comparing against defaults.

    ``None`` means "not supplied", so an omitted field keeps its stored value. This matters for
    ``False`` and ``0``: a caller explicitly disabling ``allOrganizations`` or setting a zero
    timeout must not have it dropped as falsy.
    """
    variables: dict[str, Any] = {"guid": guid}
    if name is not None:
        variables["name"] = name
    if sub_type is not None:
        variables["subType"] = sub_type
    if timeout is not None:
        variables["timeout"] = int(timeout)
    if all_organizations is not None:
        variables["allOrganizations"] = bool(all_organizations)
    if aligned_organizations is not None:
        variables["alignedOrganizations"] = list(aligned_organizations)
    return variables


async def _stored_sub_type(context: Sl1ToolContext, guid: str) -> str | None:
    """Read the credential's own ``subType``, so an update can normalise against the right shape.

    Returns ``None`` when SL1 reports no subtype, which ``serialize_universal_definition`` reads as
    the REST v104 default, as an absent subtype means everywhere else.

    A failed read is not swallowed. If the credential cannot be read the update must not proceed on
    a guess: the guid is probably wrong, and "no such credential" is far more useful than SL1
    rejecting REST keys on a definition for a credential that does not exist.

    :raises Sl1MalformedResponse: If SL1 does not return a credential object.
    """
    credential = await _run(context, d.GET_CREDENTIAL, {"guid": guid})
    if not isinstance(credential, dict):
        raise Sl1MalformedResponse
    stored = credential.get("subType")
    return stored if isinstance(stored, str) and stored else None


def make_sl1_update_universal_credential(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_update_universal_credential`` tool bound to ``context``."""

    @sl1_tool_boundary(d.UPDATE_UNIVERSAL_CREDENTIAL)
    async def sl1_update_universal_credential(
        guid: str,
        name: str | None = None,
        definition: dict[str, Any] | None = None,
        sub_type: str | None = None,
        # ASYNC109: credential timeout (ms), not a deadline.
        timeout: int | None = None,  # noqa: ASYNC109
        all_organizations: bool | None = None,
        aligned_organizations: list[int] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """PROVISIONAL partial update of a UNIVERSAL credential by GUID.

        Only the arguments you supply are sent, so omitted fields keep their stored values. No type
        argument is accepted -- the credential type cannot be changed by an update.

        This mutation's merge resolver throws on some SL1 builds. If it fails, use
        sl1_replace_universal_credential instead, but read its description first: it deletes and
        recreates, which changes the GUID.

        Args:
            guid: The credential GUID.
            name: New name, if changing it.
            definition: New definition. Normalised and sent as a JSON string, exactly as on create,
                so for the Low-code REST v104 subtype a partial definition is completed from SL1's
                defaults rather than sent partial.
            sub_type: New subtype, if changing it. It also selects how the definition is
                normalised. Omit it to keep the stored subtype: when you supply a definition
                without a sub_type, the credential's own subtype is read first and used, so
                updating a non-REST credential no longer needs you to restate it.
            timeout: New timeout in milliseconds.
            all_organizations: New all-organizations flag.
            aligned_organizations: New aligned organization ids.
        """
        variables = _update_variables_by_presence(
            guid, name, sub_type, timeout, all_organizations, aligned_organizations
        )
        if definition is not None:
            # A read inside a write, and the lesser of two bad options. Normalisation is
            # subtype-aware, and omitting ``sub_type`` means "leave it alone", not "it is REST
            # v104". Defaulting to REST would inject ``authType`` into a non-REST definition and
            # SL1 would reject the write.
            #
            # The cost is one extra round trip on the definition path only, and a failure mode
            # where the read succeeds and the write fails. That is better than a write that passes
            # SL1's validator while storing the wrong shape, which would surface at collection
            # time, far from the call that caused it.
            #
            # An explicit ``sub_type`` always wins: a caller changing the subtype is shaping the
            # definition for the new one.
            shaping_sub_type = sub_type
            if shaping_sub_type is None:
                shaping_sub_type = await _stored_sub_type(context, guid)
            variables["definition"] = _definition_argument(definition, shaping_sub_type)

        try:
            updated = await _run(context, d.UPDATE_UNIVERSAL_CREDENTIAL, variables)
        except Sl1GraphQlError as exc:
            mapped = _mapped_update_crash(exc)
            if mapped is exc:
                raise
            raise mapped from exc
        return updated if isinstance(updated, dict) else {"updated": updated}

    return sl1_update_universal_credential


def make_sl1_replace_universal_credential(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_replace_universal_credential`` tool bound to ``context``."""

    @sl1_tool_boundary(d.REPLACE_UNIVERSAL_CREDENTIAL)
    async def sl1_replace_universal_credential(
        guid: str,
        name: str,
        definition: dict[str, Any],
        sub_type: str = CRED_SUBTYPE_REST_V104,
        # ASYNC109: SL1 credential timeout (ms), not a deadline.
        timeout: int = 600000,  # noqa: ASYNC109
        all_organizations: bool = True,
        aligned_organizations: list[int] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Replace a credential by DELETING it and RECREATING it. The new credential has a NEW GUID.

        This is the reliable way to edit a UNIVERSAL credential, because the update mutation's merge
        resolver fails on some SL1 builds. It is destructive and it breaks references:

        Any device alignment that points at the old GUID must be re-pointed at the new one --
        sl1_align_dynamic_apps_to_device binds Dynamic Apps to a credential BY GUID. If something
        live depends on the current GUID, use sl1_update_universal_credential instead.

        If the delete does not succeed, the recreate is NOT attempted and the failure is reported,
        so a failed delete cannot leave two credentials where you asked for one.

        Args:
            guid: The GUID of the credential to delete.
            name: Name for the recreated credential.
            definition: Definition for the recreated credential, normalised as on create -- which
                means completed from SL1's defaults only for the Low-code REST v104 subtype.
            sub_type: Subtype for the recreated credential. It selects the normalisation exactly as
                on create, so name it if the credential is not Low-code REST v104.
            timeout: Timeout in milliseconds for the recreated credential.
            all_organizations: All-organizations flag for the recreated credential.
            aligned_organizations: Aligned organization ids for the recreated credential.
        """
        # Shape the definition before the delete. ``_credential_write`` serialises it, and a
        # definition refused there would leave the credential deleted with nothing recreated,
        # which is worse than two credentials because a destroyed one cannot be reconciled. The
        # call is pure, so the result is discarded here and rebuilt inside the write. It is shaped
        # for ``sub_type`` so the pre-check exercises the same branch the write will.
        _definition_argument(definition, sub_type)

        # Abort before creating anything: a create issued after a failed delete leaves two
        # credentials, which is worse than the edit not happening.
        deleted = await _run(context, d.DELETE_CREDENTIAL, {"guid": guid})
        if not deleted:
            return {
                "deleted": False,
                "guid": guid,
                "recreated": None,
                "note": "Delete returned false; the recreate was not attempted.",
            }

        recreated = await _credential_write(
            context,
            d.REPLACE_UNIVERSAL_CREDENTIAL,
            name=name,
            definition=definition,
            sub_type=sub_type,
            timeout=timeout,
            all_organizations=all_organizations,
            aligned_organizations=aligned_organizations,
        )
        # The new guid is returned, and the alignment consequence is stated in the payload rather
        # than only in the description, because the caller that most needs it is a client acting
        # on the response.
        return {
            "deleted_guid": guid,
            "recreated": recreated,
            "warning": (
                "The recreated credential has a NEW guid. Any device alignment referencing "
                f"{guid} must be re-pointed at the new guid."
            ),
        }

    return sl1_replace_universal_credential


# ---- Credential readers: sl1_list_credentials and sl1_get_credential ----------------------------
#
# This is the security core of the module. Read ``_filter_definition`` before editing either tool.
# Neither tool may return a secret. Nor may the passthroughs: ``sl1_credential_guard`` refuses their
# credential reads and routes any credential node found in their responses through
# ``_safe_credential``, so this section is the one place for both.
#
# Why withholding is post-processing: ``Credential.definition`` is a ``JSON`` scalar carrying
# stringified JSON, so it arrives as a ``str``. GraphQL sub-selection works on object types only,
# so no document can ask for ``definition.host`` without ``definition.password``; the field is
# all-or-nothing. It must be fetched, parsed, filtered and re-emitted as an object.
#
# Why the logging redaction layers do not help: ``errors.SECRET_FIELD_DENYLIST`` and
# ``mcp_app.logging_setup.RedactingFilter`` match on a mapping key or a LogRecord attribute name.
# Here the secrets live inside a string value under the single key ``definition``, and this is a
# tool return value, which no log filter touches.
#
# Why an allowlist and not a denylist: ``SECRET_FIELD_DENYLIST``, tested against the ten secret
# keys observed on a test appliance, caught one (``password``). It has no ``sshKeyData``,
# ``snmpRoCommunity`` or ``oauth2ClientSecret``, and the SSH private key is ``sshKeyData``, not
# ``pemkey``, so a "withhold password and pemkey" rule would have returned every SSH private key.
# A denylist has to be complete to be safe; an allowlist only has to be correct about what it
# names.


# Per-``CredentialType`` allowlist of ``definition`` keys that may be returned. Fail closed:
# anything not named here is withheld.
#
# Keys are matched exactly, as SL1 spells them. An exact match fails closed if SL1 ever re-cases a
# key (a safe field goes visibly missing into ``definition_withheld_keys``), whereas a loose match
# could admit a re-cased secret.
#
# ``authHeader`` and ``tokenKey`` are deliberately absent from ``UNIVERSAL``. Neither has been
# observed on an appliance, and both plausibly hold secret material (``authHeader`` can carry a
# literal ``Authorization`` value), consistent with withholding ``httpHeader1``/``httpHeader2``.
# They appear in ``definition_withheld_keys``, so the decision can be revisited if a caller needs
# one.
#
# Some names (``tokenFormat``, ``authEndpoint``, ``username``, ``prefix``, ``suffix``) have not
# been observed live and come from ``sl1_credential_definition``'s defaults table. Allowlisting an
# absent key is inert: it can only fail to match.
_DEFINITION_ALLOWLIST: Final[Mapping[str, frozenset[str]]] = {
    "BASIC_SNIPPET": frozenset({"host", "port", "user"}),
    "DATABASE": frozenset(
        {"host", "port", "user", "dbConnect", "dbName", "dbSid", "dbType"},
    ),
    "LDAP": frozenset(
        {
            "host",
            "port",
            "user",
            "userDn",
            "ldapDomain",
            "ldapScope",
            "ldapSecure",
            "ldapType",
        },
    ),
    "POWERSHELL": frozenset(
        {
            "host",
            "port",
            "user",
            "accountType",
            "adDomain",
            "adHost",
            "certValidate",
            "encrypted",
            "msgEncryption",
            "proxyHost",
        },
    ),
    # No ``host``: SNMP definitions carry none. The community strings and the v3 privacy password
    # are the secrets here, and none of the three is named below.
    "SNMP": frozenset(
        {
            "port",
            "user",
            "snmpRetries",
            "snmpVersion",
            "snmpv3AuthProto",
            "snmpv3Context",
            "snmpv3EngineId",
            "snmpv3PrivProto",
            "snmpv3SecLevel",
        },
    ),
    "SOAP_XML": frozenset(
        {
            "host",
            "port",
            "user",
            "url",
            "encoding",
            "httpVersion",
            "postOrGet",
            "proxyAcct",
            "proxyIp",
            "proxyPort",
        },
    ),
    # Three keys only. ``sshKeyData`` is the PEM private key and is not here.
    "SSH_KEY": frozenset({"host", "port", "user"}),
    "UNIVERSAL": frozenset(
        {
            "url",
            "authType",
            "proxy",
            "proxy_scheme",
            "proxyHost",
            "proxyPort",
            "proxyUser",
            "sslverifypeer",
            "ca_path",
            "debug",
            "timeToNextRequest",
            "tokenAuthRefresh",
            "tokenRefreshTTL",
            "tokenExpiresInSelector",
            "tokenFormat",
            "authEndpoint",
            "oauth2ClientId",
            "oauth2TokenURL",
            "oauth2TokenLabel",
            "oauth2TokenFormat",
            "oauth2TokenKey",
            "oauth2Type",
            "oauth2AuthType",
            "oauth2ClientCredentialsScope",
            "oauth2ResourceOwnerUsername",
            "oauth2ResourceOwnerScope",
            "username",
            "prefix",
            "suffix",
        },
    ),
}

# Per-``(type, subType)`` allowlist, consulted before ``_DEFINITION_ALLOWLIST`` and replacing it
# when it matches.
#
# ``_DEFINITION_ALLOWLIST`` is keyed by type alone, and its ``UNIVERSAL`` entry names the fields of
# one subtype, ``Low-code Tools: REST v104``. Without this table a ``UNIVERSAL`` credential of any
# other subtype (for example ``aws assume role``) would come back with every field withheld.
#
# This is still a hand-verified allowlist rather than being derived from the platform. The
# ``credentialFields`` templates mark secret fields with ``encryption: true``, but on the
# ``Low-code Tools: REST v104`` template that flag covers only ``password``, ``proxyPasswd``,
# ``oauth2ClientSecret``, ``oauth2ResourceOwnerPassword`` and ``apikey``. It does not mark
# ``authHeader``, ``tokenKey``, ``httpHeader1``, ``httpHeader2``, ``httpHeaders`` or ``opts``, all
# of which this module withholds deliberately, so deriving the rule from the flag would start
# returning all six. The flag is a denylist, and a denylist has to be complete to be safe. The
# templates are used to discover which fields a subtype has; this table remains the authority on
# which of them may leave.
#
# ``AwsAccessKeyId`` is withheld though the platform does not flag it: it is one half of an AWS key
# pair and identifies the account. It appears in ``definition_withheld_keys``, so the decision can
# be revisited. Note the inconsistency: ``SOAP_XML`` credentials that store an AWS access key in
# the allowlisted ``user`` field already return it. Making the two agree would change ``SOAP_XML``
# behaviour, which is a separate decision.
#
# One shared set covers all three AWS subtypes. Their templates differ (``aws ec2`` has
# ``OrganizationArn`` and ``IAM`` and no access-key pair; ``aws iam`` has no ``AssumeRole`` trio),
# but every name here is non-secret in whichever template declares it, and allowlisting an absent
# key is inert.
_AWS_UNIVERSAL_SAFE: Final[frozenset[str]] = frozenset(
    {
        "AwsEndpoint",
        "Config",
        "Regions",
        "Tags",
        "AssumeRole",
        "AssumeRoleSession",
        "OrganizationCreation",
        "OrganizationArn",
        "IAM",
        "ProxyHost",
        "ProxyPort",
        "ProxyUser",
        "ProxyProtocol",
        "SL1APISSLVerify",
    }
)

# The remaining subtypes below were measured from the ``credentialFields`` templates
# (``master.credential_fields``) on two appliances. Each set is complete for its template, because
# a subtype entry replaces the type-level set rather than extending it.
#
# The Low-code REST-shaped subtypes share the REST v104 fields, so they start from that set. The
# same deliberate withholdings apply to them (``authHeader``, ``tokenKey``, the header fields,
# ``opts``, ``authOverride``). ``Prometheus v100`` does not flag its ``apikey`` ``encryption: true``
# while REST v104 does, a second case of the flag being unreliable; it is withheld regardless.
_UNIVERSAL_REST_SAFE: Final[frozenset[str]] = _DEFINITION_ALLOWLIST["UNIVERSAL"]

# ``cred_pwd`` and ``ssh_key_data`` (the private key) are withheld; the ``ps_*`` fields are the
# PowerShell transport settings, not secrets.
_UNIVERSAL_SSH_SAFE: Final[frozenset[str]] = frozenset(
    {
        "cred_host",
        "cred_port",
        "cred_user",
        "record_metrics",
        "use_powershell",
        "ps_account_type",
        "ps_ad_domain",
        "ps_ad_host",
        "ps_msg_encryption",
        "ps_proxy_host",
        "ps_encrypted",
        "ps_cert_validate",
    }
)

# ``AccessKeyId`` is withheld with ``SecretAccessKey`` on the ``AwsAccessKeyId`` rule, and the
# backup encryption password and salt are secret.
_S3_BACKUP_SAFE: Final[frozenset[str]] = frozenset({"Provider", "Endpoint", "Region", "Bucket"})

# The SOAP_XML subtypes have their own field names, so the type-level SOAP_XML set would withhold
# nearly all of them. Key ids (``awsAccessKeyId``, Aliyun's ``accessKey``) are withheld on the
# ``AwsAccessKeyId`` rule. Azure's application, tenant and subscription ids are identifiers, not
# credentials, so they are returned; only ``azureSecretKey`` is the secret.
_SOAP_PROXY_SAFE: Final[frozenset[str]] = frozenset({"proxyHost", "proxyPort", "proxyUser"})

# Only subtypes whose templates were actually read are listed. An unlisted subtype falls back to
# ``_DEFINITION_ALLOWLIST``, which is correct for the ``BASIC_SNIPPET`` subtypes ``citrixXen`` and
# ``ibm`` (their fields match the type-level template) and withholds everything for ``SL Service
# Connection``, whose only field is ``secret``. Adding one is a data change plus a measurement.
_SUBTYPE_DEFINITION_ALLOWLIST: Final[Mapping[tuple[str, str], frozenset[str]]] = {
    ("UNIVERSAL", "aws assume role"): _AWS_UNIVERSAL_SAFE,
    ("UNIVERSAL", "aws ec2"): _AWS_UNIVERSAL_SAFE,
    ("UNIVERSAL", "aws iam"): _AWS_UNIVERSAL_SAFE,
    ("UNIVERSAL", "Low-code Tools: REST v105"): _UNIVERSAL_REST_SAFE | {"record_metrics"},
    ("UNIVERSAL", "Low-code Tools: Prometheus v100"): (
        _UNIVERSAL_REST_SAFE | {"tokenauth_refresh", "tokenauth_refresh_static_ttl"}
    ),
    ("UNIVERSAL", "HPE: Aruba Networking Central"): _UNIVERSAL_REST_SAFE,
    ("UNIVERSAL", "Low-code Tools: SSH v105"): _UNIVERSAL_SSH_SAFE,
    ("UNIVERSAL", "VMware vSphere"): frozenset({"username", "url"}),
    ("UNIVERSAL", "S3Backup"): _S3_BACKUP_SAFE,
    ("SOAP_XML", "VMware vSphere SOAP"): frozenset({"vmwareWebServiceUsername", "url"}),
    ("SOAP_XML", "aws"): _SOAP_PROXY_SAFE | {"awsEndpoint"},
    ("SOAP_XML", "azure"): _SOAP_PROXY_SAFE
    | {"azureUrl", "azureApplicationId", "azureTenantId", "azureSubscriptionId"},
    ("SOAP_XML", "aliyun"): _SOAP_PROXY_SAFE,
}

# The non-``definition`` fields either reader returns: a second fence, deliberately narrower than
# the documents.
#
# ``alignedOrganizations`` and ``editedBy`` are absent on purpose. ``alignedOrganizations`` returns
# ``[Organization]``, which carries a ``hash`` field, so it is safe only when sub-selected, and an
# object field nobody needs is one a future editor widens. If the documents are ever widened, this
# tuple drops the new field instead of forwarding it, and ``test_credential_definition_filter.py``
# asserts the two agree.
_SAFE_CREDENTIAL_FIELDS: Final[tuple[str, ...]] = (
    "id",
    "guid",
    "name",
    "type",
    "subType",
    "typeDescription",
    "timeout",
    "dateEdited",
    "allOrganizations",
)


def _is_scalar(value: object) -> bool:
    """Return whether a definition value is a JSON scalar (``str``, number, ``bool`` or ``null``).

    An extra fail-closed condition on top of the allowlist. Every allowed value observed live is a
    scalar; a container under an allowed name could nest secret material a key-level check cannot
    see. Withholding it is not silent: the key is reported in ``definition_withheld_keys``.
    """
    return value is None or isinstance(value, str | int | float | bool)


def _parse_definition(definition: object) -> tuple[dict[str, Any], str | None]:
    """Parse SL1's ``definition`` field into a mapping.

    SL1 sends a string of JSON (see this section's header). A ``dict`` is accepted too, in case a
    future build returns the object GraphQL's type says it might.

    A refusal reason never quotes the value. An unparseable definition is exactly the case where we
    do not know what is in it, so echoing it could leak a secret through the error path.

    :return: ``(mapping, refusal_reason)``; the reason is ``None`` on success.
    """
    if definition is None:
        return {}, None
    if isinstance(definition, dict):
        return definition, None
    if not isinstance(definition, str):
        return {}, (
            "The entire definition is withheld: SL1 returned it as "
            f"{type(definition).__name__}, which this tool does not know how to filter safely."
        )
    try:
        parsed = json.loads(definition)
    except ValueError:
        # ``json.JSONDecodeError`` is a ``ValueError`` subclass, so catching ``ValueError`` covers
        # it and any other ``ValueError`` from ``json.loads``, which must also be withheld.
        # ``TypeError`` cannot arise: the ``isinstance(definition, str)`` guard above rejects every
        # input ``json.loads`` would reject on type.
        return {}, (
            "The entire definition is withheld: it did not parse as JSON, so its keys could not "
            "be checked against the allowlist. The raw value is deliberately not shown."
        )
    if not isinstance(parsed, dict):
        return {}, (
            "The entire definition is withheld: it parsed as "
            f"{type(parsed).__name__} rather than an object, so it has no keys to allow."
        )
    return parsed, None


def _filter_definition(
    definition: object, credential_type: object, sub_type: object = None
) -> tuple[dict[str, Any], list[str], str | None]:
    """Filter a credential definition to its allowlisted keys; the one place secrets are withheld.

    Both readers share this function and ``_DEFINITION_ALLOWLIST`` on purpose: security-critical
    logic that exists twice will be corrected only once.

    The lookup is ``(type, subType)`` first, then ``type``. A subtype named in
    ``_SUBTYPE_DEFINITION_ALLOWLIST`` uses that set instead of the type-level one; anything else
    falls back. An unrecognised type withholds the entire definition and says so, which makes a new
    ``CredentialType`` safe by default. ``test_credential_definition_filter.py`` pins the
    allowlist's key set to the enum's eight members, so a new type fails a unit test first.

    ``withheld_keys`` keeps an omission visible: a caller who expected a field can see it was
    dropped rather than concluding SL1 does not store it. Key names are schema, not data (SL1's
    introspection publishes them to any authenticated caller), so reporting them discloses nothing.

    :param definition: SL1's ``definition`` value.
    :param credential_type: The credential's ``type``.
    :param sub_type: The credential's ``subType``.
    :return: ``(allowed, withheld_keys, refusal_reason)``.
    """
    parsed, reason = _parse_definition(definition)
    if reason is not None:
        return {}, [], reason

    # ``(type, subType)`` first, type alone as the fallback. A listed subtype replaces rather than
    # extends the type-level set: the AWS templates share no field name with the REST-shaped
    # ``UNIVERSAL`` entry, so a union would only add names that can never match.
    allowed: frozenset[str] | None = None
    if isinstance(credential_type, str):
        if isinstance(sub_type, str) and sub_type:
            allowed = _SUBTYPE_DEFINITION_ALLOWLIST.get((credential_type, sub_type))
        if allowed is None:
            allowed = _DEFINITION_ALLOWLIST.get(credential_type)
    if allowed is None:
        return (
            {},
            sorted(parsed),
            (
                f"The entire definition is withheld: credential type {credential_type!r} is not in "
                "this tool's per-type allowlist, so none of its fields can be classified as safe. "
                "Every key is listed in definition_withheld_keys."
            ),
        )

    kept: dict[str, Any] = {}
    withheld: list[str] = []
    for key, value in parsed.items():
        if key in allowed and _is_scalar(value):
            kept[key] = value
        else:
            withheld.append(key)
    return kept, sorted(withheld), None


def _safe_credential(node: dict[str, Any]) -> dict[str, Any]:
    """Reduce one ``Credential`` node to what may leave this service.

    ``definition`` leaves as a parsed object, never as the string SL1 sent, because the string
    contains the secrets. Both readers route every node through here for that reason.
    """
    shaped: dict[str, Any] = {
        field: node[field] for field in _SAFE_CREDENTIAL_FIELDS if field in node
    }
    values, withheld, reason = _filter_definition(
        node.get("definition"), node.get("type"), node.get("subType")
    )
    shaped["definition"] = values
    shaped["definition_withheld_keys"] = withheld
    if reason is not None:
        shaped["definition_withheld_reason"] = reason
    return shaped


def _credential_search(
    *, name_contains: str | None, credential_id: int | None, credential_guid: str | None
) -> dict[str, Any] | None:
    """Build SL1's ``search`` disjunction from the three optional lookups.

    ``*`` is stripped rather than translated. SL1's ``contains`` is a literal case-insensitive
    substring test, so a glob returns zero matches: ``contains: "Cisco*"`` returns 0 where
    ``"cisco"`` returns 4.

    Returns ``None`` rather than ``{"or": []}`` for no filter, because an empty disjunction is not
    a filter that matches everything.

    Kept at module level because each branch inside a tool closure also counts toward the
    factory's cognitive complexity.

    :return: The ``search`` variable, or ``None`` for no filter.
    """
    clauses: list[dict[str, Any]] = []
    needle = (name_contains or "").strip().strip("*").strip()
    if needle:
        clauses.append({"name": {"contains": needle}})
    if credential_id is not None:
        clauses.append({"id": {"eq": str(credential_id)}})
    if credential_guid:
        clauses.append({"guid": {"eq": str(credential_guid)}})
    return {"or": clauses} if clauses else None


def make_sl1_list_credentials(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_list_credentials`` tool bound to ``context``."""

    @sl1_tool_boundary(d.LIST_CREDENTIALS)
    async def sl1_list_credentials(
        name_contains: str | None = None,
        credential_id: int | None = None,
        credential_guid: str | None = None,
        first: int = 100,
    ) -> dict[str, Any] | list[Any]:
        """Find credentials by name substring, numeric id, or GUID. Read-only.

        NO SECRET IS EVER RETURNED. Passwords, community strings, SSH private keys, API keys, OAuth
        client secrets and HTTP header values are withheld. Each result lists the keys that were
        dropped in definition_withheld_keys, so nothing is missing silently.

        Returns, per match: name, id, guid, type, subType, typeDescription, timeout, dateEdited,
        allOrganizations, and the non-secret type-specific fields from the credential's definition
        (host, port, user, url and similar), as an object rather than a string.

        Any combination of the three lookups may be given and matches are OR-ed, so one call can
        resolve a name and an id at once. With none of them, the first credentials by name are
        returned. If more match than were returned, the response says so and gives the true total.

        Args:
            name_contains: Case-insensitive SUBSTRING of the credential name. This is NOT a glob:
                leading and trailing '*' characters are stripped, because SL1 matches them
                literally and 'Cisco*' would find nothing.
            credential_id: Exact numeric credential id.
            credential_guid: Exact credential GUID.
            first: Maximum credentials to return. SL1's own default is only 10.
        """
        # The glob-stripping and empty-disjunction rules live in the helper, with their reasoning.
        search = _credential_search(
            name_contains=name_contains,
            credential_id=credential_id,
            credential_guid=credential_guid,
        )

        connection = await _run(
            context, d.LIST_CREDENTIALS, {"first": int(first), "search": search}
        )
        found = [_safe_credential(node) for node in _nodes(connection)]

        page = connection.get("pageInfo") if isinstance(connection, dict) else None
        total = page.get("matchCount") if isinstance(page, dict) else None
        if isinstance(total, int) and total > len(found):
            # As in ``sl1_list_dynamic_apps``: a truncated result set is indistinguishable from a
            # complete one, so truncation is reported rather than left to be inferred.
            return {
                "credentials": found,
                "match_count": total,
                "truncated": True,
                "note": (
                    f"Showing {len(found)} of {total}. Raise first, or narrow with name_contains."
                ),
            }
        return found

    return sl1_list_credentials


def make_sl1_get_credential(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_get_credential`` tool bound to ``context``."""

    @sl1_tool_boundary(d.GET_CREDENTIAL)
    async def sl1_get_credential(
        credential_id: int | None = None, credential_guid: str | None = None
    ) -> dict[str, Any] | list[Any]:
        """Get one credential by id or by GUID -- supply exactly one. Read-only.

        NO SECRET IS EVER RETURNED, and the shape is identical to sl1_list_credentials: the
        non-secret metadata plus the allowed type-specific definition fields as an object, with
        every dropped key named in definition_withheld_keys.

        Args:
            credential_id: The numeric credential id. Supply this or credential_guid, not both.
            credential_guid: The credential GUID. Supply this or credential_id, not both.
        """
        has_id = credential_id is not None
        has_guid = bool(credential_guid and credential_guid.strip())
        if has_id == has_guid:
            # Validated here rather than by SL1: ``credential(id: null, guid: null)`` fails with
            # "The loader.load() function must be called with a value, but got: undefined.",
            # which names neither argument and reads like a service fault. Supplying both is
            # refused too, because SL1's precedence is undocumented.
            raise ValidationBlocked(
                [
                    ValidationFinding(
                        path="credential_id",
                        rule=FindingCode.TOOL_ARGUMENT,
                        message=(
                            "Supply exactly one of credential_id or credential_guid. "
                            "Use sl1_list_credentials to find a credential by name."
                        ),
                    )
                ]
            )

        variables = {"id": str(credential_id)} if has_id else {"guid": str(credential_guid).strip()}
        found = await _run(context, d.GET_CREDENTIAL, variables)
        if not isinstance(found, dict):
            # Fail closed rather than pass the value through under a wrapper key, as the
            # PowerPack and Event Policy readers do. An unfiltered credential has something to
            # hide, and ``_safe_credential`` cannot vouch for a shape it does not recognise.
            raise Sl1MalformedResponse
        return _safe_credential(found)

    return sl1_get_credential


# ---- PowerPacks: 3 tools ------------------------------------------------------------------------
#
# These return manifest-level metadata (name, version, publisher and so on), not the full LCE
# export shape that ``lce_get_powerpack`` returns. GraphQL ``powerPack(s)`` works on every version
# tested, including those below the LCE floor, which is why these exist alongside the LCE tools.
#
# ``installPowerPack`` is deliberately not wrapped: the upload step that produces a valid
# ``filename`` was never verified end to end.


def make_sl1_list_powerpacks(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_list_powerpacks`` tool bound to ``context``."""

    @sl1_tool_boundary(d.LIST_POWERPACKS)
    async def sl1_list_powerpacks(
        name_contains: str | None = None, first: int = 50
    ) -> dict[str, Any] | list[Any]:
        """List PowerPacks installed on the appliance, with manifest-level metadata.

        Returns name, version, publisher, revision, minimum version, vendors and models. This is NOT
        the full export shape with Dynamic Apps and objects -- use lce_get_powerpack for that, where
        LCE is available.

        Args:
            name_contains: Optional name substring filter.
            first: Maximum PowerPacks to return.
        """
        return _nodes(
            await _run(
                context,
                d.LIST_POWERPACKS,
                # The empty string rather than ``None``: the document declares ``$contains: String``
                # and feeds it to ``search.name.contains``, where a null filters nothing out.
                {"first": int(first), "contains": name_contains or ""},
            )
        )

    return sl1_list_powerpacks


def make_sl1_get_powerpack(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_get_powerpack`` tool bound to ``context``."""

    @sl1_tool_boundary(d.GET_POWERPACK)
    async def sl1_get_powerpack(powerpack_guid: str) -> dict[str, Any] | list[Any]:
        """Get one PowerPack's manifest-level metadata by GUID.

        Returns the fields sl1_list_powerpacks gives, plus supported versions, description, features
        and technical notes. This is NOT the full export shape -- use lce_get_powerpack for that.

        Args:
            powerpack_guid: The PowerPack GUID.
        """
        found = await _run(context, d.GET_POWERPACK, {"id": str(powerpack_guid)})
        return found if isinstance(found, dict) else {"powerPack": found}

    return sl1_get_powerpack


def make_sl1_list_uploaded_powerpacks(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_list_uploaded_powerpacks`` tool bound to ``context``."""

    @sl1_tool_boundary(d.LIST_UPLOADED_POWERPACKS)
    async def sl1_list_uploaded_powerpacks() -> dict[str, Any] | list[Any]:
        """List staged, not-yet-installed PowerPack files on the appliance.

        These are the uploaded .em7pp files -- the read half of the build, upload, install loop.
        Installation is not exposed as a tool: the upload step that produces a valid filename was
        never verified end to end, so wrapping the install would offer a workflow that may not work.
        """
        return _nodes(await _run(context, d.LIST_UPLOADED_POWERPACKS))

    return sl1_list_uploaded_powerpacks


# ---- Event Policies: 2 tools, read-only by design -----------------------------------------------
#
# Do not add create or update tools here. SL1's ``createEventPolicy`` and ``updateEventPolicy``
# mint non-hex ``cuid2`` GUIDs that break an LCE read once the policy is aligned to a Dynamic
# Application. Event Policies are created and updated through
# ``lce_create_or_update_event_policies``.


def make_sl1_list_event_policies(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_list_event_policies`` tool bound to ``context``."""

    @sl1_tool_boundary(d.LIST_EVENT_POLICIES)
    async def sl1_list_event_policies(
        name_contains: str | None = None, first: int = 50
    ) -> dict[str, Any] | list[Any]:
        """List event policies. Read-only.

        Returns id, name, enabled state, owning PowerPack, severity and cause. Works without LCE,
        unlike lce_list_event_policies.

        To CREATE or UPDATE an event policy, use lce_create_or_update_event_policies. Creating one
        through SL1's GraphQL API assigns a GUID format that breaks later LCE reads once the policy
        is aligned to a Dynamic Application.

        Args:
            name_contains: Optional name substring filter.
            first: Maximum policies to return.
        """
        return _nodes(
            await _run(
                context,
                d.LIST_EVENT_POLICIES,
                {"first": int(first), "contains": name_contains or ""},
            )
        )

    return sl1_list_event_policies


def make_sl1_get_event_policy(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_get_event_policy`` tool bound to ``context``."""

    @sl1_tool_boundary(d.GET_EVENT_POLICY)
    async def sl1_get_event_policy(event_policy_id: str) -> dict[str, Any] | list[Any]:
        """Get one event policy by id. Read-only.

        Returns the listing fields plus source, message, expiry and weight.

        To CREATE or UPDATE an event policy, use lce_create_or_update_event_policies -- see
        sl1_list_event_policies for why.

        Args:
            event_policy_id: The numeric event policy id.
        """
        found = await _run(context, d.GET_EVENT_POLICY, {"id": str(event_policy_id)})
        return found if isinstance(found, dict) else {"eventPolicy": found}

    return sl1_get_event_policy
