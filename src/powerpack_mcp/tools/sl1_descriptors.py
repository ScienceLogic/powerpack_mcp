"""
SL1 Operation Descriptors

This module describes the SL1 platform operations as data: 6 REST operations
(``Sl1OperationDescriptor``) and 19 GraphQL operations (``GraphQlDescriptor``), of which 16 are
typed and 3 send caller- or platform-supplied documents. No tool function contains a path, a
method or a GraphQL document as a literal.

SL1 operations need their own descriptor types because they do not share the LCE shape of method,
path template and lints. Most typed tools use GraphQL even though they sit in the
``ENABLE_SL1_REST_TOOLS`` set:

- REST: the 4 passthroughs and the 2 Dynamic Application readers (``dynamic_app/_lookup``).
- GraphQL: devices (5), credentials (6), PowerPacks (3), Event Policies (2), and the 3
  passthrough-style tools.

The typed GraphQL documents follow the ScienceLogic reference MCP implementation, without the
``target_host``, ``username`` and ``password`` parameters it takes: this server always uses the
caller's forwarded credential against the configured host. The two credential readers were
written for this server; see the comment above ``_LIST_CREDENTIALS``.

Descriptors that name a wrong path or transport still type-check and pass any test built from the
same descriptor. Single-sourcing prevents drift, not error; only a live appliance proves them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal, get_args

__all__ = [
    "ALLOWED_METHODS",
    "ALL_GRAPHQL_DESCRIPTORS",
    "ALL_REST_DESCRIPTORS",
    "GRAPHQL_PASSTHROUGH_DESCRIPTORS",
    "GRAPHQL_TYPED_DESCRIPTORS",
    "PASSTHROUGH_DESCRIPTORS",
    "REST_TYPED_DESCRIPTORS",
    "SL1_GRAPHQL_SET_DESCRIPTORS",
    "SL1_REST_SET_DESCRIPTORS",
    "GraphQlDescriptor",
    "Sl1Method",
    "Sl1OperationDescriptor",
]

# The closed verb set for the passthrough. ``TRACE`` and ``CONNECT`` are absent deliberately:
# neither has a legitimate use against the SL1 API, ``TRACE`` is a reflection primitive, and an open
# verb set would let a caller probe SL1's method handling.
Sl1Method = Literal["GET", "POST", "PUT", "DELETE"]

# Derived from ``Sl1Method`` rather than written out a second time, so the runtime check and the
# static type cannot drift. A hand-maintained copy would let the runtime guard admit a method the
# annotation forbids, or forbid one it permits.
ALLOWED_METHODS: Final[frozenset[str]] = frozenset(get_args(Sl1Method))


@dataclass(frozen=True, slots=True)
class Sl1OperationDescriptor:
    """One SL1 REST operation, described as data.

    ``is_mutating`` marks each destructive or mutating tool in its descriptor, so a future gate
    (a confirmation prompt, an extra flag, an audit rule) can be written once over the data rather
    than once per function.

    ``is_passthrough`` marks the four REST passthroughs that must be audit-logged. Because the
    audit rule reads the descriptor, a new passthrough cannot be forgotten by the logger.

    :ivar tool_name: The MCP tool name.
    :ivar path_base: The resource base the tool composes its path from; see the field comment.
    :ivar method: The HTTP method.
    :ivar is_mutating: Whether the tool can change SL1 state.
    :ivar is_passthrough: Whether the tool sends caller-supplied requests and must be audited.
    :ivar carries_secret_input: Whether the input carries secret material.
    """

    tool_name: str
    # A resource base, not a path template. The two typed REST tools both target
    # ``dynamic_app/_lookup`` and vary only by query string; the four passthroughs leave it empty
    # (or ``"/"``) because the path is the caller's and is validated per call. Each tool composes
    # its own complete path.
    path_base: str
    method: Sl1Method
    is_mutating: bool = False
    is_passthrough: bool = False
    # The input carries secret material and must never be logged, at any level.
    carries_secret_input: bool = False


@dataclass(frozen=True, slots=True)
class GraphQlDescriptor:
    """One SL1 GraphQL operation, described as data.

    There is no ``path`` field: every GraphQL call POSTs to the single ``/gql`` endpoint, and a
    field that always holds the same value will eventually be set wrong.

    ``document`` is the GraphQL transport's equivalent of a path and verb, so it lives here for the
    same reason paths do. The passthroughs leave it empty because their document is the caller's.

    ``root_field`` is the key to read out of ``data``. It cannot be derived from ``tool_name``:
    ``sl1_list_virtual_device_classes`` reads ``deviceClasses``, and
    ``sl1_replace_universal_credential`` reads ``createCredential`` because its second call is a
    create.

    :ivar tool_name: The MCP tool name.
    :ivar document: The query or mutation; empty for passthroughs.
    :ivar root_field: The key under ``data`` that holds the result.
    :ivar is_mutating: Whether the tool can change SL1 state.
    :ivar is_introspection: Whether the tool reads the schema rather than data.
    :ivar is_passthrough: Whether the tool sends documents it did not author and must be audited.
    :ivar carries_secret_input: Whether the input carries secret material.
    """

    tool_name: str
    document: str = ""
    root_field: str = ""
    is_mutating: bool = False
    is_introspection: bool = False
    is_passthrough: bool = False
    # The input carries secret material and must never be logged, at any level.
    carries_secret_input: bool = False


# ---- The four REST passthroughs ------------------------------------------------------------------
#
# These four are an arbitrary-request capability, registered by default and bounded by SL1's own
# authorization. Two controls compensate. The audit trail is one, which is why ``is_passthrough`` is
# descriptor data. ``sl1_credential_guard`` is the other: SL1's authorization lets an entitled
# account read stored credential secrets, so these tools refuse REST credential resources other
# than the plain indexes, refuse ``filter.``/``order.`` on secret-named fields and any
# ``link_disp_field`` beyond plain display fields on every resource, and scrub every response for
# secrets, keeping the passthroughs to the promise the typed credential readers make.

REST_REQUEST: Final = Sl1OperationDescriptor(
    tool_name="sl1_rest_request",
    path_base="",  # supplied by the caller, validated by `paths.ensure_relative_path`
    method="GET",  # overridden per call; the closed set is `ALLOWED_METHODS`
    is_mutating=True,  # it can be: the verb is the caller's, so assume the worst
    is_passthrough=True,
)

# ``path_base`` is ``"/"``, not ``""``: ``ensure_relative_path("")`` rejects the empty string, so
# with ``""`` this tool would fail validation on every call and never reach SL1. ``"/"`` passes the
# validator and composes to the API root. The path-safety validator is deliberately not loosened to
# accept ``""``.
REST_INDEX: Final = Sl1OperationDescriptor(
    tool_name="sl1_rest_index", path_base="/", method="GET", is_passthrough=True
)

REST_DESCRIBE: Final = Sl1OperationDescriptor(
    tool_name="sl1_rest_describe", path_base="", method="GET", is_passthrough=True
)

REST_SEARCH: Final = Sl1OperationDescriptor(
    tool_name="sl1_rest_search", path_base="", method="GET", is_passthrough=True
)

PASSTHROUGH_DESCRIPTORS: Final[tuple[Sl1OperationDescriptor, ...]] = (
    REST_REQUEST,
    REST_INDEX,
    REST_DESCRIBE,
    REST_SEARCH,
)

# ---- The two typed REST tools -------------------------------------------------------------------
#
# The only typed tools that are genuinely REST. Facts about the endpoint, verified live:
#
#   * the path is ``dynamic_app/_lookup``, not ``dynamic_app``
#   * the endpoint answers 302; our client raises only at ``>= 400``, so a 302 passes, but
#     redirect following must be confirmed rather than assumed
#   * a 500-row cap applies, so an unfiltered scan silently misses the target. Truncation is
#     reported in the output, because a truncated result otherwise looks complete
#   * server-side phrase filtering does not work, so multi-word search pre-filters on the longest
#     word server-side, then matches all words client-side in any order

LIST_DYNAMIC_APPS: Final = Sl1OperationDescriptor(
    tool_name="sl1_list_dynamic_apps", path_base="dynamic_app/_lookup", method="GET"
)
GET_DYNAMIC_APP: Final = Sl1OperationDescriptor(
    tool_name="sl1_get_dynamic_app", path_base="dynamic_app/_lookup", method="GET"
)

REST_TYPED_DESCRIPTORS: Final[tuple[Sl1OperationDescriptor, ...]] = (
    LIST_DYNAMIC_APPS,
    GET_DYNAMIC_APP,
)

# Every SL1 REST descriptor: 4 passthroughs + 2 typed = 6.
ALL_REST_DESCRIPTORS: Final[tuple[Sl1OperationDescriptor, ...]] = (
    *PASSTHROUGH_DESCRIPTORS,
    *REST_TYPED_DESCRIPTORS,
)

# ---- The 16 typed GraphQL tools ----------------------------------------------------------------
#
# Documents match the reference implementation token for token, except the two credential readers
# (see below). ``_CREATE_VDEV``, ``_ALIGN_DAS``, ``_UNALIGN_DAS`` and ``_CREATE_CREDENTIAL`` had
# their argument lists re-wrapped to fit 100 columns; GraphQL is whitespace-insensitive, and no
# field, argument or operation name changed.

_LIST_VDEV_CLASSES = """
query ListVirtualDeviceClasses($first: Int) {
  deviceClasses(first: $first, search: { virtualType: { eq: "virtual" } }) {
    edges { node { id class description virtualType } }
  }
}
"""

_CREATE_VDEV = """
mutation CreateVirtualDevice(
  $name: String!, $organization: ID!, $deviceClass: ID!, $collectorGroup: ID!
) {
  createVirtualDevice(
    name: $name, organization: $organization,
    deviceClass: $deviceClass, collectorGroup: $collectorGroup
  ) { id name }
}
"""

_DELETE_DEVICE = "mutation DeleteDevice($id: ID!) { deleteDevice(id: $id) }"

_ALIGN_DAS = """
mutation AlignDAs($device: ID!, $credential: ID!, $dynamicApplications: [ID!]) {
  alignDynamicApplicationsToDevice(
    device: $device, credential: $credential, dynamicApplications: $dynamicApplications
  ) {
    id pollRate credential { id name }
  }
}
"""

_UNALIGN_DAS = """
mutation UnalignDAs($device: ID!, $dynamicApplications: [ID!]) {
  unalignDynamicApplicationsFromDevice(
    device: $device, dynamicApplications: $dynamicApplications
  ) { id name }
}
"""

_CREATE_CREDENTIAL = """
mutation CreateUniversalCredential(
  $name: String!, $type: CredentialType!, $subType: String, $timeout: Int,
  $allOrganizations: Boolean, $alignedOrganizations: [ID], $definition: JSON
) {
  createCredential(
    name: $name, type: $type, subType: $subType, timeout: $timeout,
    allOrganizations: $allOrganizations, alignedOrganizations: $alignedOrganizations,
    definition: $definition
  ) { id guid name type subType timeout allOrganizations }
}
"""

_DELETE_CREDENTIAL = "mutation DeleteCredential($guid: ID!) { deleteCredential(guid: $guid) }"

_UPDATE_CREDENTIAL = """
mutation UpdateUniversalCredential(
  $guid: ID!, $name: String, $subType: String, $timeout: Int,
  $allOrganizations: Boolean, $alignedOrganizations: [ID], $definition: JSON
) {
  updateCredential(
    guid: $guid, name: $name, subType: $subType, timeout: $timeout,
    allOrganizations: $allOrganizations, alignedOrganizations: $alignedOrganizations,
    definition: $definition
  ) { id guid name timeout }
}
"""

# ---- The two credential readers ------------------------------------------------------------------
#
# Written for this server; the reference implementation wraps no credential read. Every fact below
# was measured by introspection against an SL1 12.5.x appliance:
#
#   * only three credential root fields exist, all returning the generic ``Credential`` type:
#     ``credential(guid, id)``, ``credentialTranslatedByCustomType(...)`` and ``credentials(...)``.
#     The seven typed objects (``SshCredential``, ``SnmpCredential``, ...) are unreachable from any
#     root field, so there is no way to ask for narrower fields.
#   * ``definition`` is a ``JSON`` scalar carrying stringified JSON, the same double encoding
#     ``sl1_credential_definition.serialize_universal_definition`` performs on the way in. A scalar
#     cannot be sub-selected, so the secret fields cannot be left out of the query; the field is
#     all-or-nothing. That is why ``sl1_entity_tools`` filters it after the fact.
#   * ``alignedOrganizations`` is deliberately not selected. It returns ``[Organization]``, which
#     has a ``hash`` field; an object field in the document invites a future editor to widen it.
#   * the top-level ``type:`` argument on ``credentials`` is silently ignored:
#     ``credentials(first: 1000, type: "SNMP")`` returned every type. Filter through
#     ``search: { type: { eq: "SNMP" } }``, which does push down.
#   * ``order`` takes ``[ConnectionOrder]``, whose ``field`` is an ``OrderFieldName`` scalar (hence
#     the quoted ``"name"``) and whose ``direction`` is the ``SortOrder`` enum, lowercase
#     ``asc``/``desc``. ``direction: ASC`` is a validation error.
#   * ``pageInfo.matchCount`` reports the true total independently of ``first``, which lets the
#     tool say "there are more" instead of silently truncating. The server default for ``first``
#     is 10.

_LIST_CREDENTIALS = """
query ListCredentials($first: Int, $search: CredentialSearch) {
  credentials(
    first: $first, search: $search, order: [{ field: "name", direction: asc }]
  ) {
    pageInfo { matchCount hasNextPage }
    edges {
      node {
        id guid name type subType typeDescription timeout dateEdited allOrganizations definition
      }
    }
  }
}
"""

# Both arguments are nullable ``ID``, and ``credential(id: null, guid: null)`` fails server-side
# with "The loader.load() function must be called with a value, but got: undefined.", which names
# neither argument and reads like a service fault. So ``sl1_get_credential`` validates "exactly one"
# client-side and passes only the supplied variable.
_GET_CREDENTIAL = """
query GetCredential($id: ID, $guid: ID) {
  credential(id: $id, guid: $guid) {
    id guid name type subType typeDescription timeout dateEdited allOrganizations definition
  }
}
"""

_LIST_POWERPACKS = """
query ListPowerPacks($first: Int, $contains: String) {
  powerPacks(first: $first, search: { name: { contains: $contains } }) {
    edges { node { id name version publisher revision minimumVersion vendors models } }
  }
}
"""

_GET_POWERPACK = """
query GetPowerPack($id: ID!) {
  powerPack(id: $id) {
    id name version publisher revision minimumVersion supportedVersions
    vendors models description features technicalNotes
  }
}
"""

_LIST_UPLOADED_POWERPACKS = "{ uploadedPowerPacks { edges { node { id } } } }"

_LIST_EVENT_POLICIES = """
query ListEventPolicies($first: Int, $contains: String) {
  eventPolicies(first: $first, search: { name: { contains: $contains } }) {
    edges { node { id name enabled powerpack severity { name } cause } }
  }
}
"""

_GET_EVENT_POLICY = """
query GetEventPolicy($id: ID!) {
  eventPolicy(id: $id) {
    id name enabled powerpack severity { name } source { name }
    message cause expiry weight
  }
}
"""

# Devices: 5 tools.
#
# ``alignDynamicApplicationsToDevice`` and ``unalignDynamicApplicationsFromDevice`` are absent on
# SL1 12.1.2 and 12.2.1 and present on 12.5.1 and 12.5.20. Virtual device create and delete work on
# every version tested.

LIST_VIRTUAL_DEVICE_CLASSES: Final = GraphQlDescriptor(
    tool_name="sl1_list_virtual_device_classes",
    document=_LIST_VDEV_CLASSES,
    root_field="deviceClasses",
)
CREATE_VIRTUAL_DEVICE: Final = GraphQlDescriptor(
    tool_name="sl1_create_virtual_device",
    document=_CREATE_VDEV,
    root_field="createVirtualDevice",
    is_mutating=True,
)
DELETE_DEVICE: Final = GraphQlDescriptor(
    tool_name="sl1_delete_device",
    document=_DELETE_DEVICE,
    root_field="deleteDevice",
    is_mutating=True,
)
ALIGN_DYNAMIC_APPS: Final = GraphQlDescriptor(
    tool_name="sl1_align_dynamic_apps_to_device",
    document=_ALIGN_DAS,
    root_field="alignDynamicApplicationsToDevice",
    is_mutating=True,
)
UNALIGN_DYNAMIC_APPS: Final = GraphQlDescriptor(
    tool_name="sl1_unalign_dynamic_apps_from_device",
    document=_UNALIGN_DAS,
    root_field="unalignDynamicApplicationsFromDevice",
    is_mutating=True,
)

# Credentials: 6 tools, 4 writers and 2 readers.
#
# ``createCredential``, ``deleteCredential`` and ``updateCredential`` were absent on one SL1 12.2.1
# system while present on 12.1.2, 12.5.1 and 12.5.20. The gap is not monotonic, so a version
# comparison cannot gate them.
#
# ``updateCredential`` is provisional: its merge resolver throws on some builds. Prefer replace when
# nothing live depends on the old guid, which is why the delete-then-recreate tool exists alongside
# update.

CREATE_UNIVERSAL_CREDENTIAL: Final = GraphQlDescriptor(
    tool_name="sl1_create_universal_credential",
    document=_CREATE_CREDENTIAL,
    root_field="createCredential",
    is_mutating=True,
    # ``definition`` carries secret material. Marked as data so the logging rule reads the
    # descriptor rather than relying on each tool remembering not to log an argument.
    carries_secret_input=True,
)
DELETE_CREDENTIAL: Final = GraphQlDescriptor(
    tool_name="sl1_delete_credential",
    document=_DELETE_CREDENTIAL,
    root_field="deleteCredential",
    is_mutating=True,
)
UPDATE_UNIVERSAL_CREDENTIAL: Final = GraphQlDescriptor(
    tool_name="sl1_update_universal_credential",
    document=_UPDATE_CREDENTIAL,
    root_field="updateCredential",
    is_mutating=True,
    carries_secret_input=True,
)

# Delete-then-recreate, not an in-place replace. The descriptor can name only one document, so it
# names the create, whose result the caller receives; the tool runs ``_DELETE_CREDENTIAL`` first.
# The tool must abort if the delete returns false, return the new guid, and state that device
# alignments referencing the old guid must be re-pointed, because alignment is by credential guid.
# ``is_mutating`` under-describes this: a replace that breaks every alignment is a data-integrity
# event, not an edit.
REPLACE_UNIVERSAL_CREDENTIAL: Final = GraphQlDescriptor(
    tool_name="sl1_replace_universal_credential",
    document=_CREATE_CREDENTIAL,
    root_field="createCredential",
    is_mutating=True,
    carries_secret_input=True,
)

# The two credential readers. Neither mutates nor takes secret input, but both read a record whose
# ``definition`` contains secret material. ``carries_secret_input`` does not cover that; it is
# handled by ``_filter_definition``'s per-type allowlist in ``sl1_entity_tools``.
LIST_CREDENTIALS: Final = GraphQlDescriptor(
    tool_name="sl1_list_credentials", document=_LIST_CREDENTIALS, root_field="credentials"
)
GET_CREDENTIAL: Final = GraphQlDescriptor(
    tool_name="sl1_get_credential", document=_GET_CREDENTIAL, root_field="credential"
)

# PowerPacks: 3 tools.
#
# These return manifest-level metadata (name, version, publisher, ...), not the full LCE export that
# ``lce_get_powerpack`` returns; the tool descriptions must say so or a client picks the wrong tool.
# ``installPowerPack`` is deliberately not wrapped: the upload step that produces a valid
# ``filename`` was never verified end to end.

LIST_POWERPACKS: Final = GraphQlDescriptor(
    tool_name="sl1_list_powerpacks", document=_LIST_POWERPACKS, root_field="powerPacks"
)
GET_POWERPACK: Final = GraphQlDescriptor(
    tool_name="sl1_get_powerpack", document=_GET_POWERPACK, root_field="powerPack"
)
LIST_UPLOADED_POWERPACKS: Final = GraphQlDescriptor(
    tool_name="sl1_list_uploaded_powerpacks",
    document=_LIST_UPLOADED_POWERPACKS,
    root_field="uploadedPowerPacks",
)

# Event Policies: 2 tools, read-only by design.
#
# Do not add ``createEventPolicy`` or ``updateEventPolicy``. Those mutations mint non-hex ``cuid2``
# GUIDs that break an LCE read once the policy is aligned to a Dynamic Application. Event Policies
# are created through ``lce_create_or_update_event_policies``.

LIST_EVENT_POLICIES: Final = GraphQlDescriptor(
    tool_name="sl1_list_event_policies",
    document=_LIST_EVENT_POLICIES,
    root_field="eventPolicies",
)
GET_EVENT_POLICY: Final = GraphQlDescriptor(
    tool_name="sl1_get_event_policy", document=_GET_EVENT_POLICY, root_field="eventPolicy"
)

GRAPHQL_TYPED_DESCRIPTORS: Final[tuple[GraphQlDescriptor, ...]] = (
    LIST_VIRTUAL_DEVICE_CLASSES,
    CREATE_VIRTUAL_DEVICE,
    DELETE_DEVICE,
    ALIGN_DYNAMIC_APPS,
    UNALIGN_DYNAMIC_APPS,
    CREATE_UNIVERSAL_CREDENTIAL,
    DELETE_CREDENTIAL,
    UPDATE_UNIVERSAL_CREDENTIAL,
    REPLACE_UNIVERSAL_CREDENTIAL,
    LIST_CREDENTIALS,
    GET_CREDENTIAL,
    LIST_POWERPACKS,
    GET_POWERPACK,
    LIST_UPLOADED_POWERPACKS,
    LIST_EVENT_POLICIES,
    GET_EVENT_POLICY,
)

# ---- The GraphQL passthroughs -------------------------------------------------------------------
#
# SL1 applies the caller's permissions to GraphQL data queries (see ``GRAPHQL_PREREQUISITE_MET``).
# It does not apply them to introspection: a restricted account can read the full schema, including
# fields it is forbidden to query. ``is_introspection`` therefore marks a tool with a different
# exposure profile from its sibling.
#
# The caller's permissions do not protect credential secrets from a caller entitled to read
# credentials. ``sl1_graphql`` therefore refuses, before sending, any document that would read them:
# inside a credential only allowlisted metadata may be selected, secret-named fields are refused on
# every type, and so are searches and sorts on either. It scrubs every response as well. The Guided
# Discovery tool applies the same check to every workflow-authored step before creating the
# session. ``sl1_credential_guard`` states the rule. ``sl1_graphql_introspect`` runs
# fixed documents that read the schema only, and needs neither.

GRAPHQL_QUERY: Final = GraphQlDescriptor(
    tool_name="sl1_graphql",
    # No document: it is the caller's. ``is_mutating`` assumes the worst for the same reason
    # ``REST_REQUEST`` does: an arbitrary document may carry a mutation.
    is_mutating=True,
    is_passthrough=True,
)
GRAPHQL_INTROSPECT: Final = GraphQlDescriptor(
    tool_name="sl1_graphql_introspect", is_introspection=True, is_passthrough=True
)

# Guided Discovery create-and-run.
#
# ``is_passthrough`` is correct here: the document issued for each step is built from the
# workflow's own ``discoveryActions`` (platform data), so the mutation name, arguments and
# selection set are not ours. That routes the call through ``audit_passthrough``.
#
# It sits with the GraphQL passthroughs deliberately, so it is gated by the same
# ``ENABLE_SL1_GRAPHQL_TOOLS`` flag: a caller who may not use arbitrary GraphQL must not reach it
# through a tool whose steps are arbitrary GraphQL by construction.
#
# ``carries_secret_input``: the session definition carries a credential guid rather than a secret,
# but a caller may place other workflow-declared values there, and the definition is echoed back in
# the plan.
CREATE_GUIDED_DISCOVERY_SESSION: Final = GraphQlDescriptor(
    tool_name="sl1_create_guided_discovery_session",
    is_mutating=True,
    is_passthrough=True,
    carries_secret_input=True,
)

GRAPHQL_PASSTHROUGH_DESCRIPTORS: Final[tuple[GraphQlDescriptor, ...]] = (
    GRAPHQL_QUERY,
    GRAPHQL_INTROSPECT,
    CREATE_GUIDED_DISCOVERY_SESSION,
)

# Every GraphQL descriptor: 16 typed + 3 passthrough.
ALL_GRAPHQL_DESCRIPTORS: Final[tuple[GraphQlDescriptor, ...]] = (
    *GRAPHQL_TYPED_DESCRIPTORS,
    *GRAPHQL_PASSTHROUGH_DESCRIPTORS,
)

# The SL1 REST tool set: gated by ``ENABLE_SL1_REST_TOOLS``, and not all REST.
#
# Membership is the ``sl1_rest`` set and the transport is mixed: 6 REST + 16 GraphQL. Moving the
# GraphQL tools to the GraphQL flag would change what an operator's existing configuration switches
# off. As a result, ``ENABLE_SL1_GRAPHQL_TOOLS=false`` does not disable GraphQL traffic; it disables
# only the passthroughs.
SL1_REST_SET_DESCRIPTORS: Final[tuple[Sl1OperationDescriptor | GraphQlDescriptor, ...]] = (
    *ALL_REST_DESCRIPTORS,
    *GRAPHQL_TYPED_DESCRIPTORS,
)

# The GraphQL passthroughs, gated by ``ENABLE_SL1_GRAPHQL_TOOLS``.
SL1_GRAPHQL_SET_DESCRIPTORS: Final[tuple[GraphQlDescriptor, ...]] = GRAPHQL_PASSTHROUGH_DESCRIPTORS

# Whether the GraphQL passthroughs may register. ``True`` because SL1 has been shown to apply the
# caller's permissions to a GraphQL query. Measured against a live appliance, same endpoint, headers
# and query, only the credential differing:
#
# * ``{credentials(first:3){edges{node{id name}}}}`` as a restricted account -> HTTP 200 carrying
#   ``errors[0].extensions.code == "RESTRICTED_ACCESS"``, "User does not have required
#   permissions.", and ``data.credentials: null``
# * the same query as ``em7admin`` -> three real credential records
# * ``{devices(first:3){...}}`` as the same restricted account -> real data, identical to
#   ``em7admin``'s. This call proves the credential authenticates, so the ``credentials`` denial is
#   a permission boundary rather than a broken credential or a malformed query
#
# This is a code constant, not a configuration key: an operator must not be able to enable an
# unverified authorization path, or silently disable a verified one, by editing a file. The value
# is tied to evidence, and changing it should be a reviewable commit.
#
# This does not mean GraphQL is permission-safe. Authorization applies to data queries;
# introspection is not permission-gated, so the two passthroughs do not share an exposure profile.
# Introspection exposes schema shape, not data.
GRAPHQL_PREREQUISITE_MET: Final[bool] = True
