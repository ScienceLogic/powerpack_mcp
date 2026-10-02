"""
Guided Discovery Tool

This module defines ``sl1_create_guided_discovery_session``, which creates a Guided Discovery
session and then runs its workflow's ``discoveryActions`` in order, as the SL1 UI does. Through the
API, ``createGuidedDiscoverySession`` creates the session and runs nothing, and there is no
``runGuidedDiscoverySession`` mutation to finish the job.

A workflow's ``definition.discoveryActions`` is an ordered list of ``{mutationName,
queryVariables, result}``. Each variable is a reference in one of these forms:

- ``{"field": "discoverySession.organization"}``: a field on the session.
- ``{"field": "discoverySession.definition.rootDevice"}``: a property of the definition.
- ``{"value": "B9D0…"}``: a literal embedded in the workflow.
- ``{"field": "mutation.createVirtualDevice.id"}``: an earlier action's output.
- ``{"field": "credential"}``: the session's credential, with no prefix (see
  ``_credential_from_definition``).

Both the caller-facing result and every workflow-authored action document pass through
``sl1_credential_guard``. A workflow is platform data that a caller with ``sl1_graphql`` can author,
so every action's document is checked exactly as ``sl1_graphql`` would check it, all of them before
``createGuidedDiscoverySession`` is sent (and in a dry run), so a refused workflow creates nothing.
Each action is checked again with its resolved variables just before it runs. A session
``definition`` that embeds credential objects (the UI writes them; see
``_credential_from_definition``) is scrubbed on the way out.

``dateRun`` is not a run indicator: a session that has run still reports ``null``, the UI does not
stamp it, and neither does this tool.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Final

from powerpack_mcp.errors import PowerPackMcpError
from powerpack_mcp.tools import sl1_descriptors as d
from powerpack_mcp.tools.sl1_credential_guard import (
    refuse_credential_secret_document,
    scrub_credential_secrets,
)
from powerpack_mcp.tools.sl1_pipeline import audit_passthrough, sl1_tool_boundary

if TYPE_CHECKING:
    from powerpack_mcp.tools.sl1_pipeline import Sl1ToolContext
    from powerpack_mcp.tools.sl1_rest_tools import Sl1ToolFactory

__all__ = [
    "PendingAction",
    "PlannedAction",
    "ResolutionError",
    "build_action_plan",
    "build_mutation_document",
    "discovery_actions_of",
    "make_sl1_create_guided_discovery_session",
    "resolve_reference",
]

# The prefix marking a reference into the session object.
_SESSION_PREFIX: Final = "discoverySession."

# The prefix marking a reference into a previous action's output.
_MUTATION_PREFIX: Final = "mutation."

# The segment separating the session's own fields from its definition's properties.
_DEFINITION_SEGMENT: Final = "definition."

# The bare key the AWS workflow uses for the credential. A named constant because it is the one
# reference form that is not structural, so a reader tracing ``resolve_reference`` can find it.
_BARE_CREDENTIAL: Final = "credential"


class ResolutionError(PowerPackMcpError):
    """A reference could not be resolved.

    Its own type, so a caller can tell "this workflow references something I cannot supply" (usually
    a shape mismatch) from a bug in the resolver. The message always names the reference, because a
    workflow definition is platform data a caller cannot see without asking for it.

    It derives from ``PowerPackMcpError`` so the tool boundary, which catches only that hierarchy,
    turns it into a structured error envelope rather than an unhandled exception.
    """


# N818 wants an ``Error`` suffix, but this is not an error: it is a control-flow signal, see below.
class PendingAction(Exception):  # noqa: N818
    """A reference to an action that has not produced output yet.

    This is not a failure. Step two's ``device`` comes from ``mutation.createVirtualDevice.id``, so
    the plan for step one cannot be built without also resolving step two, which is impossible until
    step one has run. ``build_action_plan`` treats this as "stop here, the caller has work to do"
    and returns the prefix it could resolve.

    A reference to a mutation the workflow never lists stays a ``ResolutionError``: one means "not
    yet", the other means "never", and collapsing them would turn a broken workflow into a silently
    truncated run.

    :ivar mutation: The mutation whose output is awaited.
    :ivar reference: The reference that needs it.
    """

    def __init__(self, mutation: str, reference: str) -> None:
        self.mutation = mutation
        self.reference = reference
        super().__init__(f"{reference!r} awaits action {mutation!r}")


class PlannedAction:
    """One resolved action: the mutation to call and the arguments to call it with.

    Deliberately not the call itself. A plan that can be inspected before it is executed makes a
    declarative action list reviewable, which matters more here than for an LCE upsert because the
    actions are named by platform data, not by this code.

    :ivar mutation: The mutation name.
    :ivar variables: The resolved GraphQL variables.
    """

    __slots__ = ("mutation", "variables")

    def __init__(self, mutation: str, variables: dict[str, Any]) -> None:
        self.mutation = mutation
        self.variables = variables

    def __repr__(self) -> str:
        return f"PlannedAction(mutation={self.mutation!r}, variables={self.variables!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PlannedAction):
            return NotImplemented
        return self.mutation == other.mutation and self.variables == other.variables


def _parse_definition(raw: object) -> dict[str, Any]:
    """Parse a session's ``definition``, whether it arrives as a JSON string or an object.

    Both occur: SL1 returns and accepts it as a string, but a caller assembling one in memory
    holds a dict.

    :raises ResolutionError: If it is not an object or a JSON string encoding one.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ResolutionError(f"session definition is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ResolutionError(
                f"session definition parsed to {type(parsed).__name__}, expected an object"
            )
        return parsed
    raise ResolutionError(f"session definition is {type(raw).__name__}, expected an object or JSON")


def _credential_from_definition(definition: dict[str, Any]) -> str:
    """Return the credential guid from either shape SL1 writes.

    The shape is not fixed. Across real sessions on one appliance:

    * a session created through the API carries ``credential``, a bare guid string;
    * a session created through the UI carries ``credentials``, a list of full credential objects,
      each with ``guid``, ``__typename``, ``timeout``, ``dateEdited`` and more.

    Neither key appears in the workflow's ``workflowSteps``, so a resolver written from the
    workflow's declared fields alone would find nothing. Both are accepted, and the singular wins
    when both exist because it is the form the API round-trips.

    Only the first entry of the plural form is used. The AWS workflow's action takes a single
    ``credential: ID!``, so a multi-credential session has no defined meaning for it; taking the
    first is a guess, made explicit here.

    :raises ResolutionError: If neither form yields a guid.
    """
    singular = definition.get(_BARE_CREDENTIAL)
    if isinstance(singular, str) and singular:
        return singular

    plural = definition.get("credentials")
    if isinstance(plural, list) and plural:
        first = plural[0]
        if isinstance(first, dict) and isinstance(guid := first.get("guid"), str) and guid:
            return guid
        raise ResolutionError(
            "session definition's 'credentials' list has no usable guid on its first entry"
        )

    raise ResolutionError(
        "session definition carries neither a 'credential' guid nor a 'credentials' list; "
        "the workflow references a credential this session does not supply"
    )


def resolve_reference(
    reference: dict[str, Any],
    session: dict[str, Any],
    definition: dict[str, Any],
    outputs: dict[str, dict[str, Any]],
) -> Any:
    """Resolve one ``queryVariables`` entry's ``fieldName`` against the run context.

    A literal is checked before a field, matching the workflow's encoding where the two are
    alternatives. A reference carrying both is malformed, and preferring the literal at least keeps
    the behaviour deterministic.

    :param reference: The ``fieldName`` object, either ``{"value": …}`` or ``{"field": "…"}``.
    :param session: The guided discovery session as SL1 returned it.
    :param definition: The session's parsed definition.
    :param outputs: Results of actions already executed, keyed by mutation name.
    :return: The resolved value.
    :raises PendingAction: If the reference needs an action that has not run yet.
    :raises ResolutionError: If the reference cannot be resolved.
    """
    if "value" in reference:
        return reference["value"]

    field = reference.get("field")
    if not isinstance(field, str) or not field:
        raise ResolutionError(
            f"reference has neither a literal value nor a field name: {reference}"
        )

    if field == _BARE_CREDENTIAL:
        return _credential_from_definition(definition)

    if field.startswith(_MUTATION_PREFIX):
        rest = field[len(_MUTATION_PREFIX) :]
        mutation, _, attribute = rest.partition(".")
        if mutation not in outputs:
            raise PendingAction(mutation, field)
        produced = outputs[mutation]
        if attribute not in produced:
            raise ResolutionError(
                f"{field!r}: action {mutation!r} returned no {attribute!r} (it returned "
                f"{sorted(produced)})"
            )
        return produced[attribute]

    if field.startswith(_SESSION_PREFIX):
        rest = field[len(_SESSION_PREFIX) :]
        if rest.startswith(_DEFINITION_SEGMENT):
            prop = rest[len(_DEFINITION_SEGMENT) :]
            if prop not in definition:
                raise ResolutionError(
                    f"{field!r}: the definition has no {prop!r} (it has {sorted(definition)})"
                )
            return definition[prop]
        return _session_field(rest, field, session)

    raise ResolutionError(f"unrecognised reference form: {field!r}")


def _session_field(name: str, field: str, session: dict[str, Any]) -> Any:
    """Return a top-level session field, unwrapping the one-key objects SL1 nests.

    ``organization`` reads back as an object (``{"id": "1", "company": "AWS"}``), while the workflow
    declares ``discoverySession.organization`` as ``ID!``. Passing the object through would fail as
    an unhelpful type error from the mutation, so a nested ``id`` is unwrapped and anything else is
    returned untouched.
    """
    if name not in session:
        raise ResolutionError(f"{field!r}: the session has no {name!r} (it has {sorted(session)})")
    value = session[name]
    if isinstance(value, dict) and isinstance(nested := value.get("id"), str):
        return nested
    return value


def build_action_plan(
    session: dict[str, Any],
    workflow_definition: object,
    outputs: dict[str, dict[str, Any]] | None = None,
) -> list[PlannedAction]:
    """Resolve the workflow's ``discoveryActions`` into an ordered, inspectable plan.

    Actions whose variables depend on an earlier action cannot be resolved up front, so this returns
    the resolvable prefix and stops at the first forward reference. Execute what you get, pass the
    results back as ``outputs``, and call again until the plan stops growing. Placeholders that look
    like values are not emitted, because a placeholder in a mutation argument is indistinguishable
    from a real one at the point it does damage.

    Stopping is not failing: a reference to an action the workflow defines ends the prefix, while a
    reference to one it does not define raises ``ResolutionError`` (see ``PendingAction``).

    :param session: The guided discovery session as SL1 returned it.
    :param workflow_definition: The workflow's ``definition``, as a JSON string or an object.
    :param outputs: Results of already-executed actions, keyed by mutation name.
    :return: One ``PlannedAction`` per resolvable entry in ``discoveryActions``, in the workflow's
        own order.
    :raises ResolutionError: If the workflow is malformed.
    """
    parsed = _parse_definition(workflow_definition)
    actions = parsed.get("discoveryActions")
    if not isinstance(actions, list):
        raise ResolutionError(
            "the workflow definition has no 'discoveryActions' list, so there are no steps to run"
        )

    definition = _parse_definition(session.get("definition", {}))
    resolved_outputs = outputs or {}
    declared = {
        name
        for entry in actions
        if isinstance(entry, dict) and isinstance(name := entry.get("mutationName"), str)
    }
    plan: list[PlannedAction] = []

    for index, action in enumerate(actions):
        mutation = _mutation_name(index, action)
        try:
            variables = _resolve_variables(mutation, action, session, definition, resolved_outputs)
        except PendingAction as pending:
            # A forward reference to an action this workflow does list: stop, and hand back the
            # prefix. The caller executes it, feeds the outputs in, and calls again.
            if pending.mutation in declared:
                return plan
            # A reference to a mutation that appears nowhere in the action list is a broken
            # workflow, not a sequencing matter, so it must not be silently truncated.
            raise ResolutionError(
                f"{pending.reference!r} refers to action {pending.mutation!r}, which this "
                f"workflow does not define (it defines {sorted(declared)})"
            ) from pending
        plan.append(PlannedAction(mutation, variables))

    return plan


def _mutation_name(index: int, action: object) -> str:
    """Return one ``discoveryActions`` entry's ``mutationName``.

    :raises ResolutionError: If the entry is not an object or names no mutation.
    """
    if not isinstance(action, dict):
        raise ResolutionError(f"discoveryActions[{index}] is not an object")
    mutation = action.get("mutationName")
    if not isinstance(mutation, str) or not mutation:
        raise ResolutionError(f"discoveryActions[{index}] has no mutationName")
    return mutation


def _resolve_variables(
    mutation: str,
    action: dict[str, Any],
    session: dict[str, Any],
    definition: dict[str, Any],
    outputs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Resolve one action's ``queryVariables`` into the values to call its mutation with.

    :raises PendingAction: If a variable refers to an action that has not run yet.
    :raises ResolutionError: If a variable has no ``fieldName`` object.
    """
    variables: dict[str, Any] = {}
    for argument, spec in (action.get("queryVariables") or {}).items():
        if not isinstance(spec, dict) or not isinstance(spec.get("fieldName"), dict):
            raise ResolutionError(f"{mutation}.{argument} has no fieldName object: {spec!r}")
        variables[argument] = resolve_reference(spec["fieldName"], session, definition, outputs)
    return variables


def discovery_actions_of(workflow_definition: object) -> list[dict[str, Any]]:
    """Return the raw ``discoveryActions`` list, validated only as a list of objects.

    The document builder needs each action's declared ``fieldType``, which ``PlannedAction``
    deliberately does not carry: a plan is values, a document is types. The executor pairs the two
    by index, which is sound because ``build_action_plan`` returns a prefix in the workflow's order.

    :raises ResolutionError: If the definition has no ``discoveryActions`` list.
    """
    parsed = _parse_definition(workflow_definition)
    actions = parsed.get("discoveryActions")
    if not isinstance(actions, list):
        raise ResolutionError(
            "the workflow definition has no 'discoveryActions' list, so there are no steps to run"
        )
    return [entry for entry in actions if isinstance(entry, dict)]


def build_mutation_document(action: dict[str, Any]) -> str:
    """Render one action as a GraphQL mutation document.

    The mutation name, argument names, types and selection all come from platform data. This is a
    generic executor rather than an allowlist, so a workflow can name any mutation the calling
    account is permitted to run. Nothing here narrows that, and nothing should pretend to: a partial
    check would only make the blast radius harder to reason about.

    What is enforced is syntactic: every argument must declare a ``fieldType``, because an
    undeclared variable is a GraphQL validation error that SL1 would report as a bad query rather
    than a malformed workflow.

    The selection set is emitted verbatim, including nested forms such as
    ``active { maintenance unavailable }``. An action with no ``result`` gets no selection, which is
    valid only for a scalar-returning mutation.

    :param action: One entry from ``discoveryActions``.
    :return: The mutation document.
    :raises ResolutionError: If the action has no ``mutationName`` or an argument has no
        ``fieldType``.
    """
    mutation = action.get("mutationName")
    if not isinstance(mutation, str) or not mutation:
        raise ResolutionError("cannot build a document for an action with no mutationName")

    declarations: list[str] = []
    arguments: list[str] = []
    for argument, spec in (action.get("queryVariables") or {}).items():
        field_type = spec.get("fieldType") if isinstance(spec, dict) else None
        if not isinstance(field_type, str) or not field_type:
            raise ResolutionError(
                f"{mutation}.{argument} declares no fieldType, so no GraphQL variable can be "
                "declared for it"
            )
        declarations.append(f"${argument}: {field_type}")
        arguments.append(f"{argument}: ${argument}")

    selection = " ".join(
        str(entry["field"])
        for entry in (action.get("result") or [])
        if isinstance(entry, dict) and entry.get("field")
    )
    body = f"{mutation}({', '.join(arguments)})" if arguments else mutation
    if selection:
        body = f"{body} {{ {selection} }}"
    header = (
        f"mutation RunDiscoveryAction({', '.join(declarations)})"
        if declarations
        else "mutation RunDiscoveryAction"
    )
    return f"{header} {{ {body} }}"


# The document that creates the session. Ours, not the workflow's: only the actions are
# platform-supplied.
_CREATE_SESSION = """
mutation CreateGuidedDiscoverySession(
  $name: String!, $discoveryWorkflow: ID!, $organization: ID!, $definition: JSON!,
  $description: String
) {
  createGuidedDiscoverySession(
    name: $name, discoveryWorkflow: $discoveryWorkflow, organization: $organization,
    definition: $definition, description: $description
  ) { id name dateRun definition organization { id } }
}
"""

# How many times the resolve-execute loop may go round before it is treated as a cycle. Each pass
# must resolve at least one more action or the plan has stopped growing, so a well-formed workflow
# finishes in as many passes as it has actions. The bound exists because the action list is
# platform data, and a cycle of references would otherwise spin forever inside a tool call.
_MAX_PASSES: Final = 32

# Per-string cap on anything inside an action's ``result``.
#
# The workflow's own selection set can ask for bulky data: the AWS workflow's
# ``createVirtualDevice`` action selects ``icon { id name svg }``, so SL1 returns inline SVG of
# 2,000 to 2,500 characters that buys the caller nothing. The request is deliberately not filtered,
# so the platform is asked for exactly what the workflow declares; the bound is applied to the
# response instead.
#
# 500 matches ``sf_collection_output.MAX_SURFACED_MESSAGE_CHARS``, the existing bound for free text
# a caller did not ask for. ``errors.MAX_LCE_BODY_CHARS`` (2048) would pass such an icon almost
# whole.
MAX_RESULT_STRING_CHARS: Final = 500

# The walk stops descending at this depth, the same value as ``errors.MAX_LCE_BODY_DEPTH``, so
# recursion is bounded by the limit rather than by the input. A GraphQL result for a mutation this
# project did not write is a document it does not control.
MAX_RESULT_DEPTH: Final = 16

_RESULT_TRUNCATED: Final[str] = "… [truncated]"
_RESULT_TOO_DEEP: Final[str] = "**elided: nested beyond the depth limit**"


def _bounded_result(value: object, depth: int = 1) -> Any:
    """Cap every string inside one action's ``result``, marking each elision explicitly.

    This bounds values, never names. The selection set is platform data, so a list of bulky field
    names would be a guess about someone else's workflow that goes stale without failing; a length
    test needs to know nothing about AWS, icons or SVG, and a small ``svg`` passes through.

    Structure survives: every key, list position and scalar stays where it was, so a caller
    debugging a failed action still sees which fields came back. Only oversized text is cut.

    The parameter is ``object`` and the return ``Any`` because this walks what ``response.json()``
    produced, so the final fallback is genuinely reachable.
    """
    if depth >= MAX_RESULT_DEPTH:
        # Return WITHOUT descending. This is the bound, not a warning about one.
        return _RESULT_TOO_DEEP
    if isinstance(value, str):
        if len(value) <= MAX_RESULT_STRING_CHARS:
            return value
        return value[:MAX_RESULT_STRING_CHARS] + _RESULT_TRUNCATED
    if value is None or isinstance(value, bool):
        # ``bool`` before any ``int`` consideration: ``0`` and ``false`` are values, never absence,
        # the same distinction ``drop_empty`` and ``errors._sanitize_value`` make.
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, dict):
        return {key: _bounded_result(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [_bounded_result(item, depth + 1) for item in value]
    # Total by construction: anything the JSON parser could not have produced is rendered as a
    # bounded string rather than passed through unexamined.
    return _bounded_result(str(value), depth)


def make_sl1_create_guided_discovery_session(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_create_guided_discovery_session`` tool bound to ``context``.

    :param context: The clients, configuration and credential source the tool uses.
    :return: The tool function to register with the MCP server.
    """

    @sl1_tool_boundary(d.CREATE_GUIDED_DISCOVERY_SESSION)
    async def sl1_create_guided_discovery_session(
        name: str,
        discovery_workflow: str,
        organization: str,
        definition: dict[str, Any],
        description: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any] | list[Any]:
        """Create a Guided Discovery session AND run its workflow's steps, as the SL1 UI does.

        Creating a session through the API alone runs NOTHING -- measured on a live appliance: no
        device is created and the session sits inert. The UI runs the workflow's actions as part of
        its create step, and there is no runGuidedDiscoverySession mutation to do it afterwards.
        This tool closes that gap by executing the workflow's own discoveryActions in order, feeding
        each action's output into the next.

        Pass dry_run=true FIRST. It resolves every action against the session you describe and
        returns the ordered plan without creating the session or running anything.

        The actions are named by the workflow definition, which is platform data -- so this tool
        issues whatever mutations that definition lists. Review a dry run before committing. A
        workflow with an action that would read credential or other secrets is refused before
        anything is created, as sl1_graphql would refuse that action.

        Args:
            name: Session name.
            discovery_workflow: The workflow id, as returned by guidedDiscoveryWorkflows.
            organization: Organization id for the session and the devices it creates.
            definition: The session definition. Supply the properties the workflow's workflowSteps
                declare -- typically rootDevice, selectedCollectorGroupId -- plus credential set to
                a credential GUID.
            description: Optional session description.
            dry_run: When true, nothing is created and nothing is executed; the resolved plan is
                returned for review.

        Returns:
            Under dry_run, {"dry_run": true, "plan": [...]} with one entry per action. Otherwise
            the created session plus an "executed" list carrying each action's mutation, the
            variables it was called with, and what SL1 returned.

            Any single string in a returned result longer than 500 characters is cut and marked
            "… [truncated]" -- a workflow can ask SL1 for a device icon's inline SVG, which is
            several KB of path data. Structure, keys and ids are never altered.
        """
        audit_passthrough(
            d.CREATE_GUIDED_DISCOVERY_SESSION, method="POST", path="/gql", outcome="invoked"
        )

        # The workflow is read, and every action document checked, before anything is created: a
        # refusal half way through would leave a session behind.
        workflow = await _read_workflow(context, discovery_workflow)
        actions = discovery_actions_of(workflow.get("definition"))
        _refuse_unsafe_actions(actions)

        # Both returns are scrubbed: a session definition can embed full credential objects, and
        # the plan echoes the caller's definition back.
        if dry_run:
            return scrub_credential_secrets(
                _dry_run(workflow, discovery_workflow, organization, definition)
            )

        created = await _issue(
            context,
            _CREATE_SESSION,
            {
                "name": name,
                "discoveryWorkflow": discovery_workflow,
                "organization": organization,
                "definition": json.dumps(definition),
                "description": description,
            },
            "createGuidedDiscoverySession",
        )
        session = created if isinstance(created, dict) else {}
        # The workflow read and checked above is the one that runs, not a second copy from the
        # create response that the check never saw.
        executed = await _execute_actions(context, session, workflow, actions)

        ran = {
            "session": {k: v for k, v in session.items() if k != "discoveryWorkflow"},
            "executed": executed,
            "note": (
                f"{len(executed)} of {len(actions)} action(s) ran. dateRun is deliberately NOT "
                "stamped: the SL1 UI does not stamp it either, and a session that has run still "
                "reads null, so the field is not a run indicator."
            ),
        }
        return scrub_credential_secrets(ran)

    return sl1_create_guided_discovery_session


def _refuse_unsafe_actions(actions: list[dict[str, Any]]) -> None:
    """Check every action's document with the GraphQL rule, before anything is sent.

    Variables are not known yet (later ones come from earlier actions' outputs), so this is the
    document check alone; ``_execute_actions`` checks each action again with its variables.

    :raises ValidationBlocked: If any action's document is refused.
    :raises ResolutionError: If an action cannot be rendered as a document.
    """
    for action in actions:
        refuse_credential_secret_document(build_mutation_document(action), argument="definition")


def _dry_run(
    workflow: dict[str, Any],
    discovery_workflow: str,
    organization: str,
    definition: dict[str, Any],
) -> dict[str, Any]:
    """Resolve the plan for a session that is described, not created, and return it for review."""
    # The resolver only needs the session's shape, and the value of a dry run is that nothing
    # exists afterwards.
    pretend = {
        "id": "<not created -- dry run>",
        "organization": {"id": organization},
        "definition": definition,
    }
    plan, _ = _plan_all(pretend, workflow, dry_run=True)
    # The variable half of the check, as far as the plan resolves: what an execution would send,
    # placeholders included, so a dry run refuses what the real run would.
    actions = discovery_actions_of(workflow.get("definition"))
    for action, planned in zip(actions, plan, strict=False):
        refuse_credential_secret_document(
            build_mutation_document(action), planned.variables, argument="definition"
        )
    return {
        "dry_run": True,
        "workflow": {"id": discovery_workflow, "name": workflow.get("name")},
        "plan": [{"mutation": action.mutation, "variables": action.variables} for action in plan],
        "note": (
            "Nothing was created and nothing ran. Actions after the first are resolved "
            "with a placeholder for any earlier action's output, because the real value "
            "does not exist until that action runs."
        ),
    }


async def _execute_actions(
    context: Sl1ToolContext,
    session: dict[str, Any],
    workflow: dict[str, Any],
    actions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Run the workflow's actions in order, feeding each one's output into the next.

    :return: One entry per action that ran, carrying its mutation, variables and bounded result.
    """
    outputs: dict[str, dict[str, Any]] = {}
    executed: list[dict[str, Any]] = []

    for _ in range(_MAX_PASSES):
        plan = build_action_plan(session, workflow.get("definition"), outputs)
        if len(plan) <= len(executed):
            break
        for index in range(len(executed), len(plan)):
            action, planned = actions[index], plan[index]
            document = build_mutation_document(action)
            # The document is the workflow's, not ours, so it gets the same check a caller's
            # document gets from ``sl1_graphql``, now with the variables it will be sent with.
            refuse_credential_secret_document(document, planned.variables, argument="definition")
            result = await _issue(context, document, planned.variables, planned.mutation)
            # ``outputs`` keeps the unbounded result. Later actions resolve
            # ``mutation.<name>.<field>`` out of this dict, so a truncated value here would be sent
            # back to SL1 as a real mutation argument. Only the caller-facing echo is bounded.
            outputs[planned.mutation] = result if isinstance(result, dict) else {}
            executed.append(
                {
                    "mutation": planned.mutation,
                    "variables": planned.variables,
                    # Scrubbed before it is bounded: a JSON string cut at the bound no longer
                    # parses, and the scrub could not reach the secrets inside it.
                    "result": _bounded_result(scrub_credential_secrets(result)),
                }
            )
    return executed


async def _read_workflow(context: Sl1ToolContext, workflow_id: str) -> dict[str, Any]:
    """Read the workflow for its ``definition``, when the create response did not carry it."""
    document = (
        "query ReadGuidedDiscoveryWorkflow($id: ID!) "
        "{ guidedDiscoveryWorkflow(id: $id) { id name definition } }"
    )
    got = await _issue(context, document, {"id": workflow_id}, "guidedDiscoveryWorkflow")
    if not isinstance(got, dict):
        raise ResolutionError(f"workflow {workflow_id!r} did not return an object")
    return got


async def _issue(
    context: Sl1ToolContext, document: str, variables: dict[str, Any], root_field: str
) -> Any:
    """Issue one GraphQL call and return ``root_field`` out of ``data``.

    A missing root field is an error rather than ``None``, as in ``sl1_entity_tools._run``: GraphQL
    guarantees the key on success, so its absence means the response is not what was asked for.

    :raises ResolutionError: If ``data`` lacks ``root_field``.
    """
    body = await context.client.graphql(
        credential=context.credential_source(), query=document, variables=variables
    )
    data = body.get("data")
    if not isinstance(data, dict) or root_field not in data:
        raise ResolutionError(f"SL1 returned no {root_field!r} (it returned {sorted(data or {})})")
    return data[root_field]


def _plan_all(
    session: dict[str, Any], workflow: dict[str, Any], *, dry_run: bool
) -> tuple[list[PlannedAction], dict[str, dict[str, Any]]]:
    """Resolve as far as possible, substituting a visible placeholder for outputs not yet produced.

    Only for ``dry_run``, and the placeholder is deliberately not value-shaped. A plan is worth
    reviewing only if it shows every action, but later actions depend on outputs that do not exist
    yet. Each unresolved reference is filled with a string that says so, such as
    ``<from createVirtualDevice.id>``, rather than a plausible-looking id that someone could mistake
    for a value when approving the plan.

    :return: ``(plan, placeholder_outputs)``.
    """
    definition_source = workflow.get("definition")
    actions = discovery_actions_of(definition_source)
    outputs: dict[str, dict[str, Any]] = {}

    for _ in range(_MAX_PASSES):
        plan = build_action_plan(session, definition_source, outputs)
        if len(plan) >= len(actions) or not dry_run:
            return plan, outputs
        # Fill the next action's dependency with a self-describing placeholder and go round again.
        blocked = actions[len(plan)]
        for spec in (blocked.get("queryVariables") or {}).values():
            reference = spec.get("fieldName", {}) if isinstance(spec, dict) else {}
            field = reference.get("field")
            if isinstance(field, str) and field.startswith(_MUTATION_PREFIX):
                mutation, _, attribute = field[len(_MUTATION_PREFIX) :].partition(".")
                outputs.setdefault(mutation, {})[attribute] = f"<from {mutation}.{attribute}>"
    return build_action_plan(session, definition_source, outputs), outputs
