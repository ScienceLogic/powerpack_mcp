"""
Prompt Registry

This module provides ``register_prompts``, which registers the MCP prompts, and the prompt text
itself. Every tool a prompt names must exist on this server: a prompt that names a missing tool
is worse than no prompt, because the caller spends its turn discovering the tool is absent.

The ruleset is served as prompts rather than also mirrored as a tool. ``get_content_standards``
already gives a client that does not surface prompts the PowerPack entity rules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from powerpack_mcp.prompts.content import build_guide_topic, framework_rules

if TYPE_CHECKING:
    from fastmcp import FastMCP

__all__ = ["PROMPT_NAMES", "register_prompts"]

# Every prompt this module registers, in registration order, so a test can assert the surface
# without reaching into FastMCP privates. The tuple enforces nothing itself; ``test_prompts.py``
# compares it against what ``register_prompts`` actually registered.
PROMPT_NAMES: Final[tuple[str, ...]] = (
    "sl1_session_bootstrap",
    "sl1_snippet_framework_development_rules",
    "sl1_dynamic_app_payload_guide",
    "sl1_dynamic_app_update_checklist",
    "sl1_dynamic_app_api_context",
    "sl1_low_code_collection_flow_guide",
    "sl1_write_blast_radius_guide",
    "sl1_surface_selection_guide",
    "sl1_device_class_and_component_guide",
    "sl1_event_verification_guide",
    "sl1_credential_definition_guide",
    "sl1_discovery_session_guide",
    "sl1_virtual_device_lifecycle_guide",
)

_SESSION_WORKFLOW: Final[str] = """\
Session workflow (mandatory):
1. Treat the Snippet Framework rules above as baseline, including section 14's field gotchas.
2. For payload legality, pull the API guide with the `sl1_dynamic_app_api_context` prompt --
   topic="payload_core" is the right first slice.
3. Choose `cu_affinity` explicitly; never leave it DEFAULT.
4. For new entities in a create payload, use explicit request-scoped `reference` placeholders.
5. Verify every low-code step's arguments and output against the Low-code Tools PowerPack's own
   documentation before you use it. This server exposes no step-reference tool, so that check is
   yours to make -- and a guessed step signature fails at collection time, far from the cause.
6. Create event policies with `lce_create_or_update_event_policies`, which assigns hex GUIDs.
   Never GraphQL's `createEventPolicy`.
7. Know exactly what the upsert tools check for you, and what they do not. The
   `lce_create_or_update_*` tools run TWO BLOCKING lints before anything is sent -- every
   guid-suffixed key must be an uppercase 32-character hex GUID (omit it or pass null to have LCE
   assign one), and `threshold_objects[].type` must be exactly PERCENTAGE, INTEGER or DECIMAL --
   DECIMAL being the right choice for a fractional threshold, though INTEGER accepts one too
   and does not round it.
   Findings come back for every offending path at once, so one round trip surfaces every problem.
   ⛔ They do NOT apply the Pleco/PQT content standards. For those, call `get_content_standards`
   and SCOPE it (entity="event_policy"|"alert"|"dynamic_application"|...) so you pull a few rules
   rather than the whole 93-rule catalog. Two worth getting right without looking them up: event
   policies need a description carrying Description / Probable Cause / Resolution sections, and an
   alert `log_message` using %T should also use %V."""

_TOOL_SELECTION: Final[str] = """\
Tool selection (prefer the earliest that fits):
1. Prefer a TYPED tool (`sl1_*` / `lce_*`) over the raw gateways `sl1_rest_request` and
   `sl1_graphql`. Reach for a gateway only when no typed tool covers the operation; when you must,
   `sl1_rest_index`, `sl1_rest_describe` and `sl1_rest_search` are how you find the shape first.
2. Prefer a business-logic API over raw data access: LCE, then GraphQL, then classic REST, then the
   SQL-backed tools last. Direct database writes are a last resort used only where no API exists.
3. Authoring Dynamic Applications, event policies or PowerPack content: use the `lce_*` tools,
   which need SL1 12.5.20 or newer.
4. Reading existing content: `lce_get_dynamic_application` / `lce_get_event_policy` /
   `lce_get_powerpack` when LCE is available; otherwise `sl1_get_dynamic_app`,
   `sl1_get_event_policy` and `sl1_get_powerpack`, which also work below the LCE floor.
5. Reuse before create -- `sl1_list_icons` before `sl1_create_icon`, and list or get before making
   a duplicate of anything.
6. Against an unfamiliar target, run `sl1_check_capabilities` first: it live-probes the box and
   reports what works there, so you never have to reason about SL1 versions. `server_health` is
   the narrower connectivity and auth check.
7. Mutating with an LCE upsert? Pass `commit=False` first. That is LCE's own dry run: nothing is
   written, and you get to review the result before the real call.
8. Credentials: read before you write, and know which write actually works. `sl1_list_credentials`
   then `sl1_get_credential` to find and inspect one -- secret values are withheld unless your
   account holds the password-viewing hook, so a redacted definition means your entitlement, not a
   missing field. ⛔ `sl1_update_universal_credential` DOES NOT WORK on SL1 12.5.21: its merge
   resolver throws and the credential is left byte-for-byte unchanged, so a "failed" update has
   changed nothing. `sl1_replace_universal_credential` is the working path -- but it is
   DESTRUCTIVE, deleting and recreating, so fetch the current definition with
   `sl1_get_credential` first and keep it. Do not discover mid-flight that you cannot reconstruct
   what you replaced.
9. Running a collection is a TWO-STEP, ASYNCHRONOUS pair, and BOTH CALLS ARE THE NORMAL PATH.
   `sl1_run_dynamic_collection` dispatches and RETURNS IMMEDIATELY with a `proc_id` -- it does not
   wait. Then poll `sl1_fetch_collection_output` with `proc_id` and `after_id` (the previous
   reply's `last_id`, or 0 to start) until `terminated` is true.
   ⛔ `terminated: false` with no lines means NOT FINISHED YET -- ask again. It is not a timeout
   and not a failure. Measured on a Central Database, dispatch to termination took 12-27 s across
   three runs and grew as jobs queued; on a busy appliance it can be MINUTES, because most of the
   wait is the collector picking the job up rather than the collection running.
   Pass `wait_seconds` to either tool if you would rather block than poll; it is capped by what the
   request deadline has left, so a slow collection still hands back a receipt.
   Two things neither tool will do: there is no inverse, so a dispatched collection cannot be
   recalled, and they read only jobs this server created -- other Remote Toolbox jobs are refused.
10. Picking between LCE, a typed `sl1_*` tool and a raw gateway, or reading the GraphQL schema's
   `@deprecated` tags: see the `sl1_surface_selection_guide` prompt. It carries the LCE app-type
   boundary, the three gateway calls that silently do the wrong thing, and why `@deprecated`
   usually means *experimental* rather than *going away*.
11. Guided discovery: use `sl1_create_guided_discovery_session`, and pass `dry_run=true` FIRST to
   see the planned actions before anything is written. ⛔ Do NOT reach for `sl1_graphql` and
   `createGuidedDiscoverySession` -- that mutation creates the session and runs NOTHING (there is
   no `runGuidedDiscoverySession`), so the session looks complete and has done nothing. Read the
   available workflows with `sl1_graphql` on `guidedDiscoveryWorkflows`, which has no typed tool.
   ⚠️ `dateRun` is not a run indicator; it stays null even after a successful run.
12. Constructing or editing a UNIVERSAL credential `definition`: see the
   `sl1_credential_definition_guide` prompt. It carries the JSON-encoded-string rule, the
   case-exact subtype names, the `credentialFields` template query, and why a read cannot be
   round-tripped into a write.
13. ⛔ BEFORE THE FIRST WRITE OF ANY KIND, read `sl1_write_blast_radius_guide`. Five tools write
   straight to `master.*` with no transaction and no rollback, the whole surface has only three
   inverses, and only two writes offer a rehearsal. It is the one prompt whose absence costs
   something permanent.
14. Four more topics have their own prompts -- read the relevant one BEFORE the first write, because
   several of the tools involved cannot be undone: `sl1_device_class_and_component_guide`,
   `sl1_event_verification_guide`, `sl1_discovery_session_guide` (create and run are separate, and
   the create cannot be deleted) and `sl1_virtual_device_lifecycle_guide`."""

_BLAST_RADIUS: Final[str] = """\
Before ANY write on this server -- the blast radius, and what has no inverse:
1. ⛔ FIVE tools write DIRECTLY to the `master.*` database, bypassing SL1's own permission
   enforcement: `sl1_create_device_class`, `sl1_update_device_class`,
   `sl1_align_dynamic_app_to_device_class`, `sl1_simulate_event` and
   `sl1_run_dynamic_collection`. That is why they sit behind their own enable flag and why this
   server re-checks your account's access hooks for them -- no API layer is doing it for you.
2. ⛔ THERE IS NO TRANSACTION AND NO ROLLBACK. Autocommit is on for the platform-owned connection,
   so each statement commits as it completes. A tool that fails part-way through a sequence has
   ALREADY APPLIED the statements before the failure, so a PARTIALLY-APPLIED WRITE IS REACHABLE,
   not theoretical. No tool reports "nothing happened" on failure, because that is a claim it
   cannot make. Read the state back; never infer it from an error.
3. ⛔ THE ENTIRE TOOL SURFACE HAS THREE INVERSES: `sl1_delete_device`,
   `sl1_delete_credential` and `sl1_unalign_dynamic_apps_from_device`. Everything else you create
   is permanent. There is NO delete for a device class and NO delete for an icon anywhere here, so
   `sl1_create_device_class` and `sl1_create_icon` each leave a row you cannot remove. Reading
   values and writing them back over an update is a SECOND unrollbackable write, not an undo.
4. ⚠️ Only two writes rehearse. `sl1_create_guided_discovery_session` takes `dry_run=true`, and
   `lce_create_or_update_dynamic_applications` takes `commit=false`. For everything else the first
   call is the real one -- there is no rehearsal, so decide you want the effect before you ask.
5. The two async dispatches cannot be taken back either: `sl1_run_dynamic_collection` cannot be
   recalled once dispatched, and `sl1_simulate_event` inserts an event row unconditionally.
   `sl1_clear_event` is a PARTIAL inverse of the latter -- it moves the event and leaves a
   permanent cleared-event row, so the count never returns to where it was.
6. Per-workflow detail, each of which assumes you have read the above:
   `sl1_device_class_and_component_guide` (the partial state reachable ACROSS the create/align
   pair, not inside either tool), `sl1_event_verification_guide` (why an inserted row is a false
   pass for engine behaviour) and `sl1_surface_selection_guide` (the two near-identical name pairs
   where only one of each is a database write)."""

_SURFACE_SELECTION: Final[str] = """\
Choosing the right surface (this is where most wasted effort goes):
1. ⛔ LCE writes only SNIPPET FRAMEWORK apps. `lce_create_or_update_dynamic_applications` accepts
   app types 14, 15, 24 and 25 and rejects everything else with a 422. On a real stack a large
   minority of installed apps fall outside those types, so "LCE returned 422 for most of the
   PowerPack" means WRONG SURFACE, not a broken payload and not a task that needs the UI.
2. The `sl1_*` readers still read those apps. `sl1_get_dynamic_app`, `sl1_list_dynamic_apps` and
   `sl1_rest_request` reach every app regardless of type, and `sl1_rest_request` on a returned
   `collection_objects` or `presentation_objects` URI gets the detail. ⚠️ Nothing on the `sl1_*`
   surface WRITES a Dynamic Application's own fields -- `sl1_update_device_class` updates a device
   class, and `sl1_run_dynamic_collection` runs a collection. Neither edits an app.
3. Same entity, two shapes: use LCE for the authoring shape and for writes, and the `sl1_*` reader
   for manifest-level metadata or when the appliance is below the LCE floor.
   `lce_get_dynamic_application` vs `sl1_get_dynamic_app`, `lce_get_event_policy` vs
   `sl1_get_event_policy`, `lce_get_powerpack` vs `sl1_get_powerpack`/`sl1_list_powerpacks`.
4. ⛔ Three places a raw gateway silently does the WRONG thing, so use the typed tool:
   * A JSON POST to a discovery-session URI REPORTS SUCCESS AND STARTS NOTHING. Only
     `sl1_run_discovery_session` sends the content type SL1 requires.
   * `createGuidedDiscoverySession` through `sl1_graphql` creates an INERT session and runs no
     actions -- there is no `runGuidedDiscoverySession` mutation. Use
     `sl1_create_guided_discovery_session`, which creates AND runs, and pass `dry_run=true` first.
   * `createEventPolicy`/`updateEventPolicy` mint non-hex GUIDs that break a later LCE read once
     the policy is aligned to a Dynamic Application. Use `lce_create_or_update_event_policies`.
5. ⚠️ Two pairs of nearly identical names, and in each pair only one is a database write:
   * `sl1_align_dynamic_apps_to_device` (plural, a DEVICE, needs a credential, batch, reversible
     with `sl1_unalign_dynamic_apps_from_device`) vs `sl1_align_dynamic_app_to_device_class`
     (singular, a device CLASS, no credential, and an UNROLLBACKABLE write).
   * `sl1_set_device_class` (reclass a device) vs `sl1_update_device_class` (edit the class
     itself, also an unrollbackable write).
6. ⛔ SL1 tags EXPERIMENTAL features `@deprecated`, so "this field is deprecated" usually means
   "still under active development", not "going away". Of 359 root query fields, 202 are tagged
   deprecated and 156 of those say *Experimental*; only 46 say *known to be problematic*.
   `sl1_graphql_introspect` reports a `stability` of `stable`, `experimental` or `problematic`.
   Do NOT conclude a capability is missing because it is experimental -- and do not conclude it is
   missing from a schema read that excluded deprecated fields, which is the mistake that made
   guided discovery look unavailable when it was reachable all along."""

_DEVICE_CLASS_WORKFLOW: Final[str] = """\
Device classes and component trees (five tools, and three of them cannot be undone):
1. The chain is `sl1_create_device_class`, then `sl1_align_dynamic_app_to_device_class`, then
   `sl1_get_device_class_alignment` to verify. Read first with `sl1_get_device_class_alignment` --
   an alignment that already exists needs no write.
2. ⛔ THE PARTIAL STATE IS REACHABLE ACROSS THE PAIR, not inside either tool. The class INSERT can
   land while the alignment that follows fails, leaving a class with no aligned Dynamic
   Application and NOTHING able to reverse either half. There is no delete-device-class tool on
   this surface, so every success leaves a permanent row. Decide you want the class before you
   create it.
3. ⛔ `sl1_align_dynamic_app_to_device_class` is the one write here that MUST touch a real
   pre-existing platform row, because nothing on this surface creates a Dynamic Application. You
   cannot rehearse it against a throwaway target. Pass `device_class="0"` to unalign.
4. `sl1_update_device_class` is an UPDATE with no rollback. Reading the current values and writing
   them back afterwards is a second unrollbackable write, not a rollback -- do not plan on it as
   an undo.
5. `category` on `sl1_create_device_class` must resolve to a real device category or NOTHING is
   inserted; the tool refuses and says so. `ppguid` takes a PowerPack GUID or name, and "0",
   "null" or "none" for unowned -- but a name that does not resolve is refused rather than
   silently leaving the class unowned.
6. ⚠️ The identifier forms differ between siblings, which is the easiest mistake to make here:
   `sl1_update_device_class` and `sl1_set_device_class_icon` need a strict 32-character hex GUID;
   `sl1_align_dynamic_app_to_device_class` and `sl1_get_device_class_alignment` accept a GUID OR a
   numeric class type; `sl1_get_component_tree` takes a device id or name.
7. `sl1_get_component_tree` and `sl1_get_device_class_alignment` only read. Both can truncate, and
   both say so -- check the truncation and limit fields they return, because a truncated answer is
   otherwise indistinguishable from a complete one."""

_EVENT_VERIFICATION: Final[str] = """\
Verifying event behaviour -- TWO tools that look interchangeable and are not:
1. `sl1_inject_alert` exercises the REAL event engine. It needs an enabled event policy that
   matches on source=API to already exist; create that with
   `lce_create_or_update_event_policies`. Processing is asynchronous, so read the result back with
   `sl1_get_recent_events`. ⚠️ "No event policy matched" is a USEFUL DIAGNOSTIC, not a failure --
   it tells you the policy is missing, disabled or does not match.
2. ⛔ `sl1_simulate_event` inserts an event row UNCONDITIONALLY and runs NONE of the engine:
   no policy matching, no deduplication, no masking, no occurrence thresholds, no topology
   correlation and no auto-clear. Choosing it to test engine behaviour therefore gives a FALSE
   PASS -- measured live, an injected message under a policy whose auto-clear should have closed
   another active event left that event untouched. Use it only when you need a row to exist.
3. `sl1_clear_event` is a PARTIAL inverse of `sl1_simulate_event`, not a full one: clearing moves
   the event and leaves a permanent cleared-event row behind. The row count does not go back.
4. Alerts are CREATE-ONLY -- SL1 rejects updating or deleting one. Auto-clear needs the clearing
   message injected as well, against a registered clearer/cleared pair.
5. ⚠️ A clearing policy whose source is a Dynamic Application CANNOT be triggered by
   `sl1_inject_alert` at all. That path needs a real collection poll, which means
   `sl1_run_dynamic_collection` and then `sl1_fetch_collection_output` to read the result.
6. Threshold types, since this is where a policy gets rejected or silently stores the wrong value.
   `PERCENTAGE`, `INTEGER` and `DECIMAL` are the three the contract declares. Use DECIMAL for a
   fractional threshold -- it is the declared type, not a workaround. ⚠️ INTEGER is SEMANTIC, not
   a storage constraint: it accepts 75.5 and does not round it. The range is NOT enforced, so a
   PERCENTAGE of 500 stores happily; integrality is not enforced; real precision stops at three
   decimal places; and the column is unsigned, so a negative threshold cannot be stored at all."""

_CREDENTIAL_DEFINITION: Final[str] = """\
UNIVERSAL credentials -- the `definition` field is where a session gets lost:
1. ⛔ `definition` is a JSON-ENCODED STRING, not a nested object. It is an opaque scalar with no
   schema of its own, so nothing in the GraphQL types will tell you its shape.
2. The field names come from the `credentialFields` query PER TYPE AND SUBTYPE. Query that for the
   template before you construct anything -- the names are not discoverable any other way.
3. ⚠️ Subtype names are CASE- AND SPACE-EXACT. The UNIVERSAL AWS ones are `aws assume role`,
   `aws ec2` and `aws iam`, all lowercase. Naming any subtype other than the REST default also
   switches OFF the REST-specific defaulting, so you must then supply a complete definition.
4. ⛔ Secrets must be PLAIN STRINGS. A read returns them wrapped, and that wrapper is rejected on
   write for every field -- so you CANNOT round-trip what a read gave you back into a write.
   Storing the read shape produces a credential that authenticates against nothing.
5. Read before you write: `sl1_list_credentials` to find one, then `sl1_get_credential` to inspect
   it. ⚠️ `name_contains` is NOT a glob -- leading and trailing `*` are stripped, because SL1
   matches them literally and would find nothing.
6. ⛔ Secrets are never returned, and for an unrecognised credential type the ENTIRE definition is
   withheld -- including non-secret fields. Withheld keys are always named in the response, so a
   redacted definition means an entitlement or type-coverage limit, never a missing field. Do not
   read "definition is empty" as "the credential is empty".
7. ⛔ `sl1_update_universal_credential` is PROVISIONAL and its merge resolver throws on some SL1
   builds. When it throws THE CREDENTIAL IS BYTE-FOR-BYTE UNCHANGED -- there is nothing to undo,
   so do not "repair" it. `sl1_replace_universal_credential` is the working path, but it DELETES
   AND RECREATES, which CHANGES THE GUID: capture the definition with `sl1_get_credential` first,
   and re-make every alignment that referenced the old GUID, because
   `sl1_align_dynamic_apps_to_device` recorded the old one. If something live depends on the
   current GUID, prefer the update and accept that it may throw."""

_DISCOVERY_SESSION: Final[str] = """\
Classic discovery -- create and run are SEPARATE, and the create is permanent:
1. ⛔ `sl1_create_discovery_session` DEFINES a session and DOES NOT START IT. Starting it is
   `sl1_run_discovery_session`. Use both or neither: a created-but-never-run session is inert, and
   there is NO delete-session tool on this surface, so stopping half way leaves permanent litter.
   Poll `sl1_get_discovery_status` afterwards; an empty result means nothing is running.
2. `sl1_list_discovery_sessions` first -- an existing session you can re-run beats a new one you
   cannot remove.
3. ⚠️ Call `sl1_rest_describe` on the discovery-session resource BEFORE building the `session`
   argument. It is a raw passthrough and ITS FIELD NAMES VARY BY SL1 VERSION, so a shape that
   worked on one appliance can be silently wrong on another.
4. ⛔ Do NOT hand-roll the start through `sl1_rest_request`. SL1 needs a specific content type for
   this one, and a plain JSON POST REPORTS SUCCESS AND STARTS NOTHING. Only
   `sl1_run_discovery_session` sends it correctly.
5. ⛔ On a distributed stack, leave `aligned_collector` OUT of the `session` dict and let the tool
   choose. The platform default is appliance 1, which on a distributed stack is the Central
   Database -- it does not collect, so the session HANGS rather than failing. ⚠️ The tool's
   auto-selection checks the MERGED body, so passing `aligned_collector` inside `session` yourself
   SUPPRESSES it. An All-In-One is unaffected, because there appliance 1 is the collector.
6. ⚠️ This is NOT Guided Discovery, which is a different entity with no IP range, no credential and
   no collector alignment. For that use `sl1_create_guided_discovery_session`."""

_VIRTUAL_DEVICE_LIFECYCLE: Final[str] = """\
Virtual devices -- the one fully reversible chain on this surface, if you order it right:
1. `sl1_list_virtual_device_classes`, then pass a returned id as `device_class` to
   `sl1_create_virtual_device`. Guessing the class id is the usual first failure.
2. Get a credential GUID before aligning: `sl1_list_credentials` then `sl1_get_credential`, or
   `sl1_create_universal_credential` if none fits. `sl1_align_dynamic_apps_to_device` needs it;
   `sl1_unalign_dynamic_apps_from_device` does not.
3. ⛔ Alignment is ALL-OR-NOTHING PER BATCH, not per app. Every Dynamic Application in the call
   must be compatible with that device's device class or SL1 REJECTS THE WHOLE BATCH. Align in
   small batches if you are unsure which app is the incompatible one.
4. Verify with `sl1_get_collected_values`. ⚠️ Its per-presentation "data found" flag is what
   separates *collection is configured* from *collection produced something* -- an aligned app with
   no data looks identical to a working one if you only check the alignment.
5. Tear down in reverse: `sl1_unalign_dynamic_apps_from_device`, then `sl1_delete_device`. Both
   `sl1_delete_device` and `sl1_delete_credential` are PERMANENT.
6. ⚠️ `sl1_delete_device` has been observed returning NOT FOUND for deletes that SUCCEEDED. Do not
   retry on that basis and do not report a failure -- read the device back and believe the read.
   `sl1_delete_credential` reports truthfully, so the pattern is not uniform across deletes.
7. ⚠️ Two non-obvious dependencies. `sl1_align_dynamic_apps_to_device` and
   `sl1_unalign_dynamic_apps_from_device` resolve a Dynamic Application name or numeric id through
   LCE, so they need LCE REACHABLE even though neither is an `lce_*` tool. And both mutations are
   ABSENT on some older SL1 builds, where the failure is indistinguishable from a permissions
   problem -- run `sl1_check_capabilities` against an unfamiliar appliance first.
8. ⚠️ Identifier forms differ within this chain: `sl1_delete_device` and the align/unalign pair take
   a NUMERIC device id only, while `sl1_get_collected_values` accepts an id or a name."""

_BUILD_WORKFLOW: Final[str] = """\
After editing content -- through this server or the SL1 UI -- and before any build, commit or push:
1. Clear THIS PowerPack's own content from `/data/ppdev` on the appliance first. Not the whole
   shared directory: other engineers work on the same box. This gets missed constantly, so do it
   every round rather than only the first.
2. `/data/ppdev`, together with the matching `/etc/silo.conf` edit, is what tells the appliance to
   decompose the PowerPack into smaller files -- which is what makes it rsync-able to a developer
   machine and therefore reviewable in git. Skipping the clear-out is what produces a stale or
   monolithic export, so it is a correctness step, not hygiene.
3. Check local repository state -- git history, committed files, the code itself -- before reaching
   for Confluence, Jira or Slack. It is free and usually authoritative. Escalate only when local
   state genuinely cannot answer the question, and then query the ONE system most likely to hold
   the answer rather than all of them."""

_INTROSPECT: Final[str] = (
    "Prefer introspection over memory. Do not guess step behaviour, parameters or output structure."
)


def _compose(goal: str | None = None, extras: tuple[str, ...] = ()) -> str:
    """Join the ruleset, the caller's goal and any extra blocks, separated by blank lines.

    The ruleset leads every composed prompt because it carries the precedence clause, so anything
    after it that conflicts is resolved in the rules' favour.

    :param goal: The caller's stated goal, omitted when blank.
    :param extras: Further text blocks to append, in order.
    :return: The composed prompt text.
    """
    parts = [framework_rules()]
    if goal is not None and goal.strip():
        parts.append(f"Goal:\n{goal.strip()}")
    parts.extend(extra.strip() for extra in extras if extra.strip())
    return "\n\n".join(parts).strip()


def register_prompts(server: FastMCP) -> tuple[str, ...]:
    """Register every prompt on ``server`` and return their names, in order.

    Registration is unconditional; there is no ``ENABLE_*`` flag. Tool sets are gated because each
    is a reachable capability with a transport, a credential and a blast radius. A prompt is static
    text that touches neither SL1 nor the database, so a flag would switch off only the guidance.

    :param server: The FastMCP server to register on.
    :return: ``PROMPT_NAMES``.
    """

    @server.prompt()
    def sl1_session_bootstrap() -> str:
        """Connection-time bootstrap: Snippet Framework rules, then how to work on this server."""
        return _compose(extras=(_SESSION_WORKFLOW, _TOOL_SELECTION, _BUILD_WORKFLOW, _INTROSPECT))

    @server.prompt()
    def sl1_snippet_framework_development_rules(goal: str) -> str:
        """Inject the canonical Snippet Framework design rules for a stated goal."""
        return _compose(
            goal=goal,
            extras=(
                (
                    "Verify each step you choose against the Low-code Tools PowerPack "
                    "documentation before using it, and pull the API guide with "
                    "`sl1_dynamic_app_api_context` when payload legality is in question."
                ),
            ),
        )

    @server.prompt()
    def sl1_dynamic_app_payload_guide(goal: str) -> str:
        """The POST payload rules for Dynamic Applications, without the full ruleset."""
        return (
            "You are preparing a ScienceLogic Dynamic Application payload.\n\n"
            f"Goal:\n{goal.strip()}\n\nKey rules:\n"
            "- POST /lce/api/dynamic_applications takes a single object or a list.\n"
            "- Include `type` for a new DA; a `guid` implies update, and it must already exist.\n"
            "- `id` fields are ignored on POST; child objects must omit `guid` and `id`.\n"
            "- `reference` values must be unique across the WHOLE payload; use `(cpu1)`-style "
            "placeholders in formulas, which are rewritten to `(o_<new_id>)` after insert.\n"
            # Worded to avoid ruff ``S608``: this block shares an implicit concatenation with an
            # f-string, and "insert ... value" in the prose reads to the linter as SQL
            # construction.
            "- ⛔ `reference` is request-scoped wiring only and is never stored. Once the object "
            "exists, LCE replaces the label with a canonical `t_<id>`/`o_<id>`/`a_<id>` form, so "
            "what you send will not come back. Use it to link objects within one payload, never "
            "as a key you intend to match on later.\n"
            "- Set `cu_affinity` explicitly, preferring ASSIGNED_COLLECTOR.\n"
            "- Every guid-suffixed key must be an uppercase 32-character hex GUID, or be omitted, "
            "or be null. This is a BLOCKING lint -- nothing reaches LCE if it fails.\n"
            "- `threshold_objects[].type` must be exactly PERCENTAGE, INTEGER or DECIMAL. Also "
            "blocking. Use DECIMAL for a fractional threshold -- it is a first-class type, "
            "not a workaround. INTEGER with a fractional value is accepted too and is NOT "
            "coerced: the type is semantic, and SL1 stores the value in a decimal(13,3) "
            "column, so the real limit is three decimal places rather than integrality. "
            "The column is unsigned, so a negative value cannot be stored.\n"
            "- Pass `retrieve=true` to get the assigned GUID and ID values back.\n"
            "- Pass `commit=false` to dry-run the payload before writing it.\n"
            "- Create event policies with `lce_create_or_update_event_policies`, never GraphQL.\n"
            "- Start from `sl1_session_bootstrap` for the full ruleset, and pull "
            "`sl1_dynamic_app_api_context` for the authoritative schemas."
        ).strip()

    @server.prompt()
    def sl1_dynamic_app_update_checklist() -> str:
        """Checklist for updating an existing Dynamic Application."""
        return (
            "Update checklist for Dynamic Applications:\n"
            "- Include the DA `guid` in the root object to target an existing app.\n"
            "- Do not send `id` fields; they are ignored.\n"
            "- Keep `reference` unique across the whole payload.\n"
            "- ⛔ A child object's `guid` is the only identity LCE matches it on. To change an "
            "existing child you must send its `guid`.\n"
            "- ⛔ Re-sending a child by `reference` alone makes a new one every single time. It "
            "does not change the existing object and it does not error -- you get silent "
            "duplicates. `reference` does not persist as identity; LCE replaces it with a "
            "canonical `t_<id>` after insert, so the label you sent matches nothing later.\n"
            "- So: read the object back with `retrieve=true`, keep the `guid` it returns, and "
            "send that `guid` when you want to change the object.\n"
            "- Use `retrieve=true` when you need the new GUID and ID values returned.\n"
            "- Use `commit=false` first if the change is one you would not want to land twice."
        ).strip()

    @server.prompt()
    def sl1_dynamic_app_api_context(goal: str, topic: str = "payload_core") -> str:
        """One topic of the authoritative LCE API guide, inlined for a stated goal."""
        try:
            description, markdown = build_guide_topic(topic)
        except ValueError as exc:
            # Returned rather than raised: a prompt's arguments are caller-supplied text, and a
            # message naming the valid topics is more use to the caller than a protocol error.
            return f"Could not assemble the API guide topic.\n\n{exc}"
        return (
            f"You are working against the ScienceLogic LCE API.\n\nGoal:\n{goal.strip()}\n\n"
            f"API guide topic `{topic}` -- {description}\n\n{markdown}"
        ).strip()

    @server.prompt()
    def sl1_low_code_collection_flow_guide(
        goal: str,
        requestor_step: str = "http",
        parser_step: str = "json",
        selector_step: str = "jmespath",
    ) -> str:
        """Design a Requestor -> Parser -> Selector collection flow for a stated goal."""
        return _compose(
            goal=goal,
            extras=(
                (
                    f"Proposed pipeline: requestor `{requestor_step}` -> parser "
                    f"`{parser_step}` -> selector `{selector_step}`.\n"
                    "Section 2 requires this shape, and JMESPath is the preferred selector "
                    "unless a documented limitation prevents it. Confirm each of the three "
                    "steps exists and takes the arguments you intend against the Low-code "
                    "Tools PowerPack documentation before writing any logic.\n"
                    "⚠️ Section 14 applies directly to the selector: a JMESPath filter placed "
                    "after a projection silently returns null on live data. Break the "
                    "projection with a pipe before filtering."
                ),
            ),
        )

    _register_operations_prompts(server)
    return PROMPT_NAMES


def _register_operations_prompts(server: FastMCP) -> None:
    """Register the SL1 operations prompts.

    Split from ``register_prompts`` to keep both under ruff's ``C901`` complexity limit. The split
    is topical: ``register_prompts`` holds LCE authoring guidance, and this function holds guidance
    on operating the SL1 surface. Add a new prompt to whichever of the two it belongs in.

    :param server: The FastMCP server to register on.
    """

    @server.prompt()
    def sl1_write_blast_radius_guide(goal: str) -> str:
        """What cannot be undone, before the first write: the `master.*` five and the 3 inverses."""
        return _compose(goal=goal, extras=(_BLAST_RADIUS,))

    @server.prompt()
    def sl1_surface_selection_guide(goal: str) -> str:
        """Choose the right surface -- LCE, SL1 typed tool, or raw gateway -- for a stated goal."""
        return _compose(goal=goal, extras=(_SURFACE_SELECTION,))

    @server.prompt()
    def sl1_device_class_and_component_guide(goal: str) -> str:
        """Create, align and read device classes and component trees without a partial write."""
        return _compose(goal=goal, extras=(_DEVICE_CLASS_WORKFLOW,))

    @server.prompt()
    def sl1_event_verification_guide(goal: str) -> str:
        """Verify event behaviour: the real engine versus an inserted row, and threshold types."""
        return _compose(goal=goal, extras=(_EVENT_VERIFICATION,))

    @server.prompt()
    def sl1_credential_definition_guide(goal: str) -> str:
        """Build a UNIVERSAL credential `definition`, and edit one without breaking references."""
        return _compose(goal=goal, extras=(_CREDENTIAL_DEFINITION,))

    @server.prompt()
    def sl1_discovery_session_guide(goal: str) -> str:
        """Define and run a classic discovery session, in order and on a real collector."""
        return _compose(goal=goal, extras=(_DISCOVERY_SESSION,))

    @server.prompt()
    def sl1_virtual_device_lifecycle_guide(goal: str) -> str:
        """Create a virtual device, align Dynamic Applications to it, verify, and tear it down."""
        return _compose(goal=goal, extras=(_VIRTUAL_DEVICE_LIFECYCLE,))
