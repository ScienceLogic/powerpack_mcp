# ScienceLogic Snippet Framework Development Rules

You are designing or modifying ScienceLogic Dynamic Applications using the Snippet Framework and the
Low-code Tools PowerPack. Favor consistency, maintainability, performance, and platform-aligned
design over creativity. If these rules conflict with older prompt guidance, these rules take
precedence.

Always prefer Snippet Framework app types (Snippet Framework Configuration or Snippet Framework
Performance). Do not choose legacy Snippet Configuration/Performance types unless explicitly
required for backward compatibility.

## 0. Core paradigm — trust the framework

Each collection object's `snippet_argument` must contain **complete instructions** for collecting
its data. Do not split logic across collection objects to "optimize" requests.

The Snippet Framework automatically detects repeated steps and eliminates duplicate work. If
multiple collection objects share identical requestor, parser or selector steps with the same
inputs, the framework deduplicates execution and does not re-request the data.

**Assume the framework handles deduplication correctly.** Do not introduce substitution or
artificial step-sharing to prevent re-requests.

## 1. Snippet Baseline

Always start from the default snippet provided by the Low-code Tools PowerPack. Do not replace the
default structure; only extend it when a functional requirement cannot be met through configuration
or step composition. Each collection object's `snippet_argument` must contain the complete
instructions for collecting that object's data.

## 2. Required Collection Pattern

Requestor -> Parser -> Selector. JMESPath is the preferred selector and must be used unless a
documented limitation prevents it. Deviation is permitted only with clear justification.

## 3. Execution Environment

The execution environment must include `silo.low_code`. Use the canonical Low-code environment;
multiple low-code environments is a configuration error.

## 4. Built-in Steps First

Prefer built-in steps over custom Python. Before using any step, confirm it exists and confirm its
arguments and output shape against the Low-code Tools PowerPack's own step documentation. **Do not
rely on memory for step signatures.**

> This server exposes no step-reference tool, so the verification is yours to do against the
> platform documentation. The discipline matters more than the mechanism: a guessed step signature
> fails at collection time, far from the cause.

## 5. Indexing

Indexes represent logical entity instances and must align across all collection objects in the same
group. Filtering must be consistent within the group. Prefer stable identifiers (IDs/names/keys);
avoid list position. In Config apps each index is a row and objects are columns; in Performance apps
each index is a time-series line.

## 6. Collection Frequency

Config apps default to 15-minute collection; Performance apps default to 5-minute. Override only
with justification.

## 7. Result Handling

The `result_handler` must be populated using the Snippet Framework. The final value returned by the
last step determines indexing behaviour:

- scalar final value -> index 0, the documented best practice for objects with no inherent index;
- list -> the index is the list position;
- dict -> the index is the dictionary key.

Two patterns are both valid, depending on design:

1. **Preferred** — return a list of objects using `{_index: <stable_id>, _value: <value>}` with
   `index: true`. This structure is **not** limited to display objects; it is a supported way to
   define indexed collection output, and in JMESPath it is usually the correct format for data
   collection objects.
2. A custom selector step returning a dictionary — used when JMESPath will not do the job.

Although the debugger may display results internally as a dictionary keyed by index at the final
step, the JMESPath step itself does **not** require you to hand-construct a pure `{uid: value}`
dictionary. **The primary requirement is stable, aligned indexes across collection objects — not a
particular output shape.**

## 8. Substitution

Substitution allows dynamic referencing of previously collected values within snippet arguments. It
is useful for:

- Component Dynamic Applications;
- referencing identifiers such as `distinguished_name` or `uid`;
- bringing in information from elsewhere in the system.

Substitutions are optional; do not add them by default. For simple static-path configuration apps
prefer literal values. **Do not use substitution to prevent duplicate requests — the framework
already deduplicates execution** (see section 0).

Substitutions must resolve deterministically and must not introduce ambiguity. Avoid circular or
overly complex chains, and do not let a substitution unintentionally alter index semantics.
`$silo_comp_uid` is only a token name; it is not inherently the index value.

## 9. Discovery & Dynamic Component Mapping (DCM)

If the application performs discovery, enable Component Mapping.

DCM terms:

- **Component** — a device created inside a DCM tree by a DCM discovery app.
- **Parent device** — the device that created the current component during discovery.
- **Root device** — a device at the top of the DCM tree; it has components beneath it and no
  component parent above it.

Map these identifier fields to collection objects:

- `name` — human-readable identifier used in the UI and API.
- `distinguished_name` — stable identifier, often non-human-facing (e.g. an AWS ARN). Frequently
  used for substitution and correlation.
- `uid` — unique identifier for the component instance.

UID rules: UIDs must be unique **within** a DCM tree, and the same UID may appear in different
trees. Each UID represents exactly one component device per tree. If the same UID is discovered
under the same root device but with a **different parent**, the platform updates the parent
association and creates a NOTICE-level new-parent event.

`$silo_comp_uid` is not inherently equivalent to the collection index. The two may align in some
designs, but they are conceptually separate unless explicitly designed to match.

## 10. Collector Affinity

Set `cu_affinity` explicitly; avoid `DEFAULT`. Use `ROOT_DEVICE` when root-collector cache locality
is required; otherwise prefer `ASSIGNED_COLLECTOR`.

## 11. Deduplication scope

The framework de-duplicates identical steps and inputs across collection objects even when each
`snippet_argument` is complete. Scope includes:

- within a Snippet Framework Configuration or Performance app;
- across devices within a single app, in bulk snippet scenarios;
- across apps and devices, when using the Snippet Framework app type.

Design each collection object as if it fully defines its own collection logic and let the framework
optimise execution internally. **Keep structure consistent between apps to maximise the chance of
steps being deduplicated** — differing inputs to a step mean it cannot be deduplicated. Do not
assume repeated requestor steps cause repeated network calls.

For large payloads, add an early selector step to sub-select before final field selection.

## 12. New-Entity Placeholders & Reference Rewrites

In a single create POST, use `reference` as a request-scoped placeholder — unique across the whole
payload — to wire relationships and formulas. Formula placeholders like `(cpu1)` are rewritten after
insert to canonical form, e.g. `(o_<new_id>)`. Canonical references: Collection `o_<id>`,
Presentation `pres_<id>`, Alert `a_<id>`, Snippet `snip_<id>`, Threshold `t_<id>`.

## 13. Final Validation Checklist

Snippet Framework app type; default snippet minimally modified; each object's `snippet_argument`
complete; `silo.low_code` environment; built-in steps preferred and each one verified against the
platform docs; requestor -> parser -> JMESPath honoured; indexes aligned and stable; filtering
consistent; `cu_affinity` explicit; new entities use explicit `reference`; large payloads
sub-selected; discovery maps `name`/`distinguished_name`/`uid` with unique UIDs.

## 14. Field-tested gotchas

These cost real debugging time on live Azure `getBatch` and event-policy work. Apply them directly.

- **Event policies: create via the LCE API, NEVER GraphQL.** GraphQL `createEventPolicy` mints
  non-hex `cuid2` GUIDs that fail LCE's `^[A-F0-9]{32}$` validator and break the Dynamic
  Application's LCE read once the policy is aligned. Use `lce_create_or_update_event_policies`,
  which assigns hex GUIDs. Align to a DA alert via `link_id` — the alert's numeric id.
- **A JMESPath filter after a projection returns null.** Break the projection with a pipe before
  filtering:
  `value[?name.value=='BgpAvailability'].timeseries[] | [?starts_with(metadatavalues[0].value,'Primary')] | [0].data[-1].average`
  The inline `timeseries[][?...][]` form silently returns null on live data.
- **Azure Peer dimension values are `Primary-IPv4`/`Secondary-IPv4`, not `Primary`/`Secondary`** —
  use `starts_with(...)`, not `==`.
- **An aggregate with no filter and no projection needs no pipe:**
  `...timeseries[][].data[-1].average | [0]`.
- **Two-tier alert suppression (team pattern):** guard the lower tier with
  `not active(<higher-tier alert>)` so only one event escalates. Expect a one-poll settling lag when
  a formula newly starts referencing another alert's state.
- **Prefer the business-logic API over raw SQL** — LCE over GraphQL over classic REST create over
  direct database access. Introspect the live system rather than trusting documentation:
  undocumented endpoints (LCE `/event_policies` among them) can exist and work.
