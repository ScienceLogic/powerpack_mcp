# Dynamic Applications API

**Get/Create/Update Dynamic Applications + Snippet Framework Entities**

## Endpoints covered

- `GET /lce/api/powerpacks/{powerpack_identifier}` _(GUID, ID, or name)_
- `GET /lce/api/dynamic_applications/{app_identifier}` _(GUID, ID or name)_
- `POST /lce/api/dynamic_applications` _(normalized request form)_

---

## 1) Overview

The Dynamic Applications API supports retrieving and bulk updating a Dynamic Application (DA) and its related entities:

- **Dynamic Application**
- **Snippets**
- **Collection Objects**
- **Presentation Objects** _(performance DAs only)_
- **Threshold Objects**
- **Alert Objects** (including triggered-alert chaining)

The **POST** endpoint is designed to support "single payload" Snippet Framework workflows:

- Create/update one or multiples Dynamic Applications and all their entities in **one POST**
- Allow in-request linking for new entities using **`reference`**
- Enforce strict "which fields are legal" rules for:
    - performance vs configuration dynamic applications
    - discovery collection objects
    - enum collection objects

#### Query parameters

##### `pretty` (GET + POST)

All the endpoints support a `pretty` boolean query parameter.

- `pretty=true`
    - Enums are serialized as their **string names** (e.g., `"ENABLED"`, `"PERFORMANCE_GAUGE"`)
    - Output is intended to be more human-readable (debugging, documentation, examples)

- `pretty=false`
    - Enums are serialized as their **integer values**
    - Output is more compact and better suited for programmatic diffing

> Note: Regardless of `pretty`, request payloads accept enums as either integers or string names (case-insensitive).

##### `retrieve` (POST only)

`POST /lce/api/dynamic_applications` supports a `retrieve` boolean query parameter.

- `retrieve=true`
    - The response includes a fully-expanded `entities` list containing the stored/normalized objects
    - This is useful for:
        - retrieving newly assigned `guid` and `id` values
        - seeing canonical `reference` rewrites (`o_<id>`, `snip_<id>`, etc.)

- `retrieve=false`
    - The response includes only the `results` array (per-entity identifiers + created/updated flags)
    - This is the default mode for bulk updates where the client does not need the full entity payload

---

## 2) Authentication & Authorization

### Authentication

Requires a valid Skylar One user session.

### Access Hooks

To call `GET /lce/api/dynamic_applications/{app_identifier}` you must have the following Access Hooks:

- `DYN_APP_VIEW`

To call `GET /lce/api/powerpacks/{powerpack_identifier}` you must have the following Access Hooks:

- `DYN_APP_VIEW`
- `SYS_POWERPACK_REG_PAGE`

To call `POST /lce/api/dynamic_applications` you must have the following Access Hooks:

- `SYS_DYN_APP_EDIT`
- `DYN_APP_EDIT`
- `DYN_APP_VIEW`
- `DYN_APP_FORMULA_EDIT`

---

## 3) Identifiers & request-scoped linking

### 3.1 `guid` (globally persistent identifier)

- Uppercase 32-hex string (`^[A-F0-9]{32}$`)
- Marks an entity as **existing** (update semantics)
- Immutable once created

**Rule:** If you supply a `guid`, the system treats the entity as _existing_ and will update it.
An exception will be raised if the entity with the GUID can not be found.

### 3.2 `reference` (request-scoped identifier)

- A string label used to link **new** entities inside the same request
- Any string value (e.g., `"cpu"`, `"snippet_1"`, `"alert_base"`)
- Must be **unique across the entire payload** (across all entity types)
- Returned back on response objects as `reference`

**Rule:** `reference` does _not_ persist as identity; it's only for request wiring and reporting.

**Reference auto-defaulting**

- If a model has `guid` and you omit `reference`, the base mixin sets `reference = guid`.
- Some entities override `set_reference()` after DB insert to set canonical references:
    - `CollectionObject.reference = "o_<id>"`
    - `PresentationObject.reference = "pres_<id>"`
    - `AlertObject.reference = "a_<id>"`
    - `Snippet.reference = "snip_<id>"`
    - `ThresholdObject.reference = "t_<id>"`

> Practical guidance: **always provide `reference`** for new objects you want to wire by reference in the same request.

### 3.3 `id` (DB numeric identifier)

- Returned in responses; not a stable external identifier for clients as it's not globally unique
- All `id` fields are **locked** (cannot be set)
- If an `id` is provided in a **POST** request, it is ignored
- Generally not accepted/required for requests except in a few internal linkage fields (e.g., `snippet_id`, `triggered_alert_id`)

---

## 4) Enum values: what you can send

Your enums inherit `FlexibleIntEnum`, which means request payloads accept **both**:

- integer values (e.g., `1`)
- string enum names (e.g., `"ENABLED"`, `"PERFORMANCE_COUNTER"`) — case-insensitive

Examples:

```json
{ "state": 1 }
{ "state": "ENABLED" }
```

Responses will typically emit the **string** as _pretty_ serialization is the default.

---

## 5) Request structure (authoritative)

`POST /lce/api/dynamic_applications` expects the **normalized** form of all the Dynamic Application
specific keys at the root level and other entities such as `snippets` nested within. The endpoint
also accepts multiple Dynamic Applications in a list:

#### Single Dynamic Application

```json
{
  "guid": "96AA113228DCF8E1396C45DFE2EAB9C0", // Existing Dynamic Application GUID
  "name": "Dynamic Application Name", // Optional Dynamic Application field
  "type": "SNIPPET_PERFORMANCE", // Required Dynamic Application field
  "snippets": [ ... ],
  "collection_objects": [ ... ],
  "presentation_objects": [ ... ],
  "threshold_objects": [ ... ],
  "alert_objects": [ ... ]
}
```

#### Multiple Dynamic Applications

```json
[
  {
    "guid": "96AA113228DCF8E1396C45DFE2EAB9C0", // Existing Dynamic Application GUID
    "name": "Dynamic Application Name", // Optional Dynamic Application field
    "type": "SNIPPET_PERFORMANCE", // Required Dynamic Application field
    "snippets": [ ... ],
    "collection_objects": [ ... ],
    "presentation_objects": [ ... ],
    "threshold_objects": [ ... ],
    "alert_objects": [ ... ]
  },
  {
    "type": "SNIPPET_CONFIGURATION", // Required Dynamic Application field
    "snippets": [ ... ],
    "collection_objects": [ ... ],
    "threshold_objects": [ ... ],
    "alert_objects": [ ... ]
  }
]
```

---

## 6) Formula conventions & reference rewrites

### 6.1 Collection object references in formulas

Canonical runtime references are:

- `o_<collection_object_id>`

Example:

```text
(o_123) * 100
```

### 6.2 Referencing newly-created objects in the same request

Because new collection objects do not yet have IDs, you can use your own **reference** label as a placeholder and the system rewrites it after insert.

Recommended pattern:

```text
(cpu1) * 100
```

Where the collection object was created with:

```json
{ "reference": "cpu1", "name": "CPU", "class_type": "PERFORMANCE_GAUGE" }
```

The service rewrites `cpu1` to `o_<new_id>` automatically during processing once an ID is assigned.

> **Recommendation:** Always wrap entity references in formulas with parentheses: `(cpu1)`.

---

## 7) Application type constraints

### 7.1 Allowed DA types

Only Snippet Framework application types are supported:

- `SNIPPET_PERFORMANCE`
- `SNIPPET_CONFIGURATION`
- `BULK_SNIPPET_PERFORMANCE`
- `BULK_SNIPPET_CONFIGURATION`

### 7.2 Snippet Framework App Type toggle (`is_sf_app_type`)

- If `is_sf_app_type == TRUE`: `type` must be **SNIPPET_PERFORMANCE** or **SNIPPET_CONFIGURATION**
- If `is_sf_app_type == FALSE`: `type` must be one of the allowed SF types listed above

### 7.3 Performance vs configuration object classes

If the DA is **performance**:

- Any unspecified `class_type` for a collection object is auto-set to `PERFORMANCE_COUNTER`
- Any non-allowed class_type raises a validation error
- Allowed `class_type` values:
    - `PERFORMANCE_COUNTER`
    - `PERFORMANCE_PERCENT`
    - `PERFORMANCE_KILOBYTE`
    - `PERFORMANCE_GAUGE`
    - `DISCOVERY`
    - `LABEL_HOURLY_POLLED`
    - `LABEL_ALWAYS_POLLED`
    - `INDEX`
    - `LABEL_IP_ALWAYS_POLLED`

If the DA is **configuration**:

- Any unspecified `class_type` for a collection object is auto-set to `CONFIG_CHARACTER`
- Any non-allowed class_type raises a validation error
- Allowed `class_type` values:
    - `CONFIG_CHARACTER`
    - `CONFIG_ENUM`
    - `CONFIG_TIMETICKS`
    - `CONFIG_GAUGE`
    - `CONFIG_NUMERIC`
    - `CONFIG_TIMESTAMP`
    - `CONFIG_MAC_ADDRESS`
    - `CONFIG_IP_ADDRESS`
    - `CONFIG_DATETIME`
    - `DISCOVERY`
    - `LABEL_HOURLY_POLLED`
    - `LABEL_ALWAYS_POLLED`
    - `INDEX`
    - `INDEX_LABEL`
    - `LABEL_CONFIG_GROUP`

---

## 8) Collection Object field legality (exact behavior)

Collection objects have _three_ "gating systems":

1. **Performance vs Configuration Application Type**
2. **Discovery Class Type**
3. **Enum Class Type**

### 8.1 Always-allowed fields (apply everywhere)

The following fields are always available for each collection object:

- `guid` _(immutable)_
- `name` _(required on create)_
- `reference`
- `class_type`
- `snippet_id`
- `snippet_reference`
- `snippet_argument`

### 8.2 Discovery object rules (class_type = DISCOVERY)

**Discovery-allowed fields**

- `tabular`
- `alignment_condition`

If `alignment_condition == IF_OID_PRESENT`, then the following fields are also allowed:

- `validity_check_pattern`
- `validity_check_operator`

### 8.3 Enum object rules (class_type = CONFIG_ENUM)

**Enum-allowed fields**

- `string_type`
- `group`
- `usage_type`
- `change_alerting`
- `table_alignment`
- `hide_object`
- `disable_maintenance`
- `description`
- `enum_values`
- `formula`

### 8.4 Performance-only vs configuration-only fields

**Configuration-allowed fields**

- `string_type`
- `group`
- `usage_type`
- `asset_link`
- `asset_link_precedence`
- `change_alerting`
- `table_alignment`
- `hide_object`
- `disable_maintenance`
- `description`
- `component_identifiers`
- `formula`

**PERFORMANCE_ONLY fields**

- `group`
- `usage_type`
- `enable_deviation_alerting`
- `min_weeks_data`
- `max_weeks_data`
- `disable_maintenance`

---

## 9) Entity schemas

### 9.1 Dynamic Application (`dynamic_app`)

**Required on create**

- `name` (string, 1–64)

**Optional**

- `guid` (GUID) _(required for existing Dynamic Applications)_
- `pp_guid` (GUID; optional - can be null if no aligned PowerPack)
- `is_sf_app_type` (BooleanToggle, default `FALSE`)
- `abandon_collection_limit` (int optional; coerces; default 0; ≥0)
- `max_devices` (int; default 50; ≥1; plus extra guard: if not SF app type, must be ≤500)
- `version` (float; default 1.0; ≥0.1)
- `state` (EnabledToggle; default ENABLED)
- `poll_interval` (PollInterval; default EVERY_15_MINUTES)
- `cu_affinity` (CUAffinity; default ASSIGNED_COLLECTOR)
- `execution_environment` (ExecutionEnvironment GUID or the default, `"sl1_default_ee"`)
- `component_mapping` (EnabledToggle; default DISABLED)
- `description` (string)
- `disable_rollup_of_data` (BooleanToggle; default FALSE)
- `release_notes` (string)
- `null_row_option` (MissingTableDataOption)
- `null_column_option` (MissingTableDataOption)
- `type` (ApplicationType, default `SNIPPET_CONFIGURATION`; If guid is provided (update), the service derives type from the database and ignores any supplied value)
- `component_mapping_dynamic_applications` (array of GUIDs or DA references; only include when component_mapping = EnabledToggle.ENABLED)
- `collection_objects` (array of CollectionObject)
- `snippets` (array of Snippet)
- `presentation_objects` (array of PresentationObject; optional - include only if you want to manually define presentation objects and disable auto-generation)
- `threshold_objects` (array of ThresholdObject)
- `alert_objects` (array of AlertObject)

### 9.2 Snippet (`snippets[]`)

**Required on create**

- `name` (string, 1–64)

**Optional**

- `guid` (GUID; immutable)
- `reference` (string)
- `snippet` (string; python code)
- `state` (EnabledToggle; default ENABLED)
- `required` (RequiredToggle; default REQUIRED)

### 9.3 Collection Object (`collection_objects[]`)

**Required on create**

- `name` (string, 1–64)
- `class_type` (CollectionObjectClass): **required in practice.** LCE's own published
  OpenAPI (and earlier revisions of this guide) show this as optional with a server
  default, but `lce_service`'s model marks it `REQUIRED_ON_CREATE`, so omitting it is a
  guaranteed 422. Verified against lce_service 3.1.0 source.

**Shared fields** _(Allowed for all types)_

- `guid` (GUID; immutable)
- `reference` (string)
- `class_type` (CollectionObjectClass)
- `snippet_id` (int; default 0)
- `snippet_reference` (string)
    - auto-set to `snip_<snippet_id>` if omitted and `snippet_id != 0`
- `snippet_argument` (string)

**Config-only**

- `string_type` (ConfigStringType)
- `group` (0–50)
- `usage_type` (CollectionObjectUsage)
- `asset_link` (AssetLink)
- `asset_link_precedence` (0..100 and must be increment of 10)
- `change_alerting` (EnabledToggle)
- `table_alignment` (TableAlignment)
- `hide_object` (BooleanToggle)
- `disable_maintenance` (BooleanToggle)
- `description` (string)
- `component_identifiers` (array of ComponentIdentifier) _(must be unique within the list; also globally unique across objects when component_mapping = EnabledToggle.ENABLED)_
- `formula` (string; max 512)

**Performance-only**

- `group` (0–50)
- `usage_type` (CollectionObjectUsage)
- `enable_deviation_alerting` (BooleanToggle)
- `min_weeks_data` (int ≥0)
- `max_weeks_data` (int ≥0)
- `disable_maintenance` (BooleanToggle)

**Discovery-only**

- `tabular` (EnabledToggle)
- `alignment_condition` (DiscoveryAlignmentCondition)
- `validity_check_pattern` (string max 128) _(only when alignment_condition is IF_OID_PRESENT)_
- `validity_check_operator` (DiscoveryOperator) _(only when alignment_condition is IF_OID_PRESENT)_

**Enum-only**

- `string_type` (ConfigStringType)
- `group` (0–50)
- `usage_type` (CollectionObjectUsage)
- `change_alerting` (EnabledToggle)
- `table_alignment` (TableAlignment)
- `hide_object` (BooleanToggle)
- `disable_maintenance` (BooleanToggle)
- `description` (string)
- `enum_values` (string)
- `formula` (string; max 512)

### 9.4 Presentation Object (`presentation_objects[]`) — performance apps only

**Required on create**

- `name` (string, 1–42)

**Optional**

- `guid` (GUID; immutable)
- `reference` (string)
- `guide_text` (string max 2048)
- `formula` (string max 512; default `"()"`)
- `show_as_percent` (BooleanToggle; default FALSE)
- `summarization_state` (BooleanToggle; default FALSE)
- `abbreviation_suffix` (string max 16)
- `data_unit` (string max 25)

### 9.5 Threshold Object (`threshold_objects[]`)

**Required on create**

- `name` (string, 1–64)

**Optional fields (with defaults/constraints)**

- `guid` (GUID; immutable)
- `reference` (string)
- `override_threshold_value` (BooleanToggle; default TRUE)
- `numeric_range_high` (float ≥0; default 100.0)
- `numeric_range_low` (float ≥0; default 0.0)
- `type` (ThresholdType; default PERCENTAGE)
- `unit` (string nullable; max 25)
- `value` (float ≥0; default 90.0)

### 9.6 Alert Object (`alert_objects[]`)

**Required on create**

- `name` (string, 1–128)
- `formula` (string, 1–512)
- `log_message` (string, 1–128)

**Optional**

- `guid` (GUID; immutable)
- `reference` (string)
- `state` (EnabledToggle; default DISABLED)
- `maintain_state` (EnabledToggle; default DISABLED)
- `triggered_alert_id` (int; default 0)
- `triggered_alert_reference` (string)
    - auto-set to `a_<triggered_alert_id>` if omitted and `triggered_alert_id != 0`

---

## 10) Cross-object validations

### 10.1 GUID uniqueness across the entire payload

All `guid` values must be unique across all entities (dynamic app, snippets, collection objects, etc.)

### 10.2 Reference uniqueness across the entire payload

All `reference` values must be unique across all entities (dynamic app, snippets, collection objects, etc.)

### 10.3 Component identifier uniqueness (when component_mapping enabled)

If `dynamic_app.component_mapping` is EnabledToggle.ENABLED:

- Each `CollectionObject.component_identifiers` must be unique within that object
- No identifier may appear in more than one collection object

---

## 11) Examples

### 11.1 Create performance app with a new collection object and explicit presentation

```json
{
    "name": "CPU Monitoring",
    "type": "SNIPPET_PERFORMANCE",
    "is_sf_app_type": "FALSE",
    "collection_objects": [
        {
            "reference": "cpu1",
            "name": "CPU Usage",
            "class_type": "PERFORMANCE_GAUGE"
        }
    ],
    "presentation_objects": [
        {
            "reference": "cpu_pres",
            "name": "CPU Chart",
            "formula": "(cpu1) * 100.0",
            "show_as_percent": "TRUE",
            "data_unit": "%"
        }
    ]
}
```

### 11.2 Config enum object

```json
{
    "name": "Interface Admin Status",
    "collection_objects": [
        {
            "name": "ifAdminStatus",
            "class_type": "CONFIG_ENUM",
            "enum_values": "1=up,2=down,3=testing",
            "table_alignment": "LEFT"
        }
    ]
}
```

### 11.3 Discovery object with OID-present

```json
{
    "name": "Discovery Example",
    "collection_objects": [
        {
            "name": "Discovery Object",
            "class_type": "DISCOVERY",
            "alignment_condition": "IF_OID_PRESENT",
            "tabular": "DISABLED",
            "validity_check_pattern": "ignored",
            "validity_check_operator": "MATCHES_REGEX"
        }
    ]
}
```

### 11.4 Adding New Threshold object to Existing Dynamic Application (retrieve=TRUE)

##### POST Body

```json
{
    "guid": "FD4DEEBD49925BEB6F04BE4DBFC8661A",
    "threshold_objects": [
        {
            "reference": "t_cpu",
            "name": "CPU High",
            "type": "PERCENTAGE",
            "value": 85,
            "unit": "%",
            "numeric_range_low": 0,
            "numeric_range_high": 100
        }
    ]
}
```

##### Response

```json
{
    "entities": [
        {
            "abandon_collection_limit": 0,
            "alert_objects": [],
            "collection_objects": [],
            "component_mapping": "DISABLED",
            "cu_affinity": "ASSIGNED_COLLECTOR",
            "description": "",
            "disable_rollup_of_data": "FALSE",
            "execution_environment": "sl1_default_ee",
            "guid": "FD4DEEBD49925BEB6F04BE4DBFC8661A",
            "id": 1134,
            "is_sf_app_type": "FALSE",
            "max_devices": 50,
            "name": "Postman - Minimal",
            "null_column_option": "DASH_VALUES",
            "null_row_option": "DASH_VALUES",
            "poll_interval": "EVERY_15_MINUTES",
            "pp_guid": null,
            "reference": "FD4DEEBD49925BEB6F04BE4DBFC8661A",
            "release_notes": "",
            "snippets": [],
            "state": "ENABLED",
            "threshold_objects": [
                {
                    "guid": "AB92071ECAC73541262265EF5A3E77E7",
                    "id": 414,
                    "name": "CPU High",
                    "numeric_range_high": 100.0,
                    "numeric_range_low": 0.0,
                    "override_threshold_value": "TRUE",
                    "reference": "t_414",
                    "type": "PERCENTAGE",
                    "unit": "%",
                    "value": 85.0
                }
            ],
            "type": "SNIPPET_CONFIGURATION",
            "version": 1.0
        }
    ],
    "results": [
        {
            "alert_objects": [],
            "collection_objects": [],
            "dynamic_app": {
                "guid": "FD4DEEBD49925BEB6F04BE4DBFC8661A",
                "id": 1134,
                "name": "Postman - Minimal",
                "new": false,
                "reference": "FD4DEEBD49925BEB6F04BE4DBFC8661A"
            },
            "presentation_objects": [],
            "snippets": [],
            "threshold_objects": [
                {
                    "guid": "AB92071ECAC73541262265EF5A3E77E7",
                    "id": 414,
                    "name": "CPU High",
                    "new": true,
                    "reference": "t_cpu"
                }
            ]
        }
    ],
    "success": true
}
```

### 11.5 Standard GET Response

```json
{
    "abandon_collection_limit": 0,
    "alert_objects": [
        {
            "formula": "(o_3351) > 1",
            "guid": "EE77BEC839E4059E95558C192F2B6D0D",
            "id": 818,
            "log_message": "Too many emails",
            "maintain_state": "DISABLED",
            "name": "Email",
            "reference": "a_818",
            "state": "DISABLED",
            "triggered_alert_id": 0
        },
        {
            "formula": "o_3350 > t_280",
            "guid": "BA86C7EC7B8462E2876D8D1DED2628AB",
            "id": 819,
            "log_message": "Too many tickets",
            "maintain_state": "DISABLED",
            "name": "Aligned Ticket",
            "reference": "a_819",
            "state": "DISABLED",
            "triggered_alert_id": 0
        }
    ],
    "collection_objects": [
        {
            "class_type": "PERFORMANCE_GAUGE",
            "description": "Random number based on aligned_ticket_queues size. The snippet argument uses substitution. For Example: \"$silo_comp_uid\" will be replaced by \"/api/account/2\"",
            "disable_maintenance": "FALSE",
            "enable_deviation_alerting": "FALSE",
            "formula": "",
            "group": 0,
            "guid": "70295D279EE9004DADA522E92604D8F5",
            "id": 3350,
            "max_weeks_data": 0,
            "min_weeks_data": 0,
            "name": "Based on Aligned Ticket Queues",
            "reference": "o_3350",
            "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"$silo_comp_uid\"\r\n    - json\r\n    - random_generator: \"aligned_ticket_queues\"",
            "snippet_id": 332,
            "snippet_reference": "snip_332",
            "usage_type": "STANDARD"
        },
        {
            "class_type": "PERFORMANCE_GAUGE",
            "description": "Random number based on email string length.The snippet argument uses substitution. For Example: \"$silo_comp_uid\" will be replaced by \"/api/account/2\"",
            "disable_maintenance": "FALSE",
            "enable_deviation_alerting": "FALSE",
            "formula": "",
            "group": 0,
            "guid": "71F6C83B432DA0C32FF7A4CA8D10CC3F",
            "id": 3351,
            "max_weeks_data": 0,
            "min_weeks_data": 0,
            "name": "Based on Email",
            "reference": "o_3351",
            "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"$silo_comp_uid\"\r\n    - json\r\n    - random_generator: \"email\"",
            "snippet_id": 332,
            "snippet_reference": "snip_332",
            "usage_type": "STANDARD"
        }
    ],
    "component_mapping": "DISABLED",
    "cu_affinity": "ASSIGNED_COLLECTOR",
    "description": "This Dynamic Application simulates performance data for each account.\r\n\r\nNotes:\r\nIn this Dynamic Application, a custom Step is defined, which is registered to generate a random number based on the previous result and action argument for the Collection Objects. Any custom Step registered via snippet code must be used in a Collection Object.",
    "disable_rollup_of_data": "FALSE",
    "execution_environment": "1BC13B3B88AAFB5399B94FEEE33EB48A",
    "guid": "96AA113228DCF8E1396C45DFE2EAB9C0",
    "id": 317,
    "is_sf_app_type": "FALSE",
    "max_devices": 50,
    "name": "Account Performance",
    "null_column_option": "DASH_VALUES",
    "null_row_option": "DASH_VALUES",
    "poll_interval": "EVERY_5_MINUTES",
    "pp_guid": "6450441E71B0EB1933D18A6C6252CF28",
    "presentation_objects": [
        {
            "abbreviation_suffix": "",
            "data_unit": "Rows",
            "formula": "(o_3350)",
            "guid": "4808E1AC211DAB3029740B077295B0A8",
            "guide_text": "This is a guide text",
            "id": 1000,
            "name": "Based on Aligned Ticket Queues",
            "reference": "pres_1000",
            "show_as_percent": "FALSE",
            "summarization_state": "TRUE"
        },
        {
            "abbreviation_suffix": "",
            "data_unit": "Rows",
            "formula": "(o_3351)",
            "guid": "240C671DF192FBADDC0B94EECA4CF2EE",
            "guide_text": "This is a guide text",
            "id": 1001,
            "name": "Based on Email",
            "reference": "pres_1001",
            "show_as_percent": "FALSE",
            "summarization_state": "TRUE"
        },
        {
            "abbreviation_suffix": "",
            "data_unit": "Emails",
            "formula": "(o_3351) + 1",
            "guid": "7BA723660C5E9DF1C86968350B3EAD2F",
            "guide_text": "",
            "id": 2367,
            "name": "Test",
            "reference": "pres_2367",
            "show_as_percent": "FALSE",
            "summarization_state": "FALSE"
        }
    ],
    "reference": "96AA113228DCF8E1396C45DFE2EAB9C0",
    "release_notes": "<strong>Version 2.0</strong><br>Updated the Execution Environment to Low-code Tools v100<br><br><strong>Version 1.1</strong><br>Updated to REST: Toolkit 101 Execution Environment and removed id fields from snippet arguments.<br><br><strong>Version 1.0</strong><br>Dynamic Application that uses available Steps from the low_code library and includes one custom Step.<ul class=\"fr-tag\"><li class=\"fr-tag\">low_code</li><li class=\"fr-tag\">http</li><li class=\"fr-tag\">json</li><li class=\"fr-tag\">random_generator (custom Step)</li></ul><br><hr><!--StartFragment--><!--EndFragment-->Copyright (c) 2003-2024 ScienceLogic, Inc.<br><br>This software is the copyrighted work of ScienceLogic, Inc.<br>Use of the Software is governed by the terms of the software license<br>agreement, which accompanies or is included with the Software<br>(&quot;License Agreement&quot;). An end user is not permitted to install any Software<br>that is accompanied by or includes a License Agreement, unless he or she<br>first agrees to the License Agreement terms.<br>The Software is made available solely for use by end users according to the<br>License Agreement. Any reproduction or redistribution of the Software not in<br>accordance with the License Agreement is expressly prohibited by law, and may<br>result in severe civil and criminal penalties. Violators will be prosecuted<br>to the maximum extent possible.<br><br>WITHOUT LIMITING THE FOREGOING, COPYING OR REPRODUCTION OF THE SOFTWARE TO<br>ANY OTHER SERVER OR LOCATION FOR FURTHER REPRODUCTION OR REDISTRIBUTION IS<br>EXPRESSLY PROHIBITED.<br><br>THE SOFTWARE IS WARRANTED, IF AT ALL, ONLY ACCORDING TO THE TERMS OF THE<br>LICENSE AGREEMENT. EXCEPT AS WARRANTED IN THE LICENSE AGREEMENT,<br>SCIENCELOGIC, INC. HEREBY DISCLAIMS ALL WARRANTIES AND CONDITIONS WITH REGARD<br>TO THE SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES AND CONDITIONS OF<br>MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT.<br><!--EndFragment--><!--EndFragment-->",
    "snippets": [
        {
            "guid": "02C935554551CA07CC790888DB819AAF",
            "id": 332,
            "name": "Custom Step Performance",
            "reference": "snip_332",
            "required": "REQUIRED",
            "snippet": "from silo.apps.errors import error_manager\r\nwith error_manager(self):\r\n\r\n    from silo.low_code import *\r\n    from silo.apps.collection import create_collections, save_collections\r\n\r\n    # =====================================\r\n    # =========== User Editable ===========\r\n    # =====================================\r\n    import random\r\n    \r\n    @register_processor\r\n    def random_generator(result, action_arg):\r\n        \"\"\"Generates random number between 0 and action_arg value size.\r\n\r\n        :param object result: Result from the parser\r\n        :param int action_arg: Action argument for the phase.\r\n\r\n        :return: Random number between 0 and action_arg value size\r\n        :rtype: Integer\r\n        \"\"\"\r\n        attribute_leng = len(result[action_arg])\r\n        generated_number = random.randint(0, attribute_leng)\r\n        return generated_number\r\n\r\n    \r\n    # List any custom substitutions that need to occur within the snippet arguments\r\n    custom_substitution = {}\r\n    # =====================================\r\n    # ========= End User Editable =========\r\n    # =====================================\r\n\r\n\r\n    collections = create_collections(self)\r\n    snippet_framework(collections, custom_substitution, snippet_id, app=self)\r\n    save_collections(collections, self)",
            "state": "ENABLED"
        }
    ],
    "state": "ENABLED",
    "threshold_objects": [
        {
            "guid": "5C08106971B4DB6E96A7B5290DD665C5",
            "id": 280,
            "name": "Test Threshold",
            "numeric_range_high": 100.0,
            "numeric_range_low": 0.0,
            "override_threshold_value": "TRUE",
            "reference": "t_280",
            "type": "INTEGER",
            "unit": "KB/s",
            "value": 90.0
        }
    ],
    "type": "SNIPPET_PERFORMANCE",
    "version": 2.0
}
```

### 11.6 Creating a Minimal Dynamic Application (retrieve=TRUE)

##### POST Body

```json
{
    "name": "Minimal"
}
```

##### Response

```json
{
    "entities": [
        {
            "abandon_collection_limit": 0,
            "alert_objects": [],
            "collection_objects": [],
            "component_mapping": "DISABLED",
            "cu_affinity": "ASSIGNED_COLLECTOR",
            "description": "",
            "disable_rollup_of_data": "FALSE",
            "execution_environment": "sl1_default_ee",
            "guid": "FD4DEEBD49925BEB6F04BE4DBFC8661A",
            "id": 1134,
            "is_sf_app_type": "FALSE",
            "max_devices": 50,
            "name": "Minimal",
            "null_column_option": "DASH_VALUES",
            "null_row_option": "DASH_VALUES",
            "poll_interval": "EVERY_15_MINUTES",
            "pp_guid": null,
            "reference": "FD4DEEBD49925BEB6F04BE4DBFC8661A",
            "release_notes": "",
            "snippets": [],
            "state": "ENABLED",
            "threshold_objects": [],
            "type": "SNIPPET_CONFIGURATION",
            "version": 1.0
        }
    ],
    "results": [
        {
            "alert_objects": [],
            "collection_objects": [],
            "dynamic_app": {
                "guid": "FD4DEEBD49925BEB6F04BE4DBFC8661A",
                "id": 1134,
                "name": "Minimal",
                "new": true
            },
            "presentation_objects": [],
            "snippets": [],
            "threshold_objects": []
        }
    ],
    "success": true
}
```

### 11.7 Multiple Dynamic Applications with References (retrieve=TRUE)

##### POST Body

```json
[
    {
        "abandon_collection_limit": 0,
        "alert_objects": [],
        "collection_objects": [
            {
                "asset_link": "NONE",
                "asset_link_precedence": 50,
                "change_alerting": "DISABLED",
                "class_type": "CONFIG_CHARACTER",
                "component_identifiers": ["DEVICE_NAME"],
                "description": "Account description.",
                "disable_maintenance": "FALSE",
                "formula": "",
                "group": 1,
                "hide_object": "FALSE",
                "name": "Account",
                "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"/account\"\r\n    - json\r\n    - jmespath:\r\n        index: true\r\n        value: \"result_set[*].{_index: URI, _value: description}\"",
                "string_type": "STANDARD",
                "table_alignment": "LEFT",
                "usage_type": "STANDARD"
            },
            {
                "component_identifiers": ["UNIQUE_IDENTIFIER", "UUID"],
                "description": "Account identifier.",
                "disable_maintenance": "FALSE",
                "formula": "",
                "group": 1,
                "hide_object": "FALSE",
                "name": "Id",
                "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"/account\"\r\n    - json\r\n    - jmespath:\r\n        index: true\r\n        value: \"result_set[*].{_index: URI, _value: URI}\"",
                "string_type": "STANDARD",
                "table_alignment": "LEFT",
                "usage_type": "STANDARD"
            },
            {
                "alignment_condition": "IF_OID_PRESENT",
                "class_type": "DISCOVERY",
                "name": "Discovery Object",
                "snippet_argument": "",
                "tabular": "DISABLED",
                "validity_check_operator": "IS_EQUAL_TO_RESULT",
                "validity_check_pattern": "true"
            }
        ],
        "component_mapping": "ENABLED",
        "component_mapping_dynamic_applications": [
            "96AA113228DCF8E1396C45DFE2EAB9C0",
            "136FECC9018400DA709E4A70777DA517"
        ],
        "cu_affinity": "ASSIGNED_COLLECTOR",
        "description": "This Dynamic Application retrieves data from 'api/account' and creates a component device for each account.",
        "execution_environment": "1BC13B3B88AAFB5399B94FEEE33EB48A",
        "name": "Test Discovery",
        "type": "SNIPPET_CONFIGURATION"
    },
    {
        "abandon_collection_limit": 0,
        "alert_objects": [
            {
                "formula": "(o_3351) > 1",
                "log_message": "Too many emails",
                "maintain_state": "DISABLED",
                "name": "Email",
                "reference": "a_818",
                "state": "DISABLED",
                "triggered_alert_id": 0
            },
            {
                "formula": "o_3350 > t_280",
                "log_message": "Too many tickets",
                "maintain_state": "DISABLED",
                "name": "Aligned Ticket",
                "reference": "a_819",
                "state": "DISABLED"
            }
        ],
        "collection_objects": [
            {
                "class_type": "PERFORMANCE_GAUGE",
                "description": "Random number based on aligned_ticket_queues size. The snippet argument uses substitution. For Example: \"$silo_comp_uid\" will be replaced by \"/api/account/2\"",
                "disable_maintenance": "FALSE",
                "enable_deviation_alerting": "FALSE",
                "formula": "",
                "group": 0,
                "max_weeks_data": 0,
                "min_weeks_data": 0,
                "name": "Based on Aligned Ticket Queues",
                "reference": "o_3350",
                "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"$silo_comp_uid\"\r\n    - json\r\n    - random_generator: \"aligned_ticket_queues\"",
                "snippet_reference": "snip_332",
                "usage_type": "STANDARD"
            },
            {
                "class_type": "PERFORMANCE_GAUGE",
                "description": "Random number based on email string length.The snippet argument uses substitution. For Example: \"$silo_comp_uid\" will be replaced by \"/api/account/2\"",
                "name": "Based on Email",
                "reference": "o_3351",
                "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"$silo_comp_uid\"\r\n    - json\r\n    - random_generator: \"email\"",
                "snippet_reference": "snip_332"
            }
        ],
        "cu_affinity": "ASSIGNED_COLLECTOR",
        "description": "This Dynamic Application simulates performance data for each account.\r\n\r\nNotes:\r\nIn this Dynamic Application, a custom Step is defined, which is registered to generate a random number based on the previous result and action argument for the Collection Objects. Any custom Step registered via snippet code must be used in a Collection Object.",
        "name": "Test Performance",
        "poll_interval": "EVERY_5_MINUTES",
        "presentation_objects": [
            {
                "abbreviation_suffix": "",
                "data_unit": "Rows",
                "formula": "(o_3350)",
                "guide_text": "This is a guide text",
                "name": "Based on Aligned Ticket Queues",
                "show_as_percent": "FALSE",
                "summarization_state": "TRUE"
            },
            {
                "data_unit": "Rows",
                "formula": "(o_3351)",
                "guide_text": "This is a guide text",
                "name": "Based on Email",
                "show_as_percent": "FALSE",
                "summarization_state": "TRUE"
            },
            {
                "data_unit": "Emails",
                "formula": "(o_3351) + 1",
                "name": "Test"
            }
        ],
        "reference": "96AA113228DCF8E1396C45DFE2EAB9C0",
        "snippets": [
            {
                "name": "Custom Step Performance",
                "snippet": "from silo.apps.errors import error_manager\r\nwith error_manager(self):\r\n\r\n    from silo.low_code import *\r\n    from silo.apps.collection import create_collections, save_collections\r\n\r\n    # =====================================\r\n    # =========== User Editable ===========\r\n    # =====================================\r\n    import random\r\n    \r\n    @register_processor\r\n    def random_generator(result, action_arg):\r\n        \"\"\"Generates random number between 0 and action_arg value size.\r\n\r\n        :param object result: Result from the parser\r\n        :param int action_arg: Action argument for the phase.\r\n\r\n        :return: Random number between 0 and action_arg value size\r\n        :rtype: Integer\r\n        \"\"\"\r\n        attribute_leng = len(result[action_arg])\r\n        generated_number = random.randint(0, attribute_leng)\r\n        return generated_number\r\n\r\n    \r\n    # List any custom substitutions that need to occur within the snippet arguments\r\n    custom_substitution = {}\r\n    # =====================================\r\n    # ========= End User Editable =========\r\n    # =====================================\r\n\r\n\r\n    collections = create_collections(self)\r\n    snippet_framework(collections, custom_substitution, snippet_id, app=self)\r\n    save_collections(collections, self)",
                "reference": "snip_332"
            }
        ],
        "threshold_objects": [
            {
                "name": "Test Threshold",
                "numeric_range_high": 100.0,
                "numeric_range_low": 0.0,
                "override_threshold_value": "TRUE",
                "reference": "t_280",
                "type": "INTEGER",
                "unit": "KB/s",
                "value": 90.0
            }
        ],
        "type": "SNIPPET_PERFORMANCE"
    },
    {
        "alert_objects": [
            {
                "name": "Unfriendly user",
                "formula": "(o_3355) != 'friend'",
                "log_message": "Bad friend!"
            },
            {
                "name": "Test Alert",
                "formula": "(thresh_1) > 1",
                "log_message": "Log Message",
                "reference": "alert_1",
                "maintain_state": "ENABLED"
            },
            {
                "name": "Test Alert 2",
                "formula": "(o_3355) + thresh_1 + (o_3357) + (o_3355)",
                "log_message": "Log Message",
                "triggered_alert_reference": "alert_1"
            }
        ],
        "collection_objects": [
            {
                "description": "First name of the account. The snippet argument uses substitution. For Example: \"$silo_comp_uid\" will be replaced by \"/api/account/2\".",
                "group": 1,
                "name": "Contact First Name",
                "reference": "o_3355",
                "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"$silo_comp_uid\"\r\n    - json\r\n    - simple_key: \"contact_fname\"\r\n    - test_step"
            },
            {
                "description": "Phone of the account. The snippet argument uses substitution. For Example: \"$silo_comp_uid\" will be replaced by \"/api/account/2\".",
                "group": 2,
                "name": "Phone",
                "reference": "o_3357",
                "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"$silo_comp_uid\"\r\n    - json\r\n    - simple_key: \"phone\""
            }
        ],
        "cu_affinity": "ROOT_DEVICE",
        "execution_environment": "1BC13B3B88AAFB5399B94FEEE33EB48A",
        "name": "Test Configuration",
        "reference": "136FECC9018400DA709E4A70777DA517",
        "threshold_objects": [
            {
                "name": "Test Threshold Object",
                "reference": "thresh_1"
            }
        ]
    }
]
```

##### Response

```json
{
    "entities": [
        {
            "abandon_collection_limit": 0,
            "alert_objects": [],
            "collection_objects": [
                {
                    "asset_link": "NONE",
                    "asset_link_precedence": 50,
                    "change_alerting": "DISABLED",
                    "class_type": "CONFIG_CHARACTER",
                    "component_identifiers": [],
                    "description": "Account description.",
                    "disable_maintenance": "FALSE",
                    "formula": "",
                    "group": 1,
                    "guid": "69DB9CC8D0B3A37049C4FE58F6686506",
                    "hide_object": "FALSE",
                    "id": 7655,
                    "name": "Account",
                    "reference": "o_7655",
                    "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"/account\"\r\n    - json\r\n    - jmespath:\r\n        index: true\r\n        value: \"result_set[*].{_index: URI, _value: description}\"",
                    "snippet_id": 1052,
                    "snippet_reference": "snip_1052",
                    "string_type": "STANDARD",
                    "table_alignment": "LEFT",
                    "usage_type": "STANDARD"
                },
                {
                    "asset_link": "NONE",
                    "asset_link_precedence": 50,
                    "change_alerting": "DISABLED",
                    "class_type": "CONFIG_CHARACTER",
                    "component_identifiers": [],
                    "description": "Account identifier.",
                    "disable_maintenance": "FALSE",
                    "formula": "",
                    "group": 1,
                    "guid": "1019E37C46BD824DBFBEB5190196EB6C",
                    "hide_object": "FALSE",
                    "id": 7656,
                    "name": "Id",
                    "reference": "o_7656",
                    "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"/account\"\r\n    - json\r\n    - jmespath:\r\n        index: true\r\n        value: \"result_set[*].{_index: URI, _value: URI}\"",
                    "snippet_id": 1052,
                    "snippet_reference": "snip_1052",
                    "string_type": "STANDARD",
                    "table_alignment": "LEFT",
                    "usage_type": "STANDARD"
                },
                {
                    "alignment_condition": "IF_OID_PRESENT",
                    "class_type": "DISCOVERY",
                    "guid": "FD1322A4D70368825827E8E8ACAA052F",
                    "id": 7657,
                    "name": "Discovery Object",
                    "reference": "o_7657",
                    "snippet_argument": "",
                    "snippet_id": 1052,
                    "snippet_reference": "snip_1052",
                    "tabular": "DISABLED",
                    "validity_check_operator": "IS_EQUAL_TO_RESULT",
                    "validity_check_pattern": "true"
                }
            ],
            "component_mapping": "ENABLED",
            "component_mapping_dynamic_applications": [
                "509E51E32D5FDB0A0D22D7189DBDF785",
                "94F84D801469684BAD62D3E442AD44FE"
            ],
            "cu_affinity": "ASSIGNED_COLLECTOR",
            "description": "This Dynamic Application retrieves data from 'api/account' and creates a component device for each account.",
            "disable_rollup_of_data": "FALSE",
            "execution_environment": "1BC13B3B88AAFB5399B94FEEE33EB48A",
            "guid": "C52446505F390B2CB8043026B24678F5",
            "id": 1141,
            "is_sf_app_type": "FALSE",
            "max_devices": 50,
            "name": "Test Discovery",
            "null_column_option": "DASH_VALUES",
            "null_row_option": "DASH_VALUES",
            "poll_interval": "EVERY_15_MINUTES",
            "pp_guid": null,
            "reference": "C52446505F390B2CB8043026B24678F5",
            "release_notes": "",
            "snippets": [
                {
                    "guid": "FC723E65393A270CE8B037C900699BA2",
                    "id": 1052,
                    "name": "Default Snippet",
                    "reference": "snip_1052",
                    "required": "REQUIRED",
                    "snippet": "from sl.snippet_api.snippet import error_manager\n\nwith error_manager(self):\n    from silo.low_code import *\n    from sl.snippet_api.collection import create_collections, save_collections\n\n    # =====================================\n    # =========== User Editable ===========\n    # =====================================\n    # List any custom substitutions that need to occur within the snippet arguments\n    custom_substitution = {}\n    # =====================================\n    # ========= End User Editable =========\n    # =====================================\n\n    collections = create_collections(self)\n    snippet_framework(collections, custom_substitution, snippet_id, app=self)\n    save_collections(collections, self)",
                    "state": "ENABLED"
                }
            ],
            "state": "ENABLED",
            "threshold_objects": [],
            "type": "SNIPPET_CONFIGURATION",
            "version": 1.0
        },
        {
            "abandon_collection_limit": 0,
            "alert_objects": [
                {
                    "formula": "(o_7659) > 1",
                    "guid": "CB8A29A1F5FDFDAC1EC3A2835B3B0C6D",
                    "id": 873,
                    "log_message": "Too many emails",
                    "maintain_state": "DISABLED",
                    "name": "Email",
                    "reference": "a_873",
                    "state": "DISABLED",
                    "triggered_alert_id": 0
                },
                {
                    "formula": "o_7658 > t_419",
                    "guid": "2F5F57F56200FB9B8FCA008E5B93E418",
                    "id": 874,
                    "log_message": "Too many tickets",
                    "maintain_state": "DISABLED",
                    "name": "Aligned Ticket",
                    "reference": "a_874",
                    "state": "DISABLED",
                    "triggered_alert_id": 0
                }
            ],
            "collection_objects": [
                {
                    "class_type": "PERFORMANCE_GAUGE",
                    "description": "Random number based on aligned_ticket_queues size. The snippet argument uses substitution. For Example: \"$silo_comp_uid\" will be replaced by \"/api/account/2\"",
                    "disable_maintenance": "FALSE",
                    "enable_deviation_alerting": "FALSE",
                    "formula": "",
                    "group": 0,
                    "guid": "42A59B8901E36C2437A26A83111778A4",
                    "id": 7658,
                    "max_weeks_data": 0,
                    "min_weeks_data": 0,
                    "name": "Based on Aligned Ticket Queues",
                    "reference": "o_7658",
                    "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"$silo_comp_uid\"\r\n    - json\r\n    - random_generator: \"aligned_ticket_queues\"",
                    "snippet_id": 1053,
                    "snippet_reference": "snip_1053",
                    "usage_type": "STANDARD"
                },
                {
                    "class_type": "PERFORMANCE_GAUGE",
                    "description": "Random number based on email string length.The snippet argument uses substitution. For Example: \"$silo_comp_uid\" will be replaced by \"/api/account/2\"",
                    "disable_maintenance": "FALSE",
                    "enable_deviation_alerting": "FALSE",
                    "formula": "",
                    "group": 0,
                    "guid": "66BB73F55783A85F36178711508D15B5",
                    "id": 7659,
                    "max_weeks_data": 0,
                    "min_weeks_data": 0,
                    "name": "Based on Email",
                    "reference": "o_7659",
                    "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"$silo_comp_uid\"\r\n    - json\r\n    - random_generator: \"email\"",
                    "snippet_id": 1053,
                    "snippet_reference": "snip_1053",
                    "usage_type": "STANDARD"
                }
            ],
            "component_mapping": "DISABLED",
            "cu_affinity": "ASSIGNED_COLLECTOR",
            "description": "This Dynamic Application simulates performance data for each account.\r\n\r\nNotes:\r\nIn this Dynamic Application, a custom Step is defined, which is registered to generate a random number based on the previous result and action argument for the Collection Objects. Any custom Step registered via snippet code must be used in a Collection Object.",
            "disable_rollup_of_data": "FALSE",
            "execution_environment": "sl1_default_ee",
            "guid": "509E51E32D5FDB0A0D22D7189DBDF785",
            "id": 1142,
            "is_sf_app_type": "FALSE",
            "max_devices": 50,
            "name": "Test Performance",
            "null_column_option": "DASH_VALUES",
            "null_row_option": "DASH_VALUES",
            "poll_interval": "EVERY_5_MINUTES",
            "pp_guid": null,
            "presentation_objects": [
                {
                    "abbreviation_suffix": "",
                    "data_unit": "Rows",
                    "formula": "(o_7658)",
                    "guid": "DC2CB87AE8DD3A372A52CA996BAA08D4",
                    "guide_text": "This is a guide text",
                    "id": 2391,
                    "name": "Based on Aligned Ticket Queues",
                    "reference": "pres_2391",
                    "show_as_percent": "FALSE",
                    "summarization_state": "TRUE"
                },
                {
                    "abbreviation_suffix": "",
                    "data_unit": "Rows",
                    "formula": "(o_7659)",
                    "guid": "02A88A423014EB78FA47FB000474817D",
                    "guide_text": "This is a guide text",
                    "id": 2392,
                    "name": "Based on Email",
                    "reference": "pres_2392",
                    "show_as_percent": "FALSE",
                    "summarization_state": "TRUE"
                },
                {
                    "abbreviation_suffix": "",
                    "data_unit": "Emails",
                    "formula": "(o_7659) + 1",
                    "guid": "F1F95DCF01D5CE3E1FAA3EAED091C495",
                    "guide_text": "",
                    "id": 2393,
                    "name": "Test",
                    "reference": "pres_2393",
                    "show_as_percent": "FALSE",
                    "summarization_state": "FALSE"
                }
            ],
            "reference": "509E51E32D5FDB0A0D22D7189DBDF785",
            "release_notes": "",
            "snippets": [
                {
                    "guid": "52867B11B4F66C3D01790CDCBD5FA1AE",
                    "id": 1053,
                    "name": "Custom Step Performance",
                    "reference": "snip_1053",
                    "required": "REQUIRED",
                    "snippet": "from silo.apps.errors import error_manager\r\nwith error_manager(self):\r\n\r\n    from silo.low_code import *\r\n    from silo.apps.collection import create_collections, save_collections\r\n\r\n    # =====================================\r\n    # =========== User Editable ===========\r\n    # =====================================\r\n    import random\r\n    \r\n    @register_processor\r\n    def random_generator(result, action_arg):\r\n        \"\"\"Generates random number between 0 and action_arg value size.\r\n\r\n        :param object result: Result from the parser\r\n        :param int action_arg: Action argument for the phase.\r\n\r\n        :return: Random number between 0 and action_arg value size\r\n        :rtype: Integer\r\n        \"\"\"\r\n        attribute_leng = len(result[action_arg])\r\n        generated_number = random.randint(0, attribute_leng)\r\n        return generated_number\r\n\r\n    \r\n    # List any custom substitutions that need to occur within the snippet arguments\r\n    custom_substitution = {}\r\n    # =====================================\r\n    # ========= End User Editable =========\r\n    # =====================================\r\n\r\n\r\n    collections = create_collections(self)\r\n    snippet_framework(collections, custom_substitution, snippet_id, app=self)\r\n    save_collections(collections, self)",
                    "state": "ENABLED"
                }
            ],
            "state": "ENABLED",
            "threshold_objects": [
                {
                    "guid": "675133EF4861D21213940AF561159581",
                    "id": 419,
                    "name": "Test Threshold",
                    "numeric_range_high": 100.0,
                    "numeric_range_low": 0.0,
                    "override_threshold_value": "TRUE",
                    "reference": "t_419",
                    "type": "INTEGER",
                    "unit": "KB/s",
                    "value": 90.0
                }
            ],
            "type": "SNIPPET_PERFORMANCE",
            "version": 1.0
        },
        {
            "abandon_collection_limit": 0,
            "alert_objects": [
                {
                    "formula": "(o_7660) != 'friend'",
                    "guid": "D57409263068EAB28D872C1EB233E489",
                    "id": 875,
                    "log_message": "Bad friend!",
                    "maintain_state": "DISABLED",
                    "name": "Unfriendly user",
                    "reference": "a_875",
                    "state": "DISABLED",
                    "triggered_alert_id": 0
                },
                {
                    "formula": "(t_420) > 1",
                    "guid": "13348515A86A96AD88EB2DE37A9BE268",
                    "id": 876,
                    "log_message": "Log Message",
                    "maintain_state": "ENABLED",
                    "name": "Test Alert",
                    "reference": "a_876",
                    "state": "DISABLED",
                    "triggered_alert_id": 0
                },
                {
                    "formula": "(o_7660) + t_420 + (o_7661) + (o_7660)",
                    "guid": "B6ED84DEE401EECCF653A22487EBCC1B",
                    "id": 877,
                    "log_message": "Log Message",
                    "maintain_state": "DISABLED",
                    "name": "Test Alert 2",
                    "reference": "a_877",
                    "state": "DISABLED",
                    "triggered_alert_id": 876,
                    "triggered_alert_reference": "a_876"
                }
            ],
            "collection_objects": [
                {
                    "asset_link": "NONE",
                    "asset_link_precedence": 50,
                    "change_alerting": "DISABLED",
                    "class_type": "CONFIG_CHARACTER",
                    "description": "First name of the account. The snippet argument uses substitution. For Example: \"$silo_comp_uid\" will be replaced by \"/api/account/2\".",
                    "disable_maintenance": "FALSE",
                    "formula": "",
                    "group": 1,
                    "guid": "8571145096F8126A408A90893AE7CEA1",
                    "hide_object": "FALSE",
                    "id": 7660,
                    "name": "Contact First Name",
                    "reference": "o_7660",
                    "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"$silo_comp_uid\"\r\n    - json\r\n    - simple_key: \"contact_fname\"\r\n    - test_step",
                    "snippet_id": 1054,
                    "snippet_reference": "snip_1054",
                    "string_type": "STANDARD",
                    "table_alignment": "LEFT",
                    "usage_type": "STANDARD"
                },
                {
                    "asset_link": "NONE",
                    "asset_link_precedence": 50,
                    "change_alerting": "DISABLED",
                    "class_type": "CONFIG_CHARACTER",
                    "description": "Phone of the account. The snippet argument uses substitution. For Example: \"$silo_comp_uid\" will be replaced by \"/api/account/2\".",
                    "disable_maintenance": "FALSE",
                    "formula": "",
                    "group": 2,
                    "guid": "033A9861E7034E4C63D673AF73B9FB1D",
                    "hide_object": "FALSE",
                    "id": 7661,
                    "name": "Phone",
                    "reference": "o_7661",
                    "snippet_argument": "low_code:\r\n  version: 2\r\n  steps:\r\n    - http:\r\n        uri: \"$silo_comp_uid\"\r\n    - json\r\n    - simple_key: \"phone\"",
                    "snippet_id": 1054,
                    "snippet_reference": "snip_1054",
                    "string_type": "STANDARD",
                    "table_alignment": "LEFT",
                    "usage_type": "STANDARD"
                }
            ],
            "component_mapping": "DISABLED",
            "cu_affinity": "ROOT_DEVICE",
            "description": "",
            "disable_rollup_of_data": "FALSE",
            "execution_environment": "1BC13B3B88AAFB5399B94FEEE33EB48A",
            "guid": "94F84D801469684BAD62D3E442AD44FE",
            "id": 1143,
            "is_sf_app_type": "FALSE",
            "max_devices": 50,
            "name": "Test Configuration",
            "null_column_option": "DASH_VALUES",
            "null_row_option": "DASH_VALUES",
            "poll_interval": "EVERY_15_MINUTES",
            "pp_guid": null,
            "reference": "94F84D801469684BAD62D3E442AD44FE",
            "release_notes": "",
            "snippets": [
                {
                    "guid": "F8E4E8C7786AEB35500BCACAFB6F2318",
                    "id": 1054,
                    "name": "Default Snippet",
                    "reference": "snip_1054",
                    "required": "REQUIRED",
                    "snippet": "from sl.snippet_api.snippet import error_manager\n\nwith error_manager(self):\n    from silo.low_code import *\n    from sl.snippet_api.collection import create_collections, save_collections\n\n    # =====================================\n    # =========== User Editable ===========\n    # =====================================\n    # List any custom substitutions that need to occur within the snippet arguments\n    custom_substitution = {}\n    # =====================================\n    # ========= End User Editable =========\n    # =====================================\n\n    collections = create_collections(self)\n    snippet_framework(collections, custom_substitution, snippet_id, app=self)\n    save_collections(collections, self)",
                    "state": "ENABLED"
                }
            ],
            "state": "ENABLED",
            "threshold_objects": [
                {
                    "guid": "ADD8C158E4D9CE85BC2F804168C26C28",
                    "id": 420,
                    "name": "Test Threshold Object",
                    "numeric_range_high": 100.0,
                    "numeric_range_low": 0.0,
                    "override_threshold_value": "TRUE",
                    "reference": "t_420",
                    "type": "PERCENTAGE",
                    "unit": null,
                    "value": 90.0
                }
            ],
            "type": "SNIPPET_CONFIGURATION",
            "version": 1.0
        }
    ],
    "results": [
        {
            "alert_objects": [],
            "collection_objects": [
                {
                    "guid": "1019E37C46BD824DBFBEB5190196EB6C",
                    "id": 7656,
                    "name": "Id",
                    "new": true
                },
                {
                    "guid": "69DB9CC8D0B3A37049C4FE58F6686506",
                    "id": 7655,
                    "name": "Account",
                    "new": true
                },
                {
                    "guid": "FD1322A4D70368825827E8E8ACAA052F",
                    "id": 7657,
                    "name": "Discovery Object",
                    "new": true
                }
            ],
            "dynamic_app": {
                "guid": "C52446505F390B2CB8043026B24678F5",
                "id": 1141,
                "name": "Test Discovery",
                "new": true
            },
            "presentation_objects": [],
            "snippets": [
                {
                    "guid": "FC723E65393A270CE8B037C900699BA2",
                    "id": 1052,
                    "name": "Default Snippet",
                    "new": true
                }
            ],
            "threshold_objects": []
        },
        {
            "alert_objects": [
                {
                    "guid": "2F5F57F56200FB9B8FCA008E5B93E418",
                    "id": 874,
                    "name": "Aligned Ticket",
                    "new": true,
                    "reference": "a_819"
                },
                {
                    "guid": "CB8A29A1F5FDFDAC1EC3A2835B3B0C6D",
                    "id": 873,
                    "name": "Email",
                    "new": true,
                    "reference": "a_818"
                }
            ],
            "collection_objects": [
                {
                    "guid": "42A59B8901E36C2437A26A83111778A4",
                    "id": 7658,
                    "name": "Based on Aligned Ticket Queues",
                    "new": true,
                    "reference": "o_3350"
                },
                {
                    "guid": "66BB73F55783A85F36178711508D15B5",
                    "id": 7659,
                    "name": "Based on Email",
                    "new": true,
                    "reference": "o_3351"
                }
            ],
            "dynamic_app": {
                "guid": "509E51E32D5FDB0A0D22D7189DBDF785",
                "id": 1142,
                "name": "Test Performance",
                "new": true,
                "reference": "96AA113228DCF8E1396C45DFE2EAB9C0"
            },
            "presentation_objects": [
                {
                    "guid": "02A88A423014EB78FA47FB000474817D",
                    "id": 2392,
                    "name": "Based on Email",
                    "new": true
                },
                {
                    "guid": "DC2CB87AE8DD3A372A52CA996BAA08D4",
                    "id": 2391,
                    "name": "Based on Aligned Ticket Queues",
                    "new": true
                },
                {
                    "guid": "F1F95DCF01D5CE3E1FAA3EAED091C495",
                    "id": 2393,
                    "name": "Test",
                    "new": true
                }
            ],
            "snippets": [
                {
                    "guid": "52867B11B4F66C3D01790CDCBD5FA1AE",
                    "id": 1053,
                    "name": "Custom Step Performance",
                    "new": true,
                    "reference": "snip_332"
                }
            ],
            "threshold_objects": [
                {
                    "guid": "675133EF4861D21213940AF561159581",
                    "id": 419,
                    "name": "Test Threshold",
                    "new": true,
                    "reference": "t_280"
                }
            ]
        },
        {
            "alert_objects": [
                {
                    "guid": "13348515A86A96AD88EB2DE37A9BE268",
                    "id": 876,
                    "name": "Test Alert",
                    "new": true,
                    "reference": "alert_1"
                },
                {
                    "guid": "B6ED84DEE401EECCF653A22487EBCC1B",
                    "id": 877,
                    "name": "Test Alert 2",
                    "new": true
                },
                {
                    "guid": "D57409263068EAB28D872C1EB233E489",
                    "id": 875,
                    "name": "Unfriendly user",
                    "new": true
                }
            ],
            "collection_objects": [
                {
                    "guid": "033A9861E7034E4C63D673AF73B9FB1D",
                    "id": 7661,
                    "name": "Phone",
                    "new": true,
                    "reference": "o_3357"
                },
                {
                    "guid": "8571145096F8126A408A90893AE7CEA1",
                    "id": 7660,
                    "name": "Contact First Name",
                    "new": true,
                    "reference": "o_3355"
                }
            ],
            "dynamic_app": {
                "guid": "94F84D801469684BAD62D3E442AD44FE",
                "id": 1143,
                "name": "Test Configuration",
                "new": true,
                "reference": "136FECC9018400DA709E4A70777DA517"
            },
            "presentation_objects": [],
            "snippets": [
                {
                    "guid": "F8E4E8C7786AEB35500BCACAFB6F2318",
                    "id": 1054,
                    "name": "Default Snippet",
                    "new": true
                }
            ],
            "threshold_objects": [
                {
                    "guid": "ADD8C158E4D9CE85BC2F804168C26C28",
                    "id": 420,
                    "name": "Test Threshold Object",
                    "new": true,
                    "reference": "thresh_1"
                }
            ]
        }
    ],
    "success": true
}
```

---

## 12) Special behaviors

### 12.1 Default snippet auto-creation

If updating or creating collection objects in a Dynamic Application that has **no snippets**, the service creates the Snippet Framework **Default Snippet** and assigns it to any collection object without a valid snippet reference.

### 12.2 Snippet alignment for collection objects

- If `snippet_id` is default/unset -> assigned to a fallback snippet (first active snippet)
- If `snippet_id` references a snippet not owned by the application -> validation error

### 12.3 Presentation auto-generation (performance apps only)

If `presentation_objects` is **empty** (or omitted) and the app is performance:

- Create presentation objects for newly created collection objects with `class_type <= PERFORMANCE_GAUGE`
- Auto formula is: `(o_<collection_object_id>)`

If **any** presentation objects are provided in the request:

- **No auto-generation** occurs

### 12.4 Derived collection object fields

Discovery collection objects enforce:

- `name = "Discovery Object"`
- `group = 0`

### 12.5 Group identity/relationship namespaces

When `usage_type` is:

- `IDENTITY_NAMESPACE` or `RELATIONSHIP_NAMESPACE`

Then:

- `group` must be set
- a group index object must exist (first one in that group with indexing enabled)
- duplicates are rejected

If invalid:

- the service resets `usage_type` to `STANDARD` to keep data consistent and raises an error.

### 12.6 Component mapping guardrails

If the parent DA has `component_mapping` = EnabledToggle.DISABLED:

- setting `component_identifiers` on collection objects is a validation error

When EnabledToggle.ENABLED:

- identifiers are diffed and synchronized (remove missing, add new)

---

## 13) Validation & error responses

### Common status codes

- **400** Bad Request: invalid JSON, invalid identifiers, illegal field combinations
- **401** Unauthorized: missing/invalid auth
- **403** Forbidden: access hooks insufficient
- **404** Not Found: referenced app/entity does not exist
- **422** Unprocessable Entity: schema validation failures
- **500** Internal Server Error: DB failures, unexpected errors

---

# 14) OpenAPI 3.0 Specification

```yaml
openapi: 3.0.3
info:
    title: Skylar One Dynamic Application API
    version: "1.0"
    description: >
        API for retrieving PowerPack/Dynamic Application definitions and creating/updating
        Dynamic Applications and their Snippet Framework entities.

servers:
    - url: /lce/api

paths:
    /powerpacks/{powerpack_identifier}:
        get:
            summary: Get PowerPack code
            operationId: get_powerpack_code
            parameters:
                - name: powerpack_identifier
                  in: path
                  required: true
                  description: |
                    PowerPack identifier. May be one of:
                    - PowerPack ID (integer)
                    - PowerPack GUID (32-character uppercase hex string)
                    - PowerPack name (string)
                  schema:
                    oneOf:
                    - type: integer
                        format: int64
                        description: PowerPack ID
                    - $ref: "#/components/schemas/GUID"
                    - type: string
                        minLength: 1
                        maxLength: 64
                        description: PowerPack name
                  examples:
                    pp_id:
                    summary: PowerPack ID
                    value: 12345
                    pp_guid:
                    summary: PowerPack GUID
                    value: "A1B2C3D4E5F6789012345678901234AB"
                    pp_name:
                    summary: PowerPack name
                    value: "my-powerpack"
                - name: pretty
                  in: query
                  required: false
                  schema:
                    type: boolean
                    default: true
                  description: |
                    When true, enums are returned as strings (e.g. "ENABLED").
                    When false, enums are returned as integers.
            responses:
                "200":
                    description: PowerPack definition
                    content:
                        application/json:
                            schema:
                                $ref: "#/components/schemas/PowerPackResponse"
                "404":
                    description: PowerPack not found

    /dynamic_applications/{app_identifier}:
        get:
            summary: Get Dynamic Application code
            operationId: get_dynamic_application_code
            parameters:
                - name: app_identifier
                  in: path
                  required: true
                  description: |
                    Dynamic Application identifier. May be one of:
                    - Dynamic Application ID (integer)
                    - Dynamic Application GUID (32-character uppercase hex string)
                    - Dynamic Application name (string)
                  schema:
                    oneOf:
                    - type: integer
                        format: int64
                        description: Dynamic Application ID
                    - $ref: "#/components/schemas/GUID"
                    - type: string
                        minLength: 1
                        maxLength: 64
                        description: Dynamic Application name
                  examples:
                    pp_id:
                    summary: Dynamic Application ID
                    value: 12345
                    pp_guid:
                    summary: Dynamic Application GUID
                    value: "A1B2C3D4E5F6789012345678901234AB"
                    pp_name:
                    summary: Dynamic Application name
                    value: "my-dynamic-application"
                - name: pretty
                  in: query
                  required: false
                  schema:
                      type: boolean
                      default: true
                  description: |
                      When true, enums are returned as strings (e.g. "ENABLED").
                      When false, enums are returned as integers.
            responses:
                "200":
                    description: Dynamic Application definition
                    content:
                        application/json:
                            schema:
                                $ref: "#/components/schemas/DynamicApplicationGetResponse"
                "404":
                    description: Dynamic Application not found

    /dynamic_applications:
        post:
            summary: Create or update a Dynamic Application
            operationId: update_dynamic_application
            parameters:
                - name: retrieve
                  in: query
                  required: false
                  schema:
                      type: boolean
                      default: false
                  description: |
                      When true, the response includes a fully-expanded `entities` list containing
                      the normalized stored objects.

                      When false, only `results` is returned.
                - name: pretty
                  in: query
                  required: false
                  schema:
                      type: boolean
                      default: true
                  description: |
                      Controls enum serialization format in responses.
                      When true, enums are returned as strings; when false, as integers.
            requestBody:
                required: true
                content:
                    application/json:
                        schema:
                            $ref: "#/components/schemas/DynamicApplicationUpdateRequest"
            responses:
                "200":
                    description: Update results
                    content:
                        application/json:
                            schema:
                                $ref: "#/components/schemas/DynamicApplicationUpdateResponse"
                "400":
                    description: Invalid request or validation error
                "401":
                    description: Unauthorized
                "403":
                    description: Forbidden (insufficient access hooks)
                "404":
                    description: Not found
                "422":
                    description: Unprocessable entity (schema validation)
                "500":
                    description: Internal server error

components:
    schemas:
        GUID:
            type: string
            pattern: "^[A-F0-9]{32}$"
            description: Uppercase 32-character hexadecimal GUID.
            example: "A1B2C3D4E5F6789012345678901234AB"

        Reference:
            type: string
            minLength: 1
            description: Request-scoped unique label for linking new entities.

        FlexibleEnumEnabledToggle:
            description: EnabledToggle (accepts integer or string).
            oneOf:
                - type: integer
                  enum: [0, 1]
                - type: string
                  enum: ["DISABLED", "ENABLED"]

        FlexibleEnumRequiredToggle:
            oneOf:
                - type: integer
                  enum: [0, 1]
                - type: string
                  enum: ["NOT_REQUIRED", "REQUIRED"]

        FlexibleEnumBooleanToggle:
            oneOf:
                - type: integer
                  enum: [0, 1]
                - type: string
                  enum: ["FALSE", "TRUE"]

        FlexibleEnumCUAffinity:
            oneOf:
                - type: integer
                  enum: [0, 1, 2]
                - type: string
                  enum: ["DEFAULT", "ROOT_DEVICE", "ASSIGNED_COLLECTOR"]

        FlexibleEnumExecutionEnvironmentType:
            oneOf:
                - type: integer
                  enum: [1, 3, 5]
                - type: string
                  enum: ["PYTHON2", "PYTHON3_LTS", "PYTHON3_LATEST"]

        FlexibleEnumPollInterval:
            oneOf:
                - type: integer
                  enum: [0, 1, 2, 3, 5, 10, 15, 30, 60, 120, 360, 720, 1440]
                - type: string
                  enum:
                      - UNSET
                      - EVERY_1_MINUTE
                      - EVERY_2_MINUTES
                      - EVERY_3_MINUTES
                      - EVERY_5_MINUTES
                      - EVERY_10_MINUTES
                      - EVERY_15_MINUTES
                      - EVERY_30_MINUTES
                      - EVERY_1_HOUR
                      - EVERY_2_HOURS
                      - EVERY_6_HOURS
                      - EVERY_12_HOURS
                      - EVERY_24_HOURS

        FlexibleEnumMissingTableDataOption:
            oneOf:
                - type: integer
                  enum: [0, 1, 2, 3]
                - type: string
                  enum: ["DASH_VALUES", "LAST_COLLECTED", "LAST_COLLECTED_WITH_INDICATOR", "HIDE"]

        FlexibleEnumCollectionObjectUsage:
            oneOf:
                - type: integer
                  enum: [0, 1, 2, 3, 4, 5, 6, 7]
                - type: string
                  enum:
                      - STANDARD
                      - GROUP_INDEX
                      - IDENTITY_NAMESPACE
                      - RELATIONSHIP_NAMESPACE
                      - GUID_RELATIONSHIP
                      - UNIQUE_IDENTIFIER_RELATIONSHIP
                      - GUID_PLUS_INDEX
                      - UNIQUE_IDENTIFIER_PLUS_INDEX

        FlexibleEnumComponentIdentifier:
            oneOf:
                - type: integer
                  enum: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
                - type: string
                  enum:
                      - UNKNOWN
                      - UNIQUE_IDENTIFIER
                      - DISTINGUISHED_NAME
                      - CLASS_IDENTIFIER_1
                      - CLASS_IDENTIFIER_2
                      - DEVICE_NAME
                      - MAC_ADDRESS
                      - UUID
                      - AVAILABILITY
                      - GUID
                      - ORGANIZATION
                      - PREVIOUS_UNIQUE_IDS
                      - IP_ADDRESS

        FlexibleEnumThresholdType:
            oneOf:
                - type: integer
                  enum: [0, 1, 2]
                - type: string
                  enum: ["PERCENTAGE", "INTEGER", "DECIMAL"]

        FlexibleEnumDiscoveryAlignmentCondition:
            oneOf:
                - type: integer
                  enum: [0, 1]
                - type: string
                  enum: ["IF_OID_PRESENT", "IF_OID_NOT_PRESENT"]

        FlexibleEnumDiscoveryOperator:
            oneOf:
                - type: integer
                  enum: [0, 1, 2, 3, 4, 5, 6, 9]
                - type: string
                  enum:
                      - UNSET
                      - IS_GREATER_THAN_RESULT
                      - IS_EQUAL_TO_RESULT
                      - IS_LESS_THAN_RESULT
                      - IS_NOT_EQUAL_TO_RESULT
                      - IS_LIKE
                      - MATCHES_REGEX
                      - NO_VALIDITY_CHECK

        FlexibleEnumTableAlignment:
            oneOf:
                - type: integer
                  enum: [0, 1, 2]
                - type: string
                  enum: ["LEFT", "CENTER", "RIGHT"]

        FlexibleEnumConfigStringType:
            oneOf:
                - type: integer
                  enum: [0, 1]
                - type: string
                  enum: ["STANDARD", "HEX_UNICODE"]

        FlexibleEnumAssetLink:
            description: |
                AssetLink values.

                IMPORTANT (config apps):
                When the Dynamic Application is configuration-type (SNIPPET_CONFIGURATION or BULK_SNIPPET_CONFIGURATION),
                only the following values are permitted:

                - NONE
                - MAKE
                - MODEL
                - SERIAL_NUMBER
                - OPERATING_SYSTEM
                - HOST_ID_SID
                - OS_SYSTEM_NAME
                - CPU_COUNT
                - CPU_TYPE_MAKE
                - CPU_SPEED
                - FIRMWARE_BIOS_NAME
                - INSTALLED_MEMORY
                - ASSET_TAG
                - DISK_ARRAY_SIZE
                - DISK_COUNT
                - DISK_SIZE
                - MODEL_NUMBER

                Any other AssetLink value will be rejected for configuration applications.
            oneOf:
                - type: integer
                  enum:
                      [
                          0,
                          1,
                          2,
                          3,
                          4,
                          5,
                          6,
                          7,
                          8,
                          9,
                          10,
                          11,
                          12,
                          13,
                          14,
                          15,
                          16,
                          17,
                          18,
                          19,
                          20,
                          21,
                          22,
                          23,
                          24,
                          25,
                          26,
                          27,
                          128,
                      ]
                - type: string
                  enum:
                      - NONE
                      - MAKE
                      - MODEL
                      - SERIAL_NUMBER
                      - OPERATING_SYSTEM
                      - HOST_ID_SID
                      - OS_SYSTEM_NAME
                      - CPU_COUNT
                      - CPU_TYPE_MAKE
                      - CPU_SPEED
                      - FIRMWARE_BIOS_NAME
                      - INSTALLED_MEMORY
                      - HARD_DISK_DRIVE
                      - COMPONENT_TYPE
                      - COMPONENT_MAKE
                      - COMPONENT_MODEL
                      - COMPONENT_SERIAL
                      - COMPONENT_SLOT
                      - COMPONENT_NOTES
                      - COMPONENT_CONNECT
                      - PROFILE_MEMO
                      - ASSET_TAG
                      - DISK_ARRAY_SIZE
                      - DISK_COUNT
                      - DISK_SIZE
                      - METHOD
                      - ANNUAL_RATE
                      - RFID_NUMBER
                      - MODEL_NUMBER

        FlexibleEnumApplicationType:
            description: ApplicationType values (accepts integer or string). Only Snippet Framework types are permitted by validation.
            oneOf:
                - type: integer
                - type: string
                  enum:
                      - SNIPPET_PERFORMANCE
                      - SNIPPET_CONFIGURATION
                      - BULK_SNIPPET_PERFORMANCE
                      - BULK_SNIPPET_CONFIGURATION
                      - SNIPPET_JOURNAL
                      - SNMP_PERFORMANCE
                      - SNMP_CONFIGURATION
                      - TRAP
                      - XML_PERFORMANCE
                      - XML_CONFIGURATION
                      - DATABASE_PERFORMANCE
                      - DATABASE_CONFIGURATION
                      - SOAP_PERFORMANCE
                      - SOAP_CONFIGURATION
                      - CPU
                      - MEMORY
                      - XSLT_PERFORMANCE
                      - XSLT_CONFIG
                      - WMI_PERFORMANCE
                      - WMI_CONFIG
                      - IT_SERVICE
                      - POWERSHELL_PERFORMANCE
                      - POWERSHELL_CONFIG
                      - INTERNAL_COLLECTION_INVENTORY
                      - INTERNAL_COLLECTION_PERFORMANCE

        FlexibleEnumCollectionObjectClass:
            description: CollectionObjectClass (accepts integer or string).
            oneOf:
                - type: integer
                  enum:
                      [
                          0,
                          1,
                          2,
                          3,
                          4,
                          10,
                          11,
                          12,
                          14,
                          15,
                          16,
                          17,
                          18,
                          19,
                          20,
                          21,
                          22,
                          23,
                          24,
                          25,
                          26,
                          27,
                          28,
                          29,
                          30,
                          31,
                          32,
                          33,
                          100,
                          101,
                          104,
                          105,
                          106,
                          107,
                          108,
                          109,
                          110,
                          111,
                      ]
                - type: string
                  enum:
                      - UNKNOWN

                      # --- Performance ---
                      - PERFORMANCE_COUNTER
                      - PERFORMANCE_PERCENT
                      - PERFORMANCE_KILOBYTE
                      - PERFORMANCE_GAUGE

                      # --- Config ---
                      - CONFIG_CHARACTER
                      - CONFIG_ENUM
                      - CONFIG_TIMETICKS
                      - CONFIG_GAUGE
                      - CONFIG_NUMERIC
                      - CONFIG_TIMESTAMP
                      - CONFIG_MAC_ADDRESS
                      - CONFIG_IP_ADDRESS
                      - CONFIG_DATETIME
                      - XXX
                      - UNICODE

                      # --- Journal ---
                      - JOURNAL_CHARACTER
                      - JOURNAL_ENUM
                      - JOURNAL_EPOC
                      - JOURNAL_GAUGE
                      - JOURNAL_NUMERIC
                      - JOURNAL_TIMESTAMP
                      - JOURNAL_MAC_ADDRESS
                      - JOURNAL_IP_ADDRESS
                      - JOURNAL_DATETIME_CLASS
                      - JOURNAL_JSON_OBJECT
                      - JOURNAL_JSON_ARRAY

                      # --- ICDA / Special ---
                      - ICDA
                      - DISCOVERY
                      - LABEL_HOURLY_POLLED
                      - LABEL_ALWAYS_POLLED
                      - INDEX
                      - DESCRIPTOR_IF
                      - INDEX_LABEL
                      - LABEL_CONFIG_GROUP
                      - SOAP_SESSION
                      - LABEL_IP_HOURLY_POLLED
                      - LABEL_IP_ALWAYS_POLLED

        # --- Request/Response wrappers ---

        DynamicApplicationUpdateRequest:
            oneOf:
                - $ref: "#/components/schemas/DynamicApplicationUpdateRequestItem"
                - type: array
                  items:
                      $ref: "#/components/schemas/DynamicApplicationUpdateRequestItem"

        DynamicApplicationUpdateRequestItem:
            allOf:
                - $ref: "#/components/schemas/DynamicApp"
                - type: object
                  properties:
                      snippets:
                          type: array
                          default: []
                          description: |
                              Optional list of Snippet Framework snippets for the Dynamic Application.

                              Special behavior (default snippet auto-creation):
                              - If the Dynamic Application has no existing snippets AND you create/update Collection Objects
                                in the same request, the service will automatically create a Default Snippet Framework snippet
                                if you do not provide any snippets here (snippets omitted or snippets: []).
                              - Created/updated Collection Objects that do not specify snippet_id/snippet_reference will automatically be linked to the first available Snippet in the Dynamic Application.

                              Notes:
                              - If you provide snippets here (non-empty list), only those snippets are created/updated.
                              - If you omit snippets but reference an existing snippet_id/snippet_reference from the DA,
                                the request will use that snippet normally (no default snippet is created).
                          items:
                              $ref: "#/components/schemas/Snippet"
                      collection_objects:
                          type: array
                          default: []
                          items:
                              $ref: "#/components/schemas/CollectionObject"
                      presentation_objects:
                          type: array
                          default: []
                          description: |
                              Performance apps only.

                              Special behavior:
                              - If this field is omitted OR provided as an empty list ([]), the system automatically
                                generates a Presentation Object for each newly created Collection Object.
                                The default Presentation Object name is the Collection Object name, and the default
                                formula is (o_<collection_object_id>).
                              - If this field is provided and contains ANY objects, the system creates ONLY the
                                specified Presentation Objects and does NOT auto-generate any additional ones.
                              - To force auto-generation, omit presentation_objects or send presentation_objects: []
                          items:
                              $ref: "#/components/schemas/PresentationObject"
                      threshold_objects:
                          type: array
                          default: []
                          items:
                              $ref: "#/components/schemas/ThresholdObject"
                      alert_objects:
                          type: array
                          default: []
                          items:
                              $ref: "#/components/schemas/AlertObject"

        EntityIdentifier:
            type: object
            required: [id, guid, name, new]
            properties:
                id:
                    type: integer
                    description: DB numeric identifier
                guid:
                    $ref: "#/components/schemas/GUID"
                name:
                    type: string
                reference:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/Reference"
                    nullable: true
                new:
                    type: boolean

        DynamicAppUpdateResult:
            type: object
            required:
                - dynamic_app
                - snippets
                - collection_objects
                - presentation_objects
                - threshold_objects
                - alert_objects
            properties:
                dynamic_app:
                    $ref: "#/components/schemas/EntityIdentifier"
                snippets:
                    type: array
                    items:
                        $ref: "#/components/schemas/EntityIdentifier"
                collection_objects:
                    type: array
                    items:
                        $ref: "#/components/schemas/EntityIdentifier"
                presentation_objects:
                    type: array
                    items:
                        $ref: "#/components/schemas/EntityIdentifier"
                threshold_objects:
                    type: array
                    items:
                        $ref: "#/components/schemas/EntityIdentifier"
                alert_objects:
                    type: array
                    items:
                        $ref: "#/components/schemas/EntityIdentifier"

        DynamicApplicationUpdateResponse:
            type: object
            required: [success, results]
            properties:
                success:
                    type: boolean
                    description: Whether the update call succeeded overall.
                results:
                    type: array
                    description: Per-entity update results (IDs/guids/new/reference).
                    items:
                        $ref: "#/components/schemas/DynamicAppUpdateResult"
                entities:
                    type: array
                    nullable: true
                    description: |
                        Only returned when retrieve=true. When present, contains the normalized, fully-expanded entities
                        as stored/returned by the API (DynamicApp + nested entity arrays).
                    items:
                        $ref: "#/components/schemas/DynamicApplicationGetResponse"

        # --- Core models ---

        DynamicApp:
            type: object
            properties:
                guid:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/GUID"
                    nullable: true
                    description: Required for update; omit or null for create.
                pp_guid:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/GUID"
                    nullable: true
                    description: PowerPack GUID (immutable).
                name:
                    type: string
                    minLength: 1
                    maxLength: 64
                    description: Required on create. Optional on update.
                type:
                    allOf:
                        - $ref: "#/components/schemas/FlexibleEnumApplicationType"
                    description: Required on create. Immutable once created.
                is_sf_app_type:
                    allOf:
                        - $ref: "#/components/schemas/FlexibleEnumBooleanToggle"
                abandon_collection_limit:
                    type: integer
                    minimum: 0
                    nullable: true
                max_devices:
                    type: integer
                    minimum: 1
                version:
                    type: number
                    minimum: 0.1
                state:
                    allOf:
                        - $ref: "#/components/schemas/FlexibleEnumEnabledToggle"
                poll_interval:
                    allOf:
                        - $ref: "#/components/schemas/FlexibleEnumPollInterval"
                cu_affinity:
                    allOf:
                        - $ref: "#/components/schemas/FlexibleEnumCUAffinity"
                execution_environment:
                    type: string
                    description: Execution environment GUID or sl1_default_ee
                component_mapping:
                    allOf:
                        - $ref: "#/components/schemas/FlexibleEnumEnabledToggle"
                component_mapping_dynamic_applications:
                    type: array
                    default: []
                    description: |
                        List of Dynamic Applications linked for component mapping.

                        Only meaningful when component_mapping is ENABLED.

                        Response behavior:
                        - This field is only returned by GET/POST responses when component_mapping is ENABLED.
                        - If component_mapping is DISABLED, this field will be omitted from the response entirely.

                        Each item may be:
                        - a Dynamic Application GUID (32-character uppercase hex), or
                        - a request-scoped reference (when linking to a DA created in the same POST).

                        If omitted in a POST request, it defaults to an empty list.
                    items:
                        oneOf:
                            - $ref: "#/components/schemas/GUID"
                            - $ref: "#/components/schemas/Reference"
                description:
                    type: string
                disable_rollup_of_data:
                    allOf:
                        - $ref: "#/components/schemas/FlexibleEnumBooleanToggle"
                release_notes:
                    type: string
                null_row_option:
                    allOf:
                        - $ref: "#/components/schemas/FlexibleEnumMissingTableDataOption"
                null_column_option:
                    allOf:
                        - $ref: "#/components/schemas/FlexibleEnumMissingTableDataOption"

        Snippet:
            type: object
            properties:
                guid:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/GUID"
                    nullable: true
                reference:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/Reference"
                    nullable: true
                name:
                    type: string
                    minLength: 1
                    maxLength: 64
                snippet:
                    type: string
                state:
                    $ref: "#/components/schemas/FlexibleEnumEnabledToggle"
                required:
                    $ref: "#/components/schemas/FlexibleEnumRequiredToggle"

        CollectionObject:
            type: object
            properties:
                guid:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/GUID"
                    nullable: true
                reference:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/Reference"
                    nullable: true
                name:
                    type: string
                    minLength: 1
                    maxLength: 64
                description:
                    type: string
                class_type:
                    $ref: "#/components/schemas/FlexibleEnumCollectionObjectClass"
                snippet_id:
                    type: integer
                    description: Snippet DB id (0 means default).
                snippet_reference:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/Reference"
                    nullable: true
                    description: Reference label for snippet (e.g., snip_123), useful for new snippets.
                snippet_argument:
                    type: string
                formula:
                    type: string
                    maxLength: 512
                group:
                    type: integer
                    minimum: 0
                    maximum: 50
                component_identifiers:
                    type: array
                    default: []
                    description: |
                        Optional list of component identifier types used for component mapping.

                        Only meaningful when the owning Dynamic Application has:
                        component_mapping = ENABLED

                        If component_mapping is DISABLED:
                        - Setting this field, even to an empty list, will cause the payload to fail validation and be rejected.
                          This field should only be set when component_mapping = ENABLED

                        Additional rules when enabled:
                        - values must be unique within the list
                        - values must be globally unique across all collection_objects in the same Dynamic Application
                    items:
                        $ref: "#/components/schemas/FlexibleEnumComponentIdentifier"
                disable_maintenance:
                    $ref: "#/components/schemas/FlexibleEnumBooleanToggle"
                usage_type:
                    $ref: "#/components/schemas/FlexibleEnumCollectionObjectUsage"
                hide_object:
                    $ref: "#/components/schemas/FlexibleEnumBooleanToggle"

                # Config-only
                change_alerting:
                    $ref: "#/components/schemas/FlexibleEnumEnabledToggle"
                asset_link:
                    $ref: "#/components/schemas/FlexibleEnumAssetLink"
                asset_link_precedence:
                    type: integer
                    minimum: 0
                    maximum: 100
                    description: Must be in increments of 10.
                table_alignment:
                    $ref: "#/components/schemas/FlexibleEnumTableAlignment"
                string_type:
                    $ref: "#/components/schemas/FlexibleEnumConfigStringType"
                enum_values:
                    type: string
                    description: Only valid for CONFIG_ENUM objects.
                tabular:
                    $ref: "#/components/schemas/FlexibleEnumEnabledToggle"
                alignment_condition:
                    $ref: "#/components/schemas/FlexibleEnumDiscoveryAlignmentCondition"
                validity_check_pattern:
                    type: string
                    maxLength: 128
                validity_check_operator:
                    $ref: "#/components/schemas/FlexibleEnumDiscoveryOperator"

                # Performance-only
                enable_deviation_alerting:
                    $ref: "#/components/schemas/FlexibleEnumBooleanToggle"
                min_weeks_data:
                    type: integer
                    minimum: 0
                max_weeks_data:
                    type: integer
                    minimum: 0

        PresentationObject:
            type: object
            properties:
                guid:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/GUID"
                    nullable: true
                reference:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/Reference"
                    nullable: true
                name:
                    type: string
                    minLength: 1
                    maxLength: 42
                guide_text:
                    type: string
                    maxLength: 2048
                formula:
                    type: string
                    maxLength: 512
                    default: "()"
                show_as_percent:
                    $ref: "#/components/schemas/FlexibleEnumBooleanToggle"
                summarization_state:
                    $ref: "#/components/schemas/FlexibleEnumBooleanToggle"
                abbreviation_suffix:
                    type: string
                    maxLength: 16
                data_unit:
                    type: string
                    maxLength: 25

        ThresholdObject:
            type: object
            properties:
                guid:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/GUID"
                    nullable: true
                reference:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/Reference"
                    nullable: true
                name:
                    type: string
                    minLength: 1
                    maxLength: 64
                override_threshold_value:
                    allOf:
                        - $ref: "#/components/schemas/FlexibleEnumBooleanToggle"
                    default: 1
                numeric_range_high:
                    type: number
                    minimum: 0
                    default: 100.0
                numeric_range_low:
                    type: number
                    minimum: 0
                    default: 0.0
                type:
                    allOf:
                        - $ref: "#/components/schemas/FlexibleEnumThresholdType"
                    default: 0
                unit:
                    type: string
                    maxLength: 25
                    nullable: true
                value:
                    type: number
                    minimum: 0
                    default: 90.0

        AlertObject:
            type: object
            properties:
                guid:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/GUID"
                    nullable: true
                reference:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/Reference"
                    nullable: true
                state:
                    $ref: "#/components/schemas/FlexibleEnumEnabledToggle"
                name:
                    type: string
                    minLength: 1
                    maxLength: 128
                formula:
                    type: string
                    minLength: 1
                    maxLength: 512
                log_message:
                    type: string
                    minLength: 1
                    maxLength: 128
                maintain_state:
                    $ref: "#/components/schemas/FlexibleEnumEnabledToggle"
                triggered_alert_id:
                    type: integer
                    default: 0
                triggered_alert_reference:
                    type: string
                    allOf:
                        - $ref: "#/components/schemas/Reference"
                    nullable: true

        # --- GET response wrappers (shape-oriented, not strict DB mirror) ---

        DynamicApplicationGetResponse:
            oneOf:
                - $ref: "#/components/schemas/DynamicApplicationGetResponsePerformance"
                - $ref: "#/components/schemas/DynamicApplicationGetResponseConfiguration"
            discriminator:
                propertyName: type
                mapping:
                    SNIPPET_PERFORMANCE: "#/components/schemas/DynamicApplicationGetResponsePerformance"
                    BULK_SNIPPET_PERFORMANCE: "#/components/schemas/DynamicApplicationGetResponsePerformance"
                    SNIPPET_CONFIGURATION: "#/components/schemas/DynamicApplicationGetResponseConfiguration"
                    BULK_SNIPPET_CONFIGURATION: "#/components/schemas/DynamicApplicationGetResponseConfiguration"

        DynamicApplicationGetResponseBase:
            allOf:
                - $ref: "#/components/schemas/DynamicApp"
                - type: object
                  properties:
                      snippets:
                          type: array
                          items:
                              $ref: "#/components/schemas/Snippet"
                      collection_objects:
                          type: array
                          items:
                              $ref: "#/components/schemas/CollectionObject"
                      threshold_objects:
                          type: array
                          items:
                              $ref: "#/components/schemas/ThresholdObject"
                      alert_objects:
                          type: array
                          items:
                              $ref: "#/components/schemas/AlertObject"

        DynamicApplicationGetResponsePerformance:
            allOf:
                - $ref: "#/components/schemas/DynamicApplicationGetResponseBase"
                - type: object
                  required: [type]
                  properties:
                      type:
                          oneOf:
                              - type: string
                                enum: ["SNIPPET_PERFORMANCE", "BULK_SNIPPET_PERFORMANCE"]
                              - type: integer
                      presentation_objects:
                          type: array
                          items:
                              $ref: "#/components/schemas/PresentationObject"

        DynamicApplicationGetResponseConfiguration:
            allOf:
                - $ref: "#/components/schemas/DynamicApplicationGetResponseBase"
                - type: object
                  required: [type]
                  properties:
                      type:
                          oneOf:
                              - type: string
                                enum: ["SNIPPET_CONFIGURATION", "BULK_SNIPPET_CONFIGURATION"]
                              - type: integer

        PowerPackResponse:
            type: object
            properties:
                guid:
                    $ref: "#/components/schemas/GUID"
                id:
                    type: integer
                name:
                    type: string
                revision:
                    type: integer
                dynamic_applications:
                    type: array
                    items:
                        $ref: "#/components/schemas/DynamicApplicationGetResponse"
                errors:
                    type: array
                    items:
                        type: string
```

---

# 15) JSONSchema Specification

```json
{
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://example.invalid/schemas/dynamic-applications.schema.json",
    "title": "Dynamic Applications API - Normalized POST Request",
    "description": "JSON Schema for POST /lce/api/dynamic_applications. Captures explicit field shapes and many implicit validation rules that are expressible in JSON Schema. Rules requiring DB lookups or cross-entity uniqueness across arrays are documented but not enforceable here.",
    "oneOf": [
        { "$ref": "#/$defs/DynamicApplicationUpdateRequestItem" },
        {
            "type": "array",
            "items": { "$ref": "#/$defs/DynamicApplicationUpdateRequestItem" }
        }
    ],
    "$defs": {
        "GUID": {
            "type": "string",
            "pattern": "^[A-F0-9]{32}$",
            "description": "Uppercase 32-hex GUID. If present, entity is treated as existing (update semantics) and must exist in DB (DB existence not enforceable via JSON Schema)."
        },

        "Reference": {
            "type": "string",
            "minLength": 1,
            "description": "Request-scoped identifier used to link newly-created entities within this request. Must be unique across the entire payload across ALL entity types (not enforceable in JSON Schema)."
        },

        "FlexibleBooleanToggle": {
            "description": "Accepts boolean-like strings or 0/1. Case-insensitive behavior is not enforceable in JSON Schema; clients should use canonical values.",
            "oneOf": [
                { "type": "integer", "enum": [0, 1] },
                { "type": "string", "enum": ["FALSE", "TRUE"] }
            ]
        },

        "FlexibleEnabledToggle": {
            "oneOf": [
                { "type": "integer", "enum": [0, 1] },
                { "type": "string", "enum": ["DISABLED", "ENABLED"] }
            ]
        },

        "FlexibleRequiredToggle": {
            "oneOf": [
                { "type": "integer", "enum": [0, 1] },
                { "type": "string", "enum": ["NOT_REQUIRED", "REQUIRED"] }
            ]
        },

        "ApplicationType": {
            "description": "Only Snippet Framework types are accepted for this endpoint.",
            "oneOf": [
                { "type": "integer" },
                {
                    "type": "string",
                    "enum": [
                        "SNIPPET_PERFORMANCE",
                        "SNIPPET_CONFIGURATION",
                        "BULK_SNIPPET_PERFORMANCE",
                        "BULK_SNIPPET_CONFIGURATION"
                    ]
                }
            ]
        },

        "CollectionObjectClassPerformance": {
            "type": "string",
            "enum": [
                "PERFORMANCE_COUNTER",
                "PERFORMANCE_PERCENT",
                "PERFORMANCE_KILOBYTE",
                "PERFORMANCE_GAUGE",
                "DISCOVERY",
                "LABEL_HOURLY_POLLED",
                "LABEL_ALWAYS_POLLED",
                "INDEX",
                "LABEL_IP_ALWAYS_POLLED"
            ]
        },

        "CollectionObjectClassConfig": {
            "type": "string",
            "enum": [
                "CONFIG_CHARACTER",
                "CONFIG_ENUM",
                "CONFIG_TIMETICKS",
                "CONFIG_GAUGE",
                "CONFIG_NUMERIC",
                "CONFIG_TIMESTAMP",
                "CONFIG_MAC_ADDRESS",
                "CONFIG_IP_ADDRESS",
                "CONFIG_DATETIME",
                "DISCOVERY",
                "LABEL_HOURLY_POLLED",
                "LABEL_ALWAYS_POLLED",
                "INDEX",
                "INDEX_LABEL",
                "LABEL_CONFIG_GROUP"
            ]
        },

        "CollectionObjectUsage": {
            "type": "string",
            "enum": [
                "STANDARD",
                "GROUP_INDEX",
                "IDENTITY_NAMESPACE",
                "RELATIONSHIP_NAMESPACE",
                "GUID_RELATIONSHIP",
                "UNIQUE_IDENTIFIER_RELATIONSHIP",
                "GUID_PLUS_INDEX",
                "UNIQUE_IDENTIFIER_PLUS_INDEX"
            ]
        },

        "TableAlignment": {
            "type": "string",
            "enum": ["LEFT", "CENTER", "RIGHT"]
        },

        "ConfigStringType": {
            "type": "string",
            "enum": ["STANDARD", "HEX_UNICODE"]
        },

        "AssetLink": {
            "type": "string",
            "enum": [
                "NONE",
                "MAKE",
                "MODEL",
                "SERIAL_NUMBER",
                "OPERATING_SYSTEM",
                "HOST_ID_SID",
                "OS_SYSTEM_NAME",
                "CPU_COUNT",
                "CPU_TYPE_MAKE",
                "CPU_SPEED",
                "FIRMWARE_BIOS_NAME",
                "INSTALLED_MEMORY",
                "HARD_DISK_DRIVE",
                "COMPONENT_TYPE",
                "COMPONENT_MAKE",
                "COMPONENT_MODEL",
                "COMPONENT_SERIAL",
                "COMPONENT_SLOT",
                "COMPONENT_NOTES",
                "COMPONENT_CONNECT",
                "PROFILE_MEMO",
                "ASSET_TAG",
                "DISK_ARRAY_SIZE",
                "DISK_COUNT",
                "DISK_SIZE",
                "METHOD",
                "ANNUAL_RATE",
                "RFID_NUMBER",
                "MODEL_NUMBER"
            ],
            "description": "AssetLink. For CONFIG apps the server restricts this to an allowed subset (captured in CollectionObject config-only rules below)."
        },

        "ComponentIdentifier": {
            "type": "string",
            "enum": [
                "UNKNOWN",
                "UNIQUE_IDENTIFIER",
                "DISTINGUISHED_NAME",
                "CLASS_IDENTIFIER_1",
                "CLASS_IDENTIFIER_2",
                "DEVICE_NAME",
                "MAC_ADDRESS",
                "UUID",
                "AVAILABILITY",
                "GUID",
                "ORGANIZATION",
                "PREVIOUS_UNIQUE_IDS",
                "IP_ADDRESS"
            ]
        },

        "DiscoveryAlignmentCondition": {
            "type": "string",
            "enum": ["IF_OID_PRESENT", "IF_OID_NOT_PRESENT"]
        },

        "DiscoveryOperator": {
            "type": "string",
            "enum": [
                "UNSET",
                "IS_GREATER_THAN_RESULT",
                "IS_EQUAL_TO_RESULT",
                "IS_LESS_THAN_RESULT",
                "IS_NOT_EQUAL_TO_RESULT",
                "IS_LIKE",
                "MATCHES_REGEX",
                "NO_VALIDITY_CHECK"
            ]
        },

        "ThresholdType": {
            "type": "string",
            "enum": ["PERCENTAGE", "INTEGER", "DECIMAL"]
        },

        "Snippet": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "guid": { "oneOf": [{ "$ref": "#/$defs/GUID" }, { "type": "null" }] },
                "reference": { "oneOf": [{ "$ref": "#/$defs/Reference" }, { "type": "null" }] },
                "name": { "type": "string", "minLength": 1, "maxLength": 64 },
                "snippet": { "type": "string", "description": "Python snippet code." },
                "state": { "$ref": "#/$defs/FlexibleEnabledToggle" },
                "required": { "$ref": "#/$defs/FlexibleRequiredToggle" },

                "id": {
                    "description": "Not accepted in POST; ignored by server if provided. This schema forbids it to prevent confusion.",
                    "not": {}
                }
            },
            "required": ["name"]
        },

        "PresentationObject": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "guid": { "oneOf": [{ "$ref": "#/$defs/GUID" }, { "type": "null" }] },
                "reference": { "oneOf": [{ "$ref": "#/$defs/Reference" }, { "type": "null" }] },
                "name": { "type": "string", "minLength": 1, "maxLength": 42 },
                "guide_text": { "type": "string", "maxLength": 2048 },
                "formula": { "type": "string", "maxLength": 512, "default": "()" },
                "show_as_percent": { "$ref": "#/$defs/FlexibleBooleanToggle" },
                "summarization_state": { "$ref": "#/$defs/FlexibleBooleanToggle" },
                "abbreviation_suffix": { "type": "string", "maxLength": 16 },
                "data_unit": { "type": "string", "maxLength": 25 },

                "id": { "not": {} }
            },
            "required": ["name"]
        },

        "ThresholdObject": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "guid": { "oneOf": [{ "$ref": "#/$defs/GUID" }, { "type": "null" }] },
                "reference": { "oneOf": [{ "$ref": "#/$defs/Reference" }, { "type": "null" }] },
                "name": { "type": "string", "minLength": 1, "maxLength": 64 },
                "override_threshold_value": { "$ref": "#/$defs/FlexibleBooleanToggle" },
                "numeric_range_high": { "type": "number", "minimum": 0 },
                "numeric_range_low": { "type": "number", "minimum": 0 },
                "type": { "$ref": "#/$defs/ThresholdType" },
                "unit": { "oneOf": [{ "type": "string", "maxLength": 25 }, { "type": "null" }] },
                "value": { "type": "number", "minimum": 0 },

                "id": { "not": {} }
            },
            "required": ["name"]
        },

        "AlertObject": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "guid": { "oneOf": [{ "$ref": "#/$defs/GUID" }, { "type": "null" }] },
                "reference": { "oneOf": [{ "$ref": "#/$defs/Reference" }, { "type": "null" }] },
                "state": { "$ref": "#/$defs/FlexibleEnabledToggle" },
                "name": { "type": "string", "minLength": 1, "maxLength": 128 },
                "formula": { "type": "string", "minLength": 1, "maxLength": 512 },
                "log_message": { "type": "string", "minLength": 1, "maxLength": 128 },
                "maintain_state": { "$ref": "#/$defs/FlexibleEnabledToggle" },

                "triggered_alert_id": { "type": "integer", "minimum": 0, "default": 0 },
                "triggered_alert_reference": { "oneOf": [{ "$ref": "#/$defs/Reference" }, { "type": "null" }] },

                "id": { "not": {} }
            },
            "required": ["name", "formula", "log_message"]
        },

        "CollectionObjectBase": {
            "type": "object",
            "description": "Collection object. Field legality depends on app type and class_type.",
            "properties": {
                "guid": { "oneOf": [{ "$ref": "#/$defs/GUID" }, { "type": "null" }] },
                "reference": { "oneOf": [{ "$ref": "#/$defs/Reference" }, { "type": "null" }] },
                "name": { "type": "string", "minLength": 1, "maxLength": 64 },

                "class_type": {
                    "description": "Validated against allowed values depending on app type. If omitted, server defaults based on app type (PERFORMANCE_COUNTER vs CONFIG_CHARACTER).",
                    "oneOf": [{ "type": "string" }, { "type": "integer" }]
                },

                "snippet_id": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "0 means default/unset. Server may assign fallback snippet."
                },
                "snippet_reference": { "oneOf": [{ "$ref": "#/$defs/Reference" }, { "type": "null" }] },
                "snippet_argument": { "type": "string" },

                "id": { "not": {} }
            },
            "required": ["name"],
            "additionalProperties": true
        },

        "CollectionObjectDiscoveryExtras": {
            "type": "object",
            "properties": {
                "class_type": { "const": "DISCOVERY" },
                "tabular": { "$ref": "#/$defs/FlexibleEnabledToggle" },
                "alignment_condition": { "$ref": "#/$defs/DiscoveryAlignmentCondition" },
                "validity_check_pattern": { "type": "string", "maxLength": 128 },
                "validity_check_operator": { "$ref": "#/$defs/DiscoveryOperator" }
            },
            "required": ["alignment_condition"],
            "allOf": [
                {
                    "if": {
                        "properties": { "alignment_condition": { "const": "IF_OID_PRESENT" } },
                        "required": ["alignment_condition"]
                    },
                    "then": {
                        "required": ["validity_check_pattern", "validity_check_operator"]
                    },
                    "else": {
                        "not": {
                            "anyOf": [
                                { "required": ["validity_check_pattern"] },
                                { "required": ["validity_check_operator"] }
                            ]
                        }
                    }
                }
            ]
        },

        "CollectionObjectEnumExtras": {
            "type": "object",
            "properties": {
                "class_type": { "const": "CONFIG_ENUM" },
                "string_type": { "$ref": "#/$defs/ConfigStringType" },
                "group": { "type": "integer", "minimum": 0, "maximum": 50 },
                "usage_type": { "$ref": "#/$defs/CollectionObjectUsage" },
                "change_alerting": { "$ref": "#/$defs/FlexibleEnabledToggle" },
                "table_alignment": { "$ref": "#/$defs/TableAlignment" },
                "hide_object": { "$ref": "#/$defs/FlexibleBooleanToggle" },
                "disable_maintenance": { "$ref": "#/$defs/FlexibleBooleanToggle" },
                "description": { "type": "string" },
                "enum_values": { "type": "string" },
                "formula": { "type": "string", "maxLength": 512 }
            },
            "required": ["enum_values"]
        },

        "CollectionObjectConfigExtras": {
            "type": "object",
            "properties": {
                "string_type": { "$ref": "#/$defs/ConfigStringType" },
                "group": { "type": "integer", "minimum": 0, "maximum": 50 },
                "usage_type": { "$ref": "#/$defs/CollectionObjectUsage" },

                "asset_link": {
                    "description": "Config-only. Server restricts to an allowed subset for config apps; schema enforces that subset here.",
                    "type": "string",
                    "enum": [
                        "NONE",
                        "MAKE",
                        "MODEL",
                        "SERIAL_NUMBER",
                        "OPERATING_SYSTEM",
                        "HOST_ID_SID",
                        "OS_SYSTEM_NAME",
                        "CPU_COUNT",
                        "CPU_TYPE_MAKE",
                        "CPU_SPEED",
                        "FIRMWARE_BIOS_NAME",
                        "INSTALLED_MEMORY",
                        "ASSET_TAG",
                        "DISK_ARRAY_SIZE",
                        "DISK_COUNT",
                        "DISK_SIZE",
                        "MODEL_NUMBER"
                    ]
                },

                "asset_link_precedence": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100,
                    "multipleOf": 10,
                    "description": "Must be increments of 10."
                },

                "change_alerting": { "$ref": "#/$defs/FlexibleEnabledToggle" },
                "table_alignment": { "$ref": "#/$defs/TableAlignment" },
                "hide_object": { "$ref": "#/$defs/FlexibleBooleanToggle" },
                "disable_maintenance": { "$ref": "#/$defs/FlexibleBooleanToggle" },
                "description": { "type": "string" },

                "component_identifiers": {
                    "type": "array",
                    "items": { "$ref": "#/$defs/ComponentIdentifier" },
                    "uniqueItems": true,
                    "description": "Only allowed when parent dynamic_app.component_mapping is ENABLED (enforced at higher level). Also must be globally unique across collection_objects (not enforceable in JSON Schema)."
                },

                "formula": { "type": "string", "maxLength": 512 }
            }
        },

        "CollectionObjectPerformanceExtras": {
            "type": "object",
            "properties": {
                "group": { "type": "integer", "minimum": 0, "maximum": 50 },
                "usage_type": { "$ref": "#/$defs/CollectionObjectUsage" },
                "enable_deviation_alerting": { "$ref": "#/$defs/FlexibleBooleanToggle" },
                "min_weeks_data": { "type": "integer", "minimum": 0 },
                "max_weeks_data": { "type": "integer", "minimum": 0 },
                "disable_maintenance": { "$ref": "#/$defs/FlexibleBooleanToggle" }
            }
        },

        "CollectionObjectConfigAllowed": {
            "allOf": [
                { "$ref": "#/$defs/CollectionObjectBase" },
                {
                    "properties": {
                        "class_type": {
                            "oneOf": [{ "$ref": "#/$defs/CollectionObjectClassConfig" }, { "type": "integer" }]
                        }
                    }
                },
                {
                    "if": { "properties": { "class_type": { "const": "DISCOVERY" } }, "required": ["class_type"] },
                    "then": {
                        "allOf": [{ "$ref": "#/$defs/CollectionObjectDiscoveryExtras" }],
                        "unevaluatedProperties": false
                    },
                    "else": {
                        "if": {
                            "properties": { "class_type": { "const": "CONFIG_ENUM" } },
                            "required": ["class_type"]
                        },
                        "then": {
                            "allOf": [
                                { "$ref": "#/$defs/CollectionObjectConfigExtras" },
                                { "$ref": "#/$defs/CollectionObjectEnumExtras" }
                            ],
                            "unevaluatedProperties": false
                        },
                        "else": {
                            "allOf": [{ "$ref": "#/$defs/CollectionObjectConfigExtras" }],
                            "unevaluatedProperties": false
                        }
                    }
                }
            ]
        },

        "CollectionObjectPerformanceAllowed": {
            "allOf": [
                { "$ref": "#/$defs/CollectionObjectBase" },
                {
                    "properties": {
                        "class_type": {
                            "oneOf": [{ "$ref": "#/$defs/CollectionObjectClassPerformance" }, { "type": "integer" }]
                        }
                    }
                },
                {
                    "if": { "properties": { "class_type": { "const": "DISCOVERY" } }, "required": ["class_type"] },
                    "then": {
                        "allOf": [{ "$ref": "#/$defs/CollectionObjectDiscoveryExtras" }],
                        "unevaluatedProperties": false
                    },
                    "else": {
                        "allOf": [{ "$ref": "#/$defs/CollectionObjectPerformanceExtras" }],
                        "unevaluatedProperties": false
                    }
                }
            ]
        },

        "DynamicAppBase": {
            "type": "object",
            "description": "Dynamic Application base model. Many server behaviors (defaults, rewrites, DB checks) are documented in field descriptions but cannot be enforced here.",
            "properties": {
                "guid": { "oneOf": [{ "$ref": "#/$defs/GUID" }, { "type": "null" }] },
                "reference": { "oneOf": [{ "$ref": "#/$defs/Reference" }, { "type": "null" }] },

                "name": { "type": "string", "minLength": 1, "maxLength": 64 },

                "type": { "$ref": "#/$defs/ApplicationType" },

                "pp_guid": { "oneOf": [{ "$ref": "#/$defs/GUID" }, { "type": "null" }] },

                "is_sf_app_type": { "$ref": "#/$defs/FlexibleBooleanToggle" },

                "abandon_collection_limit": { "oneOf": [{ "type": "integer", "minimum": 0 }, { "type": "null" }] },

                "max_devices": { "type": "integer", "minimum": 1 },

                "version": { "type": "number", "minimum": 0.1 },

                "state": { "$ref": "#/$defs/FlexibleEnabledToggle" },

                "poll_interval": {
                    "description": "Poll interval enum; request accepts string or integer in API. This schema only validates common string forms if you want to add them.",
                    "oneOf": [{ "type": "integer" }, { "type": "string" }]
                },

                "cu_affinity": {
                    "oneOf": [
                        { "type": "integer" },
                        { "type": "string", "enum": ["DEFAULT", "ROOT_DEVICE", "ASSIGNED_COLLECTOR"] }
                    ]
                },

                "execution_environment": { "type": "string" },

                "component_mapping": { "$ref": "#/$defs/FlexibleEnabledToggle" },

                "component_mapping_dynamic_applications": {
                    "type": "array",
                    "items": { "oneOf": [{ "$ref": "#/$defs/GUID" }, { "$ref": "#/$defs/Reference" }] },
                    "default": []
                },

                "description": { "type": "string" },
                "disable_rollup_of_data": { "$ref": "#/$defs/FlexibleBooleanToggle" },
                "release_notes": { "type": "string" },

                "null_row_option": { "oneOf": [{ "type": "integer" }, { "type": "string" }] },
                "null_column_option": { "oneOf": [{ "type": "integer" }, { "type": "string" }] },

                "snippets": {
                    "type": "array",
                    "items": { "$ref": "#/$defs/Snippet" },
                    "default": []
                },

                "collection_objects": {
                    "type": "array",
                    "items": {},
                    "default": []
                },

                "presentation_objects": {
                    "type": "array",
                    "items": { "$ref": "#/$defs/PresentationObject" },
                    "default": []
                },

                "threshold_objects": {
                    "type": "array",
                    "items": { "$ref": "#/$defs/ThresholdObject" },
                    "default": []
                },

                "alert_objects": {
                    "type": "array",
                    "items": { "$ref": "#/$defs/AlertObject" },
                    "default": []
                },

                "id": { "not": {} }
            },
            "required": ["name"]
        },

        "DynamicApplicationUpdateRequestItem": {
            "allOf": [
                { "$ref": "#/$defs/DynamicAppBase" },

                {
                    "if": {
                        "properties": {
                            "type": {
                                "anyOf": [{ "const": "SNIPPET_PERFORMANCE" }, { "const": "BULK_SNIPPET_PERFORMANCE" }]
                            }
                        },
                        "required": ["type"]
                    },
                    "then": {
                        "properties": {
                            "collection_objects": {
                                "type": "array",
                                "items": { "$ref": "#/$defs/CollectionObjectPerformanceAllowed" }
                            }
                        }
                    },
                    "else": {
                        "properties": {
                            "collection_objects": {
                                "type": "array",
                                "items": { "$ref": "#/$defs/CollectionObjectConfigAllowed" }
                            }
                        }
                    }
                },

                {
                    "description": "component_identifiers field legality based on component_mapping. When component_mapping is DISABLED, any appearance of component_identifiers is invalid (even empty list).",
                    "if": {
                        "properties": {
                            "component_mapping": {
                                "anyOf": [{ "const": "DISABLED" }, { "const": 0 }]
                            }
                        }
                    },
                    "then": {
                        "properties": {
                            "collection_objects": {
                                "type": "array",
                                "items": {
                                    "not": {
                                        "required": ["component_identifiers"]
                                    }
                                }
                            }
                        }
                    }
                },

                {
                    "description": "Presentation objects only meaningful for performance apps; server ignores/rejects for config apps depending on implementation. Schema forbids presentation_objects when app is config type to match documented behavior.",
                    "if": {
                        "properties": {
                            "type": {
                                "anyOf": [
                                    { "const": "SNIPPET_CONFIGURATION" },
                                    { "const": "BULK_SNIPPET_CONFIGURATION" }
                                ]
                            }
                        },
                        "required": ["type"]
                    },
                    "then": {
                        "not": { "required": ["presentation_objects"] }
                    }
                }
            ],
            "unevaluatedProperties": false
        }
    }
}
```

---

# 16) Additional Behaviors Not Found in Schemas

1. Cross-entity uniqueness across the entire payload
    - all guid unique across all entity types
    - all reference unique across all entity types
2. DB existence / ownership checks
    - guid exists when updating
    - snippet_id belongs to the same DA
    - triggered_alert_id points to an alert in same DA
3. Derived / rewritten fields
    - reference auto-defaulting (reference = guid) when guid present
    - canonical reference reassignments (o*<id>, snip*<id>, etc.)
    - formula rewrites from (cpu1) -> (o\_<new_id>)
4. App-type feature toggles
    - is_sf_app_type gating rules (if TRUE then type must be SNIPPET_PERFORMANCE/SNIPPET_CONFIGURATION, etc.)
5. Group identity/relationship namespace rules
    - when usage_type in IDENTITY_NAMESPACE / RELATIONSHIP_NAMESPACE:
        - group must be set
        - a group index object must exist
        - duplicates rejected
    - resets usage_type to STANDARD and raises an error when not set correctly
6. Performance auto-generation rules
    - presentation auto-generation when omitted/empty
    - if any are provided presentation objects, none are auto-generated
7. Default snippet auto-creation logic
    - only when DA has no snippets and COs are created/updated and snippet refs missing/invalid
