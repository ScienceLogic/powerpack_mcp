"""
SL1 Database Statements

This module builds every SQL statement the SL1 platform tools issue, each as a ``sql.Statement``:
a validated ``(sql, params)`` pair. The reference implementation built SQL by string
interpolation through ``sql_quote()``; every statement here is rebuilt with caller values bound
as parameters, and each builder names the reference code it replaces.

Two decisions apply throughout:

- No ``SET @var`` session variables. Two ``local_db()`` handles do not share session state, so a
  lookup is resolved in Python and passed as a parameter instead. That cannot be broken by a
  refactor that splits a sequence, keeps each statement independently testable, and turns silent
  no-ops into explicit refusals.
- ``db_client.run_unit`` is still used where a sequence must share one connection: for
  ``lastrowid`` and ``LAST_INSERT_ID()``, and so a write's read-back sees the same session.

No rewrite affects more rows than the original. One deliberately affects fewer: the reference
aligned a Dynamic Application with ``SET class_type = COALESCE(@ct, class_type)``, so an unknown
device-class GUID assigned the column to itself and reported success. Here the class is resolved
first and an unknown one is refused.
"""

from __future__ import annotations

from typing import Final

from powerpack_mcp.sql import Statement

__all__ = [
    "COLLECTION_TOOLBOX_ID",
    "DEVICE_CLASS_TYPES",
    "MSG_TYPE_COMPLETED",
    "MSG_TYPE_STARTED",
    "MSG_TYPE_STDERR",
    "MSG_TYPE_STDOUT",
    "REMOTE_TOOLBOX_PROCESS_ID",
    "align_dynamic_app",
    "dispatch_dynamic_collection",
    "insert_active_event",
    "insert_device_class",
    "last_insert_id",
    "looks_like_class_guid",
    "read_aligned_dynamic_apps",
    "read_class_alignment",
    "read_collection_job",
    "read_collection_output",
    "read_component_map",
    "read_device_class_by_guid",
    "read_dynamic_app_alignment",
    "read_root_summary",
    "record_device_tool_run",
    "resolve_class_type_by_guid",
    "resolve_device_collector",
    "resolve_powerpack_guid_by_name",
    "update_device_class",
]

# ``virtual`` column values, from the reference implementation's ``device_classes.py``.
DEVICE_CLASS_TYPES: Final[dict[str, int]] = {"physical": 0, "virtual": 1, "component": 2}

# The columns ``update_device_class`` may set, mapped to their SQL column names. A column name
# cannot be a driver parameter, so this closed allowlist is the only thing keeping caller input out
# of statement text. ``identifyer_1``/``identifyer_3`` are SL1's own spelling, and
# ``class_identifier_2`` really does map to ``identifyer_3``; "fixing" either would write to the
# wrong column.
_UPDATABLE_COLUMNS: Final[dict[str, str]] = {
    "class_name": "class",
    "description": "descript",
    "device_type": "virtual",
    "is_snmp": "is_snmp",
    "root_device": "root_device",
    "class_identifier_1": "identifyer_1",
    "class_identifier_2": "identifyer_3",
}

_GUID_HEX: Final[frozenset[str]] = frozenset("0123456789abcdefABCDEF")


def looks_like_class_guid(value: str) -> bool:
    """Return whether ``value`` is 32 hex characters, case-insensitive.

    Deliberately not the LCE GUID validator, which requires uppercase. This routes an argument
    (GUID, name or id), and the strict check would send a lowercase GUID to the name branch, where
    it would fail as "not found", a confusing error for a correct input.
    """
    return len(value) == 32 and all(c in _GUID_HEX for c in value)


# =================================================================================================
# `sl1_simulate_event` -- ``tools/events.py::sl1_simulate_event``
# =================================================================================================

# The ``master_events.events_active`` columns written, in order. Kept as one constant so it can be
# read side by side with ``_EVENT_VALUES``; if the two fell out of alignment the insert would put a
# message into a date column, which MariaDB rejects without naming either field.
_EVENT_COLUMNS: Final[str] = (
    "Xtype, Xid, Xguid, Xname, Ytype, Yid, Yname, roa_id, tid, esource, emessage, msg_val, "
    "threshold, label, alert_id, eseverity, etype, ecounter, estate, user_ack, date_ack, "
    "user_del, date_del, date_first, date_last, date_active, notify_count, notify_stamp, "
    "suppress_time, suppress_group, suppress_topo, user_note, correlation_reason, "
    "event_detail_uri, edit_date"
)

# Values matching ``_EVENT_COLUMNS`` position for position: the caller values are parameters and
# the rest are constants. ``NOW()`` stays as statement text because binding it would send the
# client's clock instead of the server's. The zero-date is SL1's "unset" marker for
# ``date_ack``/``date_del``.
_EVENT_VALUES: Final[str] = (
    "1, %s, NULL, %s, 0, 0, '', 0, 0, %s, %s, %s, %s, '', NULL, %s, %s, 1, 0, 0, "
    "'0000-00-00 00:00:00', '', '0000-00-00 00:00:00', NOW(), NOW(), NOW(), 0, NULL, 0, 0, "
    "NULL, '', '', '', NOW()"
)


def insert_active_event(
    *,
    device_id: int,
    device_name: str,
    source: int,
    message: str,
    sub_message: str,
    threshold: str,
    severity: int,
    event_policy: int,
) -> Statement:
    """Build the insert of one synthetic active event.

    Every value a caller controls, including the free-text ``message``, is a parameter. The new
    event id comes from the cursor's ``lastrowid``, so no second ``SELECT LAST_INSERT_ID()`` is
    needed; one statement rather than two matters in a sequence that cannot be rolled back.

    :return: The ``INSERT`` statement.
    """
    # ruff S608 fires on every f-string SQL in this module, and rightly. It is suppressed per site,
    # never file-wide, and only where every interpolated piece is a module constant or a
    # code-chosen fragment and every caller value is a parameter. Here both pieces are the
    # ``Final`` constants above.
    return Statement(
        f"INSERT INTO master_events.events_active ({_EVENT_COLUMNS}) VALUES ({_EVENT_VALUES})",  # noqa: S608
        (
            device_id,
            device_name,
            source,
            message,
            sub_message,
            threshold,
            severity,
            event_policy,
        ),
    )


# =================================================================================================
# `sl1_get_component_tree` -- ``tools/collection.py::sl1_get_component_tree``
# =================================================================================================


# There is no root-resolution statement. ``sl1_get_component_tree`` resolves its root through
# REST with the caller's credential (``sl1_db_pipeline.resolve_device``) so SL1's organization ACL
# applies before any of these statements runs; a SQL name lookup would bypass it.


def read_root_summary(root_did: int) -> Statement:
    """Read the root device's name and class.

    Unlike the reference, this does not re-select the root id; the caller already holds it, and has
    already confirmed through REST that the caller's account can see it.
    """
    return Statement(
        "SELECT (SELECT device FROM master_dev.legend_device WHERE id = %s), "
        "(SELECT CONCAT(class, ' | ', descript) FROM master.definitions_dev_classes dc "
        "JOIN master_dev.legend_device d ON d.class_type = dc.class_type "
        "WHERE d.id = %s LIMIT 1)",
        (root_did, root_did),
    )


def read_component_map(root_did: int) -> Statement:
    """Read every component beneath the root that shares the root's organization.

    Column order is fixed because the caller unpacks by position: ``component_did, parent_did,
    name, class, state, unique_id, discovered_by_aid, last_seen``.

    The root itself has passed SL1's REST ACL by the time this runs, but its components have not,
    so they are scoped here as defence in depth. SL1 puts a component in its root's organization,
    so on a consistent appliance nothing is excluded (measured on two appliances: 946 map rows, no
    mismatch). ``legend_device`` and ``legend_device_vanished`` both carry ``roa_id``, and each is
    joined on the component's id *and* the root's ``roa_id``, as outer joins, so every map row
    still comes back: an in-scope component in full, labelled active or vanished, and any other as
    a row of NULLs that the caller counts as withheld without learning what it was. A component
    with no row in either table has nothing to check against and is withheld the same way.

    An in-scope component's ``parent_did`` is scoped the same way, through ``pd``/``pv``: it is
    returned when it is the root, ``0``, or a device in the root's organization (active or
    vanished), and is NULL otherwise, so an out-of-scope parent's id never leaves the database
    either. The root has already passed REST, so it needs no check.
    """
    # Every other map column is wrapped in ``IF(COALESCE(d.id, v.id) IS NULL, NULL, ...)``, the
    # parent in a ``CASE`` that also checks ``pd``/``pv``, and the id and name come from ``d``/``v``
    # rather than ``m``, so an out-of-scope row is all NULLs. Masked in SQL rather than dropped in
    # Python, so its identifiers never leave the database.
    return Statement(
        "SELECT COALESCE(d.id, v.id), "
        "CASE WHEN COALESCE(d.id, v.id) IS NULL THEN NULL "
        "WHEN m.parent_did = m.root_did OR m.parent_did = 0 "
        "OR COALESCE(pd.id, pv.id) IS NOT NULL THEN m.parent_did END, "
        "COALESCE(d.device, v.device), "
        "(SELECT CONCAT(class, ' | ', descript) FROM master.definitions_dev_classes dc "
        "WHERE dc.class_type = COALESCE(d.class_type, v.class_type) LIMIT 1), "
        "CASE WHEN d.id IS NOT NULL THEN 'active' WHEN v.id IS NOT NULL THEN 'vanished' END, "
        "IF(COALESCE(d.id, v.id) IS NULL, NULL, m.unique_id), "
        "IF(COALESCE(d.id, v.id) IS NULL, NULL, m.discovered_by_aid), "
        "IF(COALESCE(d.id, v.id) IS NULL, NULL, m.last_seen) "
        "FROM master_dev.component_dev_map m "
        "JOIN master_dev.legend_device r ON r.id = m.root_did "
        "LEFT JOIN master_dev.legend_device d ON d.id = m.component_did AND d.roa_id = r.roa_id "
        "LEFT JOIN master_dev.legend_device_vanished v "
        "ON v.id = m.component_did AND v.roa_id = r.roa_id "
        "LEFT JOIN master_dev.legend_device pd ON pd.id = m.parent_did AND pd.roa_id = r.roa_id "
        "LEFT JOIN master_dev.legend_device_vanished pv "
        "ON pv.id = m.parent_did AND pv.roa_id = r.roa_id "
        "WHERE m.root_did = %s ORDER BY m.parent_did, m.component_did",
        (root_did,),
    )


# =================================================================================================
# `sl1_create_device_class` -- ``tools/device_classes.py::sl1_create_device_class`
# =================================================================================================


def resolve_powerpack_guid_by_name(name: str) -> Statement:
    """Resolve a PowerPack name to its GUID.

    The reference embedded this as a sub-select that could also be ``NULL`` or a quoted literal. A
    placeholder cannot stand where a SQL fragment goes, so the shape is chosen in Python (see
    ``insert_device_class``) and only the value is a parameter. Resolving the name separately also
    lets a name that does not resolve be reported rather than stored as a silent ``NULL``.
    """
    return Statement(
        "SELECT ppguid FROM master.powerpack WHERE name = %s LIMIT 1",
        (name,),
    )


def insert_device_class(
    *,
    class_guid: str,
    family_guid: str,
    class_name: str,
    description: str,
    category: str,
    device_type: str,
    is_snmp: bool,
    root_device: bool,
    powerpack_guid: str | None,
    class_identifier_1: str,
    class_identifier_2: str,
) -> Statement:
    """Build the device-class insert, as ``INSERT ... SELECT`` so ``family`` is a real ``Fid``.

    The ``INSERT ... SELECT FROM definitions_dev_cats`` shape is deliberate: it guarantees
    ``family`` is a real category or nothing is inserted. Resolving the category in Python first
    would open a time-of-check to time-of-use gap with no transaction to close it, so this is the
    one lookup not moved into Python.

    Two pieces stay SQL fragments rather than parameters, because they change the statement's
    shape:

    - ``cat_where``: ``dc.Fid = %s`` for a numeric category, ``dc.cat_name = %s`` for a name.
    - the ``ppguid`` value: ``NULL`` or ``%s``, depending on whether a GUID was resolved.

    ``(SELECT MAX(class_type)+1 ...)`` is inherently racy, since two concurrent creates can compute
    the same ``class_type``. The race comes from SL1's own allocation scheme and is left alone,
    because changing how ``class_type`` is allocated is a platform decision.

    :raises ValueError: If ``device_type`` is not a key of ``DEVICE_CLASS_TYPES``.
    """
    if device_type not in DEVICE_CLASS_TYPES:
        raise ValueError(
            f"device_type must be one of {sorted(DEVICE_CLASS_TYPES)}: {device_type!r}"
        )

    # The column differs between the two branches, so this is a fragment choice.
    category_text = category.strip()
    # ``isdecimal()``, not ``isdigit()``: ``int("²")`` raises while ``"²".isdigit()`` is True.
    # See ``sl1_db_pipeline.coded()``.
    if category_text.isdecimal():
        cat_where = "dc.Fid = %s"
        cat_param: object = int(category_text)
    else:
        cat_where = "dc.cat_name = %s"
        cat_param = category_text

    # An unowned class gets a literal NULL rather than a bound ``None``, so the two cases stay
    # distinguishable when reading the rendered statement.
    if powerpack_guid is None:
        ppguid_fragment = "NULL"
        ppguid_params: tuple[object, ...] = ()
    else:
        ppguid_fragment = "%s"
        ppguid_params = (powerpack_guid,)

    # S608 is suppressed on the interpolated lines only. ``ppguid_fragment`` is one of the
    # literals "NULL"/"%s" chosen above, and ``cat_where`` is one of two literal column comparisons.
    # Neither is caller text; ``cat_param`` and every other value is bound.
    sql = (
        "INSERT INTO master.definitions_dev_classes "  # noqa: S608
        "(devtype_guid, ppguid, class, descript, class_type, identifyer_1, identifyer_2, "
        "identifyer_3, agent_identifier_1, agent_identifier_2, image, virtual, is_snmp, "
        "root_device, weight, catagory, family, family_guid, tier_id, date_edit) "
        f"SELECT %s, {ppguid_fragment}, %s, %s, "
        "(SELECT MAX(class_type) + 1 FROM master.definitions_dev_classes), "
        "%s, '', %s, '', '', '', %s, %s, %s, 1, 0, dc.Fid, %s, 0, NOW() "
        f"FROM master.definitions_dev_cats dc WHERE {cat_where} LIMIT 1"
    )
    params: tuple[object, ...] = (
        class_guid,
        *ppguid_params,
        class_name,
        description,
        class_identifier_1,
        class_identifier_2,
        DEVICE_CLASS_TYPES[device_type],
        int(is_snmp),
        int(root_device),
        family_guid,
        cat_param,
    )
    return Statement(sql, params)


def read_device_class_by_guid(class_guid: str) -> Statement:
    """Read a device class back by GUID, for both create and update.

    Selects the union of the columns both tools need. The caller checks the row count for success,
    which is stronger than the reference's test of whether the GUID appeared in the output.
    """
    return Statement(
        "SELECT id, devtype_guid, class, descript, class_type, virtual, family, ppguid, "
        "identifyer_1, identifyer_3, "
        "(SELECT cat_name FROM master.definitions_dev_cats "
        "WHERE Fid = definitions_dev_classes.family) AS category "
        "FROM master.definitions_dev_classes WHERE devtype_guid = %s",
        (class_guid,),
    )


# =================================================================================================
# `sl1_update_device_class` -- ``tools/device_classes.py::sl1_update_device_class``
# =================================================================================================


def update_device_class(
    *,
    class_guid: str,
    changes: dict[str, object],
    category_fid: int | None,
    clear_powerpack: bool,
    powerpack_guid: str | None,
) -> Statement:
    """Build an ``UPDATE`` that sets only the fields actually supplied.

    The ``SET`` clause's column names cannot be parameters, so they come only from the closed
    ``_UPDATABLE_COLUMNS`` mapping, and every value is a parameter.

    ``family = COALESCE(%s, family)`` keeps a deliberate safety property: a bad category is a
    no-op rather than nulling ``family``, which would break the class's rendering in AP2. The
    alignment ``COALESCE`` looked identical in SQL but hid a bug; this one is intended.

    :param changes: Tool argument names to new values. Keys must be in ``_UPDATABLE_COLUMNS``.
    :raises ValueError: If a key is not updatable, or there is nothing to change.
    """
    assignments: list[str] = []
    params: list[object] = []

    for argument, value in changes.items():
        if argument not in _UPDATABLE_COLUMNS:
            # Our defect, not caller input: the tool decides what lands in `changes`.
            raise ValueError(f"{argument!r} is not an updatable device-class field")
        assignments.append(f"{_UPDATABLE_COLUMNS[argument]} = %s")
        params.append(value)

    if category_fid is not None:
        assignments.append("family = COALESCE(%s, family)")
        params.append(category_fid)

    if clear_powerpack:
        assignments.append("ppguid = NULL")
    elif powerpack_guid is not None:
        assignments.append("ppguid = %s")
        params.append(powerpack_guid)

    if not assignments:
        raise ValueError("update_device_class requires at least one change")

    assignments.append("date_edit = NOW()")
    # S608 suppressed on the next line only. Every element of ``assignments`` was built from the
    # ``_UPDATABLE_COLUMNS`` allowlist, and an argument outside it raised above. Every value is a
    # placeholder.
    return Statement(
        f"UPDATE master.definitions_dev_classes SET {', '.join(assignments)} "  # noqa: S608
        "WHERE devtype_guid = %s",
        (*params, class_guid),
    )


# =================================================================================================
# The alignment pair -- ``device_classes.py::_align_da_to_class`` and
# ``device_classes.py::sl1_get_device_class_alignment``
# =================================================================================================


def resolve_class_type_by_guid(class_guid: str) -> Statement:
    """Resolve a device-class GUID to its numeric ``class_type``.

    Running this as its own statement is what turns the alignment no-op into a refusal (see the
    module docstring): an empty result means the class does not exist, and the caller refuses
    instead of issuing an ``UPDATE`` that assigns a column to itself.
    """
    return Statement(
        "SELECT class_type FROM master.definitions_dev_classes WHERE devtype_guid = %s",
        (class_guid,),
    )


def align_dynamic_app(
    *, class_type: int, dynamic_app_id: int | None, name: str | None
) -> Statement:
    """Point a Dynamic Application at a device class, or unalign it with ``class_type = 0``.

    ``class_type`` is resolved and checked before this is built, so it is a plain parameter; the
    reference's ``COALESCE`` guard would silently reintroduce the no-op. The ``WHERE`` column is
    ``aid`` for a numeric id and ``name`` for a name.

    :raises ValueError: Unless exactly one of ``dynamic_app_id`` and ``name`` is given.
    """
    if (dynamic_app_id is None) == (name is None):
        raise ValueError("align_dynamic_app needs exactly one of dynamic_app_id or name")
    if dynamic_app_id is not None:
        return Statement(
            "UPDATE master.dynamic_app SET class_type = %s WHERE aid = %s",
            (class_type, dynamic_app_id),
        )
    return Statement(
        "UPDATE master.dynamic_app SET class_type = %s WHERE name = %s",
        (class_type, name),
    )


def read_dynamic_app_alignment(*, dynamic_app_id: int | None, name: str | None) -> Statement:
    """Read back a Dynamic Application's alignment.

    The ``WHERE`` clause must match ``align_dynamic_app``'s exactly: a read-back that matched
    different rows than the write would report someone else's alignment as this call's result.

    :raises ValueError: Unless exactly one of ``dynamic_app_id`` and ``name`` is given.
    """
    if (dynamic_app_id is None) == (name is None):
        raise ValueError("read_dynamic_app_alignment needs exactly one of dynamic_app_id or name")
    projection = (
        "SELECT da.aid, da.name, da.class_type, "
        "(SELECT CONCAT(class, ' | ', descript) FROM master.definitions_dev_classes "
        "WHERE class_type = da.class_type LIMIT 1) AS aligned_class "
        "FROM master.dynamic_app da WHERE "
    )
    if dynamic_app_id is not None:
        return Statement(f"{projection}da.aid = %s", (dynamic_app_id,))
    return Statement(f"{projection}da.name = %s", (name,))


def read_class_alignment(class_type: int) -> Statement:
    """Read the device class a ``class_type`` denotes."""
    return Statement(
        "SELECT CONCAT(class, ' | ', descript) AS device_class "
        "FROM master.definitions_dev_classes WHERE class_type = %s LIMIT 1",
        (class_type,),
    )


def read_aligned_dynamic_apps(class_type: int) -> Statement:
    """Read every Dynamic Application aligned to a class.

    The reference's ``AND @ct IS NOT NULL`` is dropped. It made the query return nothing for an
    unresolved GUID, which the caller now refuses before this runs; as ``AND %s IS NOT NULL`` it
    would test a value chosen by the code and read as a check that is not one.
    """
    return Statement(
        "SELECT aid, name FROM master.dynamic_app WHERE class_type = %s ORDER BY name",
        (class_type,),
    )


# -------------------------------------------------------------------------------------------------
# The database-only device-collection route.
#
# These statements were derived from measurement on a test appliance and from SL1's own two
# producers:
#
#   * ``/opt/em7/gui/ap/exec/device_tools_run.inc``, the UI lightning-bolt handler this route
#     recreates;
#   * ``sl_device/toolbox/admin_toolbox.py::run_command_on_module``, the Python equivalent, whose
#     shape these follow because it binds the AES key as a parameter.
#
# No caller-supplied string reaches any statement here. Every parameter is an ``int`` resolved by
# the service: the device through REST, the collector from ``V_device``, the actor from nginx. The
# payload is ``shlex.split`` into an argv list on the collector, so there is no shell either.
# -------------------------------------------------------------------------------------------------

# ``$tool_id`` for a Dynamic Application collection: SL1's Snippet Framework Detailed Collection.
# ``device_tools_run.inc`` branches on it to build the ``sf_app_detailed_collect.py`` command. On
# the installed platform the branches are 0-18, 20, 21 and 22 (there is no 19); 21 and 22 are
# deliberately not used. Jobs dispatched with the older tool id 13 are unreadable by this service;
# see ``read_collection_job``.
COLLECTION_TOOLBOX_ID: Final[int] = 20

# ``master_logs.spool_process.proc`` for the Remote Toolbox, hard-coded by
# ``master.process_admin_remote_policy`` (``CALL master.process_async(125, ...)``). Paired with
# ``COLLECTION_TOOLBOX_ID`` it distinguishes this service's jobs from every other appliance process
# that spools through the same table.
REMOTE_TOOLBOX_PROCESS_ID: Final[int] = 125

# ``master_logs.proc_remote_logs.msg_type`` values. 2 and 4 are ``MSG_TYPE_OUT``/``MSG_TYPE_ERR``
# in ``admin_toolbox.py``; 1 and 3 were measured: the collector writes "Process Started on
# Collector" and "Process Completed on Collector".
MSG_TYPE_STARTED: Final[int] = 1
MSG_TYPE_STDOUT: Final[int] = 2
MSG_TYPE_COMPLETED: Final[int] = 3
MSG_TYPE_STDERR: Final[int] = 4

# The Remote Toolbox sentinel. Mandatory, and it must be at offset 0:
# ``admin_toolbox.py::_decode_siloproc`` uses ``rpartition("SILOPROC ")`` and requires nothing
# before it, so any other payload raises ``ValueError("Unauthorized Process for Toolbox")``. The job
# then lands at ``state=4, returncode=99`` with the command echoed back into the log table.
_SILOPROC_SENTINEL: Final[str] = "SILOPROC "

# The collector-side collection entry point; ``$AUTH_backenddir`` resolves to ``/opt/em7/backend``.
# Its argument parser differs from the older ``dynamic_single.py``: here ``-p`` introduces a
# ``<did> <app_id>`` pair (there it meant profiler), and a positional ``<did> <app_id>`` is not
# accepted.
_SF_APP_DETAILED_COLLECT: Final[str] = "/opt/em7/backend/sf_app_detailed_collect.py"

# Not a secret. A fixed, platform-wide obfuscation constant, identical in ``device_tools_run.inc``
# and ``admin_toolbox.py``, that the Remote Toolbox uses to decrypt ``xmessage``, so it is not ours
# to choose or rotate. It is bound as a parameter, never interpolated, so it stays out of statement
# text, log records and ``repr``.
_XMESSAGE_KEY: Final[str] = "SILO1138"


def resolve_device_collector(*, device_id: int) -> Statement:
    """Read which appliance collects for a device, from ``collector_state.V_device``.

    The caller must check the result is ``> 0``, not merely present. ``master.process_async``
    branches on ``module_id``: ``NULL`` spools the command to every appliance and ``0`` to every
    All-In-One and collector. Only ``> 0`` targets one, so a missing row must refuse rather than
    default.
    """
    return Statement(
        "SELECT pid FROM collector_state.V_device WHERE did = %s LIMIT 1",
        (device_id,),
    )


def dispatch_dynamic_collection(
    *, device_id: int, dynamic_app_id: int, module_id: int
) -> Statement:
    """Queue a debug collection of one Dynamic Application on one device.

    Rebuilt from the ``$tool_id == 20`` branch of ``device_tools_run.inc``::

        $command = "env SILO_DEBUG=1 SF_DEBUG=1 "
                 . "$AUTH_backenddir/sf_app_detailed_collect.py "
                 . "--allow-non-sf-app-type --web-ui-format";
        // getSnippetFrameworkJobPairs returns " -p $did $app_id" for the single-pair case
        $command .= getSnippetFrameworkJobPairs($sf_job_list, $did, $policy_id);
        $command = "SILOPROC ".$command;
        CALL master.process_admin_remote_policy(
            AES_ENCRYPT('$command', 'SILO1138'), $pid, $tool_id, $policy_id
        )

    Argument choices, each measured:

    - ``--allow-non-sf-app-type`` is required. Without it the job scheduler silently drops classic
      non-Snippet-Framework apps and the run reports "No jobs scheduled", which looks like an empty
      collection.
    - ``--standard-format`` deliberately differs from the UI's ``--web-ui-format``, which renders
      JSON ``null`` as the string ``"None"``.
    - No ``-d``: this script filters it out, and debug comes from ``SILO_DEBUG``/``SF_DEBUG``.
    - Neither ``-c`` nor ``--disable-cache`` is exposed, following the platform default, so the
      collection is cache-enabled even though it is an on-demand debug run.

    The procedure returns nothing (its body is an ``INSERT`` into ``master_logs.spool_process``)
    and ``lastrowid`` reads 0 after the ``CALL``, so this must be paired with ``last_insert_id``
    in one ``run_unit``. ``fetchall()`` on the ``CALL`` returns an empty tuple rather than raising.
    """
    command = (
        f"{_SILOPROC_SENTINEL}env SILO_DEBUG=1 SF_DEBUG=1 {_SF_APP_DETAILED_COLLECT}"
        f" --allow-non-sf-app-type --standard-format -p {device_id} {dynamic_app_id}"
    )
    return Statement(
        "CALL master.process_admin_remote_policy(AES_ENCRYPT(%s, %s), %s, %s, %s)",
        (command, _XMESSAGE_KEY, module_id, COLLECTION_TOOLBOX_ID, dynamic_app_id),
    )


def last_insert_id() -> Statement:
    """Build ``SELECT LAST_INSERT_ID()``, the only way to learn the ``proc_id``.

    Connection-scoped, so this is meaningful only as the second statement of a ``run_unit``: a
    second ``local_db()`` handle returns 0. SL1's UI handler does the same. It is a function call,
    not a session variable, so it does not reintroduce the ``SET @var`` coupling.
    """
    return Statement("SELECT LAST_INSERT_ID()")


def record_device_tool_run(
    *, device_id: int, module_id: int, proc_id: int, user_id: int
) -> Statement:
    """Record the run in ``master_logs.device_tools``, correlating ``proc_id`` to its device.

    Without this row the target device is recoverable only by decrypting
    ``spool_process.X_message``, and the run is missing from SL1's Device Tools log viewer, whose
    button this route recreates.

    Every column is given explicitly. ``user_edit`` is ``NOT NULL DEFAULT 1``, so omitting it
    silently attributes the run to uid 1, ``em7admin``, a real account; ``pid`` defaults to 1 too
    (the Database node). A caller without a verified ``user_id`` must skip this statement entirely.
    """
    return Statement(
        "INSERT INTO master_logs.device_tools "
        "(did, pid, proc_id, tool_id, date_edit, user_edit) "
        "VALUES (%s, %s, %s, %s, NOW(), %s)",
        (device_id, module_id, proc_id, COLLECTION_TOOLBOX_ID, user_id),
    )


def read_collection_job_owner(*, proc_id: int) -> Statement:
    """Read which account started ``proc_id``, from ``master_logs.device_tools.user_edit``.

    The read half of ``record_device_tool_run``, used as the ownership check for fetching output.
    Returns no row when the run was started without a resolvable actor, since the audit row is
    skipped then, and ``mcp_app.authz_gate`` refuses on no row.

    Not scoped to ``tool_id``: the caller's scope check (``proc == 125 AND Xtype == 20``) has
    already established the job is a collection, and a second copy of that fact would have to stay
    in step.
    """
    return Statement(
        "SELECT user_edit FROM master_logs.device_tools WHERE proc_id = %s LIMIT 1",
        (proc_id,),
    )


def read_collection_output(*, proc_id: int, after_id: int) -> Statement:
    """Read one page of a collection's output from ``master_logs.proc_remote_logs``.

    ``id > %s`` makes polling incremental, and the composite ``proc_id(proc_id, id)`` index makes a
    resumed fetch a range scan. ``ORDER BY id`` is the true interleaving of stdout and stderr, which
    arrive interleaved in the same id range; reading the streams separately loses the order in
    which the collector emitted them.
    """
    return Statement(
        "SELECT id, msg_type, msg FROM master_logs.proc_remote_logs "
        "WHERE proc_id = %s AND id > %s ORDER BY id",
        (proc_id, after_id),
    )


def read_collection_job(*, proc_id: int) -> Statement:
    """Read the spool row behind a ``proc_id`` from ``master_logs.spool_process``.

    ``state`` and ``returncode`` do not say whether the collection succeeded: a good run and a run
    against a non-existent device both end ``state=0, returncode=0``. Only a payload the Remote
    Toolbox refused yields ``state=4, returncode=99``. This row answers only whether the request
    reached the toolbox intact.

    ``proc`` and ``Xtype`` are selected for security, not reporting. ``spool_process`` holds a row
    for every appliance process, and ``proc_remote_logs`` holds the output of every Remote Toolbox
    job, including the other ``tool_id`` values. Tool 10 (snmpwalk) builds its command from
    decrypted credentials, so a rejected snmpwalk payload echoes SNMP community strings and v3
    passwords into ``proc_remote_logs``. The caller must check ``proc == REMOTE_TOOLBOX_PROCESS_ID``
    and ``Xtype == COLLECTION_TOOLBOX_ID`` before returning any output.

    Jobs from the older tool id 13, from an earlier build or the SL1 UI's own button, fail that
    check and are refused. They age out with ``proc_remote_logs`` pruning (31 days), and
    ``sl1_fetch_collection_output``'s refusal message says why.
    """
    return Statement(
        "SELECT state, returncode, proc, Xtype FROM master_logs.spool_process "
        "WHERE id = %s LIMIT 1",
        (proc_id,),
    )
