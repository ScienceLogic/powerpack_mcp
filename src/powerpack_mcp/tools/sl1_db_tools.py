"""
SL1 Database Tools

This module provides the SQL tools that reach the appliance database: event simulation, the
component tree, device-class create, update and alignment, and running and reading a Dynamic
Application collection. No tool here contains SQL; every statement comes from
``sl1_db_statements``. No tool takes per-call SL1 credentials.

Tool docstrings are written out in full rather than composed, because an f-string is not a
docstring: it leaves ``__doc__`` as ``None`` and strips the tool description from the schema.

Autocommit is on, so each statement commits as it completes and there is no rollback. A tool that
fails part-way through a ``run_unit`` sequence has already applied the statements before the
failure. So the statement whose failure is cheapest goes first in every unit, and no tool reports
"nothing happened" on failure.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import TYPE_CHECKING, Any, Final

from powerpack_mcp.errors import (
    DbDeadlineExceeded,
    DbError,
    DbQueryTimeout,
    DbUnreachable,
    PowerPackMcpError,
)
from powerpack_mcp.tools import sl1_db_descriptors as d
from powerpack_mcp.tools import sl1_db_statements as q
from powerpack_mcp.tools.sf_collection_output import summarise_collection
from powerpack_mcp.tools.sl1_db_pipeline import (
    SEVERITY_IN,
    SEVERITY_OUT,
    SOURCE_IN,
    SOURCE_OUT,
    actor_user_id,
    as_int,
    coded,
    master_write_audit,
    one_value,
    refuse,
    resolve_device,
)
from powerpack_mcp.tools.sl1_pipeline import sl1_tool_boundary

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from sl_mysql.silo_cursor import Row

    from powerpack_mcp.db_client import DbClient
    from powerpack_mcp.tools.sl1_db_pipeline import Sl1DbToolContext

    type DbToolFactory = Callable[..., Awaitable[object]]

__all__ = [
    "make_sl1_align_dynamic_app_to_device_class",
    "make_sl1_create_device_class",
    "make_sl1_get_component_tree",
    "make_sl1_get_device_class_alignment",
    "make_sl1_simulate_event",
    "make_sl1_update_device_class",
]


async def _powerpack_guid(
    context: Sl1DbToolContext, powerpack: str | None
) -> tuple[str | None, bool]:
    """Resolve ``powerpack`` to ``(guid, clear)``.

    The shape decision (``NULL`` or a bound GUID) is made here because a placeholder cannot stand
    where a SQL fragment goes. ``clear`` is ``True`` for the explicit "unown this class" spellings.
    A name that does not resolve is refused, rather than silently unowning the class.

    :param powerpack: A PowerPack GUID or name, ``"0"``/``"null"``/``"none"`` to unown, or ``None``
        to leave ownership alone.
    :return: ``(guid, clear)``.
    :raises ValidationBlocked: If a name does not resolve.
    """
    if powerpack is None:
        return None, False
    text = powerpack.strip()
    if text.lower() in ("", "0", "null", "none"):
        return None, True
    if q.looks_like_class_guid(text):
        return text, False
    rows = await context.require_db().fetch_all(q.resolve_powerpack_guid_by_name(text))
    guid = one_value(rows)
    if guid is None:
        raise refuse("ppguid", f"No PowerPack named {powerpack!r} exists.")
    return str(guid), False


async def _class_type_for(context: Sl1DbToolContext, device_class: str) -> int:
    """Resolve a device-class GUID or numeric ``class_type`` to an int.

    An unknown GUID is refused. The reference implementation fed this lookup into
    ``COALESCE(@ct, class_type)``, so an unknown class became a silent no-op reported as success.

    :raises ValidationBlocked: If the class does not exist or the value is neither form.
    """
    text = device_class.strip()
    if q.looks_like_class_guid(text):
        rows = await context.require_db().fetch_all(q.resolve_class_type_by_guid(text))
        resolved = one_value(rows)
        if resolved is None:
            raise refuse("device_class", f"No device class with GUID {device_class!r} exists.")
        return as_int(resolved, argument="device_class")
    # ``isdecimal()``, not ``isdigit()``; see ``sl1_db_pipeline.coded()``.
    if text.isdecimal():
        return int(text)
    raise refuse(
        "device_class",
        f"device_class must be a 32-character class GUID or a numeric class_type; got "
        f"{device_class!r}.",
    )


def _rows_as_dicts(rows: tuple[Row, ...], columns: tuple[str, ...]) -> list[dict[str, object]]:
    """Name the columns of a positional result set.

    Typed with ``Row`` (``tuple[object, ...]``) rather than ``Any``, so the narrowing the
    ``typings/`` stubs provide is not undone at the consumer. A structured result also removes a
    failure mode of the reference implementation, which tested success by whether a GUID appeared
    in the text output, as it also would inside an error message.
    """
    return [dict(zip(columns, row, strict=False)) for row in rows]


def _device_class_changes(
    *,
    class_name: str | None,
    description: str | None,
    device_type: str | None,
    is_snmp: bool | None,
    root_device: bool | None,
    class_identifier_1: str | None,
    class_identifier_2: str | None,
) -> dict[str, object]:
    """Collect only the arguments the caller actually supplied, for ``update_device_class``.

    A pure function so the update tool's branching can be tested directly, and so it is easy to see
    that every key is an ``_UPDATABLE_COLUMNS`` key. ``None`` means "leave this field alone", so
    every branch tests ``is not None`` rather than truthiness: ``is_snmp=False`` and
    ``class_name=""`` are real values a caller may want to set.

    :raises ValidationBlocked: If ``device_type`` is not a known type.
    """
    changes: dict[str, object] = {}
    if class_name is not None:
        changes["class_name"] = class_name
    if description is not None:
        changes["description"] = description
    if device_type is not None:
        normalised = device_type.strip().lower()
        if normalised not in q.DEVICE_CLASS_TYPES:
            raise refuse(
                "device_type",
                f"device_type must be one of: {', '.join(sorted(q.DEVICE_CLASS_TYPES))}.",
            )
        changes["device_type"] = q.DEVICE_CLASS_TYPES[normalised]
    if is_snmp is not None:
        changes["is_snmp"] = int(is_snmp)
    if root_device is not None:
        changes["root_device"] = int(root_device)
    if class_identifier_1 is not None:
        changes["class_identifier_1"] = class_identifier_1
    if class_identifier_2 is not None:
        changes["class_identifier_2"] = class_identifier_2
    return changes


def _category_fid(category: str | None) -> int | None:
    """Return a numeric device-category id, or ``None`` to leave the category alone.

    Only a numeric category is accepted on update. Resolving a name in Python would force a choice
    between refusing an unresolvable name, which removes the documented no-op-on-bad-category
    safety of ``update_device_class``, and a second statement that cannot be rolled back. Refusing
    the name form tells the caller what to pass instead.

    :raises ValidationBlocked: If ``category`` is not numeric.
    """
    if category is None:
        return None
    text = category.strip()
    # ``isdecimal()``, not ``isdigit()``: with ``isdigit()`` a value like "²" passed this guard and
    # then crashed in ``int()`` below.
    if not text.isdecimal():
        raise refuse(
            "category",
            "category must be a numeric device-category id when updating. Create the class with a "
            "category name instead, or look the id up first.",
        )
    return int(text)


_DEVICE_CLASS_COLUMNS = (
    "id",
    "devtype_guid",
    "class",
    "description",
    "class_type",
    "virtual",
    "family",
    "ppguid",
    "class_identifier_1",
    "class_identifier_2",
    "category",
)


def make_sl1_simulate_event(context: Sl1DbToolContext) -> DbToolFactory:
    """Build the ``sl1_simulate_event`` tool bound to ``context``.

    :param context: The SL1 platform tool context.
    :return: The tool function, ready for ``server.tool``.
    """

    @sl1_tool_boundary(d.SIMULATE_EVENT)
    @master_write_audit(d.SIMULATE_EVENT)
    async def sl1_simulate_event(
        device: str,
        message: str,
        severity: str = "major",
        source: str = "api",
        event_policy: int | None = None,
        sub_message: str = "",
        threshold: str = "",
    ) -> dict[str, Any]:
        """Insert a synthetic, device-aligned ACTIVE event straight into the events table.

        The event appears in the console and in REST reads immediately, with no matching policy
        required. It is a raw row insert, so nothing in SL1's event engine runs: no regex or
        formula matching, no deduplication, no masking, no topology correlation and no auto-clear.
        Verified live: injecting under a policy whose auto_clear_events should have
        closed another active event left that event untouched, because the correlation step never
        runs for a row inserted this way.

        Use this when you need an event row to exist unconditionally. To exercise the engine's real
        behaviour instead, use sl1_inject_alert, which queues into the engine's own input queue.
        Reversible with sl1_clear_event.

        Args:
            device: Device id, or a name to resolve through REST.
            message: Event message text.
            severity: healthy, notice, minor, major or critical, or the code 0-4.
            source: syslog, internal, trap, dynamic, api, email or agent, or its numeric code.
            event_policy: Optional numeric event-policy id to attribute the event to.
            sub_message: Optional secondary message text.
            threshold: Optional threshold text.

        This tool writes to the database and the write cannot be undone by this service.
        """
        severity_code = coded(severity, SEVERITY_IN, argument="severity")
        source_code = coded(source, SOURCE_IN, argument="source")
        policy = 0 if event_policy is None else int(event_policy)
        if policy < 0:
            raise refuse("event_policy", "event_policy must be a non-negative policy id.")

        device_id, device_name = await resolve_device(context, device)
        # ``run_unit`` for one statement, because ``fetch_all`` cannot return ``lastrowid``. That is
        # also why there is no second ``SELECT LAST_INSERT_ID()`` in a sequence with no rollback.
        (result,) = await context.require_db().run_unit(
            q.insert_active_event(
                device_id=device_id,
                device_name=device_name,
                source=source_code,
                message=message,
                sub_message=sub_message,
                threshold=threshold,
                severity=severity_code,
                event_policy=policy,
            )
        )
        return {
            "event_id": result.lastrowid,
            "device_id": device_id,
            "device_name": device_name,
            "severity": SEVERITY_OUT.get(severity_code, severity_code),
            "source": SOURCE_OUT.get(source_code, source_code),
            "event_policy": policy,
            "message": message,
            # In the payload as well as the docstring, because the model reads the result, not the
            # tool definition, when it decides what the call proved.
            "note": (
                "Fabricated by raw row insert. No policy matching, correlation or auto-clear ran. "
                "Clear it with sl1_clear_event."
            ),
        }

    return sl1_simulate_event


async def _resolve_root_did(db: DbClient, root: str) -> int:
    """Resolve the component-tree ``root`` argument to a device id.

    :param db: The database client.
    :param root: A numeric device id or an exact device name.
    :return: The root device id.
    :raises ValidationBlocked: If no device has that name.
    """
    text = root.strip()
    # ``isdecimal()``, not ``isdigit()``; see ``coded()``.
    if text.isdecimal():
        return int(text)
    # Resolved in Python, so there is no ``SET @root`` session-state dependency.
    resolved = one_value(await db.fetch_all(q.resolve_root_did_by_name(text)))
    if resolved is None:
        raise refuse("root", f"No device named {root!r} exists.")
    return as_int(resolved, argument="root")


async def _read_root_summary(db: DbClient, root: str, root_did: int) -> tuple[object, object]:
    """Read the root device's ``(name, device_class)``.

    :param db: The database client.
    :param root: The caller's ``root`` argument, for the refusal message.
    :param root_did: The resolved root device id.
    :return: ``(name, device_class)``; the class is ``None`` when the row does not carry one.
    :raises ValidationBlocked: If the device no longer exists.
    """
    summary = await db.fetch_all(q.read_root_summary(root_did))
    root_name = summary[0][0] if summary and summary[0] else None
    root_class = summary[0][1] if summary and len(summary[0]) > 1 else None
    if root_name is None:
        raise refuse(
            "root",
            f"Root device {root!r} resolved to id {root_did}, which no longer exists.",
        )
    return root_name, root_class


def _tally_components(
    components: list[dict[str, object]],
) -> tuple[dict[str, int], dict[str, int], set[str]]:
    """Count components by state and by class, and collect the discovering Dynamic Applications.

    :param components: The component rows, as ``_rows_as_dicts`` returns them.
    :return: ``(by_state, by_class, discovering)``.
    """
    by_state: dict[str, int] = {}
    by_class: dict[str, int] = {}
    discovering: set[str] = set()
    for component in components:
        state = str(component.get("state"))
        by_state[state] = by_state.get(state, 0) + 1
        device_class = str(component.get("device_class"))
        by_class[device_class] = by_class.get(device_class, 0) + 1
        aid = component.get("aid")
        if aid is not None:
            discovering.add(str(aid))
    return by_state, by_class, discovering


def make_sl1_get_component_tree(context: Sl1DbToolContext) -> DbToolFactory:
    """Build the ``sl1_get_component_tree`` tool bound to ``context``.

    :param context: The SL1 platform tool context.
    :return: The tool function, ready for ``server.tool``.
    """

    @sl1_tool_boundary(d.GET_COMPONENT_TREE)
    async def sl1_get_component_tree(root: str, max_nodes: int = 2000) -> dict[str, Any]:
        """Walk the DCM component tree beneath a root device (read-only).

        Reports the root, totals by state, the Dynamic Applications doing the discovering, the
        maximum depth, counts by device class, and every component with its parent so the caller can
        reconstruct the tree. Components whose parent is not itself in the subtree are reported
        separately rather than dropped.

        Args:
            root: Root device id, or a device name to resolve through REST.
            max_nodes: Cap on components returned. A large root can have thousands; the total is
                always reported, so a truncated answer is distinguishable from a complete one.

        This tool only reads.
        """
        if max_nodes < 1:
            raise refuse("max_nodes", "max_nodes must be at least 1.")
        db = context.require_db()

        root_did = await _resolve_root_did(db, root)
        root_name, root_class = await _read_root_summary(db, root, root_did)

        rows = await db.fetch_all(q.read_component_map(root_did))
        components = _rows_as_dicts(
            rows,
            ("did", "parent_did", "name", "device_class", "state", "unique_id", "aid", "last_seen"),
        )
        by_state, by_class, discovering = _tally_components(components)

        return {
            "root": {"did": root_did, "name": root_name, "device_class": root_class},
            "total_components": len(components),
            "by_state": by_state,
            "counts_by_class": dict(sorted(by_class.items(), key=lambda kv: (-kv[1], kv[0]))),
            "discovering_dynamic_apps": sorted(discovering),
            "truncated": len(components) > max_nodes,
            "components": components[:max_nodes],
        }

    return sl1_get_component_tree


def make_sl1_create_device_class(context: Sl1DbToolContext) -> DbToolFactory:
    """Build the ``sl1_create_device_class`` tool bound to ``context``.

    :param context: The SL1 platform tool context.
    :return: The tool function, ready for ``server.tool``.
    """

    @sl1_tool_boundary(d.CREATE_DEVICE_CLASS)
    @master_write_audit(d.CREATE_DEVICE_CLASS)
    async def sl1_create_device_class(
        class_name: str,
        description: str,
        category: str = "Unknown",
        device_type: str = "physical",
        is_snmp: bool = False,
        root_device: bool = False,
        ppguid: str | None = None,
        class_identifier_1: str | None = None,
        class_identifier_2: str | None = None,
    ) -> dict[str, Any]:
        """Create an SL1 device class by direct database insert. There is no create API for these.

        Two conditions must hold for a hand-made class to render in the AP2 interface, and both are
        built in: the row must resolve a real device category, and it must carry a non-null family
        GUID. The insert selects from the category table, so if the category does not resolve
        nothing is inserted rather than a broken class being created.

        Args:
            class_name: Class name, the first half of what AP2 displays.
            description: Class description, the second half.
            category: Device category name or numeric id. Required for AP2 to render the class.
            device_type: physical, virtual or component.
            is_snmp: Mark the class as SNMP-capable.
            root_device: Mark the class as a root device.
            ppguid: Assign to a PowerPack by GUID or name; pass "0" or "null" for unowned.
            class_identifier_1: Component class-match identifier 1.
            class_identifier_2: Component class-match identifier 2.

        This tool writes to the database and the write cannot be undone by this service.
        """
        if device_type.strip().lower() not in q.DEVICE_CLASS_TYPES:
            raise refuse(
                "device_type",
                f"device_type must be one of: {', '.join(sorted(q.DEVICE_CLASS_TYPES))}.",
            )
        db = context.require_db()
        powerpack_guid, _clear = await _powerpack_guid(context, ppguid)

        class_guid = uuid.uuid4().hex.upper()
        family_guid = uuid.uuid4().hex.upper()
        results = await db.run_unit(
            q.insert_device_class(
                class_guid=class_guid,
                family_guid=family_guid,
                class_name=class_name,
                description=description,
                category=category,
                device_type=device_type.strip().lower(),
                is_snmp=is_snmp,
                root_device=root_device,
                powerpack_guid=powerpack_guid,
                class_identifier_1=class_identifier_1 or "",
                class_identifier_2=class_identifier_2 or "",
            ),
            q.read_device_class_by_guid(class_guid),
        )
        created = _rows_as_dicts(results[1].rows, _DEVICE_CLASS_COLUMNS)
        if not created:
            # Row count, not whether the GUID appears in the output: a GUID can appear in an error
            # message, and an empty read-back cannot be mistaken for success.
            raise refuse(
                "category",
                f"Device class was NOT created: category {category!r} did not resolve to a real "
                f"device category, so the insert selected no row.",
            )
        return {"created": created[0], "rows_inserted": results[0].rowcount}

    return sl1_create_device_class


def make_sl1_update_device_class(context: Sl1DbToolContext) -> DbToolFactory:
    """Build the ``sl1_update_device_class`` tool bound to ``context``.

    :param context: The SL1 platform tool context.
    :return: The tool function, ready for ``server.tool``.
    """

    @sl1_tool_boundary(d.UPDATE_DEVICE_CLASS)
    @master_write_audit(d.UPDATE_DEVICE_CLASS)
    async def sl1_update_device_class(
        device_class_guid: str,
        class_name: str | None = None,
        description: str | None = None,
        category: str | None = None,
        device_type: str | None = None,
        is_snmp: bool | None = None,
        root_device: bool | None = None,
        ppguid: str | None = None,
        class_identifier_1: str | None = None,
        class_identifier_2: str | None = None,
    ) -> dict[str, Any]:
        """Update fields on an existing device class, keyed by its GUID.

        Only the arguments you actually pass are changed; anything left unset is untouched. A
        category that does not resolve leaves the existing category in place rather than clearing
        it, because clearing it would stop the class rendering in AP2.

        Args:
            device_class_guid: GUID of the class to update.
            class_name: New class name.
            description: New description.
            category: New device category name or numeric id.
            device_type: physical, virtual or component.
            is_snmp: Set or clear the SNMP flag.
            root_device: Set or clear the root-device flag.
            ppguid: Reassign to a PowerPack by GUID or name; "0" or "null" clears ownership.
            class_identifier_1: Component class-match identifier 1.
            class_identifier_2: Component class-match identifier 2.

        This tool writes to the database and the write cannot be undone by this service.
        """
        guid = device_class_guid.strip()
        if not q.looks_like_class_guid(guid):
            raise refuse(
                "device_class_guid",
                f"device_class_guid must be a 32-character hexadecimal GUID; got "
                f"{device_class_guid!r}.",
            )
        db = context.require_db()

        changes = _device_class_changes(
            class_name=class_name,
            description=description,
            device_type=device_type,
            is_snmp=is_snmp,
            root_device=root_device,
            class_identifier_1=class_identifier_1,
            class_identifier_2=class_identifier_2,
        )
        category_fid = _category_fid(category)
        powerpack_guid, clear_powerpack = await _powerpack_guid(context, ppguid)
        if not changes and category_fid is None and not clear_powerpack and powerpack_guid is None:
            raise refuse("", "Pass at least one field to change.")

        results = await db.run_unit(
            q.update_device_class(
                class_guid=guid,
                changes=changes,
                category_fid=category_fid,
                clear_powerpack=clear_powerpack,
                powerpack_guid=powerpack_guid,
            ),
            q.read_device_class_by_guid(guid),
        )
        updated = _rows_as_dicts(results[1].rows, _DEVICE_CLASS_COLUMNS)
        if not updated:
            raise refuse(
                "device_class_guid", f"No device class with GUID {device_class_guid!r} exists."
            )
        return {"updated": updated[0], "rows_changed": results[0].rowcount}

    return sl1_update_device_class


def make_sl1_align_dynamic_app_to_device_class(context: Sl1DbToolContext) -> DbToolFactory:
    """Build the ``sl1_align_dynamic_app_to_device_class`` tool bound to ``context``.

    :param context: The SL1 platform tool context.
    :return: The tool function, ready for ``server.tool``.
    """

    @sl1_tool_boundary(d.ALIGN_DYNAMIC_APP_TO_DEVICE_CLASS)
    @master_write_audit(d.ALIGN_DYNAMIC_APP_TO_DEVICE_CLASS)
    async def sl1_align_dynamic_app_to_device_class(
        dynamic_app: str, device_class: str
    ) -> dict[str, Any]:
        """Align a Dynamic Application to a component device class, or unalign it.

        Args:
            dynamic_app: Dynamic Application id, or its exact name.
            device_class: Device class GUID or numeric class_type. Pass "0" to unalign.

        Unlike the reference implementation this refuses a device class that does not exist, rather
        than reporting success having changed nothing.

        This tool writes to the database and the write cannot be undone by this service.
        """
        app = dynamic_app.strip()
        if not app:
            raise refuse("dynamic_app", "dynamic_app must not be empty.")
        # ``isdecimal()``, not ``isdigit()``; see ``coded()``.
        app_id = int(app) if app.isdecimal() else None
        app_name = None if app.isdecimal() else app

        db = context.require_db()
        target = device_class.strip()
        class_type = 0 if target in ("0", "") else await _class_type_for(context, target)

        results = await db.run_unit(
            q.align_dynamic_app(class_type=class_type, dynamic_app_id=app_id, name=app_name),
            q.read_dynamic_app_alignment(dynamic_app_id=app_id, name=app_name),
        )
        aligned = _rows_as_dicts(
            results[1].rows, ("aid", "name", "class_type", "aligned_device_class")
        )
        if not aligned:
            raise refuse("dynamic_app", f"No Dynamic Application matching {dynamic_app!r} exists.")
        return {
            "aligned": aligned[0],
            "rows_changed": results[0].rowcount,
            "unaligned": class_type == 0,
        }

    return sl1_align_dynamic_app_to_device_class


def make_sl1_get_device_class_alignment(context: Sl1DbToolContext) -> DbToolFactory:
    """Build the ``sl1_get_device_class_alignment`` tool bound to ``context``.

    :param context: The SL1 platform tool context.
    :return: The tool function, ready for ``server.tool``.
    """

    @sl1_tool_boundary(d.GET_DEVICE_CLASS_ALIGNMENT)
    async def sl1_get_device_class_alignment(device_class: str) -> dict[str, Any]:
        """Show which Dynamic Applications are aligned to a component device class (read-only).

        Args:
            device_class: Device class GUID or numeric class_type.

        This tool only reads.
        """
        db = context.require_db()
        class_type = await _class_type_for(context, device_class)
        name = one_value(await db.fetch_all(q.read_class_alignment(class_type)))
        rows = await db.fetch_all(q.read_aligned_dynamic_apps(class_type))
        return {
            "class_type": class_type,
            "device_class": name,
            "aligned_dynamic_apps": _rows_as_dicts(rows, ("aid", "name")),
        }

    return sl1_get_device_class_alignment


# -------------------------------------------------------------------------------------------------
# The database-only device-collection route.
# -------------------------------------------------------------------------------------------------

# How long to leave between polls of ``proc_remote_logs``. The collector flushes in batches of ten
# (``THROTTLE_LINES`` in ``admin_toolbox.py``), and a 412-row run arrived in a single batch at
# 6.0 s, so sub-second polling would add load for nothing.
_POLL_INTERVAL_SECONDS: Final[float] = 1.0

# Head-room left on the request deadline. ``db_client`` clamps every statement to what the deadline
# has left, and a ``0.0`` remainder becomes ``max_statement_time = 0.001`` (errno 1969, a
# ``DbQueryTimeout``), so polling to the very end would turn "still running" into a spurious
# timeout on the last read.
_DEADLINE_MARGIN_SECONDS: Final[float] = 3.0

# Ceiling when no inbound deadline is in force, e.g. a unit test or a non-POST path, where
# ``remaining_deadline_seconds()`` returns ``None``.
_MAX_WAIT_WITHOUT_DEADLINE_SECONDS: Final[float] = 20.0

# Zero: dispatch and return a receipt. Three back-to-back runs on a Central Database took 12-27 s
# from dispatch to termination, of which only 1-10 s was the collection; the rest is queue pickup
# and poll granularity, and the totals grew as the jobs queued. The longest run spent the whole
# deadline and still returned ``terminated: false``. Waiting is nearly always futile, and a short
# non-zero default is the worst option: it pays for a wait and still hands back a receipt.
#
# So ``sl1_fetch_collection_output`` is the normal second call, and ``_collection_receipt`` says so
# in words rather than leaving the caller to infer it from ``terminated: false``.
_DEFAULT_WAIT_SECONDS: Final[float] = 0.0

# ``msg_type`` to the stream name a caller sees. An unrecognised type keeps its number rather than
# being silently folded into a known stream.
_STREAM_NAMES: Final[dict[int, str]] = {
    q.MSG_TYPE_STARTED: "started",
    q.MSG_TYPE_STDOUT: "stdout",
    q.MSG_TYPE_COMPLETED: "completed",
    q.MSG_TYPE_STDERR: "stderr",
}


def _platform_int(value: object, *, what: str) -> int:
    """Return an integer the platform supplied, raising ``DbError`` if it is not one.

    Platform values come through here and caller input through ``as_int``, and the two produce
    different errors on purpose. ``as_int`` raises ``ValidationBlocked`` with a path, which for a
    NULL ``msg_type`` or an empty ``LAST_INSERT_ID()`` row would tell the caller to fix an argument
    the tool does not accept, and would make ``master_write_audit`` record ``outcome="refused"``
    for a ``master.*`` write that had already committed.

    :raises DbError: If ``value`` is not an ``int`` (``bool`` included).
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise DbError(f"the database returned {type(value).__name__} where {what} was expected")
    return value


def _platform_int_or_none(value: object, *, what: str) -> int | None:
    """Like ``_platform_int``, but ``NULL`` is a legitimate answer rather than corruption.

    ``spool_process.returncode`` is ``NULL`` while a job is still running, which is the state a
    caller most often polls in; treating it as an error reported a read failure when the collection
    had simply not finished. Only the informational ``state`` and ``returncode`` fields use this.
    ``process_id`` and ``toolbox_id`` stay on ``_platform_int`` because ``_is_collection_job`` is a
    security check and a missing discriminator must fail closed.
    """
    if value is None:
        return None
    return _platform_int(value, what=what)


def _decode_line(value: object) -> str:
    """``msg`` is a ``BLOB``, so decode defensively and never raise.

    ``errors="replace"`` because a collection's debug output is whatever the collected device
    emitted; a single undecodable byte must not cost the caller the whole page of output.
    """
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        text = value
    else:
        text = str(value)
    return text.rstrip("\r\n")


def _wait_budget(wait_seconds: float | None) -> float:
    """Return the seconds this call may spend polling, derived from the request deadline.

    Zero by default: dispatch and return a receipt rather than hold the call. ``wait_seconds`` opts
    in to blocking, but the ceiling is absolute, the request deadline's remainder minus
    ``_DEADLINE_MARGIN_SECONDS``, because the concurrency gate cancels the whole call when the
    deadline passes. A caller can only spend time the gate has already granted.
    """
    from powerpack_mcp.mcp_app.concurrency import remaining_deadline_seconds

    remaining = remaining_deadline_seconds()
    ceiling = (
        _MAX_WAIT_WITHOUT_DEADLINE_SECONDS
        if remaining is None
        else max(0.0, remaining - _DEADLINE_MARGIN_SECONDS)
    )
    requested = _DEFAULT_WAIT_SECONDS if wait_seconds is None else max(0.0, wait_seconds)
    return min(requested, ceiling)


async def _drain_output(
    context: Sl1DbToolContext, *, proc_id: int, after_id: int, budget: float
) -> tuple[list[dict[str, object]], int, bool, PowerPackMcpError | None]:
    """Poll one collection's output until it terminates or the budget runs out.

    The error is returned, not raised, so the caller can decide. After an irreversible dispatch a
    read failure must not cost the caller the ``proc_id`` and the lines already gathered, whereas
    ``sl1_fetch_collection_output`` has nothing to protect and re-raises it.

    Each poll is a separate ``fetch_all``: only the dispatch pair needs connection-scoped state, and
    holding a ``run_unit`` worker for the whole wait would tie up one of only ``db_worker_count``
    workers.

    Termination means the Remote Toolbox has finished, not that the collection succeeded.

    :return: ``(lines, last_id, terminated, error)``.
    """
    db = context.require_db()
    lines: list[dict[str, object]] = []
    last_id = after_id
    terminated = False
    expiry = time.monotonic() + budget

    while True:
        try:
            rows = await db.fetch_all(q.read_collection_output(proc_id=proc_id, after_id=last_id))
        except (DbDeadlineExceeded, DbError, DbQueryTimeout, DbUnreachable) as exc:
            return lines, last_id, terminated, exc
        for row in rows:
            row_id = _platform_int(row[0], what="a log row id")
            msg_type = _platform_int(row[1], what="a log row msg_type")
            last_id = max(last_id, row_id)
            if msg_type == q.MSG_TYPE_COMPLETED:
                terminated = True
            lines.append(
                {
                    "id": row_id,
                    "stream": _STREAM_NAMES.get(msg_type, f"msg_type_{msg_type}"),
                    "text": _decode_line(row[2]),
                }
            )
        remaining = expiry - time.monotonic()
        if terminated or remaining <= 0:
            return lines, last_id, terminated, None
        # Sleep only what is left, not a whole interval. A full interval would overspend the budget,
        # eat into ``_DEADLINE_MARGIN_SECONDS`` and issue one more read after expiry, reintroducing
        # the spurious timeout the margin exists to prevent.
        await asyncio.sleep(min(_POLL_INTERVAL_SECONDS, remaining))


async def _job_row(context: Sl1DbToolContext, proc_id: int) -> dict[str, int | None] | None:
    """Read the spool row: ``state``/``returncode``, and the two fields that identify it as ours.

    ``state`` and ``returncode`` do not report whether the collection worked; ``state=4`` with
    ``returncode=99`` is the Remote Toolbox refusing the payload. ``process_id`` and ``toolbox_id``
    let ``_is_collection_job`` confine reads to this service's collections.

    :return: The row as a dict, or ``None`` if there is no spool row.
    """
    rows = await context.require_db().fetch_all(q.read_collection_job(proc_id=proc_id))
    if not rows:
        return None
    return {
        # NULL while the job runs. Informational, so absent is an answer.
        "state": _platform_int_or_none(rows[0][0], what="a job state"),
        "returncode": _platform_int_or_none(rows[0][1], what="a job returncode"),
        # Identity, used by the ``_is_collection_job`` security check, so these fail closed.
        "process_id": _platform_int(rows[0][2], what="a job process id"),
        "toolbox_id": _platform_int(rows[0][3], what="a job toolbox id"),
    }


def _is_collection_job(job: dict[str, int | None]) -> bool:
    """Return whether this spool row is one of this service's Dynamic Application collections.

    A security check, not bookkeeping. ``proc_remote_logs`` is shared by every Remote Toolbox job,
    across all of ``device_tools_run.inc``'s ``tool_id`` branches. Tool 10 (snmpwalk) builds its
    command from decrypted credentials, and a rejected payload of any tool is echoed verbatim into
    that table, so without this check a caller iterating ids could harvest plaintext SNMP community
    strings and v3 passwords from jobs this service does not own.
    """
    # A ``None`` discriminator compares unequal to both constants, so a row with absent identity
    # returns False and the caller refuses: it fails closed without an explicit None check.
    return (
        job["process_id"] == q.REMOTE_TOOLBOX_PROCESS_ID
        and job["toolbox_id"] == q.COLLECTION_TOOLBOX_ID
    )


async def _assert_job_is_owned(context: Sl1DbToolContext, proc_id: int) -> None:
    """Refuse unless the calling account started this collection job.

    This complements ``_is_collection_job`` and does not replace it. The scope check answers "is
    this one of our collections"; this answers "is it yours". Without it, a caller holding
    ``DEV_TOOLS_RUN`` could read every other account's collection output by iterating
    ``proc_id``. This is deliberately stricter than SL1's own viewer, ``device_tools_log.inc``,
    which checks neither ownership nor ``tool_id``. Do not remove either check to match the
    platform.

    It runs here rather than in ``mcp_app.authz_gate`` because the middleware sees the raw JSON
    arguments, and this sees ``proc_id`` after pydantic validation. Two parses of the same argument
    could resolve differently and check ownership of one job while reading another.
    ``tests/unit/test_source_invariants.py`` asserts by AST that this call site exists.

    No owner row means refuse. ``_record_correlation`` skips the row when the actor is unknown, so
    an unattributable job is unreadable by anyone, including whoever started it.

    :raises CollectionJobNotOwned: If the caller is unknown or is not the job's owner.
    """
    from powerpack_mcp.errors import CollectionJobNotOwned

    caller = actor_user_id()
    if caller is None:
        raise CollectionJobNotOwned(proc_id)
    rows = await context.require_db().fetch_all(q.read_collection_job_owner(proc_id=proc_id))
    owner = one_value(rows)
    if owner is None or _platform_int(owner, what="a job owner") != caller:
        # The same refusal for "not yours" and "nobody's". Distinguishing them would reveal whether
        # a job exists and is attributable, which is the enumeration the scope check avoids.
        raise CollectionJobNotOwned(proc_id)


async def _record_correlation(
    context: Sl1DbToolContext, *, device_id: int, module_id: int, proc_id: int
) -> bool:
    """Write the ``master_logs.device_tools`` row, but only if the caller's identity is known.

    ``user_edit`` is ``NOT NULL DEFAULT 1``, so a row written without it attributes the run to uid
    1, ``em7admin``, a real account, and a placeholder is worse because it looks deliberate. An
    unknown actor skips the whole statement.

    A failure here must not fail the tool. The collection is already queued and cannot be
    recalled; losing this row costs a log-viewer entry, whereas failing the call would cost the
    caller the ``proc_id``. With no transaction, the partial state is reported instead of hidden.

    :return: Whether the row was written.
    """
    user_id = actor_user_id()
    if user_id is None:
        return False
    try:
        await context.require_db().run_unit(
            q.record_device_tool_run(
                device_id=device_id, module_id=module_id, proc_id=proc_id, user_id=user_id
            )
        )
    except (DbDeadlineExceeded, DbError, DbQueryTimeout, DbUnreachable):
        return False
    return True


def _toolbox_view(job: dict[str, int | None] | None) -> dict[str, int | None] | None:
    """Return only the ``state`` and ``returncode`` fields; the discriminators stay internal.

    Either may be ``None``: a running job has no ``returncode`` yet, which means "not finished",
    not an error.
    """
    if job is None:
        return None
    return {"state": job["state"], "returncode": job["returncode"]}


def _collection_receipt(
    *, terminated: bool, last_id: int, read_error: PowerPackMcpError | None
) -> str:
    """Describe in words what the caller must do next.

    The two-call pattern is the normal path, so a caller must not have to infer it from
    ``terminated: false``. A collection's own work takes seconds, but dispatch to termination takes
    tens of seconds and grows with queue depth, so dispatch almost always returns first.
    """
    if terminated:
        finished = (
            "The collector has FINISHED with this job. `terminated` does not mean the collection "
            "SUCCEEDED -- read collection.outcome for that; neither the exit code nor "
            "collection.dispatch_reported_success reports it. "
        )
    else:
        finished = (
            "THE COLLECTION IS STILL RUNNING. This is the normal reply, not a failure and not a "
            f"timeout: call sl1_fetch_collection_output with proc_id and after_id={last_id} to "
            "read the output. Expect to poll -- typical time from dispatch to termination is "
            "tens of seconds, and on a busy appliance it can be MINUTES, because most of the wait "
            "is the collector picking the job up rather than the collection itself. "
        )
    sensitive = (
        "Output is the collector's debug trace verbatim, the same text the Device Tools UI shows, "
        "so treat it as sensitive."
    )
    degraded = (
        " The collection WAS queued, but a read failed part-way, so any lines here may be "
        "incomplete -- retry with sl1_fetch_collection_output."
        if read_error is not None
        else ""
    )
    return finished + sensitive + degraded


def _output_payload(lines: list[dict[str, object]]) -> dict[str, object]:
    """Build per-stream counts beside the lines, plus the parsed outcome when one is available.

    The ``collection`` summary is additive and ``lines`` is unchanged: the raw trace is what a
    caller iterating on snippet code reads, and everything the summary reports is already present
    verbatim in ``lines``. The key is absent when there is nothing to parse, which is normal for a
    collection that has not finished writing its document, and is not a failure signal.
    """
    counts: dict[str, int] = {}
    for line in lines:
        stream = line["stream"]
        if isinstance(stream, str):
            counts[stream] = counts.get(stream, 0) + 1
    payload: dict[str, object] = {"lines": lines, "line_counts": counts}
    # Read from stdout only. The chunked document goes to stdout and the debug trace to stderr, so
    # scanning every stream would let a trace line that mentions the sentinel corrupt the document.
    stdout_texts = [
        line["text"]
        for line in lines
        if line["stream"] == "stdout" and isinstance(line["text"], str)
    ]
    summary = summarise_collection(stdout_texts)
    if summary is not None:
        payload["collection"] = summary
    return payload


async def _resolve_collector_module(
    context: Sl1DbToolContext, *, device_id: int, device_name: str
) -> int:
    """Resolve the single collector appliance that runs this device's collections.

    ``master.process_async`` reads 0 as "every collector" and NULL as "every appliance", so a
    non-positive id would broadcast the command instead of targeting one box. Hence two guards
    rather than one truthiness test. Extracted from ``sl1_run_dynamic_collection`` to keep the
    tool's inner closure under the cognitive-complexity limit.

    :return: The collector's module id.
    :raises ValidationBlocked: If no collector is recorded, or the id is not a single appliance.
    """
    db = context.require_db()
    collector = one_value(await db.fetch_all(q.resolve_device_collector(device_id=device_id)))
    if collector is None:
        raise refuse(
            "device",
            f"No collector is recorded for device {device_name!r} (did {device_id}), so there "
            f"is nothing to run the collection on.",
        )
    module_id = as_int(collector, argument="collector_id")
    if module_id <= 0:
        raise refuse(
            "device",
            f"Device {device_name!r} (did {device_id}) resolves to collector id {module_id}, "
            f"which is not a single appliance. Refusing rather than broadcasting the "
            f"collection to every collector.",
        )
    return module_id


def _queued_proc_id(id_rows: tuple[Row, ...]) -> int:
    """Return the job id of a collection that has already been dispatched.

    Do not use ``as_int`` here. ``as_int(None)`` raises ``ValidationBlocked``, which would tell the
    caller to fix an argument the tool does not accept and make ``master_write_audit`` record
    ``outcome="refused"`` for a write that has already committed. Every other validation in this
    tool refuses before a write; this one runs after it, so only a platform error is honest.

    :raises DbError: If the platform returned no usable job id.
    """
    if not id_rows:
        raise DbError("the collection was queued but the platform returned no job id row")
    proc_id = _platform_int(id_rows[0][0], what="a job id")
    if proc_id <= 0:
        raise DbError("the collection was queued but the platform reported no job id")
    return proc_id


def make_sl1_run_dynamic_collection(context: Sl1DbToolContext) -> DbToolFactory:
    """Build the ``sl1_run_dynamic_collection`` tool bound to ``context``.

    :param context: The SL1 platform tool context.
    :return: The tool function, ready for ``server.tool``.
    """

    @sl1_tool_boundary(d.RUN_DYNAMIC_COLLECTION)
    @master_write_audit(d.RUN_DYNAMIC_COLLECTION)
    async def sl1_run_dynamic_collection(
        device: str,
        app_id: int,
        wait_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Queue a debug collection of one Dynamic Application on one device, and return a receipt.

        This is the Device Tools lightning bolt: it queues the same debug collection the SL1 UI
        queues when you test a Dynamic Application, on the appliance that actually collects for the
        device, and returns the collector's interleaved stdout and stderr. It is meant for
        iterating on collection objects and snippet code, where the verbose trace is the point.

        Works on distributed stacks: the job is queued in the database and picked up by the remote
        Data Collector aligned to the device, so it does not matter which appliance collects. It is
        expected to work for any Dynamic Application type, though only Bulk Snippet Performance has
        actually been exercised.

        THIS CALL DISPATCHES AND RETURNS A RECEIPT. It does NOT wait for the collection. The
        reply carries `proc_id`; pass it to `sl1_fetch_collection_output` with `after_id` to read
        the output. That second call is the normal path, not an error path.

        Expect to poll. Measured on a Central Database appliance, time from dispatch to the
        collector finishing was 12-27 seconds across three runs and grew as jobs queued up -- and
        on a busy appliance it can be MINUTES. Most of that is the collector picking the job up,
        not the collection itself, which was 1-10 seconds of the total.

        Pass `wait_seconds` if you would rather block and get the output in one call. It is capped
        by what the request deadline has left, so a long collection will still hand back a receipt.

        The reply does NOT say whether the collection succeeded, because the platform does not
        record that anywhere: a run against a device that does not exist finishes exactly like a
        good one. Read the returned lines to judge the outcome.

        Args:
            device: Device name or numeric device id, as elsewhere in this server.
            app_id: Numeric Dynamic Application id to collect.
            wait_seconds: Opt in to waiting for output before returning. Default is 0 -- dispatch
                and return immediately. Bounded by what the request deadline has left, so it
                cannot buy time the server has not granted.

        This tool writes to the database and the write cannot be undone by this service.
        """
        dynamic_app_id = as_int(app_id, argument="app_id")
        if dynamic_app_id <= 0:
            raise refuse("app_id", "app_id must be a positive Dynamic Application id.")

        device_id, device_name = await resolve_device(context, device)
        db = context.require_db()

        # The broadcast guard lives in the helper, with the reasoning.
        module_id = await _resolve_collector_module(
            context, device_id=device_id, device_name=device_name
        )

        results = await db.run_unit(
            q.dispatch_dynamic_collection(
                device_id=device_id, dynamic_app_id=dynamic_app_id, module_id=module_id
            ),
            q.last_insert_id(),
        )
        # ``results[0].lastrowid`` is 0 after a CALL, because the insert happens inside the
        # procedure, so the id comes from the second statement on the same connection.
        # ``_queued_proc_id`` explains why ``as_int`` must not be used on it.
        proc_id = _queued_proc_id(results[1].rows)

        correlated = await _record_correlation(
            context, device_id=device_id, module_id=module_id, proc_id=proc_id
        )

        # Everything from here on is best-effort. The collection is queued and cannot be recalled,
        # so a failure while reading must not cost the caller the ``proc_id``, without which they
        # cannot reach the output at all.
        #
        # All three handlers catch ``DbDeadlineExceeded``. Draining output is the part of the call
        # most likely to find the request deadline already spent, and letting it escape would
        # leave a queued collection the caller can never read.
        #
        # With a zero budget, do not read at all. Queue pickup takes 10-20 s, so a read right after
        # dispatch returns nothing, and ``last_id=0`` is the correct resume point.
        budget = _wait_budget(wait_seconds)
        if budget > 0.0:
            lines, last_id, terminated, read_error = await _drain_output(
                context, proc_id=proc_id, after_id=0, budget=budget
            )
        else:
            lines, last_id, terminated, read_error = [], 0, False, None
        job: dict[str, int | None] | None = None
        try:
            job = await _job_row(context, proc_id)
        except (DbDeadlineExceeded, DbError, DbQueryTimeout, DbUnreachable) as exc:
            read_error = read_error or exc

        payload: dict[str, Any] = {
            "proc_id": proc_id,
            "device_id": device_id,
            "device_name": device_name,
            "app_id": dynamic_app_id,
            "collector_id": module_id,
            "terminated": terminated,
            "last_id": last_id,
            "correlation_recorded": correlated,
            "toolbox": _toolbox_view(job),
            **_output_payload(lines),
        }
        if read_error is not None:
            # Reported, not raised: the dispatch succeeded and the caller needs the handle.
            payload["read_error"] = type(read_error).__name__
            payload["read_error_detail"] = str(read_error)
        payload["note"] = _collection_receipt(
            terminated=terminated, last_id=last_id, read_error=read_error
        )
        return payload

    return sl1_run_dynamic_collection


def make_sl1_fetch_collection_output(context: Sl1DbToolContext) -> DbToolFactory:
    """Build the ``sl1_fetch_collection_output`` tool bound to ``context``.

    :param context: The SL1 platform tool context.
    :return: The tool function, ready for ``server.tool``.
    """

    @sl1_tool_boundary(d.FETCH_COLLECTION_OUTPUT)
    async def sl1_fetch_collection_output(
        proc_id: int,
        after_id: int = 0,
        wait_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Poll for the output of a collection started by sl1_run_dynamic_collection.

        THIS IS THE NORMAL SECOND HALF OF A COLLECTION, not an error path.
        `sl1_run_dynamic_collection` dispatches and returns a receipt without waiting, so you will
        almost always need this call. Pass the same proc_id, and after_id=last_id to continue where
        the previous reply stopped.

        Poll it. Returns immediately with whatever is available, so an empty reply with terminated
        false means "not finished yet, ask again" -- not "nothing happened". Dispatch-to-termination
        was measured at 12-27 seconds on a Central Database and can reach MINUTES on a busy
        appliance. Pass `wait_seconds` to block instead of polling.

        Read-only. It starts nothing and changes nothing.

        Args:
            proc_id: The job id returned by sl1_run_dynamic_collection.
            after_id: Return only lines with an id greater than this. Pass the previous reply's
                last_id to continue where it stopped; 0 reads from the beginning.
            wait_seconds: Opt in to waiting for new output before returning. Default is 0 --
                return what is available now. Bounded by what the request deadline has left.
        """
        job_id = as_int(proc_id, argument="proc_id")
        if job_id <= 0:
            raise refuse("proc_id", "proc_id must be a positive job id.")
        resume_from = as_int(after_id, argument="after_id")
        if resume_from < 0:
            raise refuse("after_id", "after_id must not be negative.")

        job = await _job_row(context, job_id)
        if job is None:
            raise refuse(
                "proc_id",
                f"No spool row {job_id} exists. Either it was never queued, or the platform has "
                f"since pruned it -- note the log rows and the spool row are pruned "
                f"independently, so output may outlive the row that describes it.",
            )
        if not _is_collection_job(job):
            # The scope check; see ``_is_collection_job``. The message deliberately says nothing
            # about what the job is, so it cannot be used to enumerate the table.
            raise refuse(
                "proc_id",
                f"Job {job_id} is not a Dynamic Application collection started by this server. "
                f"This tool reads only jobs that sl1_run_dynamic_collection created. Note that "
                f"collections queued before this server moved to the platform's Snippet Framework "
                f"Detailed Collection tool, or queued by the SL1 UI's own Device Tools button, are "
                f"no longer readable here.",
            )
        # After the scope check, so the cheaper, broader test rejects before a second query.
        await _assert_job_is_owned(context, job_id)

        lines, last_id, terminated, read_error = await _drain_output(
            context, proc_id=job_id, after_id=resume_from, budget=_wait_budget(wait_seconds)
        )
        if read_error is not None:
            # Nothing to protect here -- this tool started nothing, so a read failure IS the result.
            raise read_error
        payload: dict[str, Any] = {
            "proc_id": job_id,
            "terminated": terminated,
            "last_id": last_id,
            "toolbox": _toolbox_view(job),
            **_output_payload(lines),
        }
        # Same wording as the dispatch, from one source, so the two tools describe the two-call
        # contract in one voice and a caller does not read "timeout" into "not finished yet".
        payload["note"] = _collection_receipt(
            terminated=terminated, last_id=last_id, read_error=read_error
        )
        return payload

    return sl1_fetch_collection_output
