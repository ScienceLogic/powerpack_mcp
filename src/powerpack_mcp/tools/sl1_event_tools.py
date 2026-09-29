"""
SL1 Event, Collection and Device Class Tools

This module defines the 8 event, collection and device class tools that do not use SQL: 4 over
REST (clear an event, inject an alert, read recent events, read collected values) and 4 over
GraphQL (icons and reclassing). They belong to the ``ops`` tool set rather than the database sets,
so a missing database driver, ``libem7`` or ``silo.conf`` does not disable them.

No tool takes ``target_host``, ``username`` or ``password``. Paths, verbs and GraphQL documents
come from ``sl1_db_descriptors``. Tool docstrings are written out in full because an f-string is
not a docstring and would leave ``__doc__`` as ``None``.
"""

from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING, Any

from powerpack_mcp.tools import sl1_db_descriptors as d
from powerpack_mcp.tools.sl1_db_pipeline import (
    SEVERITY_IN,
    SEVERITY_OUT,
    SOURCE_IN,
    SOURCE_OUT,
    coded,
    refuse,
    resolve_device,
)
from powerpack_mcp.tools.sl1_pipeline import sl1_tool_boundary

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from powerpack_mcp.tools.sl1_db_pipeline import Sl1DbToolContext

    type DbToolFactory = Callable[..., Awaitable[object]]

__all__ = [
    "make_sl1_clear_event",
    "make_sl1_create_icon",
    "make_sl1_get_collected_values",
    "make_sl1_get_recent_events",
    "make_sl1_inject_alert",
    "make_sl1_list_icons",
    "make_sl1_set_device_class",
    "make_sl1_set_device_class_icon",
]

# Cap on the recent-event scan window. Filters are applied client-side, so the window and the
# answer size are different quantities and the window is the one that must be bounded; fetching
# ``limit * 5`` records would pull 5000 full events for ``limit=1000``.
_MAX_EVENT_SCAN = 300


def make_sl1_clear_event(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``sl1_clear_event`` bound to ``context``.

    :param context: The clients, configuration and credential source the tool uses.
    :return: The tool function to register with the MCP server.
    """

    @sl1_tool_boundary(d.CLEAR_EVENT)
    async def sl1_clear_event(event_id: int) -> dict[str, Any]:
        """Clear an active event, moving it from active to cleared as a real resolution would.

        Args:
            event_id: Numeric id of the active event to clear.

        Use this to clean up after sl1_simulate_event, or to clear any active event.

        This tool changes SL1 state.
        """
        # REST, not SQL: ``DELETE event/<id>`` is SL1's supported path for clearing an event, and
        # using it keeps this tool free of the database prerequisite.
        if event_id < 1:
            raise refuse("event_id", "event_id must be a positive event id.")
        response = await context.client.request(
            credential=context.credential_source(),
            method="DELETE",
            path=f"event/{int(event_id)}",
        )
        return {"event_id": int(event_id), "cleared": True, "response": response}

    return sl1_clear_event


def make_sl1_inject_alert(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``sl1_inject_alert`` bound to ``context``."""

    @sl1_tool_boundary(d.INJECT_ALERT)
    async def sl1_inject_alert(
        device: str, message: str, value: str = "", threshold: str = ""
    ) -> dict[str, Any]:
        """Inject an alert into SL1's real event pipeline, so the event engine processes it.

        Policy matching, deduplication, occurrence thresholds, masking, suppression, topology
        correlation and auto-clear all run. Use this rather than sl1_simulate_event when you need to
        verify engine BEHAVIOUR; the two are deliberately different and neither replaces the other.

        An event appears only if an enabled event policy matches this message with source=API. No
        matching policy means no event, which the engine counts as "no event policy matched" -- and
        that is itself a useful diagnostic rather than a failure.

        Alerts are create-only: SL1 rejects updating or deleting an alert message, because it is a
        queue entry rather than an object. To make an auto-clear fire, inject the message that
        matches the clearing policy and make sure the clearer and cleared pair is registered.

        Args:
            device: Device id, or a name to resolve through REST.
            message: Alert message text, matched against event policies.
            value: Becomes %V in the matched policy's message.
            threshold: Becomes %T in the matched policy's message.

        A Dynamic-Application-sourced clearing policy cannot be triggered this way; that path needs
        a real collection poll.

        This tool changes SL1 state.
        """
        device_id, device_name = await resolve_device(context, device)
        body: dict[str, object] = {
            "aligned_resource": f"/api/device/{device_id}",
            "message": message,
        }
        if value != "":
            body["value"] = value
        if threshold != "":
            body["threshold"] = threshold
        response = await context.client.request(
            credential=context.credential_source(),
            method="POST",
            path="alert",
            json_body=body,
        )
        return {
            "queued": True,
            "device_id": device_id,
            "device_name": device_name,
            "message": message,
            "response": response,
            "note": (
                "The engine processes this asynchronously. Check with sl1_get_recent_events using "
                "source=api. If no event appears, the likeliest causes are that no enabled policy "
                "matches this message with source=API, or the device is inactive or in maintenance."
            ),
        }

    return sl1_inject_alert


def make_sl1_get_recent_events(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``sl1_get_recent_events`` bound to ``context``."""

    @sl1_tool_boundary(d.GET_RECENT_EVENTS)
    async def sl1_get_recent_events(
        device: str | None = None,
        limit: int = 20,
        min_severity: str = "healthy",
        source: str | None = None,
    ) -> dict[str, Any]:
        """Read back recent active events, newest first. The read-back half of event verification.

        Args:
            device: Optional device id or name to filter on.
            limit: Maximum number of events to return.
            min_severity: Severity floor -- healthy, notice, minor, major or critical, or 0-4.
            source: Optional origin filter -- syslog, internal, trap, dynamic, api, email or agent.

        Filters are applied after fetching, so a recent window is scanned rather than thousands of
        full records being pulled. When that window fills, the result says so: a truncated scan
        would otherwise look exactly like a complete one.

        This tool only reads.
        """
        if limit < 1:
            raise refuse("limit", "limit must be at least 1.")
        floor, source_code, device_id, device_name = await _event_filters(
            context, min_severity=min_severity, source=source, device=device
        )

        filtered = bool(device_id or source_code or floor)
        window = min(max(limit * 3, 60), _MAX_EVENT_SCAN) if filtered else max(limit, 20)
        data = await _fetch_event_index(context, window)

        window_full = len(data) >= window
        rows = [
            row
            for uri, event in data.items()
            if isinstance(event, dict)
            for row in [_event_row(uri, event)]
            if _keeps(row, floor=floor, source_code=source_code, device_id=device_id)
        ]
        rows.sort(key=lambda r: str(r["last_seen"]), reverse=True)
        return {
            "events": rows[:limit],
            "matched": len(rows),
            "min_severity": SEVERITY_OUT.get(floor, floor),
            "source": None if source_code is None else SOURCE_OUT.get(source_code, source_code),
            "device": None if device_id is None else {"did": device_id, "name": device_name},
            # Reported rather than implied. A caller seeing 20 of 20 cannot otherwise tell
            # whether older matches exist beyond the scan window.
            "scan_window": window,
            "scan_window_full": filtered and window_full and len(rows) < limit,
        }

    return sl1_get_recent_events


async def _event_filters(
    context: Sl1DbToolContext, *, min_severity: str, source: str | None, device: str | None
) -> tuple[int, int | None, int | None, str | None]:
    """Resolve the recent-event filters to a severity floor, source code and device.

    :param context: The clients, configuration and credential source the tool uses.
    :param min_severity: The severity floor as given by the caller.
    :param source: The optional origin filter as given by the caller.
    :param device: The optional device id or name as given by the caller.
    :return: The severity floor, source code, device id and device name.
    """
    # An unrecognised filter is refused, not ignored. Falling through to "no filter" would
    # give the caller unfiltered results they believe are filtered.
    floor = coded(min_severity, SEVERITY_IN, argument="min_severity")
    source_code = None if source is None else coded(source, SOURCE_IN, argument="source")

    device_id: int | None = None
    device_name: str | None = None
    if device is not None:
        device_id, device_name = await resolve_device(context, device)
    return floor, source_code, device_id, device_name


async def _fetch_event_index(context: Sl1DbToolContext, window: int) -> dict[str, Any]:
    """Fetch the newest ``window`` events, refusing a response that is not an index.

    :param context: The clients, configuration and credential source the tool uses.
    :param window: How many events to scan.
    :return: The event index, keyed by event URI.
    """
    data = await context.client.request(
        credential=context.credential_source(),
        method="GET",
        path="event",
        query={
            "extended_fetch": "1",
            "hide_filterinfo": "1",
            "limit": str(window),
            "order.date_last": "DESC",
        },
    )
    if not isinstance(data, dict):
        raise refuse("", "SL1 returned an unexpected shape for the event index.")
    return data


def _event_row(uri: str, event: dict[str, Any]) -> dict[str, Any]:
    """Flatten one event. Severity and source are coerced defensively."""
    return {
        "id": uri.rstrip("/").split("/")[-1],
        "severity_code": _as_int(event.get("severity")),
        "source_code": _as_int(event.get("source")),
        "aligned_resource": event.get("aligned_resource", "") or "",
        "device_name": event.get("aligned_resource_name", ""),
        "event_policy": (event.get("event_policy", "") or "").rstrip("/").split("/")[-1],
        "count": event.get("counter", ""),
        "acknowledged": bool(event.get("user_ack")),
        "last_seen": _as_timestamp(event.get("date_last", "")),
        "message": (event.get("message", "") or "").replace("\n", " ")[:100],
    }


def _keeps(
    row: dict[str, Any], *, floor: int, source_code: int | None, device_id: int | None
) -> bool:
    """Apply the client-side severity, source and device filters to one row."""
    if row["severity_code"] < floor:
        return False
    if source_code is not None and row["source_code"] != source_code:
        return False
    if device_id is not None:
        aligned = str(row["aligned_resource"])
        if not aligned.endswith(f"/device/{device_id}"):
            return False
    return True


def _as_int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _as_timestamp(value: object) -> str:
    """Render SL1's epoch seconds as a UTC timestamp, or pass the value through if not a number.

    ``datetime.fromtimestamp(..., tz=UTC)`` rather than ``utcfromtimestamp``, which is deprecated
    and returns a naive datetime that reads as local time to anything downstream.
    """
    try:
        moment = dt.datetime.fromtimestamp(int(str(value)), tz=dt.UTC)
    except (TypeError, ValueError, OSError, OverflowError):
        return str(value)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_sl1_get_collected_values(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``sl1_get_collected_values`` bound to ``context``."""

    @sl1_tool_boundary(d.GET_COLLECTED_VALUES)
    async def sl1_get_collected_values(
        device: str, dynamic_app: str | None = None, max_apps: int = 12
    ) -> dict[str, Any]:
        """Read what SL1 stored for a device's aligned Dynamic Applications.

        Uses the supported config_data and performance_data paths rather than reading the database
        directly, so it verifies that collection landed and grouped correctly as SL1 itself sees it.

        Args:
            device: Device id, or a name to resolve through REST.
            dynamic_app: Optional case-insensitive substring filter on the application name.
            max_apps: Cap on how many applications have their values fetched. A device can have
                many aligned applications and each costs one call, so the rest are listed by name.

        No data is lost when the cap bites: every application's name is returned, and the unfetched
        values are one filtered call away.

        This tool only reads.
        """
        if max_apps < 1:
            raise refuse("max_apps", "max_apps must be at least 1.")
        device_id, device_name = await resolve_device(context, device)
        credential = context.credential_source()
        wanted = None if dynamic_app is None else dynamic_app.lower()

        config = await context.client.request(
            credential=credential,
            method="GET",
            path=f"device/{device_id}/config_data",
            query={"extended_fetch": "1", "hide_filterinfo": "1", "limit": "100"},
        )
        applications = _config_applications(config, wanted)

        fetched: list[dict[str, Any]] = []
        for application in applications[:max_apps]:
            values = await context.client.request(
                credential=credential,
                method="GET",
                path=f"device/{device_id}/config_data/{application['guid']}/data",
            )
            fetched.append({**application, "index_groups": _config_groups(values)})

        performance = await context.client.request(
            credential=credential,
            method="GET",
            path=f"device/{device_id}/performance_data",
            query={"extended_fetch": "1", "hide_filterinfo": "1", "limit": "100"},
        )
        return {
            "device": {"did": device_id, "name": device_name},
            "config": {
                "total_applications": len(applications),
                "fetched": fetched,
                "not_fetched": [a["name"] for a in applications[max_apps:]],
            },
            "performance": _performance_summary(performance, wanted),
        }

    return sl1_get_collected_values


def _config_applications(config: object, wanted: str | None) -> list[dict[str, str]]:
    """List the applications in a device's config data index, filtered by name.

    :param config: The ``config_data`` index as SL1 returned it.
    :param wanted: The lower-cased name substring to keep, or ``None`` to keep every application.
    :return: The name and GUID of each kept application.
    """
    if not isinstance(config, dict):
        return []
    applications: list[dict[str, str]] = []
    for uri, meta in config.items():
        if not isinstance(meta, dict) or not meta.get("name"):
            continue
        name = str(meta["name"]).strip()
        if wanted is None or wanted in name.lower():
            applications.append({"name": name, "guid": uri.rstrip("/").split("/")[-1]})
    return applications


def _config_groups(values: object) -> list[dict[str, Any]]:
    """Flatten one application's config data into named index groups.

    Each numbered key is an index or instance group. Collection-object names are resolved from
    ``object_info`` rather than reported as bare ids, which is why this endpoint is preferable to a
    direct database read.
    """
    if not isinstance(values, dict):
        return []
    groups: list[dict[str, Any]] = []
    for index, group in values.items():
        if not isinstance(group, dict):
            continue
        info = group.get("object_info") or {}
        data = group.get("data") or {}
        groups.append(
            {
                "index": index,
                "label": group.get("group_label", "") or "",
                "objects": _named_objects(info, data),
            }
        )
    return groups


def _named_objects(info: object, data: object) -> dict[str, Any]:
    """Key one index group's readings by collection-object name.

    :param info: The group's ``object_info``, mapping object ids to their metadata.
    :param data: The group's ``data``, mapping object ids to their readings.
    :return: The readings keyed by object name, or by ``obj <id>`` where no name is known.
    """
    objects: dict[str, Any] = {}
    if not isinstance(data, dict):
        return objects
    for object_id, readings in data.items():
        name = "obj " + str(object_id)
        if isinstance(info, dict) and isinstance(info.get(object_id), dict):
            name = str(info[object_id].get("name", name))
        objects[name] = readings
    return objects


def _performance_summary(performance: object, wanted: str | None) -> dict[str, Any]:
    """Summarise presentations per application, with whether SL1 has data for each.

    ``data_found`` is reported per presentation because it distinguishes "collection is configured"
    from "collection produced something", and a caller verifying a Dynamic Application needs the
    second.
    """
    if not isinstance(performance, list):
        return {"applications": []}
    applications: list[dict[str, Any]] = []
    for application in performance:
        if not isinstance(application, dict):
            continue
        name = str(application.get("appname", ""))
        if wanted is not None and wanted not in name.lower():
            continue
        presentations = [
            {
                "name": presentation.get("presname"),
                "data_found": str(presentation.get("data_found")) == "1",
            }
            for presentation in application.get("presentations", []) or []
            if isinstance(presentation, dict)
        ]
        applications.append({"name": name, "presentations": presentations})
    return {"applications": applications}


# ---- The 4 GraphQL tools: icons and reclassing --------------------------------------------------


def make_sl1_create_icon(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``sl1_create_icon`` bound to ``context``."""

    @sl1_tool_boundary(d.CREATE_ICON)
    async def sl1_create_icon(name: str, svg: str) -> dict[str, Any]:
        """Create a reusable SVG icon.

        Args:
            name: Icon name.
            svg: Raw SVG markup.

        Assign it to a device class with sl1_set_device_class_icon. One icon can serve many classes,
        so list the existing ones first rather than creating a duplicate.

        This tool changes SL1 state.
        """
        return await _graphql(context, d.CREATE_ICON, {"name": name, "svg": svg})

    return sl1_create_icon


def make_sl1_list_icons(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``sl1_list_icons`` bound to ``context``."""

    @sl1_tool_boundary(d.LIST_ICONS)
    async def sl1_list_icons(name_contains: str | None = None, first: int = 50) -> dict[str, Any]:
        """List existing SVG icons, so one can be reused instead of a new one being created.

        Args:
            name_contains: Optional substring filter on the icon name.
            first: Maximum number of icons to return.

        This tool only reads.
        """
        if first < 1:
            raise refuse("first", "first must be at least 1.")
        return await _graphql(
            context, d.LIST_ICONS, {"first": int(first), "contains": name_contains or ""}
        )

    return sl1_list_icons


def make_sl1_set_device_class_icon(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``sl1_set_device_class_icon`` bound to ``context``."""

    @sl1_tool_boundary(d.SET_DEVICE_CLASS_ICON)
    async def sl1_set_device_class_icon(
        device_class_guid: str, icon_id: str | None = None
    ) -> dict[str, Any]:
        """Assign an SVG icon to a device class, or clear it.

        Args:
            device_class_guid: GUID of the device class.
            icon_id: Icon id to assign, or omit to clear the icon.

        The class is re-read after the change to confirm it, because the mutation's own return can
        be stale.

        This tool changes SL1 state.
        """
        credential = context.credential_source()
        await context.client.graphql(
            credential=credential,
            query=d.SET_DEVICE_CLASS_ICON.document,
            variables={"deviceClassId": device_class_guid, "iconId": icon_id},
        )
        # The confirm read is a second document, not the mutation's own payload, which can be
        # stale; trusting it could report a change that has not landed.
        confirmed = await context.client.graphql(
            credential=credential,
            query=d.READ_DEVICE_CLASS_DOCUMENT,
            variables={"id": device_class_guid},
        )
        return {"device_class": _root(confirmed, "deviceClass")}

    return sl1_set_device_class_icon


def make_sl1_set_device_class(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``sl1_set_device_class`` bound to ``context``."""

    @sl1_tool_boundary(d.SET_DEVICE_CLASS)
    async def sl1_set_device_class(device_id: str, device_class_guid: str) -> dict[str, Any]:
        """Reclass a device to a given device class.

        Args:
            device_id: Id of the device to reclass.
            device_class_guid: GUID of the device class to move it to.

        The device inherits the class's icon automatically.

        This tool changes SL1 state.
        """
        return await _graphql(
            context,
            d.SET_DEVICE_CLASS,
            {"id": str(device_id), "deviceClass": device_class_guid},
        )

    return sl1_set_device_class


async def _graphql(
    context: Sl1DbToolContext,
    descriptor: d.DbToolDescriptor,
    variables: dict[str, Any],
) -> dict[str, Any]:
    """Issue one GraphQL operation and read its root field.

    The document and root field both come from the descriptor, so no tool body contains either.
    ``Sl1Client.graphql`` already raises on a non-empty ``errors`` array, because HTTP 200 can mean
    failure for GraphQL.
    """
    data = await context.client.graphql(
        credential=context.credential_source(),
        query=descriptor.document,
        variables=variables,
    )
    return {descriptor.root_field: _root(data, descriptor.root_field)}


def _root(data: dict[str, Any], root_field: str) -> Any:
    """Read ``root_field`` out of a GraphQL ``data`` envelope, tolerating either shape.

    ``Sl1Client.graphql`` may return the envelope or the unwrapped ``data`` object; checking both is
    cheaper than asserting one and being wrong when the field genuinely returned ``null``.
    """
    if root_field in data:
        return data[root_field]
    inner = data.get("data")
    if isinstance(inner, dict):
        return inner.get(root_field)
    return None
