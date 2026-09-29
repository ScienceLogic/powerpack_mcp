"""
Snippet Framework Collection Output Parsing

This module parses the JSON document the Snippet Framework's Detailed Collection writes to stdout
and decides whether the collection actually worked. It is pure (no I/O, logging, clock or global
state), so the failure-detection rules, which are counter-intuitive, are testable without an
appliance.

Neither the exit code nor the top-level ``success`` flag reports whether the collection worked:

- ``sf_app_detailed_collect.py`` exits 0 for an unaligned device/app pair, returning
  ``{"success": false, "message": "No jobs scheduled"}``.
- A run can return ``success: true`` while its payload carries tracebacks and authentication
  failures, with every collection object reporting ``snapshots: []`` and
  ``processed_result: null``.
- The platform's job runner wraps each result in ``contextlib.suppress(Exception)``, so a malformed
  result is silently dropped and a collection object can be absent with no error anywhere.

So ``summarise_collection`` inspects every collection object, and compares ``dev_app_pairs`` with
the ``results`` keys to expose dropped results (see ``_pair_accounting``). The envelope shape, as
asserted by the Snippet Framework's own tests::

    {
      "success": bool,
      "message": str,                        # present on the refusal path
      "dev_app_pairs": [...],
      "results": {
        "<did>_<app_id>": {
          "<cobj_id>": {
            "name": str,
            "result": {
              "result": {"did": int, "snapshots": [...], "processed_result": ...},
              "logs": [...],
              "error": ...
            }
          }
        }
      }
    }
"""

from __future__ import annotations

import json
from typing import Final

__all__ = [
    "CLI_JSON_SENTINEL",
    "MAX_SURFACED_MESSAGES",
    "MAX_SURFACED_MESSAGE_CHARS",
    "extract_json_document",
    "summarise_collection",
]

# The chunk marker the platform writes at the head of every stdout chunk of the JSON document.
#
# The document is not valid JSON until the sentinels are removed and the pieces joined. Each chunk
# is ``__CLIJSONOUTPUT__`` + 5120 characters + ``\n`` (``REMOTE_DB_LOG_LIMIT = 5 * 1024``); a
# two-app device produced 16 chunks. Stripping the newlines while leaving the sentinels embedded
# produces invalid JSON; the correct parse strips the sentinel from each line, then concatenates.
#
# Chunking is specific to this route. The LCE web route reads the same document from a temp file,
# unchunked; on the Remote Toolbox path stdout is the transport, so the chunking is ours to handle.
CLI_JSON_SENTINEL: Final[str] = "__CLIJSONOUTPUT__"

# Bounds on surfaced free text, for disclosure as much as size.
#
# ``logs[].messages`` is the only place an authentication failure appears, so it cannot be dropped,
# but it is unbounded: ``json_output`` has no size cap platform-side, and ``--standard-format``
# (this route's choice) does not truncate values, unlike the UI's ``--web-ui-format`` (4096
# characters). These caps shape the summary only. The raw lines are still returned to the caller
# unchanged; they are the collector's debug trace and sensitive regardless, and the calling tool's
# ``note`` says so.
MAX_SURFACED_MESSAGES: Final[int] = 20
MAX_SURFACED_MESSAGE_CHARS: Final[int] = 500


def extract_json_document(texts: list[str]) -> str | None:
    """Reassemble the chunked JSON document from a collection's stdout lines.

    Membership is decided by the sentinel, never by the chunk length. The 5120-character figure
    would break on the final short chunk and on any change to ``REMOTE_DB_LOG_LIMIT``. Lines without
    the sentinel are ordinary debug trace and must not be concatenated into the document.

    :param texts: The collection's stdout lines.
    :return: The document text, or ``None`` when no line carries ``CLI_JSON_SENTINEL``, as for a
        collection that has not finished writing its document yet.
    """
    chunks = [text.replace(CLI_JSON_SENTINEL, "") for text in texts if CLI_JSON_SENTINEL in text]
    if not chunks:
        return None
    return "".join(chunks)


def _as_mapping(value: object) -> dict[str, object] | None:
    """Return a JSON object as a ``dict``, or ``None``; every level of platform data is checked."""
    if not isinstance(value, dict):
        return None
    # ``json.loads`` cannot produce a non-string key, so the rebuild only satisfies the type. An
    # ``isinstance`` guard per key would be unreachable, so it is deliberately not written.
    return {str(key): item for key, item in value.items()}


def _bounded_text(value: object) -> str:
    """Truncate one free-text message to ``MAX_SURFACED_MESSAGE_CHARS``, marking it when cut."""
    text = value if isinstance(value, str) else str(value)
    if len(text) <= MAX_SURFACED_MESSAGE_CHARS:
        return text
    return text[:MAX_SURFACED_MESSAGE_CHARS] + "… [truncated]"


def _messages_of(entry: dict[str, object]) -> list[str]:
    """Collect every free-text message an entry carries, from ``logs[].messages`` and ``error``.

    Free text is the only form these errors take: there is no code, level or structured field to key
    on. The messages are surfaced rather than classified, because classifying them would be guessing
    at the platform's wording.
    """
    found: list[str] = []
    error = entry.get("error")
    if error is not None and error != "":
        found.append(_bounded_text(error))
    logs = entry.get("logs")
    if isinstance(logs, list):
        for record in logs:
            mapping = _as_mapping(record)
            if mapping is None:
                continue
            messages = mapping.get("messages")
            if isinstance(messages, list):
                found.extend(_bounded_text(message) for message in messages)
            elif messages is not None:
                found.append(_bounded_text(messages))
    return found


def _object_succeeded(entry: dict[str, object]) -> bool:
    """Return whether this collection object actually produced anything.

    Empty ``snapshots`` and a null ``processed_result`` is the signature of the failure that reports
    ``success: true``. A non-empty ``error`` fails the object outright.
    """
    error = entry.get("error")
    if error is not None and error != "":
        return False
    inner = _as_mapping(entry.get("result"))
    if inner is None:
        return False
    snapshots = inner.get("snapshots")
    has_snapshots = isinstance(snapshots, list) and len(snapshots) > 0
    has_processed = inner.get("processed_result") is not None
    return has_snapshots or has_processed


def _pair_accounting(document: dict[str, object], results: dict[str, object]) -> dict[str, object]:
    """Compare requested pairs with returned pairs, to detect silently dropped results.

    The platform's job runner drops a malformed result with no error recorded anywhere, so absence
    is a failure mode in its own right, invisible if only the present objects are examined.
    """
    pairs = document.get("dev_app_pairs")
    requested = len(pairs) if isinstance(pairs, list) else None
    returned = len(results)
    accounting: dict[str, object] = {"pairs_requested": requested, "pairs_returned": returned}
    if requested is not None:
        accounting["pairs_missing"] = max(0, requested - returned)
    return accounting


def _collect_objects(
    results: dict[str, object],
) -> tuple[list[dict[str, object]], list[str]]:
    """Flatten ``results`` into one row per collection object, with its free text.

    Kept separate from ``summarise_collection`` to hold that function under the complexity limit.

    :return: ``(objects, messages)``.
    """
    objects: list[dict[str, object]] = []
    messages: list[str] = []
    for pair_key, per_pair in results.items():
        pair_objects = _as_mapping(per_pair)
        if pair_objects is None:
            continue
        for cobj_id, raw_entry in pair_objects.items():
            wrapper = _as_mapping(raw_entry) or {}
            entry = _as_mapping(wrapper.get("result")) or {}
            messages.extend(_messages_of(entry))
            objects.append(
                {
                    "pair": pair_key,
                    "collection_object_id": cobj_id,
                    "name": wrapper.get("name"),
                    "succeeded": _object_succeeded(entry),
                }
            )
    return objects, messages


def _classify(reported: object, total: int, failed: int) -> str:
    """Return the overall verdict. The order of these tests matters.

    An explicit ``success: false`` is authoritative for failure; ``success: true`` is authoritative
    for nothing, so it is never consulted. ``no_collections`` is its own verdict rather than a
    success, because a payload with no objects is what both the unaligned-pair refusal and a
    silently dropped result look like.
    """
    if reported is False:
        return "failed"
    if total == 0:
        return "no_collections"
    if failed == 0:
        return "succeeded"
    if failed == total:
        return "failed"
    return "partial"


def summarise_collection(stdout_texts: list[str]) -> dict[str, object] | None:
    """Parse a collection's stdout into an outcome the caller can trust.

    The returned ``outcome`` is the field to read. ``dispatch_reported_success`` is included only so
    a caller can see the flag that must not be trusted, and is named to say so.

    :param stdout_texts: The collection's stdout lines.
    :return: The summary, or ``None`` when there is no JSON document to parse, which the caller
        should treat as "nothing to add" rather than a failure: the collection may still be running.
    """
    document_text = extract_json_document(stdout_texts)
    if document_text is None:
        return None

    try:
        decoded = json.loads(document_text)
    except (ValueError, RecursionError) as exc:
        # ``RecursionError`` is not a ``ValueError``; without it, a deeply nested payload would
        # surface as a generic 500. Caught together, deliberately.
        return {
            "parsed": False,
            "outcome": "unparseable",
            "detail": f"{type(exc).__name__} while decoding the collection's JSON document",
            "document_chars": len(document_text),
        }

    document = _as_mapping(decoded)
    if document is None:
        return {"parsed": False, "outcome": "unparseable", "detail": "not a JSON object"}

    results = _as_mapping(document.get("results")) or {}
    reported = document.get("success")

    objects, messages = _collect_objects(results)
    failed = [obj for obj in objects if obj["succeeded"] is False]
    outcome = _classify(reported, len(objects), len(failed))

    summary: dict[str, object] = {
        "parsed": True,
        "outcome": outcome,
        "dispatch_reported_success": reported,
        "collection_objects": len(objects),
        "collection_objects_failed": len(failed),
        "collections": objects,
        "messages": messages[:MAX_SURFACED_MESSAGES],
        "message_count": len(messages),
        "messages_truncated": len(messages) > MAX_SURFACED_MESSAGES,
        **_pair_accounting(document, results),
    }
    message = document.get("message")
    if message is not None:
        summary["message"] = _bounded_text(message)
    return summary
