"""
Snippet Framework Collection Output Tests

This module tests parsing of the Snippet Framework Detailed Collection payload. The tests encode
measured platform behaviour that would make a naturally written parser silently wrong:

- An unaligned device/app pair exits 0, so exit status says nothing.
- ``success: true`` can accompany a payload of tracebacks with no collected data.
- The document is chunked, so the fixtures are multi-chunk; a single-chunk test passes against a
  reassembler that does not reassemble.
- ``job_runner.py:1971`` drops a malformed result under ``contextlib.suppress(Exception)``, so a
  collection object can be absent with no error recorded.
"""

from __future__ import annotations

import json
from typing import Any

from powerpack_mcp.tools.sf_collection_output import (
    CLI_JSON_SENTINEL,
    MAX_SURFACED_MESSAGE_CHARS,
    MAX_SURFACED_MESSAGES,
    extract_json_document,
    summarise_collection,
)


def _messages(summary: dict[str, object]) -> list[str]:
    """Narrow ``summary["messages"]`` off `object` for the strict gate."""
    value = summary["messages"]
    assert isinstance(value, list)
    return [str(item) for item in value]


# The platform's chunk size, ``REMOTE_DB_LOG_LIMIT = 5 * 1024``, measured as exactly 5120
# characters between sentinels.
_CHUNK = 5120


def _entry(
    *,
    snapshots: list[Any] | None = None,
    processed: Any = None,
    error: Any = None,
    messages: list[str] | None = None,
) -> dict[str, Any]:
    """One collection object's ``result`` value, in the platform's nesting."""
    entry: dict[str, Any] = {
        "result": {"did": 209, "snapshots": snapshots or [], "processed_result": processed}
    }
    if error is not None:
        entry["error"] = error
    if messages is not None:
        entry["logs"] = [{"messages": messages}]
    return entry


def _document(
    *,
    success: bool = True,
    pairs: int = 1,
    entries: dict[str, dict[str, Any]] | None = None,
    message: str | None = None,
) -> dict[str, Any]:
    objects = entries if entries is not None else {"1234": _entry(snapshots=[{"v": 1}])}
    document: dict[str, Any] = {
        "success": success,
        "dev_app_pairs": [["209", "526"]] * pairs,
        "results": {"209_526": {k: {"name": f"cobj {k}", "result": v} for k, v in objects.items()}},
    }
    if message is not None:
        document["message"] = message
    return document


def _chunked(document: dict[str, Any]) -> list[str]:
    """Serialise and chunk exactly as the platform does: sentinel + 5120 chars, repeating.

    The reassembly tests rest on this fixture producing more than one chunk, which
    ``test_the_fixture_really_is_multi_chunk`` asserts rather than assumes.
    """
    text = json.dumps(document)
    return [CLI_JSON_SENTINEL + text[i : i + _CHUNK] for i in range(0, len(text), _CHUNK)]


def _padded_document(**kwargs: Any) -> dict[str, Any]:
    """A document guaranteed to exceed one chunk, by padding a snapshot with real content."""
    document = _document(**kwargs)
    pair = document["results"]["209_526"]
    first = next(iter(pair.values()))
    first["result"]["result"]["snapshots"] = [{"metadata": "x" * 12000}]
    return document


class TestChunkReassembly:
    """A single-chunk test would pass while reassembly is broken."""

    def test_the_fixture_really_is_multi_chunk(self) -> None:
        """Guard the guard. If this ever drops to 1, every test below stops testing anything."""
        chunks = _chunked(_padded_document())
        assert len(chunks) > 1, len(chunks)

    def test_a_multi_chunk_document_round_trips(self) -> None:
        document = _padded_document()
        assert extract_json_document(_chunked(document)) == json.dumps(document)

    def test_no_sentinel_survives_reassembly(self) -> None:
        """Leaving sentinels embedded makes decoding fail partway through the document."""
        reassembled = extract_json_document(_chunked(_padded_document()))
        assert reassembled is not None
        assert CLI_JSON_SENTINEL not in reassembled

    def test_a_single_chunk_document_round_trips(self) -> None:
        document = _document()
        assert extract_json_document(_chunked(document)) == json.dumps(document)

    def test_lines_without_the_sentinel_are_not_part_of_the_document(self) -> None:
        """Membership is decided by the sentinel, never by position or length.

        The debug trace is interleaved with the chunk stream on a real run, so concatenating
        everything would corrupt the document.
        """
        document = _document()
        lines = ["Collecting for App ID: 526", *_chunked(document), "done"]
        assert extract_json_document(lines) == json.dumps(document)

    def test_absent_sentinel_is_none_not_an_error(self) -> None:
        """A collection still running has written no document yet. Not a failure."""
        assert extract_json_document(["Process Started on Collector"]) is None
        assert extract_json_document([]) is None

    def test_reassembly_does_not_depend_on_the_chunk_size(self) -> None:
        """A final short chunk is normal, and hard-coding 5120 would mis-handle it."""
        text = json.dumps(_document())
        odd = [CLI_JSON_SENTINEL + text[i : i + 7] for i in range(0, len(text), 7)]
        assert extract_json_document(odd) == text


class TestTheDangerousCase:
    """A measured run that reported success while collecting nothing."""

    def test_success_true_with_every_object_empty_is_a_failure(self) -> None:
        """A measured run logged 18 tracebacks under ``success: true``.

        Every collection object reported ``snapshots: []`` and ``processed_result: null``. Keying
        on the top-level flag would report this as a successful collection.
        """
        document = _document(
            success=True,
            entries={
                "1": _entry(messages=["Traceback (most recent call last):"]),
                "2": _entry(messages=["authentication failed"]),
            },
        )
        summary = summarise_collection(_chunked(document))

        assert summary is not None
        assert summary["outcome"] == "failed"
        assert summary["dispatch_reported_success"] is True
        assert summary["collection_objects"] == 2
        assert summary["collection_objects_failed"] == 2

    def test_the_untrustworthy_flag_is_reported_under_a_name_that_says_so(self) -> None:
        """It is surfaced so a caller can see it, never as the verdict."""
        summary = summarise_collection(_chunked(_document(success=True)))
        assert summary is not None
        assert "dispatch_reported_success" in summary
        assert "success" not in summary


class TestOutcomeClassification:
    """The outcome verdict across the range."""

    def test_all_objects_producing_snapshots_is_success(self) -> None:
        summary = summarise_collection(
            _chunked(_document(entries={"1": _entry(snapshots=[{"v": 1}])}))
        )
        assert summary is not None
        assert summary["outcome"] == "succeeded"

    def test_a_processed_result_alone_is_enough(self) -> None:
        """Either half satisfies the test: snapshots or a processed result."""
        summary = summarise_collection(
            _chunked(_document(entries={"1": _entry(processed={"ok": 1})}))
        )
        assert summary is not None
        assert summary["outcome"] == "succeeded"

    def test_some_failed_is_partial(self) -> None:
        document = _document(
            entries={"1": _entry(snapshots=[{"v": 1}]), "2": _entry(messages=["boom"])}
        )
        summary = summarise_collection(_chunked(document))
        assert summary is not None
        assert summary["outcome"] == "partial"
        assert summary["collection_objects_failed"] == 1

    def test_an_explicit_false_is_authoritative_for_failure(self) -> None:
        """Asymmetric on purpose: ``false`` is trusted, ``true`` is not."""
        document = _document(success=False, entries={"1": _entry(snapshots=[{"v": 1}])})
        summary = summarise_collection(_chunked(document))
        assert summary is not None
        assert summary["outcome"] == "failed"

    def test_a_non_empty_error_fails_the_object_regardless(self) -> None:
        """The platform's own tests assert that the ``error`` key exists."""
        document = _document(entries={"1": _entry(snapshots=[{"v": 1}], error="it broke")})
        summary = summarise_collection(_chunked(document))
        assert summary is not None
        assert summary["outcome"] == "failed"
        assert "it broke" in _messages(summary)


class TestTheUnalignedPair:
    """Exit code 0, and the payload is the only evidence."""

    def test_no_jobs_scheduled_is_a_failure_with_its_message(self) -> None:
        lines = _chunked({"success": False, "message": "No jobs scheduled", "results": {}})
        summary = summarise_collection(lines)

        assert summary is not None
        assert summary["outcome"] == "failed"
        assert summary["message"] == "No jobs scheduled"

    def test_an_empty_results_map_is_not_a_success(self) -> None:
        """``no_collections`` is its own verdict. Zero objects must never read as success."""
        summary = summarise_collection(_chunked({"success": True, "results": {}}))
        assert summary is not None
        assert summary["outcome"] == "no_collections"


class TestSilentlyDroppedResults:
    """``job_runner.py:1971`` suppresses a malformed result and drops it, recording nothing."""

    def test_a_missing_pair_is_counted(self) -> None:
        """Three pairs requested, one returned: visible only by comparing the two."""
        document = _document(pairs=3)
        summary = summarise_collection(_chunked(document))

        assert summary is not None
        assert summary["pairs_requested"] == 3
        assert summary["pairs_returned"] == 1
        assert summary["pairs_missing"] == 2

    def test_no_pair_list_reports_unknown_rather_than_zero(self) -> None:
        """Absent is not the same as zero, and reporting 0 would invent a fact."""
        summary = summarise_collection(_chunked({"success": True, "results": {}}))
        assert summary is not None
        assert summary["pairs_requested"] is None
        assert "pairs_missing" not in summary


class TestFreeTextBounding:
    """The only place an auth failure appears, and it is unbounded on the platform side."""

    def test_messages_are_capped_but_the_true_count_survives(self) -> None:
        many = [f"failure {i}" for i in range(MAX_SURFACED_MESSAGES + 15)]
        summary = summarise_collection(_chunked(_document(entries={"1": _entry(messages=many)})))

        assert summary is not None
        assert len(_messages(summary)) == MAX_SURFACED_MESSAGES
        assert summary["message_count"] == MAX_SURFACED_MESSAGES + 15
        assert summary["messages_truncated"] is True

    def test_a_long_message_is_truncated_and_marked(self) -> None:
        """Marked, so a caller never mistakes a cut message for the whole of one."""
        document = _document(entries={"1": _entry(messages=["z" * 4000])})
        summary = summarise_collection(_chunked(document))

        assert summary is not None
        surfaced = _messages(summary)[0]
        assert surfaced.endswith("… [truncated]")
        assert len(surfaced) == MAX_SURFACED_MESSAGE_CHARS + len("… [truncated]")

    def test_within_the_cap_nothing_is_marked(self) -> None:
        summary = summarise_collection(
            _chunked(_document(entries={"1": _entry(messages=["short"])}))
        )
        assert summary is not None
        assert _messages(summary) == ["short"]
        assert summary["messages_truncated"] is False


class TestMalformedPayloads:
    """Platform output, so every level is defended -- and reported, never raised."""

    def test_undecodable_json_is_reported_not_raised(self) -> None:
        summary = summarise_collection([CLI_JSON_SENTINEL + "{not json"])
        assert summary is not None
        assert summary["parsed"] is False
        assert summary["outcome"] == "unparseable"

    def test_a_json_array_is_not_an_envelope(self) -> None:
        summary = summarise_collection([CLI_JSON_SENTINEL + "[1, 2, 3]"])
        assert summary is not None
        assert summary["outcome"] == "unparseable"

    def test_a_garbled_results_value_does_not_crash_the_parse(self) -> None:
        lines = _chunked({"success": True, "results": {"209_526": "not a mapping"}})
        summary = summarise_collection(lines)
        assert summary is not None
        assert summary["outcome"] == "no_collections"

    def test_a_null_log_record_is_skipped(self) -> None:
        """``logs`` is a list of objects; a null among them must not stop the scan."""
        document = _document(entries={"1": _entry(snapshots=[{"v": 1}])})
        document["results"]["209_526"]["1"]["result"]["logs"] = [None, {"messages": ["kept"]}]
        summary = summarise_collection(_chunked(document))

        assert summary is not None
        assert _messages(summary) == ["kept"]

    def test_a_bare_string_messages_value_is_still_surfaced(self) -> None:
        """``messages`` is a list on every payload measured, but a scalar must not be dropped,
        because it is the only place an auth failure appears."""
        document = _document(entries={"1": _entry(snapshots=[{"v": 1}])})
        document["results"]["209_526"]["1"]["result"]["logs"] = [{"messages": "a bare string"}]
        summary = summarise_collection(_chunked(document))

        assert summary is not None
        assert _messages(summary) == ["a bare string"]

    def test_an_entry_whose_result_is_not_a_mapping_fails_the_object(self) -> None:
        """An unreadable object fails closed; it is not a successful one."""
        document = _document()
        document["results"]["209_526"]["1234"]["result"] = "garbage"
        summary = summarise_collection(_chunked(document))

        assert summary is not None
        assert summary["outcome"] == "failed"

    def test_nothing_to_parse_is_none(self) -> None:
        assert summarise_collection(["ordinary debug output"]) is None
