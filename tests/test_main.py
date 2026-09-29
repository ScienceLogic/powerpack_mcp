"""
Entry Point Tests

This module tests ``powerpack_mcp.main``: reading configuration, handing the validated listener
address to uvicorn, and the exit status and structured log record on a configuration error.
``main`` starts a uvicorn server, so every test replaces ``uvicorn.run`` rather than calling it.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from powerpack_mcp import main as main_module
from powerpack_mcp.main import EXIT_CONFIG_ERROR, main


def test_main_serves_on_the_configured_loopback_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(app: object, **kwargs: Any) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(main_module.uvicorn, "run", fake_run)

    main_module.main()

    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8000
    # uvicorn's own dictConfig would replace the root handler and drop the correlation filter.
    assert captured["log_config"] is None


def test_main_starts_without_a_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    """The credential arrives with each request, so startup must succeed with none configured.

    Failing closed happens per request instead: any request lacking a credential is refused.
    """
    called = False

    def fake_run(app: object, **kwargs: Any) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(main_module.uvicorn, "run", fake_run)

    main_module.main()
    assert called, "startup must reach uvicorn with no credential configured"


def test_a_bad_config_value_emits_one_structured_startup_failed_record(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A configuration failure must itself be logged in the structured format.

    Logging has to be configured before ``load_config()`` runs, or an invalid value exits with an
    unstructured traceback and no ``startup_failed`` event. Asserts exactly one record, at ERROR,
    carrying ``event=startup_failed``, and that ``main`` exits with ``EXIT_CONFIG_ERROR``.
    """

    def unreachable_run(app: object, **kwargs: Any) -> None:  # pragma: no cover - must not run
        raise AssertionError("uvicorn.run must not be reached when configuration is invalid")

    monkeypatch.setattr(main_module.uvicorn, "run", unreachable_run)
    # A port outside 1024-65535 is refused.
    monkeypatch.setenv("LISTEN_PORT", "99999")

    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as caught:
        main_module.main()

    assert caught.value.code == EXIT_CONFIG_ERROR
    records = [r for r in caplog.records if getattr(r, "event", None) == "startup_failed"]
    assert len(records) == 1, "exactly one record"
    exc_info = records[0].exc_info
    assert exc_info is not None, "the diagnosis must survive the exit"
    assert exc_info[1] is not None
    assert "LISTEN_PORT" in str(exc_info[1])

    failed = [r for r in caplog.records if getattr(r, "event", None) == "startup_failed"]
    assert len(failed) == 1, f"expected exactly one startup_failed record, got {len(failed)}"
    assert failed[0].levelno == logging.ERROR
    assert failed[0].exc_info is not None, "the record must carry the traceback (logger.exception)"


class TestConfigurationExitStatus:
    """A configuration error exits 78 (``EX_CONFIG``); any other startup failure does not.

    The two halves are tested together, because asserting only the first would also pass if every
    failure exited 78, which would be the defect.
    """

    def test_the_status_is_ex_config_from_sysexits(self) -> None:
        assert EXIT_CONFIG_ERROR == 78

    def test_an_unparseable_tool_set_flag_exits_78(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The value is refused, and the refusal is legible to systemd."""
        monkeypatch.setenv("ENABLE_DB_TOOLS", "maybe")
        with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as caught:
            main()
        assert caught.value.code == EXIT_CONFIG_ERROR

    def test_the_structured_startup_failed_record_survives(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Only the unstructured traceback is suppressed.

        `start_up`'s single ERROR record, its `event=startup_failed` field and its `exc_info` are
        the diagnosis. Exiting 78 must not cost them: a status without a reason would be worse than
        the crash loop it replaces.
        """
        monkeypatch.setenv("ENABLE_OPS_TOOLS", "not-a-bool")
        with caplog.at_level(logging.ERROR), pytest.raises(SystemExit):
            main()
        records = [r for r in caplog.records if getattr(r, "event", None) == "startup_failed"]
        assert len(records) == 1, "expected exactly one such record"
        exc_info = records[0].exc_info
        assert exc_info is not None, "the diagnosis must survive the exit"
        assert exc_info[1] is not None
        assert "ENABLE_OPS_TOOLS" in str(exc_info[1])

    def test_a_non_configuration_failure_does_not_exit_78(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A crash must stay restartable, which is why `main` catches narrowly.

        `Restart=on-failure` exists to recover from a crash, and mapping every startup failure to 78
        would make a transient fault permanent.
        """
        monkeypatch.setattr(
            "powerpack_mcp.main.create_app",
            lambda _config: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        with pytest.raises(RuntimeError, match="boom"):
            main()

    def test_a_valid_configuration_reaches_uvicorn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The exit-status handling must not make a valid startup conditional."""
        started: dict[str, object] = {}

        def _fake_run(app: object, **kwargs: object) -> None:
            started.update(kwargs)

        monkeypatch.setenv("ENABLE_DB_TOOLS", "false")
        monkeypatch.setattr("powerpack_mcp.main.uvicorn.run", _fake_run)
        main()
        assert started["host"] == "127.0.0.1"
        assert started["port"] == 8000
