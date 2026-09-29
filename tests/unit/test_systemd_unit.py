"""
Systemd Unit Tests

This module tests the shipped systemd unit, ``packaging/systemd/powerpack-mcp.service``, by
parsing it rather than grepping it.

Other properties of the unit are asserted in ``scripts/rpm-lifecycle-test.sh``, which runs only
inside the OL8 container, so the directives guarded here are also checked by the local test run.
The unit is INI-shaped, so ``configparser`` reports on the directives while ignoring comments.
That matters because the comments beside the guarded directives contain the directive names and
would defeat a grep.
"""

from __future__ import annotations

import configparser
from pathlib import Path

import pytest

_UNIT_PATH = Path(__file__).resolve().parents[2] / "packaging" / "systemd" / "powerpack-mcp.service"


def _parse_unit() -> configparser.ConfigParser:
    """Parse the unit as INI.

    ``strict=False`` because systemd permits a directive to repeat, and ``allow_no_value=True``
    because it permits a bare key -- neither is true of stock INI, and both would otherwise raise.
    """
    parser = configparser.ConfigParser(strict=False, allow_no_value=True)
    # Preserve case: systemd directives are case-sensitive and the default optionxform lowercases.
    parser.optionxform = str  # type: ignore[method-assign, assignment]
    parser.read_string(_UNIT_PATH.read_text(encoding="utf-8"))
    return parser


class TestEnvironmentFileIsAbsent:
    """Guards a removed directive whose return would re-open a permission bypass."""

    def test_the_service_section_declares_no_environment_file(self) -> None:
        """The assertion that matters.

        A dash-prefixed ``EnvironmentFile=`` would fix the missing-file failure but not the bypass.
        The application parses the same file itself and refuses one without 0600 permissions and
        the right owner, but systemd-injected values win because the env file never overrides them,
        so a file with wrong permissions would have its values loaded before the refusal takes
        effect.
        """
        assert "EnvironmentFile" not in _parse_unit()["Service"]

    def test_no_section_declares_one_either(self) -> None:
        """A directive in the wrong section is a misconfiguration, not a pass."""
        parser = _parse_unit()
        for section in parser.sections():
            assert "EnvironmentFile" not in parser[section], f"reintroduced under [{section}]"

    def test_the_deletion_is_explained_in_the_unit_itself(self) -> None:
        """A bare absence is indistinguishable from an oversight, and would invite restoration.

        This is the one text check here, because a rationale comment is text. It asserts the
        presence of an explanation rather than its exact wording.
        """
        text = _UNIT_PATH.read_text(encoding="utf-8")
        assert "deliberately no EnvironmentFile" in text
        assert "permission check" in text

    def test_the_comment_would_have_defeated_a_naive_grep(self) -> None:
        """Guards the method, so nobody 'simplifies' this module back into a grep.

        The explanatory comment contains the literal `EnvironmentFile=`, so a source grep for that
        string still matches. The parse is what distinguishes a comment from a directive.
        """
        assert "EnvironmentFile=" in _UNIT_PATH.read_text(encoding="utf-8")
        assert "EnvironmentFile" not in _parse_unit()["Service"]


class TestUnitStillCarriesItsLoadBearingDirectives:
    """A deletion test that passed on an empty file would be worthless. This bounds that."""

    @pytest.mark.parametrize(
        ("directive", "expected"),
        [
            ("User", "s-em7-core"),
            ("Group", "s-em7-core"),
            ("WorkingDirectory", "/opt/em7/services/powerpack-mcp"),
        ],
    )
    def test_identity_and_working_directory_survive(self, directive: str, expected: str) -> None:
        assert _parse_unit()["Service"][directive] == expected

    def test_exec_start_still_invokes_the_module_not_the_console_script(self) -> None:
        """`bin/python` is a symlink, so there is no shebang to be baked wrong."""
        exec_start = _parse_unit()["Service"]["ExecStart"]
        assert exec_start.endswith("-m powerpack_mcp")
        assert "/venv/bin/python" in exec_start


class TestRestartPreventExitStatus:
    """Guards the directive that stops a configuration error becoming a crash loop.

    Without it, a configuration typo restarts the service every five seconds for ever, because
    ``Restart=on-failure`` with ``RestartSec=5s`` never reaches systemd's default start-limit
    burst of 5 within its default 10 s window. The comment above the directive contains
    ``RestartPreventExitStatus`` several times, so a grep would pass even if the directive had
    been deleted.
    """

    def test_the_directive_is_present_and_names_exit_78(self) -> None:
        """78 is ``EX_CONFIG`` from BSD ``sysexits.h``, and it must match
        `powerpack_mcp.main.EXIT_CONFIG_ERROR` (see the next test)."""
        service = _parse_unit()["Service"]
        assert service.get("RestartPreventExitStatus") == "78"

    def test_the_unit_and_the_code_agree_on_the_status(self) -> None:
        """The directive lives in packaging and the exit status in code, so only this test stops
        them drifting apart.

        A mismatch would be silent: the service would exit 78, systemd would not recognise it, and
        the crash loop would be back with no failing test.
        """
        from powerpack_mcp.main import EXIT_CONFIG_ERROR

        assert _parse_unit()["Service"].get("RestartPreventExitStatus") == str(EXIT_CONFIG_ERROR)

    def test_restart_on_failure_is_still_in_force(self) -> None:
        """The exit status separates two failure classes; it does not disable recovery for either.

        If `Restart=` were dropped, the default is ``Restart=no`` and a genuine crash would leave
        the service down.
        """
        service = _parse_unit()["Service"]
        assert service.get("Restart") == "on-failure"
        assert service.get("RestartSec") == "5s"

    def test_no_start_limit_tuning_was_added_instead(self) -> None:
        """The rejected alternative, pinned so it is not silently adopted later.

        Setting `StartLimitIntervalSec`/`StartLimitBurst` would make the unit give up after N
        attempts, but it also caps restarts for genuine transient crashes, which
        `Restart=on-failure` exists to recover from. Adopting it should be a deliberate decision,
        so this asserts the absence.
        """
        parser = _parse_unit()
        for section in ("Unit", "Service"):
            if parser.has_section(section):
                assert "StartLimitBurst" not in parser[section]
                assert "StartLimitIntervalSec" not in parser[section]
