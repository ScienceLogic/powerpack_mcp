"""
RPM Lifecycle Sdist Guard Tests

This module tests the sdist selection guard in ``scripts/rpm-lifecycle-test.sh`` by executing it.
The harness runs only inside the OL8 container, so a regression in its front door could pass every
local gate and produce a full PASS report about the wrong RPM. The guard is sliced out of the
harness and run under ``bash`` against fabricated ``dist/`` directories, and the assertions are on
its exit codes and output. The slice ends before the first ``rpmbuild`` and uses only ``basename``,
``sed``, ``tr`` and ``printf``, so no Docker, rpm or network is needed. The slice boundaries are
asserted, so moving the guard fails loudly instead of quietly testing nothing.

The guard aborts on zero sdists, on more than one, and on exactly one whose version differs from
``EXPECTED_SDIST_VERSION``. The expected version comes from the host because only the submodule
directory is mounted, read-only, at ``/src``: ``/src/.git`` is a gitfile pointing outside the
mount, so ``git describe`` fails there. Static checks strip comments first, because the harness
quotes the defective lines it guards against in its own prose; see ``_script_code``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "rpm-lifecycle-test.sh"

# Slice boundaries. Both are load-bearing strings inside the harness; ``_guard_source`` asserts
# they are still there rather than silently returning an empty or truncated slice.
_GUARD_START = "# ---- The sdist must be unambiguous."
_GUARD_END = 'echo "  matches EXPECTED_SDIST_VERSION -- sdist is current"'

# A real current/stale pair seen in ``dist/``, kept verbatim so the fixture data documents the case.
_CURRENT = "1.1.1.dev46+gf4a1ece21"
_STALE = "1.1.1.dev32+g9dad7f03b"

# The harness's own exit contract: 2 means "cannot start", 1 means "rpmbuild failed". The exact code
# is asserted, not merely ``!= 0``, because conflating the two makes a broken harness look like a
# failing build.
_CANNOT_START = 2

requires_bash = pytest.mark.skipif(
    shutil.which("bash") is None, reason="needs bash to run the slice"
)


def _script_text() -> str:
    return _SCRIPT_PATH.read_text(encoding="utf-8")


def _script_code() -> str:
    """Return the harness with whole-line ``#`` comments dropped.

    The same precaution ``tests/unit/test_nginx_fragment.py`` takes. The harness comments quote the
    constructs the checks below forbid, such as ``SDIST=$(ls /src/dist/*.tar.gz | head -1)`` and
    ``git describe``, so a source grep would fail on the prose, and the tempting fix would be to
    delete the explanation. Whole-line only: shell has no block comments, and a ``#`` inside a
    quoted string is not a comment.
    """
    return "\n".join(
        line for line in _script_text().splitlines() if not line.lstrip().startswith("#")
    )


def _guard_source() -> str:
    """Return the guard, verbatim, from the harness.

    Anchored on a comment banner and an echo rather than line numbers, because line numbers in the
    harness move whenever a comment is added.
    """
    text = _script_text()
    start = text.find(_GUARD_START)
    assert start != -1, f"guard banner not found in {_SCRIPT_PATH.name} -- did the guard move?"
    end = text.find(_GUARD_END)
    assert end != -1, f"guard success echo not in {_SCRIPT_PATH.name} -- did the guard move?"
    assert end > start, "the version check must come after the count check, not before it"
    return text[start : end + len(_GUARD_END)]


@dataclass(frozen=True)
class _Result:
    """A guard run: its exit status and everything it said."""

    returncode: int
    output: str


def _run_guard(tmp_path: Path, sdists: list[str], expected: str | None) -> _Result:
    """Run the guard against a fabricated ``dist/``.

    ``/src/dist`` is rewritten to the temporary directory, the only edit made to the slice, so what
    runs is the shipped logic apart from where it looks. ``set -uo pipefail`` is prepended because
    the harness sets it outside the slice, and the guard's ``${EXPECTED_SDIST_VERSION-}`` default
    only matters under ``set -u``.
    """
    dist = tmp_path / "dist"
    dist.mkdir()
    for name in sdists:
        (dist / name).write_bytes(b"")
    script = tmp_path / "guard.sh"
    script.write_text(
        "set -uo pipefail\n" + _guard_source().replace("/src/dist", str(dist)),
        encoding="utf-8",
    )

    env = dict(os.environ)
    # Never inherit it: a developer with this exported in their shell would otherwise get a
    # different result from CI.
    env.pop("EXPECTED_SDIST_VERSION", None)
    if expected is not None:
        env["EXPECTED_SDIST_VERSION"] = expected

    proc = subprocess.run(
        [shutil.which("bash") or "bash", str(script)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    return _Result(proc.returncode, proc.stdout + proc.stderr)


def _sdist(version: str) -> str:
    return f"powerpack_mcp-{version}.tar.gz"


@requires_bash
class TestSdistGuardRejectsAbsentAndAmbiguous:
    """The version check extends the zero-or-many check; it must not have displaced it."""

    def test_zero_sdists_aborts(self, tmp_path: Path) -> None:
        """Nothing to build is unrecoverable, so it stops instead of recording a failure."""
        result = _run_guard(tmp_path, [], _CURRENT)
        assert result.returncode == _CANNOT_START
        assert "ABORT (sdist count): no *.tar.gz" in result.output
        assert "rm -rf dist && uv build --sdist" in result.output

    def test_two_sdists_abort_and_name_both(self, tmp_path: Path) -> None:
        """Ambiguity is reported in full -- naming what it found is what makes it actionable."""
        result = _run_guard(tmp_path, [_sdist(_CURRENT), _sdist(_STALE)], _CURRENT)
        assert result.returncode == _CANNOT_START
        assert "ABORT (sdist count): 2 sdists" in result.output
        assert _sdist(_CURRENT) in result.output
        assert _sdist(_STALE) in result.output

    def test_the_ambiguous_case_never_picks_a_winner(self, tmp_path: Path) -> None:
        """``ls | head -1`` picked the lexicographically first name, so ``dev32`` lost to ``dev1``.

        An abort has no winner to get wrong.
        """
        result = _run_guard(tmp_path, [_sdist(_CURRENT), _sdist(_STALE)], _CURRENT)
        assert "version=" not in result.output


@requires_bash
class TestStaleSingleSdist:
    """Exactly one stale sdist passes a zero-or-many check, so the version check must catch it."""

    def test_one_stale_sdist_aborts(self, tmp_path: Path) -> None:
        """One file, 14 commits old: the count check passes it, so the version check must not."""
        result = _run_guard(tmp_path, [_sdist(_STALE)], _CURRENT)
        assert result.returncode == _CANNOT_START
        assert "ABORT (sdist version)" in result.output

    def test_the_abort_prints_both_versions(self, tmp_path: Path) -> None:
        """Without both, the reader cannot tell which side is wrong: sdist, or their command."""
        result = _run_guard(tmp_path, [_sdist(_STALE)], _CURRENT)
        assert _STALE in result.output
        assert _CURRENT in result.output

    def test_the_abort_gives_the_remedy(self, tmp_path: Path) -> None:
        """The same remedy as the zero-or-many abort: stop curating ``dist/`` by hand."""
        result = _run_guard(tmp_path, [_sdist(_STALE)], _CURRENT)
        assert "rm -rf dist && uv build --sdist" in result.output

    def test_one_current_sdist_is_accepted(self, tmp_path: Path) -> None:
        """The guard must let the good case through, or it is just a broken harness."""
        result = _run_guard(tmp_path, [_sdist(_CURRENT)], _CURRENT)
        assert result.returncode == 0
        assert f"version={_CURRENT}" in result.output
        assert "sdist is current" in result.output

    def test_a_dirty_tree_sdist_matches_its_own_dirty_expectation(self, tmp_path: Path) -> None:
        """setuptools-scm's ``.d<date>`` marker reaches the filename verbatim, so it compares equal.

        Measured against real filenames such as
        ``powerpack_mcp-1.0.1.dev16+g775c04c14.d20260811.tar.gz``.
        """
        dirty = f"{_CURRENT}.d20260828"
        result = _run_guard(tmp_path, [_sdist(dirty)], dirty)
        assert result.returncode == 0

    def test_a_dirty_sdist_does_not_pass_a_clean_expectation(self, tmp_path: Path) -> None:
        """The inverse, and the reason the comparison is not a prefix match.

        A dirty-tree build is not the commit it claims to be.
        """
        result = _run_guard(tmp_path, [_sdist(f"{_CURRENT}.d20260828")], _CURRENT)
        assert result.returncode == _CANNOT_START
        assert "ABORT (sdist version)" in result.output


@requires_bash
class TestTheUnsetExpectationAborts:
    """An unset expectation aborts, and must not be softened into a warning.

    A check that only runs when someone remembered to pass a variable is off in exactly the
    circumstances that produce a stale build. The harness's rule is that ambiguity aborts rather
    than guesses, and "I do not know which commit this artifact is" is ambiguity.
    """

    def test_unset_aborts_with_the_cannot_start_code(self, tmp_path: Path) -> None:
        result = _run_guard(tmp_path, [_sdist(_CURRENT)], None)
        assert result.returncode == _CANNOT_START
        assert "ABORT (sdist version)" in result.output

    def test_unset_aborts_even_when_the_sdist_happens_to_be_current(self, tmp_path: Path) -> None:
        """The guard cannot know that, so a pass here would be luck, not a test."""
        assert _run_guard(tmp_path, [_sdist(_CURRENT)], None).returncode == _CANNOT_START

    def test_an_empty_string_is_treated_as_unset(self, tmp_path: Path) -> None:
        """An empty string, as from a failed ``$(cmd)``, must not slip past as supplied."""
        result = _run_guard(tmp_path, [_sdist(_CURRENT)], "")
        assert result.returncode == _CANNOT_START
        assert "unset" in result.output

    def test_the_abort_names_the_command_that_produces_the_value(self, tmp_path: Path) -> None:
        """An abort that does not say what to do next just gets worked around."""
        result = _run_guard(tmp_path, [_sdist(_CURRENT)], None)
        assert "EXPECTED_SDIST_VERSION" in result.output
        assert "setuptools_scm" in result.output


@requires_bash
class TestOnlyWhitespaceIsNormalised:
    """Only surrounding whitespace, including a trailing CR, is normalised.

    ``-e VAR="$(...)"`` pasted out of a document can carry an invisible trailing CR. Nothing else is
    normalised: the two strings are byte-identical when correct, so a looser comparison could only
    make a real mismatch compare equal.
    """

    @pytest.mark.parametrize("padding", ["{v}\r\n", "  {v}  ", "\t{v}\n"])
    def test_surrounding_whitespace_and_carriage_returns_are_tolerated(
        self, tmp_path: Path, padding: str
    ) -> None:
        result = _run_guard(tmp_path, [_sdist(_CURRENT)], padding.format(v=_CURRENT))
        assert result.returncode == 0

    def test_case_is_not_folded(self, tmp_path: Path) -> None:
        """A different abbreviation rendering is a different artifact, not a formatting variant."""
        result = _run_guard(tmp_path, [_sdist(_CURRENT)], _CURRENT.upper())
        assert result.returncode == _CANNOT_START

    def test_a_git_describe_string_is_rejected(self, tmp_path: Path) -> None:
        """``git describe`` output is not the sdist version, and using it must fail loudly.

        On the same commit ``git describe --tags`` gives ``v1.1.0-46-gf4a1ece`` while
        setuptools-scm, which names the sdist, gives ``1.1.1.dev46+gf4a1ece21``: a different
        next-version guess and a different abbreviation length.
        """
        result = _run_guard(tmp_path, [_sdist(_CURRENT)], "v1.1.0-46-gf4a1ece")
        assert result.returncode == _CANNOT_START
        assert "ABORT (sdist version)" in result.output


class TestTheHarnessSourceItself:
    """Static invariants that execution cannot reach: placement, and the anti-pattern's absence."""

    def test_the_selection_anti_pattern_has_not_returned(self) -> None:
        """``SDIST=$(ls /src/dist/*.tar.gz | head -1)`` must not return.

        It is the obvious "simplification" of the nullglob array, so it is pinned out by name.
        ``head -1`` on a ``find`` is fine elsewhere; selecting the sdist that way is not.
        """
        code = _script_code()
        assert "ls /src/dist" not in code
        assert "ls dist/" not in code
        for line in code.splitlines():
            assert not ("SDIST" in line and "head" in line), f"anti-pattern back: {line!r}"

    def test_selection_is_a_nullglob_array(self) -> None:
        """A shell function named ``head()`` once shadowed ``/usr/bin/head`` and broke every
        ``... | head -1`` in the harness at once. A glob plus ``${var##*/}`` needs no external
        command, so no later edit can shadow it.
        """
        text = _script_text()
        assert "shopt -s nullglob" in text
        assert "SDISTS=(/src/dist/*.tar.gz)" in text

    def test_the_staleness_comparison_exists_and_is_an_inequality_abort(self) -> None:
        """Execution proves today's behaviour; this proves the mechanism stays a string comparison.

        It must compare against the host-supplied value rather than becoming, say, an mtime
        heuristic.
        """
        text = _script_text()
        assert "EXPECTED_VER=$(printf '%s' \"${EXPECTED_SDIST_VERSION-}\"" in text
        assert '[ "$VER" != "$EXPECTED_VER" ]' in text

    def test_the_guard_sits_between_the_version_derivation_and_rpmbuild(self) -> None:
        """After ``VER`` because it needs it; before ``rpmbuild`` because after it the stale
        artifact has already been built.
        """
        text = _script_text()
        derivation = text.index('VER=$(basename "$SDIST"')
        comparison = text.index('[ "$VER" != "$EXPECTED_VER" ]')
        first_build = text.index("rpmbuild -bb")
        assert derivation < comparison < first_build

    def test_the_harness_does_not_try_to_derive_the_version_itself(self) -> None:
        """Guard against a well-meaning "fix" that derives the version inside the container.

        ``/src/.git`` there is a submodule gitfile whose target is outside the mount, so
        ``git describe`` fails, and installing git in the image does not help. A fallback that
        silently produced something would be worse than a mandatory variable.
        """
        code = _script_code()
        assert "git describe" not in code
        assert "git -C /src" not in code

    def test_the_comments_would_have_defeated_a_naive_grep(self) -> None:
        """Guard the method, so the checks above are not "simplified" into a whole-file grep.

        Both banned strings are present in the harness as prose explaining the defects, and the
        comment strip is the only thing that tells the two apart.
        """
        text = _script_text()
        assert "ls /src/dist/*.tar.gz | head -1" in text
        assert "git describe" in text
        assert "ls /src/dist" not in _script_code()
        assert "git describe" not in _script_code()

    def test_the_usage_header_documents_the_mandatory_variable(self) -> None:
        """A mandatory variable missing from the documented ``docker run`` line is a trap."""
        header = _script_text().split("set -uo pipefail")[0]
        assert "-e EXPECTED_SDIST_VERSION=" in header
        assert "python -m setuptools_scm" in header
        assert "docker run" in header

    def test_the_exit_code_contract_mentions_the_stale_sdist_abort(self) -> None:
        """The header's EXIT CODES paragraph is the only place the 0/1/2 contract is written down.

        A new exit-2 path not listed there makes it wrong.
        """
        header = _script_text().split("set -uo pipefail")[0]
        exit_codes = header[header.index("# EXIT CODES.") :]
        assert "EXPECTED_SDIST_VERSION" in exit_codes
