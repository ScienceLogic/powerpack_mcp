"""
RPM Spec Tests

This module tests the RPM spec and the packaging workflow as text: the venv flags, the absence
of ``mysqlclient``, the build and runtime requirements, the vendor, pinned action refs, and the
docs the ``%description`` promises. These tests do not replace building the RPM; they make a
future edit that reverts one of these lines fail a gate that runs on every commit.

The venv is built with ``--system-site-packages`` so the DB tools can import the platform's
``sl_mysql`` and ``MySQLdb``. The trade-off is that the venv is no longer fully self-contained:
what it resolves at runtime depends on the appliance's system Python tree. The spec checks
separately that every locked dependency is still installed into the venv itself.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
SPEC = _ROOT / "packaging" / "rpm" / "powerpack-mcp.spec"
PACKAGING_WORKFLOW = _ROOT / ".github" / "workflows" / "packaging.yml"
# The workflows that build the RPM. The public CI workflow lives in `.github/public/` here and is
# installed as `.github/workflows/ci.yml` by scripts/export-public.sh.
BUILD_WORKFLOWS = [
    path
    for path in (
        PACKAGING_WORKFLOW,
        _ROOT / ".github" / "public" / "ci.yml",
        _ROOT / ".github" / "workflows" / "ci.yml",
    )
    if path.is_file()
]
PYPROJECT = _ROOT / "pyproject.toml"
LOCKFILE = _ROOT / "uv.lock"


@pytest.fixture(scope="module")
def spec() -> str:
    return SPEC.read_text()


@pytest.fixture(scope="module")
def workflow() -> str:
    if not PACKAGING_WORKFLOW.is_file():
        pytest.skip("the internal packaging workflow is not part of the public copy")
    return PACKAGING_WORKFLOW.read_text()


def _uncommented(text: str) -> list[str]:
    """Return the lines with ``#`` comments stripped, so prose about a rule never satisfies it.

    Every assertion in this file depends on this: the spec is mostly comment by volume, and a test
    matching the explanation rather than the directive would pass for the wrong reason.
    """
    out = []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped:
            out.append(stripped)
    return out


class TestSystemSitePackages:
    """The venv is built with ``include-system-site-packages = true``."""

    def test_the_venv_is_built_with_the_flag(self, spec: str) -> None:
        build_lines = [line for line in _uncommented(spec) if line.startswith("uv venv")]
        assert len(build_lines) == 1, (
            f"expected exactly one `uv venv` invocation, got {build_lines}"
        )
        assert "--system-site-packages" in build_lines[0]

    def test_the_assertion_is_inverted_not_deleted(self, spec: str) -> None:
        """The build asserts ``= true``, so the guard stays two-sided.

        Without the assertion, a venv that silently stopped inheriting system site-packages would
        disable the DB tools on the appliance with nothing failing at build time. The service is
        designed to survive a missing DB driver quietly, which is what makes an unasserted flag
        dangerous.
        """
        directives = _uncommented(spec)
        asserts_true = [
            line for line in directives if "include-system-site-packages = true" in line
        ]
        asserts_false = [
            line for line in directives if "include-system-site-packages = false" in line
        ]
        assert asserts_true, "the build must ASSERT the flag, not merely pass it"
        assert not asserts_false, (
            "the old `= false` assertion is still live in a directive; the venv must assert `true`"
        )

    def test_relocatable_is_still_asserted(self, spec: str) -> None:
        """``relocatable`` and ``include-system-site-packages`` coexist, measured on uv 0.8.15."""
        assert any("relocatable = true" in line for line in _uncommented(spec)), (
            "the relocatable assertion must survive"
        )

    def test_the_failure_message_says_what_breaks(self, spec: str) -> None:
        """An operator reading a build failure needs the consequence, not only a rule id."""
        assert "sl_mysql is unimportable" in spec or "sl_mysql" in spec
        assert "include-system-site-packages=true is required" in spec


class TestTheCiWorkflowMatchesTheSpec:
    """The CI workflow's own ``uv venv`` must use the same flags as the spec.

    Changing the assertion without the flag, or the flag without the assertion, fails the build, so
    they must move together.
    """

    def test_the_workflow_builds_with_the_flag(self, workflow: str) -> None:
        build_lines = [line for line in _uncommented(workflow) if line.startswith("uv venv")]
        assert len(build_lines) == 1, f"expected one `uv venv` in the workflow, got {build_lines}"
        assert "--system-site-packages" in build_lines[0]

    def test_the_workflow_assertion_is_inverted_too(self, workflow: str) -> None:
        directives = _uncommented(workflow)
        assert any("include-system-site-packages = true" in line for line in directives)
        assert not any("include-system-site-packages = false" in line for line in directives)

    def test_the_two_sites_agree(self, spec: str, workflow: str) -> None:
        """The workflow claims to build "exactly as the RPM does"; this makes that checkable.

        Both must pass the same flags, or CI validates a venv shape the RPM never produces.
        """
        spec_flags = {
            flag
            for line in _uncommented(spec)
            if line.startswith("uv venv")
            for flag in re.findall(r"--[a-z-]+", line)
        }
        workflow_flags = {
            flag
            for line in _uncommented(workflow)
            if line.startswith("uv venv")
            for flag in re.findall(r"--[a-z-]+", line)
        }
        assert spec_flags == workflow_flags, (
            f"spec and CI build the venv differently: spec-only={spec_flags - workflow_flags}, "
            f"ci-only={workflow_flags - spec_flags}"
        )


class TestMysqlclientIsNotADependency:
    """``mysqlclient`` must not be declared as a dependency.

    This is a deliberate omission, and an omission is what gets silently "fixed". Someone hitting
    ``ModuleNotFoundError: MySQLdb`` off-appliance would reasonably run ``uv add mysqlclient``,
    which would work locally and break the appliance build: no Linux wheel exists for any version,
    and the appliance has no ``gcc``, no ``mysql_config`` and no outbound network.
    """

    def test_it_is_not_a_project_dependency(self) -> None:
        text = PYPROJECT.read_text()
        # Comments stripped: ``pyproject.toml`` documents the omission, and that mention must
        # neither satisfy nor fail this assertion.
        directives = "\n".join(_uncommented(text))
        assert "mysqlclient" not in directives
        assert "sl-mysql" not in directives
        assert "sl_mysql" not in directives

    def test_it_is_not_in_the_lockfile(self) -> None:
        assert "mysqlclient" not in LOCKFILE.read_text()

    def test_no_build_toolchain_is_required(self, spec: str) -> None:
        """No compiler toolchain is declared, because nothing is compiled.

        Compiling the ``mysqlclient`` sdist would need ``gcc``, ``python3.12-devel`` and
        ``mariadb-connector-c-devel``. With ``mysqlclient`` not a dependency, none are needed.
        """
        build_requires = [line for line in _uncommented(spec) if line.startswith("BuildRequires:")]
        assert build_requires == ["BuildRequires:  systemd-rpm-macros"], (
            "BuildRequires changed; if a compiler was added, the no-compile route for the DB "
            "driver has been abandoned"
        )

    def test_no_hand_written_soname_requires(self, spec: str) -> None:
        """Never hand-write a package-name ``Requires`` for the driver's shared library.

        No ``_mysql*.so`` is built, so the RPM's auto-generated dependencies cannot acquire
        ``libmariadb.so.3()(64bit)`` in the first place.
        """
        requires = [line for line in _uncommented(spec) if line.startswith("Requires:")]
        assert requires == ["Requires:       python3.12", "Requires:       nginx"]
        assert not any("mariadb" in line.lower() for line in requires)


class TestPackageIdentity:
    """The package names its vendor the way the platform's own packages do, and names no packager.

    Every ScienceLogic package on an appliance reports ``ScienceLogic, Inc.``, so a query or an
    inventory tool groups this one with them. ``Packager`` is deliberately absent: the spec is
    public, and a hard-coded value would claim anyone's build as ScienceLogic's.
    """

    def test_the_vendor_matches_the_platform_packages(self, spec: str) -> None:
        vendors = [line for line in _uncommented(spec) if line.startswith("Vendor:")]
        assert vendors == ["Vendor:         ScienceLogic, Inc."]

    def test_no_packager_is_hard_coded(self, spec: str) -> None:
        assert not any(line.startswith("Packager:") for line in _uncommented(spec))


class TestNoMutableRefInABuildPath:
    """No mutable ``@main`` or ``@master`` action ref may appear in a workflow that builds the RPM.

    One exists elsewhere in ``cicd.yml``; this stops it being copied into a build path.
    """

    def test_there_is_a_build_workflow(self) -> None:
        assert BUILD_WORKFLOWS, "no workflow that builds the RPM was found"

    @pytest.mark.parametrize("path", BUILD_WORKFLOWS, ids=lambda path: path.name)
    def test_the_build_workflow_pins_every_action(self, path: Path) -> None:
        refs = re.findall(r"uses:\s*(\S+)", path.read_text())
        mutable = [ref for ref in refs if ref.endswith(("@main", "@master"))]
        assert not mutable, f"mutable action refs in {path.name}: {mutable}"


class TestTheDescriptionsPromiseMatchesThePayload:
    """The ``%description`` is a contract: every doc it points at must be installed and shipped.

    The expected set is derived from the ``%description`` prose rather than a hand-written list, as
    in ``TestTheCiWorkflowMatchesTheSpec::test_the_two_sites_agree``, so adding a doc to the
    ``%description`` fails this test until it is shipped.
    """

    # ``%doc`` entries live under this, so the prefix comes off before comparing to ``docs/``.
    _DOC_PREFIX = "%{versioned_dir}/docs/"

    def _promised(self, spec: str) -> set[str]:
        """Return every ``docs/<name>.md`` the ``%description`` prose points an operator at."""
        description = spec.split("%description", 1)[1].split("# ====", 1)[0]
        return set(re.findall(r"docs/([a-z0-9-]+\.md)", description))

    def _installed(self, spec: str) -> set[str]:
        lines = _uncommented(spec)
        return {
            m.group(1)
            for line in lines
            if (m := re.search(r"install .*docs/([a-z0-9-]+\.md) ", line))
        }

    def _shipped(self, spec: str) -> set[str]:
        lines = _uncommented(spec)
        return {
            m.group(1) for line in lines if (m := re.match(r"%doc .*/docs/([a-z0-9-]+\.md)$", line))
        }

    def test_the_description_promises_at_least_two_docs(self, spec: str) -> None:
        """Non-vacuity. If the prose named nothing, every assertion below would pass emptily."""
        promised = self._promised(spec)
        assert "operations.md" in promised
        assert "client-setup.md" in promised

    def test_every_promised_doc_is_installed(self, spec: str) -> None:
        missing = self._promised(spec) - self._installed(spec)
        assert not missing, (
            f"%description points at {sorted(missing)} but %install does not place them in the "
            "buildroot. An operator following the package's own instruction finds nothing."
        )

    def test_every_promised_doc_is_in_the_payload(self, spec: str) -> None:
        missing = self._promised(spec) - self._shipped(spec)
        assert not missing, (
            f"%description points at {sorted(missing)} but no %doc entry ships them. An operator "
            "following the package's own instruction finds nothing."
        )

    def test_nothing_is_installed_without_being_shipped(self, spec: str) -> None:
        """The mirror. A file placed in the buildroot but absent from ``%files`` is dead work or,
        depending on rpm's strictness, an unpackaged-file build failure.
        """
        orphaned = self._installed(spec) - self._shipped(spec)
        assert not orphaned, f"installed but not in %files: {sorted(orphaned)}"

    def test_release_notes_are_deliberately_not_promised_or_shipped(self, spec: str) -> None:
        """``docs/release-notes.md`` exists in the tree and is shipped nowhere, on purpose.

        Asserted so its absence reads as a decision. The ``%description`` does not name it, so the
        contract is consistent; if it is ever promised, the tests above will require it to ship.
        """
        assert (_ROOT / "docs" / "release-notes.md").is_file()
        assert "release-notes.md" not in self._promised(spec)
        assert "release-notes.md" not in self._shipped(spec)
