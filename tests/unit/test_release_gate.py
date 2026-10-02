"""
Release Gate Tests

This module tests the release gate in ``packaging.yml``: a push to ``main`` builds the release RPM
only after a successful ``integration`` run exists for the same source tree, and that workflow
runs the live suite with ``MCP_IT_REQUIRED=1`` so an unconfigured run fails rather than passing by
testing nothing. The gate's script is executed exactly as written in the workflow, against a local
stand-in for the GitHub API.

The internal workflows and the live suite are not part of the public export, so every test here
skips when the file it reads is absent.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

_ROOT = Path(__file__).resolve().parents[2]
PACKAGING_WORKFLOW = _ROOT / ".github" / "workflows" / "packaging.yml"
INTEGRATION_WORKFLOW = _ROOT / ".github" / "workflows" / "integration.yml"
INTEGRATION_CONFTEST = _ROOT / "tests" / "integration" / "conftest.py"


def _require(path: Path) -> str:
    if not path.is_file():
        pytest.skip(f"{path.relative_to(_ROOT)} is not in this copy (internal only)")
    return path.read_text()


def _gate_script() -> str:
    """The Python the release-gate job runs, cut from its heredoc and dedented."""
    text = _require(PACKAGING_WORKFLOW)
    job = text.split("\n  release-gate:\n", 1)[1]
    body = job.split("<<'PY'\n", 1)[1].split("\n          PY\n", 1)[0]
    return "\n".join(line.removeprefix("          ") for line in body.splitlines()) + "\n"


def _head_sha() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=_ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


class _FakeApi(BaseHTTPRequestHandler):
    runs: ClassVar[list[dict[str, Any]]] = []
    paths: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        type(self).paths.append(self.path)
        body = json.dumps({"workflow_runs": type(self).runs}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - the base's name
        """Quiet."""


@pytest.fixture
def api() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), _FakeApi)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        _FakeApi.runs = []
        _FakeApi.paths = []


def _run_gate(api_url: str) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "GITHUB_API_URL": api_url,
        "GITHUB_REPOSITORY": "example-org/powerpack_mcp",
        "GITHUB_TOKEN": "test-token",
    }
    return subprocess.run(
        [sys.executable, "-c", _gate_script()],
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _run(sha: str, conclusion: str = "success") -> dict[str, Any]:
    return {
        "head_sha": sha,
        "head_branch": "develop",
        "conclusion": conclusion,
        "html_url": f"https://example.invalid/runs/{sha[:7]}",
    }


class TestTheGateScript:
    @pytest.fixture(autouse=True)
    def _needs_the_workflow(self) -> None:
        # Skip before anything runs git: the public export has neither the workflow nor, unless
        # initialised, a repository.
        _require(PACKAGING_WORKFLOW)

    def test_a_successful_run_on_this_tree_passes(self, api: str) -> None:
        _FakeApi.runs = [_run(_head_sha())]
        done = _run_gate(api)
        assert done.returncode == 0, done.stdout + done.stderr
        assert done.stdout.startswith("PASS")
        # It asks only for successful runs of the integration workflow.
        expected = (
            "/repos/example-org/powerpack_mcp/actions/workflows/integration.yml/runs"
            "?status=success&per_page=100"
        )
        assert _FakeApi.paths == [expected]

    def test_no_run_fails_and_says_what_to_do(self, api: str) -> None:
        done = _run_gate(api)
        assert done.returncode == 1
        assert "Dispatch the integration workflow" in done.stdout

    def test_a_run_that_did_not_succeed_does_not_count(self, api: str) -> None:
        _FakeApi.runs = [_run(_head_sha(), conclusion="failure")]
        assert _run_gate(api).returncode == 1

    def test_a_run_on_a_different_tree_does_not_count(self, api: str) -> None:
        # A commit with a different tree, built with plumbing rather than taken from history: CI
        # checks out one commit, so HEAD~1 need not exist. ``commit-tree`` writes a loose object
        # and touches no ref.
        empty_tree = subprocess.run(
            ["git", "mktree"], cwd=_ROOT, input="", capture_output=True, text=True, check=True
        ).stdout.strip()
        identity = {
            "GIT_AUTHOR_NAME": "release-gate-test",
            "GIT_AUTHOR_EMAIL": "release-gate-test@example.invalid",
            "GIT_COMMITTER_NAME": "release-gate-test",
            "GIT_COMMITTER_EMAIL": "release-gate-test@example.invalid",
        }
        other = subprocess.run(
            ["git", "commit-tree", empty_tree, "-m", "a different tree"],
            cwd=_ROOT,
            env={**os.environ, **identity},
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        _FakeApi.runs = [_run(other)]
        assert _run_gate(api).returncode == 1

    def test_an_unknown_commit_does_not_count(self, api: str) -> None:
        _FakeApi.runs = [_run("0" * 40)]
        assert _run_gate(api).returncode == 1


class TestTheWiring:
    def test_the_rpm_job_waits_for_the_gate_without_being_skipped_by_it(self) -> None:
        rpm = _require(PACKAGING_WORKFLOW).split("\n  rpm:\n", 1)[1].split("\n    steps:\n", 1)[0]
        assert "needs: release-gate" in rpm
        assert "needs.release-gate.result == 'success'" in rpm
        assert "needs.release-gate.result == 'skipped'" in rpm
        assert "!cancelled()" in rpm

    def test_the_gate_runs_only_for_a_push_to_main(self) -> None:
        job = _require(PACKAGING_WORKFLOW).split("\n  release-gate:\n", 1)[1]
        first_line = job.splitlines()[0]
        assert "github.event_name == 'push'" in first_line
        assert "github.ref == 'refs/heads/main'" in first_line

    def test_the_integration_workflow_runs_the_suite_as_required(self) -> None:
        assert "MCP_IT_REQUIRED=1" in _require(INTEGRATION_WORKFLOW)


class TestARequiredRunFailsInsteadOfSkipping:
    """An unconfigured suite skips, unless the run is a gate run, where it must fail.

    The probe file is written into ``tests/integration`` so it picks up that directory's
    ``conftest.py`` and its ``it_settings`` fixture, and is removed afterwards.
    """

    @pytest.mark.parametrize(
        ("required", "expected", "exit_code"), [("1", "1 error", 1), ("", "1 skipped", 0)]
    )
    def test_unconfigured(
        self, tmp_path: Path, required: str, expected: str, exit_code: int
    ) -> None:
        _require(INTEGRATION_CONFTEST)
        target = _ROOT / "tests" / "integration" / f"test_zz_required_probe_{os.getpid()}.py"
        target.write_text(
            "import pytest\n\n"
            "@pytest.mark.integration\n"
            "def test_needs_settings(it_settings):\n"
            "    pass\n"
        )
        try:
            env = {k: v for k, v in os.environ.items() if not k.startswith("MCP_IT_")}
            env["MCP_IT_ENV_FILE"] = str(tmp_path / "absent.env")
            env["MCP_IT_REQUIRED"] = required
            done = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    str(target),
                    "-m",
                    "integration",
                    "-q",
                    "--no-cov",
                    "-p",
                    "no:cacheprovider",
                ],
                cwd=_ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        finally:
            target.unlink(missing_ok=True)
        assert expected in done.stdout, done.stdout + done.stderr
        assert done.returncode == exit_code, done.stdout
        if required:
            assert "MCP_IT_REQUIRED is set" in done.stdout
