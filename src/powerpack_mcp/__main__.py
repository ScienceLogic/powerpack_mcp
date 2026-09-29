"""
Module Entry Point

This module lets ``python -m powerpack_mcp`` start the service, and it is what the systemd unit
runs:

    ExecStart=/opt/em7/services/powerpack-mcp/venv/bin/python -m powerpack_mcp

A venv built inside an RPM buildroot bakes the buildroot path into every console script's
shebang, so ``venv/bin/powerpack_mcp`` can fail with ``bad interpreter`` once installed.
``venv/bin/python`` is a symlink with no shebang, which makes this invocation immune to that
problem. The same convention is used by the other em7 Python services. The venv is still built
with ``uv venv --relocatable`` so the console script also works for manual use.

``main()`` is imported rather than reimplemented, so the two entry points cannot drift.
"""

from __future__ import annotations

from powerpack_mcp.main import main

if __name__ == "__main__":
    main()
