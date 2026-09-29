"""
Service Entry Point

This module provides ``main()``, which loads configuration, builds the ASGI application and
serves it with uvicorn on the configured loopback listener. It is exposed both as the
``powerpack_mcp`` console script and, through ``__main__``, as ``python -m powerpack_mcp``.

The systemd unit uses ``venv/bin/python -m powerpack_mcp`` rather than the console script; see
``__main__`` for why. No code path resolves ``python3`` from ``PATH``, because the appliance's
system ``python3`` is 3.6.
"""

from __future__ import annotations

from typing import Final

import uvicorn

from powerpack_mcp.errors import ConfigurationError
from powerpack_mcp.mcp_app import create_app, start_up

__all__ = ["EXIT_CONFIG_ERROR", "main"]

# Process exit status for a configuration failure, as distinct from a crash.
#
# 78 is ``EX_CONFIG`` from BSD ``sysexits.h``. The obvious alternatives are taken: 1 is Python's
# unhandled-exception status (which is exactly what this must be distinguishable from), 1-7 are LSB
# init-script conventions, and 200-242 are reserved by systemd. The unit sets
# ``RestartPreventExitStatus=78``, so a bad configuration stops the service instead of restarting
# it every few seconds.
EXIT_CONFIG_ERROR: Final = 78


def main() -> None:
    """Start the service and serve it until shutdown.

    Startup runs through ``start_up``, the same function ``create_app`` uses, so logging is
    configured before configuration is loaded and a configuration failure is itself logged as a
    structured ``startup_failed`` event. The resolved configuration is passed to ``create_app``
    so it is read only once. The listener host is guaranteed to be a loopback address; a routable
    value raises ``ConfigurationError`` and the service refuses to start.

    :raises SystemExit: With status ``EXIT_CONFIG_ERROR`` when the configuration is invalid.
    """
    # Convert a configuration error into exit status 78 here, at the entry point, and nowhere else.
    # ``start_up`` and ``create_app`` are also called from tests and as a library, where a
    # ``sys.exit`` would terminate the caller.
    #
    # Only ``ConfigurationError`` maps to 78. Any other failure is a crash and must keep status 1
    # so systemd's ``Restart=on-failure`` recovers it. ``start_up`` has already logged the error
    # with ``exc_info``; ``from None`` only suppresses the duplicate unstructured traceback that
    # would otherwise reach stderr and syslog.
    try:
        config = start_up(None)
        app = create_app(config)
    except ConfigurationError:
        raise SystemExit(EXIT_CONFIG_ERROR) from None
    uvicorn.run(
        app,
        host=config.LISTEN_HOST,
        port=config.LISTEN_PORT,
        # The service installs its own log handlers. uvicorn's default dictConfig would replace
        # the root handler and drop the correlation filter, so it is disabled rather than merged.
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    main()
