"""
Skylar One PowerPack MCP

This module is the package root. It exposes ``__version__``, read from the installed package
metadata, or ``0.0.0+unknown`` when the package is not installed.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("powerpack-mcp")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
