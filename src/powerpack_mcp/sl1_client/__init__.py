"""
SL1 Client Package

This package provides the transport for SL1's REST and GraphQL APIs. It mirrors the layout of
``lce_client`` but is deliberately kept separate from it: a shared transport abstraction would
mean reworking the proven ``LceClient`` for a symmetry nothing needs.
"""

from __future__ import annotations

from powerpack_mcp.sl1_client.bounded_read import read_json_within_limit
from powerpack_mcp.sl1_client.client import GRAPHQL_PATH, SL1_API_BASE_PATH, Sl1Client
from powerpack_mcp.sl1_client.paths import ensure_relative_path, is_safe_relative_path

__all__ = [
    "GRAPHQL_PATH",
    "SL1_API_BASE_PATH",
    "Sl1Client",
    "ensure_relative_path",
    "is_safe_relative_path",
    "read_json_within_limit",
]
