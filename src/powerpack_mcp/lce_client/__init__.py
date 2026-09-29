"""
LCE HTTP Client Package

This package provides the HTTP client for the LCE service: ``LceClient.request``, the
``LceResponse`` it returns, and the validated ``TargetHost`` destination type.
``is_valid_target_host`` is exported so the host predicate can be tested directly.
"""

from __future__ import annotations

from powerpack_mcp.lce_client.client import (
    LCE_BASE_PATH,
    LceClient,
    LceResponse,
)
from powerpack_mcp.lce_client.target_host import (
    MAX_TARGET_HOST_LENGTH,
    TARGET_HOST_PATTERN,
    TargetHost,
    is_valid_target_host,
)

__all__ = [
    "LCE_BASE_PATH",
    "MAX_TARGET_HOST_LENGTH",
    "TARGET_HOST_PATTERN",
    "LceClient",
    "LceResponse",
    "TargetHost",
    "is_valid_target_host",
]
