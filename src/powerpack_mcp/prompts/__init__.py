"""
MCP Prompts

This module re-exports what ``mcp_app.app`` needs to register the MCP prompts, plus the content
accessors the tests use.

Prompts touch no backend at all: no LCE, REST, GraphQL, database or credential. They are static
text assembled at call time, so ``register_prompts`` takes no configuration and returns no plan.
See ``content`` for how the rules text is assembled and ``registry`` for the prompts themselves.
"""

from __future__ import annotations

from powerpack_mcp.prompts.content import (
    GUIDE_TOPICS,
    GuideTopic,
    MarkdownSection,
    api_guide_topics,
    build_guide_topic,
    framework_rules,
)
from powerpack_mcp.prompts.registry import PROMPT_NAMES, register_prompts

__all__ = [
    "GUIDE_TOPICS",
    "PROMPT_NAMES",
    "GuideTopic",
    "MarkdownSection",
    "api_guide_topics",
    "build_guide_topic",
    "framework_rules",
    "register_prompts",
]
