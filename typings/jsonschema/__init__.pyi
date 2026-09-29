"""
Type Stubs for jsonschema

This module declares the part of ``jsonschema`` the property tests use. Unlike ``sl_mysql``
and ``MySQLdb``, ``jsonschema`` is installed here but ships no ``py.typed`` marker, so a strict
type checker treats it as untyped.

A narrow stub avoids both a blanket ``ignore_missing_imports`` override, which makes every symbol
``Any``, and a new ``types-jsonschema`` dependency. It declares exactly the three members
``tests/property/test_properties.py`` calls, so a test that needs more must extend this file.
"""

from collections.abc import Mapping
from typing import Any

class Draft202012Validator:
    def __init__(self, schema: Mapping[str, Any]) -> None: ...
    def is_valid(self, instance: object) -> bool: ...
    @classmethod
    def check_schema(cls, schema: Mapping[str, Any]) -> None: ...
