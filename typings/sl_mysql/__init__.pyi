"""
Type Stubs for sl_mysql

This module declares the narrow part of SL1's ``sl_mysql`` package that this service uses.
``sl_mysql`` ships as bytecode only on the appliance (under ``/opt/em7/lib/python3.12/sl_mysql/``)
and does not exist on a developer machine or in CI, so no type checker can introspect it.

A blanket ``ignore_missing_imports`` override would make every symbol reached through this package
``Any`` at every database call site. These stubs are the boundary contract for the surface this
service touches, not a model of the platform. Row values are typed ``object`` rather than ``Any``
so ``mypy --strict`` forces callers to narrow explicitly at the database boundary.
"""

from . import silo_cursor as silo_cursor

__all__ = ["silo_cursor"]
