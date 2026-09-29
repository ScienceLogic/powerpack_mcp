"""
Type Stubs for MySQLdb

This module declares the ``MySQLdb`` exception classes the database tools catch. On the
appliance ``MySQLdb`` (``mysqlclient``) lives in ``/opt/em7/lib/python3.12/MySQLdb/`` and reaches
``sys.path`` only through ``silo.pth``, so a type checker cannot see it off-appliance. It is
consumed from the platform tree and is deliberately not a declared dependency.

The distinction between the two exceptions caught matters:

- ``OperationalError`` with errno 1969 is ``max_statement_time`` firing. The server ends the
  query and leaves the connection clean and reusable, so it is classified as a timeout and the
  connection is kept.
- Any other ``OperationalError``, and any ``InterfaceError``, means the connection is suspect and
  it is discarded.

Getting that backwards would either discard healthy connections on every timeout or keep broken
ones.
"""

class MySQLError(Exception): ...
class Error(MySQLError): ...
class InterfaceError(Error): ...
class DatabaseError(Error): ...
class OperationalError(DatabaseError): ...
class ProgrammingError(DatabaseError): ...

threadsafety: int
apilevel: str
