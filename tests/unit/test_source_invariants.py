"""
Source Invariant Tests

This module tests rules about the shipped source that are checked mechanically rather than by
review: no connection parameters on the DB connection path, no tool that accepts SQL, no
``sql_quote()``, no use of the platform connection cache, ``isdecimal()`` rather than
``isdigit()``, and the survival of ``authz.registry_entry``.

The checks are AST- and token-based, not text searches. Every rule is discussed in prose in the
module it constrains, so a plain ``"host=" in source`` search would match the comment explaining
that no host is passed and pass for the wrong reason. Comments and string literals are stripped
before matching, and the ``local_db()`` check reads the call node's arguments.
"""

from __future__ import annotations

import ast
import io
import tokenize
from pathlib import Path

from powerpack_mcp import authz, db_client
from powerpack_mcp.tools import sl1_db_registry as reg

SRC = Path(db_client.__file__).parent


def code_only(path: Path) -> str:
    """``path``'s source with comments and string literals removed.

    Both matter. Comments carry the prose discussing these rules, and string literals carry the
    docstrings, which can mention almost anything. Dropping both leaves identifiers and operators,
    the only place a violation could actually live.
    """
    out: list[str] = []
    for tok in tokenize.generate_tokens(io.StringIO(path.read_text()).readline):
        if tok.type in (tokenize.COMMENT, tokenize.STRING):
            continue
        out.append(tok.string)
    return " ".join(out)


def shipped_modules() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py") if p.name != "__pycache__")


class TestNoConnectionParameters:
    """No host, port, user or password is ever passed on the connection path.

    The connection must be obtained through ``local_db()`` and never constructed. Passing
    ``host="localhost"`` would route around the platform's own `silo.conf` resolution and could
    reach a different database than the one the appliance intends.
    """

    def test_every_local_db_call_passes_no_arguments(self) -> None:
        """Asserted on the call node, not on text: the strongest available form.

        A text search for ``host=`` would match `db_client.py`'s own docstring explaining that no
        host is passed. This reads the AST, so it cannot.
        """
        offenders: list[str] = []
        for path in shipped_modules():
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = (
                    func.attr
                    if isinstance(func, ast.Attribute)
                    else func.id
                    if isinstance(func, ast.Name)
                    else None
                )
                if name == "local_db" and (node.args or node.keywords):
                    offenders.append(f"{path.name}:{node.lineno}")
        assert not offenders, (
            f"local_db() called with arguments; the platform reads them from silo.conf: {offenders}"
        )

    def test_no_connection_keyword_appears_in_the_db_client_code(self) -> None:
        """The wider form: none of the four parameter names appears as a keyword in `db_client`.

        Scoped to `db_client` deliberately. ``host``, ``port`` and ``user`` are ordinary words
        elsewhere in the service: `config` has a `LISTEN_HOST`, and the SL1 client takes a host.
        This rule is about the connection path, and widening it would produce a test that had to be
        weakened later.
        """
        code = code_only(Path(db_client.__file__))
        for keyword in ("host =", "port =", "passwd =", "password ="):
            assert keyword not in code, (
                f"{keyword!r} appears in db_client's code (not its comments). The service must not "
                "supply connection parameters; the platform resolves them from silo.conf"
            )


class TestNoToolAcceptsSql:
    """No tool accepts SQL, checked by signature inspection over every registering tool.

    A new tool taking SQL fails this test. String-built SQL is forbidden outright, and a tool
    taking a `sql` or `where` argument would hand a caller the one capability `sl1_db_statements`
    exists to deny them.
    """

    # Names that would mean a caller supplies SQL, or a fragment of it. ``where`` and ``order_by``
    # are included because the reference implementation interpolated exactly those as fragments,
    # which cannot be parameterised and must be restructured instead.
    FORBIDDEN = frozenset(
        {
            "sql",
            "query",
            "statement",
            "stmt",
            "where",
            "where_clause",
            "order_by",
            "orderby",
            "filter_sql",
            "raw",
            "raw_sql",
            "expression",
            "expr",
        }
    )

    def test_no_registering_tool_takes_a_sql_shaped_parameter(self) -> None:
        """Inspected on the built coroutine, so it covers what a caller can actually send."""
        import inspect

        from tests.unit.test_sl1_db_tools import make_context

        offenders: list[str] = []
        for set_id in authz.REGISTRY_TOOL_SETS:
            for descriptor, factory in reg.tools_for_set(set_id):
                tool = factory(make_context())
                offenders.extend(
                    f"{descriptor.tool_name}({param})"
                    for param in inspect.signature(tool).parameters
                    if param.lower() in self.FORBIDDEN
                )
        assert not offenders, (
            f"tools accept SQL-shaped parameters; no tool may accept SQL: {offenders}"
        )

    def test_the_check_would_catch_a_violation(self) -> None:
        """Non-vacuity, asserted rather than assumed.

        A signature-inspection test that silently inspected nothing would pass forever. This proves
        the forbidden set actually matches, and the loop above proves it runs over 22 tools.
        """
        assert "sql" in self.FORBIDDEN
        assert sum(len(reg.tools_for_set(s)) for s in authz.REGISTRY_TOOL_SETS) == 22


class TestSqlQuoteIsAbsent:
    """`sql_quote()` is not ported, reimplemented, or wrapped.

    The reference implementation built every statement by interpolating `sql_quote()` output into
    f-strings. This service uses parameterised builders instead, so this asserts the absence.
    """

    def test_no_shipped_module_defines_or_calls_sql_quote(self) -> None:
        offenders = [p.name for p in shipped_modules() if "sql_quote" in code_only(p)]
        assert not offenders, (
            f"sql_quote appears in shipped code; use bound parameters instead: {offenders}. "
            "It is discussed in comments deliberately; this test strips those, so a hit is real."
        )

    def test_the_prose_discussing_it_does_not_satisfy_this_test(self) -> None:
        """Proves the comment-stripping is what makes the test above meaningful.

        `sql_quote` is named in `sl1_db_statements`' docstring, on purpose. If `code_only` failed to
        strip docstrings, the test above would fail rather than pass vacuously; this pins the
        mechanism explicitly, because a future refactor of `code_only` could invert it.
        """
        statements = SRC / "tools" / "sl1_db_statements.py"
        assert "sql_quote" in statements.read_text(), "expected the rule to be discussed in prose"
        assert "sql_quote" not in code_only(statements)


class TestCredentialInTheCacheKey:
    """The platform connection cache keys on a tuple containing the plaintext DB password.

    The platform's ``connect_cache`` uses ``hashkey(**kwds)``, so the key holds ``db``, ``host``,
    ``passwd``, ``port`` and ``user`` in clear. Redaction is not an answer: the credential is in the
    key, so value-level redaction cannot reach it. The only safe posture is never to touch the
    object, which is what this asserts. This service never populates that cache.
    """

    def test_no_shipped_module_references_the_platform_connection_cache(self) -> None:
        offenders: list[str] = []
        for path in shipped_modules():
            code = code_only(path)
            if "connect_cache" in code or "sl_connex" in code:
                offenders.append(path.name)
        assert not offenders, f"platform connection cache referenced in shipped code: {offenders}"

    def test_the_rule_is_documented_where_it_applies(self) -> None:
        """The rule is prose in `db_client`, and that is correct, but prose is not the assertion.

        Pinned so that deleting the explanation is visible, since the explanation is the only thing
        telling a future reader why the absence above matters.
        """
        assert "connect_cache" in Path(db_client.__file__).read_text()


class TestTheInvariantHelperItself:
    """`code_only` is load-bearing for four rules, so it gets its own tests.

    If it silently returned everything, three of the tests above would still pass: they assert
    absence, and absence in a larger string is a stronger claim. But if it returned nothing, all
    four would pass vacuously. That second failure mode is the one worth pinning.
    """

    def test_it_strips_comments_and_docstrings_but_keeps_code(self, tmp_path: Path) -> None:
        sample = tmp_path / "sample.py"
        sample.write_text(
            '"""A docstring mentioning sql_quote and connect_cache."""\n'
            "# A comment mentioning host = 1\n"
            "value = compute(alpha)\n"
        )
        code = code_only(sample)
        assert "sql_quote" not in code
        assert "connect_cache" not in code
        assert "value" in code
        assert "compute" in code
        assert "alpha" in code

    def test_it_returns_something_for_every_shipped_module(self) -> None:
        """The vacuity guard: an empty return would make every absence assertion meaningless."""
        for path in shipped_modules():
            assert code_only(path).strip(), f"{path.name} produced no code text"

    def test_it_covers_the_whole_package(self) -> None:
        modules = shipped_modules()
        assert len(modules) > 20, f"only {len(modules)} modules found; the sweep is too narrow"
        assert any(p.name == "db_client.py" for p in modules)
        assert any(p.name == "authz.py" for p in modules)


def isdigit_call_sites(path: Path) -> list[int]:
    """Line numbers of every ``<expr>.isdigit()`` call in ``path``.

    An AST walk, not a text search: the word ``isdigit`` appears in pointer comments at each fixed
    site and in a long note in `coded()`'s docstring explaining why it must never come back, so a
    substring scan would fail against the fixed code. Matching the call node sees only real calls,
    and reports where they are, which makes a failure actionable.
    """
    tree = ast.parse(path.read_text())
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "isdigit"
    ]


class TestIsdecimalNotIsdigit:
    """A numeric branch selected by ``isdigit()`` crashes in ``int()``.

    ``"²".isdigit()`` is ``True`` and ``int("²")`` raises ``ValueError``. `sl1_tool_boundary`
    translates `PowerPackMcpError` and nothing else, so that error escapes the boundary unhandled.
    The Hypothesis ``ci`` profile found this at 500 examples; the ``dev`` profile's 50 did not.

    Measured over all 1,114,112 code points: ``isdecimal`` implies ``isdigit`` with zero
    exceptions, and ``int()`` raises on all 128 characters where they differ. So the swap can only
    remove from the numeric branch inputs that already crashed.

    The regression risk is someone retyping ``isdigit()``, from habit or to match the platform
    source, which does use ``sv.isdigit()``. Ten sites were wrong at once, so a comment is not
    enough. This is the mechanical guard.
    """

    def test_no_shipped_module_calls_isdigit(self) -> None:
        offenders = {
            path.name: lines for path in shipped_modules() if (lines := isdigit_call_sites(path))
        }
        assert not offenders, (
            f"`isdigit()` is called in shipped code. Use `isdecimal()`: "
            f"`isdigit()` is True for 128 characters `int()` rejects. Sites: {offenders}"
        )

    def test_the_prose_explaining_the_rule_does_not_satisfy_this_test(self) -> None:
        """Proves the check is not passing merely because the word is absent.

        If this assertion ever fails, the pointer comments have been deleted and the next person to
        touch these selectors has nothing telling them why `isdigit()` is wrong.
        """
        mentions = sum("isdigit" in path.read_text() for path in shipped_modules())
        assert mentions >= 3, (
            f"only {mentions} shipped modules still explain the isdigit/isdecimal rule; "
            "the guard would then be green for the wrong reason"
        )

    def test_the_check_would_catch_a_violation(self, tmp_path: Path) -> None:
        violation = tmp_path / "v.py"
        violation.write_text("def f(s: str) -> bool:\n    return s.isdigit()\n")
        assert isdigit_call_sites(violation) == [2]

    def test_a_comment_or_docstring_mentioning_isdigit_is_not_a_violation(
        self, tmp_path: Path
    ) -> None:
        """The exact false positive a substring scan would produce against the fixed code."""
        clean = tmp_path / "c.py"
        clean.write_text(
            '"""Use isdecimal, never isdigit."""\n'
            "def f(s: str) -> bool:\n"
            "    # isdigit() is wrong here\n"
            "    return s.isdecimal()\n"
        )
        assert isdigit_call_sites(clean) == []
        assert "isdigit" in clean.read_text()


def typed_error_raise_sites(path: Path, exc_name: str) -> list[tuple[str, int]]:
    """Every ``raise <exc_name>(...)`` in ``path``, as ``(enclosing function, line)``.

    AST rather than a substring scan, because the prose in `registry_entry`'s docstring
    names ``DbToolNotRegistered`` repeatedly, and a grep would count every mention.
    """
    tree = ast.parse(path.read_text())
    enclosing: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for child in ast.walk(node):
                enclosing.setdefault(id(child), node.name)
    sites: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Raise) or node.exc is None:
            continue
        exc = node.exc
        func = exc.func if isinstance(exc, ast.Call) else exc
        name = func.id if isinstance(func, ast.Name) else None
        if name == exc_name:
            sites.append((enclosing.get(id(node), "<module>"), node.lineno))
    return sites


class TestRegistryEntryIsUnreachableButNormative:
    """A tripwire so `authz.registry_entry` cannot be swept away as dead code.

    `registry_entry` has zero callers in `src/`, which is exactly what a dead-code tool reports.
    But it is the sole implementation of deny-by-default tool lookup and its refusal log record,
    and the only ``raise DbToolNotRegistered`` in `src/`, so it is the only thing that makes the
    typed refusal error reachable. It is kept, documented as unreachable but normative.

    The ordinary safety nets do not cover this. Deleting the function would take its tests with
    it (in `test_authz.py` and `tests/property/test_properties.py`), so the suite would stay green.
    Coverage would not flag it either: removing code and its tests together raises the percentage.
    This file is the one place that fails because the function is gone.
    """

    def test_the_sole_raiser_of_the_typed_error_still_exists(self) -> None:
        """The typed error is reachable only through this one `raise`."""
        sites = typed_error_raise_sites(SRC / "authz.py", "DbToolNotRegistered")
        why = (
            f"authz.py must contain exactly one `raise DbToolNotRegistered`, inside "
            f"`registry_entry` -- found {sites!r}. If you deleted it, you also deleted the only "
            "implementation of the deny-by-default tool lookup and its logged refusal."
        )
        assert len(sites) == 1, why
        assert sites[0][0] == "registry_entry", why

    def test_the_do_not_delete_rationale_travels_with_the_function(self) -> None:
        """The warning must live at the function, because that is where a deletion starts.

        Asserted against the docstring, deliberately: unlike this file's other guards, the thing
        being protected here is documentation, which `code_only()` would strip.
        """
        source = (SRC / "authz.py").read_text()
        for marker in ("Do not delete it as dead code", "deny-by-default", "DbToolNotRegistered"):
            assert marker in source, (
                f"authz.py no longer records {marker!r}. The unreachable-but-normative status of "
                "registry_entry must stay documented where someone about to remove it will read it."
            )

    def test_the_guard_would_catch_the_deletion(self, tmp_path: Path) -> None:
        """Non-vacuity: a module with the function removed reports no raise sites."""
        gutted = tmp_path / "g.py"
        gutted.write_text(
            '"""DbToolNotRegistered is only mentioned in prose here."""\n'
            "def registry_entry(name: str) -> None:\n"
            "    return None\n"
        )
        assert typed_error_raise_sites(gutted, "DbToolNotRegistered") == []
        assert "DbToolNotRegistered" in gutted.read_text()

    def test_it_is_still_genuinely_unreachable_from_src(self) -> None:
        """The function's unreachability must be re-checked, not assumed.

        No shipped path runs this lookup ahead of the pipeline's payload checks, so there is no
        requirement that a refused call skip the parse and validation cost. A new production caller
        would make that requirement live again. If this test fails, revisit that decision rather
        than editing the expectation.
        """
        callers = [
            path.name
            for path in shipped_modules()
            if path.name != "authz.py" and "registry_entry" in code_only(path)
        ]
        assert callers == [], (
            f"registry_entry now has production callers: {callers}. It was documented as "
            "unreachable, and a refused call was allowed to pay the parse and validation cost "
            "on that basis -- both need revisiting."
        )
