"""
GraphQL Executable Document Scanner

This module lexes and parses a GraphQL executable document into a small syntax tree -- operations,
fragment definitions, selections, arguments and values -- and a flattened summary of it: every
field name (with its alias and argument names), every name token, input-object key, enum value and
string literal. ``sl1_credential_guard`` walks the tree to refuse documents that would read
credential secrets, before anything is sent to SL1.

It is self-contained because the service ships as an RPM onto appliances and ``graphql-core`` is
not available there. It follows the GraphQL specification's lexical grammar (October 2021 edition)
and its executable-definition grammar, and it is stricter than a server, on purpose: anything it
does not recognise raises ``GraphQlSyntaxError``, and the guard refuses the document. A scanner
that guessed would let a document the server reads one way be classified the other way.

The places where a lenient scanner would disagree with the server, and how each is handled:

- Comments run to the next ``\\n`` or ``\\r`` and no further. A comment that ran longer than the
  server's would hide real selections from the guard, so any other line-terminator-like character
  (U+0085, U+2028, U+2029) or control character inside a comment is a syntax error rather than a
  guess.
- Strings end at the first unescaped ``"``; block strings at the first ``\"\"\"`` not preceded by a
  backslash, scanned character by character exactly as the reference implementation does, so
  ``\\\\\"\"\"`` is an escaped triple quote and not a terminator.
- Names are ASCII only. GraphQL names cannot contain escapes, so there is no encoding in which a
  field name can be spelled that this scanner does not see as itself.
- Commas, spaces, tabs, line terminators and the byte-order mark are ignored tokens, wherever they
  appear.
- Type-system definitions, descriptions and fragment variables are refused: none is executable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

__all__ = [
    "Argument",
    "DocumentSummary",
    "FieldSelection",
    "FragmentDefinition",
    "FragmentSpread",
    "GraphQlSyntaxError",
    "InlineFragment",
    "Operation",
    "Selection",
    "Token",
    "TokenKind",
    "Value",
    "ValueKind",
    "VariableDefinition",
    "summarize_executable_document",
    "tokenize",
]

# Single-character punctuators. ``...`` is the only multi-character one and is handled apart.
_PUNCTUATORS: Final[frozenset[str]] = frozenset("!$&()=:@[]{|}")

# Ignored tokens other than comments and line terminators. The BOM is ignored anywhere, as the
# specification's ``UnicodeBOM`` production says, not only at the start.
_IGNORED: Final[frozenset[str]] = frozenset({" ", "\t", ",", "\ufeff"})

_LINE_TERMINATORS: Final[frozenset[str]] = frozenset({"\n", "\r"})

# Characters some line-oriented tools treat as line breaks and GraphQL does not. Inside a comment
# they are refused: if any server ended a comment at one, the text after it would be live there and
# a comment here.
_AMBIGUOUS_BREAKS: Final[frozenset[str]] = frozenset({"\x85", "\u2028", "\u2029"})

_NAME_START: Final[frozenset[str]] = frozenset(
    "_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_NAME_CONTINUE: Final[frozenset[str]] = _NAME_START | frozenset("0123456789")
_DIGITS: Final[frozenset[str]] = frozenset("0123456789")
_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdefABCDEF")

_SIMPLE_ESCAPES: Final[dict[str, str]] = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}

_OPERATION_TYPES: Final[frozenset[str]] = frozenset({"query", "mutation", "subscription"})

# How deeply selection sets, values and types may nest. Real documents are a few levels deep; the
# bound exists so that a hostile document raises ``GraphQlSyntaxError`` (and is refused) rather
# than exhausting Python's recursion limit.
MAX_NESTING: Final = 64

# A ceiling on the token count, for the same reason. The service's request-size limits bound the
# document already; this keeps the scan's own cost bounded independently of them.
MAX_TOKENS: Final = 100_000


def _is_surrogate(char: str) -> bool:
    """Return whether ``char`` is a lone surrogate, which JSON can deliver and GraphQL forbids.

    The reference lexer ends a comment at one and rejects one in a string. Refusing it everywhere
    here keeps the two from disagreeing about where a comment ends.
    """
    return "\ud800" <= char <= "\udfff"


class GraphQlSyntaxError(ValueError):
    """The document is not a GraphQL executable document this scanner recognises.

    The message carries a position and a reason, never document text: the document is caller
    input, and quoting it into an error that may be logged is how log forging starts.

    :ivar line: 1-based line of the problem.
    :ivar column: 1-based column of the problem.
    :ivar reason: What was wrong, in words.
    """

    def __init__(self, reason: str, line: int, column: int) -> None:
        self.reason = reason
        self.line = line
        self.column = column
        super().__init__(f"{reason} (line {line}, column {column})")


class TokenKind(StrEnum):
    """The lexical token kinds the parser consumes. Ignored tokens are never emitted."""

    PUNCTUATOR = "punctuator"
    NAME = "name"
    INT = "int"
    FLOAT = "float"
    STRING = "string"
    BLOCK_STRING = "block_string"
    EOF = "eof"


@dataclass(frozen=True, slots=True)
class Token:
    """One lexical token.

    :ivar kind: The token kind.
    :ivar value: The punctuator or name text, the number's text, or a string's decoded content.
    :ivar line: 1-based line of the token's first character.
    :ivar column: 1-based column of the token's first character.
    """

    kind: TokenKind
    value: str
    line: int
    column: int


class ValueKind(StrEnum):
    """The value forms the guard tells apart. Numbers, booleans and ``null`` are all ``SCALAR``."""

    SCALAR = "scalar"
    STRING = "string"
    ENUM = "enum"
    VARIABLE = "variable"
    LIST = "list"
    OBJECT = "object"


@dataclass(frozen=True, slots=True)
class Value:
    """One input value.

    :ivar kind: The value form.
    :ivar text: A string's decoded content, an enum value's name, a variable's name (without
        ``$``) or a scalar's text; empty for lists and objects.
    :ivar items: A list's members.
    :ivar fields: An input object's ``(key, value)`` pairs, in order.
    """

    kind: ValueKind
    text: str = ""
    items: tuple[Value, ...] = ()
    fields: tuple[tuple[str, Value], ...] = ()


@dataclass(frozen=True, slots=True)
class Argument:
    """One argument of a field or directive.

    :ivar name: The argument name.
    :ivar value: Its value.
    """

    name: str
    value: Value


@dataclass(frozen=True, slots=True)
class FieldSelection:
    """One field selection, wherever it occurs: an operation, a fragment, an inline fragment.

    :ivar name: The field's real name: for ``alias: name``, the token after the colon.
    :ivar alias: The alias, or ``None``.
    :ivar argument_names: The names of the field's arguments, in order.
    :ivar line: 1-based line of the field.
    :ivar column: 1-based column of the field.
    :ivar arguments: The field's arguments, with their values.
    :ivar selections: The field's own selection set; empty for a leaf.
    :ivar directive_arguments: The arguments of the field's directives, flattened.
    """

    name: str
    alias: str | None
    argument_names: tuple[str, ...]
    line: int
    column: int
    arguments: tuple[Argument, ...] = ()
    selections: tuple[Selection, ...] = ()
    directive_arguments: tuple[Argument, ...] = ()


@dataclass(frozen=True, slots=True)
class FragmentSpread:
    """A ``...Name`` spread. Its name is a fragment's, never a field's.

    :ivar name: The spread fragment's name.
    :ivar directive_arguments: The arguments of the spread's directives, flattened.
    """

    name: str
    directive_arguments: tuple[Argument, ...] = ()


@dataclass(frozen=True, slots=True)
class InlineFragment:
    """A ``... on Type { }`` or ``... { }`` inline fragment.

    :ivar type_condition: The type named after ``on``, or ``None``.
    :ivar selections: The fragment's selection set.
    :ivar directive_arguments: The arguments of the fragment's directives, flattened.
    """

    type_condition: str | None
    selections: tuple[Selection, ...]
    directive_arguments: tuple[Argument, ...] = ()


# A selection set's members.
type Selection = FieldSelection | FragmentSpread | InlineFragment


@dataclass(frozen=True, slots=True)
class VariableDefinition:
    """One ``$name: Type = default`` in an operation's header.

    :ivar name: The variable name, without ``$``.
    :ivar default: The default value, or ``None``.
    """

    name: str
    default: Value | None


@dataclass(frozen=True, slots=True)
class Operation:
    """One operation, including the anonymous ``{ ... }`` shorthand.

    :ivar operation_type: ``query``, ``mutation`` or ``subscription``.
    :ivar name: The operation name, or ``None``.
    :ivar variables: The variable definitions.
    :ivar selections: The top-level selection set.
    :ivar directive_arguments: The arguments of the operation's directives, flattened.
    """

    operation_type: str
    name: str | None
    variables: tuple[VariableDefinition, ...]
    selections: tuple[Selection, ...]
    directive_arguments: tuple[Argument, ...] = ()


@dataclass(frozen=True, slots=True)
class FragmentDefinition:
    """One ``fragment Name on Type { }`` definition.

    :ivar name: The fragment name.
    :ivar type_condition: The type named after ``on``.
    :ivar selections: The fragment's selection set.
    :ivar directive_arguments: The arguments of the fragment's directives, flattened.
    """

    name: str
    type_condition: str
    selections: tuple[Selection, ...]
    directive_arguments: tuple[Argument, ...] = ()


@dataclass(slots=True)
class DocumentSummary:
    """A parsed document: its definitions as a tree, and what it names, flattened.

    The flattened lists cover every operation and fragment, whichever ``operationName`` selects at
    request time; an over-approximation of what one execution can select, which is the safe
    direction for a guard. The tree (``operations``, ``fragments``) is what lets the guard tell
    which selection sits under which field.

    :ivar fields: Every field selection, in document order, parents before their children.
    :ivar names: Every name token in the document, in any position.
    :ivar object_field_names: Every key of an input-object literal, in arguments and defaults.
    :ivar string_values: Every string literal's decoded content.
    :ivar enum_values: Every enum value (a bare name in value position other than ``true``,
        ``false`` and ``null``), in arguments and in variable defaults.
    :ivar type_conditions: Every ``on Type`` of a fragment or inline fragment.
    :ivar operations: The operations, in document order.
    :ivar fragments: The fragment definitions, in document order.
    """

    fields: list[FieldSelection] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    object_field_names: list[str] = field(default_factory=list)
    string_values: list[str] = field(default_factory=list)
    enum_values: list[str] = field(default_factory=list)
    type_conditions: list[str] = field(default_factory=list)
    operations: list[Operation] = field(default_factory=list)
    fragments: list[FragmentDefinition] = field(default_factory=list)


# Names that are literals in value position rather than enum values.
_LITERAL_NAMES: Final[frozenset[str]] = frozenset({"true", "false", "null"})


def _flatten(selections: tuple[Selection, ...], out: list[FieldSelection]) -> None:
    """Append every field in ``selections`` to ``out``, parents first, in document order.

    The parser bounds nesting, so this recursion is bounded too.
    """
    for selection in selections:
        if isinstance(selection, FieldSelection):
            out.append(selection)
            _flatten(selection.selections, out)
        elif isinstance(selection, InlineFragment):
            _flatten(selection.selections, out)


class _Lexer:
    """Turn source text into tokens, raising on anything outside the lexical grammar."""

    __slots__ = ("_column", "_line", "_pos", "_source")

    def __init__(self, source: str) -> None:
        self._source = source
        self._pos = 0
        self._line = 1
        self._column = 1

    def _error(self, reason: str) -> GraphQlSyntaxError:
        return GraphQlSyntaxError(reason, self._line, self._column)

    def _peek(self, offset: int = 0) -> str:
        index = self._pos + offset
        return self._source[index] if index < len(self._source) else ""

    def _advance(self, count: int = 1) -> None:
        """Move forward ``count`` characters, keeping line and column right.

        ``\\r\\n`` counts as one line break, as the specification says; a lone ``\\r`` or ``\\n``
        counts as one too.
        """
        for _ in range(count):
            char = self._source[self._pos]
            self._pos += 1
            if char == "\n" or (char == "\r" and self._peek() != "\n"):
                self._line += 1
                self._column = 1
            else:
                self._column += 1

    def tokens(self) -> list[Token]:
        out: list[Token] = []
        while True:
            token = self._next()
            out.append(token)
            if token.kind is TokenKind.EOF:
                return out
            if len(out) > MAX_TOKENS:
                raise self._error("the document has too many tokens")

    def _next(self) -> Token:
        self._skip_ignored()
        line, column = self._line, self._column
        char = self._peek()
        if not char:
            return Token(TokenKind.EOF, "", line, column)
        if char == ".":
            if self._source.startswith("...", self._pos):
                self._advance(3)
                return Token(TokenKind.PUNCTUATOR, "...", line, column)
            raise self._error("'.' is only valid as part of '...'")
        if char in _PUNCTUATORS:
            self._advance()
            return Token(TokenKind.PUNCTUATOR, char, line, column)
        if char in _NAME_START:
            return Token(TokenKind.NAME, self._read_name(), line, column)
        if char == "-" or char in _DIGITS:
            kind, text = self._read_number()
            return Token(kind, text, line, column)
        if char == '"':
            if self._source.startswith('"""', self._pos):
                return Token(TokenKind.BLOCK_STRING, self._read_block_string(), line, column)
            return Token(TokenKind.STRING, self._read_string(), line, column)
        # Anything else, including every non-ASCII character outside a string or comment and every
        # control character, is not GraphQL.
        raise self._error(f"unexpected character U+{ord(char):04X}")

    def _skip_ignored(self) -> None:
        while True:
            char = self._peek()
            if char and (char in _IGNORED or char in _LINE_TERMINATORS):
                self._advance()
            elif char == "#":
                self._skip_comment()
            else:
                return

    def _skip_comment(self) -> None:
        self._advance()  # the '#'
        while (char := self._peek()) and char not in _LINE_TERMINATORS:
            if (
                char in _AMBIGUOUS_BREAKS
                or (char < " " and char != "\t")
                or char == "\x7f"
                or _is_surrogate(char)
            ):
                raise self._error(
                    f"character U+{ord(char):04X} inside a comment is refused: servers disagree "
                    "about whether it ends the comment"
                )
            self._advance()

    def _read_name(self) -> str:
        start = self._pos
        while (char := self._peek()) and char in _NAME_CONTINUE:
            self._advance()
        return self._source[start : self._pos]

    def _read_digits(self) -> None:
        if not (self._peek() and self._peek() in _DIGITS):
            raise self._error("expected a digit")
        while self._peek() and self._peek() in _DIGITS:
            self._advance()

    def _read_number(self) -> tuple[TokenKind, str]:
        start = self._pos
        kind = TokenKind.INT
        if self._peek() == "-":
            self._advance()
        if self._peek() == "0":
            self._advance()
            if self._peek() and self._peek() in _DIGITS:
                raise self._error("a number may not have a leading zero")
        else:
            self._read_digits()
        if self._peek() == ".":
            kind = TokenKind.FLOAT
            self._advance()
            self._read_digits()
        if self._peek() in {"e", "E"}:
            kind = TokenKind.FLOAT
            self._advance()
            if self._peek() in {"+", "-"}:
                self._advance()
            self._read_digits()
        # The specification's lookahead restriction: ``1a``, ``1.2.3`` and ``0x1`` are errors, not
        # a number followed by something else.
        following = self._peek()
        if following and (following == "." or following in _NAME_START):
            raise self._error("a number may not be followed directly by a name or '.'")
        return kind, self._source[start : self._pos]

    def _read_string(self) -> str:
        self._advance()  # the opening quote
        out: list[str] = []
        while True:
            char = self._peek()
            if not char:
                raise self._error("unterminated string")
            if char in _LINE_TERMINATORS:
                raise self._error("a line break inside a string; use a block string")
            if (char < " " and char != "\t") or _is_surrogate(char):
                raise self._error(f"character U+{ord(char):04X} inside a string")
            if char == '"':
                self._advance()
                return "".join(out)
            if char == "\\":
                out.append(self._read_escape())
                continue
            out.append(char)
            self._advance()

    def _read_escape(self) -> str:
        escaped = self._peek(1)
        if escaped in _SIMPLE_ESCAPES:
            self._advance(2)
            return _SIMPLE_ESCAPES[escaped]
        if escaped != "u":
            raise self._error("invalid escape sequence in a string")
        self._advance(2)
        if self._peek() == "{":
            self._advance()
            digits: list[str] = []
            while self._peek() and self._peek() in _HEX_DIGITS:
                digits.append(self._peek())
                self._advance()
            if self._peek() != "}" or not digits or len(digits) > 6:
                raise self._error("invalid \\u{...} escape in a string")
            self._advance()
        else:
            digits = [self._peek(i) for i in range(4)]
            if not all(d and d in _HEX_DIGITS for d in digits):
                raise self._error("invalid \\u escape in a string")
            self._advance(4)
        code = int("".join(digits), 16)
        if code > 0x10FFFF:
            raise self._error("a \\u escape beyond U+10FFFF")
        return chr(code)

    def _read_block_string(self) -> str:
        self._advance(3)  # the opening triple quote
        out: list[str] = []
        while True:
            char = self._peek()
            if not char:
                raise self._error("unterminated block string")
            if self._source.startswith('"""', self._pos):
                self._advance(3)
                return "".join(out)
            if self._source.startswith('\\"""', self._pos):
                out.append('"""')
                self._advance(4)
                continue
            if (char < " " and char not in {"\t", "\n", "\r"}) or _is_surrogate(char):
                raise self._error(f"character U+{ord(char):04X} inside a block string")
            out.append(char)
            self._advance()


def tokenize(source: str) -> list[Token]:
    """Lex ``source`` into tokens, ending with one ``EOF`` token.

    :param source: The document text.
    :return: The tokens, ignored tokens removed.
    :raises GraphQlSyntaxError: On anything outside the lexical grammar.
    """
    return _Lexer(source).tokens()


class _Parser:
    """Recursive descent over the executable-definition grammar, recording what is selected."""

    __slots__ = ("_depth", "_pos", "_summary", "_tokens")

    def __init__(self, tokens: list[Token]) -> None:
        self._tokens = tokens
        self._pos = 0
        self._depth = 0
        self._summary = DocumentSummary(names=[t.value for t in tokens if t.kind is TokenKind.NAME])

    # ---- token helpers -----------------------------------------------------------------------

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _error(self, reason: str, token: Token | None = None) -> GraphQlSyntaxError:
        at = token or self._peek()
        return GraphQlSyntaxError(reason, at.line, at.column)

    def _advance(self) -> Token:
        token = self._tokens[self._pos]
        if token.kind is not TokenKind.EOF:
            self._pos += 1
        return token

    def _at(self, punctuator: str) -> bool:
        token = self._peek()
        return token.kind is TokenKind.PUNCTUATOR and token.value == punctuator

    def _at_name(self, value: str | None = None) -> bool:
        token = self._peek()
        return token.kind is TokenKind.NAME and (value is None or token.value == value)

    def _expect(self, punctuator: str) -> Token:
        if not self._at(punctuator):
            raise self._error(f"expected '{punctuator}'")
        return self._advance()

    def _expect_name(self) -> Token:
        if not self._at_name():
            raise self._error("expected a name")
        return self._advance()

    def _enter(self) -> None:
        self._depth += 1
        if self._depth > MAX_NESTING:
            raise self._error("the document nests too deeply")

    def _leave(self) -> None:
        self._depth -= 1

    # ---- the grammar -------------------------------------------------------------------------

    def document(self) -> DocumentSummary:
        if self._peek().kind is TokenKind.EOF:
            raise self._error("the document is empty")
        while self._peek().kind is not TokenKind.EOF:
            self._definition()
        return self._summary

    def _definition(self) -> None:
        if self._at("{"):
            self._summary.operations.append(Operation("query", None, (), self._selection_set()))
        elif self._at_name() and self._peek().value in _OPERATION_TYPES:
            self._operation()
        elif self._at_name("fragment"):
            self._fragment_definition()
        else:
            # Type-system definitions and extensions, descriptions, and anything else: none of them
            # is executable, and a server executing this request would reject the document too.
            raise self._error("expected an operation or a fragment definition")

    def _operation(self) -> None:
        operation_type = self._advance().value  # query | mutation | subscription
        name = self._advance().value if self._at_name() else None
        variables = self._variable_definitions() if self._at("(") else ()
        directives = self._directives(const=False)
        selections = self._selection_set()
        self._summary.operations.append(
            Operation(operation_type, name, variables, selections, directives)
        )

    def _variable_definitions(self) -> tuple[VariableDefinition, ...]:
        self._expect("(")
        if self._at(")"):
            raise self._error("an empty variable definition list")
        definitions: list[VariableDefinition] = []
        while not self._at(")"):
            self._expect("$")
            name = self._expect_name().value
            self._expect(":")
            self._type()
            default: Value | None = None
            if self._at("="):
                self._advance()
                default = self._value(const=True)
            self._directives(const=True)
            definitions.append(VariableDefinition(name, default))
        self._advance()
        return tuple(definitions)

    def _type(self) -> None:
        self._enter()
        if self._at("["):
            self._advance()
            self._type()
            self._expect("]")
        else:
            self._expect_name()
        if self._at("!"):
            self._advance()
        self._leave()

    def _fragment_definition(self) -> None:
        self._advance()  # fragment
        if self._at_name("on"):
            raise self._error("a fragment may not be named 'on'")
        name = self._expect_name().value
        if self._at("("):
            # Fragment variables are an experimental extension, not the specification.
            raise self._error("fragment variable definitions are not supported")
        type_condition = self._type_condition()
        directives = self._directives(const=False)
        selections = self._selection_set()
        self._summary.fragments.append(
            FragmentDefinition(name, type_condition, selections, directives)
        )

    def _type_condition(self) -> str:
        if not self._at_name("on"):
            raise self._error("expected 'on' and a type name")
        self._advance()
        condition = self._expect_name().value
        self._summary.type_conditions.append(condition)
        return condition

    def _selection_set(self) -> tuple[Selection, ...]:
        self._enter()
        self._expect("{")
        if self._at("}"):
            raise self._error("an empty selection set")
        selections: list[Selection] = []
        while not self._at("}"):
            if self._peek().kind is TokenKind.EOF:
                raise self._error("unterminated selection set")
            selections.append(self._selection())
        self._advance()
        self._leave()
        return tuple(selections)

    def _selection(self) -> Selection:
        if not self._at("..."):
            return self._field()
        self._advance()
        if self._at_name("on"):
            condition = self._type_condition()
            directives = self._directives(const=False)
            return InlineFragment(condition, self._selection_set(), directives)
        if self._at_name():
            name = self._advance().value  # a fragment spread's name; never a field
            return FragmentSpread(name, self._directives(const=False))
        # An inline fragment without a type condition.
        directives = self._directives(const=False)
        return InlineFragment(None, self._selection_set(), directives)

    def _field(self) -> FieldSelection:
        first = self._expect_name()
        alias: str | None = None
        name = first
        if self._at(":"):
            # ``alias: name``. The token after the colon is the field that is actually resolved,
            # which is why an alias cannot hide a field from the guard.
            self._advance()
            alias = first.value
            name = self._expect_name()
        arguments = self._arguments(const=False) if self._at("(") else ()
        directives = self._directives(const=False)
        selections = self._selection_set() if self._at("{") else ()
        return FieldSelection(
            name.value,
            alias,
            tuple(argument.name for argument in arguments),
            first.line,
            first.column,
            arguments,
            selections,
            directives,
        )

    def _arguments(self, *, const: bool) -> tuple[Argument, ...]:
        self._expect("(")
        if self._at(")"):
            raise self._error("an empty argument list")
        arguments: list[Argument] = []
        while not self._at(")"):
            name = self._expect_name().value
            self._expect(":")
            arguments.append(Argument(name, self._value(const=const)))
        self._advance()
        return tuple(arguments)

    def _directives(self, *, const: bool) -> tuple[Argument, ...]:
        """Parse any directives and return their arguments, flattened across directives."""
        arguments: list[Argument] = []
        while self._at("@"):
            self._advance()
            self._expect_name()
            if self._at("("):
                arguments.extend(self._arguments(const=const))
        return tuple(arguments)

    def _value(self, *, const: bool) -> Value:
        token = self._peek()
        if token.kind in {TokenKind.INT, TokenKind.FLOAT}:
            return Value(ValueKind.SCALAR, self._advance().value)
        if token.kind in {TokenKind.STRING, TokenKind.BLOCK_STRING}:
            text = self._advance().value
            self._summary.string_values.append(text)
            return Value(ValueKind.STRING, text)
        if token.kind is TokenKind.NAME:
            text = self._advance().value
            if text in _LITERAL_NAMES:
                return Value(ValueKind.SCALAR, text)
            # An enum value. Recorded because an enum can name a field as well as a string can:
            # ``order: [{field: definition}]``.
            self._summary.enum_values.append(text)
            return Value(ValueKind.ENUM, text)
        if self._at("$"):
            if const:
                raise self._error("a variable is not allowed in a constant value")
            self._advance()
            return Value(ValueKind.VARIABLE, self._expect_name().value)
        if self._at("["):
            return self._list_value(const=const)
        if self._at("{"):
            return self._object_value(const=const)
        raise self._error("expected a value")

    def _list_value(self, *, const: bool) -> Value:
        self._enter()
        self._advance()  # [
        items: list[Value] = []
        while not self._at("]"):
            if self._peek().kind is TokenKind.EOF:
                raise self._error("unterminated list value")
            items.append(self._value(const=const))
        self._advance()
        self._leave()
        return Value(ValueKind.LIST, items=tuple(items))

    def _object_value(self, *, const: bool) -> Value:
        self._enter()
        self._advance()  # {
        fields: list[tuple[str, Value]] = []
        while not self._at("}"):
            if self._peek().kind is TokenKind.EOF:
                raise self._error("unterminated object value")
            key = self._expect_name().value
            self._summary.object_field_names.append(key)
            self._expect(":")
            fields.append((key, self._value(const=const)))
        self._advance()
        self._leave()
        return Value(ValueKind.OBJECT, fields=tuple(fields))


def summarize_executable_document(source: str) -> DocumentSummary:
    """Lex and parse ``source`` as an executable document and summarise what it names.

    :param source: The GraphQL document.
    :return: The flattened summary; see ``DocumentSummary``.
    :raises GraphQlSyntaxError: If the document is not one this scanner recognises.
    """
    summary = _Parser(tokenize(source)).document()
    for operation in summary.operations:
        _flatten(operation.selections, summary.fields)
    for fragment in summary.fragments:
        _flatten(fragment.selections, summary.fields)
    return summary
