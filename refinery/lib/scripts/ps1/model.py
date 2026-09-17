"""
PowerShell AST node types.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass, field

from refinery.lib.scripts import Block, Expression, Node, Statement


class Ps1ScopeModifier(enum.Enum):
    NONE     = ''          # noqa
    GLOBAL   = 'global'    # noqa
    LOCAL    = 'local'     # noqa
    SCRIPT   = 'script'    # noqa
    PRIVATE  = 'private'   # noqa
    USING    = 'using'     # noqa
    ENV      = 'env'       # noqa
    VARIABLE = 'variable'  # noqa
    FUNCTION = 'function'  # noqa
    ALIAS    = 'alias'     # noqa
    DRIVE    = 'drive'     # noqa


class Ps1CommandArgumentKind(enum.Enum):
    POSITIONAL = 'positional'
    NAMED = 'named'
    SWITCH = 'switch'


class Ps1AccessKind(enum.Enum):
    INSTANCE = '.'
    STATIC = '::'


#: What a numeric literal's multiplier suffix multiplies by, and the whole set of them. The suffix
#: is part of the numeral rather than an operator on it, so it is read where the digits are.
MULTIPLIERS = {
    'kb': 1 << 10,
    'mb': 1 << 20,
    'gb': 1 << 30,
    'tb': 1 << 40,
    'pb': 1 << 50,
}


def _as_float(text: str) -> float:
    """
    The number `text` spells, read first as an integer so that a hexadecimal or binary form is
    accepted, and `0.0` for text that spells no number at all.
    """
    for read in (lambda t: float(int(t, 0)), float):
        try:
            return read(text)
        except (ValueError, OverflowError):
            continue
    return 0.0


@dataclass(repr=False, eq=False)
class Ps1Variable(Expression, spelling='braced'):
    name: str = ''
    scope: Ps1ScopeModifier = Ps1ScopeModifier.NONE
    braced: bool = False
    splatted: bool = False
    drive: str = ''


@dataclass(repr=False, eq=False)
class Ps1IntegerLiteral(Expression):
    """
    A numeral, held as the text it was written as and nothing else.

    How a number is spelled is *what it is* in PowerShell rather than how it looks: `1.5` is a
    Double and `1.5d` a Decimal, `0xFF` an Int32 and `0xFFL` an Int64, and the same digits are an
    Int32, an Int64, a Decimal or a Double depending on how many of them there are. So `raw` is a
    value field and not a spelling one, and `canonical` compares it — two numerals are the same
    program when they are written the same way.

    `value` is the magnitude the digits spell, which is weaker than what the numeral denotes: it
    carries no type, and for a hexadecimal pattern that fills its width it is the unsigned reading
    rather than the negative .NET value. It is derived rather than stored so that it cannot drift
    from `raw`, and it exists only until its last caller asks
    `refinery.lib.scripts.ps1.analysis.values.read` instead, which answers the whole question.
    """
    raw: str = '0'

    @property
    def value(self) -> int:
        text = self.raw.replace('_', '').rstrip('lL')
        try:
            if text.lstrip('+-')[:2].lower() in ('0x', '0b'):
                return int(text, 0)
            return int(text, 10)
        except ValueError:
            return 0


@dataclass(repr=False, eq=False)
class Ps1RealLiteral(Expression):
    """
    A numeral written in a form only a non-integer type can hold — a decimal point, an exponent, a
    `d` suffix or a multiplier. See `Ps1IntegerLiteral` for why `raw` is the value field and what
    `value` is weaker than.
    """
    raw: str = '0.0'

    @property
    def value(self) -> float:
        text = self.raw.replace('_', '')
        for suffix, multiplier in MULTIPLIERS.items():
            if text.lower().endswith(suffix):
                return _as_float(text[:-len(suffix)].rstrip('lL')) * multiplier
        return _as_float(text[:-1] if text[-1:] in ('d', 'D') else text)


@dataclass(repr=False, eq=False)
class Ps1StringLiteral(Expression, spelling='raw'):
    value: str = ''
    raw: str = "''"

    @property
    def is_bare_word(self) -> bool:
        """
        Whether the recorded spelling carries no quotes. Such a spelling is only valid in the slot
        it was read from: PowerShell reads a bare word as a value where a command's name and
        arguments are read, and as the start of a command everywhere else. A node moved out of such
        a slot therefore has to be re-spelled, which is why `raw` alone cannot be replayed.
        """
        return not self.raw.startswith(("'", '"'))


@dataclass(repr=False, eq=False)
class _Ps1Expandable(Expression, spelling='raw'):
    parts: list[Expression] = field(default_factory=list)
    raw: str = ''

    def canonical_form(self):
        """
        An expandable string that interpolates nothing is the literal string it spells. The parser
        collapses the single-part case on its own, but a transform that folds the last expression
        part of `"$a$b"` to text leaves a multi-part all-literal string behind, and that spells the
        same program as the literal it prints as.
        """
        values = []
        for part in self.parts:
            if not isinstance(part, Ps1StringLiteral):
                return None
            values.append(part.value)
        return Ps1StringLiteral(value=''.join(values))


@dataclass(repr=False, eq=False)
class Ps1ExpandableString(_Ps1Expandable):
    """
    An expandable (double-quoted) string with interleaved text and expression parts. Text segments
    are `Ps1StringLiteral`, expression segments are any `refinery.lib.scripts.Expression` node.
    """
    raw: str = '""'


@dataclass(repr=False, eq=False)
class Ps1HereString(Expression, spelling='raw', identity=Ps1StringLiteral):
    value: str = ''
    raw: str = ''


@dataclass(repr=False, eq=False)
class Ps1ExpandableHereString(_Ps1Expandable, identity=Ps1ExpandableString):
    pass


@dataclass(repr=False, eq=False)
class Ps1BinaryExpression(Expression):
    left: Expression | None = None
    operator: str = ''
    right: Expression | None = None


@dataclass(repr=False, eq=False)
class Ps1UnaryExpression(Expression):
    operator: str = ''
    operand: Expression | None = None
    prefix: bool = True


@dataclass(repr=False, eq=False)
class Ps1TypeExpression(Expression):
    name: str = ''


@dataclass(repr=False, eq=False)
class Ps1CastExpression(Expression):
    type_name: str = ''
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class Ps1MemberAccess(Expression):
    object: Expression | None = None
    member: str | Expression = ''
    access: Ps1AccessKind = Ps1AccessKind.INSTANCE


@dataclass(repr=False, eq=False)
class Ps1IndexExpression(Expression):
    object: Expression | None = None
    index: Expression | None = None


@dataclass(repr=False, eq=False)
class Ps1InvokeMember(Expression):
    object: Expression | None = None
    member: str | Expression = ''
    arguments: list[Expression] = field(default_factory=list)
    access: Ps1AccessKind = Ps1AccessKind.INSTANCE


@dataclass(repr=False, eq=False)
class Ps1CommandArgument(Node):
    kind: Ps1CommandArgumentKind = Ps1CommandArgumentKind.POSITIONAL
    name: str = ''
    value: Expression | None = None


@dataclass(repr=False, eq=False)
class Ps1CommandInvocation(Expression):
    name: Expression | None = None
    arguments: list[Ps1CommandArgument | Expression] = field(default_factory=list)
    invocation_operator: str = ''
    redirections: list[Ps1Redirection] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1AssignmentExpression(Expression):
    target: Expression | None = None
    operator: str = '='
    value: Node | None = None


@dataclass(repr=False, eq=False)
class Ps1ArrayLiteral(Expression):
    elements: list[Expression] = field(default_factory=list)

    def has_spelling(self) -> bool:
        """
        The comma operator needs something to build an array out of. A bare `,` is not a PowerShell
        expression, so an empty array literal spells nothing at all — `@()` is the empty array that
        does. The parser reaches this shape only through error recovery.
        """
        return bool(self.elements)


@dataclass(repr=False, eq=False)
class Ps1ArrayExpression(Expression):
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1HashLiteral(Expression):
    """
    The value of an entry is a whole statement, exactly as it is on the right of an assignment, so
    `@{ a = if ($c) { 1 } }` keeps the branch it spells rather than losing it.
    """
    pairs: list[tuple[Expression, Node]] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1SubExpression(Expression):
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1ParenExpression(Expression):
    expression: Expression | None = None

    def canonical_form(self):
        """
        A parenthesis groups; it computes nothing of its own. Whether one is written is a question
        about the neighbours an expression is printed among, not about the program, so a bracket
        the synthesizer adds to keep `(1 + 2) * 3` from re-reading as `1 + 2 * 3` must not make the
        result a different tree than the one it was printed from.

        Note that `$(...)` and `@(...)` are not this: they are `Ps1SubExpression` and
        `Ps1ArrayExpression`, and both mean something a bare expression does not.

        An empty parenthesis holds nothing and so is its own canonical form. Whether 5.1 accepts
        `()` at all is a question about the parser rather than about this identification, and it is
        left to be settled against the reference rather than guessed at here.
        """
        return self.expression


@dataclass(repr=False, eq=False)
class Ps1Code(Node):
    param_block: Ps1ParamBlock | None = None
    begin_block: Block | None = None
    process_block: Block | None = None
    end_block: Block | None = None
    dynamicparam_block: Block | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1ScriptBlock(Ps1Code, Expression):
    pass


@dataclass(repr=False, eq=False)
class Ps1RangeExpression(Expression):
    start: Expression | None = None
    end: Expression | None = None


@dataclass(repr=False, eq=False)
class Ps1Attribute(Node):
    name: str = ''
    positional_args: list[Expression] = field(default_factory=list)
    named_args: list[tuple[str, Expression]] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1ParameterDeclaration(Node):
    attributes: list[Ps1Attribute | Ps1TypeExpression] = field(default_factory=list)
    variable: Ps1Variable | None = None
    default_value: Expression | None = None


@dataclass(repr=False, eq=False)
class Ps1ParamBlock(Node):
    attributes: list[Ps1Attribute] = field(default_factory=list)
    parameters: list[Ps1ParameterDeclaration] = field(default_factory=list)


class Ps1RedirectionStream(enum.IntEnum):
    ALL         = 0  # noqa
    OUTPUT      = 1  # noqa
    ERROR       = 2  # noqa
    WARNING     = 3  # noqa
    VERBOSE     = 4  # noqa
    DEBUG       = 5  # noqa
    INFORMATION = 6  # noqa


@dataclass(repr=False, eq=False)
class Ps1FileRedirection(Node):
    stream: Ps1RedirectionStream = Ps1RedirectionStream.OUTPUT
    target: Expression | None = None
    append: bool = False


@dataclass(repr=False, eq=False)
class Ps1MergingRedirection(Node):
    from_stream: Ps1RedirectionStream = Ps1RedirectionStream.ERROR
    to_stream: Ps1RedirectionStream = Ps1RedirectionStream.OUTPUT


@dataclass(repr=False, eq=False)
class Ps1InputRedirection(Node):
    """
    A `<` redirection, which PowerShell reserves and never performs. It names no stream because it
    moves nothing: it exists so that the command it belongs to keeps the shape it spells rather than
    losing its name to an operator that reads nothing. The source is kept even though 5.1 discards
    it, because what is dropped here is what an analyst reads back.
    """
    source: Expression | None = None


Ps1Redirection = Ps1FileRedirection | Ps1MergingRedirection | Ps1InputRedirection


@dataclass(repr=False, eq=False)
class Ps1PipelineElement(Node):
    expression: Expression | None = None
    redirections: list[Ps1Redirection] = field(default_factory=list)

    def canonical_form(self):
        """
        An element that redirects nothing is the expression it holds; the wrapper exists to carry
        the redirections that a stage may have, and spells nothing when it carries none.
        """
        if self.redirections:
            return None
        return self.expression


@dataclass(repr=False, eq=False)
class Ps1Pipeline(Expression, Statement):
    elements: list[Ps1PipelineElement] = field(default_factory=list)

    def canonical_form(self):
        """
        A pipeline of one stage is that stage: nothing is piped anywhere, so it spells exactly what
        its element spells. The parser builds one only to carry a redirection an expression has no
        other slot for — `$x > out.txt` — and that element declines this same identification while
        the redirection is on it, so the write is never spelled away with the wrapper.
        """
        if len(self.elements) != 1:
            return None
        return self.elements[0]

    def has_spelling(self) -> bool:
        return bool(self.elements)


@dataclass(repr=False, eq=False)
class Ps1ExpressionStatement(Statement):
    expression: Expression | None = None


@dataclass(repr=False, eq=False)
class Ps1IfStatement(Statement):
    clauses: list[tuple[Expression, Block]] = field(default_factory=list)
    else_block: Block | None = None

    def has_spelling(self) -> bool:
        """
        There is no `else` without an `if`. A statement whose clauses have all been removed spells
        nothing, and its `else` branch — which runs precisely when no clause matched, so with no
        clauses it always runs — is not the same program as the block written alone.
        """
        return bool(self.clauses)


@dataclass(repr=False, eq=False)
class _Ps1Loop(Statement):
    label: str | None = None


@dataclass(repr=False, eq=False)
class Ps1WhileLoop(_Ps1Loop):
    condition: Expression | None = None
    body: Block | None = None


@dataclass(repr=False, eq=False)
class Ps1DoLoop(_Ps1Loop):
    body: Block | None = None
    condition: Expression | None = None
    is_until: bool = False

    def has_spelling(self) -> bool:
        """
        Both halves of a `do` loop are mandatory. `do { } while ()` is a syntax error, so a loop
        missing either spells nothing; the parser reaches this shape only through error recovery.
        """
        return self.condition is not None and self.body is not None


@dataclass(repr=False, eq=False)
class Ps1ForLoop(_Ps1Loop):
    initializer: Expression | None = None
    condition: Expression | None = None
    iterator: Expression | None = None
    body: Block | None = None


@dataclass(repr=False, eq=False)
class Ps1ForEachLoop(_Ps1Loop):
    variable: Expression | None = None
    iterable: Expression | None = None
    body: Block | None = None
    parallel: bool = False


@dataclass(repr=False, eq=False)
class Ps1SwitchStatement(Statement):
    value: Expression | None = None
    clauses: list[tuple[Expression | None, Block]] = field(default_factory=list)
    regex: bool = False
    wildcard: bool = False
    exact: bool = False
    case_sensitive: bool = False
    file: bool = False
    label: str | None = None


@dataclass(repr=False, eq=False)
class Ps1CatchClause(Node):
    types: list[str] = field(default_factory=list)
    body: Block | None = None
    filtered: bool = False


@dataclass(repr=False, eq=False)
class Ps1TryCatchFinally(Statement):
    try_block: Block | None = None
    catch_clauses: list[Ps1CatchClause] = field(default_factory=list)
    finally_block: Block | None = None

    def has_spelling(self) -> bool:
        """
        A `try` needs somewhere to go: 5.1 rejects one carrying neither a `catch` nor a `finally`.
        Printing the bare `try` would turn a guarded block into an unguarded one, which is the
        difference between a script that survives an error and one that stops on it.
        """
        return bool(self.catch_clauses) or self.finally_block is not None


@dataclass(repr=False, eq=False)
class Ps1TrapStatement(Statement):
    type_name: str = ''
    body: Block | None = None


@dataclass(repr=False, eq=False)
class Ps1FunctionDefinition(Statement):
    name: str = ''
    is_filter: bool = False
    body: Ps1ScriptBlock | None = None


class Ps1MemberModifier(enum.Flag):
    NONE   = 0       # noqa
    STATIC = enum.auto()  # noqa
    HIDDEN = enum.auto()  # noqa


@dataclass(repr=False, eq=False)
class Ps1PropertyMember(Node):
    attributes: list[Ps1Attribute] = field(default_factory=list)
    modifiers: Ps1MemberModifier = Ps1MemberModifier.NONE
    type_constraint: Ps1TypeExpression | None = None
    variable: Ps1Variable | None = None
    initial_value: Expression | None = None


@dataclass(repr=False, eq=False)
class Ps1MethodMember(Node):
    attributes: list[Ps1Attribute] = field(default_factory=list)
    modifiers: Ps1MemberModifier = Ps1MemberModifier.NONE
    return_type: Ps1TypeExpression | None = None
    definition: Ps1FunctionDefinition | None = None


@dataclass(repr=False, eq=False)
class Ps1ClassDefinition(Statement):
    name: str = ''
    base_types: list[str] = field(default_factory=list)
    members: list[Ps1PropertyMember | Ps1MethodMember] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1EnumMember(Node):
    name: str = ''
    value: Expression | None = None


@dataclass(repr=False, eq=False)
class Ps1EnumDefinition(Statement):
    name: str = ''
    base_type: str = ''
    members: list[Ps1EnumMember] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1Exit(Statement):
    pipeline: Expression | None = None


@dataclass(repr=False, eq=False)
class Ps1ReturnStatement(Ps1Exit):
    pass


@dataclass(repr=False, eq=False)
class Ps1ThrowStatement(Ps1Exit):
    pass


@dataclass(repr=False, eq=False)
class Ps1Jump(Statement):
    label: Expression | None = None


@dataclass(repr=False, eq=False)
class Ps1BreakStatement(Ps1Jump):
    pass


@dataclass(repr=False, eq=False)
class Ps1ContinueStatement(Ps1Jump):
    pass


@dataclass(repr=False, eq=False)
class Ps1ExitStatement(Ps1Exit):
    pass


@dataclass(repr=False, eq=False)
class Ps1DataSection(Statement):
    name: str = ''
    commands: list[Expression] = field(default_factory=list)
    body: Block | None = None


@dataclass(repr=False, eq=False)
class Ps1ErrorNode(Expression, unparsed=True):
    """
    A span of source the parser could not read, kept verbatim so that what an analyst gets back
    still contains what was written. It prints as `text` and so reads back as whatever that text
    parses to, which is why a tree holding one states nothing about synthesizer fidelity.

    This node always has a spelling — the text it captured, which is empty where the parser found
    nothing at all. It is the one node the parser may build in place of a shape that has none, and
    it can only serve as that escape hatch if printing it is always defined.
    """
    text: str = ''
    message: str = ''


@dataclass(repr=False, eq=False)
class Ps1Script(Ps1Code, Statement):
    pass
