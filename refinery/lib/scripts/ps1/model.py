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


@dataclass(repr=False, eq=False)
class Ps1Variable(Expression):
    name: str = ''
    scope: Ps1ScopeModifier = Ps1ScopeModifier.NONE
    braced: bool = False
    splatted: bool = False


@dataclass(repr=False, eq=False)
class Ps1IntegerLiteral(Expression):
    value: int = 0
    raw: str = '0'


@dataclass(repr=False, eq=False)
class Ps1RealLiteral(Expression):
    value: float = 0.0
    raw: str = '0.0'


@dataclass(repr=False, eq=False)
class Ps1StringLiteral(Expression):
    value: str = ''
    raw: str = "''"


@dataclass(repr=False, eq=False)
class _Ps1Expandable(Expression):
    parts: list[Expression] = field(default_factory=list)
    raw: str = ''


@dataclass(repr=False, eq=False)
class Ps1ExpandableString(_Ps1Expandable):
    """
    An expandable (double-quoted) string with interleaved text and expression parts. Text segments
    are `Ps1StringLiteral`, expression segments are any `Expression` node.
    """
    raw: str = '""'


@dataclass(repr=False, eq=False)
class Ps1HereString(Expression):
    value: str = ''
    raw: str = ''


@dataclass(repr=False, eq=False)
class Ps1ExpandableHereString(_Ps1Expandable):
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
    redirections: list[Ps1FileRedirection | Ps1MergingRedirection] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1AssignmentExpression(Expression):
    target: Expression | None = None
    operator: str = '='
    value: Node | None = None


@dataclass(repr=False, eq=False)
class Ps1ArrayLiteral(Expression):
    elements: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1ArrayExpression(Expression):
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1HashLiteral(Expression):
    pairs: list[tuple[Expression, Expression]] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1SubExpression(Expression):
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1ParenExpression(Expression):
    expression: Expression | None = None


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
class Ps1PipelineElement(Node):
    expression: Expression | None = None
    redirections: list[Ps1FileRedirection | Ps1MergingRedirection] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1Pipeline(Expression, Statement):
    elements: list[Ps1PipelineElement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Ps1ExpressionStatement(Statement):
    expression: Expression | None = None


@dataclass(repr=False, eq=False)
class Ps1IfStatement(Statement):
    clauses: list[tuple[Expression, Block]] = field(default_factory=list)
    else_block: Block | None = None


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


@dataclass(repr=False, eq=False)
class Ps1TryCatchFinally(Statement):
    try_block: Block | None = None
    catch_clauses: list[Ps1CatchClause] = field(default_factory=list)
    finally_block: Block | None = None


@dataclass(repr=False, eq=False)
class Ps1TrapStatement(Statement):
    type_name: str = ''
    body: Block | None = None


@dataclass(repr=False, eq=False)
class Ps1FunctionDefinition(Statement):
    name: str = ''
    is_filter: bool = False
    body: Ps1ScriptBlock | None = None


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
class Ps1ErrorNode(Expression):
    text: str = ''
    message: str = ''


@dataclass(repr=False, eq=False)
class Ps1Script(Ps1Code, Statement):
    pass
