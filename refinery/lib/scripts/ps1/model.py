"""
PowerShell AST node types.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass, field
from typing import Generator

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


@dataclass(repr=False)
class Ps1Variable(Expression):
    name: str = ''
    scope: Ps1ScopeModifier = Ps1ScopeModifier.NONE
    braced: bool = False
    splatted: bool = False

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class Ps1IntegerLiteral(Expression):
    value: int = 0
    raw: str = '0'

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class Ps1RealLiteral(Expression):
    value: float = 0.0
    raw: str = '0.0'

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class Ps1StringLiteral(Expression):
    value: str = ''
    raw: str = "''"

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class Ps1ExpandableString(Expression):
    """
    An expandable (double-quoted) string with interleaved text and expression
    parts. Text segments are `Ps1StringLiteral`, expression segments are any
    `Expression` node.
    """
    parts: list[Expression] = field(default_factory=list)
    raw: str = '""'

    def __post_init__(self):
        self._adopt(*self.parts)

    def children(self) -> Generator[Node, None, None]:
        yield from self.parts


@dataclass(repr=False)
class Ps1HereString(Expression):
    value: str = ''
    raw: str = ''
    expandable: bool = False

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class Ps1ExpandableHereString(Expression):
    parts: list[Expression] = field(default_factory=list)
    raw: str = ''

    def __post_init__(self):
        self._adopt(*self.parts)

    def children(self) -> Generator[Node, None, None]:
        yield from self.parts


@dataclass(repr=False)
class Ps1BinaryExpression(Expression):
    left: Expression | None = None
    operator: str = ''
    right: Expression | None = None

    def __post_init__(self):
        self._adopt(self.left, self.right)

    def children(self) -> Generator[Node, None, None]:
        if self.left is not None:
            yield self.left
        if self.right is not None:
            yield self.right


@dataclass(repr=False)
class Ps1UnaryExpression(Expression):
    operator: str = ''
    operand: Expression | None = None
    prefix: bool = True

    def __post_init__(self):
        self._adopt(self.operand)

    def children(self) -> Generator[Node, None, None]:
        if self.operand is not None:
            yield self.operand


@dataclass(repr=False)
class Ps1TypeExpression(Expression):
    name: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class Ps1CastExpression(Expression):
    type_name: str = ''
    operand: Expression | None = None

    def __post_init__(self):
        self._adopt(self.operand)

    def children(self) -> Generator[Node, None, None]:
        if self.operand is not None:
            yield self.operand


@dataclass(repr=False)
class Ps1MemberAccess(Expression):
    object: Expression | None = None
    member: str | Expression = ''
    access: Ps1AccessKind = Ps1AccessKind.INSTANCE

    def __post_init__(self):
        self._adopt(self.object)
        if isinstance(self.member, Expression):
            self._adopt(self.member)

    def children(self) -> Generator[Node, None, None]:
        if self.object is not None:
            yield self.object
        if isinstance(self.member, Expression):
            yield self.member


@dataclass(repr=False)
class Ps1IndexExpression(Expression):
    object: Expression | None = None
    index: Expression | None = None

    def __post_init__(self):
        self._adopt(self.object, self.index)

    def children(self) -> Generator[Node, None, None]:
        if self.object is not None:
            yield self.object
        if self.index is not None:
            yield self.index


@dataclass(repr=False)
class Ps1InvokeMember(Expression):
    object: Expression | None = None
    member: str | Expression = ''
    arguments: list[Expression] = field(default_factory=list)
    access: Ps1AccessKind = Ps1AccessKind.INSTANCE

    def __post_init__(self):
        self._adopt(self.object, *self.arguments)
        if isinstance(self.member, Expression):
            self._adopt(self.member)

    def children(self) -> Generator[Node, None, None]:
        if self.object is not None:
            yield self.object
        if isinstance(self.member, Expression):
            yield self.member
        yield from self.arguments


@dataclass(repr=False)
class Ps1CommandArgument(Node):
    kind: Ps1CommandArgumentKind = Ps1CommandArgumentKind.POSITIONAL
    name: str = ''
    value: Expression | None = None

    def __post_init__(self):
        self._adopt(self.value)

    def children(self) -> Generator[Node, None, None]:
        if self.value is not None:
            yield self.value


@dataclass(repr=False)
class Ps1CommandInvocation(Expression):
    name: Expression | None = None
    arguments: list[Ps1CommandArgument | Expression] = field(default_factory=list)
    invocation_operator: str = ''

    def __post_init__(self):
        self._adopt(self.name, *self.arguments)

    def children(self) -> Generator[Node, None, None]:
        if self.name is not None:
            yield self.name
        yield from self.arguments


@dataclass(repr=False)
class Ps1CallExpression(Expression):
    callee: Expression | None = None
    arguments: list[Expression] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.callee, *self.arguments)

    def children(self) -> Generator[Node, None, None]:
        if self.callee is not None:
            yield self.callee
        yield from self.arguments


@dataclass(repr=False)
class Ps1AssignmentExpression(Expression):
    target: Expression | None = None
    operator: str = '='
    value: Node | None = None

    def __post_init__(self):
        self._adopt(self.target, self.value)

    def children(self) -> Generator[Node, None, None]:
        if self.target is not None:
            yield self.target
        if self.value is not None:
            yield self.value


@dataclass(repr=False)
class Ps1ArrayLiteral(Expression):
    elements: list[Expression] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.elements)

    def children(self) -> Generator[Node, None, None]:
        yield from self.elements


@dataclass(repr=False)
class Ps1ArrayExpression(Expression):
    body: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.body)

    def children(self) -> Generator[Node, None, None]:
        yield from self.body


@dataclass(repr=False)
class Ps1HashLiteral(Expression):
    pairs: list[tuple[Expression, Expression]] = field(default_factory=list)

    def __post_init__(self):
        for k, v in self.pairs:
            self._adopt(k, v)

    def children(self) -> Generator[Node, None, None]:
        for k, v in self.pairs:
            yield k
            yield v


@dataclass(repr=False)
class Ps1SubExpression(Expression):
    body: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.body)

    def children(self) -> Generator[Node, None, None]:
        yield from self.body


@dataclass(repr=False)
class Ps1ParenExpression(Expression):
    expression: Expression | None = None

    def __post_init__(self):
        self._adopt(self.expression)

    def children(self) -> Generator[Node, None, None]:
        if self.expression is not None:
            yield self.expression


@dataclass(repr=False)
class Ps1ScriptBlock(Expression):
    param_block: Ps1ParamBlock | None = None
    begin_block: Block | None = None
    process_block: Block | None = None
    end_block: Block | None = None
    dynamicparam_block: Block | None = None
    body: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(
            self.param_block,
            self.begin_block,
            self.process_block,
            self.end_block,
            self.dynamicparam_block,
            *self.body,
        )

    def children(self) -> Generator[Node, None, None]:
        if self.param_block is not None:
            yield self.param_block
        if self.begin_block is not None:
            yield self.begin_block
        if self.process_block is not None:
            yield self.process_block
        if self.end_block is not None:
            yield self.end_block
        if self.dynamicparam_block is not None:
            yield self.dynamicparam_block
        yield from self.body


@dataclass(repr=False)
class Ps1RangeExpression(Expression):
    start: Expression | None = None
    end: Expression | None = None

    def __post_init__(self):
        self._adopt(self.start, self.end)

    def children(self) -> Generator[Node, None, None]:
        if self.start is not None:
            yield self.start
        if self.end is not None:
            yield self.end


@dataclass(repr=False)
class Ps1Attribute(Node):
    name: str = ''
    positional_args: list[Expression] = field(default_factory=list)
    named_args: list[tuple[str, Expression]] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.positional_args)
        for _, v in self.named_args:
            self._adopt(v)

    def children(self) -> Generator[Node, None, None]:
        yield from self.positional_args
        for _, v in self.named_args:
            yield v


@dataclass(repr=False)
class Ps1ParameterDeclaration(Node):
    variable: Ps1Variable | None = None
    attributes: list[Ps1Attribute | Ps1TypeExpression] = field(default_factory=list)
    default_value: Expression | None = None

    def __post_init__(self):
        self._adopt(self.variable, *self.attributes, self.default_value)

    def children(self) -> Generator[Node, None, None]:
        yield from self.attributes
        if self.variable is not None:
            yield self.variable
        if self.default_value is not None:
            yield self.default_value


@dataclass(repr=False)
class Ps1ParamBlock(Node):
    parameters: list[Ps1ParameterDeclaration] = field(default_factory=list)
    attributes: list[Ps1Attribute] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.parameters, *self.attributes)

    def children(self) -> Generator[Node, None, None]:
        yield from self.attributes
        yield from self.parameters


@dataclass(repr=False)
class Ps1Redirection(Node):
    operator: str = '>'
    target: Expression | None = None

    def __post_init__(self):
        self._adopt(self.target)

    def children(self) -> Generator[Node, None, None]:
        if self.target is not None:
            yield self.target


@dataclass(repr=False)
class Ps1PipelineElement(Node):
    expression: Expression | None = None
    redirections: list[Ps1Redirection] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.expression, *self.redirections)

    def children(self) -> Generator[Node, None, None]:
        if self.expression is not None:
            yield self.expression
        yield from self.redirections


@dataclass(repr=False)
class Ps1Pipeline(Statement):
    elements: list[Ps1PipelineElement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.elements)

    def children(self) -> Generator[Node, None, None]:
        yield from self.elements


@dataclass(repr=False)
class Ps1ExpressionStatement(Statement):
    expression: Expression | None = None

    def __post_init__(self):
        self._adopt(self.expression)

    def children(self) -> Generator[Node, None, None]:
        if self.expression is not None:
            yield self.expression


@dataclass(repr=False)
class Ps1IfStatement(Statement):
    clauses: list[tuple[Expression, Block]] = field(default_factory=list)
    else_block: Block | None = None

    def __post_init__(self):
        for cond, body in self.clauses:
            self._adopt(cond, body)
        self._adopt(self.else_block)

    def children(self) -> Generator[Node, None, None]:
        for cond, body in self.clauses:
            yield cond
            yield body
        if self.else_block is not None:
            yield self.else_block


@dataclass(repr=False)
class Ps1WhileLoop(Statement):
    condition: Expression | None = None
    body: Block | None = None
    label: str | None = None

    def __post_init__(self):
        self._adopt(self.condition, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.condition is not None:
            yield self.condition
        if self.body is not None:
            yield self.body


@dataclass(repr=False)
class Ps1DoWhileLoop(Statement):
    condition: Expression | None = None
    body: Block | None = None
    label: str | None = None

    def __post_init__(self):
        self._adopt(self.condition, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.body is not None:
            yield self.body
        if self.condition is not None:
            yield self.condition


@dataclass(repr=False)
class Ps1DoUntilLoop(Statement):
    condition: Expression | None = None
    body: Block | None = None
    label: str | None = None

    def __post_init__(self):
        self._adopt(self.condition, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.body is not None:
            yield self.body
        if self.condition is not None:
            yield self.condition


@dataclass(repr=False)
class Ps1ForLoop(Statement):
    initializer: Expression | None = None
    condition: Expression | None = None
    iterator: Expression | None = None
    body: Block | None = None
    label: str | None = None

    def __post_init__(self):
        self._adopt(self.initializer, self.condition, self.iterator, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.initializer is not None:
            yield self.initializer
        if self.condition is not None:
            yield self.condition
        if self.iterator is not None:
            yield self.iterator
        if self.body is not None:
            yield self.body


@dataclass(repr=False)
class Ps1ForEachLoop(Statement):
    variable: Expression | None = None
    iterable: Expression | None = None
    body: Block | None = None
    parallel: bool = False
    label: str | None = None

    def __post_init__(self):
        self._adopt(self.variable, self.iterable, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.variable is not None:
            yield self.variable
        if self.iterable is not None:
            yield self.iterable
        if self.body is not None:
            yield self.body


@dataclass(repr=False)
class Ps1SwitchStatement(Statement):
    value: Expression | None = None
    clauses: list[tuple[Expression | None, Block]] = field(default_factory=list)
    regex: bool = False
    wildcard: bool = False
    exact: bool = False
    case_sensitive: bool = False
    file: bool = False
    label: str | None = None

    def __post_init__(self):
        self._adopt(self.value)
        for cond, body in self.clauses:
            self._adopt(cond, body)

    def children(self) -> Generator[Node, None, None]:
        if self.value is not None:
            yield self.value
        for cond, body in self.clauses:
            if cond is not None:
                yield cond
            yield body


@dataclass(repr=False)
class Ps1CatchClause(Node):
    types: list[str] = field(default_factory=list)
    body: Block | None = None

    def __post_init__(self):
        self._adopt(self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.body is not None:
            yield self.body


@dataclass(repr=False)
class Ps1TryCatchFinally(Statement):
    try_block: Block | None = None
    catch_clauses: list[Ps1CatchClause] = field(default_factory=list)
    finally_block: Block | None = None

    def __post_init__(self):
        self._adopt(self.try_block, *self.catch_clauses, self.finally_block)

    def children(self) -> Generator[Node, None, None]:
        if self.try_block is not None:
            yield self.try_block
        yield from self.catch_clauses
        if self.finally_block is not None:
            yield self.finally_block


@dataclass(repr=False)
class Ps1TrapStatement(Statement):
    type_name: str = ''
    body: Block | None = None

    def __post_init__(self):
        self._adopt(self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.body is not None:
            yield self.body


@dataclass(repr=False)
class Ps1FunctionDefinition(Statement):
    name: str = ''
    is_filter: bool = False
    body: Ps1ScriptBlock | None = None

    def __post_init__(self):
        self._adopt(self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.body is not None:
            yield self.body


@dataclass(repr=False)
class Ps1ReturnStatement(Statement):
    pipeline: Expression | None = None

    def __post_init__(self):
        self._adopt(self.pipeline)

    def children(self) -> Generator[Node, None, None]:
        if self.pipeline is not None:
            yield self.pipeline


@dataclass(repr=False)
class Ps1ThrowStatement(Statement):
    pipeline: Expression | None = None

    def __post_init__(self):
        self._adopt(self.pipeline)

    def children(self) -> Generator[Node, None, None]:
        if self.pipeline is not None:
            yield self.pipeline


@dataclass(repr=False)
class Ps1BreakStatement(Statement):
    label: Expression | None = None

    def __post_init__(self):
        self._adopt(self.label)

    def children(self) -> Generator[Node, None, None]:
        if self.label is not None:
            yield self.label


@dataclass(repr=False)
class Ps1ContinueStatement(Statement):
    label: Expression | None = None

    def __post_init__(self):
        self._adopt(self.label)

    def children(self) -> Generator[Node, None, None]:
        if self.label is not None:
            yield self.label


@dataclass(repr=False)
class Ps1ExitStatement(Statement):
    pipeline: Expression | None = None

    def __post_init__(self):
        self._adopt(self.pipeline)

    def children(self) -> Generator[Node, None, None]:
        if self.pipeline is not None:
            yield self.pipeline


@dataclass(repr=False)
class Ps1DataSection(Statement):
    name: str = ''
    commands: list[Expression] = field(default_factory=list)
    body: Block | None = None

    def __post_init__(self):
        for cmd in self.commands:
            self._adopt(cmd)
        self._adopt(self.body)

    def children(self) -> Generator[Node, None, None]:
        yield from self.commands
        if self.body is not None:
            yield self.body


@dataclass(repr=False)
class Ps1ErrorNode(Node):
    text: str = ''
    message: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class Ps1Script(Statement):
    param_block: Ps1ParamBlock | None = None
    begin_block: Block | None = None
    process_block: Block | None = None
    end_block: Block | None = None
    dynamicparam_block: Block | None = None
    body: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(
            self.param_block,
            self.begin_block,
            self.process_block,
            self.end_block,
            self.dynamicparam_block,
            *self.body,
        )

    def children(self) -> Generator[Node, None, None]:
        if self.param_block is not None:
            yield self.param_block
        if self.begin_block is not None:
            yield self.begin_block
        if self.process_block is not None:
            yield self.process_block
        if self.end_block is not None:
            yield self.end_block
        if self.dynamicparam_block is not None:
            yield self.dynamicparam_block
        yield from self.body
