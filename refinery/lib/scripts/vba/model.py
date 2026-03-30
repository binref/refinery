from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generator

from refinery.lib.scripts import Expression, Node, Script, Statement


@dataclass(repr=False)
class VbaErrorNode(Node):
    text: str = ''
    message: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaIdentifier(Expression):
    name: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaTypedIdentifier(Expression):
    name: str = ''
    suffix: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaMeExpression(Expression):
    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaIntegerLiteral(Expression):
    value: int = 0
    raw: str = '0'

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaFloatLiteral(Expression):
    value: float = 0.0
    raw: str = '0'

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaStringLiteral(Expression):
    value: str = ''
    raw: str = '""'

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaDateLiteral(Expression):
    raw: str = '##'

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaBooleanLiteral(Expression):
    value: bool = False

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaNothingLiteral(Expression):
    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaNullLiteral(Expression):
    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaEmptyLiteral(Expression):
    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaBinaryExpression(Expression):
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
class VbaUnaryExpression(Expression):
    operator: str = ''
    operand: Expression | None = None

    def __post_init__(self):
        self._adopt(self.operand)

    def children(self) -> Generator[Node, None, None]:
        if self.operand is not None:
            yield self.operand


@dataclass(repr=False)
class VbaCallExpression(Expression):
    callee: Expression | None = None
    arguments: list[Expression | None] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.callee, *[a for a in self.arguments if a is not None])

    def children(self) -> Generator[Node, None, None]:
        if self.callee is not None:
            yield self.callee
        for arg in self.arguments:
            if arg is not None:
                yield arg


@dataclass(repr=False)
class VbaMemberAccess(Expression):
    object: Expression | None = None
    member: str = ''

    def __post_init__(self):
        self._adopt(self.object)

    def children(self) -> Generator[Node, None, None]:
        if self.object is not None:
            yield self.object


@dataclass(repr=False)
class VbaBangAccess(Expression):
    object: Expression | None = None
    member: str = ''

    def __post_init__(self):
        self._adopt(self.object)

    def children(self) -> Generator[Node, None, None]:
        if self.object is not None:
            yield self.object


@dataclass(repr=False)
class VbaIndexExpression(Expression):
    object: Expression | None = None
    arguments: list[Expression | None] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.object, *[a for a in self.arguments if a is not None])

    def children(self) -> Generator[Node, None, None]:
        if self.object is not None:
            yield self.object
        for arg in self.arguments:
            if arg is not None:
                yield arg


@dataclass(repr=False)
class VbaNewExpression(Expression):
    class_name: Expression | None = None

    def __post_init__(self):
        self._adopt(self.class_name)

    def children(self) -> Generator[Node, None, None]:
        if self.class_name is not None:
            yield self.class_name


@dataclass(repr=False)
class VbaTypeOfIsExpression(Expression):
    operand: Expression | None = None
    type_name: Expression | None = None

    def __post_init__(self):
        self._adopt(self.operand, self.type_name)

    def children(self) -> Generator[Node, None, None]:
        if self.operand is not None:
            yield self.operand
        if self.type_name is not None:
            yield self.type_name


@dataclass(repr=False)
class VbaParenExpression(Expression):
    expression: Expression | None = None

    def __post_init__(self):
        self._adopt(self.expression)

    def children(self) -> Generator[Node, None, None]:
        if self.expression is not None:
            yield self.expression


@dataclass(repr=False)
class VbaModule(Script):
    pass


@dataclass(repr=False)
class VbaOptionStatement(Statement):
    keyword: str = ''
    value: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaDeclareStatement(Statement):
    scope: str = ''
    name: str = ''
    lib: str = ''
    alias: str = ''
    is_function: bool = False
    params: list[VbaParameter] = field(default_factory=list)
    return_type: str = ''
    raw: str = ''

    def __post_init__(self):
        self._adopt(*self.params)

    def children(self) -> Generator[Node, None, None]:
        yield from self.params


@dataclass(repr=False)
class VbaTypeDefinition(Statement):
    scope: str = ''
    name: str = ''
    members: list[VbaVariableDeclarator] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.members)

    def children(self) -> Generator[Node, None, None]:
        yield from self.members


@dataclass(repr=False)
class VbaEnumDefinition(Statement):
    scope: str = ''
    name: str = ''
    members: list[VbaEnumMember] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.members)

    def children(self) -> Generator[Node, None, None]:
        yield from self.members


@dataclass(repr=False)
class VbaEnumMember(Node):
    name: str = ''
    value: Expression | None = None

    def __post_init__(self):
        self._adopt(self.value)

    def children(self) -> Generator[Node, None, None]:
        if self.value is not None:
            yield self.value


@dataclass(repr=False)
class VbaConstDeclaration(Statement):
    scope: str = ''
    name: str = ''
    type_name: str = ''
    value: Expression | None = None

    def __post_init__(self):
        self._adopt(self.value)

    def children(self) -> Generator[Node, None, None]:
        if self.value is not None:
            yield self.value


@dataclass(repr=False)
class VbaVariableDeclarator(Node):
    name: str = ''
    type_name: str = ''
    is_array: bool = False
    bounds: list[Expression] = field(default_factory=list)
    is_new: bool = False

    def __post_init__(self):
        self._adopt(*self.bounds)

    def children(self) -> Generator[Node, None, None]:
        yield from self.bounds


@dataclass(repr=False)
class VbaVariableDeclaration(Statement):
    scope: str = ''
    declarators: list[VbaVariableDeclarator] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.declarators)

    def children(self) -> Generator[Node, None, None]:
        yield from self.declarators


@dataclass(repr=False)
class VbaEventDeclaration(Statement):
    scope: str = ''
    name: str = ''
    params: list[VbaParameter] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.params)

    def children(self) -> Generator[Node, None, None]:
        yield from self.params


@dataclass(repr=False)
class VbaParameter(Node):
    name: str = ''
    passing: str = ''
    type_name: str = ''
    is_optional: bool = False
    is_paramarray: bool = False
    default: Expression | None = None
    is_array: bool = False

    def __post_init__(self):
        self._adopt(self.default)

    def children(self) -> Generator[Node, None, None]:
        if self.default is not None:
            yield self.default


@dataclass(repr=False)
class VbaSubDeclaration(Statement):
    scope: str = ''
    name: str = ''
    params: list[VbaParameter] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)
    is_static: bool = False

    def __post_init__(self):
        self._adopt(*self.params, *self.body)

    def children(self) -> Generator[Node, None, None]:
        yield from self.params
        yield from self.body


@dataclass(repr=False)
class VbaFunctionDeclaration(Statement):
    scope: str = ''
    name: str = ''
    params: list[VbaParameter] = field(default_factory=list)
    return_type: str = ''
    body: list[Statement] = field(default_factory=list)
    is_static: bool = False

    def __post_init__(self):
        self._adopt(*self.params, *self.body)

    def children(self) -> Generator[Node, None, None]:
        yield from self.params
        yield from self.body


@dataclass(repr=False)
class VbaPropertyDeclaration(Statement):
    scope: str = ''
    kind: str = ''
    name: str = ''
    params: list[VbaParameter] = field(default_factory=list)
    return_type: str = ''
    body: list[Statement] = field(default_factory=list)
    is_static: bool = False

    def __post_init__(self):
        self._adopt(*self.params, *self.body)

    def children(self) -> Generator[Node, None, None]:
        yield from self.params
        yield from self.body


@dataclass(repr=False)
class VbaExpressionStatement(Statement):
    expression: Expression | None = None
    arguments: list[Expression | None] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(
            self.expression,
            *[a for a in self.arguments if a is not None],
        )

    def children(self) -> Generator[Node, None, None]:
        if self.expression is not None:
            yield self.expression
        for arg in self.arguments:
            if arg is not None:
                yield arg


@dataclass(repr=False)
class VbaCallStatement(Statement):
    callee: Expression | None = None
    arguments: list[Expression | None] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(
            self.callee,
            *[a for a in self.arguments if a is not None],
        )

    def children(self) -> Generator[Node, None, None]:
        if self.callee is not None:
            yield self.callee
        for arg in self.arguments:
            if arg is not None:
                yield arg


@dataclass(repr=False)
class VbaLetStatement(Statement):
    target: Expression | None = None
    value: Expression | None = None
    explicit: bool = False

    def __post_init__(self):
        self._adopt(self.target, self.value)

    def children(self) -> Generator[Node, None, None]:
        if self.target is not None:
            yield self.target
        if self.value is not None:
            yield self.value


@dataclass(repr=False)
class VbaSetStatement(Statement):
    target: Expression | None = None
    value: Expression | None = None

    def __post_init__(self):
        self._adopt(self.target, self.value)

    def children(self) -> Generator[Node, None, None]:
        if self.target is not None:
            yield self.target
        if self.value is not None:
            yield self.value


@dataclass(repr=False)
class VbaElseIfClause(Node):
    condition: Expression | None = None
    body: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.condition, *self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.condition is not None:
            yield self.condition
        yield from self.body


@dataclass(repr=False)
class VbaIfStatement(Statement):
    condition: Expression | None = None
    body: list[Statement] = field(default_factory=list)
    elseif_clauses: list[VbaElseIfClause] = field(default_factory=list)
    else_body: list[Statement] = field(default_factory=list)
    single_line: bool = False

    def __post_init__(self):
        self._adopt(self.condition, *self.body, *self.elseif_clauses, *self.else_body)

    def children(self) -> Generator[Node, None, None]:
        if self.condition is not None:
            yield self.condition
        yield from self.body
        yield from self.elseif_clauses
        yield from self.else_body


@dataclass(repr=False)
class VbaForStatement(Statement):
    variable: Expression | None = None
    start: Expression | None = None
    end: Expression | None = None
    step: Expression | None = None
    body: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.variable, self.start, self.end, self.step, *self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.variable is not None:
            yield self.variable
        if self.start is not None:
            yield self.start
        if self.end is not None:
            yield self.end
        if self.step is not None:
            yield self.step
        yield from self.body


@dataclass(repr=False)
class VbaForEachStatement(Statement):
    variable: Expression | None = None
    collection: Expression | None = None
    body: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.variable, self.collection, *self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.variable is not None:
            yield self.variable
        if self.collection is not None:
            yield self.collection
        yield from self.body


@dataclass(repr=False)
class VbaDoLoopStatement(Statement):
    condition: Expression | None = None
    condition_type: str = ''
    condition_position: str = ''
    body: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.condition, *self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.condition is not None:
            yield self.condition
        yield from self.body


@dataclass(repr=False)
class VbaWhileStatement(Statement):
    condition: Expression | None = None
    body: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.condition, *self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.condition is not None:
            yield self.condition
        yield from self.body


@dataclass(repr=False)
class VbaCaseClause(Node):
    tests: list[Expression] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)
    is_else: bool = False

    def __post_init__(self):
        self._adopt(*self.tests, *self.body)

    def children(self) -> Generator[Node, None, None]:
        yield from self.tests
        yield from self.body


@dataclass(repr=False)
class VbaSelectCaseStatement(Statement):
    expression: Expression | None = None
    cases: list[VbaCaseClause] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.expression, *self.cases)

    def children(self) -> Generator[Node, None, None]:
        if self.expression is not None:
            yield self.expression
        yield from self.cases


@dataclass(repr=False)
class VbaWithStatement(Statement):
    object: Expression | None = None
    body: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.object, *self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.object is not None:
            yield self.object
        yield from self.body


@dataclass(repr=False)
class VbaGotoStatement(Statement):
    label: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaGosubStatement(Statement):
    label: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaOnErrorStatement(Statement):
    action: str = ''
    label: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaExitStatement(Statement):
    kind: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaReturnStatement(Statement):
    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaRedimStatement(Statement):
    preserve: bool = False
    declarators: list[VbaVariableDeclarator] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.declarators)

    def children(self) -> Generator[Node, None, None]:
        yield from self.declarators


@dataclass(repr=False)
class VbaEraseStatement(Statement):
    targets: list[Expression] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.targets)

    def children(self) -> Generator[Node, None, None]:
        yield from self.targets


@dataclass(repr=False)
class VbaRaiseEventStatement(Statement):
    name: str = ''
    arguments: list[Expression] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.arguments)

    def children(self) -> Generator[Node, None, None]:
        yield from self.arguments


@dataclass(repr=False)
class VbaLabelStatement(Statement):
    label: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaStopStatement(Statement):
    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaEndStatement(Statement):
    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaDebugPrintStatement(Statement):
    arguments: list[Expression] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.arguments)

    def children(self) -> Generator[Node, None, None]:
        yield from self.arguments


@dataclass(repr=False)
class VbaResumeStatement(Statement):
    label: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False)
class VbaImplementsStatement(Statement):
    name: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()
