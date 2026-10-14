from __future__ import annotations

import enum

from dataclasses import dataclass, field

from refinery.lib.scripts import Expression, Node, Statement


class Au3ScopeKind(enum.Enum):
    DIM = 'Dim'
    LOCAL = 'Local'
    GLOBAL = 'Global'


@dataclass(repr=False, eq=False)
class Au3Script(Node):
    body: list[Statement] = field(default_factory=list)
    #: Every diagnostic the parser recorded: the error nodes it recovered whole and the repairs it
    #: synthesized. No pass reads the list: its texts also live in the tree — an error node is its
    #: own record, and a repair record names a token of a line the parser went on to read — while
    #: the list outlives the edits that remove those lines, so a pass over it would refuse a tree
    #: its own transforms had cleaned.
    errors: list[Au3ErrorNode] = field(default_factory=list)

    def early_errors(self) -> list[Au3WithMember]:
        """
        The leading-dot member accesses that no enclosing `With` statement owns: outside one, `.x`
        names nothing and no engine loads the file.
        """
        result = []
        for node in self.walk():
            if not isinstance(node, Au3WithMember):
                continue
            if not any(isinstance(a, Au3WithStatement) for a in _ancestors(node)):
                result.append(node)
        return result


def _ancestors(node: Node):
    cursor = node.parent
    while cursor is not None:
        yield cursor
        cursor = cursor.parent


@dataclass(repr=False, eq=False)
class Au3ErrorNode(Expression, Statement, unparsed=True):
    text: str = ''
    message: str = ''


@dataclass(repr=False, eq=False)
class Au3Directive(Statement):
    text: str = ''


@dataclass(repr=False, eq=False)
class Au3Include(Statement):
    library: bool = False
    path: str = ''


@dataclass(repr=False, eq=False)
class Au3IncludeOnce(Statement):
    pass


@dataclass(repr=False, eq=False)
class Au3IntLiteral(Expression, spelling='raw'):
    value: int = 0
    raw: str = '0'


@dataclass(repr=False, eq=False)
class Au3FloatLiteral(Expression, spelling='raw'):
    value: float = 0.0
    raw: str = '0.0'


@dataclass(repr=False, eq=False)
class Au3StringLiteral(Expression, spelling='raw'):
    value: str = ''
    raw: str = '""'


@dataclass(repr=False, eq=False)
class Au3BooleanLiteral(Expression):
    value: bool = False


@dataclass(repr=False, eq=False)
class Au3NullLiteral(Expression):
    pass


@dataclass(repr=False, eq=False)
class Au3DefaultLiteral(Expression):
    pass


@dataclass(repr=False, eq=False)
class Au3Variable(Expression, spelling='raw'):
    name: str = ''
    raw: str = '$'


@dataclass(repr=False, eq=False)
class Au3Macro(Expression, spelling='raw'):
    name: str = ''
    raw: str = '@'


@dataclass(repr=False, eq=False)
class Au3Identifier(Expression, spelling='raw'):
    name: str = ''
    raw: str = ''


@dataclass(repr=False, eq=False)
class Au3BinaryExpression(Expression):
    operator: str = ''
    left: Expression | None = None
    right: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3UnaryExpression(Expression):
    operator: str = ''
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3Assignment(Expression):
    target: Expression | None = None
    operator: str = '='
    value: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3Ternary(Expression):
    condition: Expression | None = None
    consequent: Expression | None = None
    alternate: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3ParenExpression(Expression):
    expression: Expression | None = None

    def canonical_form(self):
        return self.expression


@dataclass(repr=False, eq=False)
class Au3Call(Expression):
    callee: Expression | None = None
    arguments: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Au3ArrayAccess(Expression):
    array: Expression | None = None
    index: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3MemberAccess(Expression, spelling='raw'):
    object: Expression | None = None
    member: str = ''
    raw: str = ''


@dataclass(repr=False, eq=False)
class Au3WithMember(Expression, spelling='raw'):
    member: str = ''
    raw: str = ''


@dataclass(repr=False, eq=False)
class Au3ArrayLiteral(Expression):
    elements: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Au3CaseRange(Node):
    start: Expression | None = None
    end: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3ExpressionStatement(Statement):
    expression: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3IfStatement(Statement):
    test: Expression | None = None
    body: list[Statement] = field(default_factory=list)
    elseifs: list[Au3ElseIf] = field(default_factory=list)
    else_body: list[Statement] | None = None


@dataclass(repr=False, eq=False)
class Au3ElseIf(Node):
    test: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Au3WhileStatement(Statement):
    test: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Au3DoUntilStatement(Statement):
    body: list[Statement] = field(default_factory=list)
    test: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3ForStatement(Statement):
    variable: Au3Variable | None = None
    start: Expression | None = None
    limit: Expression | None = None
    step: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Au3ForInStatement(Statement):
    variable: Au3Variable | None = None
    iterable: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Au3SelectStatement(Statement):
    cases: list[Au3SelectCase] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Au3SelectCase(Node):
    test: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Au3SwitchStatement(Statement):
    discriminant: Expression | None = None
    cases: list[Au3SwitchCase] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Au3SwitchCase(Node):
    values: list[Node] | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Au3WithStatement(Statement):
    object: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Au3VariableDeclaration(Statement):
    declarations: list[Au3VariableDeclarator] = field(default_factory=list)
    scope: Au3ScopeKind | None = None
    is_const: bool = False
    is_static: bool = False


@dataclass(repr=False, eq=False)
class Au3VariableDeclarator(Node):
    variable: Au3Variable | None = None
    dimensions: list[Expression | None] = field(default_factory=list)
    initializer: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3EnumDeclaration(Statement):
    declarations: list[Au3EnumDeclarator] = field(default_factory=list)
    scope: Au3ScopeKind | None = None
    is_const: bool = False
    step_operator: str = '+'
    step_value: int = 1


@dataclass(repr=False, eq=False)
class Au3EnumDeclarator(Node):
    variable: Au3Variable | None = None
    initializer: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3ReDimStatement(Statement):
    targets: list[Au3ReDimTarget] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Au3ReDimTarget(Node):
    variable: Au3Variable | None = None
    dimensions: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class Au3FunctionDeclaration(Statement):
    name: Au3Identifier | None = None
    params: list[Au3Parameter] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)
    is_volatile: bool = False


@dataclass(repr=False, eq=False)
class Au3Parameter(Node):
    variable: Au3Variable | None = None
    by_ref: bool = False
    is_const: bool = False
    default: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3ReturnStatement(Statement):
    value: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3ExitStatement(Statement):
    code: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3ExitLoopStatement(Statement):
    level: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3ContinueLoopStatement(Statement):
    level: Expression | None = None


@dataclass(repr=False, eq=False)
class Au3ContinueCaseStatement(Statement):
    pass
