from __future__ import annotations

import enum

from dataclasses import dataclass, field

from refinery.lib.scripts import Expression, Node, Script, Statement


class VbaLoopConditionType(enum.Enum):
    WHILE = 'While'
    UNTIL = 'Until'


class VbaLoopConditionPosition(enum.Enum):
    PRE = 'pre'
    POST = 'post'


class VbaScopeModifier(enum.Enum):
    NONE = ''
    PUBLIC = 'Public'
    PRIVATE = 'Private'
    FRIEND = 'Friend'
    DIM = 'Dim'
    GLOBAL = 'Global'
    STATIC = 'Static'


class VbaPropertyKind(enum.Enum):
    GET = 'Get'
    LET = 'Let'
    SET = 'Set'


class VbaExitKind(enum.Enum):
    SUB = 'Sub'
    FUNCTION = 'Function'
    DO = 'Do'
    FOR = 'For'
    PROPERTY = 'Property'


class VbaOnErrorAction(enum.Enum):
    NONE = ''
    GOTO = 'GoTo'
    RESUME = 'Resume'
    RESUME_NEXT = 'ResumeNext'


class VbaOnBranchKind(enum.Enum):
    GOTO = 'GoTo'
    GOSUB = 'GoSub'


class VbaParameterPassing(enum.Enum):
    NONE = ''
    BY_VAL = 'ByVal'
    BY_REF = 'ByRef'


@dataclass(repr=False, eq=False)
class VbaErrorNode(Expression, Statement):
    text: str = ''
    message: str = ''


@dataclass(repr=False, eq=False)
class VbaIdentifier(Expression):
    name: str = ''


@dataclass(repr=False, eq=False)
class VbaMeExpression(Expression):
    pass


@dataclass(repr=False, eq=False)
class VbaIntegerLiteral(Expression):
    value: int = 0
    raw: str = '0'


@dataclass(repr=False, eq=False)
class VbaFloatLiteral(Expression):
    value: float = 0.0
    raw: str = '0'


@dataclass(repr=False, eq=False)
class VbaStringLiteral(Expression):
    value: str = ''
    raw: str = '""'


@dataclass(repr=False, eq=False)
class VbaDateLiteral(Expression):
    raw: str = '##'


@dataclass(repr=False, eq=False)
class VbaBooleanLiteral(Expression):
    value: bool = False


@dataclass(repr=False, eq=False)
class VbaNothingLiteral(Expression):
    pass


@dataclass(repr=False, eq=False)
class VbaNullLiteral(Expression):
    pass


@dataclass(repr=False, eq=False)
class VbaEmptyLiteral(Expression):
    pass


@dataclass(repr=False, eq=False)
class VbaBinaryExpression(Expression):
    left: Expression | None = None
    operator: str = ''
    right: Expression | None = None


@dataclass(repr=False, eq=False)
class VbaUnaryExpression(Expression):
    operator: str = ''
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class VbaNamedArgument(Expression):
    name: str = ''
    expression: Expression | None = None


@dataclass(repr=False, eq=False)
class VbaByValArgument(Expression):
    expression: Expression | None = None


@dataclass(repr=False, eq=False)
class VbaCallExpression(Expression):
    callee: Expression | None = None
    arguments: list[Expression | None] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaMemberAccess(Expression):
    object: Expression | None = None
    member: str = ''


@dataclass(repr=False, eq=False)
class VbaBangAccess(Expression):
    object: Expression | None = None
    member: str = ''


@dataclass(repr=False, eq=False)
class VbaNewExpression(Expression):
    class_name: Expression | None = None


@dataclass(repr=False, eq=False)
class VbaTypeOfIsExpression(Expression):
    operand: Expression | None = None
    type_name: Expression | None = None


@dataclass(repr=False, eq=False)
class VbaParenExpression(Expression):
    expression: Expression | None = None


@dataclass(repr=False, eq=False)
class VbaRangeExpression(Expression):
    start: Expression | None = None
    end: Expression | None = None


@dataclass(repr=False, eq=False)
class VbaModule(Script):
    pass


@dataclass(repr=False, eq=False)
class VbaOptionStatement(Statement):
    keyword: str = ''
    value: str = ''


@dataclass(repr=False, eq=False)
class VbaDeclareStatement(Statement):
    scope: VbaScopeModifier = VbaScopeModifier.NONE
    name: str = ''
    lib: str = ''
    alias: str = ''
    is_function: bool = False
    params: list[VbaParameter] = field(default_factory=list)
    return_type: str = ''


@dataclass(repr=False, eq=False)
class VbaTypeDefinition(Statement):
    scope: VbaScopeModifier = VbaScopeModifier.NONE
    name: str = ''
    members: list[VbaVariableDeclarator] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaEnumDefinition(Statement):
    scope: VbaScopeModifier = VbaScopeModifier.NONE
    name: str = ''
    members: list[VbaEnumMember] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaEnumMember(Node):
    name: str = ''
    value: Expression | None = None


@dataclass(repr=False, eq=False)
class VbaConstDeclarator(Node):
    name: str = ''
    type_name: str = ''
    value: Expression | None = None


@dataclass(repr=False, eq=False)
class VbaConstDeclaration(Statement):
    scope: VbaScopeModifier = VbaScopeModifier.NONE
    declarators: list[VbaConstDeclarator] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaVariableDeclarator(Node):
    name: str = ''
    type_name: str = ''
    is_array: bool = False
    bounds: list[Expression] = field(default_factory=list)
    is_new: bool = False
    with_events: bool = False


@dataclass(repr=False, eq=False)
class VbaVariableDeclaration(Statement):
    scope: VbaScopeModifier = VbaScopeModifier.NONE
    declarators: list[VbaVariableDeclarator] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaEventDeclaration(Statement):
    scope: VbaScopeModifier = VbaScopeModifier.NONE
    name: str = ''
    params: list[VbaParameter] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaParameter(Node):
    name: str = ''
    passing: VbaParameterPassing = VbaParameterPassing.NONE
    type_name: str = ''
    is_optional: bool = False
    is_paramarray: bool = False
    default: Expression | None = None
    is_array: bool = False


@dataclass(repr=False, eq=False)
class VbaProcedureDeclaration(Statement):
    scope: VbaScopeModifier = VbaScopeModifier.NONE
    name: str = ''
    params: list[VbaParameter] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)
    is_static: bool = False


@dataclass(repr=False, eq=False)
class VbaSubDeclaration(VbaProcedureDeclaration):
    pass


@dataclass(repr=False, eq=False)
class VbaFunctionDeclaration(VbaProcedureDeclaration):
    return_type: str = ''


@dataclass(repr=False, eq=False)
class VbaPropertyDeclaration(VbaProcedureDeclaration):
    kind: VbaPropertyKind = VbaPropertyKind.GET
    return_type: str = ''


@dataclass(repr=False, eq=False)
class VbaExpressionStatement(Statement):
    expression: Expression | None = None
    arguments: list[Expression | None] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaCallStatement(Statement):
    callee: Expression | None = None
    arguments: list[Expression | None] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaLetStatement(Statement):
    target: Expression | None = None
    value: Expression | None = None
    explicit: bool = False
    keyword: str = ''


@dataclass(repr=False, eq=False)
class VbaSetStatement(Statement):
    target: Expression | None = None
    value: Expression | None = None


@dataclass(repr=False, eq=False)
class VbaElseIfClause(Node):
    condition: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaIfStatement(Statement):
    condition: Expression | None = None
    body: list[Statement] = field(default_factory=list)
    elseif_clauses: list[VbaElseIfClause] = field(default_factory=list)
    else_body: list[Statement] = field(default_factory=list)
    single_line: bool = False


@dataclass(repr=False, eq=False)
class VbaForStatement(Statement):
    variable: Expression | None = None
    start: Expression | None = None
    end: Expression | None = None
    step: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaForEachStatement(Statement):
    variable: Expression | None = None
    collection: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaDoLoopStatement(Statement):
    condition: Expression | None = None
    condition_type: VbaLoopConditionType | None = None
    condition_position: VbaLoopConditionPosition | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaWhileStatement(Statement):
    condition: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaCaseClause(Node):
    tests: list[Expression] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)
    is_else: bool = False


@dataclass(repr=False, eq=False)
class VbaSelectCaseStatement(Statement):
    expression: Expression | None = None
    cases: list[VbaCaseClause] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaWithStatement(Statement):
    object: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaGotoStatement(Statement):
    label: str = ''


@dataclass(repr=False, eq=False)
class VbaGosubStatement(Statement):
    label: str = ''


@dataclass(repr=False, eq=False)
class VbaOnErrorStatement(Statement):
    action: VbaOnErrorAction = VbaOnErrorAction.NONE
    label: str = ''


@dataclass(repr=False, eq=False)
class VbaOnBranchStatement(Statement):
    expression: Expression = field(default_factory=lambda: VbaIntegerLiteral(value=0))
    kind: VbaOnBranchKind = VbaOnBranchKind.GOTO
    labels: list[str] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaExitStatement(Statement):
    kind: VbaExitKind = VbaExitKind.SUB


@dataclass(repr=False, eq=False)
class VbaReturnStatement(Statement):
    pass


@dataclass(repr=False, eq=False)
class VbaRedimStatement(Statement):
    preserve: bool = False
    declarators: list[VbaVariableDeclarator] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaEraseStatement(Statement):
    targets: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaRaiseEventStatement(Statement):
    name: str = ''
    arguments: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaLabelStatement(Statement):
    label: str = ''


@dataclass(repr=False, eq=False)
class VbaStopStatement(Statement):
    pass


@dataclass(repr=False, eq=False)
class VbaEndStatement(Statement):
    pass


@dataclass(repr=False, eq=False)
class VbaDebugPrintStatement(Statement):
    method: str = 'Print'
    arguments: list[Expression] = field(default_factory=list)
    separators: list[str] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class VbaResumeStatement(Statement):
    label: str = ''


@dataclass(repr=False, eq=False)
class VbaImplementsStatement(Statement):
    name: str = ''
