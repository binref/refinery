from __future__ import annotations

import enum

from dataclasses import dataclass, field

from refinery.lib.scripts import Expression, Node, Statement


class PhpNameKind(enum.Enum):
    UNQUALIFIED = 'unqualified'
    QUALIFIED = 'qualified'
    FULLY_QUALIFIED = 'fully-qualified'
    RELATIVE = 'relative'


class PhpUseKind(enum.Enum):
    NORMAL = 'normal'
    FUNCTION = 'function'
    CONSTANT = 'const'


class PhpVisibility(enum.Enum):
    PUBLIC = 'public'
    PROTECTED = 'protected'
    PRIVATE = 'private'


class PhpClassKind(enum.Enum):
    CLASS = 'class'
    INTERFACE = 'interface'
    TRAIT = 'trait'
    ENUM = 'enum'


@dataclass(repr=False, eq=False)
class PhpScript(Node):
    body: list[Statement] = field(default_factory=list)
    errors: list[PhpErrorNode] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpErrorNode(Expression, Statement):
    text: str = ''
    message: str = ''


@dataclass(repr=False, eq=False)
class PhpName(Expression):
    parts: list[str] = field(default_factory=list)
    kind: PhpNameKind = PhpNameKind.UNQUALIFIED


@dataclass(repr=False, eq=False)
class PhpIdentifier(Expression):
    name: str = ''


@dataclass(repr=False, eq=False)
class PhpVariable(Expression):
    name: str = ''


@dataclass(repr=False, eq=False)
class PhpVariableVariable(Expression):
    expression: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpIntLiteral(Expression):
    value: int = 0
    raw: str = '0'


@dataclass(repr=False, eq=False)
class PhpFloatLiteral(Expression):
    value: float = 0.0
    raw: str = '0.0'


@dataclass(repr=False, eq=False)
class PhpStringLiteral(Expression):
    value: str = ''
    raw: str = "''"


@dataclass(repr=False, eq=False)
class PhpInterpolatedString(Expression):
    raw: str = '""'


@dataclass(repr=False, eq=False)
class PhpHeredoc(Expression):
    raw: str = ''
    nowdoc: bool = False


@dataclass(repr=False, eq=False)
class PhpShellExec(Expression):
    raw: str = '``'


@dataclass(repr=False, eq=False)
class PhpBooleanLiteral(Expression):
    value: bool = False
    raw: str = 'true'


@dataclass(repr=False, eq=False)
class PhpNullLiteral(Expression):
    raw: str = 'null'

    @property
    def value(self):
        return None


@dataclass(repr=False, eq=False)
class PhpMagicConstant(Expression):
    name: str = ''


@dataclass(repr=False, eq=False)
class PhpArray(Expression):
    items: list[PhpArrayItem | None] = field(default_factory=list)
    short: bool = True


@dataclass(repr=False, eq=False)
class PhpArrayItem(Node):
    value: Expression | None = None
    key: Expression | None = None
    by_ref: bool = False
    spread: bool = False


@dataclass(repr=False, eq=False)
class PhpBinaryExpression(Expression):
    operator: str = ''
    left: Expression | None = None
    right: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpUnaryExpression(Expression):
    operator: str = ''
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpUpdateExpression(Expression):
    operator: str = ''
    operand: Expression | None = None
    prefix: bool = False


@dataclass(repr=False, eq=False)
class PhpCastExpression(Expression):
    cast: str = ''
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpErrorSuppress(Expression):
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpAssignment(Expression):
    operator: str = '='
    target: Expression | None = None
    value: Expression | None = None
    by_ref: bool = False


@dataclass(repr=False, eq=False)
class PhpTernary(Expression):
    condition: Expression | None = None
    consequent: Expression | None = None
    alternate: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpParenExpression(Expression):
    expression: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpInstanceof(Expression):
    operand: Expression | None = None
    class_name: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpArg(Node):
    value: Expression | None = None
    name: str | None = None
    spread: bool = False
    by_ref: bool = False


@dataclass(repr=False, eq=False)
class PhpFirstClassCallable(Node):
    pass


@dataclass(repr=False, eq=False)
class PhpFunctionCall(Expression):
    callee: Expression | None = None
    args: list[PhpArg] = field(default_factory=list)
    first_class_callable: bool = False


@dataclass(repr=False, eq=False)
class PhpMethodCall(Expression):
    receiver: Expression | None = None
    method: Expression | None = None
    args: list[PhpArg] = field(default_factory=list)
    nullsafe: bool = False
    first_class_callable: bool = False


@dataclass(repr=False, eq=False)
class PhpStaticCall(Expression):
    class_name: Expression | None = None
    method: Expression | None = None
    args: list[PhpArg] = field(default_factory=list)
    first_class_callable: bool = False


@dataclass(repr=False, eq=False)
class PhpNew(Expression):
    class_name: Expression | None = None
    args: list[PhpArg] = field(default_factory=list)
    has_parens: bool = False


@dataclass(repr=False, eq=False)
class PhpNewAnonymous(Expression):
    args: list[PhpArg] = field(default_factory=list)
    declaration: PhpClass | None = None
    has_parens: bool = False


@dataclass(repr=False, eq=False)
class PhpClone(Expression):
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpPropertyFetch(Expression):
    receiver: Expression | None = None
    name: Expression | None = None
    nullsafe: bool = False


@dataclass(repr=False, eq=False)
class PhpStaticPropertyFetch(Expression):
    class_name: Expression | None = None
    name: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpClassConstFetch(Expression):
    class_name: Expression | None = None
    name: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpArrayDimFetch(Expression):
    receiver: Expression | None = None
    index: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpClosure(Expression):
    params: list[PhpParam] = field(default_factory=list)
    uses: list[PhpClosureUse] = field(default_factory=list)
    return_type: Expression | None = None
    body: PhpBlock | None = None
    is_static: bool = False
    by_ref: bool = False
    attributes: list[PhpAttributeGroup] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpClosureUse(Node):
    variable: PhpVariable | None = None
    by_ref: bool = False


@dataclass(repr=False, eq=False)
class PhpArrowFunction(Expression):
    params: list[PhpParam] = field(default_factory=list)
    return_type: Expression | None = None
    body: Expression | None = None
    is_static: bool = False
    by_ref: bool = False
    attributes: list[PhpAttributeGroup] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpMatch(Expression):
    subject: Expression | None = None
    arms: list[PhpMatchArm] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpMatchArm(Node):
    conditions: list[Expression] = field(default_factory=list)
    body: Expression | None = None
    is_default: bool = False


@dataclass(repr=False, eq=False)
class PhpList(Expression):
    items: list[PhpArrayItem | None] = field(default_factory=list)
    short: bool = False


@dataclass(repr=False, eq=False)
class PhpIsset(Expression):
    variables: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpEmpty(Expression):
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpEval(Expression):
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpInclude(Expression):
    kind: str = 'include'
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpExit(Expression):
    operand: Expression | None = None
    keyword: str = 'exit'


@dataclass(repr=False, eq=False)
class PhpPrint(Expression):
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpThrowExpression(Expression):
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpYield(Expression):
    key: Expression | None = None
    value: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpYieldFrom(Expression):
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpConstFetch(Expression):
    name: PhpName | None = None


@dataclass(repr=False, eq=False)
class PhpNullableType(Expression):
    type: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpUnionType(Expression):
    types: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpIntersectionType(Expression):
    types: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpParam(Node):
    name: str = ''
    type: Expression | None = None
    default: Expression | None = None
    by_ref: bool = False
    variadic: bool = False
    visibility: PhpVisibility | None = None
    readonly: bool = False
    attributes: list[PhpAttributeGroup] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpAttribute(Node):
    name: PhpName | None = None
    args: list[PhpArg] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpAttributeGroup(Node):
    attributes: list[PhpAttribute] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpExpressionStatement(Statement):
    expression: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpInlineHTML(Statement):
    value: str = ''


@dataclass(repr=False, eq=False)
class PhpEchoTagStatement(Statement):
    expressions: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpEcho(Statement):
    expressions: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpBlock(Statement):
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpIf(Statement):
    condition: Expression | None = None
    consequent: list[Statement] = field(default_factory=list)
    elseifs: list[PhpElseIf] = field(default_factory=list)
    alternate: list[Statement] | None = None
    alternative_syntax: bool = False


@dataclass(repr=False, eq=False)
class PhpElseIf(Node):
    condition: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpWhile(Statement):
    condition: Expression | None = None
    body: list[Statement] = field(default_factory=list)
    alternative_syntax: bool = False


@dataclass(repr=False, eq=False)
class PhpDoWhile(Statement):
    body: list[Statement] = field(default_factory=list)
    condition: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpFor(Statement):
    init: list[Expression] = field(default_factory=list)
    condition: list[Expression] = field(default_factory=list)
    update: list[Expression] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)
    alternative_syntax: bool = False


@dataclass(repr=False, eq=False)
class PhpForeach(Statement):
    subject: Expression | None = None
    key: Expression | None = None
    value: Expression | None = None
    by_ref: bool = False
    body: list[Statement] = field(default_factory=list)
    alternative_syntax: bool = False


@dataclass(repr=False, eq=False)
class PhpSwitch(Statement):
    subject: Expression | None = None
    cases: list[PhpCase] = field(default_factory=list)
    alternative_syntax: bool = False


@dataclass(repr=False, eq=False)
class PhpCase(Node):
    test: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpBreak(Statement):
    level: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpContinue(Statement):
    level: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpReturn(Statement):
    value: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpGoto(Statement):
    label: str = ''


@dataclass(repr=False, eq=False)
class PhpLabel(Statement):
    name: str = ''


@dataclass(repr=False, eq=False)
class PhpThrowStatement(Statement):
    operand: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpTry(Statement):
    body: list[Statement] = field(default_factory=list)
    catches: list[PhpCatch] = field(default_factory=list)
    finally_body: list[Statement] | None = None


@dataclass(repr=False, eq=False)
class PhpCatch(Node):
    types: list[PhpName] = field(default_factory=list)
    variable: PhpVariable | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpUnset(Statement):
    variables: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpGlobal(Statement):
    variables: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpStaticVar(Statement):
    declarations: list[PhpStaticVarDeclaration] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpStaticVarDeclaration(Node):
    variable: Expression | None = None
    default: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpNop(Statement):
    pass


@dataclass(repr=False, eq=False)
class PhpHaltCompiler(Statement):
    remainder: str = ''


@dataclass(repr=False, eq=False)
class PhpFunctionDeclaration(Statement):
    name: str = ''
    params: list[PhpParam] = field(default_factory=list)
    return_type: Expression | None = None
    body: PhpBlock | None = None
    by_ref: bool = False
    attributes: list[PhpAttributeGroup] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpClass(Statement):
    name: str = ''
    kind: PhpClassKind = PhpClassKind.CLASS
    extends: list[PhpName] = field(default_factory=list)
    implements: list[PhpName] = field(default_factory=list)
    members: list[Statement] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    enum_backing_type: Expression | None = None
    attributes: list[PhpAttributeGroup] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpClassConst(Statement):
    consts: list[PhpConstDeclaration] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    type: Expression | None = None
    attributes: list[PhpAttributeGroup] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpConstDeclaration(Node):
    name: str = ''
    value: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpProperty(Statement):
    props: list[PhpPropertyDeclaration] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    type: Expression | None = None
    attributes: list[PhpAttributeGroup] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpPropertyDeclaration(Node):
    variable: PhpVariable | None = None
    default: Expression | None = None


@dataclass(repr=False, eq=False)
class PhpClassMethod(Statement):
    name: str = ''
    params: list[PhpParam] = field(default_factory=list)
    return_type: Expression | None = None
    body: PhpBlock | None = None
    modifiers: list[str] = field(default_factory=list)
    by_ref: bool = False
    attributes: list[PhpAttributeGroup] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpEnumCase(Statement):
    name: str = ''
    value: Expression | None = None
    attributes: list[PhpAttributeGroup] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpTraitUse(Statement):
    traits: list[PhpName] = field(default_factory=list)
    adaptations: list[PhpTraitAdaptation] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpTraitAdaptation(Node):
    trait: PhpName | None = None
    method: str = ''
    kind: str = 'alias'
    new_name: str | None = None
    new_modifier: str | None = None
    insteadof: list[PhpName] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpNamespace(Statement):
    name: PhpName | None = None
    body: list[Statement] | None = None


@dataclass(repr=False, eq=False)
class PhpUse(Statement):
    uses: list[PhpUseItem] = field(default_factory=list)
    kind: PhpUseKind = PhpUseKind.NORMAL


@dataclass(repr=False, eq=False)
class PhpUseItem(Node):
    name: PhpName | None = None
    alias: str | None = None
    kind: PhpUseKind | None = None


@dataclass(repr=False, eq=False)
class PhpGroupUse(Statement):
    prefix: PhpName | None = None
    uses: list[PhpUseItem] = field(default_factory=list)
    kind: PhpUseKind = PhpUseKind.NORMAL


@dataclass(repr=False, eq=False)
class PhpConst(Statement):
    consts: list[PhpConstDeclaration] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class PhpDeclare(Statement):
    directives: list[PhpDeclareDirective] = field(default_factory=list)
    body: list[Statement] | None = None
    alternative_syntax: bool = False


@dataclass(repr=False, eq=False)
class PhpDeclareDirective(Node):
    name: str = ''
    value: Expression | None = None
