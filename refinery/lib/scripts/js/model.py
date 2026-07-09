from __future__ import annotations

import enum

from dataclasses import dataclass, field

from refinery.lib.scripts import Expression, Node, Statement


class JsPropertyKind(enum.Enum):
    INIT = 'init'
    GET  = 'get'   # noqa
    SET  = 'set'   # noqa


class JsMethodKind(enum.Enum):
    METHOD      = 'method'       # noqa
    GET         = 'get'          # noqa
    SET         = 'set'          # noqa
    CONSTRUCTOR = 'constructor'  # noqa


class JsVarKind(enum.Enum):
    VAR   = 'var'    # noqa
    LET   = 'let'    # noqa
    CONST = 'const'  # noqa


@dataclass(repr=False, eq=False)
class JsErrorNode(Expression, Statement):
    text: str = ''
    message: str = ''


@dataclass(repr=False, eq=False)
class JsIdentifier(Expression):
    name: str = ''


@dataclass(repr=False, eq=False)
class JsPrivateIdentifier(Expression):
    name: str = ''


@dataclass(repr=False, eq=False)
class JsNumericLiteral(Expression):
    value: int | float = 0
    raw: str = '0'


@dataclass(repr=False, eq=False)
class JsBigIntLiteral(Expression):
    value: int = 0
    raw: str = '0n'


@dataclass(repr=False, eq=False)
class JsStringLiteral(Expression):
    value: str = ''
    raw: str = "''"


@dataclass(repr=False, eq=False)
class JsRegExpLiteral(Expression):
    pattern: str = ''
    flags: str = ''
    raw: str = '//'


@dataclass(repr=False, eq=False)
class JsTemplateLiteral(Expression):
    quasis: list[JsTemplateElement] = field(default_factory=list)
    expressions: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsTemplateElement(Node):
    value: str = ''
    raw: str = ''
    tail: bool = False


@dataclass(repr=False, eq=False)
class JsBooleanLiteral(Expression):
    value: bool = False


@dataclass(repr=False, eq=False)
class JsNullLiteral(Expression):
    @property
    def value(self):
        return None


@dataclass(repr=False, eq=False)
class JsThisExpression(Expression):
    pass


@dataclass(repr=False, eq=False)
class JsArrayExpression(Expression):
    elements: list[Expression | None] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsObjectExpression(Expression):
    properties: list[JsProperty | JsSpreadElement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsProperty(Node):
    key: Expression | None = None
    value: Expression | None = None
    computed: bool = False
    shorthand: bool = False
    method: bool = False
    kind: JsPropertyKind = JsPropertyKind.INIT


@dataclass(repr=False, eq=False)
class JsSpreadElement(Expression):
    argument: Expression | None = None


@dataclass(repr=False, eq=False)
class JsFunctionExpression(Expression):
    id: JsIdentifier | None = None
    params: list[Expression] = field(default_factory=list)
    body: JsBlockStatement | None = None
    generator: bool = False
    is_async: bool = False


@dataclass(repr=False, eq=False)
class JsArrowFunctionExpression(Expression):
    params: list[Expression] = field(default_factory=list)
    body: Expression | JsBlockStatement | None = None
    is_async: bool = False


@dataclass(repr=False, eq=False)
class JsClassExpression(Expression):
    id: JsIdentifier | None = None
    super_class: Expression | None = None
    body: JsClassBody | None = None


@dataclass(repr=False, eq=False)
class JsUnaryExpression(Expression):
    operator: str = ''
    operand: Expression | None = None
    prefix: bool = True


@dataclass(repr=False, eq=False)
class JsUpdateExpression(Expression):
    operator: str = ''
    argument: Expression | None = None
    prefix: bool = True


@dataclass(repr=False, eq=False)
class JsBinaryExpression(Expression):
    left: Expression | None = None
    operator: str = ''
    right: Expression | None = None


@dataclass(repr=False, eq=False)
class JsLogicalExpression(Expression):
    left: Expression | None = None
    operator: str = ''
    right: Expression | None = None


@dataclass(repr=False, eq=False)
class JsAssignmentExpression(Expression):
    left: Expression | None = None
    operator: str = '='
    right: Expression | None = None


@dataclass(repr=False, eq=False)
class JsConditionalExpression(Expression):
    test: Expression | None = None
    consequent: Expression | None = None
    alternate: Expression | None = None


@dataclass(repr=False, eq=False)
class JsMemberExpression(Expression):
    object: Expression | None = None
    property: Expression | None = None
    computed: bool = False
    optional: bool = False


@dataclass(repr=False, eq=False)
class JsCallExpression(Expression):
    callee: Expression | None = None
    arguments: list[Expression] = field(default_factory=list)
    optional: bool = False


@dataclass(repr=False, eq=False)
class JsNewExpression(Expression):
    callee: Expression | None = None
    arguments: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsSequenceExpression(Expression):
    expressions: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsYieldExpression(Expression):
    argument: Expression | None = None
    delegate: bool = False


@dataclass(repr=False, eq=False)
class JsAwaitExpression(Expression):
    argument: Expression | None = None


@dataclass(repr=False, eq=False)
class JsTaggedTemplateExpression(Expression):
    tag: Expression | None = None
    quasi: JsTemplateLiteral | None = None


@dataclass(repr=False, eq=False)
class JsParenthesizedExpression(Expression):
    expression: Expression | None = None


@dataclass(repr=False, eq=False)
class JsArrayPattern(Expression):
    elements: list[Expression | None] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsObjectPattern(Expression):
    properties: list[JsProperty | JsRestElement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsAssignmentPattern(Expression):
    left: Expression | None = None
    right: Expression | None = None


@dataclass(repr=False, eq=False)
class JsRestElement(Expression):
    argument: Expression | None = None


@dataclass(repr=False, eq=False)
class JsClassBody(Node):
    body: list[JsMethodDefinition | JsPropertyDefinition] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsMethodDefinition(Node):
    key: Expression | None = None
    value: JsFunctionExpression | None = None
    kind: JsMethodKind = JsMethodKind.METHOD
    computed: bool = False
    is_static: bool = False


@dataclass(repr=False, eq=False)
class JsPropertyDefinition(Node):
    key: Expression | None = None
    value: Expression | None = None
    computed: bool = False
    is_static: bool = False


@dataclass(repr=False, eq=False)
class JsExpressionStatement(Statement):
    expression: Expression | None = None


@dataclass(repr=False, eq=False)
class JsBlockStatement(Statement):
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsEmptyStatement(Statement):
    pass


@dataclass(repr=False, eq=False)
class JsVariableDeclaration(Statement):
    declarations: list[JsVariableDeclarator] = field(default_factory=list)
    kind: JsVarKind = JsVarKind.VAR


@dataclass(repr=False, eq=False)
class JsVariableDeclarator(Node):
    id: Expression | None = None
    init: Expression | None = None


@dataclass(repr=False, eq=False)
class JsIfStatement(Statement):
    test: Expression | None = None
    consequent: Statement | None = None
    alternate: Statement | None = None


@dataclass(repr=False, eq=False)
class JsWhileStatement(Statement):
    test: Expression | None = None
    body: Statement | None = None


@dataclass(repr=False, eq=False)
class JsDoWhileStatement(Statement):
    test: Expression | None = None
    body: Statement | None = None


@dataclass(repr=False, eq=False)
class JsForStatement(Statement):
    init: Expression | Statement | None = None
    test: Expression | None = None
    update: Expression | None = None
    body: Statement | None = None


@dataclass(repr=False, eq=False)
class JsForInStatement(Statement):
    left: Expression | Statement | None = None
    right: Expression | None = None
    body: Statement | None = None


@dataclass(repr=False, eq=False)
class JsForOfStatement(Statement):
    left: Expression | Statement | None = None
    right: Expression | None = None
    body: Statement | None = None
    is_await: bool = False


@dataclass(repr=False, eq=False)
class JsSwitchStatement(Statement):
    discriminant: Expression | None = None
    cases: list[JsSwitchCase] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsSwitchCase(Node):
    test: Expression | None = None
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsTryStatement(Statement):
    block: JsBlockStatement | None = None
    handler: JsCatchClause | None = None
    finalizer: JsBlockStatement | None = None


@dataclass(repr=False, eq=False)
class JsCatchClause(Node):
    param: Expression | None = None
    body: JsBlockStatement | None = None


@dataclass(repr=False, eq=False)
class JsThrowStatement(Statement):
    argument: Expression | None = None


@dataclass(repr=False, eq=False)
class JsReturnStatement(Statement):
    argument: Expression | None = None


@dataclass(repr=False, eq=False)
class JsBreakStatement(Statement):
    label: JsIdentifier | None = None


@dataclass(repr=False, eq=False)
class JsContinueStatement(Statement):
    label: JsIdentifier | None = None


@dataclass(repr=False, eq=False)
class JsLabeledStatement(Statement):
    label: JsIdentifier | None = None
    body: Statement | None = None


@dataclass(repr=False, eq=False)
class JsWithStatement(Statement):
    object: Expression | None = None
    body: Statement | None = None


@dataclass(repr=False, eq=False)
class JsDebuggerStatement(Statement):
    pass


@dataclass(repr=False, eq=False)
class JsFunctionDeclaration(Statement):
    id: JsIdentifier | None = None
    params: list[Expression] = field(default_factory=list)
    body: JsBlockStatement | None = None
    generator: bool = False
    is_async: bool = False


@dataclass(repr=False, eq=False)
class JsClassDeclaration(Statement):
    id: JsIdentifier | None = None
    super_class: Expression | None = None
    body: JsClassBody | None = None


@dataclass(repr=False, eq=False)
class JsImportSpecifier(Node):
    imported: JsIdentifier | None = None
    local: JsIdentifier | None = None


@dataclass(repr=False, eq=False)
class JsImportDefaultSpecifier(Node):
    local: JsIdentifier | None = None


@dataclass(repr=False, eq=False)
class JsImportNamespaceSpecifier(Node):
    local: JsIdentifier | None = None


@dataclass(repr=False, eq=False)
class JsImportDeclaration(Statement):
    specifiers: list[
        JsImportSpecifier | JsImportDefaultSpecifier | JsImportNamespaceSpecifier
    ] = field(default_factory=list)
    source: JsStringLiteral | None = None


@dataclass(repr=False, eq=False)
class JsExportSpecifier(Node):
    local: JsIdentifier | None = None
    exported: JsIdentifier | None = None


@dataclass(repr=False, eq=False)
class JsExportNamedDeclaration(Statement):
    declaration: Statement | None = None
    specifiers: list[JsExportSpecifier] = field(default_factory=list)
    source: JsStringLiteral | None = None


@dataclass(repr=False, eq=False)
class JsExportDefaultDeclaration(Statement):
    declaration: Expression | Statement | None = None


@dataclass(repr=False, eq=False)
class JsExportAllDeclaration(Statement):
    source: JsStringLiteral | None = None
    exported: JsIdentifier | None = None


@dataclass(repr=False, eq=False)
class JsScript(Statement):
    body: list[Statement] = field(default_factory=list)
