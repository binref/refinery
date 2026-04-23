from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generator

from refinery.lib.scripts import Expression, Node, Statement


@dataclass(repr=False, eq=False)
class JsErrorNode(Node):
    text: str = ''
    message: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False, eq=False)
class JsIdentifier(Expression):
    name: str = ''

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False, eq=False)
class JsNumericLiteral(Expression):
    value: int | float = 0
    raw: str = '0'

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False, eq=False)
class JsBigIntLiteral(Expression):
    value: int = 0
    raw: str = '0n'

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False, eq=False)
class JsStringLiteral(Expression):
    value: str = ''
    raw: str = "''"

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False, eq=False)
class JsRegExpLiteral(Expression):
    pattern: str = ''
    flags: str = ''
    raw: str = '//'

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False, eq=False)
class JsTemplateLiteral(Expression):
    quasis: list[JsTemplateElement] = field(default_factory=list)
    expressions: list[Expression] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.quasis, *self.expressions)

    def children(self) -> Generator[Node, None, None]:
        qi = iter(self.quasis)
        ei = iter(self.expressions)
        for q in qi:
            yield q
            e = next(ei, None)
            if e is not None:
                yield e


@dataclass(repr=False, eq=False)
class JsTemplateElement(Node):
    value: str = ''
    raw: str = ''
    tail: bool = False

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False, eq=False)
class JsBooleanLiteral(Expression):
    value: bool = False

    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False, eq=False)
class JsNullLiteral(Expression):
    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False, eq=False)
class JsThisExpression(Expression):
    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False, eq=False)
class JsArrayExpression(Expression):
    elements: list[Expression | None] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*[e for e in self.elements if e is not None])

    def children(self) -> Generator[Node, None, None]:
        for e in self.elements:
            if e is not None:
                yield e


@dataclass(repr=False, eq=False)
class JsObjectExpression(Expression):
    properties: list[JsProperty | JsSpreadElement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.properties)

    def children(self) -> Generator[Node, None, None]:
        yield from self.properties


@dataclass(repr=False, eq=False)
class JsProperty(Node):
    key: Expression | None = None
    value: Expression | None = None
    computed: bool = False
    shorthand: bool = False
    method: bool = False
    kind: str = 'init'

    def __post_init__(self):
        self._adopt(self.key, self.value)

    def children(self) -> Generator[Node, None, None]:
        if self.key is not None:
            yield self.key
        if self.value is not None:
            yield self.value


@dataclass(repr=False, eq=False)
class JsSpreadElement(Expression):
    argument: Expression | None = None

    def __post_init__(self):
        self._adopt(self.argument)

    def children(self) -> Generator[Node, None, None]:
        if self.argument is not None:
            yield self.argument


@dataclass(repr=False, eq=False)
class JsFunctionExpression(Expression):
    id: JsIdentifier | None = None
    params: list[Expression] = field(default_factory=list)
    body: JsBlockStatement | None = None
    generator: bool = False
    is_async: bool = False

    def __post_init__(self):
        self._adopt(self.id, *self.params, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.id is not None:
            yield self.id
        yield from self.params
        if self.body is not None:
            yield self.body


@dataclass(repr=False, eq=False)
class JsArrowFunctionExpression(Expression):
    params: list[Expression] = field(default_factory=list)
    body: Expression | JsBlockStatement | None = None
    is_async: bool = False

    def __post_init__(self):
        self._adopt(*self.params, self.body)

    def children(self) -> Generator[Node, None, None]:
        yield from self.params
        if self.body is not None:
            yield self.body


@dataclass(repr=False, eq=False)
class JsClassExpression(Expression):
    id: JsIdentifier | None = None
    super_class: Expression | None = None
    body: JsClassBody | None = None

    def __post_init__(self):
        self._adopt(self.id, self.super_class, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.id is not None:
            yield self.id
        if self.super_class is not None:
            yield self.super_class
        if self.body is not None:
            yield self.body


@dataclass(repr=False, eq=False)
class JsUnaryExpression(Expression):
    operator: str = ''
    operand: Expression | None = None
    prefix: bool = True

    def __post_init__(self):
        self._adopt(self.operand)

    def children(self) -> Generator[Node, None, None]:
        if self.operand is not None:
            yield self.operand


@dataclass(repr=False, eq=False)
class JsUpdateExpression(Expression):
    operator: str = ''
    argument: Expression | None = None
    prefix: bool = True

    def __post_init__(self):
        self._adopt(self.argument)

    def children(self) -> Generator[Node, None, None]:
        if self.argument is not None:
            yield self.argument


@dataclass(repr=False, eq=False)
class JsBinaryExpression(Expression):
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


@dataclass(repr=False, eq=False)
class JsLogicalExpression(Expression):
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


@dataclass(repr=False, eq=False)
class JsAssignmentExpression(Expression):
    left: Expression | None = None
    operator: str = '='
    right: Expression | None = None

    def __post_init__(self):
        self._adopt(self.left, self.right)

    def children(self) -> Generator[Node, None, None]:
        if self.left is not None:
            yield self.left
        if self.right is not None:
            yield self.right


@dataclass(repr=False, eq=False)
class JsConditionalExpression(Expression):
    test: Expression | None = None
    consequent: Expression | None = None
    alternate: Expression | None = None

    def __post_init__(self):
        self._adopt(self.test, self.consequent, self.alternate)

    def children(self) -> Generator[Node, None, None]:
        if self.test is not None:
            yield self.test
        if self.consequent is not None:
            yield self.consequent
        if self.alternate is not None:
            yield self.alternate


@dataclass(repr=False, eq=False)
class JsMemberExpression(Expression):
    object: Expression | None = None
    property: Expression | None = None
    computed: bool = False
    optional: bool = False

    def __post_init__(self):
        self._adopt(self.object, self.property)

    def children(self) -> Generator[Node, None, None]:
        if self.object is not None:
            yield self.object
        if self.property is not None:
            yield self.property


@dataclass(repr=False, eq=False)
class JsCallExpression(Expression):
    callee: Expression | None = None
    arguments: list[Expression] = field(default_factory=list)
    optional: bool = False

    def __post_init__(self):
        self._adopt(self.callee, *self.arguments)

    def children(self) -> Generator[Node, None, None]:
        if self.callee is not None:
            yield self.callee
        yield from self.arguments


@dataclass(repr=False, eq=False)
class JsNewExpression(Expression):
    callee: Expression | None = None
    arguments: list[Expression] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.callee, *self.arguments)

    def children(self) -> Generator[Node, None, None]:
        if self.callee is not None:
            yield self.callee
        yield from self.arguments


@dataclass(repr=False, eq=False)
class JsSequenceExpression(Expression):
    expressions: list[Expression] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.expressions)

    def children(self) -> Generator[Node, None, None]:
        yield from self.expressions


@dataclass(repr=False, eq=False)
class JsYieldExpression(Expression):
    argument: Expression | None = None
    delegate: bool = False

    def __post_init__(self):
        self._adopt(self.argument)

    def children(self) -> Generator[Node, None, None]:
        if self.argument is not None:
            yield self.argument


@dataclass(repr=False, eq=False)
class JsAwaitExpression(Expression):
    argument: Expression | None = None

    def __post_init__(self):
        self._adopt(self.argument)

    def children(self) -> Generator[Node, None, None]:
        if self.argument is not None:
            yield self.argument


@dataclass(repr=False, eq=False)
class JsTaggedTemplateExpression(Expression):
    tag: Expression | None = None
    quasi: JsTemplateLiteral | None = None

    def __post_init__(self):
        self._adopt(self.tag, self.quasi)

    def children(self) -> Generator[Node, None, None]:
        if self.tag is not None:
            yield self.tag
        if self.quasi is not None:
            yield self.quasi


@dataclass(repr=False, eq=False)
class JsParenthesizedExpression(Expression):
    expression: Expression | None = None

    def __post_init__(self):
        self._adopt(self.expression)

    def children(self) -> Generator[Node, None, None]:
        if self.expression is not None:
            yield self.expression


@dataclass(repr=False, eq=False)
class JsArrayPattern(Expression):
    elements: list[Expression | None] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*[e for e in self.elements if e is not None])

    def children(self) -> Generator[Node, None, None]:
        for e in self.elements:
            if e is not None:
                yield e


@dataclass(repr=False, eq=False)
class JsObjectPattern(Expression):
    properties: list[JsProperty | JsRestElement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.properties)

    def children(self) -> Generator[Node, None, None]:
        yield from self.properties


@dataclass(repr=False, eq=False)
class JsAssignmentPattern(Expression):
    left: Expression | None = None
    right: Expression | None = None

    def __post_init__(self):
        self._adopt(self.left, self.right)

    def children(self) -> Generator[Node, None, None]:
        if self.left is not None:
            yield self.left
        if self.right is not None:
            yield self.right


@dataclass(repr=False, eq=False)
class JsRestElement(Expression):
    argument: Expression | None = None

    def __post_init__(self):
        self._adopt(self.argument)

    def children(self) -> Generator[Node, None, None]:
        if self.argument is not None:
            yield self.argument


@dataclass(repr=False, eq=False)
class JsClassBody(Node):
    body: list[JsMethodDefinition | JsPropertyDefinition] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.body)

    def children(self) -> Generator[Node, None, None]:
        yield from self.body


@dataclass(repr=False, eq=False)
class JsMethodDefinition(Node):
    key: Expression | None = None
    value: JsFunctionExpression | None = None
    kind: str = 'method'
    computed: bool = False
    is_static: bool = False

    def __post_init__(self):
        self._adopt(self.key, self.value)

    def children(self) -> Generator[Node, None, None]:
        if self.key is not None:
            yield self.key
        if self.value is not None:
            yield self.value


@dataclass(repr=False, eq=False)
class JsPropertyDefinition(Node):
    key: Expression | None = None
    value: Expression | None = None
    computed: bool = False
    is_static: bool = False

    def __post_init__(self):
        self._adopt(self.key, self.value)

    def children(self) -> Generator[Node, None, None]:
        if self.key is not None:
            yield self.key
        if self.value is not None:
            yield self.value


@dataclass(repr=False, eq=False)
class JsExpressionStatement(Statement):
    expression: Expression | None = None

    def __post_init__(self):
        self._adopt(self.expression)

    def children(self) -> Generator[Node, None, None]:
        if self.expression is not None:
            yield self.expression


@dataclass(repr=False, eq=False)
class JsBlockStatement(Statement):
    body: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.body)

    def children(self) -> Generator[Node, None, None]:
        yield from self.body


@dataclass(repr=False, eq=False)
class JsEmptyStatement(Statement):
    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False, eq=False)
class JsVariableDeclaration(Statement):
    declarations: list[JsVariableDeclarator] = field(default_factory=list)
    kind: str = 'var'

    def __post_init__(self):
        self._adopt(*self.declarations)

    def children(self) -> Generator[Node, None, None]:
        yield from self.declarations


@dataclass(repr=False, eq=False)
class JsVariableDeclarator(Node):
    id: Expression | None = None
    init: Expression | None = None

    def __post_init__(self):
        self._adopt(self.id, self.init)

    def children(self) -> Generator[Node, None, None]:
        if self.id is not None:
            yield self.id
        if self.init is not None:
            yield self.init


@dataclass(repr=False, eq=False)
class JsIfStatement(Statement):
    test: Expression | None = None
    consequent: Statement | None = None
    alternate: Statement | None = None

    def __post_init__(self):
        self._adopt(self.test, self.consequent, self.alternate)

    def children(self) -> Generator[Node, None, None]:
        if self.test is not None:
            yield self.test
        if self.consequent is not None:
            yield self.consequent
        if self.alternate is not None:
            yield self.alternate


@dataclass(repr=False, eq=False)
class JsWhileStatement(Statement):
    test: Expression | None = None
    body: Statement | None = None

    def __post_init__(self):
        self._adopt(self.test, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.test is not None:
            yield self.test
        if self.body is not None:
            yield self.body


@dataclass(repr=False, eq=False)
class JsDoWhileStatement(Statement):
    test: Expression | None = None
    body: Statement | None = None

    def __post_init__(self):
        self._adopt(self.test, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.body is not None:
            yield self.body
        if self.test is not None:
            yield self.test


@dataclass(repr=False, eq=False)
class JsForStatement(Statement):
    init: Expression | Statement | None = None
    test: Expression | None = None
    update: Expression | None = None
    body: Statement | None = None

    def __post_init__(self):
        self._adopt(self.init, self.test, self.update, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.init is not None:
            yield self.init
        if self.test is not None:
            yield self.test
        if self.update is not None:
            yield self.update
        if self.body is not None:
            yield self.body


@dataclass(repr=False, eq=False)
class JsForInStatement(Statement):
    left: Expression | Statement | None = None
    right: Expression | None = None
    body: Statement | None = None

    def __post_init__(self):
        self._adopt(self.left, self.right, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.left is not None:
            yield self.left
        if self.right is not None:
            yield self.right
        if self.body is not None:
            yield self.body


@dataclass(repr=False, eq=False)
class JsForOfStatement(Statement):
    left: Expression | Statement | None = None
    right: Expression | None = None
    body: Statement | None = None
    is_await: bool = False

    def __post_init__(self):
        self._adopt(self.left, self.right, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.left is not None:
            yield self.left
        if self.right is not None:
            yield self.right
        if self.body is not None:
            yield self.body


@dataclass(repr=False, eq=False)
class JsSwitchStatement(Statement):
    discriminant: Expression | None = None
    cases: list[JsSwitchCase] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.discriminant, *self.cases)

    def children(self) -> Generator[Node, None, None]:
        if self.discriminant is not None:
            yield self.discriminant
        yield from self.cases


@dataclass(repr=False, eq=False)
class JsSwitchCase(Node):
    test: Expression | None = None
    consequent: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(self.test, *self.consequent)

    def children(self) -> Generator[Node, None, None]:
        if self.test is not None:
            yield self.test
        yield from self.consequent


@dataclass(repr=False, eq=False)
class JsTryStatement(Statement):
    block: JsBlockStatement | None = None
    handler: JsCatchClause | None = None
    finalizer: JsBlockStatement | None = None

    def __post_init__(self):
        self._adopt(self.block, self.handler, self.finalizer)

    def children(self) -> Generator[Node, None, None]:
        if self.block is not None:
            yield self.block
        if self.handler is not None:
            yield self.handler
        if self.finalizer is not None:
            yield self.finalizer


@dataclass(repr=False, eq=False)
class JsCatchClause(Node):
    param: Expression | None = None
    body: JsBlockStatement | None = None

    def __post_init__(self):
        self._adopt(self.param, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.param is not None:
            yield self.param
        if self.body is not None:
            yield self.body


@dataclass(repr=False, eq=False)
class JsThrowStatement(Statement):
    argument: Expression | None = None

    def __post_init__(self):
        self._adopt(self.argument)

    def children(self) -> Generator[Node, None, None]:
        if self.argument is not None:
            yield self.argument


@dataclass(repr=False, eq=False)
class JsReturnStatement(Statement):
    argument: Expression | None = None

    def __post_init__(self):
        self._adopt(self.argument)

    def children(self) -> Generator[Node, None, None]:
        if self.argument is not None:
            yield self.argument


@dataclass(repr=False, eq=False)
class JsBreakStatement(Statement):
    label: JsIdentifier | None = None

    def __post_init__(self):
        self._adopt(self.label)

    def children(self) -> Generator[Node, None, None]:
        if self.label is not None:
            yield self.label


@dataclass(repr=False, eq=False)
class JsContinueStatement(Statement):
    label: JsIdentifier | None = None

    def __post_init__(self):
        self._adopt(self.label)

    def children(self) -> Generator[Node, None, None]:
        if self.label is not None:
            yield self.label


@dataclass(repr=False, eq=False)
class JsLabeledStatement(Statement):
    label: JsIdentifier | None = None
    body: Statement | None = None

    def __post_init__(self):
        self._adopt(self.label, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.label is not None:
            yield self.label
        if self.body is not None:
            yield self.body


@dataclass(repr=False, eq=False)
class JsWithStatement(Statement):
    object: Expression | None = None
    body: Statement | None = None

    def __post_init__(self):
        self._adopt(self.object, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.object is not None:
            yield self.object
        if self.body is not None:
            yield self.body


@dataclass(repr=False, eq=False)
class JsDebuggerStatement(Statement):
    def children(self) -> Generator[Node, None, None]:
        yield from ()


@dataclass(repr=False, eq=False)
class JsFunctionDeclaration(Statement):
    id: JsIdentifier | None = None
    params: list[Expression] = field(default_factory=list)
    body: JsBlockStatement | None = None
    generator: bool = False
    is_async: bool = False

    def __post_init__(self):
        self._adopt(self.id, *self.params, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.id is not None:
            yield self.id
        yield from self.params
        if self.body is not None:
            yield self.body


@dataclass(repr=False, eq=False)
class JsClassDeclaration(Statement):
    id: JsIdentifier | None = None
    super_class: Expression | None = None
    body: JsClassBody | None = None

    def __post_init__(self):
        self._adopt(self.id, self.super_class, self.body)

    def children(self) -> Generator[Node, None, None]:
        if self.id is not None:
            yield self.id
        if self.super_class is not None:
            yield self.super_class
        if self.body is not None:
            yield self.body


@dataclass(repr=False, eq=False)
class JsImportSpecifier(Node):
    imported: JsIdentifier | None = None
    local: JsIdentifier | None = None

    def __post_init__(self):
        self._adopt(self.imported, self.local)

    def children(self) -> Generator[Node, None, None]:
        if self.imported is not None:
            yield self.imported
        if self.local is not None:
            yield self.local


@dataclass(repr=False, eq=False)
class JsImportDefaultSpecifier(Node):
    local: JsIdentifier | None = None

    def __post_init__(self):
        self._adopt(self.local)

    def children(self) -> Generator[Node, None, None]:
        if self.local is not None:
            yield self.local


@dataclass(repr=False, eq=False)
class JsImportNamespaceSpecifier(Node):
    local: JsIdentifier | None = None

    def __post_init__(self):
        self._adopt(self.local)

    def children(self) -> Generator[Node, None, None]:
        if self.local is not None:
            yield self.local


@dataclass(repr=False, eq=False)
class JsImportDeclaration(Statement):
    specifiers: list[
        JsImportSpecifier | JsImportDefaultSpecifier | JsImportNamespaceSpecifier
    ] = field(default_factory=list)
    source: JsStringLiteral | None = None

    def __post_init__(self):
        self._adopt(*self.specifiers, self.source)

    def children(self) -> Generator[Node, None, None]:
        yield from self.specifiers
        if self.source is not None:
            yield self.source


@dataclass(repr=False, eq=False)
class JsExportSpecifier(Node):
    local: JsIdentifier | None = None
    exported: JsIdentifier | None = None

    def __post_init__(self):
        self._adopt(self.local, self.exported)

    def children(self) -> Generator[Node, None, None]:
        if self.local is not None:
            yield self.local
        if self.exported is not None:
            yield self.exported


@dataclass(repr=False, eq=False)
class JsExportNamedDeclaration(Statement):
    declaration: Statement | None = None
    specifiers: list[JsExportSpecifier] = field(default_factory=list)
    source: JsStringLiteral | None = None

    def __post_init__(self):
        self._adopt(self.declaration, *self.specifiers, self.source)

    def children(self) -> Generator[Node, None, None]:
        if self.declaration is not None:
            yield self.declaration
        yield from self.specifiers
        if self.source is not None:
            yield self.source


@dataclass(repr=False, eq=False)
class JsExportDefaultDeclaration(Statement):
    declaration: Expression | Statement | None = None

    def __post_init__(self):
        self._adopt(self.declaration)

    def children(self) -> Generator[Node, None, None]:
        if self.declaration is not None:
            yield self.declaration


@dataclass(repr=False, eq=False)
class JsExportAllDeclaration(Statement):
    source: JsStringLiteral | None = None
    exported: JsIdentifier | None = None

    def __post_init__(self):
        self._adopt(self.source, self.exported)

    def children(self) -> Generator[Node, None, None]:
        if self.source is not None:
            yield self.source
        if self.exported is not None:
            yield self.exported


@dataclass(repr=False, eq=False)
class JsScript(Statement):
    body: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.body)

    def children(self) -> Generator[Node, None, None]:
        yield from self.body
