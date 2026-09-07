"""
The JavaScript syntax tree: one node type per production of the grammar, and the few predicates that
answer a question about a node from the node alone.

A node states what was written and nothing about what it means. `strip_parens` and `names_a_property`
live here because the answer is in the shape; anything needing a scope, a binding or an effect
belongs in `refinery.lib.scripts.js.analysis` instead, which is why nothing here imports that package.
Nothing here holds state either, so a pass may ask any of it at any point of a rewrite.
"""
from __future__ import annotations

import enum
import functools

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from refinery.lib.scripts import Expression, Node, Statement
from refinery.lib.scripts.js.numbers import to_js_number

if TYPE_CHECKING:
    from refinery.lib.scripts.js.strict import StrictViolation


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
class JsErrorNode(Expression, Statement, unparsed=True):
    """
    A span of source the parser could not read, kept verbatim so that what an analyst gets back
    still contains what was written. It prints as `text` and so reads back as whatever that text
    parses to, which is why a tree holding one states nothing about synthesizer fidelity.

    It stands in either position, because the recovery that builds it does not know which was
    expected. In statement position it is the statement, and is deliberately not wrapped in an
    expression statement: the wrapper prints a semicolon that nobody wrote, which grows the file by
    one character every time the tool reads its own output.
    """
    text: str = ''
    message: str = ''


@dataclass(repr=False, eq=False)
class JsIdentifier(Expression, spelling='raw'):
    """
    A name. `name` is the name the source denotes and `raw` is the text it was written with, which
    part ways wherever a unicode escape stands between them: `\\u0061bc` and `abc` are one binding
    written two ways, and every question about names is asked of `name`.

    `raw` is empty wherever the two would be the same text, so it holds something only for a name
    the source wrote some other way. What it holds is trusted only for as long as it still spells
    `name`, which is what leaves a pass renaming a node nothing to maintain: the synthesizer asks
    whether the spelling it was handed spells the name it is printing, and writes the name itself
    where it does not.
    """
    name: str = ''
    raw: str = ''

    def has_spelling(self) -> bool:
        """
        There is no name spelled by nothing. Printing one writes whatever stands around it and
        closes up over the gap, so `a.` becomes `a` and a program loses a member read; the parser
        builds an error node where it finds no name, and this is what says so if a transform ever
        assembles one anyway.
        """
        return bool(self.name)


@dataclass(repr=False, eq=False)
class JsPrivateIdentifier(Expression, spelling='raw'):
    """
    A private name, written with the `#` that opens it left out of `name` and out of `raw` alike.
    An escape spells one of these as it spells any other name, so `this.#\\u0061` reads the member
    `#a` declares.
    """
    name: str = ''
    raw: str = ''


@dataclass(repr=False, eq=False)
class JsNumericLiteral(Expression, spelling='raw'):
    """
    A Number literal. `value` is the double the source denotes and `raw` is how that source spelled
    it; the two are independent because a spelling carries information the value does not, such as
    the base of `0xFF` or the sign of `-0`. Coercion happens here rather than at the call sites so
    that no construction anywhere can introduce a value JavaScript cannot hold.
    """
    value: float = 0.0
    raw: str = '0'

    def __post_init__(self):
        super().__post_init__()
        self.value = to_js_number(self.value)


@dataclass(repr=False, eq=False)
class JsBigIntLiteral(Expression, spelling='raw'):
    value: int = 0
    raw: str = '0n'


@dataclass(repr=False, eq=False)
class JsStringLiteral(Expression, spelling='raw'):
    """
    A String literal. `value` is the text it denotes and `raw` is how the source spelled it, which
    part ways wherever an escape stands between them.

    `value` is `None` where the literal denotes nothing, which is a literal written with a `\\x` or
    `\\u` escape that names no character. A string keeps the legacy escapes Annex B holds open for
    sloppy code, so those still denote text; an escape no literal has at all denotes none, the way
    the same escape leaves a `JsTemplateElement` denoting none.

    `terminated` reports whether the closing quote was there. A literal the source never closed is
    not a form the language has, so no text spells it: printing what was written runs the literal on
    into whatever the synthesizer prints next, and printing the quote that is missing turns a file
    that does not parse into a program that runs.
    """
    value: str | None = ''
    raw: str = "''"
    terminated: bool = True

    @property
    def body(self) -> str:
        """
        The source text between the quotes, every escape still spelled as it was written. A rule
        about how a literal was written reads this rather than `value`: a directive spelled with an
        escape in it denotes the text `use strict` and is not a Use Strict Directive, because what
        makes a directive is the spelling and not the value.
        """
        return self.raw[1:-1] if self.terminated else self.raw[1:]


@dataclass(repr=False, eq=False)
class JsRegExpLiteral(Expression, spelling='raw'):
    pattern: str = ''
    flags: str = ''
    raw: str = '//'


@dataclass(repr=False, eq=False)
class JsTemplateLiteral(Expression):
    quasis: list[JsTemplateElement] = field(default_factory=list)
    expressions: list[Expression] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsTemplateElement(Node, spelling='raw'):
    """
    One run of text in a template literal. `raw` is that run as the source wrote it and `value` the
    text it denotes; neither holds the delimiters that separate the runs from the expressions,
    because the literal prints those itself and a run is what stands between them.

    `terminated` reports whether the delimiter that ends the run was there. Only a template can
    reach the end of the file unclosed, since no line terminator ends one, and a hole the source
    left open ends here as an empty run that closes nothing.

    `value` is `None` where the run denotes nothing, which is a run written with an escape the
    template grammar excludes. The language says the same thing by handing a tag `undefined` for
    such a run, and by refusing the untagged literal outright.
    """
    value: str | None = ''
    raw: str = ''
    tail: bool = False
    terminated: bool = True
    #: Whether the `}` that closes the hole in front of this run was there. Only the run behind a
    #: hole the file ended inside lacks it, and such a run holds no text at all.
    opened: bool = True


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
    properties: list[JsProperty | JsSpreadElement | JsErrorNode] = field(default_factory=list)


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
class JsFunctionExpression(Expression, spelling='source_text'):
    id: JsIdentifier | None = None
    params: list[Expression] = field(default_factory=list)
    body: JsBlockStatement | None = None
    generator: bool = False
    is_async: bool = False
    source_text: str | None = None


@dataclass(repr=False, eq=False)
class JsArrowFunctionExpression(Expression, spelling='source_text'):
    params: list[Expression] = field(default_factory=list)
    body: Expression | JsBlockStatement | None = None
    is_async: bool = False
    source_text: str | None = None


@dataclass(repr=False, eq=False)
class JsDecorator(Node):
    expression: Expression | None = None


@dataclass(repr=False, eq=False)
class JsClassExpression(Expression):
    id: JsIdentifier | None = None
    super_class: Expression | None = None
    body: JsClassBody | None = None
    decorators: list[JsDecorator] = field(default_factory=list)


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
    properties: list[JsProperty | JsRestElement | JsErrorNode] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsAssignmentPattern(Expression):
    left: Expression | None = None
    right: Expression | None = None


@dataclass(repr=False, eq=False)
class JsRestElement(Expression):
    argument: Expression | None = None


@dataclass(repr=False, eq=False)
class JsClassBody(Node):
    body: list[JsMethodDefinition | JsPropertyDefinition | JsStaticBlock | JsErrorNode] = field(default_factory=list)
    #: Whether the closing brace was there. The file may end inside a class body, and a body the
    #: file ends inside prints the elements it holds and nothing after them.
    terminated: bool = True


@dataclass(repr=False, eq=False)
class JsMethodDefinition(Node):
    key: Expression | None = None
    value: JsFunctionExpression | None = None
    kind: JsMethodKind = JsMethodKind.METHOD
    computed: bool = False
    is_static: bool = False
    decorators: list[JsDecorator] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsPropertyDefinition(Node):
    key: Expression | None = None
    value: Expression | None = None
    computed: bool = False
    is_static: bool = False
    decorators: list[JsDecorator] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsStaticBlock(Node):
    body: list[Statement] = field(default_factory=list)
    terminated: bool = True


@dataclass(repr=False, eq=False)
class JsExpressionStatement(Statement, spelling='directive'):
    expression: Expression | None = None
    #: Whether the source wrote this statement into a Directive Prologue. It records where the
    #: statement came from and not what it computes, which is why it is a spelling field: two trees
    #: that differ only here spell the same program. A clone carries it, deliberately — a directive
    #: that is copied elsewhere was still written as one, and whether it *is* one is decided by
    #: `refinery.lib.scripts.js.strict.is_prologue_host` at wherever it now stands.
    directive: bool = False


@dataclass(repr=False, eq=False)
class JsBlockStatement(Statement):
    body: list[Statement] = field(default_factory=list)
    #: Whether the closing brace was there. A file carved out of memory ends inside a block more
    #: often than anywhere else, and the block keeps the statements it holds and says that nothing
    #: closed it: printing what it holds and nothing after it is what keeps the file's end where the
    #: file had it. `refinery.lib.scripts.js.model.JsScript.early_errors` reports it.
    terminated: bool = True


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
    cases: list[JsSwitchCase | JsErrorNode] = field(default_factory=list)
    terminated: bool = True


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
class JsFunctionDeclaration(Statement, spelling='source_text'):
    id: JsIdentifier | None = None
    params: list[Expression] = field(default_factory=list)
    body: JsBlockStatement | None = None
    generator: bool = False
    is_async: bool = False
    source_text: str | None = None


@dataclass(repr=False, eq=False)
class JsClassDeclaration(Statement):
    id: JsIdentifier | None = None
    super_class: Expression | None = None
    body: JsClassBody | None = None
    decorators: list[JsDecorator] = field(default_factory=list)


@dataclass(repr=False, eq=False)
class JsImportSpecifier(Node):
    imported: Expression | None = None
    local: Expression | None = None


@dataclass(repr=False, eq=False)
class JsImportDefaultSpecifier(Node):
    local: Expression | None = None


@dataclass(repr=False, eq=False)
class JsImportNamespaceSpecifier(Node):
    local: Expression | None = None


@dataclass(repr=False, eq=False)
class JsImportAttribute(Node):
    key: Expression | None = None
    value: Expression | None = None


@dataclass(repr=False, eq=False)
class JsImportDeclaration(Statement):
    specifiers: list[
        JsImportSpecifier | JsImportDefaultSpecifier | JsImportNamespaceSpecifier | JsErrorNode
    ] = field(default_factory=list)
    source: JsStringLiteral | None = None
    attributes: list[JsImportAttribute | JsErrorNode] = field(default_factory=list)
    attributes_keyword: str = ''


@dataclass(repr=False, eq=False)
class JsImportExpression(Expression):
    source: Expression | None = None
    options: Expression | None = None


@dataclass(repr=False, eq=False)
class JsMetaProperty(Expression):
    meta: str = ''
    property: str = ''


@dataclass(repr=False, eq=False)
class JsExportSpecifier(Node):
    local: Expression | None = None
    exported: Expression | None = None


@dataclass(repr=False, eq=False)
class JsExportNamedDeclaration(Statement):
    declaration: Statement | None = None
    specifiers: list[JsExportSpecifier | JsErrorNode] = field(default_factory=list)
    source: JsStringLiteral | None = None
    attributes: list[JsImportAttribute | JsErrorNode] = field(default_factory=list)
    attributes_keyword: str = ''


@dataclass(repr=False, eq=False)
class JsExportDefaultDeclaration(Statement):
    declaration: Expression | Statement | None = None


@dataclass(repr=False, eq=False)
class JsExportAllDeclaration(Statement):
    source: JsStringLiteral | None = None
    exported: Expression | None = None
    attributes: list[JsImportAttribute | JsErrorNode] = field(default_factory=list)
    attributes_keyword: str = ''


@dataclass(repr=False, eq=False)
class JsScript(Statement, spelling=('module', 'recovered', 'html_comment')):
    body: list[Statement] = field(default_factory=list)
    #: Whether the source is module code, which the host decides (§16.1) and the syntax only reports:
    #: an `import` or `export` declaration, or `import.meta`, can appear in nothing else. It is a
    #: spelling field because two scripts differing only here hold the same text — what differs is how
    #: a host loads it — and because a pass that cuts the last import out of a body does not turn a
    #: module into a script.
    module: bool = False
    #: Whether the parser had to invent a token, or step over one, in order to read this file. It is
    #: a spelling field for the reason `module` is: it records where the tree came from rather than
    #: what it spells, so two scripts differing only here are the same program. Nothing ever clears
    #: it, because no later pass can put back a token the source never held.
    recovered: bool = False
    #: The offset of the first HTML-like comment delimiter the lexer read in this file (§B.1.1), or
    #: `None` where it read none. Module code refuses both delimiters, and the comment one opens may
    #: stand where no statement carries it, so the fact is kept on the script rather than looked for
    #: among the comments the tree holds. It is a spelling field for the reason `recovered` is.
    html_comment: int | None = None

    def is_recovered(self) -> bool:
        return self.recovered

    def early_errors(self) -> list[StrictViolation]:
        """
        What the language refuses in the file under its own mode and goal: the early errors
        `refinery.lib.scripts.js.strict.collect_strict_violations` reports over the tree read as a
        script, or as a module where the file spells module syntax, and every construct the file
        ended inside — a literal, a block, a class body or a switch — which an engine refuses as
        an unexpected end of input.
        """
        from refinery.lib.scripts.js.strict import collect_strict_violations
        return collect_strict_violations(self, module=self.module)


#: The three nodes that hold a function body. A class or object method holds a
#: `JsFunctionExpression` as its value, so it needs no entry of its own.
FUNCTION_NODES = (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)

JsFunctionNode = JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression


class AwaitReading(enum.Enum):
    """
    What the word `await` is where a piece of code stands. It names a binding or a reference in a
    script and in every function that is not `async`; it is the operator in an `async` function's
    parameter list and body; and it is neither in a class static block or a static field
    initializer, where the language refuses the word in every position.
    """
    NAME = enum.auto()
    OPERATOR = enum.auto()
    RESERVED = enum.auto()


@dataclass(frozen=True)
class CodeContext:
    """
    The grammar parameters a piece of code is read under: what `await` is, whether `yield` is the
    operator rather than a name, whether `arguments` may be referred to at all, and whether the
    code is the top level of a file. The parser descends it and the early-error collector threads
    it, both through `code_context_within`, so that the tree a text is read into and the errors
    reported over that tree agree on what every word is.

    The top level is set apart because its goal symbol is not known while parsing: `await` is read
    as a name there, as a script reads it, but a `for await` head is read as well, since that is
    one way a module spells its top-level `await`. Below a function or a class element the goal
    decides nothing, and a `for await` head stands only where `await` is the operator.
    """
    await_reading: AwaitReading
    yield_is_operator: bool
    arguments_reserved: bool
    top_level: bool

    @property
    def reads_for_await(self) -> bool:
        """
        Whether a `for await` head is read here: where `await` is the operator, and at the top
        level of a file, whose goal may make it one.
        """
        return self.await_reading is AwaitReading.OPERATOR or self.top_level


SCRIPT_CONTEXT = CodeContext(AwaitReading.NAME, False, False, True)
"""
The context the top level of a file is read under: both words are names, `arguments` is free, and
the goal symbol is open.
"""


@functools.cache
def function_context(is_async: bool, is_generator: bool) -> CodeContext:
    """
    The context the parameter list and the body of a function of the given kind are read under.
    """
    return CodeContext(
        AwaitReading.OPERATOR if is_async else AwaitReading.NAME,
        is_generator,
        False,
        False,
    )


@functools.cache
def class_element_context(static: bool) -> CodeContext:
    """
    The context a class element's own code is read under: a field initializer, or a static block.
    Each is a function context of its own that reserves `arguments` (§15.7.1) and reads `yield` as
    a name; a static one refuses `await` outright, where an instance initializer reads it as a name.
    """
    return CodeContext(
        AwaitReading.RESERVED if static else AwaitReading.NAME,
        False,
        True,
        False,
    )


def arrow_body_context(is_async: bool, enclosing: CodeContext) -> CodeContext:
    """
    The context an arrow function's body is read under, given that the arrow stands in
    *enclosing*: the context a function of its kind gives its body, except that an arrow has no
    `arguments` of its own (§15.7.1) and so keeps the reservation it stands in.
    """
    return replace(function_context(is_async, False), arguments_reserved=enclosing.arguments_reserved)


def code_context_within(parent: Node, child: Node, enclosing: CodeContext) -> CodeContext:
    """
    The context *child* is read under, given that *parent* is read under *enclosing*. This is the
    one transition every reader of the context takes, so that the parser descending the tree, the
    collector threading it, and `code_context_at` folding it agree on every node.

    A function body takes the readings its own kind gives it, and so does the name of a function
    expression, which is bound inside it (§15.2.1); a declaration's name is bound outside it and
    keeps the enclosure's. An arrow's parameters are still the enclosing code and keep its
    readings, except that an `async` arrow reads `await` as the operator there too; its body is
    what `arrow_body_context` says. A class element's own code is what `class_element_context`
    says, whatever encloses the class.
    """
    if isinstance(parent, JsStaticBlock):
        return class_element_context(static=True)
    if isinstance(parent, JsPropertyDefinition):
        return class_element_context(parent.is_static) if child is parent.value else enclosing
    if isinstance(parent, JsArrowFunctionExpression):
        if any(child is param for param in parent.params):
            if parent.is_async and enclosing.await_reading is not AwaitReading.OPERATOR:
                return replace(enclosing, await_reading=AwaitReading.OPERATOR)
            return enclosing
        return arrow_body_context(parent.is_async, enclosing)
    if isinstance(parent, JsFunctionDeclaration):
        return enclosing if child is parent.id else function_context(parent.is_async, parent.generator)
    if isinstance(parent, JsFunctionExpression):
        return function_context(parent.is_async, parent.generator)
    return enclosing


def code_context_at(node: Node, root_context: CodeContext = SCRIPT_CONTEXT) -> CodeContext:
    """
    The context *node* is read under, folded from the root of its tree down through
    `code_context_within`. *root_context* is what the root itself stands in: the top level of a
    file by default, and the splice site's context for a tree about to be inlined there.
    """
    chain: list[Node] = []
    cursor: Node | None = node
    while cursor is not None:
        chain.append(cursor)
        cursor = cursor.parent
    chain.reverse()
    context = root_context
    for parent, child in zip(chain, chain[1:]):
        context = code_context_within(parent, child, context)
    return context


def is_async_function(func: JsFunctionNode) -> bool:
    """
    Whether *func* is written `async`.
    """
    return func.is_async


def is_generator_function(func: JsFunctionNode) -> bool:
    """
    Whether *func* is written `function*`. An arrow holds no such field, because the language has no
    generator arrow to write, and answers `False` rather than raising: a caller deciding what kind of
    function to rebuild asks this about whatever it holds, and a raise there would be an arrow the
    rebuild refuses rather than one it rebuilds as an arrow.
    """
    return isinstance(func, (JsFunctionDeclaration, JsFunctionExpression)) and func.generator


def wraps_return(func: JsFunctionNode) -> bool:
    """
    Whether calling *func* answers something wrapped around what the body returned: a promise for an
    `async` function, a generator object for a generator, an async generator object for both. In none
    of the three is the call the value the body returned, so a pass that answers such a call with the
    body's return expression hands back a program computing something else.
    """
    return is_async_function(func) or is_generator_function(func)


def strip_parens(node: Node | None) -> Node | None:
    """
    The expression *node* denotes once any enclosing parentheses are removed, so that a parenthesized
    operand is classified by the operator that actually applies to it rather than by the redundant
    grouping the parser preserves. A grouping whose inner expression is absent strips to `None`, which
    every caller treats as "not the node being matched".
    """
    while isinstance(node, JsParenthesizedExpression):
        node = node.expression
    return node


def callee_form_sensitive(node: Node | None) -> bool:
    """
    Whether a call invoking *node* directly as its callee means something a call reaching the same
    value through a neutral spelling does not. The language has two such forms: a member access
    binds `this` to its object, and a bare `eval` performs a *direct* eval evaluated in the
    caller's own scope. Any other callee — a plain identifier or a value — invokes with no
    receiver and no direct-eval effect, exactly as the same value called behind `(0, ...)` does,
    so only these two forms constrain what may stand in a callee position.
    """
    inner = strip_parens(node)
    if isinstance(inner, JsMemberExpression):
        return True
    return isinstance(inner, JsIdentifier) and inner.name == 'eval'


def names_a_property(node: Node) -> bool:
    """
    Whether *node* spells the name of a property and reads nothing. A member written with a dot, a
    key of an object literal, the name of a class member, the key of an import attribute, and a
    name on the far side of a module boundary are the positions the language has for such a name,
    and in each of them the text is a name the value carries rather than one the program looks up.

    A computed key is not one of these: what stands inside the brackets is an expression and is
    read like any other. Neither is a shorthand property, which is written like a key and is both:
    `{ x }` means `{ x: x }`, and the one node the parser builds for it is the read as much as it
    is the key, so calling it a property name would excuse a reference the program really makes.

    An import attribute answers `True` for a key of any kind, a string as readily as a name,
    because a with-clause holds nothing a program could refer to:

        import d from 'm' with { 'type': 'json' }

    names an attribute and not a binding, and so does the same clause written without the quotes.

    A name across the module boundary is an IdentifierName the grammar takes wider than a name the
    file could bind: `import { yield as v }`, `export { v as yield }`, `export * as yield from`,
    and both words of `export { yield } from "m"` name what another module carries. The shorthand
    `import { yield }` is the one spelling that is the far side and the binding at once, and it
    is read as the binding.
    """
    parent = node.parent
    if isinstance(parent, JsMemberExpression):
        return parent.property is node and not parent.computed
    if isinstance(parent, JsProperty):
        return parent.key is node and not parent.computed and not parent.shorthand
    if isinstance(parent, (JsMethodDefinition, JsPropertyDefinition)):
        return parent.key is node and not parent.computed
    if isinstance(parent, JsImportAttribute):
        return parent.key is node
    if isinstance(parent, JsImportSpecifier):
        return parent.imported is node and parent.local is not node
    if isinstance(parent, JsExportSpecifier):
        declaration = parent.parent
        if isinstance(declaration, JsExportNamedDeclaration) and declaration.source is not None:
            return True
        return parent.exported is node and parent.local is not node
    if isinstance(parent, JsExportAllDeclaration):
        return parent.exported is node
    return False


ACCESSOR_INSTALL_METHODS = frozenset({
    'defineProperty',
    'defineProperties',
    '__defineGetter__',
    '__defineSetter__',
})


def static_string(node: Node | None) -> str | None:
    """
    The string *node* certainly evaluates to, or `None`. It reads a string literal, a
    substitution-free template, and concatenations of those — the forms a constant fold collapses
    to a literal.

    This exists so that an analysis answer cannot change as folds fire: a property key the
    simplifier will turn into `'defineProperty'` must already be read as that name, or a consumer
    holding the answer across a pass would be told there is no install and then have one appear.
    It is deliberately a *must* analysis — an unknown value yields `None`, and a key whose value
    is unknown names no method, since only a key a fold can collapse can reveal an install
    mid-pass.
    """
    node = strip_parens(node)
    if isinstance(node, JsStringLiteral):
        return node.value
    if isinstance(node, JsTemplateLiteral):
        if node.expressions:
            return None
        if any(quasi.value is None for quasi in node.quasis):
            return None
        return ''.join(quasi.value or '' for quasi in node.quasis)
    if isinstance(node, JsBinaryExpression) and node.operator == '+':
        left = static_string(node.left)
        if left is None:
            return None
        right = static_string(node.right)
        if right is None:
            return None
        return left + right
    return None


def static_property_key(node: JsMemberExpression) -> str | None:
    """
    The property name *node* accesses, or `None` where no single static name is known: the
    identifier of a dotted access, or the string a computed key certainly evaluates to
    (`static_string`), so a key a fold would collapse to a literal already reads as that name.
    """
    prop = node.property
    if node.computed:
        return static_string(prop)
    return prop.name if isinstance(prop, JsIdentifier) else None


def accessor_install_method(node: JsMemberExpression) -> str | None:
    """
    The accessor-install method *node* names, through a dotted property or a computed key whose
    string value is statically known, or `None`. Matching the dotted form alone is what let
    `Object['defineProperty']` slip past both callers, and a fold rewriting that key to a dot
    would then reveal the install only after the fact was consumed.
    """
    name = static_property_key(node)
    return name if name in ACCESSOR_INSTALL_METHODS else None
