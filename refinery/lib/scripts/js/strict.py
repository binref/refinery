"""
Where strict mode comes from, and what it forbids. The parser is fully permissive and always produces
the sloppy-mode parse tree; strict mode never changes how source is parsed, only which already-parsed
constructs are illegal. This module is therefore a pure post-parse pass, and it owns two things.

The first is the vocabulary of the Directive Prologue: which nodes can hold one (`is_prologue_host`),
what a given one holds (`directive_prologue`), whether it declares the Use Strict Directive
(`declares_use_strict`), and which mode any node consequently runs in (`strict_mode_at`). Directive-hood
is a fact about a statement's *position in a statement list*, and a deobfuscator rewrites statement
lists constantly, so every pass that moves, inserts, removes or folds a statement must ask the same
question of the same names — a pass that re-derives the rules is a pass that gets a different answer.

The second is the early errors: `collect_strict_violations` walks a parsed tree, threading strictness
down through function bodies, class bodies and prologues along with the
`refinery.lib.scripts.js.model.CodeContext` each region is read under, and records a
`StrictViolation` at every construct the language refuses. The tree is never altered. Most of those
constructs are refused only by a strict region, which is what the seeded mode is for; several are
refused whatever mode the program runs in, and are named at `StrictViolation`.

Two consumers read it. `refinery.lib.scripts.is_well_formed` asks the root of a file for its early
errors under the file's own mode and goal, so that a tree the language refuses is outside the domain
every fidelity law is stated over. The reflection transform inlines payloads from always-sloppy
surfaces (`Function`, indirect `eval`, string timers) and must refuse an inlining that its
destination would reject; that wiring is deliberately not part of this module, since a payload with
no strict violation can still diverge at runtime, so `collect_strict_violations` is necessary but
not sufficient for that decision.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.js.lexer import has_legacy_numeric_escape
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    SCRIPT_CONTEXT,
    AwaitReading,
    CodeContext,
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsAwaitExpression,
    JsBlockStatement,
    JsCatchClause,
    JsClassDeclaration,
    JsClassExpression,
    JsExportAllDeclaration,
    JsExportDefaultDeclaration,
    JsExportNamedDeclaration,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsFunctionNode,
    JsIdentifier,
    JsIfStatement,
    JsImportDeclaration,
    JsImportDefaultSpecifier,
    JsImportNamespaceSpecifier,
    JsImportSpecifier,
    JsLabeledStatement,
    JsMetaProperty,
    JsMethodDefinition,
    JsMethodKind,
    JsNumericLiteral,
    JsObjectPattern,
    JsProperty,
    JsPropertyKind,
    JsRestElement,
    JsScript,
    JsStaticBlock,
    JsStringLiteral,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsWithStatement,
    JsYieldExpression,
    code_context_within,
    file_ended_inside,
    names_a_property,
    strip_parens,
)


@dataclass(frozen=True)
class StrictViolation:
    """
    A single early error found in an otherwise sloppy-parsed tree. `rule` is a stable slug naming the
    violated restriction; `name` carries the offending identifier for the name-based rules and is empty
    otherwise. The parse tree is never changed.

    Most rules record that the code at `offset` would be a `SyntaxError` if its enclosing region ran in
    strict mode. Five do not: a Use Strict Directive under a parameter list that is not simple, a
    repeated name in a list the grammar requires to be unique, the arity of an accessor, a name
    reserved by the kind of function it stands in, and `arguments` referred to from a class field
    initializer or static block are refused in *either* mode, so a caller that treats an empty
    result as "sloppy code is safe" is reading it right, and one that treats a non-empty result as
    "only strict code would refuse this" is not. Two more ask neither about the mode but about the
    goal symbol: `await-in-module` records a name a module refuses to bind or to refer to, and
    `html-comment` a comment delimiter only script code has; both are reported only when the tree
    is read as module code.
    """
    offset: int
    rule: str
    name: str = ''


def is_leading_zero_number(raw: str) -> bool:
    return len(raw) >= 2 and raw[0] == '0' and raw[1] in '0123456789'


def has_octal_string_escape(node: JsStringLiteral) -> bool:
    """
    Whether a string literal was written with an escape that strict code rejects. It is the same
    spelling a template excludes from its grammar, so the scan itself lives beside the escapes it
    reads and both rules ask it there.
    """
    return has_legacy_numeric_escape(node.body)


def is_use_strict(node: JsStringLiteral) -> bool:
    """
    Whether a literal spells the Use Strict Directive. It is asked of the spelling rather than of
    the value, because a directive is one: a literal that denotes `use strict` through an escape is
    not the directive, and neither is one the source never closed.
    """
    return node.terminated and node.body == 'use strict'


def spelling_states(body: str) -> tuple[bool, bool]:
    """
    What a literal's spelling states, as against what it denotes: whether it is the Use Strict
    Directive, and whether it carries an escape strict code rejects. Both are facts about how the
    literal was written and about nothing else, so a pass that re-spells one may do so only where
    neither answer moves — re-spelling `'use\\x20strict'` as `'use strict'` writes a directive the
    source never wrote, and every line behind it becomes strict code.
    """
    return body == 'use strict', has_legacy_numeric_escape(body)


def statement_list(node: Node | None) -> list[Statement] | None:
    """
    The statement list *node* holds directly, or `None` when it holds none. Only the three node types
    that can host a Directive Prologue are answered for, so a caller that already knows it is looking
    at a host reads the list here without consulting the tree above it.
    """
    if isinstance(node, (JsScript, JsBlockStatement, JsStaticBlock)):
        return node.body
    return None


def is_prologue_host(node: Node | None) -> bool:
    """
    Whether *node* holds a statement list that a Directive Prologue can open (§11.2.1): a script body,
    a function body, or a class static block. Nothing else does. A plain block, the body of a `try`,
    `catch` or `finally`, a labelled statement, a `switch` case and the expression body of a concise
    arrow all hold code no directive governs, so a `'use strict'` written at the head of one is an
    ordinary string-valued statement that changes no mode.

    A function body is recognized through the function that owns it, because a body and a plain block
    are the same node type and only the tree above tells them apart.
    """
    if isinstance(node, (JsScript, JsStaticBlock)):
        return True
    if isinstance(node, JsBlockStatement):
        owner = node.parent
        return isinstance(owner, FUNCTION_NODES) and owner.body is node
    return False


def directive_prologue(host: Node | None) -> list[JsExpressionStatement]:
    """
    The Directive Prologue of *host*: the run of statements it opens with that consist of nothing but
    a string literal. The run ends at the first statement that is anything else, so it is a prefix, and
    every statement behind that one is ordinary code however it happens to be spelled.

    A parenthesized literal is not one of them. A directive is a statement whose expression *is* the
    literal, so `('use strict');` states nothing, and the parser keeps the parenthesis as a node of its
    own precisely so that this stays decidable.

    *host* is taken to be a prologue host; where a caller must find the host from a statement inside
    it, `is_prologue_host` decides that.
    """
    return leading_string_statements(statement_list(host) or [])


def leading_string_statements(statements: list[Statement]) -> list[JsExpressionStatement]:
    """
    The opening run of *statements* that consist of nothing but a string literal. Where *statements*
    is a prologue host's own list this is its Directive Prologue; a caller holding the list rather
    than the host — the printer, which is handed a body — asks here.
    """
    run: list[JsExpressionStatement] = []
    for statement in statements:
        if not isinstance(statement, JsExpressionStatement):
            break
        if not isinstance(statement.expression, JsStringLiteral):
            break
        run.append(statement)
    return run


def declares_use_strict(host: Node | None) -> bool:
    """
    Whether the Directive Prologue of *host* holds the Use Strict Directive, which makes the code
    *host* encloses strict. The directive need not open the prologue: every string-literal statement
    ahead of it is a directive too, and one the language does not recognize is simply inert.

    It is the same directive `is_use_strict_directive` names, which is what keeps the mode this reports
    and the mode the printer writes from parting company. A string an edit lifted to the head of a body
    declares nothing — the printer puts it in a bracket precisely so that it cannot — and a body read as
    strict on the strength of one would be reasoned about in a mode the text will not have.
    """
    return any(is_use_strict_directive(statement) for statement in directive_prologue(host))


def mark_directives(root: Node) -> None:
    """
    Record on every statement of every Directive Prologue in the tree at *root* that the source wrote
    it where a directive stands. A parser calls this once over the finished tree, which is the only
    point at which the question can be answered: a statement is a directive by virtue of the list it
    sits in and the statements ahead of it, and neither is known while it is being built.

    The mark is provenance and never a conclusion. Whether a marked statement still *is* a directive
    is asked of where it stands now; what the mark adds is the other half, that a statement standing
    at the head of a body today was not merely put there by an edit.
    """
    for node in root.walk():
        if is_prologue_host(node):
            for statement in directive_prologue(node):
                statement.directive = True


def names_module_syntax(root: Node) -> bool:
    """
    Whether the tree at *root* holds syntax only module code may hold: an `import` or `export`
    declaration, or `import.meta`. A dynamic `import()` is not among them — it is available to a script
    as well — and neither is a top-level `await`, which the parser reads as a name followed by a call
    and which would therefore fire on any program that happens to use `await` as an ordinary
    identifier.

    The answer is a lower bound and never a refutation. §16.1 leaves module-ness to the host, so a
    module that spells none of this syntax is one nothing in the text distinguishes from a script.
    """
    for node in root.walk():
        if isinstance(node, (
            JsImportDeclaration,
            JsExportAllDeclaration,
            JsExportDefaultDeclaration,
            JsExportNamedDeclaration,
        )):
            return True
        if isinstance(node, JsMetaProperty) and node.meta == 'import' and node.property == 'meta':
            return True
    return False


def mark_module(script: JsScript) -> None:
    """
    Record on *script* whether its source is module code, as `names_module_syntax` observes it. A parser
    calls this once over the finished tree, beside `mark_directives`: both record what the source was,
    at the one point where the whole source is in hand and no edit has moved anything yet.
    """
    script.module = names_module_syntax(script)


def is_use_strict_directive(statement: Statement) -> bool:
    """
    Whether *statement* is the Use Strict Directive, and so the reason some body runs in strict mode.
    Three things must hold and each rules out a different mistake.

    The source must have written it where a directive stands, or an edit that moved a string here is
    credited with a mode the file never declared. It must still stand in a prologue host's opening
    run, or a directive carried somewhere else by a clone or a splice is credited with a mode it no
    longer declares. And it must spell `use strict`, because every other directive is inert and
    deleting one changes nothing.

    This is the predicate a removal asks before dropping a statement and an insertion asks before
    stepping over one, so that the two cannot disagree about which statement is at stake.
    """
    if not isinstance(statement, JsExpressionStatement) or not statement.directive:
        return False
    expression = statement.expression
    if not isinstance(expression, JsStringLiteral) or not is_use_strict(expression):
        return False
    host = statement.parent
    if not is_prologue_host(host):
        return False
    return any(member is statement for member in directive_prologue(host))


def keeping_directives(host: Node, replacement: list[Statement]) -> list[Statement]:
    """
    *replacement* with a Use Strict Directive that *host* currently opens with put back at its head,
    for a caller about to install *replacement* as *host*'s whole body. Nothing is carried where
    *replacement* already opens with one, whether that is the host's own statement or a copy of it: a
    pass that rebuilds a body by cloning it keeps the directive by value and not by identity, and
    carrying the original as well would write the directive twice.

    A directive is what a body opens with, so one the caller kept but put behind another statement
    declares nothing where it now stands and the host's is put in front of it. It is *moved* there
    and never copied ahead of itself: a tree holds a node in one place, and a list naming the same
    statement at two indices would leave one node with one parent standing at both, which every
    `id`-keyed map over the tree then reads as two. Where the statement stood it computed a string
    and discarded it, so taking it from there changes nothing but the mode it now declares.

    Whole-body replacement is the one way a directive is lost without a removal: nothing is deleted,
    the statement is simply absent from the list handed in, so a rule phrased over removals cannot see
    it. It is repaired rather than refused because a pass reaches this point having already rewritten
    what it is about to install, and declining here would leave those rewrites standing over a body
    that never received them.
    """
    if not is_prologue_host(host) or _opens_with_use_strict(replacement):
        return replacement
    carried = next(
        (
            statement for statement in directive_prologue(host)
            if is_use_strict_directive(statement)
        ),
        None,
    )
    if carried is None:
        return replacement
    return [carried, *(kept for kept in replacement if kept is not carried)]


def _opens_with_use_strict(statements: list[Statement]) -> bool:
    """
    Whether the opening run of *statements* holds a statement the source wrote as the Use Strict
    Directive, so that a body built from them declares strict mode wherever it is installed. It is
    asked of a list that stands in no tree yet, which is why it reads the mark and the spelling
    rather than `is_use_strict_directive`, whose third question is where the statement stands.
    """
    return any(
        statement.directive
        and isinstance(statement.expression, JsStringLiteral)
        and is_use_strict(statement.expression)
        for statement in leading_string_statements(statements)
    )


def promoted_use_strict(statements: list[Statement]) -> list[JsExpressionStatement]:
    """
    Which statements of *statements* would be read as the Use Strict Directive without ever having
    been written as one. *statements* is a prologue host's own list, so its opening run of
    string-literal statements is a Directive Prologue: a member of that run spelling `use strict` and
    carrying no mark came to stand there through an edit, and writing it plain makes the body strict
    where the source left it sloppy.

    None are reported once the run holds a directive the source did write. The body is strict either
    way, so there is no mode to save, and a parenthesis there would end the run and eject every real
    directive standing behind it — which is how a repair becomes a second defect.

    Only `use strict` is reported. Every other promoted string is inert wherever it lands: it declares
    no mode, and parenthesizing it would end the run for nothing.
    """
    promoted: list[JsExpressionStatement] = []
    for statement in leading_string_statements(statements):
        expression = statement.expression
        if not isinstance(expression, JsStringLiteral) or not is_use_strict(expression):
            continue
        if statement.directive:
            return []
        promoted.append(statement)
    return promoted


def joins_directive_prologue(statement: Statement) -> bool:
    """
    Whether *statement* would enter the Directive Prologue of the body that holds it were it spelled as
    a string literal: it sits in a prologue host, and nothing but string-literal statements precede it.
    A pass that rewrites such a statement into a literal hands the prologue that statement *and* every
    string-literal statement standing behind it, so a `'use strict'` that was ordinary code becomes the
    directive that makes the whole body strict.
    """
    host = statement.parent
    body = statement_list(host)
    if body is None or not is_prologue_host(host):
        return False
    index = len(directive_prologue(host))
    return index < len(body) and body[index] is statement


def strict_mode_at(node: Node) -> bool:
    """
    Whether the code at *node* runs in strict mode. Mode is inherited (§11.2.2): a body is strict when
    its own Directive Prologue declares it or when the code enclosing it is strict, and every part of a
    class definition is strict whatever encloses it (§15.7). *node* itself counts, so asking this of a
    function body answers the mode that body runs in.

    A function's directive reaches further than the body that holds it: the parameter list and the name
    the function binds are strict code too, which is why `function f(eval) { 'use strict'; }` is refused
    and `function f(eval) {}` is a program. Neither stands inside the body, so the whole function is
    asked, not only the host.

    Module code is strict throughout (§11.2.2), whatever any body in it declares, so the climb ends by
    asking the script it arrives at. What it asks is `mark_module`'s observation of the source, which
    only ever reports a module and never denies one: a program the host loads as a module while its
    text names no import, export or `import.meta` is read here as a script, and the mode it is given is
    the weaker of the two.
    """
    cursor: Node | None = node
    while cursor is not None:
        if isinstance(cursor, JsScript) and cursor.module:
            return True
        if isinstance(cursor, (JsClassDeclaration, JsClassExpression)):
            return True
        if is_prologue_host(cursor) and declares_use_strict(cursor):
            return True
        if isinstance(cursor, FUNCTION_NODES) and declares_use_strict(cursor.body):
            return True
        cursor = cursor.parent
    return False


def has_simple_parameters(fn: JsFunctionNode) -> bool:
    """
    Whether *fn* has a simple parameter list (§15.1.3): every parameter is a plain identifier, with no
    default, no rest element and no destructuring. An empty list is simple — nothing in it is anything
    else — which is what makes a Use Strict Directive legal in `function f() { 'use strict'; }`.

    A rule that additionally needs there to be *something* to be simple about must ask that separately.
    Whether the `arguments` object aliases a parameter is such a rule: with no parameters there is
    nothing to alias, but the parameter list is simple all the same.
    """
    return all(isinstance(param, JsIdentifier) for param in fn.params)


def has_parameter_expressions(fn: JsFunctionNode) -> bool:
    """
    Whether *fn*'s parameter list holds an expression that runs when the function is called
    (`ContainsExpression`, §8.6.2): a default anywhere in it, or a computed key of an object
    pattern. A rest element is descended into, since a pattern inside one may hold either.

    This is what decides whether a function has a parameter scope of its own. A parameter list with
    no expression in it cannot observe the difference: nothing in it runs, so nothing in it can read
    a name, and the body may as well hold the parameters. One with an expression can, and the
    expression evaluates before the body's declarations exist.

    The answer must be exact rather than merely safe in one direction. Answering `False` where an
    expression stands leaves a default reading what the body declares; answering `True` where none
    does splits one binding into two, which costs every consumer that reads a parameter and its
    body together the reference the other half records.
    """
    return any(_contains_expression(param) for param in fn.params)


def _contains_expression(node: Node | None) -> bool:
    if node is None or isinstance(node, JsIdentifier):
        return False
    if isinstance(node, JsAssignmentPattern):
        return True
    if isinstance(node, JsRestElement):
        return _contains_expression(node.argument)
    if isinstance(node, JsArrayPattern):
        return any(_contains_expression(element) for element in node.elements)
    if isinstance(node, JsObjectPattern):
        return any(
            isinstance(prop, JsRestElement) and _contains_expression(prop.argument)
            or isinstance(prop, JsProperty) and (prop.computed or _contains_expression(prop.value))
            for prop in node.properties
        )
    return True


class ParameterGrammar(enum.Enum):
    """
    The grammar a function's parameter list is read through, which decides how many parameters it may
    hold and whether a name may repeat among them. It is a fact about the *position* the function
    stands in rather than about the function: `function (a, a) {}` is a program as the value of a
    property and a Syntax Error as a method, and the two are the same node.
    """
    #: `FormalParameters`. A repeated name is legal, and only sloppy mode and a simple list keep it so.
    FORMAL = enum.auto()
    #: `UniqueFormalParameters`. A repeated name is a Syntax Error in either mode.
    UNIQUE = enum.auto()
    #: A getter, which takes no parameters at all.
    GETTER = enum.auto()
    #: `PropertySetParameterList`. Exactly one parameter, and never a rest element.
    SETTER = enum.auto()


_PROPERTY_ACCESSORS = {
    JsPropertyKind.GET: ParameterGrammar.GETTER,
    JsPropertyKind.SET: ParameterGrammar.SETTER,
}

_METHOD_ACCESSORS = {
    JsMethodKind.GET: ParameterGrammar.GETTER,
    JsMethodKind.SET: ParameterGrammar.SETTER,
}


def parameter_grammar(fn: JsFunctionNode) -> ParameterGrammar:
    """
    Which grammar *fn* takes its parameters through. An arrow always takes `UniqueFormalParameters`;
    a method, a getter and a setter take theirs through the member that holds them, so the member is
    what is asked. A function standing anywhere else — including as the plain value of a property,
    which is the shape a method is easily confused with — takes `FormalParameters`.
    """
    if isinstance(fn, JsArrowFunctionExpression):
        return ParameterGrammar.UNIQUE
    parent = fn.parent
    if isinstance(parent, JsProperty) and parent.value is fn and parent.method:
        return _PROPERTY_ACCESSORS.get(parent.kind, ParameterGrammar.UNIQUE)
    if isinstance(parent, JsMethodDefinition) and parent.value is fn:
        return _METHOD_ACCESSORS.get(parent.kind, ParameterGrammar.UNIQUE)
    return ParameterGrammar.FORMAL


_STRICT_RESERVED = frozenset({
    'implements',
    'interface',
    'let',
    'package',
    'private',
    'protected',
    'public',
    'static',
    'yield',
})

_EVAL_ARGS = frozenset({'eval', 'arguments'})


def _child_strictness(node: Node, strict: bool) -> bool:
    if isinstance(node, JsScript):
        return strict or node.module or declares_use_strict(node)
    if isinstance(node, (JsClassDeclaration, JsClassExpression)):
        return True
    if not isinstance(node, FUNCTION_NODES):
        return strict
    body = node.body
    if isinstance(body, JsBlockStatement):
        return strict or declares_use_strict(body)
    return strict


def _check_kind_reserved(node: Node, context: CodeContext, out: list[StrictViolation]) -> None:
    """
    Report a name that may name nothing where it stands because of the kind of code it is: `await`
    where it is the operator or refused outright, and `yield` where it is the operator. Unlike the
    strict-mode reserved words this holds in either mode: `function* g(yield) {}` and
    `async function h(await) {}` are texts no engine reads, sloppy file or not.

    Which context a name stands in, `refinery.lib.scripts.js.model.code_context_within` decides.
    The region a function reserves for is its own parameter list and its own body, and it stops at
    every function written inside it — `function* g() { function h(yield) {} }` is a program,
    because `h`'s code is `h`'s and not the generator's. An arrow is the exception in half: its
    parameters are still the enclosing function's code and inherit the reservation, while its body
    is its own and does not, so `(yield) => {}` inside a generator is refused and
    `() => { var yield = 1; }` is not. A class field initializer and a static block are contexts of
    their own, and the static ones refuse `await` in every position, whatever encloses the class.

    A function's name is governed by one context and never by two, but which one depends on how the
    function is written. A declaration's name is bound outside it and takes the enclosing context,
    so `function* yield() {}` is read at the top level and refused inside a generator. An
    expression's name is bound inside it and takes its own kind alone (§15.2.1, §15.5.1, §15.8.1),
    so `x = (function* yield() {})` is refused while `function* g() { var f = function yield() {}; }`
    is read.
    """
    if not isinstance(node, JsIdentifier):
        return
    if node.name == 'await':
        reserved = context.await_reading is not AwaitReading.NAME
    elif node.name == 'yield':
        reserved = context.yield_is_operator
    else:
        return
    if reserved and not names_a_property(node):
        out.append(StrictViolation(node.offset, 'reserved-by-function-kind', node.name))


def _record_nested_function(stmt: Statement | None, out: list[StrictViolation]) -> None:
    if isinstance(stmt, JsFunctionDeclaration):
        out.append(StrictViolation(stmt.offset, 'function-in-statement'))


def _check_node(node: Node, strict: bool, out: list[StrictViolation]) -> None:
    if not strict:
        return
    if isinstance(node, JsNumericLiteral):
        if is_leading_zero_number(node.raw):
            out.append(StrictViolation(node.offset, 'octal-literal'))
    elif isinstance(node, JsStringLiteral):
        if has_octal_string_escape(node):
            out.append(StrictViolation(node.offset, 'octal-escape'))
    elif isinstance(node, JsWithStatement):
        out.append(StrictViolation(node.offset, 'with-statement'))
    elif isinstance(node, JsUnaryExpression):
        if node.operator == 'delete':
            target = strip_parens(node.operand)
            if isinstance(target, JsIdentifier) and target.name != 'super':
                out.append(StrictViolation(node.offset, 'delete-of-reference'))
    elif isinstance(node, JsIfStatement):
        _record_nested_function(node.consequent, out)
        _record_nested_function(node.alternate, out)
    elif isinstance(node, JsLabeledStatement):
        _record_nested_function(node.body, out)
    elif isinstance(node, JsForInStatement):
        left = node.left
        if isinstance(left, JsVariableDeclaration) and left.kind is JsVarKind.VAR:
            declarations = left.declarations
            if len(declarations) == 1 and declarations[0].init is not None:
                out.append(StrictViolation(left.offset, 'for-in-var-init'))


def _target_identifiers(target: Node | None) -> list[JsIdentifier]:
    """
    Every identifier bound or assigned by a binding or assignment target, flattening array and object
    patterns, defaults, and rest elements down to their leaves. A pattern default value and a computed
    property key are references rather than targets, so they are left for the ordinary traversal; only
    the names actually bound by the pattern are returned.
    """
    result: list[JsIdentifier] = []
    stack: list[Node | None] = [target]
    while stack:
        node = stack.pop()
        if isinstance(node, JsIdentifier):
            result.append(node)
        elif isinstance(node, JsArrayPattern):
            stack.extend(node.elements)
        elif isinstance(node, JsObjectPattern):
            for prop in node.properties:
                if isinstance(prop, JsProperty):
                    stack.append(prop.value)
                elif isinstance(prop, JsRestElement):
                    stack.append(prop.argument)
        elif isinstance(node, JsAssignmentPattern):
            stack.append(node.left)
        elif isinstance(node, JsRestElement):
            stack.append(node.argument)
    return result


def _flag_name(ident: JsIdentifier, strict: bool, module: bool, out: list[StrictViolation]) -> None:
    """
    Report *ident* where the code it binds refuses the name it carries. The name is the one its
    escapes denote, which is what ECMA-262 states these rules over: a StringValue is asked for, not
    the text that spelled it.

    Two of the rules are strict-mode ones, and one is a module one. `await` names nothing in a
    module — §13.1.1 refuses it as a binding, a reference and a label wherever the goal symbol is
    Module, in every function nesting and async code or not, where a script under `"use strict"`
    binds it freely — so the word is module-reserved and not strict-reserved, and is reported under
    *module* rather than under *strict*, here for the bindings and in `_check_names` for the rest.

    V8 asks the text at two of the strict positions this reaches. `function f(ev\\u0061l) {}` and
    `argum\\u0065nts = 1` are accepted there under strict where `function f(eval) {}` and
    `arguments = 1` are refused, though `var ev\\u0061l = 1` is refused like its plain spelling.
    Reporting all of them is the specification's answer and the deliberate divergence: what reads
    this decides whether a text may be spliced somewhere, so agreeing with the specification costs
    a splice nobody writes and disagreeing with it would pass one no other engine runs.
    """
    if strict and ident.name in _EVAL_ARGS:
        out.append(StrictViolation(ident.offset, 'eval-arguments-target', ident.name))
    elif strict and ident.name in _STRICT_RESERVED:
        out.append(StrictViolation(ident.offset, 'reserved-word', ident.name))
    elif module and ident.name == 'await':
        out.append(StrictViolation(ident.offset, 'await-in-module', ident.name))


def _flag_bound(
    target: Node | None,
    strict: bool,
    module: bool,
    out: list[StrictViolation],
    handled: set[int],
) -> None:
    for ident in _target_identifiers(target):
        handled.add(id(ident))
        _flag_name(ident, strict, module, out)


def _suspend_operator_in_parameters(fn: JsFunctionNode) -> Node | None:
    """
    A `yield` or `await` operator written into *fn*'s parameter list, or `None` where none is. No
    parameter list may hold either, in any kind of function and in either mode: a default value is
    evaluated as the call is being entered, before there is anything to suspend.

    A function written inside a parameter list is not descended into. Its parameters are its own, and
    the walk reaches it in its own right; its body is a place where the operator can be perfectly
    legal, `function f(a = function* () { yield 1; }) {}` being a program.

    The first such operator in source order is the one answered with, which is the order
    `collect_strict_violations` reports in; a stack visits what is pushed last first, so each run of
    children is pushed reversed.
    """
    stack: list[Node] = list(reversed(fn.params))
    while stack:
        node = stack.pop()
        if isinstance(node, (JsYieldExpression, JsAwaitExpression)):
            return node
        if isinstance(node, FUNCTION_NODES):
            continue
        stack.extend(reversed(node.children()))
    return None


def _check_function(
    fn: JsFunctionNode,
    strict: bool,
    module: bool,
    out: list[StrictViolation],
    handled: set[int],
) -> None:
    """
    Every early error a function's signature carries. *strict* is the mode the function's own code
    runs in, which its body may have declared; it decides the name rules and one of the three clauses
    that forbid a repeated parameter. The other two, the arity of an accessor, and the directive rule
    hold whatever mode the program is in.

    A Use Strict Directive is illegal under a parameter list that is not simple (§15.2.1). The rule is
    the body's own prologue against the list, and not the mode: in a body that is already strict the
    directive changes nothing and the text is refused all the same, which is the shape a promoted
    directive lands in.

    A repeated name is a Syntax Error under three separate clauses, and reporting on any one of them
    alone is wrong in one direction or the other. `UniqueFormalParameters` — every arrow and every
    method definition — forbids it outright; `FormalParameters` forbids it in strict code, and forbids
    it in either mode once the list holds anything that is not a plain identifier.
    """
    grammar = parameter_grammar(fn)
    simple = has_simple_parameters(fn)
    suspend = _suspend_operator_in_parameters(fn)
    if suspend is not None:
        out.append(StrictViolation(suspend.offset, 'suspend-in-parameters'))
    if not simple and declares_use_strict(fn.body):
        out.append(StrictViolation(fn.offset, 'use-strict-with-non-simple-parameters'))
    if grammar is ParameterGrammar.GETTER and fn.params:
        out.append(StrictViolation(fn.offset, 'accessor-arity'))
    if grammar is ParameterGrammar.SETTER and (
        len(fn.params) != 1
        or isinstance(fn.params[0], JsRestElement)
    ):
        out.append(StrictViolation(fn.offset, 'accessor-arity'))
    repeats_are_errors = strict or not simple or grammar is not ParameterGrammar.FORMAL
    seen: set[str] = set()
    for param in fn.params:
        for ident in _target_identifiers(param):
            handled.add(id(ident))
            _flag_name(ident, strict, module, out)
            if ident.name not in seen:
                seen.add(ident.name)
            elif repeats_are_errors:
                out.append(StrictViolation(ident.offset, 'duplicate-parameter', ident.name))


def _check_names(
    node: Node,
    cur_strict: bool,
    child_strict: bool,
    module: bool,
    context: CodeContext,
    out: list[StrictViolation],
    handled: set[int],
) -> None:
    if isinstance(node, (JsFunctionDeclaration, JsFunctionExpression)):
        _check_function(node, child_strict, module, out, handled)
        _flag_bound(node.id, child_strict, module, out, handled)
    elif isinstance(node, JsArrowFunctionExpression):
        _check_function(node, child_strict, module, out, handled)
    elif isinstance(node, (JsClassDeclaration, JsClassExpression)):
        _flag_bound(node.id, child_strict, module, out, handled)
    elif isinstance(node, JsVariableDeclarator):
        _flag_bound(node.id, cur_strict, module, out, handled)
    elif isinstance(node, JsCatchClause):
        _flag_bound(node.param, cur_strict, module, out, handled)
    elif isinstance(node, (JsImportSpecifier, JsImportDefaultSpecifier, JsImportNamespaceSpecifier)):
        _flag_bound(node.local, cur_strict, module, out, handled)
    elif isinstance(node, JsAssignmentExpression):
        _flag_bound(node.left, cur_strict, module, out, handled)
    elif isinstance(node, JsUpdateExpression):
        _flag_bound(node.argument, cur_strict, module, out, handled)
    elif isinstance(node, (JsForInStatement, JsForOfStatement)):
        if not isinstance(node.left, JsVariableDeclaration):
            _flag_bound(node.left, cur_strict, module, out, handled)
    elif isinstance(node, JsIdentifier):
        if id(node) in handled or names_a_property(node):
            return
        if cur_strict and node.name in _STRICT_RESERVED:
            out.append(StrictViolation(node.offset, 'reserved-word', node.name))
        elif module and node.name == 'await':
            out.append(StrictViolation(node.offset, 'await-in-module', node.name))
        elif node.name == 'arguments' and context.arguments_reserved:
            out.append(StrictViolation(node.offset, 'arguments-in-class-initializer', node.name))


def _check_terminated(node: Node, out: list[StrictViolation]) -> None:
    """
    A construct the file ended inside is one every engine refuses as an unexpected end of input,
    whatever the mode and the goal. The node says so itself, and the tree holding it is no program.
    """
    if file_ended_inside(node):
        out.append(StrictViolation(node.offset, 'unterminated'))


def _check_html_comment(node: Node, module: bool, out: list[StrictViolation]) -> None:
    """
    An HTML-like comment is script grammar alone (§B.1.1): a module refuses `<!--` anywhere and
    `-->` at the head of a line. The lexer records the first delimiter it read on the script,
    since the comment one opens may stand where no node of the tree carries it, so a tree read as
    module code is reported on once, at that delimiter.
    """
    if module and isinstance(node, JsScript) and node.html_comment is not None:
        out.append(StrictViolation(node.html_comment, 'html-comment'))


def collect_strict_violations(
    node: Node,
    *,
    strict: bool = False,
    module: bool = False,
    context: CodeContext = SCRIPT_CONTEXT,
) -> list[StrictViolation]:
    """
    Every early error in the tree rooted at *node*, in source order. *strict* seeds the strictness of
    *node* itself; the pass then forces strict inside class bodies and inside any function whose body
    opens with a `"use strict"` directive, so a violation is recorded even when the seed is sloppy but
    the offending code sits in an inherently strict region.

    *module* asks the tree as though its goal symbol were Module, which unlike strictness is a fact of
    the whole file and never reset by a nested region: it adds the two rules a module carries beyond
    a strict script, that `await` names nothing, bound or referred to, and that the HTML-like
    comment delimiters open no comment. It is off by default, since a tree read on its own is a
    Script; a caller weighing text against a module destination seeds it True.

    *context* is what the code at *node* reads `await`, `yield` and `arguments` as, and every
    region below derives its own from it through
    `refinery.lib.scripts.js.model.code_context_within`. A tree read on its own stands at the top
    level of a file; a caller weighing text against a splice site seeds the site's context, so
    that a payload legal as a script is reported on where the site would refuse it — `arguments` in
    a class field initializer, `await` in a static block, `yield` in a generator body.

    A node the parser stores under two fields of its parent — a shorthand property's key and
    value, the local and exported halves of `export { x }` — is one node and is visited once.

    Not every rule asks about the mode. A Use Strict Directive under a parameter list that is not
    simple, a repeated name where the grammar requires a unique list, the arity of an accessor, a
    name a generator or an async function reserves, and `arguments` in a class field initializer or
    static block are refused whatever mode the program runs in, so a sloppy seed can report on a
    tree with no `"use strict"` anywhere in it. That is what makes a sloppy seed a usable gate on
    text about to be spliced into a destination whose mode is not yet known.

    An empty result means the tree has no parse error under the seeded mode; it does not imply the tree
    behaves identically in strict mode, since some divergences surface only at runtime.
    """
    out: list[StrictViolation] = []
    handled: set[int] = set()
    visited: set[int] = set()
    stack: list[tuple[Node, bool, CodeContext]] = [(node, strict, context)]
    while stack:
        current, current_strict, current_context = stack.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        child_strict = _child_strictness(current, current_strict)
        _check_node(current, current_strict, out)
        _check_terminated(current, out)
        _check_kind_reserved(current, current_context, out)
        _check_html_comment(current, module, out)
        _check_names(current, current_strict, child_strict, module, current_context, out, handled)
        for child in current.children():
            stack.append((child, child_strict, code_context_within(current, child, current_context)))
    out.sort(key=lambda violation: violation.offset)
    return out
