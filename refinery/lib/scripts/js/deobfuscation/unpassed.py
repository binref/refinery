"""
Put back the declarations an obfuscation moved into the parameter list of a function. It gives a
function no call passes more arguments to than it declares a parameter for each declaration of its
body, and writes the declaration as a store the function makes when it starts:

    function parse(source) {               function parse(source, decode) {
      function decode(n) { ... }             if (!decode) {
      ...                                      decode = function (n) { ... };
    }                                        }
                                             ...
                                           }

A `var` whose value is made of literals and stands first in the body becomes a parameter with that
value as its default, `function parse(source, limit = 8)`, and any other `var` a parameter the body
assigns where the declaration stood.

No call passes such a parameter
(`refinery.lib.scripts.js.analysis.model.SemanticModel.parameter_never_passed`), so when the
function starts it holds `undefined` or its default, as the local it was. The pass makes it a local
again: the store of a function becomes the declaration of that function, a default a `var` with
that value at the top of the body, and a plain parameter a `var` without one. Only parameters that
end the list go, since the position of every other one is what a call passes to it.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Expression, Node, Statement, set_child_list
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    arguments_aliasing_changes,
    pattern_identifiers,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    is_literal,
    walk_scope,
)
from refinery.lib.scripts.js.deobfuscation.parameters import every_call_shown
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsArrayExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsBigIntLiteral,
    JsBinaryExpression,
    JsBlockStatement,
    JsCatchClause,
    JsClassDeclaration,
    JsConditionalExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsFunctionNode,
    JsIdentifier,
    JsIfStatement,
    JsLogicalExpression,
    JsObjectExpression,
    JsProperty,
    JsPropertyKind,
    JsScript,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
)
from refinery.lib.scripts.js.strict import directive_prologue, strict_mode_at


def _made_of_literals(node: Node | None) -> bool:
    """
    Whether *node* computes its value from literals alone and can neither throw nor run code of the
    program: an array or object literal of such values with plain keys, a conditional or logical
    operator over them, `!` or `void` of one, or a primitive made of literals
    (`_primitive_literal`). Such a value is the same wherever and whenever it is computed, so a
    generator, which computes its defaults when it is called and its body when it first resumes,
    computes it the same in either.
    """
    if isinstance(node, JsArrayExpression):
        return all(_made_of_literals(element) for element in node.elements)
    if isinstance(node, JsObjectExpression):
        return all(
            isinstance(prop, JsProperty)
            and not prop.computed
            and not prop.method
            and prop.kind is JsPropertyKind.INIT
            and _made_of_literals(prop.value)
            for prop in node.properties
        )
    if isinstance(node, JsConditionalExpression):
        return all(_made_of_literals(part) for part in (node.test, node.consequent, node.alternate))
    if isinstance(node, JsLogicalExpression):
        return _made_of_literals(node.left) and _made_of_literals(node.right)
    if isinstance(node, JsUnaryExpression) and node.operator in ('!', 'void'):
        return _made_of_literals(node.operand)
    return _primitive_literal(node)


def _primitive_literal(node: Node | None) -> bool:
    """
    Whether *node* is a primitive made of literals that no operator over it can throw on: a literal
    that is no `BigInt`, or `-`, `+` or `~` of one, or a binary operator but `in` and `instanceof`
    over two of them.
    """
    if node is None or isinstance(node, JsBigIntLiteral):
        return False
    if isinstance(node, JsUnaryExpression) and node.operator in ('-', '+', '~'):
        return _primitive_literal(node.operand)
    if isinstance(node, JsBinaryExpression):
        if node.operator in ('in', 'instanceof'):
            return False
        return _primitive_literal(node.left) and _primitive_literal(node.right)
    return is_literal(node)


class _Store(NamedTuple):
    """
    A statement `if (!p) { p = function () {...}; }`, the read of `p` it tests, and the function.
    """
    statement: JsIfStatement
    test: JsIdentifier
    function: JsFunctionExpression


class _Local(NamedTuple):
    """
    A parameter no call passes, by its name: its default, and the store of the function it holds
    where it holds one. It becomes the declaration of that function in place of the store, or a
    `var` at the top of the body.
    """
    name: str
    default: Expression | None
    store: _Store | None

    def declaration(self) -> Statement:
        """
        The declaration the parameter becomes, made of the nodes of the tree when the edit is made.
        """
        if (store := self.store) is not None:
            function = store.function
            return JsFunctionDeclaration(
                id=JsIdentifier(name=self.name),
                params=list(function.params),
                body=function.body,
                generator=function.generator,
                is_async=function.is_async,
            )
        declarator = JsVariableDeclarator(id=JsIdentifier(name=self.name), init=self.default)
        return JsVariableDeclaration(kind=JsVarKind.VAR, declarations=[declarator])


def _function_store(statement: Statement, binding: Binding, cache: ModelCache) -> _Store | None:
    """
    The function *statement* stores into the parameter *binding* when the parameter is falsy,
    `if (!p) { p = function () {...}; }`, where that store is the only write of the parameter.
    """
    model = cache.model
    if not isinstance(statement, JsIfStatement) or statement.alternate is not None:
        return None
    test = statement.test
    if (
        not isinstance(test, JsUnaryExpression)
        or test.operator != '!'
        or not isinstance(read := test.operand, JsIdentifier)
        or model.resolve(read) is not binding
    ):
        return None
    body = statement.consequent
    if isinstance(body, JsBlockStatement):
        if len(body.body) != 1:
            return None
        body = body.body[0]
    if (
        not isinstance(body, JsExpressionStatement)
        or not isinstance(store := body.expression, JsAssignmentExpression)
        or store.operator != '='
        or not isinstance(target := store.left, JsIdentifier)
        or not isinstance(function := store.right, JsFunctionExpression)
        or function.id is not None
        or binding.writes != [target]
    ):
        return None
    return _Store(statement, read, function)


def _tested_names(statements: list[Statement]) -> dict[str, list[JsIfStatement]]:
    """
    The statements among *statements* that test a plain name for being falsy and have no `else`,
    `if (!p) ...`, by the name they test: the only statements that can store a function into a
    parameter (`_function_store`).
    """
    tested: dict[str, list[JsIfStatement]] = {}
    for statement in statements:
        if (
            isinstance(statement, JsIfStatement)
            and statement.alternate is None
            and isinstance(test := statement.test, JsUnaryExpression)
            and test.operator == '!'
            and isinstance(read := test.operand, JsIdentifier)
        ):
            tested.setdefault(read.name, []).append(statement)
    return tested


def _names_declared_in_the_body(function: JsFunctionNode) -> set[str]:
    """
    The names the body of *function* declares itself, in any of its blocks or clauses. Annex B
    copies a block function to the body only where its name is no parameter, and with a default in
    the list the body's own `var`s and functions live apart from the parameters; a parameter made a
    declaration of the body would meet either.
    """
    declared: set[str] = set()
    if function.body is None:
        return declared
    for node in walk_scope(function.body):
        if isinstance(node, (JsFunctionDeclaration, JsClassDeclaration)):
            if node.id is not None:
                declared.add(node.id.name)
        elif isinstance(node, JsVariableDeclarator):
            declared.update(identifier.name for identifier in pattern_identifiers(node.id))
        elif isinstance(node, JsCatchClause):
            declared.update(identifier.name for identifier in pattern_identifiers(node.param))
    return declared


def _locals(function: JsFunctionNode, cache: ModelCache, options: object) -> list[_Local] | None:
    """
    The parameters that end the list of *function* and become declarations of its body, last first,
    or `None` where none does. Every call of the function is one the text shows, the host's included
    (`refinery.lib.scripts.js.deobfuscation.parameters.every_call_shown`), so nothing else passes
    them or reads the `length`. The run is the obfuscation's only where one of them holds a
    function stored under `if (!p)`, a shape no author writes; a run of plain or defaulted
    parameters alone is the shape an optional argument has, and stays. A function whose body tests
    none of its parameters that way is therefore passed over before the model is asked anything.
    """
    body = function.body
    if not isinstance(body, JsBlockStatement):
        return None
    statements = body.body[len(directive_prologue(body)):]
    tested = _tested_names(statements)
    if not any(
        isinstance(parameter, JsIdentifier) and parameter.name in tested
        for parameter in function.params
    ):
        return None
    model = cache.model
    if not every_call_shown(model, function, options):
        return None
    declared = _names_declared_in_the_body(function)
    found: list[_Local] = []
    for parameter in reversed(function.params):
        default = None
        name = parameter
        if isinstance(parameter, JsAssignmentPattern):
            name, default = parameter.left, parameter.right
            if not _made_of_literals(default):
                break
        if not isinstance(name, JsIdentifier) or name.name in declared:
            break
        binding = model.binding_of(name)
        if (
            binding is None
            or not model.parameter_never_passed(binding)
            or model.reflection_can_reach(binding)
            or model.references(binding, exclude=body)
        ):
            break
        stored = None
        if default is None:
            candidates = tested.get(name.name, [])
            stores = (_function_store(statement, binding, cache) for statement in candidates)
            stored = next((store for store in stores if store is not None), None)
        if stored is not None:
            reads = [read for read in binding.reads if read is not stored.test]
            if not all(cache.dominance.runs_before(stored.statement, read) for read in reads):
                break
        found.append(_Local(name.name, default, stored))
    if not any(local.store is not None for local in found):
        return None
    kept = function.params[:len(function.params) - len(found)]
    if (
        kept
        and arguments_aliasing_changes(function, function.params, kept, strict=strict_mode_at(body))
    ):
        return None
    return found


class JsUnpassedParameters(ScriptLevelTransformer):
    """
    Make the parameters no call passes that end a parameter list the declarations of the body they
    were moved out of.
    """

    def _process_script(self, node: JsScript) -> None:
        cache = model_cache(self, node)
        edits: list[tuple[JsFunctionNode, list[_Local]]] = []
        with cache.pinned():
            for function in node.walk():
                if not isinstance(function, FUNCTION_NODES) or not function.params:
                    continue
                if (found := _locals(function, cache, self.options)) is not None:
                    edits.append((function, found))
        for function, found in edits:
            body = function.body
            assert isinstance(body, JsBlockStatement)
            set_child_list(function, 'params', function.params[:len(function.params) - len(found)])
            statements = list(body.body)
            prologue = len(directive_prologue(body))
            placed = [local.declaration() for local in reversed(found) if local.store is None]
            for local in found:
                if local.store is not None:
                    statements[statements.index(local.store.statement)] = local.declaration()
            statements[prologue:prologue] = placed
            set_child_list(body, 'body', statements)
        if edits:
            self.mark_changed()
