"""
The obfuscator converts statement sequences into calls to a self-disabling no-op function whose
arguments carry all side effects. This transformer detects the pattern structurally, expands the
calls that reach such a function back into individual statements, and removes the declaration where
the expansion left nothing that reads it.

Which calls reach it is a question about the binding the wrapper declares and never about the name
it answers to, and every part of that question is settled before anything is rewritten:
`_the_calls_that_reach` holds the rule.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import (
    Expression,
    Node,
    _remove_from_parent,
    _replace_in_parent,
    owning_list,
    reattach,
    set_child_list,
)
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    SemanticModel,
    enclosing_operator,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    a_host_reaches_the_binding,
)
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsNumericLiteral,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsStaticBlock,
    JsUnaryExpression,
    JsVariableDeclarator,
    strip_parens,
    wraps_return,
)
from refinery.lib.scripts.js.strict import is_prologue_host


class _Wrapper(NamedTuple):
    """
    A self-disabling wrapper declaration and every call that reaches it.

    The calls are the nodes themselves rather than a question asked again later, because the
    rewrite moves them: the declaration goes exactly when every one of them was expanded, and that
    is a question about the calls this list named before anything moved. The list is never empty, so
    that answer is never one no call was asked for.
    """
    declaration: JsFunctionDeclaration
    calls: list[JsCallExpression]


def _is_expression_wrapper(node: JsFunctionDeclaration) -> bool:
    """
    Test whether a function declaration matches the self-disabling wrapper pattern:

        function NAME() {
            NAME = function() {};
        }
    """
    if node.id is None or node.body is None:
        return False
    if node.params:
        return False
    if not isinstance(node.body, JsBlockStatement):
        return False
    body = node.body.body
    if len(body) != 1:
        return False
    stmt = body[0]
    if not isinstance(stmt, JsExpressionStatement):
        return False
    expr = stmt.expression
    if not isinstance(expr, JsAssignmentExpression):
        return False
    if expr.operator != '=':
        return False
    if not isinstance(expr.left, JsIdentifier):
        return False
    if expr.left.name != node.id.name:
        return False
    rhs = expr.right
    if not isinstance(rhs, JsFunctionExpression):
        return False
    if wraps_return(rhs):
        return False
    if rhs.params:
        return False
    if isinstance(rhs.body, JsBlockStatement) and rhs.body.body:
        return False
    return True


def _stands_as_a_statement_of_a_function_or_the_script(node: JsFunctionDeclaration) -> bool:
    """
    Whether *node* is a statement of the script or of a function body, which is the only placement
    the whole of a declaration can be read from.

    A block-scoped function declaration is one thing in strict code, where it is scoped to the
    block, and another in sloppy code, where the enclosing scope holds the name from the start and
    reaching the block is what puts the function in it; a labeled or exported declaration sits in a
    slot `_remove_from_parent` cannot take it from.

    The three placements a Directive Prologue can open are the same three, which is why
    `refinery.lib.scripts.js.strict.is_prologue_host` answers this. A class static block is the one
    of them left out: it is a scope of its own that nothing here has measured the model against, and
    admitting it would buy a shape no obfuscator writes.
    """
    parent = node.parent
    return is_prologue_host(parent) and not isinstance(parent, JsStaticBlock)


def _a_bare_var_declarator_outside_a_loop_head(declared: Node) -> bool:
    """
    Whether *declared* declares a `var` with no initializer outside a loop head, which is the one
    further declaration of a wrapper's name that says nothing about what the name holds.

    An initializer is a declaration and not a write, and the store a `for-in` or `for-of` head makes
    is neither, so the model reports no reference for either of them. A binding carrying one is a
    binding something puts a value into that the expansion would never have seen.
    """
    declarator = declared.parent
    if not isinstance(declarator, JsVariableDeclarator) or declarator.init is not None:
        return False
    declaration = declarator.parent
    if declaration is None:
        return False
    return not isinstance(declaration.parent, (JsForInStatement, JsForOfStatement))


def _the_calls_that_reach(
    model: SemanticModel,
    binding: Binding,
    declaration: JsFunctionDeclaration,
) -> list[JsCallExpression] | None:
    """
    Every call that reaches the wrapper *declaration* declares, or `None` where the expansion is not
    equivalent for *binding*, the binding it declares, at all.

    Expanding a call to the statements its arguments carry is equivalent only where the name holds
    this wrapper when the call runs and nothing observes that the call then disabled it. That is
    three questions about the binding:

    - it is declared once, here, but for a bare `var` of the same name, which stores nothing;
    - every write to it is the self-disabling assignment inside this declaration, so nothing else
      ever puts a value into the name;
    - every reference to it is the callee of a call, so that no read of the name can tell the
      wrapper from what it left behind. The parentheses around a callee and around the call itself
      are looked through, which is what `refinery.lib.scripts.js.analysis.model.enclosing_operator`
      and `refinery.lib.scripts.js.model.strip_parens` are for;
      `refinery.lib.scripts.js.analysis.model.is_invocation_target` answers a wider question than
      this one, counting the tag of a tagged template, which no expansion here is written for. An
      export list naming the wrapper is such a reference — the local half of a sourceless list
      reads the binding — and is never the callee of a call, so an exported wrapper is refused
      here without being looked for separately.

    A reference that is not an identifier stands in for an access made through an object aliasing
    the binding, which is not a name this pass can follow.

    `refinery.lib.scripts.js.analysis.effects.EffectModel.function_escapes` asks a question the
    same shape as this one and answers `True` for every self-disabling wrapper there is: it refuses
    a written binding, a dynamic reference and a second declaration outright, and those three are
    exactly what the carve-outs above are about. It cannot stand in for this.

    A reference a `with` body resolves at run time is counted as a call that reaches the wrapper,
    which the object supplying the name instead would make wrong. That acceptance, and the reason
    it is made rather than refused, is
    `test.lib.scripts.js.test_unfixed_defects.TestAWithObjectMayCarryTheNameAWrapperAnswersTo`; the
    opaque reflective surfaces are accepted for the reason
    `test.lib.scripts.js.test_unfixed_defects.TestAnUnreadableEvalMayRebindAWrapper` states. A
    dynamic reference that resolves to another binding is not such a reference: it reaches this
    wrapper only in the reading where that binding is absent
    (`refinery.lib.scripts.js.analysis.model.Binding.may_be_absent`) and reaches the other one in
    the reading where it is not, so the wrapper is refused.
    """
    for name in binding.declarations:
        if name is not declaration.id and not _a_bare_var_declarator_outside_a_loop_head(name):
            return None
    for write in (*binding.writes, *binding.indefinite_writes):
        if not isinstance(write, JsIdentifier) or not write.is_descendant_of(declaration):
            return None
    if any(model.resolve(reference) is not None for reference in binding.dynamic_refs):
        return None
    calls: list[JsCallExpression] = []
    for reference in (*binding.reads, *binding.dynamic_refs):
        if not isinstance(reference, JsIdentifier):
            return None
        call = enclosing_operator(reference)
        if not isinstance(call, JsCallExpression) or strip_parens(call.callee) is not reference:
            return None
        calls.append(call)
    return calls


def _admitted_wrappers(cache: ModelCache, root: JsScript, options: object) -> list[_Wrapper]:
    """
    The self-disabling wrappers of *root* the pass may expand, each with the calls that reach it.

    A wrapper whose call answers a promise or a generator object is refused: expanding one call site
    takes the body that disables the wrapper with it, so a call left standing beside an expanded one
    answers a promise where the input answered `undefined`. This is decided per declaration and no
    longer poisons a plain wrapper elsewhere that happens to answer to the same name.

    The shape question is asked before the model is read, so a file carrying no wrapper at all never
    pays for one being built.
    """
    shaped = [
        node for node in root.walk()
        if isinstance(node, JsFunctionDeclaration)
        and not wraps_return(node)
        and _stands_as_a_statement_of_a_function_or_the_script(node)
        and _is_expression_wrapper(node)
    ]
    if not shaped:
        return []
    model = cache.model
    wrappers: list[_Wrapper] = []
    for node in shaped:
        assert node.id is not None
        binding = model.binding_of(node.id)
        if binding is None:
            continue
        if a_host_reaches_the_binding(model, binding, options):
            continue
        calls = _the_calls_that_reach(model, binding, node)
        if not calls:
            continue
        wrappers.append(_Wrapper(node, calls))
    return wrappers


class JsAssignmentsAsFunctionArgs(ScriptLevelTransformer):
    """
    Detect self-disabling wrapper functions and expand the call sites that reach one: a call in
    statement position becomes the individual argument statements, and a call embedded in a larger
    expression becomes the equivalent comma sequence in place, so evaluation order is preserved.

    Which wrapper a call site reaches, and which of them may be expanded at all, is decided by
    `_admitted_wrappers` before the first call is rewritten.
    """

    @staticmethod
    def _sequence_lowering(arguments: list[Expression]) -> Expression:
        """
        The value a self-disabling wrapper call `W(a, b)` computes — its arguments evaluated left to
        right, then `undefined` — expressed in place so nothing is reordered: the comma sequence
        `(a, b, void 0)`, or a bare `void 0` when there are no arguments.
        """
        void_0 = JsUnaryExpression(operator='void', operand=JsNumericLiteral(value=0, raw='0'))
        if not arguments:
            return void_0
        return JsSequenceExpression(expressions=[*arguments, void_0])

    def _expand(self, call: JsCallExpression) -> bool:
        """
        Expand one call to the statements or the sequence it is worth, and report whether it was.

        A spread argument is neither a statement nor a sequence operand, and a statement its own
        list does not hold cannot be spliced into; either way the call stays, and the wrapper it
        reaches stays with it. Which list holds it is `refinery.lib.scripts.owning_list`'s answer,
        the same one `refinery.lib.scripts._remove_from_parent` would reach, so a statement position
        this pass can splice is exactly one a removal could take the statement from. A replacement
        that finds no slot is the same answer: the sequence it built has adopted the arguments by
        then, so the call takes them back before the refusal.
        """
        if any(isinstance(arg, JsSpreadElement) for arg in call.arguments):
            return False
        parent = call.parent
        if isinstance(parent, JsExpressionStatement) and (held := owning_list(parent)) is not None:
            block, attribute = held
            body = getattr(block, attribute)
            index = next(i for i, item in enumerate(body) if item is parent)
            statements = [JsExpressionStatement(expression=arg) for arg in call.arguments]
            set_child_list(block, attribute, [*body[:index], *statements, *body[index + 1:]])
            return True
        if _replace_in_parent(call, self._sequence_lowering(call.arguments)):
            return True
        reattach(call)
        return False

    def _process_script(self, node: JsScript):
        wrappers = _admitted_wrappers(model_cache(self, node), node, self.options)
        if not wrappers:
            return
        reached = {id(call) for wrapper in wrappers for call in wrapper.calls}
        expanded: set[int] = set()
        for ast_node in list(node.walk()):
            if not isinstance(ast_node, JsCallExpression) or id(ast_node) not in reached:
                continue
            if self._expand(ast_node):
                expanded.add(id(ast_node))
        if not expanded:
            return
        self.mark_changed()
        for wrapper in wrappers:
            if all(id(call) in expanded for call in wrapper.calls):
                _remove_from_parent(wrapper.declaration)
