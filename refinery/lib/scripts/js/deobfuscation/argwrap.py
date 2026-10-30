"""
The obfuscator converts statement sequences into calls to a self-disabling no-op function whose
arguments carry all side effects. This transformer detects the pattern structurally, expands the
calls that reach such a function back into individual statements, and removes the declaration where
the expansion left nothing that reads it.

Which calls reach it is a question about the binding the wrapper declares and never about the name
it answers to, and every part of that question is settled before anything is rewritten:
`refinery.lib.scripts.js.deobfuscation.helpers.self_disabling_wrapper_calls` holds the rule, which
the template matcher asks too.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import (
    Expression,
    _remove_from_parent,
    _replace_in_parent,
    owning_list,
    reattach,
    set_child_list,
)
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    declares_a_self_disabling_wrapper,
    self_disabling_wrapper_calls,
)
from refinery.lib.scripts.js.model import (
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsNumericLiteral,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsUnaryExpression,
)


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


def _admitted_wrappers(cache: ModelCache, root: JsScript) -> list[_Wrapper]:
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
        if isinstance(node, JsFunctionDeclaration) and declares_a_self_disabling_wrapper(node)
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
        calls = self_disabling_wrapper_calls(model, binding)
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
        wrappers = _admitted_wrappers(model_cache(self, node), node)
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
