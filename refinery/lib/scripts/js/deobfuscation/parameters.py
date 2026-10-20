"""
An unpacking of a function's arguments, written as its parameter list.

A pass that moves the unpacking of the arguments into the parameter list, or gives a function the
parameters it reads out of a rest array, asks `parameter_list` for the list. The list binds what the
unpacking binds and has the `length` the pass asks for, which is how many parameters precede the
first one with a default, a rest element or a hole:

    function add(...args) { var [a, b] = args; ... }    length 0
    function add(...[a, b]) { ... }                      length 0
    function add(a, b) { ... }                           length 2

`JsRestPatternParameters` writes `(a, b)` for `(...[a, b])` wherever nothing reads the `length`.
"""
from __future__ import annotations

from typing import Collection, Iterator, NamedTuple, Sequence

from refinery.lib.scripts import Expression, Node, set_child_list
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    SemanticModel,
    is_direct_eval_call,
    pattern_binds_unread_names,
    pattern_identifiers,
    references_own_arguments,
    walk_receiver_scope,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    a_host_reaches_the_binding,
    walk_scope,
)
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsArrayPattern,
    JsAssignmentPattern,
    JsAwaitExpression,
    JsBlockStatement,
    JsFunctionDeclaration,
    JsFunctionNode,
    JsIdentifier,
    JsObjectPattern,
    JsProperty,
    JsRestElement,
    JsScript,
    JsYieldExpression,
    is_generator_function,
)
from refinery.lib.scripts.js.strict import declares_use_strict, strict_mode_at


class ParameterList(NamedTuple):
    """
    A parameter list `parameter_list` decided on: the elements of the unpacking that are parameters
    of their own, and those after them, which are the elements of one rest pattern where any are
    left. The list is decided without touching the elements, which stay where they are in the tree
    until `ParameterList.build` is called for the edit.
    """
    head: list[Expression]
    tail: list[Expression | None]

    def build(self) -> list[Expression]:
        """
        The parameters, made of the elements themselves.
        """
        if not self.tail:
            return list(self.head)
        return [*self.head, JsRestElement(argument=JsArrayPattern(elements=self.tail))]


def _counted_length(elements: Sequence[Expression | None]) -> int:
    """
    The `length` of a function whose parameters are *elements*: the number of them before the first
    one with a default, the rest element, or a hole.
    """
    count = 0
    for element in elements:
        if element is None or isinstance(element, (JsAssignmentPattern, JsRestElement)):
            break
        count += 1
    return count


def _arguments_may_alias(elements: Sequence[Expression | None], function: JsFunctionNode) -> bool:
    """
    Whether plain names in place of *elements* would give *function* an `arguments` object whose
    elements alias them: in sloppy mode, where its body reads its own `arguments` or holds a direct
    `eval`, which can.
    """
    if not elements or strict_mode_at(function):
        return False
    if references_own_arguments(function):
        return True
    return any(is_direct_eval_call(node) for node in walk_receiver_scope(function))


def parameter_list(
    elements: Sequence[Expression | None],
    function: JsFunctionNode,
    length: int | None,
) -> ParameterList | None:
    """
    The parameter list of *function* that binds what an unpacking of its arguments into an array
    pattern with *elements* binds, and gives it the `length` *length*; where *length* is `None`, the
    list may give it any. The answer is `None` where no list does: a pattern binding a name twice,
    binding `arguments` or `eval`, or holding source the parser could not read; a negative *length*
    or one greater than the elements count; and a list that is not plain names in a function whose
    own body says `'use strict'`, which the language refuses.

    The elements are parameters of their own as far as that keeps *length*, and the rest of them
    are the elements of one rest pattern after those: `(a, ...[b])` has length 1. A list of plain
    names in a sloppy function reading its own `arguments` would have the object alias the names,
    which the unpacking did not, so the list keeps a rest pattern there, with length 0 where any
    length will do, and is refused where *length* counts every name.
    """
    elements = list(elements)
    names = [name for element in elements for name in pattern_identifiers(element)]
    spelled = {name.name for name in names}
    if (
        any(pattern_binds_unread_names(element) for element in elements)
        or len(spelled) != len(names)
        or spelled & {'arguments', 'eval'}
    ):
        return None
    counted = _counted_length(elements)
    plain = all(isinstance(element, JsIdentifier) for element in elements)
    keeps_rest = (
        plain
        and (length is None or length == counted)
        and _arguments_may_alias(elements, function)
    )
    if length is None:
        length = 0 if keeps_rest else counted
    if not 0 <= length <= counted:
        return None
    if keeps_rest and length == counted:
        return None
    named = length
    if length == counted and None not in elements and not keeps_rest:
        named = len(elements)
    head: list[Expression] = []
    for element in elements[:named]:
        if element is None:
            return None
        head.append(element)
    tail = elements[named:]
    if tail or not plain:
        body = function.body
        if isinstance(body, JsBlockStatement) and declares_use_strict(body):
            return None
    return ParameterList(head, tail)


def _parameter_expressions(pattern: JsArrayPattern) -> Iterator[tuple[int, Node]]:
    """
    The defaults and computed keys *pattern* evaluates, each with the index of the element holding
    it.
    """
    def within(node: Node | None) -> Iterator[Node]:
        if isinstance(node, JsArrayPattern):
            for element in node.elements:
                yield from within(element)
        elif isinstance(node, JsObjectPattern):
            for prop in node.properties:
                if isinstance(prop, JsRestElement):
                    yield from within(prop.argument)
                elif isinstance(prop, JsProperty):
                    if prop.computed and prop.key is not None:
                        yield prop.key
                    yield from within(prop.value)
        elif isinstance(node, JsAssignmentPattern):
            yield from within(node.left)
            if node.right is not None:
                yield node.right
        elif isinstance(node, JsRestElement):
            yield from within(node.argument)

    for index, element in enumerate(pattern.elements):
        for expression in within(element):
            yield index, expression


def unpacking_moves_into_parameters(
    model: SemanticModel,
    pattern: JsArrayPattern,
    function: JsFunctionNode,
    exempt: Collection[Binding] = (),
) -> bool:
    """
    Whether the `var` unpacking *pattern* at the start of the body of *function* means what it
    means as the parameter list of *function*. A parameter list is bound at the call, before the
    function declarations of the body, and evaluates its defaults and computed keys in a scope of
    its own, which sees no name of the body and a later parameter not yet bound. So the answer is
    no for a generator, which runs its unpacking only at its first step; for a function declaration
    of the body named like a name the pattern binds; and for an expression of the pattern that reads
    a name the body declares or a name of its own element or a later one, holds a direct `eval`, or
    holds an `await` or a `yield`, which no parameter list may. Where the pattern evaluates any
    expression, a name it binds must be declared by the pattern alone, since a parameter list with
    expressions gives the body names of its own. Reads of a binding in *exempt* are the caller's.
    """
    if is_generator_function(function):
        return False
    expressions = list(_parameter_expressions(pattern))
    order: dict[int, int] = {}
    spelled: set[str] = set()
    for index, element in enumerate(pattern.elements):
        for name in pattern_identifiers(element):
            binding = model.binding_of(name)
            if binding is None:
                return False
            order[id(binding)] = index
            spelled.add(name.name)
            if expressions and any(site is not name for site in binding.declarations):
                return False
    for node in walk_scope(function, include_root_body=True):
        if (
            isinstance(node, JsFunctionDeclaration)
            and isinstance(node.id, JsIdentifier)
            and node.id.name in spelled
        ):
            return False
    for index, expression in expressions:
        for node in expression.walk():
            if (
                is_direct_eval_call(node)
                or isinstance(node, (JsAwaitExpression, JsYieldExpression))
            ):
                return False
            if not isinstance(node, JsIdentifier) or not model.is_reference(node):
                continue
            binding = model.resolve(node)
            if binding is None or binding in exempt:
                continue
            if id(binding) in order:
                if order[id(binding)] >= index:
                    return False
                continue
            if binding.declared_within(function) and not binding.declared_within(expression):
                return False
    return True


def function_length_unobserved(
    model: SemanticModel,
    function: JsFunctionNode,
    options: object,
) -> bool:
    """
    Whether nothing can read the `length` of *function*: every way to it is a call the text shows
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.reached_only_by_shown_calls`), and no
    name it is reached through, which is the name of its class for a constructor
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.names_reaching`), is one a host reaches.
    """
    if not model.reached_only_by_shown_calls(function):
        return False
    return not any(
        a_host_reaches_the_binding(model, binding, options)
        for binding in model.names_reaching(function)
    )


class JsRestPatternParameters(ScriptLevelTransformer):
    """
    Write `function f(...[a, b])` as `function f(a, b)` wherever nothing can read its `length`: the
    elements of a rest pattern that ends the parameter list become parameters of their own as far
    as `parameter_list` allows.
    """

    def _process_script(self, node: JsScript) -> None:
        cache = model_cache(self, node)
        model = cache.model
        edits: list[tuple[JsFunctionNode, ParameterList]] = []
        with cache.pinned():
            for function in node.walk():
                if not isinstance(function, FUNCTION_NODES):
                    continue
                params = function.params
                if (
                    not params
                    or not isinstance(rest := params[-1], JsRestElement)
                    or not isinstance(inner := rest.argument, JsArrayPattern)
                ):
                    continue
                if not function_length_unobserved(model, function, self.options):
                    continue
                leading = len(params) - 1
                decided = parameter_list([*params[:leading], *inner.elements], function, None)
                if decided is None or len(decided.head) <= leading:
                    continue
                edits.append((function, decided))
        for function, decided in edits:
            set_child_list(function, 'params', decided.build())
        if edits:
            self.mark_changed()
