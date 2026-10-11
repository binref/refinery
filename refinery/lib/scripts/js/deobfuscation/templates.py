"""
Recognize a helper an obfuscator inserts by what it is: a function is the helper when its normal form
equals the normal form of the helper's template, the text the obfuscator writes it from. The normal
form undoes the changes minifying and the other transforms of the obfuscator make to a function, so
a pass asking this reads the helper wherever it stands and whatever its names are, and reads no
other function that merely holds a landmark of it.
"""
from __future__ import annotations

import functools

from typing import Collection, Iterable, NamedTuple

from refinery.lib.scripts import (
    Expression,
    Node,
    _clone_node,
    _remove_from_parent,
    _replace_in_parent,
    canonical,
    set_child,
    set_child_list,
    set_value,
)
from refinery.lib.scripts.js.analysis.model import SemanticModel, build_semantic_model, statement_list_of
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsDoWhileStatement,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionNode,
    JsIdentifier,
    JsIfStatement,
    JsMemberExpression,
    JsNumericLiteral,
    JsParenthesizedExpression,
    JsSequenceExpression,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVarKind,
    JsWhileStatement,
    static_property_key,
)
from refinery.lib.scripts.js.parser import JsParser

_LOOPS = (
    JsWhileStatement,
    JsDoWhileStatement,
    JsForStatement,
    JsForInStatement,
    JsForOfStatement,
)


class Template(NamedTuple):
    """
    A helper as the obfuscator writes it, and the free names in its text that stand for a part the
    function compared to it supplies: a name holding another helper, or a node of its own.
    """
    text: str
    placeholders: frozenset[str] = frozenset()


class Shape(NamedTuple):
    """
    The normal form of a function: whether it is a generator, whether it is `async`, and the
    canonical forms of its parameters and of its body.
    """
    generator: bool
    is_async: bool
    params: tuple[object, ...]
    body: object


class NormalForm:
    """
    The form a function is compared to a template in. Its own names are renamed in the order they
    appear, a name of an outer helper the template refers to becomes that helper's placeholder,
    parentheses go, a computed key that is a fixed name becomes a dotted one, the body of an `if`
    or a loop becomes a block, a `var` or `let` declaration becomes the assignments it makes, a
    sequence or a call of an empty function in statement position becomes one statement per
    operand, and a negated number literal becomes the negative number constant folding leaves. Those
    are the changes minifying, moving declarations and the other transforms of the obfuscator make
    to a helper. A negated zero stays negated, since a literal compares by its value and zero equals
    its negation.

    The names *placeholders* maps by the identity of their binding stand for the placeholder they
    are mapped to, and so does every node *nodes* maps by its identity, whatever it spells: the
    literal holding a decoder's alphabet, or the callee of the call it returns through. The names
    *empty* holds by the identity of their binding hold an empty function. A statement of the
    function *left_out* holds is no part of the form, with every name it spells: another transform
    inserted it, and the template does not hold it.
    """

    def __init__(
        self,
        model: SemanticModel,
        placeholders: dict[int, str],
        empty: set[int],
        nodes: dict[int, str] | None = None,
        left_out: Collection[Node] = (),
    ):
        self.model = model
        self.placeholders = placeholders
        self.empty = empty
        self.nodes = nodes or {}
        self.left_out = left_out

    def of(self, function: JsFunctionNode) -> Shape | None:
        renames: dict[int, str] = {}
        own: dict[int, str] = {}
        left_out = {id(statement) for statement in self.left_out}
        unread = {id(node) for statement in self.left_out for node in statement.walk()}
        for node in function.walk():
            if not isinstance(node, JsIdentifier) or id(node) in unread:
                continue
            binding = self.model.resolve(node) or self.model.binding_of(node)
            if binding is None:
                if self.model.is_reference(node):
                    renames[id(node)] = F'#free:{node.name}'
                continue
            if id(binding) in self.placeholders:
                renames[id(node)] = self.placeholders[id(binding)]
            elif id(binding) in self.empty:
                renames[id(node)] = '#empty'
            elif binding.scope.node is function or binding.scope.node.is_descendant_of(function):
                renames[id(node)] = own.setdefault(id(binding), F'#v{len(own)}')
            else:
                renames[id(node)] = '#outer'
        clone = _clone_node(function)
        swaps: list[tuple[Node, str]] = []
        dropped: list[Node] = []
        for original, copy in zip(function.walk(), clone.walk()):
            if type(original) is not type(copy):
                return None
            if id(original) in renames:
                set_value(copy, 'name', renames[id(original)])
            if id(original) in self.nodes:
                swaps.append((copy, self.nodes[id(original)]))
            if id(original) in left_out:
                dropped.append(copy)
        for copy, placeholder in swaps:
            _replace_in_parent(copy, JsIdentifier(name=placeholder))
        for copy in dropped:
            if not _remove_from_parent(copy):
                return None
        self._normalize(clone)
        return Shape(
            bool(getattr(clone, 'generator', False)),
            bool(getattr(clone, 'is_async', False)),
            tuple(canonical(parameter) for parameter in clone.params),
            None if clone.body is None else canonical(clone.body),
        )

    def _normalize(self, root: Node) -> None:
        for node in list(root.walk()):
            if isinstance(node, JsParenthesizedExpression) and node.expression is not None:
                _replace_in_parent(node, node.expression)
        for node in list(root.walk()):
            if (
                isinstance(node, JsUnaryExpression)
                and node.operator == '-'
                and isinstance(node.operand, JsNumericLiteral)
                and node.operand.value != 0
            ):
                _replace_in_parent(node, JsNumericLiteral(value=-node.operand.value))
            if isinstance(node, JsMemberExpression) and node.computed:
                key = static_property_key(node)
                if key is not None and key.isidentifier():
                    set_value(node, 'computed', False)
                    set_child(node, 'property', JsIdentifier(name=key))
            if isinstance(node, (JsIfStatement, *_LOOPS)):
                for field in ('consequent', 'alternate', 'body'):
                    child = getattr(node, field, None)
                    if child is not None and not isinstance(child, JsBlockStatement):
                        block = JsBlockStatement()
                        set_child(node, field, block)
                        set_child_list(block, 'body', [child])
        for node in list(root.walk()):
            if isinstance(node, JsForStatement) and isinstance(node.init, JsVariableDeclaration):
                assignments = self._assignments(node.init)
                if assignments is None:
                    continue
                if not assignments:
                    set_child(node, 'init', None)
                elif len(assignments) == 1:
                    set_child(node, 'init', assignments[0])
                else:
                    set_child(node, 'init', JsSequenceExpression(expressions=assignments))
        for node in list(root.walk()):
            if not isinstance(node, JsBlockStatement):
                continue
            body: list[Node] = []
            for statement in node.body:
                assignments = None
                if isinstance(statement, JsVariableDeclaration):
                    assignments = self._assignments(statement)
                if assignments is None:
                    body.extend(self._split(statement))
                    continue
                for assignment in assignments:
                    body.extend(self._split(JsExpressionStatement(expression=assignment)))
            set_child_list(node, 'body', body)

    @staticmethod
    def _assignments(declaration: JsVariableDeclaration) -> list[Expression] | None:
        if declaration.kind not in (JsVarKind.VAR, JsVarKind.LET):
            return None
        result: list[Expression] = []
        for declarator in declaration.declarations:
            if not isinstance(declarator.id, JsIdentifier):
                return None
            if declarator.init is None:
                continue
            result.append(JsAssignmentExpression(left=declarator.id, operator='=', right=declarator.init))
        return result

    def _split(self, statement: Node) -> list[Node]:
        if not isinstance(statement, JsExpressionStatement):
            return [statement]
        expression = statement.expression
        if isinstance(expression, JsSequenceExpression):
            parts = expression.expressions
        elif (
            isinstance(expression, JsCallExpression)
            and isinstance(expression.callee, JsIdentifier)
            and expression.callee.name == '#empty'
        ):
            parts = expression.arguments
        else:
            return [statement]
        result: list[Node] = []
        for part in parts:
            result.extend(self._split(JsExpressionStatement(expression=part)))
        return result


def _rename_free(form: object, names: frozenset[str]) -> object:
    if isinstance(form, tuple):
        return tuple(_rename_free(item, names) for item in form)
    if isinstance(form, str) and form.startswith('#free:') and form[6:] in names:
        return form[6:]
    return form


@functools.lru_cache(maxsize=None)
def template_form(template: Template) -> Shape:
    """
    The normal form of *template*. Each of its placeholders is renamed to itself, which only a name
    or a node a caller maps to it takes in the form of a function: a call of a global the program
    never declares keeps its spelling as a free name, so a function calling an undeclared `IMUL`
    does not match a template calling the placeholder `IMUL`.
    """
    script = JsParser(template.text).parse()
    function = script.body[0]
    assert isinstance(function, JsFunctionDeclaration)
    form = NormalForm(build_semantic_model(script), {}, set()).of(function)
    assert form is not None
    return form._replace(
        params=tuple(_rename_free(parameter, template.placeholders) for parameter in form.params),
        body=_rename_free(form.body, template.placeholders),
    )


def empty_functions_called(model: SemanticModel, function: Node) -> set[int]:
    """
    The names *function* calls that hold one function with no parameters and an empty body, the
    wrapper the obfuscator puts around a sequence of statements, by the identity of their binding.
    """
    empty: set[int] = set()
    for node in function.walk():
        if not isinstance(node, JsCallExpression) or not isinstance(node.callee, JsIdentifier):
            continue
        binding = model.resolve(node.callee)
        value = None if binding is None else model.singular_value(binding)
        if isinstance(value, FUNCTION_NODES) and not value.params and statement_list_of(value) == []:
            empty.add(id(binding))
    return empty


def matches(
    model: SemanticModel,
    function: JsFunctionNode,
    templates: Iterable[Template],
    placeholders: dict[int, str],
    nodes: dict[int, str] | None = None,
    left_out: Collection[Node] = (),
) -> bool:
    """
    Whether *function* has the normal form of one of *templates*, the names *placeholders* maps and
    the nodes *nodes* maps standing for the placeholders they are mapped to, and the statements of
    *left_out* left out. A function whose number of parameters no template has is refused before
    its form is built, which costs a copy of the whole function.
    """
    shapes = [template_form(template) for template in templates]
    if all(len(function.params) != len(shape.params) for shape in shapes):
        return False
    empty = empty_functions_called(model, function)
    form = NormalForm(model, placeholders, empty, nodes, left_out).of(function)
    return form is not None and form in shapes
