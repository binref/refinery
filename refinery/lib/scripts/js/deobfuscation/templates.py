"""
Recognize a helper an obfuscator inserts by what it is: a function is the helper when its normal
form equals the normal form of the helper's template, the text the obfuscator writes it from. The
normal form undoes the changes minifying and the other transforms of the obfuscator make to a
function, so a pass asking this reads the helper wherever it stands and whatever its names are, and
reads no other function that merely holds a landmark of it.
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
from refinery.lib.scripts.js.analysis.model import (
    SemanticModel,
    build_semantic_model,
    statement_list_of,
)
from refinery.lib.scripts.js.deobfuscation.helpers import names_global_value
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    LOOP_NODES,
    JsAssignmentExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsCallExpression,
    JsExpressionStatement,
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
    static_property_key,
)
from refinery.lib.scripts.js.parser import JsParser


class Shuffle(NamedTuple):
    """
    The statements of a template's body the obfuscator writes in an order of its choosing: those
    from *start* on in its normal form. It always writes the first *kept* of them and leaves out any
    of the others. No own name first appears in them: an own name is numbered where it first
    appears, and one first appearing in a statement written in an order of the obfuscator's choosing
    would be numbered by that order (`template_form` refuses such a template).
    """
    start: int
    kept: int


class Template(NamedTuple):
    """
    A helper as the obfuscator writes it, and the free names in its text that stand for a part the
    function compared to it supplies: a name holding another helper, or a node of its own. With
    *shuffled*, the obfuscator writes some of the statements of the body in an order of its choosing
    and leaves some of them out.
    """
    text: str
    placeholders: frozenset[str] = frozenset()
    shuffled: Shuffle | None = None


class Shape(NamedTuple):
    """
    The normal form of a function: whether it is a generator, whether it is `async`, the canonical
    forms of its parameters, and the canonical form of each statement of its body, or of the
    expression that is its body.
    """
    generator: bool
    is_async: bool
    params: tuple[object, ...]
    statements: tuple[object, ...] | None
    expression: object

    def fit(self, template: Template) -> tuple[int, ...] | None:
        """
        Which statement of *template* each statement of the body is, by its position in the
        template, or `None` where this is not the form of *template*. It is equal to the form of
        *template* but for the statements the obfuscator writes in an order of its choosing: those
        hold the ones it always writes and no statement the template does not, each at most as often
        as the template holds it.
        """
        form = template_form(template)
        if (
            self.generator != form.generator
            or self.is_async != form.is_async
            or self.params != form.params
            or self.expression != form.expression
        ):
            return None
        written = self.statements
        allowed = form.statements
        if written is None or allowed is None:
            return () if written is allowed else None
        if (shuffled := template.shuffled) is None:
            return tuple(range(len(allowed))) if written == allowed else None
        start = shuffled.start
        if written[:start] != allowed[:start]:
            return None
        positions: dict[object, list[int]] = {}
        for position, statement in enumerate(allowed[start:], start):
            positions.setdefault(statement, []).append(position)
        fit = [*range(start)]
        for statement in written[start:]:
            if not (free := positions.get(statement)):
                return None
            fit.append(free.pop(0))
        if any(start + index not in fit for index in range(shuffled.kept)):
            return None
        return tuple(fit)


class NormalForm:
    """
    The form a function is compared to a template in. Its own names are numbered in the order they
    first appear once the rest is normalized, a name of an outer helper the template refers to
    becomes that helper's placeholder, `undefined` where it still names the global value becomes
    `void 0`, parentheses go, a computed key that is a fixed name becomes a dotted one, the body of
    an `if` or a loop becomes a block, a `var` or `let` declaration becomes the assignments it
    makes, a sequence or a call of an empty function in statement position becomes one statement
    per operand, a negated number literal becomes the negative number constant folding leaves, and
    `!0` and `!1` become the `true` and `false` a minifier spells that way.
    Those are the changes minifying, moving declarations and the other transforms of the obfuscator
    make to a helper. A negated zero stays negated, since a literal compares by its value and zero
    equals its negation.

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
        """
        The normal form of *function*, or `None` where a statement *left_out* holds cannot be left
        out.
        """
        clone = self.normalized(function)
        return None if clone is None else _shape_of(clone)

    def normalized(self, function: JsFunctionNode) -> Node | None:
        """
        A copy of *function* written in its normal form, its own names spelled `#v0`, `#v1` and so
        on in the order they first appear, or `None` as for `of`.
        """
        renames: dict[int, str] = {}
        own: dict[int, str] = {}
        undefined: set[int] = set()
        left_out = {id(statement) for statement in self.left_out}
        unread = {id(node) for statement in self.left_out for node in statement.walk()}
        for node in function.walk():
            if not isinstance(node, JsIdentifier) or id(node) in unread:
                continue
            binding = self.model.resolve(node) or self.model.binding_of(node)
            if binding is None:
                if not self.model.is_reference(node):
                    continue
                if node.name == 'undefined' and names_global_value(node, self.model):
                    undefined.add(id(node))
                else:
                    renames[id(node)] = F'#free:{node.name}'
                continue
            if id(binding) in self.placeholders:
                renames[id(node)] = self.placeholders[id(binding)]
            elif id(binding) in self.empty:
                renames[id(node)] = '#empty'
            elif binding.declared_within(function):
                renames[id(node)] = own.setdefault(id(binding), F'#own:{len(own)}')
            else:
                renames[id(node)] = '#outer'
        clone = _clone_node(function)
        swaps: list[tuple[Node, str]] = []
        voided: list[Node] = []
        dropped: list[Node] = []
        for original, copy in zip(function.walk(), clone.walk()):
            if type(original) is not type(copy):
                return None
            if id(original) in renames:
                set_value(copy, 'name', renames[id(original)])
            if id(original) in undefined:
                voided.append(copy)
            if id(original) in self.nodes:
                swaps.append((copy, self.nodes[id(original)]))
            if id(original) in left_out:
                dropped.append(copy)
        for copy, placeholder in swaps:
            _replace_in_parent(copy, JsIdentifier(name=placeholder))
        for copy in voided:
            void = JsUnaryExpression(operator='void', operand=JsNumericLiteral(value=0))
            _replace_in_parent(copy, void)
        for copy in dropped:
            if not _remove_from_parent(copy):
                return None
        self._normalize(clone)
        numbers: dict[str, str] = {}
        for node in clone.walk_in_order():
            if isinstance(node, JsIdentifier) and node.name.startswith('#own:'):
                set_value(node, 'name', numbers.setdefault(node.name, F'#v{len(numbers)}'))
        return clone

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
            if (
                isinstance(node, JsUnaryExpression)
                and node.operator == '!'
                and isinstance(node.operand, JsNumericLiteral)
                and node.operand.value in (0, 1)
            ):
                _replace_in_parent(node, JsBooleanLiteral(value=node.operand.value == 0))
            if isinstance(node, JsMemberExpression) and node.computed:
                key = static_property_key(node)
                if key is not None and key.isidentifier():
                    set_value(node, 'computed', False)
                    set_child(node, 'property', JsIdentifier(name=key))
            if isinstance(node, (JsIfStatement, *LOOP_NODES)):
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


def _shape_of(clone: Node) -> Shape:
    """
    The form of *clone*, a function written in its normal form (`NormalForm.normalized`).
    """
    body = getattr(clone, 'body', None)
    statements = None
    expression = None
    if isinstance(body, JsBlockStatement):
        statements = tuple(canonical(statement) for statement in body.body)
    elif body is not None:
        expression = canonical(body)
    return Shape(
        bool(getattr(clone, 'generator', False)),
        bool(getattr(clone, 'is_async', False)),
        tuple(canonical(parameter) for parameter in getattr(clone, 'params', ())),
        statements,
        expression,
    )


def _first_appears_in_the_shuffle(clone: Node, shuffled: Shuffle) -> bool:
    """
    Whether an own name of the normalized function *clone* first appears in one of the statements
    *shuffled* names.
    """
    statements = statement_list_of(clone) or []
    before = [*getattr(clone, 'params', ()), *statements[:shuffled.start]]
    seen = {node.name for part in before for node in part.walk() if isinstance(node, JsIdentifier)}
    return any(
        isinstance(node, JsIdentifier) and node.name.startswith('#v') and node.name not in seen
        for statement in statements[shuffled.start:]
        for node in statement.walk()
    )


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
    does not match a template calling the placeholder `IMUL`; a placeholder the template writes is
    a name the model binds, and it is renamed to itself as well. A template one of whose own names
    first appears in a statement the obfuscator writes in an order of its choosing is refused
    (`Shuffle`).
    """
    script = JsParser(template.text).parse()
    function = script.body[0]
    assert isinstance(function, JsFunctionDeclaration)
    model = build_semantic_model(script)
    written = {
        id(binding): binding.name for node in function.walk()
        if isinstance(node, JsIdentifier)
        and node.name in template.placeholders
        and (binding := model.resolve(node)) is not None
    }
    normal = NormalForm(model, written, set())
    clone = normal.normalized(function)
    assert clone is not None
    shuffled = template.shuffled
    if shuffled is not None and _first_appears_in_the_shuffle(clone, shuffled):
        raise ValueError(
            F'an own name first appears in a shuffled statement of the template: {template.text}'
        )
    form = _shape_of(clone)
    statements = form.statements
    if statements is not None:
        statements = tuple(
            _rename_free(statement, template.placeholders) for statement in statements
        )
    return form._replace(
        params=tuple(_rename_free(parameter, template.placeholders) for parameter in form.params),
        statements=statements,
        expression=_rename_free(form.expression, template.placeholders),
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


def match(
    model: SemanticModel,
    function: JsFunctionNode,
    templates: Iterable[Template],
    placeholders: dict[int, str],
    nodes: dict[int, str] | None = None,
    left_out: Collection[Node] = (),
) -> tuple[Template, tuple[int, ...]] | None:
    """
    The first of *templates* whose normal form *function* has, the names *placeholders* maps and
    the nodes *nodes* maps standing for the placeholders they are mapped to, and the statements of
    *left_out* left out; with it, which statement of the template each statement of the body of
    *function* is (`Shape.fit`). A function whose number of parameters no template has is refused
    before its form is built, which costs a copy of the whole function.
    """
    templates = list(templates)
    if all(len(function.params) != len(template_form(template).params) for template in templates):
        return None
    empty = empty_functions_called(model, function)
    form = NormalForm(model, placeholders, empty, nodes, left_out).of(function)
    if form is None:
        return None
    for template in templates:
        if (fit := form.fit(template)) is not None:
            return template, fit
    return None


def matches(
    model: SemanticModel,
    function: JsFunctionNode,
    templates: Iterable[Template],
    placeholders: dict[int, str],
    nodes: dict[int, str] | None = None,
    left_out: Collection[Node] = (),
) -> bool:
    """
    Whether *function* has the normal form of one of *templates* (`match`).
    """
    return match(model, function, templates, placeholders, nodes, left_out) is not None
