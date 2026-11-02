"""
When each part of a JavaScript node is evaluated, relative to the node holding it.

A control-flow graph has a node for a statement and for each part of one that is evaluated at a
point of its own, such as the test of a loop, and no node for the parts of an expression. Whether a
store below `&&` has run when its statement has completed is therefore not a question the graph
answers; `evaluated_whenever_completed` answers it from `PART_EVALUATION`, which says for every node
type and child field whether the child is evaluated on every run on which its holder is, on some of
them only, or at a time of its own.

The table fails closed: a part it does not list is taken to be evaluated on some runs only, which
costs a reduction and never changes what a program does.

The parts evaluated at a time of their own are the one boundary of a run, the code one invocation
executes: `evaluated_later` asks it of a step, `owns_a_run` of a node, `walk_run` lists what a run
evaluates and `enclosing_run` names the run that evaluates a node.
"""
from __future__ import annotations

import enum

from typing import Callable, Iterator, NamedTuple

from refinery.lib.scripts import Node, child_fields
from refinery.lib.scripts.js.model import (
    LOGICAL_ASSIGNMENT_OPERATORS,
    JsArrayExpression,
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsAwaitExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsBreakStatement,
    JsCallExpression,
    JsCatchClause,
    JsClassBody,
    JsClassDeclaration,
    JsClassExpression,
    JsConditionalExpression,
    JsContinueStatement,
    JsDecorator,
    JsDoWhileStatement,
    JsExportAllDeclaration,
    JsExportDefaultDeclaration,
    JsExportNamedDeclaration,
    JsExportSpecifier,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIfStatement,
    JsImportAttribute,
    JsImportDeclaration,
    JsImportDefaultSpecifier,
    JsImportExpression,
    JsImportNamespaceSpecifier,
    JsImportSpecifier,
    JsLabeledStatement,
    JsLogicalExpression,
    JsMemberExpression,
    JsMethodDefinition,
    JsNewExpression,
    JsObjectExpression,
    JsObjectPattern,
    JsParenthesizedExpression,
    JsProperty,
    JsPropertyDefinition,
    JsRestElement,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsStaticBlock,
    JsSwitchCase,
    JsSwitchStatement,
    JsTaggedTemplateExpression,
    JsTemplateLiteral,
    JsThrowStatement,
    JsTryStatement,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsWhileStatement,
    JsWithStatement,
    JsYieldExpression,
)

__all__ = [
    'Evaluation',
    'PART_EVALUATION',
    'enclosing_run',
    'evaluated_later',
    'evaluated_whenever_completed',
    'evaluation_of',
    'owns_a_run',
    'walk_run',
]


class Evaluation(enum.Enum):
    """
    When a part of a node is evaluated, relative to the node holding it. `ALWAYS`: on every run on
    which the holder is evaluated and completes. `SOMETIMES`: on some of those runs only, or on
    none, as the right operand of `&&` or an arm of a conditional. `LATER`: at a time of its own
    rather than as a part of the holder, as the body of a function when it is called or the
    initializer of a field when an instance is constructed.
    """
    ALWAYS = 'always'
    SOMETIMES = 'sometimes'
    LATER = 'later'


def _optional_link_below(node: Node | None) -> bool:
    """
    Whether the member and call spine at *node* holds an optional link, past which evaluation stops
    when the value before the link is nullish.
    """
    while isinstance(node, (JsMemberExpression, JsCallExpression)):
        if node.optional:
            return True
        node = node.object if isinstance(node, JsMemberExpression) else node.callee
    return False


def _assigns_logically(holder: Node) -> bool:
    """
    Whether *holder* is an assignment with a logical operator, which assigns only when the target's
    value asks for it.
    """
    return (
        isinstance(holder, JsAssignmentExpression)
        and holder.operator in LOGICAL_ASSIGNMENT_OPERATORS
    )


def _is_static(holder: Node) -> bool:
    """
    Whether *holder* is a `static` field, whose initializer runs while the class statement does.
    """
    return isinstance(holder, JsPropertyDefinition) and holder.is_static


class _Choice(NamedTuple):
    """
    The evaluation of a part that its holder decides: *when* where *test* holds of the holder,
    *otherwise* where it does not.
    """
    test: Callable[[Node], bool]
    when: Evaluation
    otherwise: Evaluation

    def of(self, holder: Node) -> Evaluation:
        return self.when if self.test(holder) else self.otherwise


_A = Evaluation.ALWAYS
_S = Evaluation.SOMETIMES
_L = Evaluation.LATER

_PAST_A_LINK = _Choice(_optional_link_below, _S, _A)

#: For each node type and child field, when the child is evaluated relative to the node: one of
#: `Evaluation`, or a `_Choice` the node makes where its operator, its links or its being `static`
#: decide it.
PART_EVALUATION: dict[tuple[type[Node], str], Evaluation | _Choice] = {
    (JsArrayExpression, 'elements')                 : _A,
    (JsArrayPattern, 'elements')                    : _A,
    (JsArrowFunctionExpression, 'params')           : _L,
    (JsArrowFunctionExpression, 'body')             : _L,
    (JsAssignmentExpression, 'left')                : _A,
    (JsAssignmentExpression, 'right')               : _Choice(_assigns_logically, _S, _A),
    (JsAssignmentPattern, 'left')                   : _A,
    (JsAssignmentPattern, 'right')                  : _S,
    (JsAwaitExpression, 'argument')                 : _A,
    (JsBinaryExpression, 'left')                    : _A,
    (JsBinaryExpression, 'right')                   : _A,
    (JsBlockStatement, 'body')                      : _S,
    (JsBreakStatement, 'label')                     : _A,
    (JsCallExpression, 'callee')                    : _A,
    (JsCallExpression, 'arguments')                 : _PAST_A_LINK,
    (JsCatchClause, 'param')                        : _A,
    (JsCatchClause, 'body')                         : _S,
    (JsClassBody, 'body')                           : _S,
    (JsClassDeclaration, 'id')                      : _A,
    (JsClassDeclaration, 'super_class')             : _A,
    (JsClassDeclaration, 'body')                    : _A,
    (JsClassDeclaration, 'decorators')              : _A,
    (JsClassExpression, 'id')                       : _A,
    (JsClassExpression, 'super_class')              : _A,
    (JsClassExpression, 'body')                     : _A,
    (JsClassExpression, 'decorators')               : _A,
    (JsConditionalExpression, 'test')               : _A,
    (JsConditionalExpression, 'consequent')         : _S,
    (JsConditionalExpression, 'alternate')          : _S,
    (JsContinueStatement, 'label')                  : _A,
    (JsDecorator, 'expression')                     : _A,
    (JsDoWhileStatement, 'test')                    : _A,
    (JsDoWhileStatement, 'body')                    : _S,
    (JsExportAllDeclaration, 'source')              : _A,
    (JsExportAllDeclaration, 'exported')            : _A,
    (JsExportAllDeclaration, 'attributes')          : _A,
    (JsExportDefaultDeclaration, 'declaration')     : _A,
    (JsExportNamedDeclaration, 'declaration')       : _A,
    (JsExportNamedDeclaration, 'specifiers')        : _A,
    (JsExportNamedDeclaration, 'source')            : _A,
    (JsExportNamedDeclaration, 'attributes')        : _A,
    (JsExportSpecifier, 'local')                    : _A,
    (JsExportSpecifier, 'exported')                 : _A,
    (JsExpressionStatement, 'expression')           : _A,
    (JsForInStatement, 'left')                      : _S,
    (JsForInStatement, 'right')                     : _A,
    (JsForInStatement, 'body')                      : _S,
    (JsForOfStatement, 'left')                      : _S,
    (JsForOfStatement, 'right')                     : _A,
    (JsForOfStatement, 'body')                      : _S,
    (JsForStatement, 'init')                        : _A,
    (JsForStatement, 'test')                        : _S,
    (JsForStatement, 'update')                      : _S,
    (JsForStatement, 'body')                        : _S,
    (JsFunctionDeclaration, 'id')                   : _A,
    (JsFunctionDeclaration, 'params')               : _L,
    (JsFunctionDeclaration, 'body')                 : _L,
    (JsFunctionExpression, 'id')                    : _A,
    (JsFunctionExpression, 'params')                : _L,
    (JsFunctionExpression, 'body')                  : _L,
    (JsIfStatement, 'test')                         : _A,
    (JsIfStatement, 'consequent')                   : _S,
    (JsIfStatement, 'alternate')                    : _S,
    (JsImportAttribute, 'key')                      : _A,
    (JsImportAttribute, 'value')                    : _A,
    (JsImportDeclaration, 'specifiers')             : _A,
    (JsImportDeclaration, 'source')                 : _A,
    (JsImportDeclaration, 'attributes')             : _A,
    (JsImportDefaultSpecifier, 'local')             : _A,
    (JsImportExpression, 'source')                  : _A,
    (JsImportExpression, 'options')                 : _A,
    (JsImportNamespaceSpecifier, 'local')           : _A,
    (JsImportSpecifier, 'imported')                 : _A,
    (JsImportSpecifier, 'local')                    : _A,
    (JsLabeledStatement, 'label')                   : _A,
    (JsLabeledStatement, 'body')                    : _S,
    (JsLogicalExpression, 'left')                   : _A,
    (JsLogicalExpression, 'right')                  : _S,
    (JsMemberExpression, 'object')                  : _A,
    (JsMemberExpression, 'property')                : _PAST_A_LINK,
    (JsMethodDefinition, 'key')                     : _A,
    (JsMethodDefinition, 'value')                   : _A,
    (JsMethodDefinition, 'decorators')              : _A,
    (JsNewExpression, 'callee')                     : _A,
    (JsNewExpression, 'arguments')                  : _A,
    (JsObjectExpression, 'properties')              : _A,
    (JsObjectPattern, 'properties')                 : _A,
    (JsParenthesizedExpression, 'expression')       : _A,
    (JsProperty, 'key')                             : _A,
    (JsProperty, 'value')                           : _A,
    (JsPropertyDefinition, 'key')                   : _A,
    (JsPropertyDefinition, 'value')                 : _Choice(_is_static, _A, _L),
    (JsPropertyDefinition, 'decorators')            : _A,
    (JsRestElement, 'argument')                     : _A,
    (JsReturnStatement, 'argument')                 : _A,
    (JsScript, 'body')                              : _S,
    (JsSequenceExpression, 'expressions')           : _A,
    (JsSpreadElement, 'argument')                   : _A,
    (JsStaticBlock, 'body')                         : _S,
    (JsSwitchCase, 'test')                          : _S,
    (JsSwitchCase, 'body')                          : _S,
    (JsSwitchStatement, 'discriminant')             : _A,
    (JsSwitchStatement, 'cases')                    : _S,
    (JsTaggedTemplateExpression, 'tag')             : _A,
    (JsTaggedTemplateExpression, 'quasi')           : _A,
    (JsTemplateLiteral, 'quasis')                   : _A,
    (JsTemplateLiteral, 'expressions')              : _A,
    (JsThrowStatement, 'argument')                  : _A,
    (JsTryStatement, 'block')                       : _S,
    (JsTryStatement, 'handler')                     : _S,
    (JsTryStatement, 'finalizer')                   : _S,
    (JsUnaryExpression, 'operand')                  : _A,
    (JsUpdateExpression, 'argument')                : _A,
    (JsVariableDeclaration, 'declarations')         : _A,
    (JsVariableDeclarator, 'id')                    : _A,
    (JsVariableDeclarator, 'init')                  : _A,
    (JsWhileStatement, 'test')                      : _A,
    (JsWhileStatement, 'body')                      : _S,
    (JsWithStatement, 'object')                     : _A,
    (JsWithStatement, 'body')                       : _S,
    (JsYieldExpression, 'argument')                 : _A,
}

_UNIFORM: dict[type[Node], Evaluation | None] = {}


def _uniform_evaluation(node_type: type[Node]) -> Evaluation | None:
    """
    The evaluation every child field of *node_type* has, where they all have the same one, so that
    a child's own field need not be searched for: a sequence of a thousand expressions would be
    searched once for every one of them.
    """
    try:
        return _UNIFORM[node_type]
    except KeyError:
        pass
    rules = {PART_EVALUATION.get((node_type, name), _S) for name in child_fields(node_type)}
    uniform = None
    if len(rules) == 1:
        rule = next(iter(rules))
        if isinstance(rule, Evaluation):
            uniform = rule
    _UNIFORM[node_type] = uniform
    return uniform


def _field_holding(holder: Node, part: Node) -> str | None:
    """
    The child field of *holder* that holds *part*. A part in no field of its own lies in a list,
    and where the holder has one list only, that list is the answer without a search through it: a
    call with a thousand arguments would be searched once for every one of them.
    """
    lists: list[str] = []
    for name in child_fields(type(holder)):
        value = getattr(holder, name)
        if value is part:
            return name
        if isinstance(value, list):
            lists.append(name)
    if len(lists) == 1:
        return lists[0]
    for name in lists:
        if any(item is part for item in getattr(holder, name)):
            return name
    return None


def evaluation_of(holder: Node, part: Node) -> Evaluation:
    """
    When *part*, a child of *holder*, is evaluated relative to *holder*, as `PART_EVALUATION` says;
    `Evaluation.SOMETIMES` for a part in a field the table does not list.
    """
    uniform = _uniform_evaluation(type(holder))
    if uniform is not None:
        return uniform
    name = _field_holding(holder, part)
    if name is None:
        return _S
    rule = PART_EVALUATION.get((type(holder), name), _S)
    return rule if isinstance(rule, Evaluation) else rule.of(holder)


def evaluated_whenever_completed(node: Node, element: Node) -> bool:
    """
    Whether *node* is evaluated on every run on which the statement or loop head *element* holding
    it completes: each part on the way down from *element* to *node* is evaluated whenever the part
    holding it is (`evaluation_of`).
    """
    cursor = node
    while cursor is not element:
        holder = cursor.parent
        if holder is None or evaluation_of(holder, cursor) is not Evaluation.ALWAYS:
            return False
        cursor = holder
    return True


def _may_be(rule: Evaluation | _Choice, evaluation: Evaluation) -> bool:
    """
    Whether a part *rule* governs is evaluated as *evaluation* for some holder.
    """
    if isinstance(rule, Evaluation):
        return rule is evaluation
    return evaluation in (rule.when, rule.otherwise)


#: The node types with a part that may be evaluated `Evaluation.LATER`: the holders of a run of
#: their own, a function and a field. `evaluated_later` consults the table for these types only.
_RUN_HOLDERS = frozenset(
    node_type for (node_type, _), rule in PART_EVALUATION.items() if _may_be(rule, _L)
)


def evaluated_later(holder: Node, part: Node) -> bool:
    """
    Whether *part*, a child of *holder*, is evaluated at a time of its own (`Evaluation.LATER`): the
    parameters and the body of a function when it is called, the initializer of a field each time
    an instance is constructed. The boundary of every run.
    """
    return type(holder) in _RUN_HOLDERS and evaluation_of(holder, part) is _L


def owns_a_run(node: Node | None) -> bool:
    """
    Whether some part of *node* is evaluated at a time of its own (`evaluated_later`): a function,
    or a field written without `static` that has an initializer. Such a node owns a run: a body
    that is executed apart from the code around it, and each time it is invoked.
    """
    return (
        node is not None
        and type(node) in _RUN_HOLDERS
        and any(evaluated_later(node, child) for child in node.children())
    )


def walk_run(owner: Node) -> Iterator[Node]:
    """
    The nodes one run of *owner* evaluates: the statements of a script, or the parts of a run
    owner that are evaluated later (`evaluated_later`), with their descendants down to the parts of
    a nested node that are evaluated at a time of their own. A nested run owner is yielded, as its
    creation is part of the run, and so are its parts evaluated with it: the computed key of a
    field, the name of a function.
    """
    if isinstance(owner, JsScript):
        stack: list[Node] = list(reversed(owner.body))
    else:
        stack = [child for child in reversed(owner.children()) if evaluated_later(owner, child)]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(
            child for child in reversed(node.children()) if not evaluated_later(node, child)
        )


def enclosing_run(node: Node) -> Node | None:
    """
    The run owner (`owns_a_run`) whose run evaluates *node*, or `None` for a node the script's own
    run evaluates.
    """
    cursor = node
    while (holder := cursor.parent) is not None:
        if evaluated_later(holder, cursor):
            return holder
        cursor = holder
    return None
