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
"""
from __future__ import annotations

import enum

from typing import Callable

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
    'evaluated_whenever_completed',
    'evaluated_with',
    'evaluation_of',
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


def _past_a_link(holder: Node) -> Evaluation:
    """
    The evaluation of the key of a member or the arguments of a call: on some runs only where the
    link or one below it is optional.
    """
    if _optional_link_below(holder):
        return Evaluation.SOMETIMES
    return Evaluation.ALWAYS


def _assigned_value(holder: Node) -> Evaluation:
    """
    The evaluation of the value of an assignment: on some runs only where the operator is a logical
    one, which assigns only when the target's value asks for it.
    """
    if (
        isinstance(holder, JsAssignmentExpression)
        and holder.operator in LOGICAL_ASSIGNMENT_OPERATORS
    ):
        return Evaluation.SOMETIMES
    return Evaluation.ALWAYS


_A = Evaluation.ALWAYS
_S = Evaluation.SOMETIMES
_L = Evaluation.LATER

#: For each node type and child field, when the child is evaluated relative to the node: one of
#: `Evaluation`, or a function deciding it from the node where its operator or its links decide it.
PART_EVALUATION: dict[tuple[type[Node], str], Evaluation | Callable[[Node], Evaluation]] = {
    (JsArrayExpression, 'elements')                 : _A,
    (JsArrayPattern, 'elements')                    : _A,
    (JsArrowFunctionExpression, 'params')           : _L,
    (JsArrowFunctionExpression, 'body')             : _L,
    (JsAssignmentExpression, 'left')                : _A,
    (JsAssignmentExpression, 'right')               : _assigned_value,
    (JsAssignmentPattern, 'left')                   : _A,
    (JsAssignmentPattern, 'right')                  : _S,
    (JsAwaitExpression, 'argument')                 : _A,
    (JsBinaryExpression, 'left')                    : _A,
    (JsBinaryExpression, 'right')                   : _A,
    (JsBlockStatement, 'body')                      : _S,
    (JsBreakStatement, 'label')                     : _A,
    (JsCallExpression, 'callee')                    : _A,
    (JsCallExpression, 'arguments')                 : _past_a_link,
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
    (JsMemberExpression, 'property')                : _past_a_link,
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
    (JsPropertyDefinition, 'value')                 : _L,
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
    return rule if isinstance(rule, Evaluation) else rule(holder)


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


def evaluated_with(node: Node, element: Node) -> bool:
    """
    Whether *node*, on the runs that evaluate it at all, is evaluated while the statement or loop
    head *element* holding it is: no part on the way down from *element* to *node* is evaluated at
    a time of its own (`Evaluation.LATER`), as the initializer of a field is when an instance is
    constructed.
    """
    cursor = node
    while cursor is not element:
        holder = cursor.parent
        if holder is None or evaluation_of(holder, cursor) is Evaluation.LATER:
            return False
        cursor = holder
    return True
