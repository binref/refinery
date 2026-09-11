"""
Unpack rest-parameter arrays that pack multiple variables into a single parameter.

Some obfuscation transforms replace named function parameters and locals with indexed accesses
on a single rest parameter array:

    function(...stack) { stack.length = N; ... }

This transformer detects the pattern, builds a variable map from collected access keys, and
replaces indexed accesses with fresh named identifiers.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Node, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.model import SemanticModel, references_own_arguments
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    insert_after_prologue,
    member_key,
    numeric_value,
)
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsBlockStatement,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNumericLiteral,
    JsRestElement,
    JsScript,
    JsStringLiteral,
    JsUnaryExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
)
from refinery.lib.scripts.js.numbers import (
    canonical_array_index,
    exact_integer,
    js_number_to_string,
)
from refinery.lib.scripts.js.strict import strict_mode_at

_MAX_PARAMETERS = 65535
"""
The largest truncation length this pass will rewrite into a formal parameter list. A larger one does
not describe the pattern, and taking it at face value would spend the rest of the run minting names
for parameters no engine would accept.

The number is not itself an engine limit and should not be read as one: V8 refuses a function of
more than 65525 formal parameters, so a length between that and this bound is still rewritten into a
program the engine will not load. Nor is every larger length a runtime error to begin with — a
non-uint32 length such as `1e300` throws `RangeError`, but any uint32 up to 4294967295 does not.
"""


class _TruncationInfo(NamedTuple):
    param_count: int
    stack_chain: str | None
    length_access: JsMemberExpression


class _NestedFrameAccess(Exception):
    pass


def _extract_truncation(
    stmts: list,
    rest_name: str,
) -> _TruncationInfo | None:
    """
    Find the `.length = N` truncation statement in the function body. Returns the param count
    and the stack chain key (None for simple case where rest param IS the stack). Returns None
    if no truncation pattern is found.

    The object decides which statement is the truncation, and the length is read afterwards: the
    first write to the length of the rest array or of a resolvable chain is the one this rewrite is
    about, and a length it cannot read as a parameter count means the rewrite cannot be done.
    Reading the length first and moving on when it does not answer would let a later, unrelated
    `.length =` stand in for the real one, and the parameter list would then be built from a count
    belonging to something else.
    """
    for stmt in stmts:
        if not isinstance(stmt, JsExpressionStatement):
            continue
        expr = stmt.expression
        if not isinstance(expr, JsAssignmentExpression) or expr.operator != '=':
            continue
        lhs = expr.left
        if not isinstance(lhs, JsMemberExpression):
            continue
        if lhs.computed:
            continue
        if not isinstance(lhs.property, JsIdentifier) or lhs.property.name != 'length':
            continue
        obj = lhs.object
        if isinstance(obj, JsIdentifier) and obj.name == rest_name:
            chain = None
        elif isinstance(obj, JsMemberExpression):
            chain = member_key(obj)
            if chain is None:
                continue
        else:
            continue
        rhs = expr.right
        n = None if rhs is None else numeric_value(rhs)
        length = None if n is None else exact_integer(n)
        if length is None or not (0 <= length <= _MAX_PARAMETERS):
            return None
        return _TruncationInfo(length, chain, lhs)
    return None


def _collect_accesses_simple(
    body: JsBlockStatement,
    rest_name: str,
    length_access: JsMemberExpression,
) -> dict[str, list[JsMemberExpression]] | None:
    """
    Collect all `restParam[key]` and `restParam.key` accesses in the immediate function body
    (not descending into nested functions). Returns a map from string key to list of AST nodes.
    Returns None if the rest param is used in a way that prevents demasking.

    Only the one `.length` member that *length_access* names is skipped, because it is the one the
    rewrite removes. Any other mention of the rest array's length is an ordinary read of a binding
    the rewrite is about to delete, and answering it with a rewritten body would leave a reference
    to a name that no longer exists.
    """
    accesses: dict[str, list[JsMemberExpression]] = {}
    if not _walk_collect_simple(body, rest_name, accesses, length_access):
        return None
    return accesses


def _walk_collect_simple(
    node: Node,
    rest_name: str,
    accesses: dict[str, list[JsMemberExpression]],
    length_access: JsMemberExpression,
) -> bool:
    for child in node.children():
        if isinstance(child, (JsFunctionExpression, JsFunctionDeclaration)):
            continue
        if isinstance(child, JsMemberExpression):
            obj = child.object
            if isinstance(obj, JsIdentifier) and obj.name == rest_name:
                if child is length_access:
                    continue
                key = _extract_access_key(child)
                if key is None:
                    return False
                accesses.setdefault(key, []).append(child)
                continue
        if isinstance(child, JsIdentifier) and child.name == rest_name:
            parent = child.parent
            if isinstance(parent, JsMemberExpression) and parent.object is child:
                continue
            return False
        if not _walk_collect_simple(child, rest_name, accesses, length_access):
            return False
    return True


def _collect_accesses_frame(
    body: JsBlockStatement,
    stack_chain: str,
) -> dict[str, list[JsMemberExpression]] | None:
    """
    Collect all accesses to the frame-qualified stack chain. Returns None if any access exists
    inside a nested function (closure capture prevents demasking).
    """
    accesses: dict[str, list[JsMemberExpression]] = {}
    try:
        _walk_collect_frame(body, stack_chain, accesses, depth=0)
    except _NestedFrameAccess:
        return None
    return accesses


def _walk_collect_frame(
    node: Node,
    stack_chain: str,
    accesses: dict[str, list[JsMemberExpression]],
    depth: int,
) -> None:
    for child in node.children():
        if isinstance(child, (JsFunctionExpression, JsFunctionDeclaration)):
            _walk_collect_frame(child, stack_chain, accesses, depth + 1)
            continue
        if isinstance(child, JsMemberExpression):
            obj = child.object
            if isinstance(obj, JsMemberExpression):
                chain = member_key(obj)
                if chain == stack_chain:
                    key = _extract_access_key(child)
                    if key is not None:
                        if depth > 0:
                            raise _NestedFrameAccess
                        accesses.setdefault(key, []).append(child)
                        continue
        _walk_collect_frame(child, stack_chain, accesses, depth)


def _numeric_key(value: float) -> str | None:
    """
    The property name a Number indexes, or `None` when it names no slot this pass rewrites. The
    spelling is `Number.prototype.toString` and not `str` of a Python integer, because the two part
    ways exactly where a double stops determining its own digits: `s[2 ** 60]` reads the property
    `'1152921504606847000'`, which is not what the exact value spells.
    """
    if exact_integer(value) is None:
        return None
    return js_number_to_string(value)


def _extract_access_key(node: JsMemberExpression) -> str | None:
    if node.computed:
        prop = node.property
        if isinstance(prop, JsNumericLiteral):
            return _numeric_key(prop.value)
        if isinstance(prop, JsStringLiteral):
            return prop.value
        if (
            isinstance(prop, JsUnaryExpression)
            and prop.operator == '-'
            and isinstance(prop.operand, JsNumericLiteral)
        ):
            return _numeric_key(-prop.operand.value)
        return None
    if isinstance(node.property, JsIdentifier):
        if node.property.name == 'length':
            return None
        return node.property.name
    return None


def _mentioned_names(node: Node) -> set[str]:
    """
    Every identifier name the subtree mentions. A name this pass introduces has to avoid all of them
    and not only the declared ones: one that matches a local the body declares shadows it, and one
    that matches a name the body reads from an enclosing scope captures it.
    """
    return {child.name for child in node.walk() if isinstance(child, JsIdentifier)}


class _StackNames(NamedTuple):
    """
    The identifier every stack key is rewritten to, together with the parameter list the function is
    given and the locals it has to declare. The three are answered at once because they are one
    classification, and a rewrite that re-derives it reaches a different verdict in each place it
    asks.
    """
    of_key: dict[str, str]
    params: list[str]
    local_names: list[str]


def _generate_names(
    param_count: int,
    keys: set[str],
    taken: set[str],
) -> _StackNames:
    """
    Fresh identifier names for the stack keys, together with the whole parameter list they are drawn
    from. A key naming an index below *param_count* is that parameter and takes its name from its
    position, so that two keys can never land on one name; every other key names a local.

    Naming an index is what `canonical_array_index` decides and not what `str.isdigit` accepts: an
    array is indexed only by the canonical decimal spelling of its index, so `'01'`, `'٢'` and `'²'`
    are ordinary property names that read `undefined`. Handing any of them the parameter it resembles
    both collapses two properties onto one binding and mints one parameter name twice.
    """
    used = set(taken)
    params: list[str] = []
    candidate = 0
    while len(params) < param_count:
        name = F'p{candidate}'
        candidate += 1
        if name not in used:
            used.add(name)
            params.append(name)
    of_key: dict[str, str] = {}
    local_names: list[str] = []
    candidate = 0
    for key in sorted(keys, key=_sort_key):
        index = canonical_array_index(key)
        if index is not None and index < param_count:
            of_key[key] = params[index]
            continue
        while True:
            name = F'v{candidate}'
            candidate += 1
            if name not in used:
                break
        used.add(name)
        of_key[key] = name
        local_names.append(name)
    return _StackNames(of_key, params, local_names)


def _sort_key(key: str) -> tuple[int, int | str]:
    index = canonical_array_index(key)
    return (1, key) if index is None else (0, index)


def _remove_truncation(body: JsBlockStatement, length_access: JsMemberExpression) -> None:
    """
    Remove the truncation statement from the function body. It is found by the member node the match
    recorded rather than by re-running the match: a body may hold more than one `.length =` and only
    the one that was read as the parameter count may be dropped.
    """
    stmts = body.body
    for i, stmt in enumerate(stmts):
        if not isinstance(stmt, JsExpressionStatement):
            continue
        expr = stmt.expression
        if isinstance(expr, JsAssignmentExpression) and expr.left is length_access:
            stmts.pop(i)
            return


class JsRestArrayUnpacking(ScriptLevelTransformer):
    """
    Unpack rest-param arrays back into named identifiers. Detects functions where all parameters
    and locals are packed into a single rest parameter accessed by index, and replaces indexed
    accesses with fresh named variables.
    """

    def _process_script(self, node: JsScript) -> None:
        count = 0
        model = model_cache(self, node).model
        for fn_node in node.walk():
            if not isinstance(fn_node, (JsFunctionExpression, JsFunctionDeclaration)):
                continue
            if self._demask_function(fn_node, model):
                count += 1
        if count > 0:
            self.mark_changed()

    def _demask_function(
        self,
        fn: JsFunctionExpression | JsFunctionDeclaration,
        model: SemanticModel,
    ) -> bool:
        if len(fn.params) != 1:
            return False
        param = fn.params[0]
        if not isinstance(param, JsRestElement):
            return False
        if not isinstance(param.argument, JsIdentifier):
            return False
        binding = model.binding_of(param.argument)
        if binding is None or binding.captured or model.reflection_can_reach(binding):
            return False
        rest_name = param.argument.name
        if fn.body is None or not isinstance(fn.body, JsBlockStatement):
            return False
        if not fn.body.body:
            return False
        result = _extract_truncation(fn.body.body, rest_name)
        if result is None:
            return False
        param_count, stack_chain, length_access = result
        if stack_chain is None:
            accesses = _collect_accesses_simple(fn.body, rest_name, length_access)
        else:
            accesses = _collect_accesses_frame(fn.body, stack_chain)
        if accesses is None:
            return False
        if param_count > 0 and not any(str(i) in accesses for i in range(param_count)):
            return False
        if not accesses:
            _remove_truncation(fn.body, length_access)
            fn.params.clear()
            return True
        taken = _mentioned_names(fn.body)
        names = _generate_names(param_count, set(accesses.keys()), taken)
        if names.params and self._would_map_arguments(fn):
            return False
        for key, nodes in accesses.items():
            name = names.of_key[key]
            for access_node in nodes:
                replacement = JsIdentifier(name=name)
                _replace_in_parent(access_node, replacement)
        _remove_truncation(fn.body, length_access)
        fn.params.clear()
        for name in names.params:
            fn.params.append(JsIdentifier(name=name))
        if stack_chain is None:
            self._add_local_declarations(fn.body, names.local_names)
        return True

    @staticmethod
    def _would_map_arguments(fn: JsFunctionExpression | JsFunctionDeclaration) -> bool:
        """
        Whether unpacking *fn* would give it an `arguments` object aliasing the parameters it does not
        have yet. A rest parameter is not a simple list, so the object *fn* has now is an independent
        copy; the plain identifiers this pass puts in its place make the list simple, and a sloppy body
        then reads and writes its parameters through that object as well as by name. A write the pass
        leaves standing therefore means something afterwards that it did not mean before.

        The question is about the function this pass would produce, and it is asked before that function
        exists, because `_demask_function` rewrites in place with nothing to roll back to. It is
        answerable early: the mode and whether the body reads its own `arguments` are both untouched by
        the rewrite, and the result's parameter list is simple by construction, so the only part left to
        the caller is whether the result keeps a parameter at all.
        """
        return not strict_mode_at(fn) and references_own_arguments(fn)

    def _add_local_declarations(
        self,
        body: JsBlockStatement,
        locals_: list[str],
    ) -> None:
        """
        Insert `var` declarations for the locals the rewrite minted, behind the body's Directive
        Prologue rather than ahead of it: a declaration written above a `'use strict'` ends the
        prologue before it is reached and the unpacked function runs sloppy where the source wrote it
        strict.
        """
        if not locals_:
            return
        declarators = [
            JsVariableDeclarator(id=JsIdentifier(name=n), init=None)
            for n in locals_
        ]
        decl = JsVariableDeclaration(declarations=declarators, kind=JsVarKind.VAR)
        for d in declarators:
            d.parent = decl
            if d.id is not None:
                d.id.parent = d
        insert_after_prologue(body, [decl])
