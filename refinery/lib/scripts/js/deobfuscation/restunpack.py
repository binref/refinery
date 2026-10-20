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

from refinery.lib.scripts import BodyEdit, Node, _replace_in_parent, set_child_list
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    SemanticModel,
    enclosing_operator,
    is_member_write_target,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    insert_after_prologue,
    is_receiver_binding_call,
    member_key,
    numeric_value,
    property_is_inherited,
    references_receiver_this,
)
from refinery.lib.scripts.js.deobfuscation.parameters import parameter_list
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
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
    strip_parens,
)
from refinery.lib.scripts.js.numbers import (
    canonical_array_index,
    exact_integer,
    js_number_to_string,
)

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
    model: SemanticModel,
    binding: Binding,
    length_access: JsMemberExpression,
    param_count: int,
) -> dict[str, list[JsMemberExpression]] | None:
    """
    Collect every access of the rest array from the references the model records for *binding*,
    those of the functions nested in the masked one included, as a map from string key to the member
    nodes. Returns None if the rest array is used in a way that prevents demasking: a reference that
    is no access of a fixed key, the operand of `delete`, or a key the prototype chain of an array
    supplies, such as `push` or `join`, which the array answers and no slot does.

    A slot called with the array as its receiver, as in `m[0]()`, hands the array to the function
    as `this`, and the unpacked call hands it nothing. Such a slot is unpacked only where it is no
    parameter, whose value the caller chooses, and every value stored into it is a function that
    reads no receiver.

    Only the one `.length` member that *length_access* names is skipped, because it is the one the
    rewrite removes. Any other mention of the rest array's length is an ordinary read of a binding
    the rewrite is about to delete, and answering it with a rewritten body would leave a reference
    to a name that no longer exists.
    """
    accesses: dict[str, list[JsMemberExpression]] = {}
    called: set[str] = set()
    for reference in model.references(binding):
        member = reference.parent
        if not isinstance(reference, JsIdentifier) or not isinstance(member, JsMemberExpression):
            return None
        if member.object is not reference:
            return None
        if member is length_access:
            continue
        operator = enclosing_operator(member)
        if isinstance(operator, JsUnaryExpression) and operator.operator == 'delete':
            return None
        key = _extract_access_key(member)
        if key is None:
            return None
        if canonical_array_index(key) is None and property_is_inherited(list, key):
            return None
        if is_receiver_binding_call(member):
            called.add(key)
        accesses.setdefault(key, []).append(member)
    for key in called:
        index = canonical_array_index(key)
        if index is not None and index < param_count:
            return None
        for member in accesses[key]:
            if is_member_write_target(member) and not _stores_a_function_reading_no_receiver(member):
                return None
    return accesses


def _stores_a_function_reading_no_receiver(member: JsMemberExpression) -> bool:
    """
    Whether the write to *member* is a plain assignment of a function that reads no receiver.
    """
    store = enclosing_operator(member)
    if not isinstance(store, JsAssignmentExpression) or store.operator != '=':
        return False
    if strip_parens(store.left) is not member:
        return False
    value = strip_parens(store.right)
    return isinstance(value, FUNCTION_NODES) and not references_receiver_this(value)


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


def _truncated_before_every_access(
    dominance: DominanceModel,
    length_access: JsMemberExpression,
    accesses: dict[str, list[JsMemberExpression]],
) -> bool:
    """
    Whether the truncation writing *length_access* has run before every access of *accesses*, those
    in nested functions included. Before the truncation, a slot past the truncated length still
    holds the argument passed at its index, and a value written to it is gone once the truncation
    runs; the fresh local the rewrite gives the slot holds neither. A nested function called before
    the truncation reads the array as early as a read written there.
    """
    return dominance.runs_before_all(
        length_access, (access for keyed in accesses.values() for access in keyed)
    )


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
    """
    The key *node* reads, or `None` where the key is computed at runtime or is `length`, which the
    array answers itself however the key is spelled.
    """
    prop = node.property
    if not node.computed:
        key = prop.name if isinstance(prop, JsIdentifier) else None
    elif isinstance(prop, JsNumericLiteral):
        key = _numeric_key(prop.value)
    elif isinstance(prop, JsStringLiteral):
        key = prop.value
    elif (
        isinstance(prop, JsUnaryExpression)
        and prop.operator == '-'
        and isinstance(prop.operand, JsNumericLiteral)
    ):
        key = _numeric_key(-prop.operand.value)
    else:
        key = None
    return None if key == 'length' else key


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
    for stmt in stmts:
        if not isinstance(stmt, JsExpressionStatement):
            continue
        expr = stmt.expression
        if isinstance(expr, JsAssignmentExpression) and expr.left is length_access:
            edit = BodyEdit(body, 'body')
            edit.splice(stmt, [])
            edit.apply()
            return


class JsRestArrayUnpacking(ScriptLevelTransformer):
    """
    Unpack rest-param arrays back into named identifiers. Detects functions where all parameters
    and locals are packed into a single rest parameter accessed by index, and replaces indexed
    accesses with fresh named variables.
    """

    def _process_script(self, node: JsScript) -> None:
        count = 0
        cache = model_cache(self, node)
        model = cache.model
        dominance = cache.dominance
        for fn_node in node.walk():
            if not isinstance(fn_node, (JsFunctionExpression, JsFunctionDeclaration)):
                continue
            if self._demask_function(fn_node, model, dominance):
                count += 1
        if count > 0:
            self.mark_changed()

    def _demask_function(
        self,
        fn: JsFunctionExpression | JsFunctionDeclaration,
        model: SemanticModel,
        dominance: DominanceModel,
    ) -> bool:
        if len(fn.params) != 1:
            return False
        param = fn.params[0]
        if not isinstance(param, JsRestElement):
            return False
        if not isinstance(param.argument, JsIdentifier):
            return False
        binding = model.binding_of(param.argument)
        if (
            binding is None
            or any(site is not param.argument and site is not fn.id for site in binding.declarations)
            or binding.dynamic_refs
            or model.reflection_can_reach(binding)
        ):
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
            stack = length_access.object
            if not isinstance(stack, JsIdentifier) or model.resolve(stack) is not binding:
                return False
            accesses = _collect_accesses_simple(model, binding, length_access, param_count)
        elif binding.captured:
            return False
        else:
            accesses = _collect_accesses_frame(fn.body, stack_chain)
        if accesses is None or not _truncated_before_every_access(dominance, length_access, accesses):
            return False
        if param_count > 0 and not any(str(i) in accesses for i in range(param_count)):
            return False
        if not accesses:
            _remove_truncation(fn.body, length_access)
            set_child_list(fn, 'params', [])
            return True
        taken = _mentioned_names(fn.body)
        names = _generate_names(param_count, set(accesses.keys()), taken)
        parameters = parameter_list([JsIdentifier(name=name) for name in names.params], fn, None)
        if parameters is None:
            return False
        for key, nodes in accesses.items():
            name = names.of_key[key]
            for access_node in nodes:
                replacement = JsIdentifier(name=name)
                _replace_in_parent(access_node, replacement)
        _remove_truncation(fn.body, length_access)
        set_child_list(fn, 'params', parameters.build())
        if stack_chain is None:
            self._add_local_declarations(fn.body, names.local_names)
        return True

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
