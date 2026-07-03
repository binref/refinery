"""
A lexical semantic model for JavaScript: a tree of scopes with resolved bindings and def/use sets,
computed once over an AST and then queried by deobfuscation transforms instead of each transform
re-deriving scope, binding, and liveness facts on its own.

This is the foundation layer of the analysis substrate. Its public surface is intentionally
representation-agnostic: callers receive `Scope` and `Binding` objects and ask questions about AST
nodes by identity, never about how the facts were computed. Later layers (control-flow graphs, effect
summaries) attach behind the same surface without changing it.

The model is *flow-insensitive*. It answers lexical questions — which declaration a name resolves to,
what a scope binds, where a binding is read or written, whether it is captured by a closure — but not
control-flow questions such as which definition reaches a use. A read that only ever consumes a value
that is never observed (a dead store) is still counted as a read; distinguishing those needs a
control-flow graph and is left to a later layer.

Where JavaScript scoping is genuinely ambiguous the model is deliberately conservative, resolving a
name to a *wider* binding rather than risk treating a live reference as free: a function declaration
nested in a block is hoisted to the enclosing function scope (legacy/Annex-B semantics), and a name
used inside a `with` body or any dynamically-scoped region resolves to `None` (unknown) rather than to
a guessed binding. `has_reflection_surface` likewise errs toward reporting reflection.

A name the program assigns without ever declaring it (an implicit global) is given a synthetic binding
at script scope so that its whole-program liveness can be reasoned about; a name that is only ever
*read* without being assigned stays free (`None`), since it denotes an external or built-in global the
model cannot describe. Writes inside a `with` body do not create such a binding, because the name may
denote a property of the `with` object rather than a global.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass, field
from typing import Iterator

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsBlockStatement,
    JsBreakStatement,
    JsCallExpression,
    JsCatchClause,
    JsClassDeclaration,
    JsClassExpression,
    JsContinueStatement,
    JsExportSpecifier,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsImportDeclaration,
    JsImportDefaultSpecifier,
    JsImportNamespaceSpecifier,
    JsImportSpecifier,
    JsLabeledStatement,
    JsMemberExpression,
    JsObjectExpression,
    JsObjectPattern,
    JsParenthesizedExpression,
    JsProperty,
    JsRestElement,
    JsScript,
    JsSpreadElement,
    JsStringLiteral,
    JsSwitchStatement,
    JsTaggedTemplateExpression,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsWithStatement,
)

FUNCTION_NODES = (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression)

_FunctionNode = JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression

GLOBAL_OBJECT_ALIASES = frozenset({'globalThis', 'global', 'window', 'self', 'top', 'frames'})

TIMER_NAMES = frozenset({'setTimeout', 'setInterval', 'setImmediate', 'execScript'})

REFLECTIVE_INTRINSICS = frozenset({'eval', 'Function'})

_PATTERN_CONTAINERS = (
    JsArrayExpression,
    JsArrayPattern,
    JsObjectExpression,
    JsObjectPattern,
    JsRestElement,
    JsSpreadElement,
)


class ScopeKind(enum.Enum):
    SCRIPT   = 'script'    # noqa
    FUNCTION = 'function'  # noqa
    BLOCK    = 'block'     # noqa
    CATCH    = 'catch'     # noqa
    CLASS    = 'class'     # noqa
    WITH     = 'with'      # noqa


class BindingKind(enum.Enum):
    VAR             = 'var'              # noqa
    LET             = 'let'              # noqa
    CONST           = 'const'            # noqa
    PARAM           = 'param'            # noqa
    FUNCTION        = 'function'         # noqa
    CLASS           = 'class'            # noqa
    CATCH           = 'catch'            # noqa
    IMPORT          = 'import'           # noqa
    ARGUMENTS       = 'arguments'        # noqa
    FUNC_NAME       = 'func_name'        # noqa  the own name of a named function expression
    IMPLICIT_GLOBAL = 'implicit_global'  # noqa  a name assigned but never declared


class Role(enum.Enum):
    READ      = 'read'        # noqa
    WRITE     = 'write'       # noqa
    READWRITE = 'readwrite'   # noqa


class ContainerRole(enum.Enum):
    """
    How a reference touches the container value (object or array) its binding holds — a finer
    distinction than `Role`, which describes how a reference touches the *binding* itself. `obj.k = v`
    reads the binding `obj` (so `reference_role` reports `READ`) yet writes the container it holds, so
    here it is a `MEMBER_WRITE`.
    """
    MEMBER_READ  = 'member_read'   # noqa  read through the container: `obj.k`, `obj[i]`
    MEMBER_WRITE = 'member_write'  # noqa  write through it: `obj.k = v`, `obj[i]++`, `delete obj[i]`
    MEMBER_CALL  = 'member_call'   # noqa  method invoked on it: `obj.m(...)`, which may mutate it
    REBIND       = 'rebind'        # noqa  plain reassignment of the name: `obj = ...`
    ESCAPE       = 'escape'        # noqa  any other use, through which the container could be aliased


@dataclass(eq=False)
class Binding:
    """
    A single declared name within one scope. `declarations` holds the binding-site identifier nodes
    that introduce the name; `reads` and `writes` hold the referencing identifiers that read and write
    it (a compound assignment or update appears in both). `captured` is set when the name is referenced
    from a function nested below the one that owns it. A write performed through a member access on a
    global-object alias (`globalThis.g = ...`) has no referencing identifier for the global it targets,
    so the `JsMemberExpression` stands in for that write site; every other `writes` entry is an
    identifier. `dynamic_refs` holds referencing identifiers a dynamic scope resolves at runtime — a name
    inside a `with` body that could denote this binding — which `reads`/`writes` omit because such a name
    resolves to no binding statically; its target is uncertain, so it is kept apart from the definite
    references.
    """
    name: str
    kind: BindingKind
    scope: Scope
    declarations: list[JsIdentifier] = field(default_factory=list)
    reads: list[JsIdentifier] = field(default_factory=list)
    writes: list[JsIdentifier | JsMemberExpression] = field(default_factory=list)
    dynamic_refs: list[JsIdentifier] = field(default_factory=list)
    captured: bool = False

    @property
    def is_read(self) -> bool:
        """
        Whether the binding's value is ever read.
        """
        return bool(self.reads)

    @property
    def is_dead(self) -> bool:
        """
        Whether the binding is never read. Definitions of a dead binding can be removed if they carry
        no other side effect (which the caller decides).
        """
        return not self.reads

    @property
    def has_global_member_write(self) -> bool:
        """
        Whether the binding is written through a member access on a global-object alias
        (`globalThis.x = ...`), recorded as a `JsMemberExpression` write site rather than a referencing
        identifier (see the class docstring). Only a global ever carries such a write, so the answer is
        always false for a lexical binding whose writes are all identifiers.
        """
        return any(isinstance(write, JsMemberExpression) for write in self.writes)


@dataclass(eq=False)
class Scope:
    """
    A lexical scope. `node` is the AST node that introduces it (the script, a function, a block, a
    catch clause, a class, or a `with`). `is_dynamic` marks a region whose bindings cannot be resolved
    statically because names may be injected at runtime (`with`, direct `eval`).
    """
    kind: ScopeKind
    node: Node
    parent: Scope | None = None
    children: list[Scope] = field(default_factory=list)
    bindings: dict[str, Binding] = field(default_factory=dict)
    is_dynamic: bool = False

    @property
    def is_var_scope(self) -> bool:
        """
        Whether this scope is the target of `var`/function-declaration hoisting: a function body or
        the script itself.
        """
        return self.kind is ScopeKind.FUNCTION or self.kind is ScopeKind.SCRIPT

    @property
    def var_scope(self) -> Scope | None:
        """
        The function or script scope that governs `var`/function-declaration hoisting for this scope:
        this scope itself when it is already a var-scope, otherwise the nearest enclosing one (the
        boundary a closure crosses).
        """
        scope: Scope | None = self
        while scope is not None and not scope.is_var_scope:
            scope = scope.parent
        return scope

    def contains(self, other: Scope, *, strict: bool = False) -> bool:
        """
        Whether this scope lexically contains *other*: *other* itself or any scope nested below it.
        With *strict*, the reflexive case is excluded, so only a scope nested strictly below this one
        qualifies — the shape of the shadowing test in `SemanticModel.is_shadowed`.
        """
        cursor: Scope | None = other.parent if strict else other
        while cursor is not None:
            if cursor is self:
                return True
            cursor = cursor.parent
        return False


def is_use_position(node: JsIdentifier) -> bool:
    """
    Whether an identifier occupies a position where it reads or writes a value, as opposed to naming a
    property, an object-literal key, a label, or an import/export specifier. Binding sites are not
    excluded here; `SemanticModel.is_reference` is the binding-aware predicate that also excludes them.
    """
    p = node.parent
    if p is None:
        return False
    if isinstance(p, JsMemberExpression) and p.property is node and not p.computed:
        return False
    if isinstance(p, JsProperty) and p.key is node and not p.computed and not p.shorthand:
        return False
    if isinstance(p, (JsBreakStatement, JsContinueStatement, JsLabeledStatement)) and p.label is node:
        return False
    if isinstance(p, (
        JsImportSpecifier,
        JsImportDefaultSpecifier,
        JsImportNamespaceSpecifier,
        JsExportSpecifier,
    )):
        return False
    return True


def pattern_identifiers(target: Node | None) -> Iterator[JsIdentifier]:
    """
    Yield every binding-site identifier introduced by a declaration target, descending through
    destructuring patterns (`[a, {b: c}]`, `{x, ...rest}`), default patterns, and rest elements. A
    member-expression target (`[a.b] = ...`) introduces no binding and yields nothing.
    """
    if target is None:
        return
    if isinstance(target, JsIdentifier):
        yield target
    elif isinstance(target, JsArrayPattern):
        for element in target.elements:
            yield from pattern_identifiers(element)
    elif isinstance(target, JsObjectPattern):
        for prop in target.properties:
            if isinstance(prop, JsRestElement):
                yield from pattern_identifiers(prop.argument)
            elif isinstance(prop, JsProperty):
                yield from pattern_identifiers(prop.value)
    elif isinstance(target, JsAssignmentPattern):
        yield from pattern_identifiers(target.left)
    elif isinstance(target, JsRestElement):
        yield from pattern_identifiers(target.argument)


def reference_role(node: JsIdentifier) -> Role:
    """
    Classify how a referencing identifier touches its binding: a plain read, a write-only target (the
    left of a simple `=`, including inside a destructuring pattern or a destructuring default, or a
    `for-in`/`for-of` head), or a read-and-write (compound assignment, `++`/`--`, or a `delete`, each
    of which keeps the name live as a read rather than overwriting it outright). The shared
    `_governing_target` climb looks through destructuring containers, default patterns, and
    parentheses, so a target nested in a pattern or a grouping (`[x = 9] = xs`, `(x)++`, `(o) = v`) is
    still recognized as a write.
    """
    governor, target = _governing_target(node)
    if isinstance(governor, JsAssignmentExpression) and _strip_parens(governor.left) is target:
        return Role.WRITE if governor.operator == '=' else Role.READWRITE
    if isinstance(governor, JsUpdateExpression) and _strip_parens(governor.argument) is target:
        return Role.READWRITE
    if (
        isinstance(governor, JsUnaryExpression)
        and governor.operator == 'delete'
        and _strip_parens(governor.operand) is target
    ):
        return Role.READWRITE
    if isinstance(governor, (JsForInStatement, JsForOfStatement)) and _strip_parens(governor.left) is target:
        return Role.WRITE
    return Role.READ


def _strip_parens(node: Node | None) -> Node | None:
    """
    The expression *node* denotes once any enclosing parentheses are removed, so that a parenthesized
    operand is classified by the operator that actually applies to it rather than by the redundant
    grouping the parser preserves.
    """
    while isinstance(node, JsParenthesizedExpression):
        node = node.expression
    return node


def _enclosing_operator(node: Node) -> Node | None:
    """
    The nearest ancestor of *node* that is not merely a parenthesization of it — the construct whose
    operator actually governs *node*.
    """
    parent = node.parent
    while isinstance(parent, JsParenthesizedExpression):
        parent = parent.parent
    return parent


def _governing_target(node: Node) -> tuple[Node | None, Node]:
    """
    Climb outward from *node* through the destructuring containers and parentheses that keep it in
    an assignment or binding target position — array and object patterns (and the literal-shaped
    forms a destructuring assignment or `for-in`/`for-of` target is parsed as), their rest and
    spread elements, the value side of a pattern property, and the target side of a default pattern
    (`[a = d] = ...`, climbing the `a` side only, never into the default `d`) — then return the
    first ancestor that does not continue the target, together with the operand it sees: the
    outermost container the climb carried *node* up to. An object shorthand-default
    (`({a = d} = ...)`) is one such default: the parser reuses its key node as that default's
    target, so the climb follows the shared key as the write it also is instead of stopping at it as
    a bare property key. That ancestor is the construct whose operator governs the target; when
    *node* really sits in a target it is an assignment, update, `delete`, `for-in`/`for-of` head, or
    declarator, but it is some other node (a call, an operand) when *node* is not a target, and
    `None` past the top of the tree — so a caller decides a write by asking whether the returned
    operand is the governor's write side, never from the governor's type alone. Centralizing the
    climb keeps the pattern-and-parenthesis handling identical for every def-use, write-target, and
    liveness query, so a case one copy forgot — such as the array-default `JsAssignmentPattern`
    target or a `for-of` rest element — cannot be missed by one and not another.
    """
    cursor: Node = node
    parent = _enclosing_operator(cursor)
    while parent is not None:
        if isinstance(parent, JsProperty):
            value = _strip_parens(parent.value)
            if value is not cursor and not (
                parent.shorthand
                and isinstance(value, JsAssignmentPattern)
                and _strip_parens(value.left) is cursor
            ):
                break
        elif isinstance(parent, JsAssignmentPattern):
            if _strip_parens(parent.left) is not cursor:
                break
        elif not isinstance(parent, _PATTERN_CONTAINERS):
            break
        cursor = parent
        parent = _enclosing_operator(cursor)
    return parent, cursor


def container_reference_role(node: JsIdentifier | JsMemberExpression) -> ContainerRole:
    """
    Classify how the reference *node* touches the container value (object or array) its binding holds.
    A member access based on *node* is a `MEMBER_READ` unless the outermost member of the chain it
    begins is being written — the left of an assignment, the operand of `++`/`--` or `delete`, or a
    target of a `for-in`/`for-of` head or a destructuring pattern — which makes it a `MEMBER_WRITE` (a
    write through `a.b.c = v` mutates the object `a` holds), or is invoked as a method (`a.m(...)`, also
    as a template tag `` a.m`...` ``), which makes it a `MEMBER_CALL` since the call may mutate the
    receiver. A plain `node = ...` reassignment is a `REBIND`; anything else — passed as an argument,
    aliased to another binding, returned, used as an operand or a computed key — is an `ESCAPE`, through
    which an alias could mutate the container. Parentheses are looked through throughout, so a grouped
    write or call (`(a.b) = v`, `(a.sort)()`) is classified by the operator that applies, not as a bare
    read. This is the per-reference primitive the EffectModel composes over a binding's whole reference
    set (with alias-following and callee summaries) to decide container immutability.
    """
    parent = _enclosing_operator(node)
    if isinstance(parent, JsMemberExpression) and _strip_parens(parent.object) is node:
        member: Node = parent
        while True:
            outer = _enclosing_operator(member)
            if isinstance(outer, JsMemberExpression) and _strip_parens(outer.object) is member:
                member = outer
                continue
            break
        if _is_invocation_of(_enclosing_operator(member), member):
            return ContainerRole.MEMBER_CALL
        return ContainerRole.MEMBER_WRITE if is_member_write_target(member) else ContainerRole.MEMBER_READ
    if isinstance(parent, JsAssignmentExpression) and _strip_parens(parent.left) is node and parent.operator == '=':
        return ContainerRole.REBIND
    return ContainerRole.ESCAPE


def _is_invocation_of(node: Node | None, callee: Node) -> bool:
    """
    Whether *node* invokes *callee* — a call `callee(...)` or a tagged template `` callee`...` `` —
    looking through parentheses around the callee.
    """
    if isinstance(node, JsCallExpression):
        return _strip_parens(node.callee) is callee
    if isinstance(node, JsTaggedTemplateExpression):
        return _strip_parens(node.tag) is callee
    return False


def is_member_write_target(member: Node) -> bool:
    """
    Whether the outermost *member* of a container's access chain is being written rather than read: the
    left of an assignment, the operand of `++`/`--` or `delete`, or a target of a `for-in`/`for-of` head
    or a destructuring pattern (including a destructuring default, `[a.b = d] = ...`). The shared
    `_governing_target` climb looks through destructuring containers and parentheses (`(a.b) = v`), so a
    member nested in a pattern or a grouping is still recognized as a write, mirroring `reference_role`
    and the binding-target climb in the liveness model.
    """
    governor, target = _governing_target(member)
    if isinstance(governor, JsAssignmentExpression):
        return _strip_parens(governor.left) is target
    if isinstance(governor, JsUpdateExpression):
        return _strip_parens(governor.argument) is target
    if isinstance(governor, JsUnaryExpression):
        return governor.operator == 'delete' and _strip_parens(governor.operand) is target
    if isinstance(governor, (JsForInStatement, JsForOfStatement)):
        return _strip_parens(governor.left) is target
    return False


def is_simple_assignment_target(node: Node) -> bool:
    """
    Whether *node* is the write-only target of a simple (`=`) assignment — the left of `=`, looking
    through destructuring patterns, destructuring defaults, and parentheses — but not a compound
    assignment (`+=`, `++`), a `delete`, or a `for-in`/`for-of` head, each of which keeps the name
    live as a read instead of overwriting it outright. Built on the shared `_governing_target` climb,
    so the pattern, default, and parenthesis handling matches every other write-target query rather
    than a hand-rolled copy that a later case could drift away from.
    """
    governor, target = _governing_target(node)
    return (
        isinstance(governor, JsAssignmentExpression)
        and governor.operator == '='
        and _strip_parens(governor.left) is target
    )


def _walk_skipping_functions(stmts: list) -> Iterator[Node]:
    """
    Yield the statements in *stmts* and all their descendants, but do not descend into nested function
    bodies (the function nodes themselves are yielded so their declared names can be read).
    """
    stack: list[Node] = list(reversed(stmts))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, FUNCTION_NODES):
            continue
        stack.extend(reversed(node.children()))


def enclosing_function(node: Node) -> Node | None:
    """
    The nearest function node — declaration, expression, or arrow — that lexically encloses *node*, or
    `None` when *node* sits at the top level below no function.
    """
    cursor = node.parent
    while cursor is not None:
        if isinstance(cursor, FUNCTION_NODES):
            return cursor
        cursor = cursor.parent
    return None


def _is_global_base(node: Node | None) -> bool:
    """
    Whether *node* denotes the global object by a well-known alias, so that a dynamic property access
    on it could read or write any global by name.
    """
    return isinstance(node, JsIdentifier) and node.name in GLOBAL_OBJECT_ALIASES


def _global_member_name(member: JsMemberExpression) -> str | None:
    """
    The name of the global a member access on a global-object alias designates when it is statically
    known: the property identifier of a dot access (`globalThis.g`) or the value of a string-literal
    computed access (`globalThis['g']`). A non-literal computed key (`globalThis[expr]`) has no static
    name — it is a reflection surface `_detect_reflection` accounts for — and yields `None`.
    """
    prop = member.property
    if member.computed:
        return prop.value if isinstance(prop, JsStringLiteral) else None
    return prop.name if isinstance(prop, JsIdentifier) else None


def _is_reflective_member(member: JsMemberExpression) -> bool:
    """
    Whether a member access is a reflective surface — one through which code obtains the `eval`/`Function`
    intrinsic or reads an unknown global by a runtime-computed name. A statically named property is a
    surface exactly when the name is a reflective intrinsic: `window.eval`, `g['Function']`, and the same
    under any unrecognized base, since the base may alias the global object. A computed access with a
    non-literal key is a surface when its base is a global-object alias (`window[expr]`), through which any
    global can be named at runtime; on any other base it designates a property of one specific object and
    is not a surface.
    """
    prop = member.property
    if member.computed:
        if isinstance(prop, JsStringLiteral):
            return prop.value in REFLECTIVE_INTRINSICS
        return _is_global_base(member.object)
    return isinstance(prop, JsIdentifier) and prop.name in REFLECTIVE_INTRINSICS


def _is_direct_eval_call(node: Node) -> bool:
    """
    Whether *node* is a direct `eval` call — a call whose callee, once parentheses are stripped, is
    the bare identifier `eval`. Parentheses are transparent to the reference, so `(eval)(...)` is a
    direct eval exactly as `eval(...)`; a callee that instead only yields the function as a value —
    the comma sequence `(0, eval)(...)` that strips to a sequence expression, or a member
    `o.eval(...)` — is indirect, runs in the global scope, and is excluded. Direct eval is the one
    reflective surface that runs in the caller's own scope and can therefore name its locals; the
    excluded indirect forms name only globals, and `has_reflection_surface` accounts for them
    whole-program.
    """
    if not isinstance(node, JsCallExpression):
        return False
    callee = _strip_parens(node.callee)
    return isinstance(callee, JsIdentifier) and callee.name == 'eval'


def _has_direct_eval(function: Node) -> bool:
    """
    Whether *function*'s body contains a direct `eval` call — a call whose callee, once parentheses are
    stripped, is the bare identifier `eval` (see `_is_direct_eval_call`), the one reflective surface that
    runs in the function's own scope and can therefore name its locals. Nested functions are included,
    since a direct `eval` in a closure inherits the enclosing locals. The `with` surface is not scanned
    here — a `with` body's accesses are attributed precisely as dynamic references, so only direct eval
    needs a per-function answer; `Function`, string timers, indirect eval, and dynamic global access all
    run in the global scope and cannot name a local.
    """
    for node in function.walk():
        if _is_direct_eval_call(node):
            return True
    return False


def _timer_callee_name(callee: Node | None) -> str | None:
    """
    The timer/`execScript` function *callee* names, or `None` when it is not one. A bare identifier
    names the timer directly (`setTimeout(...)`); a member access on a global-object alias
    (`window.setTimeout(...)`, `globalThis['setInterval'](...)`) names the same global timer through
    the global object. Parentheses are transparent to the reference. Any other base designates a
    property of one specific object and is not the global timer. The base is not shadow-checked — a
    local `window` yielding a match only over-reports a reflection surface, the safe direction for the
    whole-program detector this feeds.
    """
    callee = _strip_parens(callee)
    if isinstance(callee, JsIdentifier):
        return callee.name if callee.name in TIMER_NAMES else None
    if isinstance(callee, JsMemberExpression) and _is_global_base(callee.object):
        name = _global_member_name(callee)
        return name if name in TIMER_NAMES else None
    return None


def _is_string_timer(call: JsCallExpression) -> bool:
    """
    Whether *call* is a timer/`execScript` invocation whose first argument is not a function literal,
    so it may evaluate a string of code. The callee may name the timer directly (`setTimeout(...)`) or
    through a global-object alias (`window.setTimeout(...)`), both of which reach the same evaluating
    global (see `_timer_callee_name`).
    """
    if _timer_callee_name(call.callee) is None:
        return False
    if not call.arguments:
        return False
    return not isinstance(call.arguments[0], (JsFunctionExpression, JsArrowFunctionExpression))


class SemanticModel:
    """
    The resolved scope/binding/def-use model for one script. Build it with `build_semantic_model` and
    query it through `resolve`, `scope_of`, `binding_of`, `references`, `is_shadowed`,
    `would_capture`, and `has_reflection_surface`.
    """

    def __init__(self, root: JsScript):
        self.root = root
        self._node_scope: dict[int, Scope] = {}
        self._binding_of: dict[int, Binding] = {}
        self._reflection_surface: bool | None = None
        self._function_direct_eval: dict[int, bool] = {}
        self.root_scope: Scope = _ScopeBuilder(self).build(root)
        self._build_def_use()

    def scope_of(self, node: Node) -> Scope | None:
        """
        The innermost scope that lexically contains *node*, or `None` if the node was not part of the
        script the model was built from.
        """
        return self._node_scope.get(id(node))

    def function_scope(self, func: Node) -> Scope | None:
        """
        The scope a function (or the script) introduces for its body: the script's `root_scope`, or
        the body block's scope for a function node, and `None` when *func* has no body block.
        """
        if isinstance(func, JsScript):
            return self.root_scope
        body = getattr(func, 'body', None)
        if body is None:
            return None
        return self.scope_of(body)

    def binding_of(self, decl_id: JsIdentifier) -> Binding | None:
        """
        The binding introduced by a binding-site identifier (a declarator id, parameter, function or
        class name, catch parameter, or import local), or `None` if the identifier is not a binding
        site.
        """
        return self._binding_of.get(id(decl_id))

    def lookup(self, name: str, scope: Scope | None, *, cross_dynamic: bool = False) -> Binding | None:
        """
        Resolve *name* from *scope* outward through enclosing scopes, stopping at a dynamically-scoped
        region where the name could be injected at runtime. Returns `None` for a free name. With
        *cross_dynamic*, the walk does not stop at a dynamic boundary but continues outward to the binding
        the name would denote if the `with` object lacked the property — the lexical binding a dynamic
        scope could still reach at runtime — which is how a `with`-body reference is attributed to the
        binding it may touch. The default keeps the definite-resolution semantics every other caller
        relies on.
        """
        while scope is not None:
            binding = scope.bindings.get(name)
            if binding is not None:
                return binding
            if scope.is_dynamic and not cross_dynamic:
                return None
            scope = scope.parent
        return None

    def is_reference(self, node: JsIdentifier) -> bool:
        """
        Whether *node* is a referencing occurrence of a name: it occupies a use position and is not a
        binding site, so it reads or writes an existing binding rather than declaring one or naming a
        property, key, label, or import/export specifier. The binding-aware companion to the syntactic
        `is_use_position`; `resolve` resolves exactly the identifiers for which this holds.
        """
        return is_use_position(node) and id(node) not in self._binding_of

    def resolve(self, ref: JsIdentifier) -> Binding | None:
        """
        The binding a referencing identifier reads or writes, found by walking outward from its scope.
        Returns `None` when the name is free (an external global the program never assigns), when the
        identifier is not a reference (a property name, key, or label), or when resolution crosses a
        dynamically-scoped region where the name could be injected at runtime.
        """
        if not self.is_reference(ref):
            return None
        return self.lookup(ref.name, self._node_scope.get(id(ref)))

    def references(
        self, binding: Binding, *, exclude: Node | None = None,
    ) -> list[JsIdentifier | JsMemberExpression]:
        """
        Every reference (read or write) bound to *binding*, optionally omitting those that lie within
        the subtree of *exclude*. Each is a referencing identifier except the member-expression write
        site of a global written through an alias (see `Binding`).
        """
        nodes = binding.reads + binding.writes
        if exclude is None:
            return nodes
        return [n for n in nodes if n is not exclude and not n.is_descendant_of(exclude)]

    def dynamic_references(
        self, binding: Binding, *, exclude: Node | None = None,
    ) -> list[JsIdentifier]:
        """
        Every reference to *binding* that a dynamic scope resolves at runtime — an identifier inside a
        `with` body that could denote *binding* (it may instead denote a property of the `with` object,
        which is why the static `references` set omits it) — optionally omitting those within the subtree
        of *exclude*. Each is classified on demand by `reference_role` or `container_reference_role`, the
        same oracles the definite references use, so a consumer applies one role logic to both; only the
        ordering and alias-following a resolved reference permits do not carry to an uncertain one.
        """
        nodes = binding.dynamic_refs
        if exclude is None:
            return list(nodes)
        return [n for n in nodes if n is not exclude and not n.is_descendant_of(exclude)]

    def naming_binding(self, function: Node) -> Binding | None:
        """
        The binding that gives *function* a name through which it can be invoked: the declared name of a
        named function declaration, or the single `var`/`let`/`const` declarator a function or arrow
        expression is the initializer of. `None` for an anonymous function whose invocation point cannot
        be pinned to a name — an IIFE, a callback, a function stored through any other expression.
        """
        if isinstance(function, JsFunctionDeclaration) and function.id is not None:
            return self.binding_of(function.id)
        parent = function.parent
        if (
            isinstance(parent, JsVariableDeclarator)
            and parent.init is function
            and isinstance(parent.id, JsIdentifier)
        ):
            return self.binding_of(parent.id)
        return None

    def is_shadowed(self, name: str, at: Node, outer: Scope) -> bool:
        """
        Whether *name*, referenced at *at*, resolves to a binding declared strictly inside *outer*
        rather than in *outer* itself or an enclosing scope. This replaces the various hand-rolled
        shadowing checks: a name shadowed below *outer* does not refer to *outer*'s binding.
        """
        binding = self.lookup(name, self._node_scope.get(id(at)))
        if binding is None:
            return False
        return outer.contains(binding.scope, strict=True)

    def would_capture(self, names: set[str], scope: Scope) -> bool:
        """
        Whether introducing a binding for any of *names* directly in *scope* would capture an
        identifier already meaningful there. Every use-position occurrence of one of *names* within
        *scope*, including in a nested function that would close over the new binding, must already
        resolve to a binding strictly nested below *scope* (see `is_shadowed`); otherwise that
        occurrence — free, inherited from an enclosing scope, or bound in *scope* itself — would be
        rebound by the introduced declaration.
        """
        for node in scope.node.walk():
            if not isinstance(node, JsIdentifier) or node.name not in names:
                continue
            if not is_use_position(node):
                continue
            if not self.is_shadowed(node.name, node, scope):
                return True
        return False

    def has_reflection_surface(self) -> bool:
        """
        Whether the program still contains a construct through which code could reference a global by
        name at runtime: a value-read of the `eval` or `Function` intrinsic in any form — a direct or
        indirect call, an alias (`var e = eval`), a comma sequence (`(0, eval)`), or a member access
        (`window.eval`, `g['Function']`) — a string-valued timer, a dynamic property access on the
        global object (`window[expr]`), or a `with` statement. Computed conservatively (over-reporting
        is safe): while any such surface remains, a dead global must not be removed, because reflective
        code may read it.
        """
        if self._reflection_surface is None:
            self._reflection_surface = self._detect_reflection()
        return self._reflection_surface

    def reflection_can_reach(self, binding: Binding) -> bool:
        """
        Whether a runtime name lookup could read or write *binding* without a reference this model
        records. Derived over the precise dynamic-scope facts. A global is reachable through any
        reflective surface — `eval`, `Function`, a string timer, dynamic global access, `with` — all of
        which run in the global scope, so it defers to the whole-program `has_reflection_surface`. A
        function-local is reachable only from within its own function and only by name: a `with` body that
        names it (a `dynamic_references` entry) or a direct `eval` in the function
        (`local_reachable_by_direct_eval`). A `with` that never names it cannot reach it, and reflective
        code in the global scope cannot name a local — so the local answer is exact, while the global one
        stays conservative (any surface).
        """
        owner = binding.scope.var_scope
        if owner is None or owner.kind is ScopeKind.SCRIPT:
            return self.has_reflection_surface()
        return bool(binding.dynamic_refs) or self._function_has_direct_eval(owner.node)

    def local_reachable_by_direct_eval(self, binding: Binding) -> bool:
        """
        Whether a direct `eval` positioned to name *binding* could read or write it with no reference this
        model records. True only for a function-local whose owning function — or a closure nested inside
        it, which inherits its scope — contains a direct `eval`, the one reflective surface that runs in
        the caller's own scope and can therefore name a local. False for a global: an opaque global-scope
        surface can name any global, but that is what the whole-program `reflection_can_reach` answers, and
        freezing every global on it is an over-approximation the caller must choose to accept, not a fact
        this query asserts. The `with` surface is not counted — a `with` body's accesses are attributed
        precisely as `dynamic_references`, so only the opaque `eval` case needs this per-function answer.
        """
        owner = binding.scope.var_scope
        if owner is None or owner.kind is ScopeKind.SCRIPT:
            return False
        return self._function_has_direct_eval(owner.node)

    def binding_maybe_reassigned_dynamically(self, binding: Binding) -> bool:
        """
        Whether a dynamic scope could rebind *binding* — give the name a new value through a surface
        the static `writes` set does not record. A `with` body that names it as an assignment target
        may rebind it (the target may instead be a property of the `with` object, but may equally be
        this binding, so it is treated as a possible rebind), and a direct `eval` in its owning
        function can rebind it opaquely. A member write or method call through the name does not
        rebind it — the name keeps its value — so only a dynamic reference whose role is not a plain
        read counts. A consumer that judges a binding's value stable from `writes` alone must also
        consult this, since neither reassignment leaves a `writes` entry; a script-scope binding
        reassigned only through an opaque `eval` stays the documented residual, as
        `local_reachable_by_direct_eval` reports it false there.
        """
        if self.local_reachable_by_direct_eval(binding):
            return True
        return any(
            reference_role(ref) is not Role.READ
            for ref in self.dynamic_references(binding)
        )

    def _function_has_direct_eval(self, function: Node) -> bool:
        cached = self._function_direct_eval.get(id(function))
        if cached is None:
            cached = _has_direct_eval(function)
            self._function_direct_eval[id(function)] = cached
        return cached

    def _reads_reflective_intrinsic(self, node: JsIdentifier) -> bool:
        """
        Whether *node* obtains the genuine `eval`/`Function` intrinsic as a value: a read of the bare name
        in a use position that resolves to no binding, so it denotes the intrinsic rather than a local
        shadow. Naming the intrinsic as a value is itself the reflective surface — once obtained it can be
        aliased, sequenced (`(0, eval)(...)`), or passed on, all beyond what this model tracks — so the read
        alone is conclusive, with no need to follow where the value flows. A binding site that declares the
        name (`function eval(){}`, `var Function`) introduces a shadow rather than reading the intrinsic,
        and a name that resolves to such a shadow is not the intrinsic, so neither is a surface.
        """
        if node.name not in REFLECTIVE_INTRINSICS:
            return False
        if not self.is_reference(node):
            return False
        if reference_role(node) is not Role.READ:
            return False
        return self.lookup(node.name, self._node_scope.get(id(node))) is None

    def _detect_reflection(self) -> bool:
        for node in self.root.walk():
            if isinstance(node, JsWithStatement):
                return True
            elif isinstance(node, JsIdentifier):
                if self._reads_reflective_intrinsic(node):
                    return True
            elif isinstance(node, JsMemberExpression):
                if _is_reflective_member(node):
                    return True
            elif isinstance(node, JsCallExpression):
                if _is_string_timer(node):
                    return True
        return False

    def _build_def_use(self):
        self._create_implicit_globals()
        for node in self.root.walk():
            if not isinstance(node, JsIdentifier):
                continue
            if not self.is_reference(node):
                continue
            ref_scope = self._node_scope.get(id(node))
            binding = self.lookup(node.name, ref_scope)
            if binding is None:
                self._attribute_dynamic_reference(node, ref_scope)
                continue
            role = reference_role(node)
            if role is not Role.WRITE:
                binding.reads.append(node)
            if role is not Role.READ:
                binding.writes.append(node)
            if ref_scope is None or ref_scope.var_scope is not binding.scope.var_scope:
                binding.captured = True

    def _attribute_dynamic_reference(self, node: JsIdentifier, scope: Scope | None):
        """
        Attribute a reference that did not resolve statically to the binding it could reach across a
        dynamic scope. A name inside a `with` body resolves to `None` — it may denote a property of the
        `with` object or a lexical binding — so the def-use walk would otherwise drop it. Only a name that
        crosses a dynamic scope is a candidate; continuing the lookup past that boundary finds the lexical
        binding it may touch, and the reference is recorded on that binding's `dynamic_refs`. A genuinely
        free name that crosses no dynamic scope (an external global the program never declares) is left
        untouched, as is one whose cross-boundary lookup still finds no binding.
        """
        if not self._crosses_dynamic_scope(scope):
            return
        binding = self.lookup(node.name, scope, cross_dynamic=True)
        if binding is not None:
            binding.dynamic_refs.append(node)

    def _create_implicit_globals(self):
        """
        Give every implicitly-declared global a binding at script scope, so that the def-use pass that
        follows resolves its references to it like any other binding. A name becomes an implicit global
        when the program writes it — an assignment, update, or `for-in`/`for-of` target — without it
        resolving to any lexical binding, which in sloppy mode creates a property on the global object.
        A write through a member access on a global-object alias (`globalThis.g = ...`) likewise writes
        the named global, even though its property name is not a use-position identifier the def-use
        walk would resolve. A write that resolves through a dynamic scope is skipped: inside a `with`
        body the target may be a property of the `with` object rather than a global, so the model cannot
        claim a global binding.
        """
        for node in self.root.walk():
            if isinstance(node, JsMemberExpression):
                self._record_global_member_write(node)
                continue
            if not isinstance(node, JsIdentifier) or not self.is_reference(node):
                continue
            scope = self._node_scope.get(id(node))
            if reference_role(node) is Role.READ:
                continue
            if self.lookup(node.name, scope) is not None or self._crosses_dynamic_scope(scope):
                continue
            self.root_scope.bindings.setdefault(
                node.name, Binding(node.name, BindingKind.IMPLICIT_GLOBAL, self.root_scope))

    def _record_global_member_write(self, member: JsMemberExpression):
        """
        Record a write performed through a member access on a global-object alias (`globalThis.g = ...`,
        `window['g'] = ...`) as a write of the named global's binding, creating an implicit-global
        binding when the name is otherwise undeclared. Without this the global's property name, which is
        not a use-position identifier, leaves the def-use model unaware that the global is reassigned, so
        a transform could wrongly treat its value as stable. The alias must not be locally shadowed (a
        local `window` names an ordinary object, not the global) and the write must not cross a dynamic
        scope, where the alias itself could be rebound or the target could be a `with`-object property —
        in either case the model cannot claim the global is written.
        """
        base = member.object
        if not isinstance(base, JsIdentifier) or base.name not in GLOBAL_OBJECT_ALIASES:
            return
        if not is_member_write_target(member):
            return
        name = _global_member_name(member)
        if name is None:
            return
        scope = self._node_scope.get(id(member))
        if self.lookup(base.name, scope) is not None or self._crosses_dynamic_scope(scope):
            return
        binding = self.root_scope.bindings.setdefault(
            name, Binding(name, BindingKind.IMPLICIT_GLOBAL, self.root_scope))
        binding.writes.append(member)

    def _crosses_dynamic_scope(self, scope: Scope | None) -> bool:
        """
        Whether resolving a name from *scope* outward passes through a dynamically-scoped region.
        """
        while scope is not None:
            if scope.is_dynamic:
                return True
            scope = scope.parent
        return False


class _ScopeBuilder:
    """
    Single-pass scope and binding construction. Bindings are collected when a scope is created
    (parameters and hoisted `var`/function names for function scopes, lexical `let`/`const`/`class`
    for block scopes); the recursive walk only records which scope each node belongs to.
    """

    def __init__(self, model: SemanticModel):
        self.model = model

    def build(self, root: JsScript) -> Scope:
        scope = Scope(kind=ScopeKind.SCRIPT, node=root)
        self.model._node_scope[id(root)] = scope
        self._hoist(root.body, scope)
        self._collect_imports(root.body, scope)
        self._collect_lexical(root.body, scope)
        for stmt in root.body:
            self._visit(stmt, scope)
        return scope

    def _new_scope(self, kind: ScopeKind, node: Node, parent: Scope) -> Scope:
        scope = Scope(kind=kind, node=node, parent=parent)
        parent.children.append(scope)
        return scope

    def _declare(
        self, scope: Scope, name: str, kind: BindingKind, decl_id: JsIdentifier | None,
    ) -> Binding:
        binding = scope.bindings.get(name)
        if binding is None:
            binding = Binding(name=name, kind=kind, scope=scope)
            scope.bindings[name] = binding
        if decl_id is not None:
            binding.declarations.append(decl_id)
            self.model._binding_of[id(decl_id)] = binding
        return binding

    def _hoist(self, stmts: list, func_scope: Scope):
        for node in _walk_skipping_functions(stmts):
            if isinstance(node, JsVariableDeclaration) and node.kind is JsVarKind.VAR:
                for decl in node.declarations:
                    if isinstance(decl, JsVariableDeclarator):
                        for ident in pattern_identifiers(decl.id):
                            self._declare(func_scope, ident.name, BindingKind.VAR, ident)
            elif isinstance(node, JsFunctionDeclaration) and node.id is not None:
                self._declare(func_scope, node.id.name, BindingKind.FUNCTION, node.id)

    def _collect_imports(self, stmts: list, scope: Scope):
        for stmt in stmts:
            if not isinstance(stmt, JsImportDeclaration):
                continue
            for spec in stmt.specifiers:
                local = spec.local
                if isinstance(local, JsIdentifier):
                    self._declare(scope, local.name, BindingKind.IMPORT, local)

    def _collect_lexical(self, stmts: list, scope: Scope):
        for stmt in stmts:
            if isinstance(stmt, JsVariableDeclaration) and stmt.kind in (
                JsVarKind.LET, JsVarKind.CONST,
            ):
                kind = BindingKind.LET if stmt.kind is JsVarKind.LET else BindingKind.CONST
                for decl in stmt.declarations:
                    if isinstance(decl, JsVariableDeclarator):
                        for ident in pattern_identifiers(decl.id):
                            self._declare(scope, ident.name, kind, ident)
            elif isinstance(stmt, JsClassDeclaration) and stmt.id is not None:
                self._declare(scope, stmt.id.name, BindingKind.CLASS, stmt.id)

    def _visit(self, node: Node, scope: Scope):
        self.model._node_scope[id(node)] = scope
        if isinstance(node, (
            JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression,
        )):
            self._visit_function(node, scope)
        elif isinstance(node, JsBlockStatement):
            self._visit_block(node, scope)
        elif isinstance(node, JsForStatement):
            self._visit_for(node, scope)
        elif isinstance(node, (JsForInStatement, JsForOfStatement)):
            self._visit_for_in_of(node, scope)
        elif isinstance(node, JsSwitchStatement):
            self._visit_switch(node, scope)
        elif isinstance(node, JsCatchClause):
            self._visit_catch(node, scope)
        elif isinstance(node, JsWithStatement):
            self._visit_with(node, scope)
        elif isinstance(node, (JsClassDeclaration, JsClassExpression)):
            self._visit_class(node, scope)
        else:
            for child in node.children():
                self._visit(child, scope)

    def _visit_function(self, node: _FunctionNode, enclosing: Scope):
        fscope = self._new_scope(ScopeKind.FUNCTION, node, enclosing)
        is_arrow = isinstance(node, JsArrowFunctionExpression)
        if isinstance(node, JsFunctionExpression) and node.id is not None:
            self._declare(fscope, node.id.name, BindingKind.FUNC_NAME, node.id)
        for param in node.params:
            for ident in pattern_identifiers(param):
                self._declare(fscope, ident.name, BindingKind.PARAM, ident)
        if not is_arrow:
            self._declare(fscope, 'arguments', BindingKind.ARGUMENTS, None)
        body = node.body
        if isinstance(body, JsBlockStatement):
            self._hoist(body.body, fscope)
            self._collect_lexical(body.body, fscope)
        for param in node.params:
            self._visit(param, fscope)
        if isinstance(body, JsBlockStatement):
            self.model._node_scope[id(body)] = fscope
            for stmt in body.body:
                self._visit(stmt, fscope)
        elif body is not None:
            self._visit(body, fscope)

    def _visit_block(self, node: JsBlockStatement, enclosing: Scope):
        bscope = self._new_scope(ScopeKind.BLOCK, node, enclosing)
        self._collect_lexical(node.body, bscope)
        for stmt in node.body:
            self._visit(stmt, bscope)

    def _visit_for(self, node: JsForStatement, enclosing: Scope):
        init = node.init
        if isinstance(init, JsVariableDeclaration) and init.kind in (JsVarKind.LET, JsVarKind.CONST):
            scope = self._new_scope(ScopeKind.BLOCK, node, enclosing)
            self._collect_lexical([init], scope)
        else:
            scope = enclosing
        for part in (node.init, node.test, node.update, node.body):
            if part is not None:
                self._visit(part, scope)

    def _visit_for_in_of(self, node: JsForInStatement | JsForOfStatement, enclosing: Scope):
        left = node.left
        if isinstance(left, JsVariableDeclaration) and left.kind in (JsVarKind.LET, JsVarKind.CONST):
            scope = self._new_scope(ScopeKind.BLOCK, node, enclosing)
            self._collect_lexical([left], scope)
        else:
            scope = enclosing
        if node.right is not None:
            self._visit(node.right, enclosing)
        if left is not None:
            self._visit(left, scope)
        if node.body is not None:
            self._visit(node.body, scope)

    def _visit_switch(self, node: JsSwitchStatement, enclosing: Scope):
        if node.discriminant is not None:
            self._visit(node.discriminant, enclosing)
        sscope = self._new_scope(ScopeKind.BLOCK, node, enclosing)
        for case in node.cases:
            self._collect_lexical(case.body, sscope)
        for case in node.cases:
            self.model._node_scope[id(case)] = sscope
            if case.test is not None:
                self._visit(case.test, sscope)
            for stmt in case.body:
                self._visit(stmt, sscope)

    def _visit_catch(self, node: JsCatchClause, enclosing: Scope):
        cscope = self._new_scope(ScopeKind.CATCH, node, enclosing)
        if node.param is not None:
            for ident in pattern_identifiers(node.param):
                self._declare(cscope, ident.name, BindingKind.CATCH, ident)
            self._visit(node.param, cscope)
        if node.body is not None:
            self._visit(node.body, cscope)

    def _visit_with(self, node: JsWithStatement, enclosing: Scope):
        if node.object is not None:
            self._visit(node.object, enclosing)
        wscope = self._new_scope(ScopeKind.WITH, node, enclosing)
        wscope.is_dynamic = True
        if node.body is not None:
            self._visit(node.body, wscope)

    def _visit_class(self, node: JsClassDeclaration | JsClassExpression, enclosing: Scope):
        if isinstance(node, JsClassDeclaration) and node.id is not None:
            self._declare(enclosing, node.id.name, BindingKind.CLASS, node.id)
        if node.super_class is not None:
            self._visit(node.super_class, enclosing)
        cscope = self._new_scope(ScopeKind.CLASS, node, enclosing)
        if isinstance(node, JsClassExpression) and node.id is not None:
            self._declare(cscope, node.id.name, BindingKind.CLASS, node.id)
        body = node.body
        if body is not None:
            self.model._node_scope[id(body)] = cscope
            for member in body.body:
                self._visit(member, cscope)


def build_semantic_model(root: JsScript) -> SemanticModel:
    """
    Build the `SemanticModel` for a parsed script.
    """
    return SemanticModel(root)
