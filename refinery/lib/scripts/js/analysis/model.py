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
from typing import Callable, Iterator

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsArrayExpression,
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsBinaryExpression,
    JsBlockStatement,
    JsBreakStatement,
    JsCallExpression,
    JsCatchClause,
    JsClassDeclaration,
    JsClassExpression,
    JsConditionalExpression,
    JsContinueStatement,
    JsDoWhileStatement,
    JsErrorNode,
    JsExportDefaultDeclaration,
    JsExportNamedDeclaration,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsFunctionNode,
    JsIdentifier,
    JsIfStatement,
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
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsObjectPattern,
    JsParenthesizedExpression,
    JsProperty,
    JsPropertyDefinition,
    JsRestElement,
    JsReturnStatement,
    JsScript,
    JsSpreadElement,
    JsStaticBlock,
    JsStringLiteral,
    JsSwitchCase,
    JsSwitchStatement,
    JsTaggedTemplateExpression,
    JsThisExpression,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
    JsWhileStatement,
    JsWithStatement,
    file_ended_inside,
    names_a_property,
    static_property_key,
    strip_parens,
)
from refinery.lib.scripts.js.numbers import canonical_array_index, exact_integer
from refinery.lib.scripts.js.strict import (
    has_parameter_expressions,
    has_simple_parameters,
    strict_mode_at,
)

# A class static block hoists its own `var`/function declarations, so it bounds the hoist walk like a
# function body. It is deliberately absent from FUNCTION_NODES so the effect model stays transparent to
# it: its statements run once, at class-definition time, as part of the enclosing function.
HOIST_BOUNDARY = FUNCTION_NODES + (JsStaticBlock,)

#: The spellings of the global object that name *this* realm's, which is the one a file's own
#: top-level declarations are properties of. `GLOBAL_OBJECT_ALIASES` knows two more, `top` and
#: `frames`, deliberately absent here: which document's global object each names depends on where
#: the file runs — `top` is another document's in a framed one, and both are read by the document a
#: frame is embedded in — so a removal must not trust either to be this realm's, since deleting a
#: write for want of a reader in this file deletes one another document reads. A removal keys on
#: this set; a reading of what code may reach keys on the wider one.
SAME_REALM_GLOBAL_OBJECT_ALIASES = frozenset({'globalThis', 'global', 'window', 'self'})

GLOBAL_OBJECT_ALIASES = SAME_REALM_GLOBAL_OBJECT_ALIASES | frozenset({'top', 'frames'})

TIMER_NAMES = frozenset({'setTimeout', 'setInterval', 'setImmediate'})

SYNC_EVAL_NAMES = frozenset({'execScript'})

STRING_EVAL_NAMES = TIMER_NAMES | SYNC_EVAL_NAMES

REFLECTIVE_INTRINSICS = frozenset({'eval', 'Function'})

_PROTOTYPE_YIELDING_KEYS = frozenset({'__proto__', 'constructor'})
"""
The two member keys whose value shares the prototype surface of the object they are read off —
the species keys the effect layer refuses for the same reason — so a write through what they
return lands on the surface an inherited method is dispatched over.
"""

_PROTOTYPE_KEEPING_KEYS = _PROTOTYPE_YIELDING_KEYS | frozenset({'prototype'})
"""
The member keys that keep yielding a prototype surface when read off one, so a chain climbing
through them still holds the surface: another species key, and `prototype`, which is the chain.
"""

_PROTOTYPE_REFLECTING_CALLEES = frozenset({'getPrototypeOf', 'setPrototypeOf'})
"""
The member names that reach or replace an object's prototype as calls, so their mere presence —
aliased and invoked later, perhaps — lets text touch the surface with no chain this model can
climb.
"""

_DISPLACING_CHAIN_KEYS = _PROTOTYPE_YIELDING_KEYS | frozenset({
    '__defineGetter__',
    '__defineSetter__',
})
"""
The member keys a read may not pass while its base stays trusted for intrinsic dispatch: a
prototype-yielding key hands out the surface a write would displace the dispatch through, and the
`__defineGetter__`/`__defineSetter__` pair installs on its receiver when invoked anywhere along
the chain.
"""

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
    NAME     = 'name'      # noqa  the own name of a named function expression
    PARAMS   = 'params'    # noqa  a parameter list holding an expression
    BLOCK    = 'block'     # noqa
    CATCH    = 'catch'     # noqa
    CLASS    = 'class'     # noqa
    WITH     = 'with'      # noqa
    STATIC_BLOCK = 'static-block'  # noqa


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


#: What a binding's reference lists hold. A reference is ordinarily the identifier naming the
#: binding; where an object aliases it there is no such identifier, and the node the program reached
#: the object through stands in — a member access for `globalThis.g` and for `arguments[0]`, and the
#: `this` of a script's top level where the object itself is handed to a call.
ReferenceNode = JsIdentifier | JsMemberExpression | JsThisExpression


@dataclass(eq=False)
class Binding:
    """
    A single declared name within one scope. `declarations` holds the binding-site identifier nodes
    that introduce the name; `reads` and `writes` hold the referencing identifiers that read and write
    it (a compound assignment or update appears in both). `captured` is set when the name is referenced
    from a function nested below the one that owns it. A read or write performed through an object that
    aliases the binding has no referencing identifier for the name it targets, so the
    `JsMemberExpression` stands in for that reference; every other `reads`/`writes` entry is an
    identifier. Two objects alias this way — a global-object alias (`globalThis.g`) reaching a global,
    and a mapped `arguments` reaching a parameter — and they are told apart by what the access is on,
    never by the entry being a member access at all. `dynamic_refs` holds referencing identifiers a dynamic
    scope resolves at runtime — a name inside a `with` body that could denote this binding — which
    `reads`/`writes` omit because such a name resolves to no binding statically; its target is
    uncertain, so it is kept apart from the definite references.
    """
    name: str
    kind: BindingKind
    scope: Scope
    declarations: list[JsIdentifier] = field(default_factory=list)
    reads: list[ReferenceNode] = field(default_factory=list)
    writes: list[ReferenceNode] = field(default_factory=list)
    dynamic_refs: list[JsIdentifier] = field(default_factory=list)
    indefinite_writes: list[ReferenceNode] = field(default_factory=list)
    captured: bool = False
    #: Whether the call writes this binding before any statement of its scope runs. A `var` of a
    #: parameter's name is the one shape that does: the body's name starts out holding the argument,
    #: and only a declarator that runs later says anything about what it holds after that. There is
    #: no node for that write - the call makes it, not anything in the text - so it can be neither a
    #: `writes` nor an `indefinite_writes` entry, both of which every consumer orders by position.
    written_at_entry: bool = False
    #: Whether the program hands a call the object that carries this binding, so a body no reading of
    #: the text follows can name it. The references such a call may make are recorded like any other,
    #: and this says the one thing they cannot: that a walk which finds a name only where the text
    #: spells it is looking at less than the whole program. Only a global is ever carried this way.
    reachable_through_a_handed_object: bool = False
    #: Whether the binding is exported, so an importer observes its value across the module boundary
    #: after the module runs. Like the two flags above, it names an observer no reading of the text
    #: reaches: its declaration must be kept and never relocated out of module scope, and a write to
    #: it is never a dead store, because the final value is read from outside. `export var a`,
    #: `export function`/`class`, and the local half of a sourceless `export { a }` all set it; a
    #: `from`-clause list and a re-export name a binding of another module and set nothing here.
    exported: bool = False

    def note_reference_from(self, scope: Scope | None) -> None:
        """
        Mark this binding captured where *scope* is on the far side of a closure boundary from the
        scope declaring it, which is what a reference made from a scope with a different variable
        scope is. A reference whose own scope is not known is counted as a capture, since nothing
        about it says that it is not one.

        Three walks record a reference and each of them asks this: the identifier walk, the one
        reading a binding through an alias of the global object, and the one reading a parameter
        through a mapped `arguments`. They have to agree, and one of them being written differently
        from the others is not a difference anything downstream could act on.
        """
        if scope is None or scope.closure_home is not self.scope.closure_home:
            self.captured = True

    @property
    def is_read(self) -> bool:
        """
        Whether the binding's value is ever read.
        """
        return bool(self.reads)

    @property
    def is_hoisted(self) -> bool:
        """
        Whether the binding is hoisted to the top of its variable scope — a `var` or a function
        declaration — and so is visible (as `undefined`, or the function) throughout that scope before
        its textual position, rather than sitting in a temporal dead zone.
        """
        return self.kind in (BindingKind.VAR, BindingKind.FUNCTION)

    @property
    def is_lexical(self) -> bool:
        """
        Whether the binding is block-scoped in a declarative environment — a `let`, `const`, or
        `class`. Defined positively: a parameter, catch binding, import, or implicit global is neither
        hoisted nor lexical in this sense.
        """
        return self.kind in (BindingKind.LET, BindingKind.CONST, BindingKind.CLASS)

    @property
    def is_dead(self) -> bool:
        """
        Whether no use observes the binding's value: it is read through no resolved reference, named
        inside no dynamic scope, and not exported. Definitions of a dead binding can be removed if they
        carry no other side effect (which the caller decides). A name a `with` body could read is not
        dead even though `reads` is empty — the dynamic reference may observe it at runtime — nor is an
        exported one, whose value an importer reads across the module boundary, so removers need not
        rely on a separate reflection gate to keep such a binding.
        """
        return not self.reads and not self.dynamic_refs and not self.exported

    @property
    def has_indefinite_write(self) -> bool:
        """
        Whether some access writes the binding at a point where what it stores, or whether it stores
        at all, is decided only at run time, so that its value stops holding there and no definition
        says what replaced it. Every write through a mapped `arguments` object is one. `arguments[k]
        = v` for a `k` no reading of the text computes writes exactly one parameter of the function
        and which one is not decidable, so it is a kill of each with a value for none; `arguments[0]
        = v` names its parameter but still lands only where the call supplied that argument
        (§10.2.11 maps an element onto a parameter only for a position `index < len`), so it is a
        kill of that one with a value for none. The object handed to a call or bound to a second
        name is another, and the entry is then the identifier the object escaped through rather than
        an access on it.

        It is kept apart from `writes` for the same reason `dynamic_refs` is kept apart: a `writes`
        entry is a definition, and a consumer reading one expects to find the value it stored. Recording
        this as a definition of every parameter would let a fold answer with a value only one of them
        can hold; recording it nowhere lets a fold carry a value across it that the write destroyed.

        The write a call makes on entry is one of these too, and it is the one with no node at all,
        so it is carried by `written_at_entry` and read here beside the rest.
        """
        return bool(self.indefinite_writes) or self.written_at_entry

    @property
    def has_global_member_write(self) -> bool:
        """
        Whether the binding is written through a member access on a global-object alias
        (`globalThis.x = ...`), recorded as a `JsMemberExpression` write site rather than a referencing
        identifier (see the class docstring). Only a global ever carries such a write, so the answer is
        always false for a lexical binding.

        The access is tested by what it is on and not by its being a member access, because a parameter
        of a sloppy function carries member-access writes too — through the `arguments` object that
        aliases it — and those reach one function's own parameter rather than the global object.
        """
        return any(_is_global_alias_access(write) for write in self.writes)

    @property
    def has_member_reference(self) -> bool:
        """
        Whether the binding is read or written through a member access on a global-object alias
        (`globalThis.x`), recorded as a `JsMemberExpression` reference rather than a referencing
        identifier (see the class docstring). Such a binding is reachable through the global object, so
        a caller must not treat it as an ordinary local — it cannot be relocated into a function.

        As with `has_global_member_write`, an access through a mapped `arguments` object is not one of
        these: it reaches a parameter, which no other function can name.
        """
        return any(_is_global_alias_access(ref) for ref in (*self.reads, *self.writes))


@dataclass(eq=False)
class Scope:
    """
    A lexical scope. `node` is the AST node that introduces it (the script, a function, a block, a
    catch clause, a class, or a `with`). `is_dynamic` marks a scope whose bindings cannot be
    resolved statically: a `with` body, whose object supplies them at run time, and a parameter or
    catch scope declared by a pattern the parser could not read, which spells names this model
    cannot see (`pattern_binds_unread_names`). A name that would resolve across either boundary
    resolves to nothing instead, since the binding it denotes may be one that is not there.

    A direct `eval` is not marked here even though it too can inject a name. It would have to mark the
    whole enclosing function, which would make every name in a function containing one unresolvable,
    where what an `eval` actually does is narrower and is answered by the two queries written for it:
    `local_reachable_by_direct_eval` for a binding that already exists, and
    `free_name_reachable_by_direct_eval` for one the `eval` may have declared.
    """
    kind: ScopeKind
    node: Node
    parent: Scope | None = None
    children: list[Scope] = field(default_factory=list)
    bindings: dict[str, Binding] = field(default_factory=dict)
    is_dynamic: bool = False
    #: For one of the two scopes a function introduces around its body - the one holding its own
    #: name and the one holding its parameters - the scope holding that body. It is what says the
    #: three are one call rather than three, which `closure_home` reads and nothing else does.
    function_body: Scope | None = None

    @property
    def is_var_scope(self) -> bool:
        """
        Whether this scope is the target of `var`/function-declaration hoisting: a function body, a
        class static block, or the script itself.
        """
        return (
            self.kind is ScopeKind.FUNCTION
            or self.kind is ScopeKind.SCRIPT
            or self.kind is ScopeKind.STATIC_BLOCK
            or self.kind is ScopeKind.PARAMS
        )

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

    @property
    def closure_home(self) -> Scope | None:
        """
        The scope that decides whether a reference made from this one crosses a closure boundary: a
        name read from a scope with a different one is read by a function other than the one that
        declares it, and is a capture.

        This is the variable scope for every scope but the two a function introduces around its
        body. A parameter default and the body it belongs to are run by one call and share every
        binding either of them makes, and so does the name a function expression answers to inside
        itself, so no closure boundary runs between the three: all of them answer the body's scope.
        """
        if self.function_body is not None:
            return self.function_body
        home = self.var_scope
        if home is not None and home.function_body is not None:
            return home.function_body
        return home

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


def crosses_dynamic_scope(scope: Scope | None) -> bool:
    """
    Whether resolving a name from *scope* outward passes through a dynamically-scoped region.
    """
    while scope is not None:
        if scope.is_dynamic:
            return True
        scope = scope.parent
    return False


def is_use_position(node: JsIdentifier) -> bool:
    """
    Whether an identifier occupies a position where it reads or writes a value, as opposed to naming
    a property, a key, a label, or something across a module boundary. `names_a_property` answers
    for every position that names what a value carries, the far side of a module boundary among
    them; what is added here is the two positions that name something else the program cannot
    refer to: a label, and the binding an import creates. The local half of an export list without
    a `from` clause reads the binding it names, which is why an engine refuses to link
    `export { a };` where nothing declares `a`; where nothing renames, one node fills both halves
    of the specifier, and that node is the local half and reads. Binding sites are not excluded
    here; `SemanticModel.is_reference` is the binding-aware predicate that also excludes them.
    """
    p = node.parent
    if p is None:
        return False
    if names_a_property(node):
        return False
    if isinstance(p, (JsBreakStatement, JsContinueStatement, JsLabeledStatement)) and p.label is node:
        return False
    if isinstance(p, (
        JsImportSpecifier,
        JsImportDefaultSpecifier,
        JsImportNamespaceSpecifier,
    )):
        return False
    return True


def name_uses_in_scope(names: set[str], scope: Scope) -> Iterator[JsIdentifier]:
    """
    Every use-position identifier within *scope* (descending into nested functions) whose name is one
    of *names* — the shared walk behind the capture check and the reflection dominance gate, which both
    enumerate the live occurrences of a set of names across a region.
    """
    for node in scope.node.walk():
        if isinstance(node, JsIdentifier) and node.name in names and is_use_position(node):
            yield node


def is_unread_source(node: Node) -> bool:
    """
    Whether *node* is source this model never read: a span the parser could not read at all, or a
    construct the file ended inside, whose closing delimiter and everything that would have
    followed it the file never held. Nothing says what such a span references, so every binding in
    scope where one stands may be read or written by it, and none of them is provably unused.
    """
    return isinstance(node, JsErrorNode) or file_ended_inside(node)


def pattern_targets(target: Node | None) -> Iterator[Node]:
    """
    Yield every node standing in a binding position of a declaration target, descending through
    destructuring patterns (`[a, {b: c}]`, `{x, ...rest}`), default patterns, and rest elements.
    What stands there is an identifier wherever the target binds a name, a member expression where
    it binds none (`[a.b] = ...`), and a span the parser could not read wherever the source spelled
    a binding position with text no grammar reads.
    """
    if target is None:
        return
    if isinstance(target, JsArrayPattern):
        for element in target.elements:
            yield from pattern_targets(element)
    elif isinstance(target, JsObjectPattern):
        for prop in target.properties:
            if isinstance(prop, JsRestElement):
                yield from pattern_targets(prop.argument)
            elif isinstance(prop, JsProperty):
                yield from pattern_targets(prop.value)
            else:
                yield prop
    elif isinstance(target, JsAssignmentPattern):
        yield from pattern_targets(target.left)
    elif isinstance(target, JsRestElement):
        yield from pattern_targets(target.argument)
    else:
        yield target


def pattern_identifiers(target: Node | None) -> Iterator[JsIdentifier]:
    """
    Yield every binding-site identifier introduced by a declaration target. A member-expression
    target (`[a.b] = ...`) introduces no binding and yields nothing, and neither does a binding
    position the parser could not read, which `pattern_binds_unread_names` is what reports.
    """
    for node in pattern_targets(target):
        if isinstance(node, JsIdentifier):
            yield node


def pattern_binds_unread_names(target: Node | None) -> bool:
    """
    Whether a declaration target holds source this model never read in a binding position, so the
    names it binds are not the names `pattern_identifiers` yields: the unread span may spell one
    this model cannot see. A scope such a target declares into holds a binding no lookup can find,
    which is what `Scope.is_dynamic` says of a scope whose declarations are not statically known.
    """
    return any(is_unread_source(node) for node in pattern_targets(target))


def reference_role(node: ReferenceNode) -> Role:
    """
    Classify how a reference touches its binding: a plain read, a write-only target (the left of a
    simple `=`, including inside a destructuring pattern or a destructuring default, or a
    `for-in`/`for-of` head), or a read-and-write (compound assignment, `++`/`--`, or a `delete`, each
    of which keeps the name live as a read rather than overwriting it outright). The shared
    `_governing_target` climb looks through destructuring containers, default patterns, and
    parentheses, so a target nested in a pattern or a grouping (`[x = 9] = xs`, `(x)++`, `(o) = v`) is
    still recognized as a write. The reference is usually an identifier, but the same rules classify
    the node an object aliasing the binding was reached through — a member access on a global-object
    alias (`globalThis.g`, `globalThis.g = ...`), and the global object itself where a call is handed
    it — so the def-use pass records each as the read or write it is.
    """
    governor, target = _governing_target(node)
    if isinstance(governor, JsAssignmentExpression) and strip_parens(governor.left) is target:
        return Role.WRITE if governor.operator == '=' else Role.READWRITE
    if isinstance(governor, JsUpdateExpression) and strip_parens(governor.argument) is target:
        return Role.READWRITE
    if (
        isinstance(governor, JsUnaryExpression)
        and governor.operator == 'delete'
        and strip_parens(governor.operand) is target
    ):
        return Role.READWRITE
    if isinstance(governor, (JsForInStatement, JsForOfStatement)) and strip_parens(governor.left) is target:
        return Role.WRITE
    return Role.READ


def enclosing_operator(node: Node) -> Node | None:
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
    parent = enclosing_operator(cursor)
    while parent is not None:
        if isinstance(parent, JsProperty):
            value = strip_parens(parent.value)
            if value is not cursor and not (
                parent.shorthand
                and isinstance(value, JsAssignmentPattern)
                and strip_parens(value.left) is cursor
            ):
                break
        elif isinstance(parent, JsAssignmentPattern):
            if strip_parens(parent.left) is not cursor:
                break
        elif not isinstance(parent, _PATTERN_CONTAINERS):
            break
        cursor = parent
        parent = enclosing_operator(cursor)
    return parent, cursor


_UNRESOLVABLE_TOLERANT_OPERATORS = frozenset({'typeof', 'delete'})
"""
The two unary operators the language lets stand in front of a name that resolves to nothing:
`typeof` answers `'undefined'` (§13.5.3) and `delete` answers `true` (§13.5.1.2), where every other
read of an unresolvable reference throws a `ReferenceError`. This is about the operand and nothing
further: `typeof name === 'undefined'` is spared, but a read the guard stands in front of is a
separate position and is still answered as a throw, since nothing here orders the guard before it.
So the feature-detection idiom parses its own guard for free and its guarded body does not.
"""


def _is_unary_operand(governor: Node | None, node: Node, operators: frozenset[str]) -> bool:
    """
    Whether *governor* is a unary expression whose operator is one of *operators* and whose
    operand, looked through parentheses, is *node*. The single test behind every question of the
    form `does this operator stand in front of this reference`, so a parenthesization or
    operand-shape case fixed once is fixed for all of them; a caller that has not already resolved
    the governing construct obtains it from `enclosing_operator`.
    """
    return (
        isinstance(governor, JsUnaryExpression)
        and governor.operator in operators
        and strip_parens(governor.operand) is node
    )


def tolerates_unresolvable(node: Node) -> bool:
    """
    Whether the operator governing *node* reads it without demanding that the name resolve, so a
    free name standing there names nothing and still yields a value rather than throwing.
    """
    return _is_unary_operand(enclosing_operator(node), node, _UNRESOLVABLE_TOLERANT_OPERATORS)


def container_reference_role(node: ReferenceNode) -> ContainerRole:
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
    parent = enclosing_operator(node)
    if isinstance(parent, JsMemberExpression) and strip_parens(parent.object) is node:
        member: Node = parent
        while True:
            outer = enclosing_operator(member)
            if isinstance(outer, JsMemberExpression) and strip_parens(outer.object) is member:
                member = outer
                continue
            break
        if _is_invocation_of(enclosing_operator(member), member):
            return ContainerRole.MEMBER_CALL
        return ContainerRole.MEMBER_WRITE if is_member_write_target(member) else ContainerRole.MEMBER_READ
    if isinstance(parent, JsAssignmentExpression) and strip_parens(parent.left) is node and parent.operator == '=':
        return ContainerRole.REBIND
    return ContainerRole.ESCAPE


def _is_invocation_of(node: Node | None, callee: Node) -> bool:
    """
    Whether *node* invokes *callee* — a call `callee(...)` or a tagged template `` callee`...` `` —
    looking through parentheses around the callee.
    """
    if isinstance(node, JsCallExpression):
        return strip_parens(node.callee) is callee
    if isinstance(node, JsTaggedTemplateExpression):
        return strip_parens(node.tag) is callee
    return False


def is_invocation_target(node: Node) -> bool:
    """
    Whether *node* is the callee a call invokes or the tag a tagged template applies — `node(...)` or
    `` node`...` `` — looking through parentheses around both *node* and the operator that governs it.
    The shared primitive for "is this reference actually being called", replacing the hand-rolled
    `parent.callee is node` checks that a parenthesized or tagged callee slips past.

    A `new` is not one of them, because what makes these two positions special is the receiver a call
    reads off a member and the scope a direct `eval` runs in, and a construction has neither. A caller
    that asks instead whether the value it is about to write down will be invoked at all wants
    `is_constructed_or_invoked`.
    """
    return _is_invocation_of(enclosing_operator(node), node)


def is_constructed_or_invoked(node: Node) -> bool:
    """
    Whether the value *node* produces is immediately applied — called, tagged, or constructed with
    `new` — looking through parentheses around *node* and around the operator that governs it.

    This is the question a fold asks before writing a constant in place of an expression. A constant
    is not callable and not a constructor, so the application throws either way; but a `TypeError`
    names the thing that could not be applied, and `new (3)()` reports the `3` a file never wrote
    where `new ('abc'.length)()` reported the access it did. Nothing is gained by folding a value
    into the one position where it can only fail, so the access is left as the file spelled it.
    """
    if is_invocation_target(node):
        return True
    operator = enclosing_operator(node)
    return isinstance(operator, JsNewExpression) and strip_parens(operator.callee) is node


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
        return strip_parens(governor.left) is target
    if isinstance(governor, JsUpdateExpression):
        return strip_parens(governor.argument) is target
    if isinstance(governor, JsUnaryExpression):
        return governor.operator == 'delete' and strip_parens(governor.operand) is target
    if isinstance(governor, (JsForInStatement, JsForOfStatement)):
        return strip_parens(governor.left) is target
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
        and strip_parens(governor.left) is target
    )


_VERDICT_UNARY_OPERATORS = frozenset({'!', 'typeof', 'void'})

_VERDICT_BINARY_OPERATORS = frozenset({'===', '!=='})


def _read_forwards_no_alias(node: Node) -> bool:
    """
    Whether the position *node* stands in consumes the value it denotes entirely, so no alias of
    the object can flow onward from it: the operand of a `!`, `typeof` or `void`, either side of a
    strict equality, or the test of an `if`, a loop, or a conditional. Each yields a verdict — a
    boolean, a type name, or `undefined` — never the object itself, and invokes nothing on it,
    since a strict equality compares without conversion. A caller refusing on escapes may clear
    one of these; everything else — a loose equality included, whose `ToPrimitive` conversion runs
    a method the object's prototype chain chooses — forwards or consults the object and stays an
    escape.
    """
    governor = enclosing_operator(node)
    if isinstance(governor, JsUnaryExpression):
        return (
            governor.operator in _VERDICT_UNARY_OPERATORS
            and strip_parens(governor.operand) is node
        )
    if isinstance(governor, JsBinaryExpression):
        return governor.operator in _VERDICT_BINARY_OPERATORS
    if isinstance(governor, (JsIfStatement, JsWhileStatement, JsDoWhileStatement, JsForStatement)):
        return governor.test is not None and strip_parens(governor.test) is node
    if isinstance(governor, JsConditionalExpression):
        return strip_parens(governor.test) is node
    return False


def _member_reaches_dispatch_surface(member: JsMemberExpression) -> bool:
    """
    Whether *member* lets text touch a prototype surface that intrinsic dispatch walks: a
    `getPrototypeOf`/`setPrototypeOf` member on sight, or a prototype-yielding key whose value is
    written through or flows onward. The per-access half of `_dispatch_surface_reachable`, which
    says why each form counts.
    """
    key = static_property_key(member)
    if key in _PROTOTYPE_REFLECTING_CALLEES:
        return True
    if key not in _PROTOTYPE_YIELDING_KEYS:
        return False
    return _prototype_surface_escapes(member)


def _prototype_surface_escapes(access: JsMemberExpression) -> bool:
    """
    Whether the prototype-surface value the member *access* yields can be written through or flow
    onward. The chain above it is climbed while its keys keep yielding the surface
    (`_PROTOTYPE_KEEPING_KEYS`, and a key not statically known stays conservative); a write
    reached on that climb lands on the surface and counts, and so does a chain result that is
    neither invoked nor consumed as a bare verdict, since an escape may be the surface itself
    under a new name. A read of any other key ends the climb holding an ordinary property, and a
    write into the access's own key merely swaps one object's chain, so neither counts.
    """
    cursor: JsMemberExpression = access
    while True:
        outer = _enclosing_member_access(cursor)
        if outer is None:
            if _is_invocation_of(enclosing_operator(cursor), cursor):
                return False
            if is_member_write_target(cursor):
                return False
            return not _read_forwards_no_alias(cursor)
        key = static_property_key(outer)
        if key is None or key in _PROTOTYPE_KEEPING_KEYS:
            cursor = outer
            continue
        return is_member_write_target(outer)


def _walk_skipping_functions(stmts: list) -> Iterator[Node]:
    """
    Yield the statements in *stmts* and all their descendants, but do not descend into nested function
    bodies or class static blocks — each hoists its own declarations (the boundary nodes themselves are
    yielded so their declared names can be read).
    """
    stack: list[Node] = list(reversed(stmts))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, HOIST_BOUNDARY):
            continue
        stack.extend(reversed(node.children()))


def statement_list_of(node: Node) -> list[Statement] | None:
    """
    The list of statements *node* holds, or `None` where it holds none. A script and a block hold
    theirs directly, a function holds its body's, and a `switch` case holds the statements written
    under it - the four places a declaration may stand in a list at all.

    A `switch` holds every case's statements as one list, freshly built, because that is what its
    one scope binds: a `let` written under one case is visible under all of them, so a reader asking
    what a switch declares has to be given the cases together and not one at a time.
    """
    if isinstance(node, JsScript):
        return node.body
    if isinstance(node, JsSwitchStatement):
        return [
            statement
            for case in node.cases
            if isinstance(case, JsSwitchCase)
            for statement in case.body
        ]
    if isinstance(node, JsBlockStatement):
        return node.body
    if isinstance(node, JsStaticBlock):
        return node.body
    if isinstance(node, JsSwitchCase):
        return node.body
    if isinstance(node, FUNCTION_NODES):
        body = node.body
        return body.body if isinstance(body, JsBlockStatement) else None
    return None


def is_a_var_home(node: Node) -> bool:
    """
    Whether *node* is where a `var` and a function declaration written in it are bound: a function,
    a class static block, or the script. The same set `HOIST_BOUNDARY` bounds a hoist walk by, asked
    of one node rather than used to stop one.
    """
    return isinstance(node, (JsScript, HOIST_BOUNDARY))


def declaration_under_export(statement: Statement | None) -> Statement | None:
    """
    The declaration *statement* is an `export` of, or *statement* itself where it is not one. An
    export names what the declaration written under it declares and declares nothing of its own, so
    a reader asking what a statement list binds reads through it.
    """
    while isinstance(statement, (JsExportNamedDeclaration, JsExportDefaultDeclaration)):
        inner = statement.declaration
        if not isinstance(inner, Statement):
            break
        statement = inner
    return statement


def _writes_the_statement_of(parent: Node, child: Node) -> bool:
    """
    Whether *parent* is a wrapper *child* is the statement of rather than a list holding it: the
    label a statement may be written under, or the `export` a declaration may be written under.
    """
    if isinstance(parent, JsLabeledStatement):
        return parent.body is child
    if isinstance(parent, (JsExportNamedDeclaration, JsExportDefaultDeclaration)):
        return parent.declaration is child
    return False


def statement_list_holding(node: Node) -> Node | None:
    """
    The nearest node holding *node* in a statement list, looking through the labels and the `export`
    a statement may be written under, and through the `switch` case a statement stands in. A
    labelled declaration stands in the list its label stands in - Annex B reads a label as
    transparent at every level, and so does the placement of a `var` - an exported one stands where
    the export stands, and every case of a `switch` stands in the one list its scope binds.
    """
    cursor: Node = node
    parent: Node | None = cursor.parent
    while parent is not None and _writes_the_statement_of(parent, cursor):
        cursor, parent = parent, parent.parent
    if isinstance(parent, JsSwitchCase):
        cursor, parent = parent, parent.parent
    if parent is None:
        return None
    return parent if statement_list_of(parent) is not None else None


def lexically_declared_names(statements: list[Statement]) -> frozenset[str]:
    """
    The names *statements* declares with a `let`, a `const` or a class directly, read through the
    labels and the `export` a declaration may be written under.
    """
    names: set[str] = set()
    for statement in statements:
        statement = declaration_under_export(statement)
        while isinstance(statement, JsLabeledStatement):
            statement = declaration_under_export(statement.body)
        if isinstance(statement, JsVariableDeclaration) and statement.kind in (
            JsVarKind.LET, JsVarKind.CONST,
        ):
            for declarator in statement.declarations:
                if isinstance(declarator, JsVariableDeclarator):
                    names.update(ident.name for ident in pattern_identifiers(declarator.id))
        elif isinstance(statement, JsClassDeclaration) and statement.id is not None:
            names.add(statement.id.name)
    return frozenset(names)


class LexicalNameCache:
    """
    The lexically declared names of each statement list a walk passes, held for as long as the tree
    is not being rewritten.

    `annex_b_var_home` climbs from a declaration to the body that gives it a `var`, asking every
    list on the way whether it declares the name lexically. A body holding many function
    declarations is asked the same question about the same list once per declaration, and the scope
    builder asks it twice over, so the answer is quadratic in the size of the body without this.
    A cache is only ever right where nothing moves, which is why it is passed in rather than kept:
    the caller is the one that knows its rewrites have not started.
    """

    def __init__(self):
        self._names: dict[int, frozenset[str]] = {}

    def declares(self, holder: Node, name: str) -> bool:
        """
        Whether the statement list *holder* holds declares *name* lexically, false where it holds
        none.
        """
        names = self._names.get(id(holder))
        if names is None:
            statements = statement_list_of(holder)
            names = frozenset() if statements is None else lexically_declared_names(statements)
            self._names[id(holder)] = names
        return name in names


def annex_b_var_home(
    declaration: JsFunctionDeclaration, cache: LexicalNameCache | None = None,
) -> Node | None:
    """
    The function, script or static block whose `var` names the function *declaration* declares, or
    `None` where nothing outside the block holding it ever does.

    A declaration written directly in such a body names something there and is answered with that
    body. A declaration written inside a block is a lexical binding of that block, and only Annex
    B.3.3 puts the name outside it: the enclosing body gets a `var` of the name, which the copy the
    declaration makes writes to when it runs. That happens in sloppy code only, and §B.3.3.1 names
    three things that stop it:

    - a `let`, `const` or `class` of the same name between the block and the body, the body's own
      list included, which the `var` would conflict with;
    - a parameter of the function, which already binds the name;
    - the name `arguments`, whose binding the function already has, which is a condition about a
      function and not about a script or a static block, neither of which has one.

    A catch parameter is not one of them, and the mismatch is deliberate: a simple catch parameter
    does not stop the copy, so the enclosing name still ends up holding the function, while a
    destructuring one does, being a lexical declaration the `var` would conflict with. Both were
    read from an engine rather than from the text of the specification.

    *cache* holds the lexical names of the lists the climb passes, for a caller asking this of many
    declarations over a tree it is not rewriting.
    """
    cache = cache if cache is not None else LexicalNameCache()
    home = statement_list_holding(declaration)
    if home is not None and is_a_var_home(home):
        return home
    if strict_mode_at(declaration):
        return None
    name = declaration.id.name if declaration.id is not None else None
    if name is None:
        return None
    cursor: Node | None = declaration.parent
    while cursor is not None:
        if cache.declares(cursor, name):
            return None
        if (
            isinstance(cursor, JsCatchClause)
            and cursor.param is not None
            and not isinstance(cursor.param, JsIdentifier)
            and any(ident.name == name for ident in pattern_identifiers(cursor.param))
        ):
            return None
        if is_a_var_home(cursor):
            if (
                name == 'arguments'
                and isinstance(cursor, FUNCTION_NODES)
                and not isinstance(cursor, JsArrowFunctionExpression)
            ):
                return None
            if any(
                ident.name == name
                for param in getattr(cursor, 'params', ())
                for ident in pattern_identifiers(param)
            ):
                return None
            return cursor
        cursor = cursor.parent
    return None


def annex_b_suppressor_names(
    declaration: Statement, cache: LexicalNameCache | None = None,
) -> frozenset[str]:
    """
    The names *declaration* binds lexically whose binding keeps a block-scoped function declaration
    of the same name from being copied to an enclosing `var` scope by §B.3.3.1.

    A `let`, `const` or class between such a function and the body that would give it a `var` is one
    of the three things `annex_b_var_home` reads as stopping the copy, so the name it binds decides
    that the function means nothing outside its block. That is a use no reader of the name can see:
    the binding may have no reference anywhere and still be load-bearing, and removing it lets the
    function reach the scope around it. A pass that removes a lexically declared name it finds no
    reference to reads this to leave such a binding standing.

    The answer is the subset of the names, so a `let f, g` where only `f` suppresses a copy keeps
    `f` and gives up `g`. It is a lower bound in the safe direction: a name is reported wherever a
    same-named block function has no `var` home, which counts a home stopped by a nearer binding or
    by the mode as well, so the name is kept where removing it could not in fact free the function.
    """
    names = lexically_declared_names([declaration])
    if not names:
        return frozenset()
    home = statement_list_holding(declaration)
    if home is None:
        return frozenset()
    stmts = statement_list_of(home)
    if stmts is None:
        return frozenset()
    cache = cache if cache is not None else LexicalNameCache()
    suppressed: set[str] = set()
    for node in _walk_skipping_functions(stmts):
        if (
            isinstance(node, JsFunctionDeclaration)
            and node.id is not None
            and node.id.name in names
            and node.id.name not in suppressed
            and annex_b_var_home(node, cache) is None
        ):
            suppressed.add(node.id.name)
    return frozenset(suppressed)


def annex_b_copies_into(binding: Binding) -> bool:
    """
    Whether *binding* holds a function Annex B copies into its scope rather than declares there.

    The difference the copy makes is one of time. A function declared in the scope it names holds
    its value before any statement of that scope runs, so nothing has to be ordered against it; one
    Annex B copies holds it only from the point the declaration is reached, so a read before that
    point - or in a run in which the block is never entered - finds whatever was there instead.
    `binding_establishment_sites` is where that is answered, by naming the declaration as the node
    the value waits on rather than by answering with the empty list a hoisted value gets.

    Spelled over the scope the binding is in rather than over its variable scope, because a block
    function that is *not* copied is declared in the block it stands in, and that one is a plain
    lexical binding: it is initialized before any statement of the block runs and the declaration is
    exactly what it holds.
    """
    if binding.kind is not BindingKind.FUNCTION or len(binding.declarations) != 1:
        return False
    declaration = binding.declarations[0].parent
    if not isinstance(declaration, JsFunctionDeclaration):
        return False
    return statement_list_holding(declaration) is not _statement_list_holder_of(binding.scope)


def _loop_head_assigns(declarator: JsVariableDeclarator) -> bool:
    """
    Whether *declarator* is the target a `for-in`/`for-of` head writes on each iteration — a value
    channel that spells no stored value, so a binding it declares has no complete value set.
    """
    declaration = declarator.parent
    if not isinstance(declaration, JsVariableDeclaration):
        return False
    head = declaration.parent
    return isinstance(head, (JsForInStatement, JsForOfStatement)) and head.left is declaration


def _statement_list_holder_of(scope: Scope) -> Node | None:
    """
    The node whose statement list *scope* binds the declarations of, which is the scope's own node
    but for a function, whose statements are its body's.
    """
    node = scope.node
    if isinstance(node, FUNCTION_NODES):
        body = node.body
        return body if isinstance(body, JsBlockStatement) else None
    return node


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


def walk_receiver_scope(root: Node) -> Iterator[Node]:
    """
    Yield every node in the subtree at *root* that shares *root*'s `this`/`super` receiver, without
    descending into a nested regular or generator function, which rebinds `this`. Arrow functions are
    descended, since they inherit the receiver lexically. A class rebinds `this` for its method bodies
    and field initializers, but its `extends` clause and any computed member keys are evaluated in the
    enclosing receiver context, so only those parts of a class are descended. *root* itself is always
    yielded and descended, so a method reached directly through *root* is included.

    The receiver scope is also the *argument* scope: an arrow has no `arguments` object of its own and
    reads the enclosing one, a nested function has its own. So `references_own_arguments` asks the same
    boundary, and both live here rather than beside either caller.
    """
    stack: list[Node] = [root]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (JsFunctionExpression, JsFunctionDeclaration)) and node is not root:
            continue
        if isinstance(node, (JsClassDeclaration, JsClassExpression)):
            if node.super_class is not None:
                stack.append(node.super_class)
            if node.body is not None:
                for member in node.body.body:
                    if isinstance(member, (JsStaticBlock, JsErrorNode)):
                        continue
                    if member.computed and member.key is not None:
                        stack.append(member.key)
            continue
        stack.extend(node.children())


def _shares_the_receiver_of(parent: Node, child: Node) -> bool:
    """
    Whether *child*, a child of *parent*, is evaluated with the receiver *parent* is - the one step
    `walk_receiver_scope` takes, read from the child upwards rather than from the root down.

    The two have to agree, because they are one boundary asked from two directions: the walk gives
    every node under a receiver, and this gives the receiver of one node without a root to start
    from. A node has no receiver of its own unless something above it made one, so answering from
    below is what lets the question be asked of a node whose tree is being rewritten around it.
    """
    if isinstance(parent, (JsFunctionExpression, JsFunctionDeclaration, JsStaticBlock)):
        return False
    if isinstance(parent, (JsMethodDefinition, JsPropertyDefinition)):
        return parent.computed and child is parent.key
    if isinstance(parent, (JsClassDeclaration, JsClassExpression)):
        return child is parent.super_class or child is parent.body
    return True


def is_the_this_of_a_script(node: Node) -> bool:
    """
    Whether *node* is a `this` denoting what the top level of a classic script does, which is the
    global object: the position it stands in is reached from the top of the file without crossing
    anything that makes a receiver of its own.

    Written as a climb rather than as a walk from the root so that it answers for a node whose tree
    is being rewritten: a climb that runs out of parents has reached a root and answers `True`, so a
    node lifted out of the tree reads as the top level, which is the direction that keeps a
    declaration rather than removing one.

    An arrow crosses nothing - it has no `this` of its own - so a `this` inside any number of them
    is still the top level's, and so is one in the `extends` clause or a computed key of a class,
    which are evaluated where the class is written. A method, an accessor, a field initializer and a
    static block each hold one of their own. A decorator is not answered for, because no engine this
    is checked against parses one.
    """
    if not isinstance(node, JsThisExpression):
        return False
    child: Node = node
    cursor = node.parent
    while cursor is not None:
        if not _shares_the_receiver_of(cursor, child):
            return False
        child, cursor = cursor, cursor.parent
    return True


def references_own_arguments(fn: Node) -> bool:
    """
    Whether *fn* reads its own `arguments` object, rather than one belonging to a function around it or
    inside it. `walk_receiver_scope` draws that boundary: an arrow inherits the enclosing `arguments`
    and is descended, a nested regular or generator function has its own and is not.
    """
    return any(
        isinstance(node, JsIdentifier) and node.name == 'arguments' and is_use_position(node)
        for node in walk_receiver_scope(fn)
    )


def has_mapped_arguments(fn: Node, *, strict: bool) -> bool:
    """
    Whether *fn* observes an `arguments` object whose elements alias its parameters. Aliasing holds for
    a regular or generator function, in sloppy mode, with a simple parameter list: writing a parameter
    then writes `arguments[i]`, and writing `arguments[i]` writes the parameter. Strict mode gives an
    independent copy, and so does any default, rest or destructuring parameter; an arrow has no
    `arguments` of its own at all.

    *strict* is the mode *fn*'s body runs in and is supplied by the caller rather than derived here,
    because a payload being examined out of place has no tree above it to derive it from, and because
    module code is strict for a reason no node records.

    The parameter list must also be non-empty: `has_simple_parameters` answers §15.1.3, which an empty
    list satisfies, but with no parameters there is nothing for an element to alias.
    """
    if strict or not isinstance(fn, (JsFunctionExpression, JsFunctionDeclaration)):
        return False
    if not fn.params or not has_simple_parameters(fn):
        return False
    return references_own_arguments(fn)


def is_global_object_base(node: Node | None) -> bool:
    """
    Whether *node*, written as the base of a member access, denotes the global object - so that a
    property named on it is a global, and a property named on it at run time could be any global.

    Only the spelling is read. Parentheses around the base are looked through, because they change
    what a base is written as and nothing about what it denotes: `(window).eval` obtains the same
    intrinsic `window.eval` does, and a reader that saw the two differently would refuse a fold for
    one of them and not the other.

    Whether the name is bound to something else is a separate question, and the two callers want
    opposite answers to it, which is why it is not asked here.
    `SemanticModel.global_alias_member_name` asks it, because a reference it records has to be a
    reference to the global it names, and a local `window` names an ordinary object.
    `_is_reflective_member` deliberately does not: a surface it reports where there is none only
    refuses a fold, and one it misses removes code that runs.
    """
    base = strip_parens(node) if node is not None else None
    if base is None:
        return False
    if isinstance(base, JsThisExpression):
        return is_the_this_of_a_script(base)
    return isinstance(base, JsIdentifier) and base.name in GLOBAL_OBJECT_ALIASES


def may_be_global_object_base(node: Node | None) -> bool:
    """
    Whether *node*, written as the base of a member access, may denote the global object once the
    program runs. `is_global_object_base` widened by the receiver a call supplies: a function called
    with no receiver is given `undefined`, and sloppy code replaces that with the global object
    before the body runs, so a `this` in such a body reads the same properties the top level does.

    Which calls reach a body is not decided here, and every `this` is admitted rather than only the
    ones a bare call can reach. The two directions cost different things: admitting a receiver that
    is some other object keeps a declaration a reader may never reach, while missing one removes a
    declaration the program still reads.

    The readers that decide a *rewrite* keep the narrow question. `_is_reflective_member` does
    because a `this` reaches every method of every object in a file, and reporting a surface for one
    freezes every removal in it; `_timer_callee_name` because it names a callee it will act on.
    """
    base = strip_parens(node) if node is not None else None
    if isinstance(base, JsThisExpression):
        return True
    return is_global_object_base(base)


def member_property_name(member: JsMemberExpression) -> str | None:
    """
    The statically known property name a member access designates: the property identifier of a dot
    access (`o.g`) or the value of a string-literal computed access (`o['g']`). A non-literal computed
    key (`o[expr]`) has no static name and yields `None`. The base is not inspected — a caller that
    needs the base to be a global-object alias checks that separately.
    """
    prop = member.property
    if member.computed:
        return prop.value if isinstance(prop, JsStringLiteral) else None
    return prop.name if isinstance(prop, JsIdentifier) else None


def _last_positions(params: list[Binding | None]) -> list[Binding | None]:
    """
    *params* with every position a repeated parameter name occupies but the final one blanked out. A
    repeated name declares one binding, and only its last occurrence is the one an `arguments`
    element is mapped onto (§10.2.11), so every earlier position of a repeated name aliases nothing.
    """
    result = list(params)
    seen: set[int] = set()
    for index in reversed(range(len(result))):
        binding = result[index]
        if binding is None:
            continue
        if id(binding) in seen:
            result[index] = None
        seen.add(id(binding))
    return result


_DELETE_OPERATOR = frozenset({'delete'})


def _is_delete_operand(node: Node) -> bool:
    """
    Whether *node* stands as the operand of a `delete`. `reference_role` answers `Role.READWRITE`
    for such a reference as it does for a compound assignment, because both keep the name live as a
    read; only the assignment puts a value under the name.
    """
    return _is_unary_operand(enclosing_operator(node), node, _DELETE_OPERATOR)


def _displaces_arguments(
    binding: Binding,
    fn: JsFunctionExpression | JsFunctionDeclaration,
) -> bool:
    """
    Whether the name `arguments` inside *fn* denotes something other than the mapped object *fn* is
    given, either because no such object is ever created or because a value is put in its place.

    §10.2.11 creates no object at all where the name is a parameter of *fn*, or where the body
    declares it lexically (`let arguments;`) or as a function of its own: each of those puts the
    name in a list the creation is conditioned on, and the name then denotes whatever that
    declaration binds. An assignment over the name and a `var` that initializes it are the other
    case — the object is created and then replaced by a value whose elements alias no parameter.

    Three shapes displace nothing. A `var arguments;` with no initializer redeclares a name the
    function already has, and a `var` never overwrites a value already bound to its name, so the
    object and its aliasing are what they were; refusing it would stop recording the reads that keep
    a write to a parameter alive, and that write would then be dropped as dead. A `delete` of the
    name stores nothing — the binding is not configurable, so the operator evaluates to `false` and
    leaves the object where it was. And a function expression's own name is bound in an environment
    the object's own shadows, so `var f = function arguments(a) { return arguments[0]; }` still
    reads the mapped object; that site is skipped here because the scope model records the two names
    as one binding.

    The declarator distinction lives here because a declarator with an initializer is recorded as a
    declaration and not as a write, so asking for writes alone would let `var arguments = [7]` through.
    """
    if any(not _is_delete_operand(write) for write in binding.writes):
        return True
    for site in binding.declarations:
        if site is fn.id:
            continue
        declarator = site.parent
        if not isinstance(declarator, JsVariableDeclarator) or declarator.id is not site:
            return True
        if declarator.init is not None:
            return True
        declaration = declarator.parent
        if not isinstance(declaration, JsVariableDeclaration):
            return True
        if declaration.kind is not JsVarKind.VAR:
            return True
        if isinstance(declaration.parent, (JsForInStatement, JsForOfStatement)):
            return True
    return False


def own_arguments_binding(model: SemanticModel, fn: Node) -> Binding | None:
    """
    The binding the name `arguments` resolves to inside *fn*'s body when that is the arguments
    object the call to *fn* is given, or `None` where it is anything else. An arrow reads the
    object belonging to a function around it, which this call cannot supply — a lookup from its
    body would find that one. A name a parameter, a lexical declaration, an initialized `var`, a
    catch parameter or an assignment displaced denotes something whose elements alias nothing,
    which `_displaces_arguments` decides. A binding of kind `FUNC_NAME` is admitted alongside
    `ARGUMENTS` because a function expression whose own name is `arguments` binds that name in
    an environment the object's own shadows, so the body still reads the object.
    """
    if not isinstance(fn, (JsFunctionExpression, JsFunctionDeclaration)):
        return None
    scope = model.function_scope(fn)
    if scope is None:
        return None
    own = model.lookup('arguments', scope)
    if own is None or own.kind not in (BindingKind.ARGUMENTS, BindingKind.FUNC_NAME):
        return None
    if _displaces_arguments(own, fn):
        return None
    return own


def arguments_reads_only_elements(binding: Binding) -> bool:
    """
    Whether every reference to *binding* — an `arguments` object — reads it only element-wise:
    the receiver of a member access that is not a write target, with a computed key or the
    `length` key. Any other position hands the object to code the text alone does not read —
    a call argument, a second name, a spread, a coercion, a bare truth test — or writes through
    it, so a caller modelling the object from the call's argument values alone cannot answer
    for what the program does there. A reference from a nested arrow is included, because it
    reads this object and not one of the arrow's own.
    """
    for reference in [
        *binding.reads, *binding.writes, *binding.dynamic_refs, *binding.indefinite_writes,
    ]:
        member = _enclosing_member_access(reference)
        if member is None:
            return False
        if is_member_write_target(member):
            return False
        if not member.computed and member_property_name(member) != 'length':
            return False
    return True


def call_supplies_an_arguments_object(model: SemanticModel, fn: Node) -> bool:
    """
    Whether a call to *fn* may be handed the arguments object the name `arguments` denotes in its
    body, modelled from the argument values the call passes: the binding is the object
    (`own_arguments_binding`), every reference reads it element-wise
    (`arguments_reads_only_elements`), and — where sloppy mode links the elements to the
    parameters, so a written parameter is a value read back off the object — no parameter is
    written anywhere its name resolves to it. This is the admission every consumer shares: the
    interpreter binds the name exactly under it, and a fold asking which names a call supplies
    counts `arguments` only under it. A write to a parameter inside a nested function counts,
    because the binding it writes is this function's parameter and not the nested one's own.
    """
    own = own_arguments_binding(model, fn)
    if own is None:
        return False
    if not arguments_reads_only_elements(own):
        return False
    if not strict_mode_at(fn) and fn.params:
        for param in fn.params:
            binding = model.binding_of(param)
            if binding is None or binding.writes or binding.indefinite_writes:
                return False
    return True


def _is_global_alias_access(node: Node) -> bool:
    """
    Whether *node* is a member access on a global-object alias, which is the one kind of access that
    reaches a binding no lexical name of its own is written for. An access on a mapped `arguments`
    object is the other, and reaches a parameter of the one function that holds it.
    """
    return isinstance(node, JsMemberExpression) and may_be_global_object_base(node.object)


def _enclosing_member_access(node: Node) -> JsMemberExpression | None:
    """
    The member access *node* is the receiver of, looking through any parentheses written around it,
    or `None` where *node* is used as something other than a receiver. `(arguments)[0]` reaches its
    element exactly as `arguments[0]` does, so a receiver is recognized through a grouping the way
    every other operand in this module is — through the one climb `enclosing_operator` performs.
    """
    parent = enclosing_operator(node)
    if isinstance(parent, JsMemberExpression) and strip_parens(parent.object) is node:
        return parent
    return None


def _is_call_argument(node: Node) -> bool:
    """
    Whether *node* is written as an argument of a call or a `new`, so that evaluating the call hands
    what it denotes to a body this walk does not read. The callee position is not one: a call on the
    global object reaches the object as a receiver, which is the question
    `may_be_global_object_base` answers, and a call *of* it throws.
    """
    governor = enclosing_operator(node)
    if not isinstance(governor, (JsCallExpression, JsNewExpression)):
        return False
    return any(strip_parens(argument) is node for argument in governor.arguments)


def _enclosing_call(node: Node) -> JsCallExpression | JsNewExpression | None:
    """
    The call or `new` *node* is written as an argument of, looking through parentheses, or `None`
    when it is not an argument. This is the call whose body may observe what *node* denotes, and it
    is recognized the way `_is_call_argument` recognizes the position — the two ask one question,
    one for the answer and one for the call.
    """
    governor = enclosing_operator(node)
    if not isinstance(governor, (JsCallExpression, JsNewExpression)):
        return None
    if any(strip_parens(argument) is node for argument in governor.arguments):
        return governor
    return None


def _sole_returned_function(function: Node) -> JsFunctionNode | None:
    """
    The single function literal *function* returns to its caller, or `None` when it returns none or
    more than one. Only a `return` in *function*'s own receiver scope is one of its returns, so a
    `return` inside a function it defines is not counted; `walk_receiver_scope` draws that boundary.
    This is the shape a self-defending wrapper's factory takes — a zero-argument IIFE whose one
    `return` yields the `function(a, b)` that a guard site calls.
    """
    returned: list[JsFunctionNode] = []
    for node in walk_receiver_scope(function):
        if not isinstance(node, JsReturnStatement) or node.argument is None:
            continue
        value = strip_parens(node.argument)
        if isinstance(value, FUNCTION_NODES):
            returned.append(value)
    return returned[0] if len(returned) == 1 else None


_GLOBAL_ALIAS_CHAIN_LIMIT = 4
"""
How far `SemanticModel.names_the_global_object` follows one name to the next before it
gives up. A program names the global object once and reads through that name; a chain of four
is already past anything a file writes, and the bound is what keeps `var a = b, b = a` from
recurring forever.
"""


_HANDED_OBJECT_OBSERVATION_DEPTH = 4
"""
How far `SemanticModel.global_object_argument_is_observed` follows a handed object through nested
calls — a callee that hands its receiver on with `apply`, whose target hands it on again — before
it gives up and takes the object for observed. The obfuscator's self-defending wrapper is one hop
deep; the bound is what keeps a chain of mutual hand-offs from recurring forever.
"""


_IDENTITY_OPERATORS = frozenset({'typeof', 'void', '!'})
"""
The unary operators that take their operand to a type name or a truth value without entering the
object protocol. `+`, `-` and `~` are not in it: `ToNumber` calls `valueOf`, which a poisoned
`Object.prototype` answers with code that receives the operand as `this`.
"""


def _observes_identity_alone(governor: Node | None, operand: Node) -> bool:
    """
    Whether the construct governing a bare reference to a mapped `arguments` object observes only
    what the object is, never what it holds or where it goes: the operand of `typeof`, `void` or
    `!`, and the test of a branch, a loop or a conditional expression, take the object to a type
    name or a truth value without reading an element, writing one, or letting the object itself
    flow anywhere. `for-in` is here and `for-of` is not, because enumeration reads the key set,
    which a write to a parameter never changes — §10.2.11 keys the mapping by the call's arity —
    while iteration reads the elements.

    A statement that is the reference and nothing else is the plainest of them: it reads the
    binding and discards what it read, which is what `void` spells with a keyword in front. A
    statement value is unobservable in a function body, and a mapped `arguments` object is only
    ever named inside one, so nothing downstream can pick the object up from there.
    """
    if isinstance(governor, JsUnaryExpression):
        return _is_unary_operand(governor, operand, _IDENTITY_OPERATORS)
    if isinstance(governor, (
        JsIfStatement,
        JsWhileStatement,
        JsDoWhileStatement,
        JsForStatement,
        JsConditionalExpression,
    )):
        return strip_parens(governor.test) is operand
    if isinstance(governor, JsForInStatement):
        return strip_parens(governor.right) is operand
    if isinstance(governor, JsExpressionStatement):
        return strip_parens(governor.expression) is operand
    return False


def _reads_every_element_alone(governor: Node | None, operand: Node) -> bool:
    """
    Whether the construct governing a bare reference to a mapped `arguments` object reads the
    elements out of it and does nothing else: a spread copies the values and a synchronous `for-of`
    walks them, and both leave the object behind — the values escape, the object does not, and a
    value cannot write the parameter it was read from. Both walks go through the object's own
    `@@iterator`, which holds the values intrinsic from the moment of creation and can only be
    replaced through a member write that `_record_arguments_alias_references` already takes as an
    indefinite write of every parameter, so a program that could turn the walk into a write has
    refused every fold before this answer is consulted.

    `for await` is not one of them, and being one keyword away from a walk that is makes it worth
    saying why: asynchronous iteration asks for `@@asyncIterator` first, which §10.2.11 gives the
    object none of, so the lookup leaves the object and reaches `Object.prototype` — and whatever
    stands there is then called with the object as `this`. Node prints `10` rather than `3` for
    `f(2)` where `f` is `async function f(a) { for await (const v of arguments) {} return a + 1; }`
    and `Object.prototype[Symbol.asyncIterator]` writes `this[0]`, which is a parameter written
    through a walk this answer would have called incapable of writing one.
    """
    if isinstance(governor, JsSpreadElement):
        return strip_parens(governor.argument) is operand
    if isinstance(governor, JsForOfStatement) and not governor.is_await:
        return strip_parens(governor.right) is operand
    return False


def _aliased_parameter_positions(member: JsMemberExpression, count: int) -> range | None:
    """
    The parameter positions a member access on a mapped `arguments` object names, out of *count*
    parameters, or `None` where it names none of them because the key is not statically known. A key
    that is the canonical spelling of an index in range designates that one parameter; a key that is
    statically known and is not — `length`, `callee`, an index past the end of the list — designates
    the empty range, an element being the only thing that aliases anything.

    Naming and reaching are separate answers, which is why an unknown key is `None` rather than the
    whole range. Every position is in reach of such an access, but no position is *named* by it, and a
    caller that recorded the access's own role against each would turn one indefinite write into a
    definite write of every parameter.

    The key is read through `exact_integer` and `canonical_array_index` rather than through `int`,
    which raises on the infinities a Number literal may denote and accepts the non-ASCII digits a
    property key may spell.
    """
    prop = member.property
    if not member.computed:
        return range(0)
    if isinstance(prop, JsNumericLiteral):
        index = exact_integer(prop.value)
    elif isinstance(prop, JsStringLiteral) and prop.value is not None:
        index = canonical_array_index(prop.value)
    else:
        return None
    if index is None or not 0 <= index < count:
        return range(0)
    return range(index, index + 1)


def _is_a_named_global_object_base(node: Node | None) -> bool:
    """
    Whether *node* denotes the global object by one of the names written for it, which is
    `is_global_object_base` without the positional reading of `this`. Only `_timer_callee_name`
    reads it, and its docstring says why. Asked of the one reading rather than spelled a second
    time, so that what counts as a named base is decided in one place.
    """
    base = strip_parens(node) if node is not None else None
    return not isinstance(base, JsThisExpression) and is_global_object_base(base)


def _is_reflective_member(member: JsMemberExpression) -> bool:
    """
    Whether a member access is a reflective surface — one through which code obtains the
    `eval`/`Function` intrinsic or reads an unknown global by a runtime-computed name. A
    statically named property is a surface exactly when the name is a reflective intrinsic:
    `window.eval`, `g['Function']`, and the same under any unrecognized base, since the base may
    alias the global object. A computed access with a non-literal key is a surface when its base
    is a global-object alias (`window[expr]`), through which any global can be *read* at runtime;
    the one form that names no global is a plain write (`window[expr] = x`, the one position where
    the access is written without its prior value being read — `is_simple_assignment_target`),
    which stores a property and consults nothing, and is counted by
    `SemanticModel.has_opaque_global_write` instead. On any other base a computed access
    designates a property of one specific object and is not a surface.

    A `constructor` key whose yield flows onward is one more spelling of the read: what it hands
    out is a constructor — off a function value, the `Function` intrinsic itself — so an alias
    of it compiles strings the way the named intrinsic does. One only invoked in place or feeding a
    further non-surface read is left uncounted (`_prototype_surface_escapes`), the measured shape
    of the obfuscator's own defense payloads, which invoke `.constructor(...)` on values this
    detector cannot type.
    """
    prop = member.property
    if member.computed:
        if isinstance(prop, JsStringLiteral):
            if prop.value in REFLECTIVE_INTRINSICS:
                return True
            return prop.value == 'constructor' and _prototype_surface_escapes(member)
        if not is_global_object_base(member.object):
            return False
        return not is_simple_assignment_target(member)
    if not isinstance(prop, JsIdentifier):
        return False
    if prop.name in REFLECTIVE_INTRINSICS:
        return True
    return prop.name == 'constructor' and _prototype_surface_escapes(member)


def is_direct_eval_call(node: Node) -> bool:
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
    callee = strip_parens(node.callee)
    return isinstance(callee, JsIdentifier) and callee.name == 'eval'


def _timer_callee_name(callee: Node | None) -> str | None:
    """
    The timer/`execScript` function *callee* names, or `None` when it is not one. A bare identifier
    names the timer directly (`setTimeout(...)`); a member access on a global-object alias
    (`window.setTimeout(...)`, `globalThis['setInterval'](...)`) names the same global timer through
    the global object. Parentheses are transparent to the reference. Any other base designates a
    property of one specific object and is not the global timer. The base is not shadow-checked — a
    local `window` yielding a match only over-reports a reflection surface, the safe direction for the
    whole-program detector this feeds.

    A `this` is not read as the global object here even where it stands for one, which is the one
    place the two readings of a base part company. Over-reporting is safe for a surface and this
    detector accepts it, but a `this` reaches every method of every object in the file, so reading
    one as the global object would report a surface for `this.setTimeout(f)` on any receiver at all
    - and a surface freezes every removal in the file it is found in.
    """
    callee = strip_parens(callee)
    if isinstance(callee, JsIdentifier):
        return callee.name if callee.name in STRING_EVAL_NAMES else None
    if isinstance(callee, JsMemberExpression) and _is_a_named_global_object_base(callee.object):
        name = member_property_name(callee)
        return name if name in STRING_EVAL_NAMES else None
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

    def __init__(self, root: JsScript, environment: HostEnvironment = HostEnvironment.universal):
        self.root = root
        self.environment = environment
        self._node_scope: dict[int, Scope] = {}
        self._binding_of: dict[int, Binding] = {}
        self._reflection_surface: bool | None = None
        self._opaque_surface_sites: list[Node] | None = None
        self._opaque_global_write: bool | None = None
        self._opaque_global_write_sites: list[JsMemberExpression] | None = None
        self._opaque_global_write_sites_known = False
        self._recording_def_use = False
        self._dispatch_surface_reached: bool | None = None
        self._function_direct_eval_sites: dict[int, list[Node]] = {}
        self._function_unread_source_sites: dict[int, list[Node]] = {}
        self.root_scope: Scope = _ScopeBuilder(self).build(root)
        self._build_def_use()
        self._deleted_host_globals: frozenset[str] = self._scan_deleted_host_globals()

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

    def parameter_scope(self, func: Node) -> Scope | None:
        """
        The scope holding *func*'s parameters and the `arguments` object a call gives it, which is
        its body's scope but for a function whose parameter list holds an expression: that one binds
        them in a scope of its own standing between the body and what encloses the function.

        A consumer reading a parameter binding out of a scope's own `bindings` asks for this one.
        `function_scope` answers the body's, which for such a function holds neither.
        """
        scope = self.function_scope(func)
        if scope is None:
            return None
        parent = scope.parent
        if parent is not None and parent.kind is ScopeKind.PARAMS and parent.node is scope.node:
            return parent
        return scope

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
    ) -> list[ReferenceNode]:
        """
        Every reference (read or write) bound to *binding*, optionally omitting those that lie within
        the subtree of *exclude*. Each is a referencing identifier except where an object aliasing the
        binding stands in for one (see `Binding`).
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

    def read_has_dynamic_effect(self, node: Node) -> bool:
        """
        Whether reading *node* as a value resolves through a dynamic scope — a bare identifier inside a
        `with` body — so that evaluating it is not a pure, droppable, or reorderable operand. Reading the
        bare name consults the `with` object first: a matching property fires the object's getter (or a
        proxy trap), an observable side effect; a missing one falls through to the lexical binding, or,
        failing that, throws a `ReferenceError`. Neither the getter nor the throw can be proved absent for
        an unknown object, so any reference that crosses a dynamic scope is effectful regardless of a
        lexical fallback. False for a statically resolved reference and any non-reference node.
        """
        if not isinstance(node, JsIdentifier) or not self.is_reference(node):
            return False
        return crosses_dynamic_scope(self._node_scope.get(id(node)))

    def read_may_throw(self, node: JsIdentifier) -> bool:
        """
        Whether evaluating *node* as a read may throw a `ReferenceError` because the name it spells
        is not certain to denote a binding. The companion to `read_has_dynamic_effect`, which asks
        what else a read may do; this asks whether it may not happen at all. A caller that treats an
        unresolved read as free is asserting the host defines the name, which for a name the program
        neither declares nor assigns is an assertion about someone else's global object.

        A name resolves for certain when a declaration binds it, or when the pinned host environment
        guarantees it on the global object (`HostEnvironment.provides`). The default `universal`
        environment provides exactly `GUARANTEED_GLOBALS`, the existence allowlist the language
        mandates everywhere, so `globalThis` resolves while the other `GLOBAL_OBJECT_ALIASES` spellings
        (`window`, `self`, `top`, `frames`, `global`) are a *host* assumption rather than a language
        one, and are not admitted: no host defines all of them, so a bare `window` throws under Node
        exactly as a bare `global` throws in a browser. An analyst who knows the host pins it with the
        `js` unit's `-e` switch, and the names that host guarantees become certain here, recovering the
        reading the sound default refuses — except a host-conditional global the program `delete`s off a
        same-realm alias, which `_scan_deleted_host_globals` withholds program-wide so the bare read
        keeps its throw. Unpinned, the read is answered may-throw so no pass drops the `ReferenceError`
        the absent host raises, and `_base_is_safe` agrees, refusing to clear a property access on such
        an alias. Everything else may not be there:

        - a free name, which reaches the host and may simply not exist
        - a name whose only binding is an `IMPLICIT_GLOBAL`, which the assignment that creates it
          brings into existence, so a read that runs first — or whose creating assignment sits in a
          function nobody calls — throws exactly as a free name does
        - a name resolved through a `with` body whose object may not carry it and which has no
          lexical binding to fall through to, which the `cross_dynamic` lookup is what distinguishes

        A reference that is written and not read answers `False`, as do the two operator positions
        `tolerates_unresolvable` names. The write case is a scope boundary, not a claim that
        writing is safe: sloppy code assigning to a name nothing binds creates a property of the
        global object, while strict code throws the same `ReferenceError` a read does, which is a
        separate defect with its own pin
        (`test_unfixed_defects.A_STRICT_REGION_ASSIGNING_TO_NO_BINDING`).
        """
        if not self.is_reference(node) or reference_role(node) is Role.WRITE:
            return False
        if self._certainly_resolves(node.name):
            return False
        if tolerates_unresolvable(node):
            return False
        scope = self._node_scope.get(id(node))
        binding = self.lookup(node.name, scope, cross_dynamic=True)
        return binding is None or binding.kind is BindingKind.IMPLICIT_GLOBAL

    def _certainly_resolves(self, name: str) -> bool:
        """
        Whether a bare read of *name* is guaranteed to find a global the host defines, so it cannot
        raise a `ReferenceError`. The pinned `environment` answers which names the host provides; a
        host-conditional global the program deletes off a same-realm global alias is withheld, since
        after that delete the bare read throws. A language-mandated name is never withheld, so the
        default `universal` environment answers exactly as its `GUARANTEED_GLOBALS` membership did.
        """
        if not self.environment.provides(name):
            return False
        return not (
            name in self._deleted_host_globals
            and self.environment.withholds_on_delete(name)
        )

    def _scan_deleted_host_globals(self) -> frozenset[str]:
        """
        The host-conditional global names the program deletes off a global-object alias anywhere
        (`delete globalThis.Buffer`, `delete window['setTimeout']`), whose presence the pinned host
        would otherwise assert. The scan is flow-insensitive: a delete on any path, reachable or not,
        withholds the name program-wide, which over-keeps a read's throw and so stays sound. It keys on
        the wide `GLOBAL_OBJECT_ALIASES`, not the same-realm subset, because `top` and `frames` name
        this realm's own global object in an unframed document, so a delete spelled through one there
        removes the name here too; withholding on a framed document's cross-realm delete only over-keeps
        a throw, which stays sound. It is the empty set under the default `universal` environment, which
        withholds nothing and so needs no scan, keeping an unpinned run free of the walk. A delete
        reached through a variable holding the global object rather than through an alias spelling is not
        modelled, the limit the rest of the global-object analysis shares.
        """
        if self.environment is HostEnvironment.universal:
            return frozenset()
        deleted: set[str] = set()
        for node in self.root.walk():
            if not (isinstance(node, JsUnaryExpression) and node.operator == 'delete'):
                continue
            target = strip_parens(node.operand)
            if not isinstance(target, JsMemberExpression):
                continue
            base = strip_parens(target.object)
            if not isinstance(base, JsIdentifier):
                continue
            if base.name not in GLOBAL_OBJECT_ALIASES:
                continue
            if self.lookup(base.name, self._node_scope.get(id(base))) is not None:
                continue
            name = static_property_key(target)
            if name is not None:
                deleted.add(name)
        return frozenset(deleted)

    def lexical_binding_read(self, node: JsIdentifier) -> Binding | None:
        """
        The `let`/`const`/`class` binding *node* reads, or `None` when *node* is not a read of
        one. A read of such a binding resolves for certain, yet may still raise a
        `ReferenceError` when it runs before the declaration that ends the binding's temporal
        dead zone; a caller that needs the binding — to defer it to a call site
        (`EffectSummary.dead_zone_reads`) — takes it from here rather than resolving a second
        time. Whether the read is in fact in the dead zone is an ordering question this layer
        does not answer — a caller's establishment proof (`ModelCache.read_established`) decides
        it against the dominance model.
        """
        if not self.is_reference(node) or reference_role(node) is Role.WRITE:
            return None
        binding = self.resolve(node)
        return binding if binding is not None and binding.is_lexical else None

    def reads_lexical_binding(self, node: JsIdentifier) -> bool:
        """
        Whether *node* is a read of a `let`, `const`, or `class` binding. The companion flag to
        `read_may_throw`, which instead flags a name that may denote no binding at all; together
        they are the complete set of reads a discarding context must not drop without a proof the
        read is past its establishing point. The binding itself, when a caller needs it, comes from
        `lexical_binding_read`.
        """
        return self.lexical_binding_read(node) is not None

    def read_may_raise_reference_error(self, node: JsIdentifier) -> bool:
        """
        Whether evaluating *node* as a read may raise a `ReferenceError`: it may denote no binding at
        all (`read_may_throw`) or it reads a `let`/`const`/`class` binding that may still be in its
        temporal dead zone (`reads_lexical_binding`). The one flag a discarding context tests before
        dropping a read; a context holding an ordering proof clears the dead-zone case through it
        (`EffectModel.read_throws`), a context holding none fails closed and keeps the read
        (`EffectModel._read_effectful_or_throwing`).
        """
        return self.read_may_throw(node) or self.reads_lexical_binding(node)

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

    def invocation_binding(self, function: Node) -> Binding | None:
        """
        The binding whose value-reads are the sites through which *function* is invoked — its
        `naming_binding`, extended to a lone assignment installing it in an already-declared name
        (`f = function(){}`) as well as a named declaration or a declarator initializer. `None` for a
        function with no such name — an anonymous IIFE or callback, or one stored through a member or
        other non-identifier target — whose invocation cannot be pinned to a name. Unlike `naming_binding`
        this also recognizes the bare-assignment form, so a function held in a hoisted `var` assigned once
        is ordered by its calls rather than by its creation; a caller confirms the binding is singly
        declared, `binding_pinned_to` *function*, and free of dynamic references before trusting its reads
        to enumerate every invocation.
        """
        binding = self.naming_binding(function)
        if binding is not None:
            return binding
        parent = function.parent
        if (
            isinstance(parent, JsAssignmentExpression)
            and parent.operator == '='
            and parent.right is function
        ):
            target = strip_parens(parent.left)
            if isinstance(target, JsIdentifier):
                return self.resolve(target)
        return None

    def binding_pinned_to(self, binding: Binding, function: Node) -> bool:
        """
        Whether *binding* holds *function* as its one assigned value, so every read of it outside the
        value's temporal dead zone denotes *function* and its reads enumerate *function*'s invocations.
        True when the binding's only write is the assignment that establishes *function* — a bare
        `name = function(){}` records that target as its sole write — and false once any other write could
        give the name a different value. A named function declaration or a declarator initializer installs
        the value with no recorded write, so any write at all is a reassignment that unpins it. The
        single-declaration and dynamic-reference checks a caller also needs are left to the caller; this
        answers only the reassignment question — the whole of it, so a write that leaves no `writes`
        entry because nothing says what it stored (`has_indefinite_write`) unpins the name as much
        as one that does.
        """
        parent = function.parent
        establishing = None
        if (
            isinstance(parent, JsAssignmentExpression)
            and parent.operator == '='
            and parent.right is function
        ):
            establishing = strip_parens(parent.left)
        if binding.has_indefinite_write:
            return False
        return all(write is establishing for write in binding.writes)

    def object_property_reference_points(self, function: Node) -> list[Node] | None:
        """
        The reference points that no invocation of *function* can precede when it is installed as a
        property of a non-escaping local object — the read sites of that property. Returns them when
        *function* is the value of a `BASE.key = function` assignment whose `BASE` identifier resolves to
        a local binding that holds one object value (`singular_value` is a `JsObjectExpression`) and never
        escapes as a bare value — every reference to it is the object of a member access, so the object
        identity is pinned to that binding and the only way to obtain the callable is to read `BASE.key`.
        Every such read is a point the invocation follows, including one whose value is stored and called
        later; the establishing write installs the value without reading it and is excluded, as is an
        access of a statically different property, which never reads the value. A computed access whose
        key is not statically known (`BASE[expr]`) may read the property and is kept. The opaque reflective
        surfaces that could name the binding are added as points exactly as the name-based enumeration adds
        them, and a `with` that could rename the base (a `dynamic_refs` entry) makes the ordering
        unknowable and yields `None`, as does any pattern the recognition does not match, so a caller falls
        through to its name-based ordering.

        This is a bounded points-to fact: a method reached only through property reads on an object that
        never leaks is ordered by those reads, not by its creation site, which a member assignment target
        gives no name to order by. It answers, at the binding level, the ordering `invocation_binding`
        cannot when the callable is pinned to a member rather than a name.
        """
        parent = function.parent
        if not (
            isinstance(parent, JsAssignmentExpression)
            and parent.operator == '='
            and parent.right is function
        ):
            return None
        target = strip_parens(parent.left)
        if not isinstance(target, JsMemberExpression) or not isinstance(target.object, JsIdentifier):
            return None
        key = member_property_name(target)
        if key is None:
            return None
        binding = self.resolve(target.object)
        if binding is None or not isinstance(self.singular_value(binding), JsObjectExpression):
            return None
        if binding.dynamic_refs:
            return None
        points: list[Node] = []
        for read in binding.reads:
            node = read
            access = node.parent
            while isinstance(access, JsParenthesizedExpression):
                node, access = access, access.parent
            if not isinstance(access, JsMemberExpression) or access.object is not node:
                return None
            name = member_property_name(access)
            if name is not None and name != key:
                continue
            if is_simple_assignment_target(access):
                continue
            points.append(access)
        points.extend(
            site
            for site in self.reflection_surface_sites(binding)
            if not site.is_descendant_of(function)
        )
        return points

    def binding_values(
        self, binding: Binding | None, *, ignore_dynamic_rebinds: bool = False,
    ) -> tuple[list[Node], bool]:
        """
        Every value expression the text stores under *binding* through a channel that spells its stored
        value, in no promised order, and whether that list is complete — whether no other channel can
        give the name a value.
        The readable channels are a declarator's initializer, the function or class of a declaration,
        and the right side of a plain `=` written through the referencing identifier. Every other way a
        value can arrive makes the answer incomplete without contributing a value: **every** parameter
        is incomplete, because the call site is a value channel this model cannot see, and so are a
        catch or import binding and a function expression's own name; a compound assignment, an update,
        a `for-in`/`for-of` head, and a destructuring target store a value they do not spell; a write
        recorded with no value and a dynamic rebinding (`binding_maybe_reassigned_dynamically`) say a
        value arrived without saying which. A write through a member access on a global-object alias is
        left unread and breaks completeness too, because the walk recording those entries consults this
        query through `names_the_global_object`, so an answer built on them would depend on how far
        that walk had got. A binding with no declaration — an implicit global, and the binding
        `_ensure_implicit_global_from_alias_write` mints — contributes nothing and is never complete,
        for that same walk-order reason. With *ignore_dynamic_rebinds* the dynamic-rebind conjunct is
        left out of the completeness verdict: the values answer what the text spells, and whether a
        rebind crosses a given read is the caller's ordering question over `binding_dynamic_rebind_sites`.

        The values hold wherever the name is not in their temporal dead zone; a bare declarator
        contributes no value even though the name reads `undefined` there, and a consumer that needs a
        value established before a use orders it separately (`binding_establishment_sites`). A
        recognizer whose safe direction is admitting decides on ANY value and ignores completeness; a
        consumer whose rewrite needs the binding to hold nothing else requires completeness first, and
        must also require a value, since a complete empty list answers every universal question
        vacuously. `refinery.lib.scripts.js.analysis.effects._binding_value_roots` is the may-side
        sibling that over-approximates where this list refuses, and
        `refinery.lib.scripts.js.analysis.reaching.ReachingModel._value_definitions` the flow-aware one
        that enumerates kill sites rather than values.
        """
        channels, complete = self._binding_value_channels(
            binding, ignore_dynamic_rebinds=ignore_dynamic_rebinds)
        return [value for _, value in channels], complete

    def values_at_call(
        self,
        binding: Binding | None,
        arguments: dict[Binding | None, Node | None],
    ) -> tuple[list[Node], bool]:
        """
        `binding_values` read at one call site: *arguments* maps each parameter binding of the
        called function to the argument that call supplies for it (`_argument_parameter_map`), and
        for a binding it covers, the mapped argument is the entry channel `binding_values` cannot
        see — so the answer can be complete where the plain query never is. A parameter the
        call supplies no argument for maps to `None` and stays incomplete. Every other rule is
        `binding_values`' own: a write the text spells no value for, and any dynamic rebinding —
        a direct `eval` in the function, and a write through its own `arguments` object — still
        poison the answer. For a binding *arguments* does not cover, the answer is exactly
        `binding_values`.
        """
        channels, complete = self._binding_value_channels(binding, arguments)
        return [value for _, value in channels], complete

    def _binding_value_channels(
        self,
        binding: Binding | None,
        arguments: dict[Binding | None, Node | None] | None = None,
        *,
        ignore_dynamic_rebinds: bool = False,
    ) -> tuple[list[tuple[Node, Node]], bool]:
        """
        The readable value channels of *binding* as `(site, value)` pairs — the node whose execution
        installs the value, and the value expression — plus the completeness verdict `binding_values`
        documents. One derivation feeds `binding_values`, `values_at_call`, `singular_value`, and
        `binding_establishment_sites`, so they can never disagree about which channels a binding
        has. With *arguments* — a call's parameter-to-argument map — a parameter declaration of a
        covered binding is a readable channel carrying the mapped argument, the `values_at_call`
        reading; without it, a parameter declaration is an unseen channel. With
        *ignore_dynamic_rebinds* the dynamic-rebind conjunct is left out of the completeness
        verdict: the channels answer the one value the text spells, and whether a rebind crosses a
        given read stays the caller's ordering question over `binding_dynamic_rebind_sites`. The
        value of a lone-assignment channel is returned with its parentheses stripped, the
        normalization every consumer of `singular_value` has always received there.
        """
        if binding is None or not binding.declarations:
            return [], False
        channels: list[tuple[Node, Node]] = []
        complete = (
            ignore_dynamic_rebinds
            or not self.binding_maybe_reassigned_dynamically(binding)
        )
        for declaration in binding.declarations:
            parent = declaration.parent
            if (
                isinstance(parent, (JsFunctionDeclaration, JsClassDeclaration))
                and parent.id is declaration
            ):
                channels.append((parent, parent))
            elif isinstance(parent, JsVariableDeclarator) and parent.id is declaration:
                if _loop_head_assigns(parent):
                    complete = False
                if parent.init is not None:
                    channels.append((parent, parent.init))
            elif (
                arguments is not None
                and binding in arguments
                and isinstance(parent, FUNCTION_NODES)
                and declaration in parent.params
            ):
                argument = arguments[binding]
                if argument is None:
                    complete = False
                else:
                    channels.append((declaration, argument))
            else:
                complete = False
        for write in binding.writes:
            assignment = write.parent
            stored = None
            if (
                isinstance(write, JsIdentifier)
                and isinstance(assignment, JsAssignmentExpression)
                and assignment.operator == '='
                and strip_parens(assignment.left) is write
            ):
                stored = strip_parens(assignment.right)
            if stored is None:
                complete = False
            else:
                channels.append((write, stored))
        return channels, complete

    def singular_value(self, binding: Binding | None) -> Node | None:
        """
        The single value node a *binding* provably holds: the sole entry of a complete
        `binding_values` answer. `None` when the binding is absent, stores more than one value, or has
        any channel the text does not spell — a name whose declaration carries a value and is then
        assigned holds two values across its life and is refused, as is every parameter. The value is
        what the name denotes wherever it is not in the value's temporal dead zone; a consumer that also
        needs the value established before a use orders it separately, since a bare-assignment binding
        reads `undefined` before its write. `EffectModel.function_of` is the function-typed specialization
        of this query, and it is the value-resolution the bare-assignment recognition sites route through
        instead of re-deriving binding shapes.
        """
        channels, complete = self._binding_value_channels(binding)
        if not complete or len(channels) != 1:
            return None
        return channels[0][1]

    def establishment_sites(self, function: Node) -> list[Node] | None:
        """
        The nodes that must all have executed before *function*'s callable value is installed under the
        name it is invoked through, for a consumer that gates a use on execution order. The
        function-invocation view of `binding_establishment_sites`: `None` when *function* is not invoked
        through a single orderable name, so its presence cannot be ordered and the caller declines.
        """
        return self.binding_establishment_sites(self.invocation_binding(function))

    def binding_establishment_sites(
        self, binding: Binding | None, *, ignore_dynamic_rebinds: bool = False,
    ) -> list[Node] | None:
        """
        The nodes that must all have executed before *binding*'s `singular_value` is installed, for a
        consumer that gates a use on execution order. An empty list when the value is hoisted into place
        before any statement runs — a function declaration — so no ordering is required; the declarator
        when the value is a `var`/`let`/`const` initializer, which is absent until that declarator runs;
        the class declaration when the value is a class, which is in its temporal dead zone until it runs;
        the recorded write when a lone assignment installs it (`f = function(){}`, the form namespace
        flattening leaves). `None` when the binding holds no single such value, so its presence cannot
        be ordered and the caller declines — decided by the same complete-singleton `binding_values`
        answer `singular_value` requires, so the two queries can never disagree about which bindings
        have an orderable value: one returns the value and the other the node that establishes it.
        With *ignore_dynamic_rebinds* that answer is read on the view `binding_values` documents, the
        one a positioned consumer orders rebind hazards against itself. Ordering the returned nodes
        against the use is the caller's job, since that needs the
        dominance model this layer must not depend on.
        """
        if binding is None:
            return None
        channels, complete = self._binding_value_channels(
            binding, ignore_dynamic_rebinds=ignore_dynamic_rebinds)
        if not complete or len(channels) != 1:
            return None
        site, _ = channels[0]
        if isinstance(site, JsFunctionDeclaration):
            return [site] if annex_b_copies_into(binding) else []
        return [site]

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
        for node in name_uses_in_scope(names, scope):
            if not self.is_shadowed(node.name, node, scope):
                return True
        return False

    def has_reflection_surface(self) -> bool:
        """
        Whether the program still contains a construct through which code could reference a global
        by name at runtime: a value-read of the `eval` or `Function` intrinsic in any form — a
        direct or indirect call, an alias (`var e = eval`), a comma sequence (`(0, eval)`), or a
        member access (`window.eval`, `g['Function']`) — a string-valued timer, a dynamic property
        read on the global object (`window[expr]`), a `with` statement, or a span of source this
        model never read, which may spell a name nothing here records. Computed conservatively
        (over-reporting is safe): while any such surface remains, a dead global must not be removed,
        because reflective code may read it. A computed global *write* names no global
        (`has_opaque_global_write` owns that question) and is not counted here.
        """
        self._ensure_reflection_detected()
        assert self._reflection_surface is not None
        return self._reflection_surface

    def has_opaque_global_write(self) -> bool:
        """
        Whether the program stores a property on the global object under a key only the runtime
        resolves (`window[expr] = x`), so an intrinsic or a script-scope name may hold something
        else than what the text spells once the program runs. The read-naming question
        `has_reflection_surface` answers is unaffected by such a write — storing a property names
        nothing and runs nothing — but the *replacement* questions are not: a written key may be
        `Math`, `String`, or the name a top-level `var` carries, so a consumer that trusts an
        intrinsic by name, or that a script-scope binding keeps its spelled value, refuses while
        this holds.

        Detection is model-aware, distinct from the spelling-level exemption
        `_is_reflective_member` grants the same sites: a base may be the global object here
        (`may_be_the_global_object`), so a local holding the object (`var g = globalThis;
        g[k] = 1`) and the receiver a sloppy call supplies a write through (`this[k] = 1`) are
        both counted, not only its spelled names — the alias would otherwise store a global under
        a key the spelling never saw, and the receiver is the one spelling a callee can choose
        freely. Every store form counts
        (`is_member_write_target`: plain and compound assignment, update, `delete`, `for-in`/`for-of`
        heads, destructuring patterns), so the fact stands on its own wherever a consumer consults it.
        Computed lazily and memoized,
        but never while `_record_def_use_references` is still recording: that walk is what fills the
        `binding.writes` list `binding_values` reads, so an answer taken mid-walk would depend on how
        far it had got; asked there, the conservative `True` is answered instead of a partial fact.
        The alias-recording walks that follow consult only value facts those first walks froze, so
        the answer they get is the final one.
        """
        if self._recording_def_use:
            return True
        if not self._opaque_global_write_sites_known:
            self._compute_opaque_global_write_sites()
        return self._opaque_global_write is True

    def _compute_opaque_global_write_sites(self) -> None:
        sites = [
            member for member in self.root.walk()
            if isinstance(member, JsMemberExpression) and self._is_opaque_global_write(member)
        ]
        self._opaque_global_write_sites = sites
        self._opaque_global_write_sites_known = True
        if sites and self._opaque_global_write is None:
            self._opaque_global_write = True

    def opaque_global_write_sites(self) -> list[JsMemberExpression] | None:
        """
        The member expressions storing a property on the global object under a key only the runtime
        resolves — the located form of the fact `has_opaque_global_write` reports, for a consumer
        that orders the fact's consequences rather than refusing on it. `None` when the fact holds
        without a site to order: an observed hand-over of the object to a callee that may write it,
        or an answer taken while the reference-recording walk is still running, where the boolean
        answers `True` for the same reason. A consumer that turns sites into kills treats `None` as
        volatility it cannot locate.
        """
        if self._recording_def_use:
            return None
        if not self._opaque_global_write_sites_known:
            self._compute_opaque_global_write_sites()
        sites = self._opaque_global_write_sites
        assert sites is not None
        if sites or self._opaque_global_write is not True:
            return sites
        return None

    def opaque_global_write_replacement_sites(self, binding: Binding) -> list[JsMemberExpression] | None:
        """
        The opaque global writes that could replace the value *binding* holds, or `None` when that
        question cannot be answered in sites. Only a script-scope name is replaceable — it is a
        property of the global object under the script execution model the write stores to — so a
        binding in any other scope answers `None`: its reflection hazards, if any, are not this
        write's. A script-scope name under a reflection surface answers `None` too, since any surface
        could write the name from anywhere, and so does the fact when it holds without a site
        (`opaque_global_write_sites`). `None` therefore means the binding is reflection-reachable for
        reasons no located site spells, and a consumer that turned sites into kills keeps the value
        volatile instead.
        """
        owner = binding.scope.var_scope
        if owner is None or owner.kind is ScopeKind.SCRIPT:
            if self.has_reflection_surface():
                return None
            return self.opaque_global_write_sites()
        return None

    def _is_opaque_global_write(self, member: JsMemberExpression) -> bool:
        if not member.computed or isinstance(member.property, JsStringLiteral):
            return False
        if not is_member_write_target(member):
            return False
        return self.may_be_the_global_object(member.object)

    def reflection_can_reach(self, binding: Binding) -> bool:
        """
        Whether a runtime name lookup could read or write *binding* without a reference this model
        records. Derived over the precise dynamic-scope facts. A global is reachable through any
        reflective surface — `eval`, `Function`, a string timer, dynamic global access, `with` — all
        of which run in the global scope, so it defers to the whole-program
        `has_reflection_surface`, and by an opaque global write rebinding its name
        (`has_opaque_global_write`), which no reference records either. A function-local is
        reachable only from within its own function and only by name: a `with` body that names
        it (a `dynamic_references` entry), a direct `eval` in the function
        (`local_reachable_by_direct_eval`), or a span of the function this model never read
        (`unread_source_can_reach`), which may spell the name where nothing records that it does.
        A `with` that never names it cannot reach it, and reflective code in the global scope
        cannot name a local — so the local answer is exact, while the global one stays
        conservative (any surface).
        """
        owner = binding.scope.var_scope
        if owner is None or owner.kind is ScopeKind.SCRIPT:
            return self.has_reflection_surface() or self.has_opaque_global_write()
        return (
            bool(binding.dynamic_refs)
            or self._function_has_direct_eval(owner.node)
            or bool(self._unread_source_sites(owner.node))
        )

    def reachable_by_opaque_reflection(self, binding: Binding) -> bool:
        """
        Whether an opaque reflective surface — a value-read of `eval` or `Function`, a string timer,
        a dynamic access on the global object, or a span of source this model never read — could
        name *binding* at runtime with no reference this model records. Unlike
        `reflection_can_reach`, a `with` body is not counted: a `with` that names the binding is
        attributed precisely as a `dynamic_references` entry, so a caller that already consults
        `dynamic_refs` needs only the opaque surfaces here, the ones that leave no attributable
        reference. A global is reachable through any such surface, all of which run in the global
        scope; a function-local only through a direct `eval` or an unread span in its own function,
        since a surface running in the global scope cannot name a local. The boolean companion of
        `reflection_surface_sites` — true exactly when that site list is non-empty.
        """
        return bool(self.reflection_surface_sites(binding))

    def reflection_surface_sites(self, binding: Binding) -> list[Node]:
        """
        The AST nodes of the opaque reflective surfaces that could name *binding* at runtime with no
        reference this model records — the points no reflected invocation of it can precede. A
        caller ranks a definition against these to prove it runs before every such invocation, the
        site-level companion of `reachable_by_opaque_reflection`. For a global (script-scope)
        binding they are the whole-program opaque surfaces (`opaque_reflection_sites`), each
        running in the global scope and able to name any global; for a function-local, the direct
        `eval` sites in its owning function (`_direct_eval_sites`) and the spans of that function
        this model never read (`_unread_source_sites`), the only opaque surfaces that stand in the
        local's own scope and can name it. Empty exactly when the binding is not opaque-reflection
        reachable. A `with` surface is not included — a `with` that names the binding is attributed
        as a `dynamic_references` entry a caller consults separately.
        """
        owner = binding.scope.var_scope
        if owner is None or owner.kind is ScopeKind.SCRIPT:
            return self.opaque_reflection_sites()
        return self._direct_eval_sites(owner.node) + self._unread_source_sites(owner.node)

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

    def unread_source_can_reach(self, binding: Binding) -> bool:
        """
        Whether a span of source this model never read stands where it could name *binding*. Such a
        span is text the file holds at a definite position, and nothing says what it references, so
        everything in scope where it stands may be read or written by it with no reference this
        model records. A binding of the script is within reach of every span in the file; a
        function-local only of one inside its own function, since no span outside it can name a
        local.

        This is not folded into the `eval` answers, even though both surfaces are opaque, because
        the two are known to different degrees. Whether an `eval` anywhere in a file rebinds a given
        global is a question about text no one has, and freezing every global on it is the
        over-approximation `local_reachable_by_direct_eval` documents as refused; an unread span is
        the file's own text, standing in one place, and refusing to count it is what drops the write
        that text spells.
        """
        owner = binding.scope.var_scope
        if owner is None or owner.kind is ScopeKind.SCRIPT:
            return bool(self._unread_source_sites(self.root))
        return bool(self._unread_source_sites(owner.node))

    def free_name_reachable_by_direct_eval(self, node: Node) -> bool:
        """
        Whether a direct `eval` could have installed a binding that a free name at *node* reads instead
        of the global one. `resolve` answering `None` means this model saw no declaration of the name,
        which is not the same as there being none: `eval('var undefined = 4')` declares one that no
        reference here records, and a read of that name afterwards is the binding, not the global.

        Only `var` and function declarations escape an `eval` — a `let` inside one lives in a scope
        discarded with the call — so a binding it installs lands in the var scope the call itself stands
        in, and is visible at *node* exactly when that var scope contains *node*'s scope. This is the
        mirror of `local_reachable_by_direct_eval`, which asks whether an `eval` can name a binding that
        already exists and therefore counts one nested *below* the binding's owner; a nested `eval`
        declares into its own function and so is not counted here.

        An `eval` whose own argument contains *node* is excluded, and that exclusion is about order
        rather than scope: the arguments of a call are evaluated before the call runs, so the code the
        `eval` is about to execute cannot have declared anything the argument reads. Without it,
        `eval(atob('...'))` — the shape most of this tool's corpus is written in — would refuse to read
        `atob` on the strength of the very `eval` it is decoding the body of.
        """
        scope = self.scope_of(node)
        if scope is None:
            return True
        enclosing = {id(node)}
        cursor = node.parent
        while cursor is not None:
            enclosing.add(id(cursor))
            cursor = cursor.parent
        for site in self._direct_eval_sites(self.root):
            if any(id(argument) in enclosing for argument in getattr(site, 'arguments', ())):
                continue
            site_scope = self.scope_of(site)
            owner = site_scope.var_scope if site_scope is not None else None
            if owner is None or owner.contains(scope):
                return True
        return False

    def binding_dynamic_rebind_sites(self, binding: Binding) -> list[Node] | None:
        """
        The AST nodes at which a dynamic scope could rebind *binding*, or `None` for the one such
        rebind that holds no node to order — the write a call makes on entry (`written_at_entry`),
        which the text does not spell. The located form of
        `binding_maybe_reassigned_dynamically`, which is re-derived from this answer, so the two
        can never disagree about which bindings are volatile: a consumer that gets a list holds a
        hazard per node, and one that gets `None` holds the nodeless kill. Each leg of the boolean
        contributes its nodes — a write through an object that aliases the binding
        (`indefinite_writes`), a `with`-body reference whose role is not a plain read, a direct
        `eval` in the owning function, and a span of source the model never read — with the two
        scope lines the boolean draws drawn identically: the eval leg is a function-local's only
        (a global is not frozen on a global-scope surface), and the unread-source leg reaches a
        global from anywhere in the file but a local only from its own function. An empty list is
        a binding no dynamic scope can rebind.
        """
        if binding.written_at_entry:
            return None
        owner = binding.scope.var_scope
        sites = list(binding.indefinite_writes)
        if owner is None or owner.kind is ScopeKind.SCRIPT:
            sites.extend(self._unread_source_sites(self.root))
        else:
            sites.extend(self._direct_eval_sites(owner.node))
            sites.extend(self._unread_source_sites(owner.node))
        sites.extend(
            ref for ref in self.dynamic_references(binding)
            if reference_role(ref) is not Role.READ
        )
        return sites

    def binding_maybe_reassigned_dynamically(self, binding: Binding) -> bool:
        """
        Whether a dynamic scope could rebind *binding* — give the name a new value through a surface
        the static `writes` set does not record. A `with` body that names it as an assignment target
        may rebind it (the target may instead be a property of the `with` object, but may equally be
        this binding, so it is treated as a possible rebind), a direct `eval` in its owning function
        can rebind it opaquely, and so can a span of source this model never read
        (`unread_source_can_reach`), whose text may spell an assignment to the name. A member write
        or method call through the name does not rebind it — the name keeps its value — so only a
        dynamic reference whose role is not a plain read counts. A write through an object that
        aliases the binding — `indefinite_writes` — is counted here too: it replaces the value under
        the name while leaving no entry that says with what. A consumer that judges a binding's
        value stable from `writes` alone must also consult this, since none of these reassignments
        leaves a `writes` entry; a script-scope binding reassigned only through an opaque `eval`
        stays the documented residual, as `local_reachable_by_direct_eval` reports it false there.
        The boolean form of `binding_dynamic_rebind_sites`: true exactly when that answer is
        `None` or holds a node.
        """
        sites = self.binding_dynamic_rebind_sites(binding)
        return sites is None or bool(sites)

    def binding_never_reassigned(self, binding: Binding) -> bool:
        """
        Whether *binding* holds one value for its whole lifetime: it is never written after its
        declaration, statically (`writes`) or through a dynamic scope
        (`binding_maybe_reassigned_dynamically`). This is the value-stability contract a caller needs
        before treating the binding's initializer as its value everywhere — distinct from the
        orderability contract `dynamic_refs` expresses (whether every reference can be ranked), which a
        `with`-body read violates while a stable value does not. It does not itself require a single
        declaration; a caller that needs one checks `declarations` alongside.
        """
        return not binding.writes and not self.binding_maybe_reassigned_dynamically(binding)

    def reaches_global_object(self, binding: Binding, *, module_scope: bool) -> bool:
        """
        Whether *binding* is a property of the global object at runtime — the global a free name in
        global-scope reflected code (a `Function` body, an indirect `eval`, a string timer) resolves to.
        An implicit global always is. A top-level `var`/function declaration is, but only under the
        script execution model; under the module model (*module_scope*) it is scoped to the module and
        never reaches the global. A top-level `let`/`const`/`class`, or any binding nested below the
        script, is a distinct lexical binding that global-scope code cannot see.
        """
        if binding.kind is BindingKind.IMPLICIT_GLOBAL:
            return True
        if module_scope:
            return False
        return (
            binding.scope is self.root_scope
            and binding.is_hoisted
        )

    def _direct_eval_sites(self, function: Node) -> list[Node]:
        """
        The direct `eval` call sites within *function* — every call whose callee, once parentheses are
        stripped, is the bare identifier `eval` (see `is_direct_eval_call`), the one reflective surface
        that runs in the function's own scope and can therefore name its locals. Nested functions are
        included, since a direct `eval` in a closure inherits the enclosing locals. The `with` surface is
        not scanned — a `with` body's accesses are attributed precisely as dynamic references — so only
        direct eval needs a per-function answer. Computed once per function and memoized.
        """
        cached = self._function_direct_eval_sites.get(id(function))
        if cached is None:
            cached = [node for node in function.walk() if is_direct_eval_call(node)]
            self._function_direct_eval_sites[id(function)] = cached
        return cached

    def _function_has_direct_eval(self, function: Node) -> bool:
        return bool(self._direct_eval_sites(function))

    def _unread_source_sites(self, function: Node) -> list[Node]:
        """
        The spans within *function* that this model never read — text the parser could not read, and
        a construct the file ended inside (see `is_unread_source`). Each stands where the function's
        own locals are in scope and says nothing about what it references, so it can name any of
        them with no reference this model records, exactly as a direct `eval` can. Nested functions
        are included, since a span inside one names the enclosing locals too. Computed once per
        function and memoized.
        """
        cached = self._function_unread_source_sites.get(id(function))
        if cached is None:
            cached = [node for node in function.walk() if is_unread_source(node)]
            self._function_unread_source_sites[id(function)] = cached
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

    def _ensure_reflection_detected(self) -> None:
        """
        Populate the reflection-surface memos in a single AST walk. A `with` statement contributes
        only to the whole-program surface; every other surface — a span of source this model never
        read, an `import()`, a value-read of the `eval`/`Function` intrinsic, a reflective
        global-object member, or a string-valued timer — is opaque, and its node is collected so a
        caller can order a definition against the site. The whole-program surface is present when
        any opaque site exists or a `with` statement is seen.

        The unread span is tested before the shapes are, because a construct the file ended inside
        is one of those shapes: an unterminated call is a call, and what matters about it is the
        source that never followed it rather than what it would compute.
        """
        if self._reflection_surface is not None:
            return
        sites: list[Node] = []
        saw_with = False
        for node in self.root.walk():
            if is_unread_source(node):
                sites.append(node)
            elif isinstance(node, JsWithStatement):
                saw_with = True
            elif isinstance(node, JsImportExpression):
                sites.append(node)
            elif isinstance(node, JsIdentifier):
                if self._reads_reflective_intrinsic(node):
                    sites.append(node)
            elif isinstance(node, JsMemberExpression):
                if _is_reflective_member(node):
                    sites.append(node)
            elif isinstance(node, JsCallExpression):
                if _is_string_timer(node):
                    sites.append(node)
            elif isinstance(node, (JsVariableDeclarator, JsAssignmentExpression)):
                if self._destructures_a_reflective_intrinsic(node):
                    sites.append(node)
        self._opaque_surface_sites = sites
        self._reflection_surface = saw_with or bool(sites)

    def _destructures_a_reflective_intrinsic(
        self, node: JsVariableDeclarator | JsAssignmentExpression,
    ) -> bool:
        """
        Whether *node* binds one of the reflective intrinsics out of the global object: an object
        pattern whose source may be the object (`may_be_the_global_object`) and that names `eval` or
        `Function` among its keys. `const {eval} = globalThis` is the same value-read of the
        intrinsic that the bare name spells — the pattern reads the property off the object and
        binds its value — so it is a reflection surface just as the bare spelling is. A pattern
        destructuring anything else, or the same names out of any other object, binds a value the
        program chose and is no surface.
        """
        if isinstance(node, JsVariableDeclarator):
            pattern, source = node.id, node.init
        else:
            pattern, source = node.left, node.right
        if not isinstance(pattern, JsObjectPattern) or not self.may_be_the_global_object(source):
            return False
        for prop in pattern.properties:
            if not isinstance(prop, JsProperty) or prop.computed:
                continue
            key = prop.key
            name = key.value if isinstance(key, JsStringLiteral) else (
                key.name if isinstance(key, JsIdentifier) else None)
            if name in REFLECTIVE_INTRINSICS:
                return True
        return False

    def opaque_reflection_sites(self) -> list[Node]:
        """
        The AST nodes of the whole-program opaque reflective surfaces — a value-read of the
        `eval`/`Function` intrinsic, a reflective global-object member, a string-valued timer, an
        `import()`, or a span of source this model never read. A `with` statement is not opaque (its
        body's accesses are attributed as dynamic references) and is excluded. Computed once and
        memoized; empty exactly when the program has no opaque surface, which
        `_has_opaque_reflection_surface` reports as its non-emptiness.
        """
        self._ensure_reflection_detected()
        assert self._opaque_surface_sites is not None
        return self._opaque_surface_sites

    def _has_opaque_reflection_surface(self) -> bool:
        return bool(self.opaque_reflection_sites())

    def _build_def_use(self):
        self._recording_def_use = True
        self._create_implicit_globals()
        self._record_def_use_references()
        self._recording_def_use = False
        self._record_arguments_alias_references()
        self._record_global_object_alias_references()

    def _mark_export_declaration(self, declaration: JsExportNamedDeclaration | JsExportDefaultDeclaration):
        """
        Flag the bindings one `export` ties to the outside as `Binding.exported`. A declaration written
        under an export (`export var a`, `export function`/`class`, and `export default` of a named
        function or class) exports the binding it declares; a sourceless list (`export { a }`,
        `export { a as q }`) exports the binding each specifier's local half names. A list carrying a
        `from` clause and a re-export name a binding of the module the clause spells, nothing local,
        and are passed over here.
        """
        if isinstance(declaration, JsExportDefaultDeclaration):
            self._mark_declaration_exported(declaration.declaration)
        elif declaration.declaration is not None:
            self._mark_declaration_exported(declaration.declaration)
        elif declaration.source is None:
            for specifier in declaration.specifiers:
                if isinstance(specifier, JsErrorNode):
                    continue
                if isinstance(specifier.local, JsIdentifier):
                    self._mark_binding_exported(self.resolve(specifier.local))

    def _mark_declaration_exported(self, declaration: Node | None):
        """
        Flag the bindings a declaration written under an export declares. A `var`/`let`/`const`
        exports every name its declarators bind, descending through destructuring; a function or
        class declaration exports its own name. An expression under `export default` declares no
        binding and is read like any other value.
        """
        if isinstance(declaration, JsVariableDeclaration):
            for declarator in declaration.declarations:
                if isinstance(declarator, JsVariableDeclarator):
                    for ident in pattern_identifiers(declarator.id):
                        self._mark_binding_exported(self.binding_of(ident))
        elif isinstance(declaration, (JsFunctionDeclaration, JsClassDeclaration)):
            if isinstance(declaration.id, JsIdentifier):
                self._mark_binding_exported(self.binding_of(declaration.id))

    @staticmethod
    def _mark_binding_exported(binding: Binding | None):
        if binding is not None:
            binding.exported = True

    def _record_def_use_references(self):
        """
        One record per reference node: the walk reaches a node once per slot holding it, and the
        one identifier of `{ a }` or of `export { a };` fills two, so without the dedup a read's
        multiplicity would follow its spelling rather than the program. The export-marking rider
        shares the walk: it consults only scope-builder state, so riding along changes nothing the
        remaining construction walks observe.
        """
        seen: set[int] = set()
        for node in self.root.walk():
            if isinstance(node, (JsExportNamedDeclaration, JsExportDefaultDeclaration)):
                self._mark_export_declaration(node)
            if isinstance(node, JsMemberExpression):
                self._record_global_alias_member_reference(node)
                continue
            if not isinstance(node, JsIdentifier):
                continue
            if id(node) in seen:
                continue
            seen.add(id(node))
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
            binding.note_reference_from(ref_scope)

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
        if not crosses_dynamic_scope(scope):
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
        A write through a member access on a global-object alias (`globalThis.g = ...`) likewise creates
        the named global; the reference itself — the alias write, and any alias read — is recorded
        against the binding by `_build_def_use` like any other reference, so this pass establishes
        existence only. A write that resolves through a dynamic scope is skipped: inside a `with` body
        the target may be a property of the `with` object rather than a global, so the model cannot
        claim a global binding.
        """
        for node in self.root.walk():
            if isinstance(node, JsMemberExpression):
                self._ensure_implicit_global_from_alias_write(node)
                continue
            if not isinstance(node, JsIdentifier) or not self.is_reference(node):
                continue
            scope = self._node_scope.get(id(node))
            if reference_role(node) is Role.READ:
                continue
            if self.lookup(node.name, scope) is not None or crosses_dynamic_scope(scope):
                continue
            self.root_scope.bindings.setdefault(
                node.name, Binding(node.name, BindingKind.IMPLICIT_GLOBAL, self.root_scope))

    def global_alias_member_name(
        self, member: JsMemberExpression, *, module_scope: bool = False,
    ) -> str | None:
        """
        The name of the global that a member access on a global-object alias references
        (`globalThis.g`, `window['g']` → `g`), or `None` when *member* is not such an access. The alias
        must be an unshadowed `GLOBAL_OBJECT_ALIASES` identifier (a local `window` names an ordinary
        object, not the global) with a statically known property name, and the access must not cross a
        dynamic scope, where the alias could be rebound or the target could be a `with`-object property —
        in either case the model cannot claim the reference denotes a global.

        *module_scope* is the one thing about the file this query cannot read off the access. A
        `this` written where a classic script's top level holds one denotes the global object; the
        same `this` in a module denotes nothing, and in a CommonJS file it denotes that file's
        exports. So a caller rewriting a program for a host answers under the model it runs, and the
        default is the script model, which is the model this class records under: recording a
        reference the module model would not have is what keeps a declaration a reader may reach,
        and refusing to record it is what removes one.
        """
        return self._global_member_name(
            member, self._base_is_the_global_object, module_scope=module_scope)

    def may_name_a_global(self, member: JsMemberExpression) -> str | None:
        """
        The name of the global that a member access *may* reference once the program runs, read
        through `may_be_global_object_base` rather than through the spelling alone, or `None`.

        The reading half of `global_alias_member_name`, and separate from it because the two answers
        are spent on opposite things. This one is recorded as a reference, where admitting an access
        whose receiver turns out to be another object keeps a declaration nothing reaches. That one
        drives a rewrite, where the same admission renames a method's own property to a global:
        `refinery.lib.scripts.js.deobfuscation.reflection` resolves a member callee through it, and
        a `this.eval(...)` answered as the global `eval` rewrites a call to an ordinary method.

        No binding is minted from this answer. `_ensure_implicit_global_from_alias_write` keeps the
        spelling question, because a minted global is a name every intrinsic-trust and reflection
        reader then sees, and one minted from a receiver that was some other object withdraws trust
        the file never gave up.
        """
        return self._global_member_name(member, self._base_may_be_the_global_object)

    def _global_member_name(
        self,
        member: JsMemberExpression,
        base_is_the_global_object: Callable[[Node | None], bool],
        *,
        module_scope: bool = False,
    ) -> str | None:
        base = strip_parens(member.object)
        if not base_is_the_global_object(base):
            return None
        if module_scope and isinstance(base, JsThisExpression):
            return None
        name = member_property_name(member)
        if name is None:
            return None
        if crosses_dynamic_scope(self._node_scope.get(id(member))):
            return None
        return name

    def _base_is_the_global_object(self, base: Node | None) -> bool:
        """
        Whether *base* is the global object under the narrow reading: the spelling says so, and the
        name it is spelled with is not bound to anything else. A local `window` names an ordinary
        object, so the two questions are one answer here, and every reader that drives a rewrite
        gets that answer.
        """
        return is_global_object_base(base) and not self._is_bound_here(base)

    def _holds_the_global_object(self, node: Node | None) -> bool:
        """
        Whether *node* is the global object: spelled as one, or a name the file gives it to. A
        program meant to run in a browser and in something else names it once — `var w = window ||
        {}` — and every read through that name afterwards reads a global property, which
        `_base_is_the_global_object` cannot see, because the name it is asked about is `w`.
        """
        return self._base_is_the_global_object(node) or self.names_the_global_object(node)

    def _base_may_be_the_global_object(self, base: Node | None) -> bool:
        """
        Whether *base* may be the global object once the program runs: `_holds_the_global_object`
        widened by the receiver a call supplies, which `may_be_global_object_base` states. Only a
        reader recording a reference asks this, and the argument for admitting a receiver that turns
        out to be another object is written there.
        """
        return (
            may_be_global_object_base(base) and not self._is_bound_here(base)
        ) or self.names_the_global_object(base)

    def may_be_the_global_object(self, node: Node | None) -> bool:
        """
        Whether *node* may be the global object once the program runs, asked of the node alone:
        spelled as one and not bound to something else, a receiver any call may supply (`this`), or
        a name any value of which the file gives the object. The node-level form of the base
        question `may_name_a_global` asks of a member access, so a consumer deciding whether a
        write, an install, or a hand-over reached the global object shares this one reading rather
        than each spelling a narrower one — the miss of one narrower spelling is how a written
        global went unrecorded while the fold kept trusting it.
        """
        return self._base_may_be_the_global_object(node)

    def _is_bound_here(self, node: Node | None) -> bool:
        return (
            isinstance(node, JsIdentifier)
            and self.lookup(node.name, self._node_scope.get(id(node))) is not None
        )

    def names_the_global_object(self, node: Node | None, *, depth: int = 0) -> bool:
        """
        Whether *node* is a name the file gives the global object, so a property read on it may be a
        read of a global. ANY value of `binding_values` being the object is enough, and completeness
        is not asked: the callers record a reference, where one admission too many keeps a
        declaration and one refusal too many deletes one, so admitting is this answer's safe
        direction — a name that held the object on one branch of its life records the reads made
        through it even where another branch gave it something else.

        A name the file only ever assigns still answers nothing:
        `_ensure_implicit_global_from_alias_write` mints its binding without a declaration and
        `binding_values` declines for it. That is what keeps this answer out of the walk which is
        still recording those very writes — a read admitted or refused by how far that walk had got
        would depend on nothing the program says.

        The values hold wherever the name is not in their temporal dead zone, and nothing here orders
        an establishing definition before the read. A caller driving a rewrite has to — and needs the
        complete-singleton reading `singular_value` gives, not this one.
        """
        if depth >= _GLOBAL_ALIAS_CHAIN_LIMIT or not isinstance(node, JsIdentifier):
            return False
        values, _ = self.binding_values(self.resolve(node))
        return any(self._value_is_the_global_object(value, depth + 1) for value in values)

    def _value_is_the_global_object(self, value: Node | None, depth: int) -> bool:
        """
        Whether *value*, the one value a name holds, is the global object. `A || B` is it whenever
        `A` is: every spelling of the object is truthy, so the guard a program writes to survive a
        host lacking the name it prefers evaluates to the object wherever that name exists.
        """
        value = strip_parens(value)
        if value is None:
            return False
        if self._base_is_the_global_object(value):
            return True
        if isinstance(value, JsLogicalExpression) and value.operator == '||':
            return self._value_is_the_global_object(value.left, depth)
        return self.names_the_global_object(value, depth=depth)

    def _ensure_implicit_global_from_alias_write(self, member: JsMemberExpression):
        """
        Give a global written through a member access on a global-object alias (`globalThis.g = ...`) an
        implicit-global binding when the name is otherwise undeclared, so the def-use pass resolves the
        reference to it. Only a write creates a global property, so a read establishes nothing; the write
        itself is recorded against the binding by `_build_def_use` like any other reference, so this
        establishes existence only.

        The binding minted here is one nothing reads a value out of: it carries no declaration, so
        both value queries decline for it, and all it does is give a reference somewhere to resolve
        to instead of standing free. That is why a write through the `this` of a top level mints one
        too, although whether such a write creates a global at all is decided by the host - a
        CommonJS file writes its own exports there. Under the model where it creates nothing, the
        binding this mints answers no question differently; the one rewrite that reads such a write
        as a property having been created asks for the execution model itself.
        """
        if not is_member_write_target(member):
            return
        name = self.global_alias_member_name(member)
        if name is None:
            return
        self.root_scope.bindings.setdefault(
            name, Binding(name, BindingKind.IMPLICIT_GLOBAL, self.root_scope))

    def _global_alias_member_binding(self, member: JsMemberExpression) -> Binding | None:
        """
        The existing global binding a member access on a global-object alias references, or `None`.
        Unlike `_ensure_implicit_global_from_alias_write` this never creates a binding: a read of an
        otherwise-undeclared global has none to attribute and leaves the name free.

        Read through `may_name_a_global`, so a receiver a call may supply the global object for is
        recorded too. Nothing is created from that answer, so the widest it can be wrong is to keep
        a declaration a reader never reaches.
        """
        name = self.may_name_a_global(member)
        if name is None:
            return None
        return self.root_scope.bindings.get(name)

    def _record_global_alias_member_reference(self, member: JsMemberExpression):
        """
        Record a reference performed through a member access on a global-object alias (`globalThis.g`,
        `globalThis.g = ...`, `globalThis.g += 1`) against the global's binding, exactly as an ordinary
        identifier reference is recorded: `reference_role` decides whether the access reads, writes, or
        both. The binding must already exist — `_ensure_implicit_global_from_alias_write` established one
        for an alias write, while a read of an undeclared global stays free. The member node stands in
        for the referencing identifier the global has none of (see `Binding`). Without the read half a
        `globalThis.g` read would leave the binding looking unreferenced, so a remover could drop a live
        global whose only use is through the alias.
        """
        binding = self._global_alias_member_binding(member)
        if binding is None:
            return
        role = reference_role(member)
        if role is not Role.WRITE:
            binding.reads.append(member)
        if role is not Role.READ:
            binding.writes.append(member)
        binding.note_reference_from(self._node_scope.get(id(member)))

    def _record_arguments_alias_references(self):
        """
        Record, against each parameter binding, the references made through an `arguments` object whose
        elements alias the parameters, exactly as a reference through a global-object alias is recorded
        by `_record_global_alias_member_reference`. The two are the same situation: a binding reached
        through an object rather than by its own name, which the identifier walk therefore does not see.
        Without this a body that only ever reads `arguments[0]` leaves its first parameter looking
        unreferenced, and a remover drops the write whose value that read answers with.

        `has_mapped_arguments` decides which functions have such an object at all, so a strict body, an
        arrow, and any list holding a default, a rest element or a destructuring pattern contribute
        nothing.

        Where the object is reached is `walk_receiver_scope`: an arrow reads the enclosing `arguments`
        and is descended, a nested function has its own and is not.

        An element access is attributed to the parameter it names. The read half of that access is a
        definite read of the parameter, and the write half never is: §10.2.11 maps an element onto a
        parameter only at a position the call supplied an argument for, so `arguments[0] = 9` writes
        the first parameter when the call passed one and creates an ordinary property when it passed
        none. Nothing in the text of the function says which, so the write is recorded as an
        `indefinite_writes` entry — a kill that names no value — and not as a definition a fold
        could answer with. A bare use of the object is asked what its governing construct can do with
        it: one that observes identity alone — a `typeof`, a truth test, a `for-in` head — is
        recorded as nothing, and one that reads every element and nothing else — a spread, a
        `for-of` head — as a read of each parameter. `_observes_identity_alone` and
        `_reads_every_element_alone` carry the argument for every admitted position, and an
        indefinite write recorded at one of them would refuse every fold in the function for a use
        that cannot write anything. Every use those two decline — the object handed to a call, the
        object bound to a second name — is recorded as a read of every parameter and an indefinite
        write of every one of them: reading is what makes a write to a parameter observable, which
        is the fact a remover needs, and the object may reach code that writes any element.
        `arguments[i] = v` for an `i` the model cannot read is recorded the same way, since it may
        write any single one and recording a definition of each would let a fold answer with a value
        only one of them can hold.

        The name is resolved rather than matched, because a body may bind `arguments` itself — as a
        parameter, a lexical declaration, a `var` given a value, or a catch parameter — and may also
        assign over the one it was given. In either case the name denotes something whose elements
        alias nothing, so attributing an access to a parameter would credit the parameter with a
        write the program never makes. Such a function is left alone entirely rather than up to the
        point of the rebinding, because which accesses run before it is a question about flow that a
        walk over the text does not answer. `_displaces_arguments` decides it.

        A function expression whose own name is `arguments` is not one of those: that name is bound
        in an environment the object's own shadows, so the body still reads the mapped object. The
        scope model records the two as one binding, which is why the binding's kind is admitted as
        well as `ARGUMENTS` here rather than only it.

        A name that resolves to nothing is still taken for the object where it stands: resolution
        answers `None` for a free name and across a `with`, neither of which is evidence that something
        else was bound.
        """
        for fn in self.root.walk():
            if not isinstance(fn, (JsFunctionExpression, JsFunctionDeclaration)):
                continue
            if not has_mapped_arguments(fn, strict=False) or strict_mode_at(fn):
                continue
            own = self.lookup('arguments', self._node_scope.get(id(fn.body)))
            if own is None or own.kind not in (BindingKind.ARGUMENTS, BindingKind.FUNC_NAME):
                continue
            if _displaces_arguments(own, fn):
                continue
            params = _last_positions([
                self.binding_of(param) if isinstance(param, JsIdentifier) else None
                for param in fn.params
            ])
            for node in walk_receiver_scope(fn):
                if not isinstance(node, JsIdentifier) or node.name != 'arguments':
                    continue
                if not self.is_reference(node):
                    continue
                denotes = self.resolve(node)
                if denotes is not None and denotes is not own:
                    continue
                access = _enclosing_member_access(node)
                if access is not None and denotes is not None:
                    named = _aliased_parameter_positions(access, len(params))
                    if named is not None:
                        role = reference_role(access)
                        for index in named:
                            self._record_alias_reference(params[index], access, role)
                        continue
                if access is None:
                    governor = enclosing_operator(node)
                    if _observes_identity_alone(governor, node):
                        continue
                    if _reads_every_element_alone(governor, node):
                        for binding in params:
                            self._record_alias_reference(binding, node, Role.READ)
                        continue
                site: JsIdentifier | JsMemberExpression = node if access is None else access
                may_write = access is None or reference_role(access) is not Role.READ
                for binding in params:
                    self._record_alias_reference(binding, node, Role.READ)
                    if may_write:
                        self._record_alias_reference(binding, site, Role.WRITE)

    def _record_global_object_alias_references(self):
        """
        Record, against every binding a classic script's global object carries, the references a
        call may make through the object once it is handed one, but only for a hand-over the callee
        could read a property through. `a(globalThis, 'q')` and `a(this, 'q')` both give `a` an
        object whose properties are the script's top-level declarations, and a body that writes one
        of them writes the declaration — which no identifier in the text names, so the identifier
        walk sees nothing. A call that never reads a property of the object it is handed reaches no
        declaration through it, and admitting one there freezes every fold in the file for a
        reference the program never makes.

        `global_object_argument_is_observed` decides, per hand-over, whether the callee could read a
        property. An observed hand-over records the same way `_record_arguments_alias_references`
        does — a read of every binding, so a declaration reached only through the object is not
        removed, and an indefinite write of every one, so a fold does not carry a value across a
        write the callee made. Which properties the callee touches is not decided, and every binding
        is admitted, for the reason the argument list is admitted whole: a value only some of them
        can hold is not a definition of any of them. An unobserved hand-over records nothing, and
        the union is taken across hand-overs — a binding stays reachable if any one is observed.

        The gate runs in two phases because it reads `singular_value` to resolve a callee, and the
        record it is about to make is an indefinite write that would make that query decline. Every
        hand-over is judged first, against the model as it stands before this method writes anything,
        and only then are the observed ones recorded. This is the order `names_the_global_object`
        keeps for the same reason — an answer read out of the walk still recording those very writes
        would depend on how far the walk had got, not on what the program says.

        The object is recognized by `_holds_the_global_object`, so only the `this` a script's top
        level holds is one. A `this` inside a function is the receiver its call supplied, and
        admitting it costs every fold in a file that hands one to anything: obfuscator.io's
        self-defending wrapper passes its own `this` to a call, and a run that took it for the
        global object leaves that sample twenty times its deobfuscated size. `may_be_global_object_base`
        admits every `this` for the opposite reason — there the wrong answer only keeps a
        declaration alive, and here it freezes the file.

        Only an argument is read. A `return` of the object hands it to a caller the text still
        shows, and taking that for an escape refuses `refinery.lib.scripts.js.deobfuscation
        .globalfinder` the very function whose removal makes the object nameable, leaving the two
        obfuscated samples that use a finder at their original size.
        """
        bindings = list(self.root_scope.bindings.values())
        observed: list[ReferenceNode] = []
        for node in self.root.walk():
            if not isinstance(node, (JsIdentifier, JsThisExpression)):
                continue
            if not self._holds_the_global_object(node) or not _is_call_argument(node):
                continue
            if self.global_object_argument_is_observed(node):
                observed.append(node)
        if observed:
            # A callee that could read a property of the object it was handed could write one under
            # a key no text spells, which is the opaque global write's own question, so an observed
            # hand-over makes that fact hold: `t(globalThis)` and `Reflect.set(globalThis, …)` are
            # otherwise invisible to every consumer of `has_opaque_global_write`. The walk runs
            # even where no binding exists to record against, because the fact is not a binding's.
            self._opaque_global_write = True
        for node in observed:
            for binding in bindings:
                binding.reachable_through_a_handed_object = True
                self._record_alias_reference(binding, node, Role.READWRITE)

    def global_object_argument_is_observed(self, node: Node) -> bool:
        """
        Whether the call *node* is handed to could read a property of the global object *node*
        stands for. An unobserved hand-over lets the globals the object carries stay foldable; an
        observed one, or one the model cannot resolve, is admitted whole the way it always has been.

        The callee is resolved to the function it runs: a function written in place, a name whose
        one value is a function, or a name whose one value is the zero-argument IIFE a self-defending
        wrapper's factory is, whose single returned function is the one that runs. A callee resolving
        to none of these is not read, so its object is observed. A function that reaches its own
        `arguments` is observed too, because an element of that object is the handed argument under
        another name, which the parameter walk does not follow.

        The argument is matched to the parameter it binds by position; a list with a rest, default,
        or destructuring element is not matched and its object is observed. An argument past the last
        parameter binds nothing the callee can name and is not observed. A parameter reflection can
        reach is observed. Otherwise `_parameter_is_observed` asks the body.
        """
        call = _enclosing_call(node)
        if call is None:
            return True
        function = self.target_function_of_call(call)
        if function is None:
            return True
        if references_own_arguments(function):
            return True
        mapping = self._argument_parameter_map(call, function)
        if mapping is None:
            return True
        parameter = next((b for b, argument in mapping.items() if argument is node), None)
        if parameter is None:
            return False
        if self.reflection_can_reach(parameter):
            return True
        return self._parameter_is_observed(function, parameter, mapping, {id(function)}, 0)

    def target_function_of_call(self, call: JsCallExpression | JsNewExpression) -> JsFunctionNode | None:
        """
        The function *call* runs, as far as it resolves without leaving the text: the callee written
        as a function, a name whose one value is a function, or a name whose one value is a
        zero-argument IIFE returning a single function — the shape the self-defending wrapper's
        factory takes. `None` when the callee resolves to none of these. A named callee is read
        through `singular_value`, the complete-singleton reading: a name that may hold another value
        — a parameter, or a declaration value later overwritten — resolves to `None`, and every
        consumer treats an unresolved callee as the observed hand-over.
        """
        callee = strip_parens(call.callee)
        if isinstance(callee, FUNCTION_NODES):
            return callee
        if not isinstance(callee, JsIdentifier):
            return None
        value = self.singular_value(self.resolve(callee))
        if value is None:
            return None
        value = strip_parens(value)
        if isinstance(value, FUNCTION_NODES):
            return value
        if isinstance(value, JsCallExpression) and not value.arguments:
            inner = strip_parens(value.callee)
            if isinstance(inner, FUNCTION_NODES):
                return _sole_returned_function(inner)
        return None

    def _argument_parameter_map(
        self,
        call: JsCallExpression | JsNewExpression,
        function: JsFunctionNode,
    ) -> dict[Binding | None, Node | None] | None:
        """
        A map from each parameter binding of *function* to the argument *call* supplies for it by
        position, or `None` when a parameter is not a plain name — a rest, default, or destructuring
        element the model cannot bind by position — or when an argument is a spread, whose element
        count is not known until it runs, so no argument after it aligns with a parameter by index. A
        parameter the call gives no argument for maps to `None`.
        """
        if any(not isinstance(parameter, JsIdentifier) for parameter in function.params):
            return None
        if any(isinstance(strip_parens(argument), JsSpreadElement) for argument in call.arguments):
            return None
        mapping: dict[Binding | None, Node | None] = {}
        for index, parameter in enumerate(function.params):
            if not isinstance(parameter, JsIdentifier):
                continue
            argument = strip_parens(call.arguments[index]) if index < len(call.arguments) else None
            mapping[self.binding_of(parameter)] = argument
        return mapping

    def _parameter_is_observed(
        self,
        function: JsFunctionNode,
        parameter: Binding | None,
        mapping: dict[Binding | None, Node | None],
        visiting: set[int],
        depth: int,
    ) -> bool:
        """
        Whether *function*'s body reads a property of the object bound to *parameter*. The parameter
        as the base of a member access reads one; the receiver an `apply`/`call` hands to a function
        that reads its own `this` does; a receiver handed to a `this`-free function does not, because
        that function never reads it. Every other use — returned, aliased, enumerated, handed on as
        a plain argument — is taken for an observation. The whole subtree is walked and each
        identifier resolved, so a use inside a nested closure that captures the parameter counts, and
        a shadowing binding of the same name does not.
        """
        if depth > _HANDED_OBJECT_OBSERVATION_DEPTH:
            return True
        for reference in function.walk():
            if not isinstance(reference, JsIdentifier) or not self.is_reference(reference):
                continue
            if self.resolve(reference) is not parameter:
                continue
            access = _enclosing_member_access(reference)
            if access is not None and strip_parens(access.object) is reference:
                return True
            if self._apply_receiver_is_safe(reference, mapping, visiting, depth) is not True:
                return True
        return False

    def _apply_receiver_is_safe(
        self,
        node: Node,
        mapping: dict[Binding | None, Node | None],
        visiting: set[int],
        depth: int,
    ) -> bool | None:
        """
        For a *node* that denotes the handed object: `True` when it is the `thisArg` of an
        `apply`/`call` that provably never reads the object; `False` when it is such a receiver but
        that is not proven; and `None` when *node* is not used as such a receiver at all, the case
        the caller reads as an observation. A named target is judged over every value it can hold
        during this call — `values_at_call`, so the argument mapped to a target parameter and every
        value assigned over it are weighed alike — and the receiver is safe only when that set is
        complete, non-empty, and every value never reads the receiver
        (`_apply_target_value_observes_the_receiver`). Every target — a name or a function written
        in place — presumes the intrinsic `apply` is what the dispatch finds, so any target is
        refused while a reflection surface stands, since reflected code can replace that intrinsic
        with a forwarder no matter which function the name holds — and this subsumes every way
        reflection could reach the target binding itself — and likewise while text can reach the
        prototype surface the dispatch walks (`_dispatch_surface_reachable`) or stores a property
        on the global object under a runtime key (`has_opaque_global_write`), which may replace
        the intrinsic the same way; a named target is
        further refused when the program installs properties through it
        (`_properties_installed_through`), which can shadow the intrinsic on the object alone.
        """
        parent = enclosing_operator(node)
        if not isinstance(parent, JsCallExpression):
            return None
        callee = strip_parens(parent.callee)
        if not isinstance(callee, JsMemberExpression):
            return None
        if member_property_name(callee) not in ('apply', 'call'):
            return None
        if not parent.arguments or strip_parens(parent.arguments[0]) is not node:
            return None
        if self.has_reflection_surface() or self.has_opaque_global_write():
            return False
        if self._dispatch_surface_reachable():
            return False
        target = strip_parens(callee.object)
        if isinstance(target, FUNCTION_NODES):
            return not self._function_observes_its_this(target, visiting, depth + 1)
        if not isinstance(target, JsIdentifier):
            return False
        binding = self.resolve(target)
        if binding is None:
            return False
        if self._properties_installed_through(binding):
            return False
        values, complete = self.values_at_call(binding, mapping)
        if not complete or not values:
            return False
        return not any(
            self._apply_target_value_observes_the_receiver(value, visiting, depth)
            for value in values
        )

    def _apply_target_value_observes_the_receiver(
        self,
        value: Node,
        visiting: set[int],
        depth: int,
    ) -> bool:
        """
        Whether *value*, dispatched as the target of an `apply`/`call`, may read the handed
        receiver. A function reads it exactly when it reads its own `this`
        (`_function_observes_its_this`). A `null` literal and an unshadowed `undefined` never do,
        because the apply then throws before the object is touched — and the obfuscator's
        self-defending wrapper writes `payload = null` after applying, so refusing them would
        refuse the wrapper's own fold. Every other value is taken for a reader.
        """
        value = strip_parens(value) or value
        if isinstance(value, FUNCTION_NODES):
            return self._function_observes_its_this(value, visiting, depth + 1)
        if isinstance(value, JsNullLiteral):
            return False
        if (
            isinstance(value, JsIdentifier)
            and value.name == 'undefined'
            and self.resolve(value) is None
        ):
            return False
        return True

    def _properties_installed_through(self, binding: Binding) -> bool:
        """
        Whether the text may install a property on the object *binding* holds, or on a prototype
        that object dispatches through — the two ways an own or inherited name can come to shadow
        an intrinsic a consumer trusts. Judged over every recorded read by what its position lets
        code do with the object, refusing wherever the answer would otherwise depend on code the
        model does not read. A member write anywhere on the access chain installs (`t.apply = f`,
        `t[k] = f`, and through the chain, `t.__proto__.apply = f`). A read whose chain passes a
        key that is not statically known, reaches the prototype surface, or names an accessor
        installer may perform or reveal an install (`_DISPLACING_CHAIN_KEYS`). Any escape hands
        the object to code that may install on it under another name — an alias, a call argument,
        which is how a `defineProperty` or an `Object.assign` receives its target, a return —
        except a position that consumes the value as a bare verdict and forwards nothing
        (`_read_forwards_no_alias`). A plain rebind of the name is a write of the binding rather
        than of the object, weighed by `values_at_call` and recorded as a write, so it never
        appears among the reads walked here. Which key an install stores is never asked: a
        computed write names no fixed key, and refusing every install keeps the answer independent
        of the folds that would reveal one.
        """
        for reference in binding.reads:
            role = container_reference_role(reference)
            if role is ContainerRole.MEMBER_WRITE:
                return True
            if role is ContainerRole.REBIND:
                continue
            if role is ContainerRole.ESCAPE:
                if _read_forwards_no_alias(reference):
                    continue
                return True
            access = _enclosing_member_access(reference)
            while access is not None:
                key = static_property_key(access)
                if key is None or key in _DISPLACING_CHAIN_KEYS:
                    return True
                access = _enclosing_member_access(access)
        return False

    def _dispatch_surface_reachable(self) -> bool:
        """
        Whether text can obtain and then write through the prototype surface an `apply`/`call`
        dispatch walks, without spelling `Function` — a name whose read is already a reflection
        surface. A write there may replace the intrinsic the dispatch is trusted to find, so while
        one is possible anywhere, no receiver hand-over is safe. A `getPrototypeOf`/
        `setPrototypeOf` member reaches the surface as a call and counts on sight, since an alias
        of it leaves no chain to climb. A `__proto__` or `constructor` key yields the surface as a
        value and counts exactly when what it yields is written through or flows onward
        (`_prototype_surface_escapes`): the obfuscator's own defense reads `.constructor(...)`
        merely to invoke it, and a gate refusing every such read would refuse the corpus it exists
        to fold. Keys are read statically (`static_property_key`), so a computed key no fold
        collapses stays unrecognized — the documented residual of every static key reading in
        this model.
        """
        if self._dispatch_surface_reached is None:
            self._dispatch_surface_reached = any(
                isinstance(node, JsMemberExpression)
                and _member_reaches_dispatch_surface(node)
                for node in self.root.walk()
            )
        return self._dispatch_surface_reached

    def _function_observes_its_this(
        self,
        function: JsFunctionNode,
        visiting: set[int],
        depth: int,
    ) -> bool:
        """
        Whether *function* reads the `this` its caller supplies. An arrow has none of its own and
        reads the enclosing one, so a receiver handed to it is never read; a regular function that
        names `this` anywhere in its own receiver scope, or runs a direct `eval` that could, reads
        it. The bound and the *visiting* set take a function that hands `this` on to itself, or a
        chain too deep to follow, for a reader.
        """
        if depth > _HANDED_OBJECT_OBSERVATION_DEPTH or id(function) in visiting:
            return True
        if isinstance(function, JsArrowFunctionExpression):
            return False
        if self._function_has_direct_eval(function):
            return True
        return any(isinstance(node, JsThisExpression) for node in walk_receiver_scope(function))

    def _record_alias_reference(
        self,
        binding: Binding | None,
        node: ReferenceNode,
        role: Role,
    ) -> None:
        """
        Record against a binding one reference made through an object that aliases it — a mapped
        `arguments` reaching a parameter, or the global object reaching a global. The read half is a
        definite read — the access observes whatever the binding holds — while the write half never
        is: what an object handed to a call writes through is decided by code the walk does not
        read, so it lands in `indefinite_writes` as a kill that names no value rather than in
        `writes` as a definition.
        """
        if binding is None:
            return
        if role is not Role.WRITE:
            binding.reads.append(node)
        if role is not Role.READ:
            binding.indefinite_writes.append(node)
        binding.note_reference_from(self._node_scope.get(id(node)))


class _ScopeBuilder:
    """
    Single-pass scope and binding construction. Bindings are collected when a scope is created
    (parameters and hoisted `var`/function names for function scopes, lexical `let`/`const`/`class`
    for block scopes); the recursive walk only records which scope each node belongs to.
    """

    def __init__(self, model: SemanticModel):
        self.model = model
        self._lexical_names = LexicalNameCache()

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
        """
        Declare in *func_scope* the names the statements of *stmts* bind with a `var` or with a
        function declaration, which is what runs before any of them does.

        A function declared inside a block and given a `var` outside it by Annex B is declared here
        too. What is different about it is not where the name is but when it holds the function, and
        that is `binding_establishment_sites`' answer rather than this one's.
        """
        for node in _walk_skipping_functions(stmts):
            if isinstance(node, JsVariableDeclaration) and node.kind is JsVarKind.VAR:
                for decl in node.declarations:
                    if isinstance(decl, JsVariableDeclarator):
                        for ident in pattern_identifiers(decl.id):
                            self._declare(func_scope, ident.name, BindingKind.VAR, ident)
            elif isinstance(node, JsFunctionDeclaration) and node.id is not None:
                if annex_b_var_home(node, self._lexical_names) is func_scope.node:
                    self._declare(func_scope, node.id.name, BindingKind.FUNCTION, node.id)

    def _collect_imports(self, stmts: list, scope: Scope):
        for stmt in stmts:
            if not isinstance(stmt, JsImportDeclaration):
                continue
            for spec in stmt.specifiers:
                if isinstance(spec, JsErrorNode):
                    continue
                if isinstance(spec.local, JsIdentifier):
                    self._declare(scope, spec.local.name, BindingKind.IMPORT, spec.local)

    def _collect_lexical(self, stmts: list, scope: Scope):
        """
        Declare in *scope* what the statements of *stmts* bind lexically: a `let`, a `const`, a
        class, and a function no `var` outside the block is created for.

        That last one is the whole of what a mode decides about a block-declared function. Strict
        code binds it in the block and nowhere else, and so does sloppy code wherever §B.3.3.1 stops
        the copy; where the copy runs, the name outside the block is what every reference reads and
        `_hoist` has already declared it, so nothing is declared here and the block holds no binding
        of its own - which is what makes a read inside the block and one after it read one name, as
        they do.

        A declaration written under an `export` is read through it: the export names what the
        declaration binds and binds nothing of its own.
        """
        for stmt in stmts:
            stmt = declaration_under_export(stmt)
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
            elif isinstance(stmt, JsFunctionDeclaration) and stmt.id is not None:
                if annex_b_var_home(stmt, self._lexical_names) is None:
                    self._declare(scope, stmt.id.name, BindingKind.FUNCTION, stmt.id)

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
        elif isinstance(node, JsStaticBlock):
            self._visit_static_block(node, scope)
        else:
            for child in node.children():
                self._visit(child, scope)

    def _visit_function(self, node: JsFunctionNode, enclosing: Scope):
        """
        Build the scopes of *node*. A function whose parameter list holds no expression gets one
        scope for its name, its parameters and its body together, which nothing in such a function
        can tell from the three the specification gives it: no parameter runs, so none of them can
        read a name, and no reference is made before the body's declarations exist.

        A function whose parameter list does hold an expression gets all three, nested the way §10.2
        nests them - the name outside the parameters, so a parameter spelling it wins, and the
        parameters outside the body, so a default reads what encloses the function rather than what
        the body declares. A `var` of a parameter's name is then a second binding, which is what the
        entry copy is: the body's name starts out holding the argument, and only the declarator that
        follows says anything about what it holds after that.
        """
        split = has_parameter_expressions(node)
        outer = enclosing
        if split and isinstance(node, JsFunctionExpression) and node.id is not None:
            outer = self._new_scope(ScopeKind.NAME, node, outer)
            self._declare(outer, node.id.name, BindingKind.FUNC_NAME, node.id)
        pscope = self._new_scope(ScopeKind.PARAMS, node, outer) if split else None
        fscope = self._new_scope(ScopeKind.FUNCTION, node, pscope or outer)
        params = pscope or fscope
        if pscope is not None:
            pscope.function_body = fscope
            if outer is not enclosing:
                outer.function_body = fscope
        is_arrow = isinstance(node, JsArrowFunctionExpression)
        if not split and isinstance(node, JsFunctionExpression) and node.id is not None:
            self._declare(fscope, node.id.name, BindingKind.FUNC_NAME, node.id)
        for param in node.params:
            for ident in pattern_identifiers(param):
                self._declare(params, ident.name, BindingKind.PARAM, ident)
            if pattern_binds_unread_names(param):
                params.is_dynamic = True
        if not is_arrow:
            self._declare(params, 'arguments', BindingKind.ARGUMENTS, None)
        body = node.body
        if isinstance(body, JsBlockStatement):
            self._hoist(body.body, fscope)
            self._collect_lexical(body.body, fscope)
            self._note_entry_copies(fscope, params)
        for param in node.params:
            self._visit(param, params)
        if isinstance(body, JsBlockStatement):
            self.model._node_scope[id(body)] = fscope
            for stmt in body.body:
                self._visit(stmt, fscope)
        elif body is not None:
            self._visit(body, fscope)

    @staticmethod
    def _note_entry_copies(fscope: Scope, params: Scope):
        """
        Record, on every body binding repeating a parameter's name, that the call writes it before
        any statement runs and says nothing about what it wrote.

        The name starts the body holding the argument. A `var` declarator for it is a write that
        happens later, so neither the value it installs nor its own position is what the name holds
        throughout - and a `var` with no declarator at all installs nothing, leaving the argument
        standing. Entering the declarators as writes that name no value is what says both.
        """
        if params is fscope:
            return
        for name, binding in fscope.bindings.items():
            if binding.kind is BindingKind.VAR and name in params.bindings:
                binding.written_at_entry = True

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
        cases = [case for case in node.cases if isinstance(case, JsSwitchCase)]
        for case in cases:
            self._collect_lexical(case.body, sscope)
        for case in cases:
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
            if pattern_binds_unread_names(node.param):
                cscope.is_dynamic = True
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
        for decorator in node.decorators:
            self._visit(decorator, enclosing)
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

    def _visit_static_block(self, node: JsStaticBlock, enclosing: Scope):
        sscope = self._new_scope(ScopeKind.STATIC_BLOCK, node, enclosing)
        self._hoist(node.body, sscope)
        self._collect_lexical(node.body, sscope)
        for stmt in node.body:
            self._visit(stmt, sscope)


def build_semantic_model(
    root: JsScript, environment: HostEnvironment = HostEnvironment.universal
) -> SemanticModel:
    """
    Build the `SemanticModel` for a parsed script, resolving bare global reads against *environment*.
    The default `universal` environment asserts only `GUARANTEED_GLOBALS`, so the model answers
    `read_may_throw` exactly as an unpinned run; a pinned host recovers the reads that host guarantees.
    """
    return SemanticModel(root, environment)
