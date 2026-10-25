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
from typing import Callable, Collection, Iterator, NamedTuple

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.js.analysis.environment import (
    COMMONJS_WRAPPER_PARAMETERS,
    FileKind,
    HostEnvironment,
    node_require_runs_no_code,
)
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsArrayExpression,
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsBreakStatement,
    JsCallExpression,
    JsCatchClause,
    JsClassBody,
    JsClassDeclaration,
    JsClassExpression,
    JsConditionalExpression,
    JsContinueStatement,
    JsDoWhileStatement,
    JsErrorNode,
    JsExportAllDeclaration,
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
    JsMethodKind,
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
    JsSequenceExpression,
    JsSpreadElement,
    JsStaticBlock,
    JsStringLiteral,
    JsSwitchCase,
    JsSwitchStatement,
    JsTaggedTemplateExpression,
    JsTemplateLiteral,
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
    static_string,
    strip_parens,
    value_is_discarded,
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
    VERDICT_READ = 'verdict_read'  # noqa  consumed whole for a verdict: `!obj`, `if (obj)`, `obj === x`
    ESCAPE       = 'escape'        # noqa  any other use, through which the container could be aliased


#: What a binding's reference lists hold. A reference is ordinarily the identifier naming the
#: binding; where an object aliases it there is no such identifier, and the node the program reached
#: the object through stands in — a member access for `globalThis.g` and for `arguments[0]`, and the
#: `this` of a script's top level where the object itself is handed to a call. The copy Annex B
#: makes of a function declared in a block reads the block's binding where the declaration runs and
#: hands the value to another name, and the declaration stands in for that read (`AnnexBCopy`).
ReferenceNode = JsIdentifier | JsMemberExpression | JsThisExpression | JsFunctionDeclaration


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
    uncertain, so it is kept apart from the definite references. It also holds the references to a
    binding that may be absent which the reading without that binding resolves to this one
    (`Binding.may_be_absent`): such a reference does resolve statically, to the other binding.
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
    #: The copies Annex B makes of this block binding of a function declared in a block, one for
    #: each declaration of it B.3.3.1 does not stop, each into the same `var` outside the block.
    copies_made: list[AnnexBCopy] = field(default_factory=list)
    #: The copies Annex B makes into this `var` from the block bindings of functions declared in
    #: blocks of its function, script or static block.
    copies_received: list[AnnexBCopy] = field(default_factory=list)
    #: Whether the host supplies this binding: a parameter or the `arguments` of the function a
    #: CommonJS host wraps around the text of the file, which holds what the host passed from the
    #: moment the file starts to run. A `var` or function declaration of the file joins it, as one
    #: in the body of a function joins a parameter.
    supplied_by_host: bool = False
    #: Whether the binding exists in one way the file may run and not in another, so that a
    #: reference to it may find no binding at all: a binding the host supplies where the file may
    #: also be an ES module, which binds none of them, unless a declaration of the file joins it,
    #: and a `var` only conditional copies declare (`AnnexBCopy.conditional`).
    may_be_absent: bool = False

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

    def declared_within(self, node: Node) -> bool:
        """
        Whether the scope declaring this binding is introduced by *node* or by a node inside it, so
        that the binding belongs to *node*: a copy of *node* carries it along, and a name *node*
        reads that resolves elsewhere comes from outside.
        """
        owner = self.scope.node
        return owner is node or owner.is_descendant_of(node)

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
class AnnexBCopy:
    """
    The copy Annex B makes of a function declared in a block outside strict code (§B.3.3): where
    *declaration* runs, the `var` of the enclosing function, script or static block (*var*)
    receives what the block's own binding (*block*) holds at that point. The block binding holds the
    function from the moment the block is entered, the `var` only from the point the copy runs.

    The copy reads the block binding, and the declaration stands among the reads of *block* for that
    read wherever something observes *var* (`observed`), so that a consumer asking whether, where or
    how the value of the block binding is used sees a use it cannot follow. *var* keeps the
    declaration among its own declarations, since that declaration is what gives it the name.

    A copy is *conditional* where the file may be a CommonJS file, whose code is sloppy where it
    says nothing, or an ES module, which is strict code throughout and makes no copy.
    """
    declaration: JsFunctionDeclaration
    block: Binding
    var: Binding
    conditional: bool = False

    @property
    def observed(self) -> bool:
        """
        Whether anything may read what the copy stores: *var* is read, named inside a `with` body,
        exported, or carried by an object the program hands a call. A direct `eval` or another
        reflective surface that could name *var* could name *block* too, the two sharing a variable
        scope, and `SemanticModel.reflection_can_reach` answers that question for both.
        """
        var = self.var
        return bool(
            var.reads
            or var.dynamic_refs
            or var.exported
            or var.reachable_through_a_handed_object
        )


@dataclass(frozen=True)
class FunctionNames:
    """
    The names a function is called and observed through. *own* is the name its declaration gives
    it, or the one name a declarator or a lone assignment stores it into. A function declared in a
    block has a second name where the copy Annex B makes of it is observed (*copy*): the `var` the
    copy writes, which holds the function from the point the declaration runs.
    """
    own: Binding
    copy: AnnexBCopy | None = None

    @property
    def bindings(self) -> tuple[Binding, ...]:
        """
        Every name of the function, its own first.
        """
        if self.copy is None:
            return (self.own,)
        return (self.own, self.copy.var)

    def reads_of(self, binding: Binding) -> list[ReferenceNode]:
        """
        The reads through which *binding*, one of these names, reaches the function. The read the
        copy makes of the block binding is not one of them: what the copy reads is what the reads of
        the `var` see.
        """
        if self.copy is not None and binding is self.copy.block:
            return [read for read in binding.reads if read is not self.copy.declaration]
        return binding.reads

    def references_of(self, binding: Binding) -> list[ReferenceNode]:
        """
        The references through which *binding*, one of these names, reaches the function: its reads
        as `reads_of` gives them, and its writes.
        """
        return self.reads_of(binding) + binding.writes

    @property
    def reads(self) -> list[ReferenceNode]:
        """
        The reads through which any of the names reaches the function.
        """
        return [read for binding in self.bindings for read in self.reads_of(binding)]


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


def is_plain_store_target(node: Node) -> bool:
    """
    Whether *node* is the target of a plain assignment `node = v`, whose value is the value stored.
    """
    parent = enclosing_operator(node)
    return (
        isinstance(parent, JsAssignmentExpression)
        and parent.operator == '='
        and strip_parens(parent.left) is node
    )


def _tests_or_replaces_the_exports(reference: Node) -> bool:
    """
    Whether the reference *reference* to the name `module` reads nothing of the object: it is the
    operand of `typeof`, a side of a comparison with `null`, or the object of the store
    `module.exports = v`.
    """
    parent = enclosing_operator(reference)
    if isinstance(parent, JsUnaryExpression):
        return parent.operator == 'typeof'
    if isinstance(parent, JsBinaryExpression):
        if parent.operator not in ('==', '!=', '===', '!=='):
            return False
        return any(isinstance(strip_parens(side), JsNullLiteral) for side in (parent.left, parent.right))
    return (
        isinstance(parent, JsMemberExpression)
        and strip_parens(parent.object) is reference
        and static_property_key(parent) == 'exports'
        and is_plain_store_target(parent)
    )


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
    receiver. A plain `node = ...` reassignment is a `REBIND`; a position that consumes the value whole
    for a verdict (`_read_forwards_no_alias`: the operand of `!`, `typeof` or `void`, either side of a
    strict equality, the test of an `if`, a loop, or a conditional) is a `VERDICT_READ`, which mutates
    nothing and forwards no alias — an empty array is truthy and a strict equality converts nothing;
    anything else — passed as an argument, aliased to another binding, returned, used as an operand or
    a computed key, a loose-equality operand whose `ToPrimitive` runs a method the prototype chain
    chooses — is an `ESCAPE`, through which an alias could mutate the container. Parentheses are
    looked through throughout, so a grouped write or call (`(a.b) = v`, `(a.sort)()`) is classified by
    the operator that applies, not as a bare read. This is the per-reference primitive the EffectModel
    composes over a binding's whole reference set (with alias-following and callee summaries) to
    decide container immutability.
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
    if _read_forwards_no_alias(node):
        return ContainerRole.VERDICT_READ
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
        none. A generator or an async function declared in a block or a `switch` is lexical there
        (`_lexical_function_names`).
        """
        names = self._names.get(id(holder))
        if names is None:
            statements = statement_list_of(holder)
            names = frozenset() if statements is None else lexically_declared_names(statements)
            if statements is not None and not hoists_its_functions(holder):
                names |= _lexical_function_names(statements)
            self._names[id(holder)] = names
        return name in names


def hoists_its_functions(holder: Node) -> bool:
    """
    Whether the statement list *holder* holds is the top level of a script, a static block or the
    body of a function, where every function declaration it holds is var-scoped, rather than a
    block or a `switch`.
    """
    if is_a_var_home(holder):
        return True
    parent = holder.parent
    return isinstance(parent, FUNCTION_NODES) and parent.body is holder


def _lexical_function_names(statements: list[Statement]) -> frozenset[str]:
    """
    The names *statements* declare with a generator or an async function, which a block or a
    `switch` binds lexically in every mode: Annex B gives a `var` to a plain function only.
    """
    return frozenset(
        statement.id.name
        for statement in statements
        if isinstance(statement, JsFunctionDeclaration)
        and statement.id is not None
        and (statement.generator or statement.is_async)
    )


def annex_b_var_home(
    declaration: JsFunctionDeclaration,
    file_kind: FileKind,
    cache: LexicalNameCache | None = None,
) -> Node | None:
    """
    The function, script or static block whose `var` names the function *declaration* declares, or
    `None` where nothing outside the block holding it ever does.

    A declaration written directly in such a body names something there and is answered with that
    body. A declaration written inside a block is a lexical binding of that block, and only Annex
    B.3.3 puts the name outside it: the enclosing body gets a `var` of the name, which the copy the
    declaration makes writes to when it runs. That happens in sloppy code only, for a plain function
    only and never for a generator or an async function, and §B.3.3.1 names three things that stop
    it:

    - a `let`, `const` or `class` of the same name between the block and the body, the body's own
      list included, or a generator or an async function of the same name in a block between them,
      which the `var` would conflict with;
    - a parameter of the function, which already binds the name;
    - the name `arguments`, whose binding the function already has, which is a condition about a
      function and not about a script or a static block, neither of which has one.

    A catch parameter is not one of them, and the mismatch is deliberate: a simple catch parameter
    does not stop the copy, so the enclosing name still ends up holding the function, while a
    destructuring one does, being a lexical declaration the `var` would conflict with. Both were
    read from an engine rather than from the text of the specification.

    What the file is (*file_kind*) decides two more. An ES module is strict code throughout and
    makes no copy. The top of a file that may be CommonJS is the body of the function the host
    wraps around it, whose parameters
    (`refinery.lib.scripts.js.analysis.environment.COMMONJS_WRAPPER_PARAMETERS`) and `arguments`
    stop a copy there as a function's own do.

    *cache* holds the lexical names of the lists the climb passes, for a caller asking this of many
    declarations over a tree it is not rewriting.
    """
    cache = cache if cache is not None else LexicalNameCache()
    home = statement_list_holding(declaration)
    if home is not None and is_a_var_home(home):
        return home
    if (
        declaration.generator
        or declaration.is_async
        or file_kind is FileKind.es_module
        or strict_mode_at(declaration)
    ):
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
            if (
                isinstance(cursor, JsScript)
                and file_kind.may_be_commonjs
                and (name == 'arguments' or name in COMMONJS_WRAPPER_PARAMETERS)
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


def annex_b_function_home(
    declaration: JsFunctionDeclaration,
    cache: LexicalNameCache | None = None,
) -> Node | None:
    """
    The function or static block whose `var` names the function *declaration* declares where the
    file is not an ES module, or `None` where that is the top of the file or nothing
    (`annex_b_var_home`). Below the top of the file, the kind of the file decides a home only by
    being an ES module, which makes no copy at all; a caller that may stand in one asks the
    semantic model (`SemanticModel.file_kind`).
    """
    home = annex_b_var_home(declaration, FileKind.script, cache)
    return None if isinstance(home, JsScript) else home


def annex_b_suppressor_names(
    declaration: Statement,
    file_kind: FileKind,
    cache: LexicalNameCache | None = None,
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
            and annex_b_var_home(node, file_kind, cache) is None
        ):
            suppressed.add(node.id.name)
    return frozenset(suppressed)


def _copy_made_by(binding: Binding, declaration: Node | None) -> AnnexBCopy | None:
    """
    The copy Annex B makes of the block binding *binding* where *declaration* runs, if any.
    """
    return next((copy for copy in binding.copies_made if copy.declaration is declaration), None)


def _copy_received_by(binding: Binding, declaration: Node | None) -> AnnexBCopy | None:
    """
    The copy Annex B makes into the `var` *binding* where *declaration* runs, if any.
    """
    return next((copy for copy in binding.copies_received if copy.declaration is declaration), None)


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


def _lets_another_module_run(node: Node) -> bool:
    """
    Whether *node* lets code of another module run after this module is linked and before its body
    has finished: an `import` or an `export … from` declaration, whose module the linker evaluates
    first and which, in an import cycle, can call back into this module's hoisted exports. An
    `await` at the top level is not one: every importer waits for the awaiting module to finish,
    and a module importing none can be in no cycle.
    """
    if isinstance(node, (JsImportDeclaration, JsExportAllDeclaration)):
        return True
    if isinstance(node, JsExportNamedDeclaration):
        return node.source is not None
    return False


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
    return isinstance(node, JsThisExpression) and receiver_owner(node) is None


def receiver_owner(node: Node) -> Node | None:
    """
    The nearest node above *node* that gives the code at *node* a receiver of its own: a regular
    function, a method, an accessor, a field initializer or a static block, by the boundary
    `walk_receiver_scope` draws. `None` when the climb reaches the top of its tree first, which is
    where a `this` at *node* denotes what the top level does.
    """
    child = node
    cursor = node.parent
    while cursor is not None:
        if not _shares_the_receiver_of(cursor, child):
            return cursor
        child, cursor = cursor, cursor.parent
    return None


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


def arguments_name_their_function(function: Node) -> bool:
    """
    Whether the body of *function* may reach the function through its own `arguments`, whose
    `callee` is the function in sloppy mode: any use of it other than an index, its `length`, a
    spread, or the second argument of `apply`.
    """
    if isinstance(function, JsArrowFunctionExpression):
        return False
    for node in walk_receiver_scope(function):
        if not isinstance(node, JsIdentifier) or node.name != 'arguments' or not is_use_position(node):
            continue
        parent = enclosing_operator(node)
        if isinstance(parent, JsSpreadElement):
            continue
        if (
            isinstance(parent, JsMemberExpression)
            and strip_parens(parent.object) is node
            and not is_member_write_target(parent)
        ):
            if parent.computed and isinstance(strip_parens(parent.property), JsNumericLiteral):
                continue
            if static_property_key(parent) == 'length':
                continue
        if (
            isinstance(parent, JsCallExpression)
            and len(parent.arguments) == 2
            and strip_parens(parent.arguments[1]) is node
        ):
            callee = strip_parens(parent.callee)
            if isinstance(callee, JsMemberExpression) and static_property_key(callee) == 'apply':
                continue
        return True
    return False


def references_new_target(root: Node) -> bool:
    """
    Whether *root* reads the `new.target` meta-property, which the parser models as a member access
    whose object is the reserved word `new`. A `Function`-constructed function is invoked as a call,
    so its `new.target` is always `undefined`; splicing the body into a real function would rebind
    `new.target` to the caller's, so a body that reads it cannot be inlined.
    """
    for node in root.walk():
        if (
            isinstance(node, JsMemberExpression)
            and isinstance(node.object, JsIdentifier)
            and node.object.name == 'new'
        ):
            return True
    return False


def _spells_caller_at(node: Node) -> bool:
    """
    Whether *node* spells the name `caller`, in the sense of `SemanticModel.spells_caller`.
    """
    if isinstance(node, JsIdentifier):
        return node.name == 'caller'
    if isinstance(node, (JsStringLiteral, JsTemplateLiteral)):
        return static_string(node) == 'caller'
    if isinstance(node, JsMemberExpression) and node.computed:
        return static_property_key(node) == 'caller'
    return False


_TESTED_FORMS = (
    JsIfStatement,
    JsWhileStatement,
    JsDoWhileStatement,
    JsForStatement,
    JsConditionalExpression,
)


def read_is_only_tested(node: Node) -> bool:
    """
    Whether the value read at *node* is only tested: its type asked, negated, compared for equality,
    or used as the condition of a branch or a loop or as the left of `&&`, which is how a program
    detects a feature without taking it. A `&&` or `||` whose own value is tested in turn passes the
    test on to its operands.
    """
    parent = enclosing_operator(node)
    if isinstance(parent, JsUnaryExpression):
        return parent.operator in ('typeof', '!', 'void')
    if isinstance(parent, JsBinaryExpression):
        return parent.operator in ('===', '!==', '==', '!=')
    if isinstance(parent, JsLogicalExpression):
        if parent.operator == '&&' and strip_parens(parent.left) is node:
            return True
        return read_is_only_tested(parent)
    if isinstance(parent, _TESTED_FORMS):
        return strip_parens(parent.test) is node
    return False


def _constructor_read_is_harmless(node: Node) -> bool:
    """
    Whether a read of a `constructor` property at *node* only constructs with it, compares it, reads
    its name, or tests it.
    """
    parent = enclosing_operator(node)
    if isinstance(parent, JsNewExpression) and strip_parens(parent.callee) is node:
        return True
    if isinstance(parent, JsMemberExpression) and strip_parens(parent.object) is node:
        return static_property_key(parent) == 'name' and not is_member_write_target(parent)
    if isinstance(parent, JsBinaryExpression) and parent.operator == 'instanceof':
        return True
    return read_is_only_tested(node)


def _lets_a_constructor_escape(node: Node) -> bool:
    """
    Whether *node* lets a constructor escape in the sense of
    `SemanticModel.constructors_may_escape`, a concatenation aside: a string spelling `constructor`,
    a read of a `constructor` property that does more than `_constructor_read_is_harmless` allows,
    or a destructuring property that may take one.
    """
    if isinstance(node, (JsStringLiteral, JsTemplateLiteral)):
        return static_string(node) == 'constructor'
    if isinstance(node, JsMemberExpression):
        return (
            static_property_key(node) == 'constructor'
            and not is_member_write_target(node)
            and not _constructor_read_is_harmless(node)
        )
    if isinstance(node, JsProperty) and isinstance(node.parent, JsObjectPattern):
        return node.computed or _property_key_name(node) in (None, 'constructor')
    return False


def _concatenation_spells(concatenations: list[JsBinaryExpression], text: str) -> bool:
    """
    Whether one of the `+` concatenations, each listed before those it holds, or a part of one,
    spells *text* from constant strings, as `static_string` reads it. They are read from the inside
    out, each once, and a string longer than *text* is kept only as long as it takes to stay longer,
    so a chain of concatenations costs its length rather than its square.
    """
    limit = len(text) + 1
    spelled: dict[Node, str | None] = {}

    def part(node: Node | None) -> str | None:
        node = strip_parens(node)
        if isinstance(node, JsBinaryExpression) and node.operator == '+':
            return spelled.get(node)
        return static_string(node)

    for concatenation in reversed(concatenations):
        left = part(concatenation.left)
        right = part(concatenation.right) if left is not None else None
        if left is None or right is None:
            spelled[concatenation] = None
            continue
        value = spelled[concatenation] = (left + right)[:limit]
        if value == text:
            return True
    return False


def _declared_parameter(declaration: Node) -> tuple[JsFunctionNode, int, Node | None] | None:
    """
    The function whose parameter list declares the name *declaration* as a plain name, with or
    without a default, together with the position of that parameter and its default, or `None`.
    """
    parameter, parent, default = declaration, declaration.parent, None
    if isinstance(parent, JsAssignmentPattern) and parent.left is declaration:
        parameter, parent, default = parent, parent.parent, parent.right
    if not isinstance(parent, FUNCTION_NODES):
        return None
    for position, candidate in enumerate(parent.params):
        if candidate is parameter:
            return parent, position, default
    return None


def constructed_class(function: Node) -> JsClassDeclaration | JsClassExpression | None:
    """
    The class whose constructor the function *function* is, or `None`.
    """
    method = function.parent
    if (
        not isinstance(method, JsMethodDefinition)
        or method.kind is not JsMethodKind.CONSTRUCTOR
        or method.value is not function
    ):
        return None
    body = method.parent
    cls = body.parent if isinstance(body, JsClassBody) else None
    return cls if isinstance(cls, (JsClassDeclaration, JsClassExpression)) else None


def _call_of(node: Node) -> JsCallExpression | JsNewExpression | None:
    """
    The call or `new` that *node*, through any parentheses, is the callee of, or `None`.
    """
    call = enclosing_operator(node)
    if isinstance(call, (JsCallExpression, JsNewExpression)) and strip_parens(call.callee) is node:
        return call
    return None


def _extended_by(read: Node) -> JsClassDeclaration | JsClassExpression | None:
    """
    The class whose `extends` clause is the read *read*, or `None`.
    """
    cls = enclosing_operator(read)
    if isinstance(cls, (JsClassDeclaration, JsClassExpression)) and strip_parens(cls.super_class) is read:
        return cls
    return None


def _super_calls(cls: JsClassDeclaration | JsClassExpression) -> list[JsCallExpression] | None:
    """
    The `super` calls in the constructor of the class *cls*, or `None` when the class has no
    constructor of its own: the one the language gives it passes every argument on.
    """
    for member in cls.body.body if cls.body is not None else ():
        if not isinstance(member, JsMethodDefinition) or member.value is None:
            continue
        if member.kind is not JsMethodKind.CONSTRUCTOR:
            continue
        calls: list[JsCallExpression] = []
        for node in walk_receiver_scope(member.value):
            if not isinstance(node, JsCallExpression):
                continue
            callee = strip_parens(node.callee)
            if isinstance(callee, JsIdentifier) and callee.name == 'super':
                calls.append(node)
        return calls
    return None


def _constructed_without_its_name(cls: JsClassDeclaration | JsClassExpression) -> bool:
    """
    Whether the class *cls* may be constructed without a read of its name: a decorator receives
    it, or a static member reads `this`, which is the class there.
    """
    if cls.decorators:
        return True
    for member in cls.body.body if cls.body is not None else ():
        if isinstance(member, (JsMethodDefinition, JsPropertyDefinition)) and member.decorators:
            return True
        if isinstance(member, JsStaticBlock):
            receiver = member
        elif isinstance(member, JsMethodDefinition) and member.is_static:
            receiver = member.value
        elif isinstance(member, JsPropertyDefinition) and member.is_static:
            receiver = member
        else:
            continue
        if receiver is None:
            continue
        for node in receiver.walk():
            if isinstance(node, JsThisExpression) and receiver_owner(node) is receiver:
                return True
    return False


def _passed_at(call: JsCallExpression | JsNewExpression, position: int) -> tuple[Node | None, bool]:
    """
    The argument *call* passes at *position*, `None` when it passes none there, and whether a
    spread at or before the position hides which argument that is.
    """
    arguments = call.arguments
    if any(isinstance(strip_parens(argument), JsSpreadElement) for argument in arguments[:position + 1]):
        return None, True
    if position < len(arguments):
        return strip_parens(arguments[position]), False
    return None, False


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
    freezes every removal in it; `timer_callee_name` because it names a callee it will act on.
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


def _property_key_name(prop: JsProperty) -> str | None:
    """
    The name the object-pattern property *prop* reads, when it is statically known: a string-literal
    key (`{['eval']: e}` names `eval` as surely as `{eval: e}` does), or a plain non-computed
    identifier key. A computed identifier key (`{[k]: e}`) names the value the variable holds, not
    the text it spells, and a computed non-literal names nothing static, so both answer `None`.
    """
    key = prop.key
    if isinstance(key, JsStringLiteral):
        return key.value
    if isinstance(key, JsIdentifier) and not prop.computed:
        return key.name
    return None


def _property_key_is_dynamic(prop: JsProperty) -> bool:
    """
    Whether the object-pattern property *prop* reads a key only the runtime resolves — a computed
    key that is not a string literal (`{[k]: e}`, `{['ev' + 'al']: e}`). Off the global object such a
    read designates an unknown global, the destructuring counterpart of the computed member access
    `_is_reflective_member` treats as a surface: the key could resolve to `eval` or `Function`, so a
    caller proving a destructuring names no reflective intrinsic cannot clear it.
    """
    return prop.computed and not isinstance(prop.key, JsStringLiteral)


class _PatternExposure(NamedTuple):
    """
    What reflective intrinsics an object destructuring pattern could bind, decided from the
    pattern alone: the precise names it reads under a statically known key (`eval`/`Function`,
    whether a plain key `{eval}`, a renamed key `{eval: e}`, or a string-literal computed key
    `{['eval']: e}`), whether any key is one only the runtime resolves (`{[k]: e}`), and whether a
    rest element (`{...r}`) captures whatever else the source holds. The caller supplies the
    separate check that the source may be the global object; only then do these say a reflective
    intrinsic is exposed.
    """
    named: tuple[str, ...]
    dynamic_key: bool
    rest: bool


def _pattern_reflective_exposure(pattern: JsObjectPattern) -> _PatternExposure:
    """
    Classify an object pattern's reflective exposure. A property is read three ways: a precise
    reflective-intrinsic key contributes its name, a runtime-resolved computed key sets
    `dynamic_key`, and a rest element sets `rest`. A truncated-source error node among the
    properties is neither a property nor a rest element and is skipped, not treated as a rest that
    captures everything.
    """
    named: list[str] = []
    dynamic_key = False
    rest = False
    for prop in pattern.properties:
        if isinstance(prop, JsRestElement):
            rest = True
        elif isinstance(prop, JsProperty):
            if _property_key_is_dynamic(prop):
                dynamic_key = True
            else:
                name = _property_key_name(prop)
                if name is not None and name in REFLECTIVE_INTRINSICS:
                    named.append(name)
    return _PatternExposure(tuple(named), dynamic_key, rest)


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

#: The binding kinds a plain store never refuses: every one of them is a mutable binding that
#: exists before any code of its scope runs.
_BINDINGS_A_STORE_CANNOT_REFUSE = frozenset({
    BindingKind.VAR,
    BindingKind.FUNCTION,
    BindingKind.PARAM,
    BindingKind.CATCH,
})


def _is_delete_operand(node: Node) -> bool:
    """
    Whether *node* stands as the operand of a `delete`. `reference_role` answers `Role.READWRITE`
    for such a reference as it does for a compound assignment, because both keep the name live as a
    read; only the assignment puts a value under the name.
    """
    return _is_unary_operand(enclosing_operator(node), node, _DELETE_OPERATOR)


def _displaces_arguments(
    binding: Binding,
    fn: JsFunctionExpression | JsFunctionDeclaration | JsScript,
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
        if not isinstance(fn, JsScript) and site is fn.id:
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

    The key is read as `element_positions` reads it.
    """
    positions = element_positions(member)
    if positions is None or positions.stop <= count:
        return positions
    return range(0)


def element_positions(member: JsMemberExpression) -> range | None:
    """
    The element positions the member access *member* names, or `None` where its key is not
    statically known. A key that is the canonical spelling of an index designates that one
    element; a key that is statically known and is not, such as `length` or `callee`, designates
    the empty range.

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
    if index is None or index < 0:
        return range(0)
    return range(index, index + 1)


def _is_a_named_global_object_base(node: Node | None) -> bool:
    """
    Whether *node* denotes the global object by one of the names written for it, which is
    `is_global_object_base` without the positional reading of `this`. Only `timer_callee_name`
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


def timer_callee_name(callee: Node | None) -> str | None:
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
    global (see `timer_callee_name`).
    """
    if timer_callee_name(call.callee) is None:
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

    def __init__(
        self,
        root: JsScript,
        environment: HostEnvironment = HostEnvironment.universal,
        trust_eval: bool = False,
        file_kind: FileKind = FileKind.script,
        exports_read_outside: bool = True,
    ):
        self.root = root
        self.environment = environment
        self.trust_eval = trust_eval
        self.file_kind = file_kind
        self.exports_read_outside = exports_read_outside
        self._module_exports_unread: bool | None = None
        self._code_load_sites: list[Node] | None = None
        self._node_scope: dict[Node, Scope] = {}
        self._binding_of: dict[Node, Binding] = {}
        self._reflection_surface: bool | None = None
        self._opaque_surface_sites: list[Node] | None = None
        self._opaque_global_write: bool | None = None
        self._opaque_global_write_sites: list[JsMemberExpression] | None = None
        self._opaque_global_write_sites_known = False
        self._recording_def_use = False
        self._dispatch_surface_reached: bool | None = None
        self._function_direct_eval_sites: dict[int, list[Node]] = {}
        self._function_unread_source_sites: dict[int, list[Node]] = {}
        self._dynamic_rebind_sites: dict[Binding, list[Node] | None] = {}
        self._built = False
        self._spells_caller: bool | None = None
        self._constructors_escape: bool | None = None
        self._values_through_calls: dict[Binding, tuple[list[Node], bool]] = {}
        self._shown_calls: dict[Node, tuple[list[JsCallExpression | JsNewExpression], bool]] = {}
        self._module_may_be_reentered = False
        self._annex_b_copies: list[AnnexBCopy] = []
        self.root_scope: Scope = _ScopeBuilder(self).build(root)
        self._build_def_use()
        self._deleted_host_globals: frozenset[str] = self._scan_deleted_host_globals()
        self._built = True

    def scope_of(self, node: Node) -> Scope | None:
        """
        The innermost scope that lexically contains *node*, or `None` if the node was not part of the
        script the model was built from.
        """
        return self._node_scope.get(node)

    def knows(self, node: Node) -> bool:
        """
        Whether the model was built over *node*. The model holds every node it maps, so a node made
        after the build is never taken for one it mapped.
        """
        return node in self._node_scope

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
        site. The name of a function declared in a block introduces the block's binding, which this
        answers; where Annex B copies it, the `var` the copy writes lists the name among its own
        declarations as well (`AnnexBCopy`).
        """
        return self._binding_of.get(decl_id)

    def lookup(
        self,
        name: str,
        scope: Scope | None,
        *,
        cross_dynamic: bool = False,
        exclude: Collection[Binding] = (),
    ) -> Binding | None:
        """
        Resolve *name* from *scope* outward through enclosing scopes, stopping at a dynamically-scoped
        region where the name could be injected at runtime. Returns `None` for a free name. With
        *cross_dynamic*, the walk does not stop at a dynamic boundary but continues outward to the binding
        the name would denote if the `with` object lacked the property — the lexical binding a dynamic
        scope could still reach at runtime — which is how a `with`-body reference is attributed to the
        binding it may touch. The default keeps the definite-resolution semantics every other caller
        relies on.

        A binding in *exclude* is passed over as though its scope did not bind the name: the
        simulated post-rewrite resolution an atomic fold admits against, where one edit splices a
        body and deletes the bindings the splice consumes together. What the name denotes without
        them is what the tree after that edit reads.
        """
        while scope is not None:
            binding = scope.bindings.get(name)
            if binding is not None and binding not in exclude:
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
        return is_use_position(node) and node not in self._binding_of

    def resolve(self, ref: JsIdentifier) -> Binding | None:
        """
        The binding a referencing identifier reads or writes, found by walking outward from its scope.
        Returns `None` when the name is free (an external global the program never assigns), when the
        identifier is not a reference (a property name, key, or label), or when resolution crosses a
        dynamically-scoped region where the name could be injected at runtime.
        """
        if not self.is_reference(ref):
            return None
        return self.lookup(ref.name, self._node_scope.get(ref))

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
        return crosses_dynamic_scope(self._node_scope.get(node))

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
        mandates everywhere, so `globalThis` resolves while the other `GLOBAL_OBJECT_ALIASES`
        spellings (`window`, `self`, `top`, `frames`, `global`) are a *host* assumption rather than
        a language one, and are not admitted: no host defines all of them, so a bare `window` throws
        under Node exactly as a bare `global` throws in a browser. An analyst who knows the host
        pins it with the `djs` unit's `-e` switch, and the names that host guarantees become certain
        here, recovering the reading the sound default refuses — except a host-conditional global
        the program `delete`s off a same-realm alias, which `_scan_deleted_host_globals` withholds
        program-wide so the bare read keeps its throw. Unpinned, the read is answered may-throw so
        no pass drops the `ReferenceError` the absent host raises, and `_base_is_safe` agrees,
        refusing to clear a property access on such an alias. Everything else may not be there:

        - a free name, which reaches the host and may simply not exist
        - a name whose only binding is an `IMPLICIT_GLOBAL`, which the assignment that creates it
          brings into existence, so a read that runs first — or whose creating assignment sits in a
          function nobody calls — throws exactly as a free name does
        - a name resolved through a `with` body whose object may not carry it and which has no
          lexical binding to fall through to, which the `cross_dynamic` lookup is what distinguishes
        - a binding one way the file may run has and another does not (`Binding.may_be_absent`)

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
        scope = self._node_scope.get(node)
        binding = self.lookup(node.name, scope, cross_dynamic=True)
        return (
            binding is None
            or binding.kind is BindingKind.IMPLICIT_GLOBAL
            or binding.may_be_absent
        )

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
            if self.lookup(base.name, self._node_scope.get(base)) is not None:
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

    def statement_cannot_throw(
        self,
        statement: Node | None,
        store_cannot_throw: Callable[[JsAssignmentExpression], bool] | None = None,
    ) -> bool:
        """
        Whether evaluating *statement* throws on no run at all, so that a run leaving it for a
        handler never leaves it half done. Only a declaration of plain names, a function declaration
        and an expression statement qualify, the first and the last when `evaluation_cannot_throw`
        holds for everything they evaluate. Binding a destructuring pattern can throw after its
        initializer ran, and a `var` declared inside a `with` body stores through the object, whose
        setter may throw, so a declaration with either does not qualify. Reaching a function
        declaration does nothing, since its function is in place before the statements of its scope
        run, except where Annex B copies it out of its block: that copy stores the function into the
        name of the enclosing scope, which is ruled as every other store into a declared name is. A
        declaration standing as the target of a `for-in` or `for-of` head is asked as the store of
        the value the head hands it on every iteration. *store_cannot_throw* is handed on to
        `evaluation_cannot_throw`.
        """
        if isinstance(statement, JsVariableDeclaration):
            for declarator in statement.declarations:
                if not isinstance(declarator, JsVariableDeclarator):
                    return False
                target = declarator.id
                if not isinstance(target, JsIdentifier):
                    return False
                binding = self.binding_of(target)
                if binding is None or crosses_dynamic_scope(self._node_scope.get(target)):
                    return False
                init = declarator.init
                each_iteration = _loop_head_assigns(declarator)
                if init is not None and each_iteration:
                    return False
                if (
                    (init is not None or each_iteration)
                    and not binding.is_lexical
                    and not self._stores_into_without_throwing(binding, declarator)
                ):
                    return False
                if init is not None and not self.evaluation_cannot_throw(init, store_cannot_throw):
                    return False
            return True
        if isinstance(statement, JsFunctionDeclaration):
            binding = None if statement.id is None else self.binding_of(statement.id)
            if binding is None:
                return False
            copy = _copy_made_by(binding, statement)
            if copy is None:
                return True
            return self._stores_into_without_throwing(copy.var, statement)
        if isinstance(statement, JsExpressionStatement):
            return self.evaluation_cannot_throw(statement.expression, store_cannot_throw)
        return False

    def evaluation_cannot_throw(
        self,
        node: Node | None,
        store_cannot_throw: Callable[[JsAssignmentExpression], bool] | None = None,
    ) -> bool:
        """
        Whether evaluating the expression *node* throws on no run at all. Deliberately minimal: a
        primitive literal, a function value, a read that neither `read_may_raise_reference_error`
        nor `read_has_dynamic_effect` flags, and a plain `=` store of such a value to a name, joined
        by parentheses and the comma operator.

        A store to a name cannot throw when the name resolves, through no `with` body, to a `var`,
        a function, a parameter or a catch binding, unless it is a strict store to a script-level
        `var` or function. Such a binding is a property of the global object, whose attributes are
        the host's: the language makes `undefined`, `NaN` and `Infinity` read-only, and a browser
        gives `window`, `document`, `top`, `navigator` and many more a getter without a setter,
        which a strict store refuses and a sloppy one ignores. A `let` may still be in its temporal
        dead zone, a `const` refuses every store, and a function expression's own name and a name
        nothing declares refuse a strict one. *store_cannot_throw* vouches for any other store its
        caller holds a proof for.
        """
        if node is None:
            return False
        if isinstance(node, (
            JsStringLiteral,
            JsNumericLiteral,
            JsBooleanLiteral,
            JsNullLiteral,
        )):
            return True
        if isinstance(node, FUNCTION_NODES):
            return True
        if isinstance(node, JsParenthesizedExpression):
            return self.evaluation_cannot_throw(node.expression, store_cannot_throw)
        if isinstance(node, JsSequenceExpression):
            return all(
                self.evaluation_cannot_throw(part, store_cannot_throw) for part in node.expressions
            )
        if isinstance(node, JsIdentifier):
            return (
                self.is_reference(node)
                and not self.read_has_dynamic_effect(node)
                and not self.read_may_raise_reference_error(node)
            )
        if isinstance(node, JsAssignmentExpression):
            if node.operator != '=':
                return False
            target = strip_parens(node.left)
            if not isinstance(target, JsIdentifier):
                return False
            binding = self.resolve(target)
            vouched = binding is not None and self._stores_into_without_throwing(binding, node)
            if not vouched and (store_cannot_throw is None or not store_cannot_throw(node)):
                return False
            return self.evaluation_cannot_throw(node.right, store_cannot_throw)
        return False

    def _stores_into_without_throwing(self, binding: Binding, store: Node) -> bool:
        if binding.kind not in _BINDINGS_A_STORE_CANNOT_REFUSE or binding.may_be_absent:
            return False
        return binding.scope is not self.root_scope or not strict_mode_at(store)

    def _naming_binding(self, function: Node) -> Binding | None:
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

    def function_names(self, function: Node) -> FunctionNames | None:
        """
        The names *function* is called and observed through, or `None` for a function no name
        holds: an IIFE, a callback, a function stored through anything but a name, which a consumer
        reads as running where it stands or wherever what holds it hands it on. The own name is the
        declared name of a function declaration, the one declarator a function or arrow expression
        initializes, or the name a lone assignment installs it in (`f = function(){}`), so that a
        function held in a hoisted `var` assigned once is ordered by its calls rather than by its
        creation. A function declared in a block has the `var` Annex B copies it into as a second
        name wherever something observes that copy (`AnnexBCopy.observed`).

        A caller confirms that each name is singly declared, `binding_pinned_to` *function*, and
        free of dynamic references before trusting its reads to enumerate every invocation.
        """
        own = self._invocation_binding(function)
        if own is None:
            return None
        copy = None
        if isinstance(function, JsFunctionDeclaration):
            copy = _copy_made_by(own, function)
        if copy is not None and not copy.observed:
            copy = None
        return FunctionNames(own, copy)

    def _invocation_binding(self, function: Node) -> Binding | None:
        """
        The own name of `function_names`.
        """
        binding = self._naming_binding(function)
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

    def name_holding(self, read: Node) -> Binding | None:
        """
        The one name the value read at *read* is stored into, when *read* is the whole value a
        declarator or an assignment whose own value is discarded stores into a name. An assignment
        whose value is used hands it on as well, so its target is not the one name holding the
        value: `f(x = ref)` and `var y = (x = ref)`.
        """
        store = enclosing_operator(read)
        if isinstance(store, JsVariableDeclarator):
            if strip_parens(store.init) is not read or not isinstance(store.id, JsIdentifier):
                return None
            return self.binding_of(store.id)
        if not isinstance(store, JsAssignmentExpression):
            return None
        if store.operator != '=' or strip_parens(store.right) is not read:
            return None
        if not value_is_discarded(store):
            return None
        target = strip_parens(store.left)
        if not isinstance(target, JsIdentifier):
            return None
        return self.resolve(target)

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
        as one that does. A copy Annex B makes into the name is a write too, and it unpins the name
        unless it stores the function its declaration declares (`copy_stores_the_function`).
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
        if not all(self.copy_stores_the_function(copy) for copy in binding.copies_received):
            return False
        return all(write is establishing for write in binding.writes)

    def copy_stores_the_function(self, copy: AnnexBCopy) -> bool:
        """
        Whether *copy* stores the function its declaration declares, and nothing else can come of
        the function through the block binding: the block binding has that one declaration, no write
        of any kind and nothing that could rebind it at run time, so it holds the function wherever
        the copy runs; and every other read of it calls or constructs it, so the one function object
        the two names share is not handed on, stored or given properties through the name the `var`
        cannot see.
        """
        block = copy.block
        if (
            len(block.declarations) != 1
            or block.writes
            or block.has_indefinite_write
            or block.dynamic_refs
            or self.binding_maybe_reassigned_dynamically(block)
        ):
            return False
        return all(
            isinstance(read, JsFunctionDeclaration) or is_constructed_or_invoked(read)
            for read in block.reads
        )

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
        value arrived without saying which. A write through a member access on a global-object alias
        is left unread and breaks completeness too: which member accesses are such writes depends on
        the names holding the global object, and those are found from these values
        (`_bindings_holding_the_global_object`), so a value read out of such a write would feed the
        very set that decides whether it is one. A binding with no declaration — an implicit global,
        and the binding `_ensure_implicit_global_from_alias_write` mints — contributes nothing and
        is never complete, even where the file assigns it by name. With *ignore_dynamic_rebinds* the
        dynamic-rebind conjunct is left out of the completeness verdict: the values answer what the
        text spells, and whether a rebind crosses a given read is the caller's ordering question
        over `binding_dynamic_rebind_sites`.

        The values hold wherever the name is not in their temporal dead zone; a bare declarator
        contributes no value even though the name reads `undefined` there, and a consumer that needs a
        value established before a use orders it separately (`binding_establishment_sites`). A
        recognizer whose safe direction is admitting decides on ANY value and ignores completeness; a
        consumer whose rewrite needs the binding to hold nothing else requires completeness first, and
        must also require a value, since a complete empty list answers every universal question
        vacuously. `refinery.lib.scripts.js.analysis.intrinsics._binding_value_roots` is the
        may-side sibling that over-approximates where this list refuses, and
        `refinery.lib.scripts.js.analysis.reaching.ReachingModel._value_definitions` the flow-aware
        one that enumerates kill sites rather than values.
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
        call supplies no argument for maps to `None` and stays incomplete, unless the parameter list
        gives it a default; the default is then one of its values, as it is beside an argument that
        may be `undefined`. Every other rule is
        `binding_values`' own: a write the text spells no value for, and any dynamic rebinding —
        a direct `eval` in the function, and a write through its own `arguments` object — still
        poison the answer. For a binding *arguments* does not cover, the answer is exactly
        `binding_values`.
        """
        channels, complete = self._binding_value_channels(binding, arguments)
        return [value for _, value in channels], complete

    def values_through_calls(self, binding: Binding | None) -> tuple[list[Node], bool]:
        """
        `binding_values`, with a parameter read through the calls of its function the text shows:
        its values are its own writes, its default, and the argument each such call passes at its
        position (`values_at_call`). A call shown is a call or `new` directly through a name
        holding the function, its own name included, or the call of a function written as the
        callee; for a class constructor, a `new` of its class the same way, and a `super` call in
        the constructor of a class extending it. A value one of these calls passes is listed
        whatever other calls exist and whatever the other parameters are; only a spread at or
        before the position hides which argument the call passes there.

        The list is complete only when no call can come another way (`_calls_shown`) and every
        shown call passes an argument at the position, or the parameter has a default. Every
        consumer reads a parameter through here, so none can forget a way a call comes. Memoized
        per binding.
        """
        if binding is None or not binding.declarations:
            return self.binding_values(binding)
        declared = _declared_parameter(binding.declarations[0])
        if declared is None:
            return self.binding_values(binding)
        cached = self._values_through_calls.get(binding)
        if cached is not None:
            return cached
        function, position, default = declared
        values, _ = self.binding_values(binding)
        listed = {id(value) for value in values}

        def list_value(value: Node) -> None:
            if id(value) not in listed:
                listed.add(id(value))
                values.append(value)

        calls, complete = self._calls_shown(function)
        for call in calls:
            argument, hidden = _passed_at(call, position)
            if hidden:
                complete = False
                continue
            received, received_all = self.values_at_call(binding, {binding: argument})
            complete = complete and received_all
            for value in received:
                list_value(value)
        if default is not None:
            list_value(default)
        cached = self._values_through_calls[binding] = values, complete
        return cached

    def arguments_through_calls(self, function: JsFunctionNode, position: int | None) -> tuple[list[Node], bool]:
        """
        What an element of the `arguments` of *function* holds: the arguments the calls of the
        function the text shows (`values_through_calls`) pass at *position*, or at any position
        when it is `None`. The list is complete only when no call can come another way
        (`_calls_shown`) and every shown call passes an argument there that no spread hides.
        """
        calls, complete = self._calls_shown(function)
        passed: list[Node] = []
        for call in calls:
            if position is None:
                for argument in call.arguments:
                    argument = strip_parens(argument)
                    if isinstance(argument, JsSpreadElement):
                        complete = False
                    elif argument is not None:
                        passed.append(argument)
                continue
            argument, _ = _passed_at(call, position)
            if argument is None:
                complete = False
            else:
                passed.append(argument)
        return passed, complete

    def _names_calling(self, held: Node) -> list[tuple[Binding, list[ReferenceNode]] | None]:
        """
        The names the function or class *held* is called or constructed through, each with the
        reads through which it reaches *held*: its declared names (`function_names`), or the one
        name a declarator or an assignment statement stores it into (`name_holding`), and the own
        name of a function or class expression. `None` stands for a holder that is no name. One
        written as the callee of a call or a `new` is held by none.
        """
        names: list[tuple[Binding, list[ReferenceNode]] | None] = []
        if isinstance(held, JsFunctionDeclaration):
            declared = self.function_names(held)
            if declared is None:
                names.append(None)
            else:
                names.extend((name, declared.reads_of(name)) for name in declared.bindings)
        elif isinstance(held, JsClassDeclaration):
            own = self.binding_of(held.id) if isinstance(held.id, JsIdentifier) else None
            names.append(None if own is None else (own, own.reads))
        elif _call_of(held) is None:
            holder = self.name_holding(held)
            names.append(None if holder is None else (holder, holder.reads))
        if isinstance(held, (JsFunctionExpression, JsClassExpression)) and isinstance(held.id, JsIdentifier):
            own = self.binding_of(held.id)
            names.append(None if own is None else (own, own.reads))
        return names

    def reached_only_by_shown_calls(self, function: JsFunctionNode) -> bool:
        """
        Whether every way to *function* is a call the text shows or a test of its names
        (`SemanticModel._calls_shown`), and no class extends it, so that nothing reads a property
        of it: the static code of a class extending it reads its properties through `super`.
        """
        if not self._calls_shown(function)[1]:
            return False
        return not any(
            _extended_by(read) is not None
            for _, reads in self._shown_names(function)
            for read in reads
        )

    def names_reaching(self, function: JsFunctionNode) -> list[Binding]:
        """
        The names `reached_only_by_shown_calls` follows to *function*: those of the class it
        constructs where it is a constructor, and its own otherwise.
        """
        return [binding for binding, _ in self._shown_names(function)]

    def _shown_names(self, function: JsFunctionNode) -> list[tuple[Binding, list[ReferenceNode]]]:
        """
        The names `_calls_shown` follows to *function* or to the class it constructs, each with its
        reads.
        """
        held = constructed_class(function) or function
        return [named for named in self._names_calling(held) if named is not None]

    def _calls_shown(self, function: JsFunctionNode) -> tuple[list[JsCallExpression | JsNewExpression], bool]:
        """
        The calls of *function* the text shows, in the sense of `values_through_calls`, and whether
        no call can come another way: every read of the names it is called through is such a call,
        only tested (`read_is_only_tested`), or the `extends` clause of a class whose own
        constructor makes the `super` calls shown, or which has none, so that its own calls are
        shown in turn; the names of such a class are read the same way, since its prototype is the
        one it extends; each name holds the function, or the class it constructs, alone and is
        neither exported nor reached through a handed object or by reflection; no class among them
        can be constructed without its name (`_constructed_without_its_name`); the function reaches
        itself neither through its own `arguments` beyond an index, its length, a spread or `apply`
        (`arguments_name_their_function`) nor through `new.target` (`references_new_target`); the
        program spells no `caller` (`spells_caller`); and where a shown call constructs it, no
        `constructor` property escapes (`constructors_may_escape`), which an instance would call it
        through. Memoized per function.
        """
        cached = self._shown_calls.get(function)
        if cached is not None:
            return cached
        calls: list[JsCallExpression | JsNewExpression] = []
        complete = not (
            self.spells_caller()
            or arguments_name_their_function(function)
            or references_new_target(function)
        )
        root = constructed_class(function) or function
        pending: list[Node] = [root]
        seen = {root}
        while pending:
            held = pending.pop()
            own = held.id if isinstance(held, (JsFunctionExpression, JsClassExpression)) else None
            cls = held if isinstance(held, (JsClassDeclaration, JsClassExpression)) else None
            forwards = held is root or (cls is not None and _super_calls(cls) is None)
            if cls is not None and _constructed_without_its_name(cls):
                complete = False
            direct = _call_of(held)
            if direct is not None and forwards:
                calls.append(direct)
            for named in self._names_calling(held):
                if named is None:
                    complete = False
                    continue
                name, reads = named
                if (
                    name.exported
                    or name.written_at_entry
                    or name.reachable_through_a_handed_object
                    or self.reflection_can_reach(name)
                ):
                    complete = False
                if own not in name.declarations and strip_parens(self.singular_value(name)) is not held:
                    complete = False
                for read in reads:
                    call = _call_of(read)
                    subclass = _extended_by(read)
                    if call is not None:
                        if forwards:
                            calls.append(call)
                    elif subclass is not None:
                        calls.extend(_super_calls(subclass) or ())
                        if subclass not in seen:
                            seen.add(subclass)
                            pending.append(subclass)
                    elif not read_is_only_tested(read):
                        complete = False
        if (
            complete
            and any(isinstance(call, JsNewExpression) for call in calls)
            and self.constructors_may_escape()
        ):
            complete = False
        cached = self._shown_calls[function] = calls, complete
        return cached

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
        if binding.supplied_by_host and not any(
            isinstance(declaration.parent, JsFunctionDeclaration)
            and declaration.parent.id is declaration
            for declaration in binding.declarations
        ):
            complete = False
        for declaration in binding.declarations:
            parent = declaration.parent
            if (
                isinstance(parent, (JsFunctionDeclaration, JsClassDeclaration))
                and parent.id is declaration
            ):
                copy = _copy_received_by(binding, parent)
                if copy is None or (not copy.conditional and self.copy_stores_the_function(copy)):
                    channels.append((parent, parent))
                else:
                    complete = False
            elif isinstance(parent, JsVariableDeclarator) and parent.id is declaration:
                if _loop_head_assigns(parent):
                    complete = False
                if parent.init is not None:
                    channels.append((parent, parent.init))
            elif (
                arguments is not None
                and binding in arguments
                and (parameter := _declared_parameter(declaration)) is not None
            ):
                argument = arguments[binding]
                default = parameter[2]
                if argument is not None:
                    channels.append((declaration, argument))
                if default is not None:
                    channels.append((declaration, default))
                elif argument is None:
                    complete = False
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

    def binding_establishment_sites(
        self, binding: Binding | None, *, ignore_dynamic_rebinds: bool = False,
    ) -> list[Node] | None:
        """
        The nodes that must all have executed before *binding*'s `singular_value` is installed, for a
        consumer that gates a use on execution order. An empty list when the value is hoisted into
        place before any statement runs — a function declaration — so no ordering is required; the
        declaration when the value is a function a copy Annex B makes stores there (`AnnexBCopy`);
        the declarator when the value is a `var`/`let`/`const` initializer, which is absent until that
        declarator runs; the class declaration when the value is a class, which is in its temporal
        dead zone until it runs; the recorded write when a lone assignment installs it
        (`f = function(){}`, the form namespace flattening leaves). `None` when the binding holds no
        single such value, so its presence cannot be ordered and the caller declines — decided by the
        same complete-singleton `binding_values` answer `singular_value` requires, so the two queries
        can never disagree about which bindings have an orderable value: one returns the value and
        the other the node that establishes it. With *ignore_dynamic_rebinds* that answer is read on
        the view `binding_values` documents, the one a positioned consumer orders rebind hazards
        against itself. Ordering the returned nodes against the use is the caller's job, since that
        needs the dominance model this layer must not depend on.
        """
        if binding is None:
            return None
        channels, complete = self._binding_value_channels(
            binding, ignore_dynamic_rebinds=ignore_dynamic_rebinds)
        if not complete or len(channels) != 1:
            return None
        site, _ = channels[0]
        if isinstance(site, JsFunctionDeclaration):
            return [site] if _copy_received_by(binding, site) is not None else []
        return [site]

    def is_shadowed(self, name: str, at: Node, outer: Scope) -> bool:
        """
        Whether *name*, referenced at *at*, resolves to a binding declared strictly inside *outer*
        rather than in *outer* itself or an enclosing scope. This replaces the various hand-rolled
        shadowing checks: a name shadowed below *outer* does not refer to *outer*'s binding.
        """
        binding = None
        if isinstance(at, JsIdentifier) and at.name == name:
            binding = self._copy_written_at(at)
        if binding is None:
            binding = self.lookup(name, self._node_scope.get(at))
        if binding is None:
            return False
        return outer.contains(binding.scope, strict=True)

    def _copy_written_at(self, node: Node) -> Binding | None:
        """
        The `var` Annex B copies the function into where *node* is the name of a function declared
        in a block: the declaration writes that name as well as declaring its own.
        """
        if not isinstance(node, JsIdentifier) or (own := self._binding_of.get(node)) is None:
            return None
        copy = _copy_made_by(own, node.parent)
        return None if copy is None else copy.var

    def may_run_as_strict(self, node: Node) -> bool:
        """
        Whether the code at *node* may run as strict code: the file may be an ES module, which is
        strict code throughout whatever its text says, or the text makes it strict.
        """
        return self.file_kind.may_be_an_es_module or strict_mode_at(node)

    def annex_b_copy_observed(self, declaration: JsFunctionDeclaration) -> bool:
        """
        Whether anything may observe the copy Annex B makes of the function *declaration*, declared
        in a block, or the `var` that copy declares: the `var` is read, written, named in a `with`
        body, exported, carried by an object handed to a call, or reachable by reflection. A write
        observes the `var` because without it the same assignment lands on whatever the name means
        outside the function, or creates a global. A declaration this model was not built over may
        be observed.
        """
        if declaration.id is None:
            return False
        block = self.binding_of(declaration.id)
        if block is None:
            return True
        return any(
            copy.observed
            or copy.var.writes
            or copy.var.has_indefinite_write
            or self.reflection_can_reach(copy.var)
            for copy in block.copies_made
            if copy.declaration is declaration
        )

    def declaration_may_land(
        self,
        names: set[str],
        scope: Scope,
        *,
        exclude: Collection[Binding] = (),
    ) -> bool:
        """
        Whether declarations of *names* may be introduced directly in *scope*: none of them captures
        a use already meaningful there (`would_capture`), and none lands on a binding the host
        supplies (`Binding.supplied_by_host`), which no identifier of the text spells for that walk
        to find. At the top of a CommonJS file a `let` of a parameter's name makes Node refuse the
        file as CommonJS, and a `var` of it starts out holding what the host passed rather than
        `undefined`.
        """
        for name in names:
            binding = scope.bindings.get(name)
            if binding is not None and binding.supplied_by_host:
                return False
        return not self.would_capture(names, scope, exclude=exclude)

    def would_capture(
        self, names: set[str], scope: Scope, *, exclude: Collection[Binding] = (),
    ) -> bool:
        """
        Whether introducing a binding for any of *names* directly in *scope* would capture an
        identifier already meaningful there. Every use-position occurrence of one of *names* within
        *scope*, including in a nested function that would close over the new binding, must already
        resolve to a binding strictly nested below *scope* (see `is_shadowed`); otherwise that
        occurrence — free, inherited from an enclosing scope, or bound in *scope* itself — would be
        rebound by the introduced declaration.

        A use resolving to a binding in *exclude* is skipped: the edit the caller asks this for
        deletes that binding with the same splice that introduces the declaration, so the use is
        carried off rather than captured. The natural binding is what decides membership — a
        resolution walked past an excluded binding answers where the name would land *after* the
        edit, which is the question the callers below `_admit_reflected_body` ask of their free
        names, not the one this capture rule asks of a use the tree still holds.
        """
        return next(self._capturing_uses(names, scope, exclude), None) is not None

    def captured_names(
        self, names: set[str], scope: Scope, *, exclude: Collection[Binding] = (),
    ) -> set[str]:
        """
        Those of *names* for which `would_capture` holds, read in one walk of *scope*.
        """
        return {node.name for node in self._capturing_uses(names, scope, exclude)}

    def _capturing_uses(
        self, names: set[str], scope: Scope, exclude: Collection[Binding],
    ) -> Iterator[JsIdentifier]:
        for node in name_uses_in_scope(names, scope):
            binding = (
                self._copy_written_at(node)
                or self.lookup(node.name, self._node_scope.get(node))
            )
            if binding in exclude:
                continue
            if binding is None or not scope.contains(binding.scope, strict=True):
                yield node

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

    def spells_caller(self) -> bool:
        """
        Whether the text spells the name `caller` anywhere: as a name, a property key or a string.
        In sloppy mode `g.caller` is whichever function called `g`, so a program spelling it can
        reach every function that calls another one without naming it. Memoized.
        """
        if self._spells_caller is None:
            self._spells_caller = any(_spells_caller_at(node) for node in self.root.walk())
        return self._spells_caller

    def constructors_may_escape(self) -> bool:
        """
        Whether a constructor may run on a receiver or with arguments of the program's choice: the
        program spells `"constructor"` in a string or in a concatenation of constant strings, reads
        a `constructor` property other than to construct with it, compare it, read its name or test
        it, or destructures one. An instance reaches the function that built it through that
        property, and so does its prototype. Memoized.
        """
        if self._constructors_escape is None:
            concatenations: list[JsBinaryExpression] = []
            escapes = False
            for node in self.root.walk():
                if isinstance(node, JsBinaryExpression):
                    if node.operator == '+':
                        concatenations.append(node)
                elif _lets_a_constructor_escape(node):
                    escapes = True
                    break
            self._constructors_escape = escapes or _concatenation_spells(concatenations, 'constructor')
        return self._constructors_escape

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
        but never while `_build_def_use` is still recording references: which member accesses reach
        the global object depends on the names holding it, which that step finds from the writes it
        records, so an answer taken inside it would depend on how far it had got; asked there, the
        conservative `True` is answered instead of a partial fact.
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
        if owner is None or self._named_by_global_code(binding):
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

    def _named_by_global_code(self, binding: Binding) -> bool:
        """
        Whether code running in the global scope, which every reflective surface but a direct `eval`
        runs, can name *binding*: an implicit global, and where the file is a script, every binding
        of its top scope. In a module of either kind a top-level declaration is scoped to the file,
        but a binding of its top scope that may be absent leaves its name to a global in the reading
        without it (`Binding.may_be_absent`).
        """
        owner = binding.scope.var_scope
        if owner is None or owner.kind is not ScopeKind.SCRIPT:
            return False
        return (
            binding.kind is BindingKind.IMPLICIT_GLOBAL
            or binding.may_be_absent
            or not self.file_kind.scopes_declarations_to_the_file
        )

    def _named_by_code_of_its_function(self, binding: Binding) -> bool:
        """
        Whether *binding* belongs to its function, or to the function a CommonJS host wraps around
        the file, in some way the file may run, so that a direct `eval` there can name it: every
        binding global code alone names is left out (`_named_by_global_code`). A binding of the top
        scope that may be absent is both, the file's own where it exists and a global's name where
        it does not (`Binding.may_be_absent`).
        """
        return binding.may_be_absent or not self._named_by_global_code(binding)

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

        Where the file is a module of either kind a declaration of the top-level scope is scoped to
        the file: global-scope code cannot name it, so it is reached the way a function-local is,
        from the file's own text only (`reflection_can_reach_from_its_scope`). An implicit global
        stays a global.
        """
        if self._named_by_global_code(binding):
            return self.has_reflection_surface() or self.has_opaque_global_write()
        return self.reflection_can_reach_from_its_scope(binding)

    def reflection_can_reach_from_its_scope(self, binding: Binding) -> bool:
        """
        Whether code standing in the scope of *binding* that this model cannot read could name it: a
        `with` body that names it, a direct `eval` in its function, or a span of that function this
        model never read. The scope of an implicit global is the global scope, where every
        reflective surface runs. Code in the global scope outside the file is not asked about, which
        is the whole question for a binding scoped to a function or to a module and one half of it
        for a declaration of a script's top scope (`reflection_can_reach`).
        """
        owner = binding.scope.var_scope
        if owner is None or binding.kind is BindingKind.IMPLICIT_GLOBAL:
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
        if owner is None or self._named_by_global_code(binding):
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
        A binding of the top scope that may be absent is a local of the CommonJS wrapper where it
        exists, and counts as one (`_named_by_code_of_its_function`).
        """
        owner = binding.scope.var_scope
        if owner is None or not self._named_by_code_of_its_function(binding):
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
        if owner is None or self._named_by_global_code(binding):
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
        return any(
            owner is None or owner.contains(scope)
            for owner in self._var_scopes_of_evals_before(node)
        )

    def direct_eval_declares_below(self, node: Node, outer: Scope) -> bool:
        """
        Whether a direct `eval` could have installed a `var` that a name written at *node* finds
        before its lookup reaches the scope *outer*: one whose var scope contains the scope of
        *node* and lies strictly inside *outer*. The bounded form of
        `free_name_reachable_by_direct_eval`, for a caller about to declare the name in *outer*.
        """
        scope = self.scope_of(node)
        if scope is None:
            return True
        return any(
            owner is None or owner.contains(scope) and outer.contains(owner, strict=True)
            for owner in self._var_scopes_of_evals_before(node)
        )

    def _var_scopes_of_evals_before(self, node: Node) -> Iterator[Scope | None]:
        """
        The var scope of every direct `eval` that can have run before *node* is evaluated, or `None`
        where the scope of one is unknown: all of them but those whose own argument holds *node*,
        which is evaluated before its `eval` runs (`free_name_reachable_by_direct_eval`).
        """
        enclosing = {id(node)}
        cursor = node.parent
        while cursor is not None:
            enclosing.add(id(cursor))
            cursor = cursor.parent
        for site in self._direct_eval_sites(self.root):
            if any(id(argument) in enclosing for argument in getattr(site, 'arguments', ())):
                continue
            site_scope = self.scope_of(site)
            yield site_scope.var_scope if site_scope is not None else None

    def bare_name_reaches_the_host(self, name: str, at: Node) -> bool:
        """
        Whether a bare *name* read at *at* denotes what the host supplies under that name: nothing
        binds it where *at* stands, not even an assignment the model records as an
        `IMPLICIT_GLOBAL`, no `with` body between *at* and the global scope may supply it from its
        object, and no direct `eval` may have declared it (`free_name_reachable_by_direct_eval`).
        *at* need not be an identifier, so a pass can ask before it writes the name there, as one
        that rewrites a `this` to `globalThis` must.
        """
        scope = self.scope_of(at)
        return (
            scope is not None
            and self.lookup(name, scope) is None
            and not crosses_dynamic_scope(scope)
            and not self.free_name_reachable_by_direct_eval(at)
        )

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
        (a global is not frozen on a global-scope surface, and a binding of the top scope that may
        be absent is a local of the CommonJS wrapper where it exists), and the unread-source leg
        reaches a global from anywhere in the file but a local only from its own function. An
        empty list is a binding no dynamic scope can rebind. Memoized per binding once the model is
        built: while it is, the references made through objects aliasing a binding are still being
        recorded, and an answer taken then would depend on how far that had got.
        """
        if binding in self._dynamic_rebind_sites:
            return self._dynamic_rebind_sites[binding]
        sites = self._dynamic_rebind_sites_of(binding)
        if self._built:
            self._dynamic_rebind_sites[binding] = sites
        return sites

    def _dynamic_rebind_sites_of(self, binding: Binding) -> list[Node] | None:
        if binding.written_at_entry:
            return None
        owner = binding.scope.var_scope
        sites = list(binding.indefinite_writes)
        if owner is not None and self._named_by_code_of_its_function(binding):
            sites.extend(self._direct_eval_sites(owner.node))
        if owner is None or self._named_by_global_code(binding):
            sites.extend(self._unread_source_sites(self.root))
        else:
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

    def binding_reflection_kill_sites(self, binding: Binding) -> list[Node] | None:
        """
        The AST nodes at which a reflective surface could change the value *binding* holds — the
        located kills a flow query orders a read against — or `None` when the question has no
        located answer.

        A script-scope binding is replaceable only by an opaque global write, and the existing
        `opaque_global_write_replacement_sites` answer is the whole of it: `None` under any
        whole-program reflective surface, which could write the name from anywhere, and the member
        sites otherwise. A function-local can change value only through a surface standing in its
        own scope: a direct `eval` in its owning function or a span of that function this model
        never read (`reflection_surface_sites`), or a reference a `with` body resolves at runtime
        (`dynamic_references`). Every `with`-governed reference counts, read or not — reading the
        bare name consults the `with` object first, and a getter there runs code that can rebind
        the local — so only a located answer keeps that hazard orderable rather than refusing on
        it. Each site is a node a consumer that has ordered a definition against a use can also
        order the kill against; `None` is the volatility it cannot.
        """
        owner = binding.scope.var_scope
        if owner is None or self._named_by_global_code(binding):
            return self.opaque_global_write_replacement_sites(binding)
        return self.reflection_surface_sites(binding) + self.dynamic_references(binding)

    def holds_what_the_host_passed(self, binding: Binding) -> bool:
        """
        Whether *binding* is supplied by the host and still holds what the host passed wherever it
        is read: nothing in the file declares or writes it, and no direct `eval` or span of source
        this model never read stands where it could. Where the ES-module reading leaves the name to
        a global, no reflective surface may reach it either.
        """
        return (
            binding.supplied_by_host
            and not binding.declarations
            and not binding.writes
            and self.binding_dynamic_rebind_sites(binding) == []
            and not (binding.may_be_absent and self.reflection_can_reach(binding))
        )

    def module_exports_unread(self) -> bool:
        """
        Whether nothing reads what the file stores in `module.exports`. Outside the file, only code
        that loads it reads its exports, and the run assumes none does unless told otherwise
        (`exports_read_outside`). Node's module registry is part of loading: a file reaching itself
        through `require.cache`, `require.main`, `process.mainModule` or a `require` or `import()`
        of its own path reads its exports as a loader does. Inside the file, the object the store
        replaces is read through the `module` the host passed, which is therefore named only as the
        target of a store `module.exports = v`, as the operand of `typeof`, or compared with `null`,
        and through the `arguments` of the function the host wraps around the file, which the file
        does not name, nor reaches through a function's `caller`. Memoized.
        """
        if self._module_exports_unread is None:
            self._module_exports_unread = self._compute_module_exports_unread()
        return self._module_exports_unread

    def _compute_module_exports_unread(self) -> bool:
        if self.exports_read_outside or not self.file_kind.may_be_commonjs:
            return False
        bindings = self.root_scope.bindings
        module = bindings.get('module')
        if module is None or not self.holds_what_the_host_passed(module):
            return False
        if self.reflection_can_reach(module) or self.local_reachable_by_direct_eval(module):
            return False
        if self.dynamic_references(module):
            return False
        if not all(_tests_or_replaces_the_exports(reference) for reference in self.references(module)):
            return False
        arguments = bindings.get('arguments')
        if arguments is not None and arguments.supplied_by_host and any(True for _ in self.references(arguments)):
            return False
        return not self.spells_caller()

    def supplied_from_outside(self, binding: Binding | None) -> bool:
        """
        Whether a name resolving to *binding* holds something the file does not supply: it resolves
        to no binding, so to a global the host may define, or to one the host passed and the file
        never replaces (`holds_what_the_host_passed`). A callee read through such a name runs
        nothing the file declares.
        """
        return binding is None or self.holds_what_the_host_passed(binding)

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

    def reaches_global_object(self, binding: Binding) -> bool:
        """
        Whether *binding* is a property of the global object at runtime — the global a free name in
        global-scope reflected code (a `Function` body, an indirect `eval`, a string timer) resolves to.
        An implicit global always is. A top-level `var`/function declaration is where the file is a
        script; in a module of either kind it is scoped to the file and never reaches the global. A
        top-level `let`/`const`/`class`, or any binding nested below the script, is a distinct
        lexical binding that global-scope code cannot see.
        """
        if binding.kind is BindingKind.IMPLICIT_GLOBAL:
            return True
        if self.file_kind.scopes_declarations_to_the_file:
            return False
        return (
            binding.scope is self.root_scope
            and binding.is_hoisted
        )

    def module_may_be_reentered(self) -> bool:
        """
        Whether code of another module can run after this module is linked and before its body has
        finished (`_lets_another_module_run`). A module in an import cycle with this one can then
        call an exported function before the declarations after its definition have run. A module
        that imports nothing is in no cycle and runs its whole body before any importer does, so
        every importer calls into it after its last statement.
        """
        return self._module_may_be_reentered

    def _direct_eval_sites(self, function: Node) -> list[Node]:
        """
        The direct `eval` call sites within *function* — every call whose callee, once parentheses are
        stripped, is the bare identifier `eval` (see `is_direct_eval_call`), the one reflective surface
        that runs in the function's own scope and can therefore name its locals. Nested functions are
        included, since a direct `eval` in a closure inherits the enclosing locals. The `with` surface is
        not scanned — a `with` body's accesses are attributed precisely as dynamic references — so only
        direct eval needs a per-function answer. Filed for every scope owning variables while the
        model is built (`_record_def_use_references`), and computed once and memoized for any other
        node.

        The trusting model (`trust_eval`) answers no sites: a direct `eval` whose argument cannot be
        resolved is the one surface that model assumes inert, so every consumer that freezes a local
        on it — the rebind hazards, the reflection surfaces, the install question a free name asks —
        loses the eval leg alone, and the other legs a `with` body or an unread span carries keep
        refusing.
        """
        if self.trust_eval:
            return []
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
        are included, since a span inside one names the enclosing locals too. Filed and memoized the
        way `_direct_eval_sites` is.
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
        return self.lookup(node.name, self._node_scope.get(node)) is None

    def code_load_sites(self) -> list[Node]:
        """
        The calls by which the program has Node's `require` load code its text does not hold
        (`_loads_code_from_outside`): a file, a package, or a built-in module that runs code. What
        such code does is unknown; what a loaded module commonly does is set up globals, such as a
        `window` for code written for a page or an AMD `define`. A question that orders a point
        against code the text does not hold takes these as sites
        (`refinery.lib.scripts.js.analysis.tampering.TamperingModel`, and the `typeof` of a global
        name through
        `refinery.lib.scripts.js.analysis.tampering.TamperingModel.code_load_may_precede`). They
        are no reflection surface: that would withdraw every trust the whole program is asked for
        from a file that holds one in a function it never calls. Memoized.
        """
        if self._code_load_sites is None:
            self._code_load_sites = [
                site for node in self.root.walk()
                if isinstance(node, (JsIdentifier, JsMemberExpression))
                and (site := self._loads_code_from_outside(node)) is not None
            ]
        return self._code_load_sites

    def imports_code(self) -> bool:
        """
        Whether the file has the host load code its text does not hold before its body runs: an
        `import` or an `export … from` declaration (`_lets_another_module_run`) naming a module
        that is not a built-in one running no code (`_specifier_loads_code`). The host links and
        evaluates every such module before the first statement of the file, wherever the
        declaration stands, so no point of the file is ordered before the load.
        """
        for statement in self.root.body:
            if not isinstance(statement, (JsImportDeclaration, JsExportAllDeclaration, JsExportNamedDeclaration)):
                continue
            if not _lets_another_module_run(statement):
                continue
            source = statement.source
            if self._specifier_loads_code(None if source is None else source.value):
                return True
        return False

    def _loads_code_from_outside(self, node: JsIdentifier | JsMemberExpression) -> Node | None:
        """
        The call `require(m)` *node* is the callee of, where it calls the host's `require` and may
        load code the text does not hold: *m* is not a string naming a built-in module that runs no
        code (`_specifier_loads_code`). The callee is the host's `require` where it is the name
        `require` resolving to no binding or to the one the host passed that the file does not
        declare or assign, or the member `module.require` of such a `module`, which is the same
        function. `None` where *node* is no such callee. A `require` read for anything but a call
        is not followed: real programs hold it under another name (`global.r = require`) and call
        it with built-in names, and a site at every such read would order nothing after it.
        """
        if isinstance(node, JsMemberExpression):
            base = strip_parens(node.object)
            if (
                not isinstance(base, JsIdentifier)
                or base.name != 'module'
                or static_property_key(node) != 'require'
                or not self._may_hold_what_the_host_passed(base)
            ):
                return None
        elif node.name != 'require' or not self.is_reference(node) or not self._may_hold_what_the_host_passed(node):
            return None
        call = enclosing_operator(node)
        if not isinstance(call, JsCallExpression) or strip_parens(call.callee) is not node:
            return None
        arguments = call.arguments
        if len(arguments) == 1 and isinstance(module := strip_parens(arguments[0]), JsStringLiteral):
            if not self._specifier_loads_code(module.value):
                return None
        return call

    def _may_hold_what_the_host_passed(self, name: JsIdentifier) -> bool:
        """
        Whether the name *name* may read what the CommonJS host passed under it: it resolves to no
        binding, or to the one the host passed that the file does not declare or assign.
        """
        binding = self.resolve(name)
        return binding is None or (binding.supplied_by_host and not binding.declarations and not binding.writes)

    def _specifier_loads_code(self, specifier: str | None) -> bool:
        """
        Whether loading the module *specifier* names runs code the file's text does not hold: it is
        not a built-in module that runs none (`node_require_runs_no_code`), nor `vm` under the
        trusting model, which assumes the code it runs inert since the program hands it as data.
        """
        if specifier is None:
            return True
        if node_require_runs_no_code(specifier):
            return False
        return not (self.trust_eval and specifier in ('vm', 'node:vm'))

    def _computed_read_aliases_a_global(self, member: JsMemberExpression) -> bool:
        """
        Whether *member* reads an unknown global under a runtime key through a name the file gives
        the global object — `g[k]` where `var g = globalThis`. `_is_reflective_member` recognizes
        the same read on a base spelled as the global object (`globalThis[k]`); an alias holds the
        object under another name, so a read of it under a key only the runtime resolves names any
        global just as the spelled base does, and is the same surface. A plain write (`g[k] = x`)
        stores a property and reads nothing, and is left to `has_opaque_global_write` as on the
        spelled base.
        """
        if not member.computed or isinstance(member.property, JsStringLiteral):
            return False
        if is_simple_assignment_target(member):
            return False
        return self.names_the_global_object(strip_parens(member.object))

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

        The trusting model (`trust_eval`) declines to count the surfaces of the kinds it assumes
        inert — the question `_surface_is_trusted` answers per node — so the whole-program surface
        and the site list lose exactly those and keep the rest.
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
                if self._reads_reflective_intrinsic(node) and not self._surface_is_trusted(node):
                    sites.append(node)
            elif isinstance(node, JsMemberExpression):
                surface = _is_reflective_member(node) or self._computed_read_aliases_a_global(node)
                if surface and not self._surface_is_trusted(node):
                    sites.append(node)
            elif isinstance(node, JsCallExpression):
                if _is_string_timer(node) and not self._surface_is_trusted(node):
                    sites.append(node)
            elif isinstance(node, (JsVariableDeclarator, JsAssignmentExpression)):
                if (
                    self._destructures_a_reflective_intrinsic(node)
                    and not self._surface_is_trusted(node)
                ):
                    sites.append(node)
        self._opaque_surface_sites = sites
        self._reflection_surface = saw_with or bool(sites)

    def _surface_is_trusted(self, node: Node) -> bool:
        """
        Whether the reflective surface at *node* is of a kind the trusting model assumes inert, so
        the surface walk declines to count it. The covered kinds are the ones that run code
        supplied as data this model cannot read: the callee read that spells a direct `eval` call,
        the `Function` intrinsic obtained as a value — a bare read of the name, a member key
        naming it, a `constructor` key whose yield flows onward, or a destructuring of it out of
        the global object — and a string timer whose first argument is not a function literal.

        What is never trusted is a spelling of `eval` other than a direct call's callee — a value
        read of the bare name, an `eval` member key, a destructuring, or a destructuring key only
        the runtime resolves (`{[k]: e}`), which may extract `eval` — because that is indirect eval,
        which runs in the global scope; and a computed read of an unknown global consults no code
        this model cannot read. A span of source this model never read, a `with` body, and an
        `import()` reach this walk through their own branches and stay kept under both models.
        """
        if not self.trust_eval:
            return False
        if isinstance(node, JsCallExpression):
            return True
        if isinstance(node, JsIdentifier):
            if node.name == 'Function':
                return True
            return node.name == 'eval' and self._is_the_callee_of_a_direct_eval_call(node)
        if isinstance(node, JsMemberExpression):
            name = member_property_name(node)
            return name == 'Function' or name == 'constructor'
        if isinstance(node, (JsVariableDeclarator, JsAssignmentExpression)):
            pattern = node.id if isinstance(node, JsVariableDeclarator) else node.left
            if not isinstance(pattern, JsObjectPattern):
                return False
            exposure = _pattern_reflective_exposure(pattern)
            return 'eval' not in exposure.named and not exposure.dynamic_key
        return False

    @staticmethod
    def _is_the_callee_of_a_direct_eval_call(node: JsIdentifier) -> bool:
        """
        Whether the read of `eval` at *node* is the callee that spells a direct `eval` call — the
        one position of the name the trusting model counts as the covered kind. Every other read of
        the name hands the intrinsic out for an indirect call, which no model trusts.
        """
        cursor: Node | None = node
        while isinstance(cursor.parent, JsParenthesizedExpression):
            cursor = cursor.parent
        call = cursor.parent
        return (
            isinstance(call, JsCallExpression)
            and call.callee is cursor
            and is_direct_eval_call(call)
        )

    def _destructures_a_reflective_intrinsic(
        self, node: JsVariableDeclarator | JsAssignmentExpression,
    ) -> bool:
        """
        Whether *node* binds one of the reflective intrinsics out of the global object: an object
        pattern whose source may be the object (`may_be_the_global_object`) and that names `eval` or
        `Function` among its keys, or reads one under a key only the runtime resolves. `const {eval}
        = globalThis` is the same value-read of the intrinsic that the bare name spells — the pattern
        reads the property off the object and binds its value — so it is a reflection surface just as
        the bare spelling is, and `const {[k]: e} = globalThis` is the destructuring counterpart of
        the computed member read `globalThis[k]` (`_is_reflective_member`): its key may resolve to
        `eval` at runtime, so it is a surface too. A pattern destructuring anything else, or the same
        names out of any other object, binds a value the program chose and is no surface.
        """
        if isinstance(node, JsVariableDeclarator):
            pattern, source = node.id, node.init
        else:
            pattern, source = node.left, node.right
        if not isinstance(pattern, JsObjectPattern) or not self.may_be_the_global_object(source):
            return False
        exposure = _pattern_reflective_exposure(pattern)
        return bool(exposure.named) or exposure.dynamic_key

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
        """
        Record every reference of the program against the binding it reaches. The identifier
        references come first, the names holding the global object are found from the values those
        write, and only then is each member access classified: whether `w.g = 2` writes the global
        `g` depends on whether `w` holds the object, wherever in the program `w` is given it.
        """
        self._recording_def_use = True
        self._create_implicit_globals()
        accesses = self._record_def_use_references()
        self._global_object_holders = self._bindings_holding_the_global_object()
        for access in accesses:
            self._record_global_alias_member_reference(access)
        self._recording_def_use = False
        self._record_arguments_alias_references()
        self._record_global_object_alias_references()
        self._record_copy_reads()

    def _record_copy_reads(self):
        """
        Record, against the block binding of each function declared in a block, the read the copy
        Annex B makes of it where the declaration runs, wherever something observes the copy. The
        declaration stands in for the read (`ReferenceNode`). It is recorded last because whether
        the copy is observed is read off every other reference the `var` has.
        """
        for copy in self._annex_b_copies:
            if copy.observed:
                self._record_alias_reference(copy.block, copy.declaration, Role.READ)

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

    def _record_def_use_references(self) -> list[JsMemberExpression]:
        """
        Record every identifier reference, and return the member accesses the walk passes in the
        order it meets them, for `_build_def_use` to classify once the names holding the global
        object are known. One record per reference node: the walk reaches a node once per slot
        holding it, and the one identifier of `{ a }` or of `export { a };` fills two, so without
        the dedup a read's multiplicity would follow its spelling rather than the program. The
        export-marking rider shares the walk: it consults only scope-builder state, so riding along
        changes nothing the remaining construction walks observe. So does the rider answering
        `module_may_be_reentered`, which consults nothing but the node, and the one filing the
        direct `eval` calls and unread spans of every scope owning variables, which
        `_direct_eval_sites` and `_unread_source_sites` answer from. Those lists are facts of the
        tree the model is built from like every other: a pass holding the model across its own edits
        would otherwise read them off the edited tree, where an `eval` it spliced away no longer
        stands while the writes the splice made are missing from the model.
        """
        pending = [self.root_scope]
        while pending:
            scope = pending.pop()
            if scope.is_var_scope:
                self._function_direct_eval_sites[id(scope.node)] = []
                self._function_unread_source_sites[id(scope.node)] = []
            pending.extend(scope.children)
        seen: set[int] = set()
        accesses: list[JsMemberExpression] = []
        for node in self.root.walk():
            if isinstance(node, (JsExportNamedDeclaration, JsExportDefaultDeclaration)):
                self._mark_export_declaration(node)
            if _lets_another_module_run(node):
                self._module_may_be_reentered = True
            if is_direct_eval_call(node):
                self._file_reflective_site(node, self._function_direct_eval_sites)
            elif is_unread_source(node):
                self._file_reflective_site(node, self._function_unread_source_sites)
            if isinstance(node, JsMemberExpression):
                accesses.append(node)
                continue
            if not isinstance(node, JsIdentifier):
                continue
            if id(node) in seen:
                continue
            seen.add(id(node))
            if not self.is_reference(node):
                continue
            ref_scope = self._node_scope.get(node)
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
            if binding.may_be_absent:
                self._lend_to_the_binding_outside(node, binding)
        return accesses

    def _lend_to_the_binding_outside(self, node: JsIdentifier, binding: Binding):
        """
        Record *node*, a reference to a binding that may be absent, as a dynamic reference of what
        its name means outside the scope of *binding*, which the reading without *binding* resolves
        it to (`Binding.may_be_absent`).
        """
        if binding.scope.parent is None:
            return
        outside = self.lookup(node.name, binding.scope.parent, cross_dynamic=True)
        if outside is not None:
            outside.dynamic_refs.append(node)

    @staticmethod
    def _file_reflective_site(site: Node, sites_of: dict[int, list[Node]]):
        """
        Add *site* to the list *sites_of* keeps for every scope node enclosing it, which is the list
        of each scope owning variables that the site can name a variable of.
        """
        cursor: Node | None = site
        while cursor is not None:
            sites = sites_of.get(id(cursor))
            if sites is not None:
                sites.append(site)
            cursor = cursor.parent

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
            scope = self._node_scope.get(node)
            if reference_role(node) is Role.READ:
                continue
            if self.lookup(node.name, scope) is not None or crosses_dynamic_scope(scope):
                continue
            self.root_scope.bindings.setdefault(
                node.name, Binding(node.name, BindingKind.IMPLICIT_GLOBAL, self.root_scope))

    def global_alias_member_name(self, member: JsMemberExpression) -> str | None:
        """
        The name of the global that a member access on a global-object alias references
        (`globalThis.g`, `window['g']` → `g`), or `None` when *member* is not such an access. The alias
        must be an unshadowed `GLOBAL_OBJECT_ALIASES` identifier (a local `window` names an ordinary
        object, not the global) with a statically known property name, and the access must not cross a
        dynamic scope, where the alias could be rebound or the target could be a `with`-object property —
        in either case the model cannot claim the reference denotes a global.

        A `this` where the top level holds one denotes the global object only where the file is a
        script (`file_kind`): in an ES module it denotes nothing, and in a CommonJS file that file's
        exports.
        """
        if (
            self.file_kind.scopes_declarations_to_the_file
            and isinstance(strip_parens(member.object), JsThisExpression)
        ):
            return None
        return self._global_member_name(member, self._base_is_the_global_object)

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
    ) -> str | None:
        base = strip_parens(member.object)
        if not base_is_the_global_object(base):
            return None
        name = member_property_name(member)
        if name is None:
            return None
        if crosses_dynamic_scope(self._node_scope.get(member)):
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
            and self.lookup(node.name, self._node_scope.get(node)) is not None
        )

    def names_the_global_object(self, node: Node | None) -> bool:
        """
        Whether *node* is a name the file gives the global object, so a property read on it may be a
        read of a global: one of the names `_bindings_holding_the_global_object` finds. ANY value of
        `binding_values` being the object is enough, and completeness is not asked: the callers
        record a reference, where one admission too many keeps a declaration and one refusal too
        many deletes one, so admitting is this answer's safe direction — a name that held the object
        on one branch of its life records the reads made through it even where another branch gave
        it something else. Parentheses around the name are looked through, as they are for a name
        spelled as the object (`is_global_object_base`).

        A name the file never declares answers nothing, since `binding_values` declines for a
        binding with no declaration: an implicit global the file assigns by name, and the binding
        `_ensure_implicit_global_from_alias_write` mints for a name the file installs on the global
        object, whose value only a member access gives.

        The values hold wherever the name is not in their temporal dead zone, and nothing here orders
        an establishing definition before the read. A caller driving a rewrite has to — and needs the
        complete-singleton reading `singular_value` gives, not this one.
        """
        if not self._global_object_holders:
            return False
        node = strip_parens(node)
        return isinstance(node, JsIdentifier) and self.resolve(node) in self._global_object_holders

    def _bindings_holding_the_global_object(self) -> frozenset[Binding]:
        """
        Every binding the text gives the global object, directly or through any number of other
        names, read once per build from `binding_values`. A value is the object when it is spelled
        as one, and `A || B` is it whenever `A` is: every spelling of the object is truthy, so the
        guard a program writes to survive a host lacking the name it prefers evaluates to the object
        wherever that name exists. A value that is a name passes on whatever that name holds.
        """
        holders: set[Binding] = set()
        copies: dict[Binding, list[Binding]] = {}
        for binding in dict.fromkeys(self._binding_of.values()):
            values, _ = self.binding_values(binding, ignore_dynamic_rebinds=True)
            for value in values:
                value = strip_parens(value)
                while isinstance(value, JsLogicalExpression) and value.operator == '||':
                    value = strip_parens(value.left)
                if self._base_is_the_global_object(value):
                    holders.add(binding)
                elif isinstance(value, JsIdentifier):
                    source = self.resolve(value)
                    if source is not None:
                        copies.setdefault(source, []).append(binding)
        pending = list(holders)
        while pending:
            for binding in copies.get(pending.pop(), ()):
                if binding not in holders:
                    holders.add(binding)
                    pending.append(binding)
        return frozenset(holders)

    def _ensure_implicit_global_from_alias_write(self, member: JsMemberExpression):
        """
        Give a global written through a member access on a global-object alias (`globalThis.g = ...`) an
        implicit-global binding when the name is otherwise undeclared, so the def-use pass resolves the
        reference to it. Only a write creates a global property, so a read establishes nothing; the write
        itself is recorded against the binding by `_build_def_use` like any other reference, so this
        establishes existence only.

        The binding minted here is one nothing reads a value out of: it carries no declaration, so
        both value queries decline for it, and all it does is give a reference somewhere to resolve
        to instead of standing free. A write through the `this` of a top level mints one where the
        file is a script; in a module of either kind that `this` is not the global object
        (`global_alias_member_name`).
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
        binding.note_reference_from(self._node_scope.get(member))

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

        The function a CommonJS host wraps around the file has an `arguments` of its own too, whose
        elements alias the wrapper's parameters in their order
        (`refinery.lib.scripts.js.analysis.environment.COMMONJS_WRAPPER_PARAMETERS`), and its
        references are recorded the same way (`_record_wrapper_arguments`).
        """
        for fn in self.root.walk():
            if not isinstance(fn, (JsFunctionExpression, JsFunctionDeclaration)):
                continue
            if not has_mapped_arguments(fn, strict=False) or strict_mode_at(fn):
                continue
            own = self.lookup('arguments', self.function_scope(fn))
            if own is None or own.kind not in (BindingKind.ARGUMENTS, BindingKind.FUNC_NAME):
                continue
            if _displaces_arguments(own, fn):
                continue
            params = _last_positions([
                self.binding_of(param) if isinstance(param, JsIdentifier) else None
                for param in fn.params
            ])
            self._record_mapped_arguments(fn, own, params)
        self._record_wrapper_arguments()

    def _record_wrapper_arguments(self):
        """
        Record the references the `arguments` of the function a CommonJS host wraps around the file
        makes to that function's parameters, where the file may be CommonJS and its text leaves the
        top sloppy.
        """
        if not self.file_kind.may_be_commonjs or strict_mode_at(self.root):
            return
        own = self.root_scope.bindings.get('arguments')
        if own is None or not own.supplied_by_host:
            return
        if not references_own_arguments(self.root) or _displaces_arguments(own, self.root):
            return
        params = [self.root_scope.bindings.get(name) for name in COMMONJS_WRAPPER_PARAMETERS]
        self._record_mapped_arguments(self.root, own, params)

    def _record_mapped_arguments(self, fn: Node, own: Binding, params: list[Binding | None]):
        """
        Record, against each of *params* by its position, the references the `arguments` object
        *own* of *fn* makes to it (`_record_arguments_alias_references`).
        """
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
        and only then are the observed ones recorded. `_build_def_use` finds the names holding the
        global object in the same order for the same reason — an answer read out of a walk still
        recording the writes it depends on would depend on how far the walk had got, not on what the
        program says.

        The object is recognized by `_holds_the_global_object`, so only the `this` a script's top
        level holds is one. A `this` inside a function is the receiver its call supplied, and
        admitting it costs every fold in a file that hands one to anything: a self-defending
        wrapper passes its own `this` to a call, and a run that took it for the global object
        leaves that sample twenty times its deobfuscated size. `may_be_global_object_base`
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
            if not _is_call_argument(node) or not self._holds_the_global_object(node):
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
        which is how a `defineProperty` or an `Object.assign` receives its target, a return. A
        `VERDICT_READ` forwards nothing, so it is neither. A plain rebind of the name is a write
        of the binding rather than of the object, weighed by `values_at_call` and recorded as a
        write, so it never appears among the reads walked here. Which key an install stores is
        never asked: a computed write names no fixed key, and refusing every install keeps the
        answer independent of the folds that would reveal one.
        """
        for reference in binding.reads:
            role = container_reference_role(reference)
            if role is ContainerRole.MEMBER_WRITE:
                return True
            if role is ContainerRole.REBIND:
                continue
            if role is ContainerRole.ESCAPE:
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
        `arguments` reaching a parameter, or the global object reaching a global — or through the
        copy Annex B makes of a block binding, which hands its value to a `var`. The read half is a
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
        binding.note_reference_from(self._node_scope.get(node))


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
        self.model._node_scope[root] = scope
        self._declare_host_parameters(scope)
        self._hoist(root.body, scope)
        self._collect_imports(root.body, scope)
        self._collect_lexical(root.body, scope)
        self._settle_absence(scope)
        for stmt in root.body:
            self._visit(stmt, scope)
        self._settle_conditional_copies()
        return scope

    def _declare_host_parameters(self, scope: Scope):
        """
        Declare in the top scope of a file that may be CommonJS what the function the host wraps
        around its text binds there: its parameters, in their order, and its `arguments`. No
        statement declares them, and they hold what the host passed. Where the file may be an ES
        module as well, which binds none of them, each may be absent.

        A `let`, `const` or class named `arguments` at the top of the file means the function gets
        no `arguments` object (§10.2.11), and the name is that declaration's alone, with its dead
        zone.
        """
        kind = self.model.file_kind
        if not kind.may_be_commonjs:
            return
        supplied = [
            self._declare(scope, name, BindingKind.PARAM, None)
            for name in COMMONJS_WRAPPER_PARAMETERS
        ]
        if 'arguments' not in lexically_declared_names(self.model.root.body):
            supplied.append(self._declare(scope, 'arguments', BindingKind.ARGUMENTS, None))
        for binding in supplied:
            binding.supplied_by_host = True
            binding.may_be_absent = kind is not FileKind.commonjs

    @staticmethod
    def _settle_absence(scope: Scope):
        """
        Clear `Binding.may_be_absent` for every binding the host supplies that a declaration of the
        file joins: the ES-module reading binds that declaration where the CommonJS reading binds
        the parameter, so the name is bound however the file runs.
        """
        for binding in scope.bindings.values():
            if binding.supplied_by_host and binding.declarations:
                binding.may_be_absent = False

    def _settle_conditional_copies(self):
        """
        Mark as `Binding.may_be_absent` the `var` of every conditional copy
        (`AnnexBCopy.conditional`) that nothing but such copies declares: the ES-module reading
        makes no copy, so there the name means what it means outside the scope of the `var`.
        """
        for copy in self.model._annex_b_copies:
            var = copy.var
            if not copy.conditional or var.may_be_absent:
                continue
            copied = {id(received.declaration.id) for received in var.copies_received}
            if all(id(site) in copied for site in var.declarations):
                var.may_be_absent = True

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
            self.model._binding_of[decl_id] = binding
        return binding

    def _hoist(self, stmts: list, func_scope: Scope):
        """
        Declare in *func_scope* the names the statements of *stmts* bind with a `var` or with a
        function declaration, which is what runs before any of them does.

        A function declared inside a block and given a `var` outside it by Annex B is declared here
        too, and in its block as well (`_collect_lexical`). The `var` holds the function only from
        the point the copy runs, which is `binding_establishment_sites`' answer rather than this
        one's.
        """
        for node in _walk_skipping_functions(stmts):
            if isinstance(node, JsVariableDeclaration) and node.kind is JsVarKind.VAR:
                for decl in node.declarations:
                    if isinstance(decl, JsVariableDeclarator):
                        for ident in pattern_identifiers(decl.id):
                            self._declare(func_scope, ident.name, BindingKind.VAR, ident)
            elif isinstance(node, JsFunctionDeclaration) and node.id is not None:
                home = annex_b_var_home(node, self.model.file_kind, self._lexical_names)
                if home is func_scope.node:
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
        class, and a function declared in a block.

        A function declared in a block is bound in the block in every mode, holding the function
        from the moment the block is entered. Outside strict code Annex B also gives the enclosing
        function, script or static block a `var` of the name, which `_hoist` has declared, and
        copies the block's binding into it where the declaration runs (`AnnexBCopy`), unless
        §B.3.3.1 stops the copy. A label is looked through, as `lexically_declared_names` reads it.

        A declaration written under an `export` is read through it: the export names what the
        declaration binds and binds nothing of its own.
        """
        for stmt in stmts:
            stmt = declaration_under_export(stmt)
            while isinstance(stmt, JsLabeledStatement):
                stmt = declaration_under_export(stmt.body)
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
                home = annex_b_var_home(stmt, self.model.file_kind, self._lexical_names)
                if home is not None and scope.is_var_scope:
                    continue
                binding = self._declare(scope, stmt.id.name, BindingKind.FUNCTION, stmt.id)
                if home is None or (var := self._copy_target(scope, home, stmt.id.name)) is None:
                    continue
                conditional = self.model.file_kind is FileKind.commonjs_or_es_module
                copy = AnnexBCopy(stmt, binding, var, conditional)
                binding.copies_made.append(copy)
                var.copies_received.append(copy)
                self.model._annex_b_copies.append(copy)

    @staticmethod
    def _copy_target(scope: Scope, home: Node, name: str) -> Binding | None:
        """
        The binding *name* has in the scope *home* introduces, found from *scope* inside it: the
        `var` Annex B copies a function declared in a block of *scope* into.
        """
        cursor: Scope | None = scope
        while cursor is not None:
            if cursor.node is home and cursor.is_var_scope and cursor.kind is not ScopeKind.PARAMS:
                return cursor.bindings.get(name)
            cursor = cursor.parent
        return None

    def _visit(self, node: Node, scope: Scope):
        self.model._node_scope[node] = scope
        if isinstance(node, JsFunctionDeclaration) and isinstance(node.parent, JsIfStatement):
            self._visit_clause_function(node, scope)
        elif isinstance(node, (
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
            self.model._node_scope[node.id] = outer
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
            self.model._node_scope[node.id] = fscope
        if isinstance(node, JsFunctionDeclaration) and node.id is not None:
            self.model._node_scope[node.id] = enclosing
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
            self.model._node_scope[body] = fscope
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

    def _visit_clause_function(self, node: JsFunctionDeclaration, enclosing: Scope):
        """
        Build the scopes of a function declaration written as the whole clause of an `if`, which
        binds its name as though it were the one statement of a block in that position (§B.3.4).
        The scope of that block is introduced by the declaration, since nothing else stands there,
        and the declaration stands in it, as a function declared in a block statement stands in the
        block.
        """
        bscope = self._new_scope(ScopeKind.BLOCK, node, enclosing)
        self.model._node_scope[node] = bscope
        self._collect_lexical([node], bscope)
        self._visit_function(node, bscope)

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
        """
        The loop's own `let` or `const` names are bound before its head is evaluated and hold no
        value yet (ForIn/OfHeadEvaluation), so the object or iterable is read in the scope of the
        loop: a name the declaration binds is read there in its dead zone, not from outside.
        """
        left = node.left
        if isinstance(left, JsVariableDeclaration) and left.kind in (JsVarKind.LET, JsVarKind.CONST):
            scope = self._new_scope(ScopeKind.BLOCK, node, enclosing)
            self._collect_lexical([left], scope)
        else:
            scope = enclosing
        if node.right is not None:
            self._visit(node.right, scope)
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
            self.model._node_scope[case] = sscope
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
        """
        The `extends` clause is evaluated in the scope of the class, where the own name of a class
        expression is bound and holds no value yet (ClassDefinitionEvaluation), so a read of that
        name there is one in its dead zone.
        """
        for decorator in node.decorators:
            self._visit(decorator, enclosing)
        cscope = self._new_scope(ScopeKind.CLASS, node, enclosing)
        if isinstance(node, JsClassExpression) and node.id is not None:
            self._declare(cscope, node.id.name, BindingKind.CLASS, node.id)
            self.model._node_scope[node.id] = cscope
        if node.super_class is not None:
            self._visit(node.super_class, cscope)
        if isinstance(node, JsClassDeclaration) and node.id is not None:
            self.model._node_scope[node.id] = enclosing
        body = node.body
        if body is not None:
            self.model._node_scope[body] = cscope
            for member in body.body:
                self._visit(member, cscope)

    def _visit_static_block(self, node: JsStaticBlock, enclosing: Scope):
        sscope = self._new_scope(ScopeKind.STATIC_BLOCK, node, enclosing)
        self._hoist(node.body, sscope)
        self._collect_lexical(node.body, sscope)
        for stmt in node.body:
            self._visit(stmt, sscope)


def build_semantic_model(
    root: JsScript,
    environment: HostEnvironment = HostEnvironment.universal,
    trust_eval: bool = False,
    file_kind: FileKind = FileKind.script,
    exports_read_outside: bool = True,
) -> SemanticModel:
    """
    Build the `SemanticModel` for a parsed script, resolving bare global reads against *environment*.
    The default `universal` environment asserts only `GUARANTEED_GLOBALS`, so the model answers
    `read_may_throw` exactly as an unpinned run; a pinned host recovers the reads that host guarantees.
    *trust_eval* selects the trusting model, which assumes code supplied as data is inert; see
    `refinery.lib.scripts.js.options.DeobfuscationOptions`. *file_kind* is what the file is, which
    `refinery.lib.scripts.js.options.file_kind` decides for a run; text that runs as global code,
    such as the payload of a `Function` construction, is a script. *exports_read_outside* says
    whether code that loads the file may read what it exports; see
    `SemanticModel.module_exports_unread`.
    """
    return SemanticModel(root, environment, trust_eval, file_kind, exports_read_outside)
