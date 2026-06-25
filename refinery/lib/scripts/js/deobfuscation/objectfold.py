"""
Inline properties of locally-defined constant object literals.

When the obfuscator lifts string literals and operator wrappers into a local object, this
transformer detects the pattern and replaces all member-access reads with the inlined property
values. Function-valued properties that are trivial wrappers (single return statement whose body is
an expression using only parameters) are inlined at the call site.
"""
from __future__ import annotations

from typing import Iterator

from refinery.lib.scripts import (
    Node,
    Statement,
    Transformer,
    _clone_node,
    _replace_in_parent,
)
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.model import Binding, Scope, SemanticModel, is_use_position
from refinery.lib.scripts.js.deobfuscation.helpers import (
    OBJECT_PROTOTYPE_MEMBERS,
    ScopeProcessingTransformer,
    access_key,
    property_key,
    references_receiver_this,
    remove_declarator,
    try_inline_trivial_function,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsCallExpression,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNewExpression,
    JsObjectExpression,
    JsProperty,
    JsPropertyKind,
    JsScript,
    JsTaggedTemplateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
)


def _build_property_map(
    obj: JsObjectExpression,
) -> dict[str, Node] | None:
    """
    Build a map from string key to value node for every property in the object literal.
    Returns `None` if any property cannot be statically keyed (computed key, spread, etc.).
    """
    result: dict[str, Node] = {}
    for prop in obj.properties:
        if not isinstance(prop, JsProperty):
            return None
        if prop.kind is not JsPropertyKind.INIT:
            return None
        key = property_key(prop)
        if key is None or prop.value is None:
            return None
        result[key] = prop.value
    return result


def _object_binds_this(prop_map: dict[str, Node]) -> bool:
    """
    Return whether any property value depends on `this` being supplied by the object, so that
    folding the object away (detaching the value from its receiver) would change its meaning.
    """
    return any(references_receiver_this(value) for value in prop_map.values())


def _binding_inside(binding: Binding, value: Node) -> bool:
    """
    Whether *binding* is declared inside *value* — its scope is introduced by *value* or a node nested
    within it — so that a clone of *value* carries the binding along and a reference to it stays bound
    to the same declaration wherever the clone lands.
    """
    node = binding.scope.node
    return node is value or node.is_descendant_of(value)


def _resolves_consistently(model: SemanticModel, value: Node, dest: Scope | None) -> bool:
    """
    Whether every free identifier in *value* resolves, from *dest* — the scope the value would be
    folded into — to the same binding it reads at the object literal. A value moved into a use site
    that binds one of its free names anew (a parameter, a block-scoped `let`, or the per-call
    `arguments` of a nested function) would silently rebind there and read a different value than the
    object captured. This is the spatial counterpart to the temporal `_value_is_stable`; an identifier
    bound inside *value* itself places no constraint, since the clone carries its binding with it.
    """
    for node in value.walk():
        if not isinstance(node, JsIdentifier) or not is_use_position(node):
            continue
        if model.binding_of(node) is not None:
            continue
        binding = model.resolve(node)
        if binding is not None and _binding_inside(binding, value):
            continue
        if binding is not model.lookup(node.name, dest):
            return False
    return True


class JsObjectFold(ScopeProcessingTransformer):
    """
    Inline properties of locally-defined constant objects. Processes at function-scope and
    script-scope boundaries because JavaScript `var` declarations are function-scoped.
    """

    def __init__(self):
        super().__init__()
        self._root: JsScript | None = None

    def visit_JsScript(self, node: JsScript):
        self._root = node
        return super().visit_JsScript(node)

    def _process_scope_body(self, scope: Node, body: list[Statement]) -> None:
        assert self._root is not None
        cache = model_cache(self, self._root)
        for declarator in list(self._find_candidates(body)):
            name = declarator.id
            init = declarator.init
            if not isinstance(name, JsIdentifier) or not isinstance(init, JsObjectExpression):
                continue
            prop_map = _build_property_map(init)
            if prop_map is None or _object_binds_this(prop_map):
                continue
            if self._has_freshly_allocating_value(prop_map):
                continue
            if not cache.effects.is_side_effect_free(init, {name.name}):
                continue
            model = cache.model
            binding = model.binding_of(name)
            if binding is None or binding.writes or len(binding.declarations) != 1:
                continue
            if not cache.effects.binding_is_immutable_container(binding, member_calls_mutate=False):
                continue
            if self._self_referential(model, binding, init):
                continue
            if any(not self._value_is_stable(model, value) for value in prop_map.values()):
                continue
            changed, can_remove = self._inline_references(model, binding, prop_map, self)
            if changed:
                if can_remove:
                    remove_declarator(declarator)
                self.mark_changed()

    @staticmethod
    def _find_candidates(body: list[Statement]) -> Iterator[JsVariableDeclarator]:
        """
        Yield each variable declarator in *body* that initializes a variable to an object literal — the
        syntactic precondition for folding. Whether the literal is actually foldable (every key static,
        the name a single immutable binding) is decided per candidate by the caller against a model
        rebuilt after any earlier fold in the same body, and its property map is read from the live
        initializer at that point, so an earlier fold into this initializer is reflected.
        """
        for stmt in body:
            if not isinstance(stmt, JsVariableDeclaration):
                continue
            for decl in stmt.declarations:
                if isinstance(decl, JsVariableDeclarator) and isinstance(decl.init, JsObjectExpression):
                    yield decl

    @staticmethod
    def _value_is_stable(model: SemanticModel, value: Node) -> bool:
        """
        Whether *value* evaluates to the same result wherever it is inlined — the precondition for
        moving a property value from the object literal to each access site. It holds when every binding
        the value reads as a free variable is immutable: a property whose value reads a local that is
        reassigned (`{ p: x }` where `x` is later written) would, once inlined past the reassignment,
        read the new value instead of the one the object captured at the literal. Identifiers bound
        inside *value* itself (a function's own parameters) and free references that resolve to no
        binding (external globals) place no constraint, so a string, a numeric literal, a `const`
        reference, or a self-contained function wrapper all remain foldable.
        """
        local_nodes = {id(node) for node in value.walk()}
        for node in value.walk():
            if not isinstance(node, JsIdentifier) or model.binding_of(node) is not None:
                continue
            if not is_use_position(node):
                continue
            binding = model.resolve(node)
            if binding is None or not binding.writes:
                continue
            if any(id(decl) in local_nodes for decl in binding.declarations):
                continue
            return False
        return True

    @staticmethod
    def _has_freshly_allocating_value(prop_map: dict[str, Node]) -> bool:
        """
        Whether any property value, when evaluated, may allocate a fresh object whose identity folding
        would duplicate. Folding clones the value into every access site, so a value that builds a new
        array or object — directly as a container literal, or by returning one from a call or `new`
        (only a side-effect-free, hence pure, one reaches this far) — would become a distinct object at
        each site: two `o.arr` reads that name one shared array become two arrays, diverging on identity
        (`o.arr === o.arr` flips from true to false), on a mutation made through one access (or an alias,
        argument, or method call that reaches it) and observed through another, and on element identity
        one level down. Deciding precisely which such folds are safe is the nested-container escape
        analysis the model does not yet provide, so such an object is left unfolded. A function or arrow
        literal value is judged per reference instead — folded only where it is immediately called, so
        its identity is never observed — and a primitive, a binding, a member read, or an operator over
        them duplicates without a fresh identity, so none of those constrains the fold.
        """
        return any(JsObjectFold._value_allocates(value) for value in prop_map.values())

    @staticmethod
    def _value_allocates(value: Node) -> bool:
        """
        Whether evaluating *value* may allocate a fresh object — a container literal it builds directly,
        or one a call, `new`, or tagged template in its evaluation may return. A function or arrow
        literal value is excluded, since its own identity is handled where it is folded; a nested
        function inside the value is not entered, as its body runs only when the function is later
        called, not when the value the object captured is evaluated.
        """
        if isinstance(value, (JsFunctionExpression, JsArrowFunctionExpression)):
            return False
        stack = [value]
        while stack:
            node = stack.pop()
            if node is not value and isinstance(node, (JsFunctionExpression, JsArrowFunctionExpression)):
                continue
            if isinstance(node, (
                JsArrayExpression,
                JsObjectExpression,
                JsCallExpression,
                JsNewExpression,
                JsTaggedTemplateExpression,
            )):
                return True
            stack.extend(node.children())
        return False

    @staticmethod
    def _self_referential(model: SemanticModel, binding: Binding, init: JsObjectExpression) -> bool:
        """
        Whether any reference to *binding* lies within its own initializer *init* — the object names
        itself in one of its property values (`var o = { f: function() { return o.x; } }`). Inlining
        such a value into a use site re-introduces a reference to the object there, so removing the
        declaration would leave it dangling; the caller skips folding the object rather than fold it
        into invalid code.
        """
        return any(ref.is_descendant_of(init) for ref in model.references(binding))

    @staticmethod
    def _inline_references(
        model: SemanticModel,
        binding: Binding,
        prop_map: dict[str, Node],
        transformer: Transformer,
    ) -> tuple[bool, bool]:
        """
        Replace each `obj['key']` access through *binding* with the corresponding property value. For
        function-valued properties called as `obj['key'](args)`, inline the call. When a key is
        statically known, absent from the property map, and not the name of a member every object
        inherits from `Object.prototype` (`toString`, `hasOwnProperty`, …), the access provably
        evaluates to `undefined` and is replaced accordingly; an inherited-member access is left intact
        (folding `o.toString` to `undefined` would turn `o.toString()` into `undefined()`). Iterating
        the binding's resolved references (not every textual occurrence of the name) keeps a shadowing
        inner binding of the same name untouched.

        Two per-reference conditions block a fold that would change meaning at the destination, leaving
        the access intact. A function-valued property is folded only where it is immediately called
        (the value's identity never escapes); a bare read of it is kept, since cloning it into two sites
        would make `o.f === o.f` two distinct functions. And a value is folded into a use site only when
        each of its free identifiers resolves to the same binding there as at the literal, so a value
        read inside a nested function that rebinds one of those names — a parameter, a block `let`, or
        that function's own `arguments` — is not silently recaptured.

        Returns a pair `(changed, can_remove)` where *changed* is True when any replacement was made and
        *can_remove* is True when every reference was folded away, so no use of the binding survives — a
        bare reference (an alias such as `var b = obj`), a retained inherited-member access, or a
        reference one of the two conditions above kept leaves *can_remove* False so the declaration is
        kept.
        """
        changed = False
        can_remove = True
        for ref in list(model.references(binding)):
            member = ref.parent
            if not isinstance(member, JsMemberExpression) or member.object is not ref:
                can_remove = False
                continue
            key = access_key(member)
            if key is None:
                can_remove = False
                continue
            if key not in prop_map:
                if key in OBJECT_PROTOTYPE_MEMBERS or '__proto__' in prop_map:
                    can_remove = False
                    continue
                _replace_in_parent(member, JsIdentifier(name='undefined'))
                changed = True
                continue
            value = prop_map[key]
            parent = member.parent
            if (
                isinstance(parent, JsCallExpression)
                and parent.callee is member
                and isinstance(value, JsFunctionExpression)
            ):
                replacement = try_inline_trivial_function(
                    value,
                    parent.arguments,
                    relaxed=True,
                    transformer=transformer,
                )
                if replacement is not None:
                    _replace_in_parent(parent, replacement)
                    changed = True
                    continue
            called_here = isinstance(parent, JsCallExpression) and parent.callee is member
            if isinstance(value, (JsFunctionExpression, JsArrowFunctionExpression)) and not called_here:
                can_remove = False
                continue
            if not _resolves_consistently(model, value, model.scope_of(member)):
                can_remove = False
                continue
            _replace_in_parent(member, _clone_node(value))
            changed = True
        return changed, can_remove
