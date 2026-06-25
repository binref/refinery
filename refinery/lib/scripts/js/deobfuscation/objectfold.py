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
from refinery.lib.scripts.js.analysis.model import Binding, SemanticModel, is_use_position
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScopeProcessingTransformer,
    access_key,
    property_key,
    references_receiver_this,
    remove_declarator,
    try_inline_trivial_function,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsCallExpression,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsProperty,
    JsPropertyKind,
    JsScript,
    JsTaggedTemplateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
)

_OBJECT_PROTOTYPE_MEMBERS = frozenset({
    'constructor',
    'hasOwnProperty',
    'isPrototypeOf',
    'propertyIsEnumerable',
    'toLocaleString',
    'toString',
    'valueOf',
    '__proto__',
    '__defineGetter__',
    '__defineSetter__',
    '__lookupGetter__',
    '__lookupSetter__',
})


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


def _strip(node: Node | None) -> Node | None:
    while isinstance(node, JsParenthesizedExpression):
        node = node.expression
    return node


def _invokes(node: Node | None, callee: Node) -> bool:
    """
    Whether *node* invokes *callee* — a call `callee(...)` or a tagged template `` callee`...` `` —
    looking through parentheses around the callee.
    """
    if isinstance(node, JsCallExpression):
        return _strip(node.callee) is callee
    if isinstance(node, JsTaggedTemplateExpression):
        return _strip(node.tag) is callee
    return False


def _is_method_receiver(access: JsMemberExpression) -> bool:
    """
    Whether *access* (a property access `o.k`) is the receiver a method is invoked on, as in
    `o.k.m(...)` — the access is the object of a further member that is then called. Parentheses are
    looked through at every level.
    """
    cursor: Node = access
    parent = cursor.parent
    while isinstance(parent, JsParenthesizedExpression):
        cursor = parent
        parent = cursor.parent
    if not isinstance(parent, JsMemberExpression) or _strip(parent.object) is not cursor:
        return False
    outer = parent.parent
    while isinstance(outer, JsParenthesizedExpression):
        outer = outer.parent
    return _invokes(outer, parent)


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
            if self._mutates_nested_container(model, binding, prop_map):
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
    def _mutates_nested_container(
        model: SemanticModel, binding: Binding, prop_map: dict[str, Node],
    ) -> bool:
        """
        Whether a reference invokes a method on a property whose value is itself a mutable container —
        `o.arr.unshift(...)` where `o.arr` holds an array or object literal. Such a call may mutate the
        nested container, so folding `o.arr` to that literal at the read sites would drop the mutation
        (`o.arr[0]` would read the original element, not the mutated one). A method call on a property
        holding an immutable primitive — a string, number, or boolean — cannot mutate it (`o.s.split(...)`
        on a string returns a new value), so it does not block folding. A direct method call on the
        object itself (`o.m(...)`) is governed separately by the immutable-container judgment.
        """
        for ref in model.references(binding):
            access = ref.parent
            if not isinstance(access, JsMemberExpression) or _strip(access.object) is not ref:
                continue
            if not isinstance(prop_map.get(access_key(access) or ''), (
                JsArrayExpression, JsObjectExpression,
            )):
                continue
            if _is_method_receiver(access):
                return True
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
        init_nodes = {id(node) for node in init.walk()}
        return any(id(ref) in init_nodes for ref in model.references(binding))

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
        inner binding of the same name untouched. Returns a pair `(changed, can_remove)` where *changed*
        is True when any replacement was made and *can_remove* is True when every reference was folded
        away, so no use of the binding survives — a bare reference (an alias such as `var b = obj`) or a
        retained inherited-member access leaves *can_remove* False so the declaration is kept.
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
                if key in _OBJECT_PROTOTYPE_MEMBERS or '__proto__' in prop_map:
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
            _replace_in_parent(member, _clone_node(value))
            changed = True
        return changed, can_remove
