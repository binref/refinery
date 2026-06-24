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
from refinery.lib.scripts.js.analysis.model import Binding, SemanticModel
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScopeProcessingTransformer,
    access_key,
    property_key,
    references_receiver_this,
    remove_declarator,
    try_inline_trivial_function,
)
from refinery.lib.scripts.js.model import (
    JsCallExpression,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsObjectExpression,
    JsProperty,
    JsPropertyKind,
    JsScript,
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
    def _inline_references(
        model: SemanticModel,
        binding: Binding,
        prop_map: dict[str, Node],
        transformer: Transformer,
    ) -> tuple[bool, bool]:
        """
        Replace each `obj['key']` access through *binding* with the corresponding property value. For
        function-valued properties called as `obj['key'](args)`, inline the call. When a key is
        statically known but absent from the property map, the access provably evaluates to `undefined`
        and is replaced accordingly. Iterating the binding's resolved references (not every textual
        occurrence of the name) keeps a shadowing inner binding of the same name untouched. Returns a
        pair `(changed, can_remove)` where *changed* is True when any replacement was made and
        *can_remove* is True when every reference was a member access with a statically extractable key,
        so no use of the binding survives — a bare reference (an alias such as `var b = obj`) leaves
        *can_remove* False so the declaration is kept.
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
