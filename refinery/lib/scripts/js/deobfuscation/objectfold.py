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
    _clone_node,
    _replace_in_parent,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScopeProcessingTransformer,
    access_key,
    property_key,
    references_receiver_this,
    remove_declarator,
    try_inline_trivial_function,
)
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
    JsCallExpression,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsObjectExpression,
    JsProperty,
    JsPropertyKind,
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

    def _process_scope_body(self, scope: Node, body: list[Statement]) -> None:
        for candidate in list(self._find_candidates(body)):
            obj_name, declarator, prop_map = candidate
            if _object_binds_this(prop_map):
                continue
            if not self._is_safe_to_fold(scope, obj_name, declarator):
                continue
            changed, can_remove = self._inline_references(scope, obj_name, prop_map)
            if changed:
                if can_remove:
                    remove_declarator(declarator)
                self.mark_changed()

    @staticmethod
    def _find_candidates(body: list[Statement]) -> Iterator[tuple[str, JsVariableDeclarator, dict[str, Node]]]:
        """
        Yield tuples of (name, declarator_node, property_map) for each variable declarator in
        *body* that initializes a variable to an object literal with all statically-keyed
        properties.
        """
        for stmt in body:
            if not isinstance(stmt, JsVariableDeclaration):
                continue
            for decl in stmt.declarations:
                if not isinstance(decl, JsVariableDeclarator):
                    continue
                if not isinstance(decl.id, JsIdentifier):
                    continue
                if not isinstance(decl.init, JsObjectExpression):
                    continue
                prop_map = _build_property_map(decl.init)
                if prop_map is None:
                    continue
                yield decl.id.name, decl, prop_map

    @staticmethod
    def _is_safe_to_fold(root: Node, name: str, declarator: JsVariableDeclarator) -> bool:
        """
        Verify that the variable is never reassigned, passed as an argument, or used in any
        context other than `obj['key']` or `obj.key` member access. Also reject objects that are
        mutated via property assignment at any nesting depth (e.g. `obj.x = val` or
        `obj.x.y = val`).
        """
        decl_name_node = declarator.id
        for node in root.walk():
            if node is decl_name_node:
                continue
            if not isinstance(node, JsIdentifier) or node.name != name:
                continue
            p = node.parent
            if not isinstance(p, JsMemberExpression) or p.object is not node:
                return False
            ancestor = p
            while True:
                ap = ancestor.parent
                if isinstance(ap, JsAssignmentExpression) and ap.left is ancestor:
                    return False
                if not isinstance(ap, JsMemberExpression) or ap.object is not ancestor:
                    break
                ancestor = ap
        return True

    @staticmethod
    def _inline_references(
        root: Node,
        name: str,
        prop_map: dict[str, Node],
    ) -> tuple[bool, bool]:
        """
        Replace all `obj['key']` accesses with the corresponding property value. For function-valued
        properties called as `obj['key'](args)`, inline the call. When a key is statically known
        but absent from the property map, the access provably evaluates to `undefined` and is
        replaced accordingly. Returns a pair `(changed, can_remove)` where *changed* is True when
        any replacement was made and *can_remove* is True when no unresolvable member accesses
        remain on the object (i.e. every access had a statically extractable key).
        """
        changed = False
        can_remove = True
        for node in list(root.walk()):
            if not isinstance(node, JsMemberExpression):
                continue
            if not isinstance(node.object, JsIdentifier) or node.object.name != name:
                continue
            key = access_key(node)
            if key is None:
                can_remove = False
                continue
            if key not in prop_map:
                _replace_in_parent(node, JsIdentifier(name='undefined'))
                changed = True
                continue
            value = prop_map[key]
            parent = node.parent
            if (
                isinstance(parent, JsCallExpression)
                and parent.callee is node
                and isinstance(value, JsFunctionExpression)
            ):
                replacement = try_inline_trivial_function(value, parent.arguments, relaxed=True)
                if replacement is not None:
                    _replace_in_parent(parent, replacement)
                    changed = True
                    continue
            _replace_in_parent(node, _clone_node(value))
            changed = True
        return changed, can_remove
