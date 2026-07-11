"""
JavaScript syntax normalization transforms.
"""
from __future__ import annotations

from typing import Callable

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    GUARANTEED_GLOBALS,
    Binding,
    BindingKind,
    SemanticModel,
    is_invocation_target,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    OBJECT_PROTOTYPE_MEMBERS,
    RELATIONAL_OPS,
    _to_int32,
    access_key,
    escape_js_string,
    eval_binary_op,
    extract_identifier_params,
    extract_literal_value,
    is_closed_expression,
    is_literal,
    is_nullish,
    is_safe_iife_inline,
    is_simple_expression,
    is_statically_evaluable,
    is_truthy,
    is_valid_identifier,
    is_valid_property_key,
    js_parse_int,
    make_numeric_literal,
    make_string_literal,
    numeric_value,
    string_value,
    substitute_params,
    value_to_node,
)
from refinery.lib.scripts.js.deobfuscation.interpreter import BUILTIN_REGISTRY, STATIC_OBJECTS
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBinaryExpression,
    JsBlockStatement,
    JsBooleanLiteral,
    JsCallExpression,
    JsClassDeclaration,
    JsClassExpression,
    JsConditionalExpression,
    JsFunctionExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsProperty,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsUnaryExpression,
    strip_parens,
)
from refinery.lib.scripts.js.precedence import parens_required

_OBJECT_PROTO_PROPERTIES = OBJECT_PROTOTYPE_MEMBERS

_FUNCTION_PROPERTIES = _OBJECT_PROTO_PROPERTIES | frozenset({
    'apply',
    'arguments',
    'bind',
    'call',
    'caller',
    'length',
    'name',
    'prototype',
})

_EMPTY_OBJECT_PROPERTIES = _OBJECT_PROTO_PROPERTIES


def _callee_form_sensitive(node: Node) -> bool:
    """
    Whether invoking *node* directly as a call callee, rather than behind the comma sequence that
    currently wraps it, would change the call's meaning. A member access binds `this` to its object and
    a bare `eval` performs a *direct* eval evaluated in the caller's own scope; any other callee — a
    plain identifier or value — invokes with no receiver and no direct-eval effect, exactly as the
    wrapping indirect sequence does, so collapsing the sequence down to it preserves the call.
    """
    inner = strip_parens(node)
    if isinstance(inner, JsMemberExpression):
        return True
    return isinstance(inner, JsIdentifier) and inner.name == 'eval'


_UNCONVERTIBLE = object()


def _node_to_value(node: Node) -> object:
    """
    Convert an AST expression to its Python equivalent for use with BUILTIN_REGISTRY dispatch.
    Returns the module-level sentinel `_UNCONVERTIBLE` when the node cannot be statically resolved.
    """
    ok, value = extract_literal_value(node)
    return value if ok else _UNCONVERTIBLE


class JsSimplifications(Transformer):

    def __init__(self):
        super().__init__()
        self._cache: ModelCache | None = None

    @property
    def model(self) -> SemanticModel:
        assert self._cache is not None
        return self._cache.model

    @property
    def effects(self) -> EffectModel:
        assert self._cache is not None
        return self._cache.effects

    @property
    def dominance(self) -> DominanceModel:
        assert self._cache is not None
        return self._cache.dominance

    def visit_JsScript(self, node: JsScript):
        """
        Attach the shared model cache for the whole script, then rewrite. The model, effect, and
        dominance models are all read from that version-aware cache, so a mid-pass mutation rebuilds them
        together and the three stay consistent. Simplification only ever removes bindings within a pass,
        never adds one, so a name the model reports as locally bound stays bound; reading shadowing from
        it can therefore only over-preserve a global-alias access, never collapse one a local now captures.
        """
        self._cache = model_cache(self, node)
        self.generic_visit(node)
        return None

    def _resolves_to_local(self, member: JsMemberExpression, name: str) -> bool:
        """
        Whether *name*, written as a bare identifier where *member* sits, would bind to a local
        declaration rather than the global the `<global-alias>.name` access denotes. An implicit
        global is not a local: the bare name and the property access name the same global, so
        collapsing them stays sound. An unmapped or dynamically-scoped position is treated as bound,
        leaving the access untouched where the model cannot prove the name is free.
        """
        scope = self.model.scope_of(member)
        if scope is None:
            return True
        binding = self.model.lookup(name, scope)
        return binding is not None and binding.kind is not BindingKind.IMPLICIT_GLOBAL

    def _alias_property_defined(self, member: JsMemberExpression, name: str) -> bool:
        """
        Whether a bare read of *name* where *member* sits is guaranteed to resolve, so collapsing
        `<global-alias>.name` to `name` cannot turn the member read's `undefined` into a
        `ReferenceError`. A free name must be one the specification mandates on the global object
        (`GUARANTEED_GLOBALS`); a name the program itself defines as a global (an implicit global) exists
        only after its establishing write, so it is admitted only when a write is proven to run before
        this read — interprocedurally, so a top-level write still covers a read inside a function invoked
        after it, but strictly, so a same-statement or earlier read is declined.
        """
        binding = self.model.lookup(name, self.model.scope_of(member))
        if binding is None:
            return name in GUARANTEED_GLOBALS
        return any(self.dominance.runs_before(w, member) for w in binding.writes)

    def _resolve_in(self, node: JsBinaryExpression, key: str) -> bool | None:
        """
        Statically resolve `key in name` by asking the model what value *name* holds. A sole function,
        an empty class, or an empty object literal has a bounded property set — the built-in members of
        its type plus the own properties the binding is assigned — so membership is decidable; any other
        value, or one whose own-property set cannot be bounded, yields `None`. The binding is resolved
        through the model, so the answer is shadowing-correct across scopes and recognizes the
        bare-assignment form namespace flattening leaves, not only declarations. A value installed by
        assignment reads `undefined` before that write runs, so a `key in name` the establishing write
        does not dominate is left unresolved rather than fold away the `TypeError` a premature read
        would throw; a declaration or initializer, established without a write, needs no such gate.
        """
        right = node.right
        if not isinstance(right, JsIdentifier):
            return None
        binding = self.model.resolve(right)
        if binding is None:
            return None
        value = self.model.singular_value(binding)
        if value is None:
            return None
        if binding.writes and not self.dominance.runs_before(binding.writes[0], right):
            return None
        if isinstance(value, FUNCTION_NODES):
            members = _FUNCTION_PROPERTIES
        elif isinstance(value, (JsClassDeclaration, JsClassExpression)):
            if value.super_class is not None:
                return None
            if value.body is not None and value.body.body:
                return None
            members = _FUNCTION_PROPERTIES
        elif isinstance(value, JsObjectExpression) and not value.properties:
            members = _EMPTY_OBJECT_PROPERTIES
        else:
            return None
        if key in members:
            return True
        stores = self._own_property_stores(binding)
        if stores is None:
            return None
        if key in stores:
            return True
        if stores:
            return None
        return False

    def _own_property_stores(self, binding: Binding) -> set[str] | None:
        """
        The property names assigned as own properties of a binding's value (`name.k = ...`,
        `name['k'] = ...`), collected from the binding's references so the set is shadowing-correct.
        `None` when a write targets a computed key that is not a string literal, since the own-property
        set is then unbounded and no `in` membership can be decided.
        """
        stores: set[str] = set()
        for ref in self.model.references(binding):
            member = ref.parent
            if not isinstance(member, JsMemberExpression) or member.object is not ref:
                continue
            assignment = member.parent
            if (
                not isinstance(assignment, JsAssignmentExpression)
                or strip_parens(assignment.left) is not member
            ):
                continue
            prop = member.property
            if member.computed:
                if isinstance(prop, JsStringLiteral):
                    stores.add(prop.value)
                else:
                    return None
            elif isinstance(prop, JsIdentifier):
                stores.add(prop.name)
            else:
                return None
        return stores

    def visit_JsBinaryExpression(self, node: JsBinaryExpression):
        self.generic_visit(node)
        if node.left is None or node.right is None:
            return None
        op = node.operator
        left_str = string_value(node.left)
        right_str = string_value(node.right)
        if op == '+' and left_str is not None and right_str is not None:
            return make_string_literal(left_str + right_str)
        left_num = numeric_value(node.left)
        right_num = numeric_value(node.right)
        if left_num is not None and right_num is not None:
            result = eval_binary_op(op, left_num, right_num)
            if result is None:
                pass
            elif isinstance(result, bool):
                return JsBooleanLiteral(value=result)
            elif isinstance(result, (int, float)):
                if result != result or result == float('inf') or result == float('-inf'):
                    return None
                return make_numeric_literal(result)
        if op in ('===', '!==', '==', '!='):
            equal: bool | None = None
            if left_str is not None and right_str is not None:
                equal = left_str == right_str
            elif (
                isinstance(node.left, JsBooleanLiteral)
                and isinstance(node.right, JsBooleanLiteral)
            ):
                equal = node.left.value == node.right.value
            elif isinstance(node.left, JsNullLiteral) and isinstance(node.right, JsNullLiteral):
                equal = True
            if equal is not None:
                return JsBooleanLiteral(value=equal if op in ('===', '==') else not equal)
        if op in RELATIONAL_OPS:
            if left_str is not None and right_str is not None:
                return JsBooleanLiteral(value=RELATIONAL_OPS[op](left_str, right_str))
        if op == 'in' and isinstance(node.left, JsStringLiteral):
            result = self._resolve_in(node, node.left.value)
            if result is not None:
                return JsBooleanLiteral(value=result)
        return None

    def visit_JsCallExpression(self, node: JsCallExpression):
        self.generic_visit(node)
        callee = node.callee
        if isinstance(callee, JsIdentifier) and callee.name == 'parseInt':
            return self._fold_parseint(node)
        fn = callee
        if isinstance(fn, JsParenthesizedExpression):
            fn = fn.expression
        if isinstance(fn, JsFunctionExpression):
            return self._try_inline_iife(
                node,
                fn,
                lambda call: self.effects.is_pure_call(call),
                self.model.read_has_dynamic_effect,
                lambda call: self.effects.call_clearable(
                    call, lambda f: self.dominance.established_before(f, call)),
                self,
            )
        return (
            self._try_fold_static_method(node)
            or self._try_fold_free_function(node)
            or self._try_fold_instance_method(node)
            or self._try_fold_split(node)
            or self._try_fold_join(node)
        )

    @staticmethod
    def _fold_parseint(node: JsCallExpression) -> JsNumericLiteral | None:
        if len(node.arguments) < 1:
            return None
        radix = 10
        if len(node.arguments) >= 2:
            radix_value = numeric_value(node.arguments[1])
            if radix_value is None:
                return None
            radix = int(radix_value)
        sv = string_value(node.arguments[0])
        if sv is not None:
            result = js_parse_int(sv, radix)
            if result is not None:
                return make_numeric_literal(result)
        return None

    @staticmethod
    def _try_inline_iife(
        node: JsCallExpression,
        fn: JsFunctionExpression,
        call_pure: Callable[..., bool],
        read_effect: Callable[[Node], bool],
        call_established: Callable[..., bool],
        transformer: Transformer,
    ) -> Node | None:
        if fn.body is None or not isinstance(fn.body, JsBlockStatement):
            return None
        body = fn.body.body
        if len(body) != 1:
            return None
        stmt = body[0]
        if not isinstance(stmt, JsReturnStatement) or stmt.argument is None:
            return None
        param_names = extract_identifier_params(fn.params)
        if param_names is None or len(node.arguments) != len(param_names):
            return None
        expr = stmt.argument
        if not is_closed_expression(expr, set(param_names)):
            return None
        if not is_safe_iife_inline(
            expr, param_names, node.arguments, call_pure, read_effect, call_established,
        ):
            return None
        return substitute_params(expr, fn.params, node.arguments, transformer=transformer)

    @staticmethod
    def _try_fold_static_method(node: JsCallExpression) -> Node | None:
        callee = node.callee
        if not isinstance(callee, JsMemberExpression):
            return None
        if not isinstance(callee.object, JsIdentifier):
            return None
        static_name = callee.object.name
        if static_name not in STATIC_OBJECTS:
            return None
        if static_name == 'Buffer':
            return None
        method_name = access_key(callee)
        if method_name is None:
            return None
        builtin = BUILTIN_REGISTRY.get((static_name, method_name))
        if builtin is None:
            return None
        args = [_node_to_value(a) for a in node.arguments]
        if any(a is _UNCONVERTIBLE for a in args):
            return None
        try:
            result = builtin(args)
        except Exception:
            return None
        return value_to_node(result)

    @staticmethod
    def _try_fold_free_function(node: JsCallExpression) -> Node | None:
        callee = node.callee
        if not isinstance(callee, JsIdentifier):
            return None
        builtin = BUILTIN_REGISTRY.get((None, callee.name))
        if builtin is None:
            return None
        args = [_node_to_value(a) for a in node.arguments]
        if any(a is _UNCONVERTIBLE for a in args):
            return None
        try:
            result = builtin(args)
        except Exception:
            return None
        return value_to_node(result)

    @staticmethod
    def _try_fold_instance_method(node: JsCallExpression) -> Node | None:
        callee = node.callee
        if not isinstance(callee, JsMemberExpression):
            return None
        method_name = access_key(callee)
        if method_name is None or method_name in ('split', 'join', 'length'):
            return None
        if callee.object is None:
            return None
        receiver = _node_to_value(callee.object)
        if receiver is _UNCONVERTIBLE:
            return None
        if isinstance(receiver, str):
            builtin = BUILTIN_REGISTRY.get((str, method_name))
        elif isinstance(receiver, list):
            builtin = BUILTIN_REGISTRY.get((list, method_name))
        else:
            return None
        if builtin is None:
            return None
        args = [_node_to_value(a) for a in node.arguments]
        if any(a is _UNCONVERTIBLE for a in args):
            return None
        try:
            result = builtin(receiver, args)
        except Exception:
            return None
        return value_to_node(result)

    @staticmethod
    def _try_fold_split(node: JsCallExpression) -> JsArrayExpression | None:
        if len(node.arguments) != 1:
            return None
        callee = node.callee
        if not isinstance(callee, JsMemberExpression):
            return None
        obj_str = string_value(callee.object)
        if obj_str is None:
            return None
        method_name = access_key(callee)
        if method_name != 'split':
            return None
        sep = string_value(node.arguments[0])
        if sep is None:
            return None
        if sep:
            parts = obj_str.split(sep)
        else:
            parts = []
            for ch in obj_str:
                cp = ord(ch)
                if cp > 0xFFFF:
                    hi = 0xD800 + ((cp - 0x10000) >> 10)
                    lo = 0xDC00 + ((cp - 0x10000) & 0x3FF)
                    parts.append(chr(hi))
                    parts.append(chr(lo))
                else:
                    parts.append(ch)
        return JsArrayExpression(
            elements=[make_string_literal(p) for p in parts],
        )

    @staticmethod
    def _try_fold_join(node: JsCallExpression) -> JsStringLiteral | None:
        if len(node.arguments) > 1:
            return None
        callee = node.callee
        if not isinstance(callee, JsMemberExpression):
            return None
        method_name = access_key(callee)
        if method_name != 'join':
            return None
        obj = callee.object
        if not isinstance(obj, JsArrayExpression):
            return None
        parts: list[str] = []
        for e in obj.elements:
            if not isinstance(e, JsStringLiteral):
                return None
            parts.append(e.value)
        if node.arguments:
            sep = string_value(node.arguments[0])
            if sep is None:
                return None
        else:
            sep = ','
        return make_string_literal(sep.join(parts))

    def visit_JsConditionalExpression(self, node: JsConditionalExpression):
        self.generic_visit(node)
        if node.test is None or not is_statically_evaluable(node.test):
            return None
        truthy = is_truthy(node.test)
        if truthy is None:
            return None
        return node.consequent if truthy else node.alternate

    def visit_JsSequenceExpression(self, node: JsSequenceExpression):
        self.generic_visit(node)
        if not node.expressions:
            return None
        filtered = [
            e for i, e in enumerate(node.expressions)
            if i == len(node.expressions) - 1
            or not is_simple_expression(e)
            or self.model.read_has_dynamic_effect(e)
        ]
        if len(filtered) == len(node.expressions):
            return None
        if len(filtered) == 1:
            if is_invocation_target(node) and _callee_form_sensitive(filtered[0]):
                return None
            return filtered[0]
        node.expressions = filtered
        self.mark_changed()
        return None

    def visit_JsParenthesizedExpression(self, node: JsParenthesizedExpression):
        self.generic_visit(node)
        inner = node.expression
        if inner is None:
            return None
        if isinstance(inner, (
            JsSequenceExpression,
            JsFunctionExpression,
            JsArrowFunctionExpression,
            JsObjectExpression,
            JsClassExpression,
        )):
            return None
        if parens_required(inner, node.parent, node):
            return None
        return inner

    def visit_JsMemberExpression(self, node: JsMemberExpression):
        self.generic_visit(node)
        if (
            not node.computed
            and isinstance(node.object, JsIdentifier)
            and isinstance(node.property, JsIdentifier)
            and self.model.global_alias_member_name(node) is not None
            and not self._resolves_to_local(node, node.property.name)
            and self._alias_property_defined(node, node.property.name)
        ):
            p = node.parent
            if isinstance(p, JsAssignmentExpression) and p.left is node:
                return None
            if is_invocation_target(node):
                return None
            return node.property
        if node.computed and node.object is not None and node.property is not None:
            if (
                isinstance(node.object, JsArrayExpression)
                and isinstance(node.property, JsNumericLiteral)
            ):
                idx = node.property.value
                elements = node.object.elements
                if (
                    isinstance(idx, int)
                    and 0 <= idx < len(elements)
                    and all(e is not None and is_literal(e) for e in elements)
                ):
                    return elements[idx]
            prop_str = string_value(node.property)
            if prop_str is not None and is_valid_identifier(prop_str):
                node.computed = False
                node.property = JsIdentifier(name=prop_str)
                node._adopt(node.property)
                self.mark_changed()
                return None
        return None

    def visit_JsProperty(self, node: JsProperty):
        self.generic_visit(node)
        if node.computed and node.key is not None:
            key_str = string_value(node.key)
            if (
                key_str is not None
                and is_valid_property_key(key_str)
                and (node.method or key_str != '__proto__')
            ):
                node.computed = False
                node.key = JsIdentifier(name=key_str)
                node._adopt(node.key)
                self.mark_changed()
        return None

    def visit_JsUnaryExpression(self, node: JsUnaryExpression):
        self.generic_visit(node)
        if node.operand is None:
            return None
        op = node.operator
        if op == '!' and is_statically_evaluable(node.operand):
            truthy = is_truthy(node.operand)
            if truthy is not None:
                return JsBooleanLiteral(value=not truthy)
        if op == '-' and isinstance(node.operand, JsNumericLiteral):
            value = node.operand.value
            if value == 0 and isinstance(value, int):
                value = -0.0
            else:
                value = -value
            return make_numeric_literal(value)
        if op == '+' and isinstance(node.operand, JsNumericLiteral):
            return node.operand
        if op == '~' and isinstance(node.operand, JsNumericLiteral):
            value = node.operand.value
            if value == value and value not in (float('inf'), float('-inf')):
                return make_numeric_literal(_to_int32(~int(value)))
        if op == 'typeof' and is_literal(node.operand):
            if isinstance(node.operand, JsNumericLiteral):
                return make_string_literal('number')
            if isinstance(node.operand, JsStringLiteral):
                return make_string_literal('string')
            if isinstance(node.operand, JsBooleanLiteral):
                return make_string_literal('boolean')
        return None

    def visit_JsStringLiteral(self, node: JsStringLiteral):
        quote = node.raw[0] if node.raw else '\''
        rebuilt = quote + escape_js_string(node.value, quote) + quote
        if rebuilt != node.raw:
            node.raw = rebuilt
            self.mark_changed()
        return None

    def visit_JsLogicalExpression(self, node: JsLogicalExpression):
        self.generic_visit(node)
        if node.left is None or node.right is None:
            return None
        if not is_statically_evaluable(node.left):
            return None
        op = node.operator
        if op == '??':
            if is_nullish(node.left):
                return node.right
            return node.left
        truthy = is_truthy(node.left)
        if truthy is None:
            return None
        if op == '&&':
            return node.right if truthy else node.left
        if op == '||':
            return node.left if truthy else node.right
        return None
