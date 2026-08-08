"""
JavaScript syntax normalization transforms.
"""
from __future__ import annotations

from typing import Callable

from refinery.lib.scripts import Expression, Node, Transformer
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import GLOBAL_OBJECT, EffectModel
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    GUARANTEED_GLOBALS,
    Binding,
    BindingKind,
    SemanticModel,
    is_invocation_target,
)
from refinery.lib.scripts.js.analysis.reaching import ReachingModel
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
    utf16_code_units,
    value_to_node,
)
from refinery.lib.scripts.js.deobfuscation.interpreter import (
    BUILTIN_REGISTRY,
    STATIC_OBJECTS,
    to_string,
)
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


def concat_string(node: Expression | None) -> str | None:
    """
    The string *node* contributes to a `+` concatenation, or `None` when appending it to a string cannot
    be decided statically.

    This is deliberately narrower than `_node_to_value`: only a primitive literal qualifies. Every
    primitive converts by an internal specification operation that no program can intercept — patching
    `Number.prototype.toString`, `valueOf`, or even `Symbol.toPrimitive` leaves `'a' + 1` as `'a1'` — so
    the result is a property of the syntax alone and needs no fold-admission gate. An array or object
    literal is excluded precisely because its conversion is interceptable, through `Array.prototype.join`
    and `Object.prototype.toString`.

    A numeric literal is admitted only when the value the parser stored still denotes the number the
    source spells. A JS number is a double, so `9007199254740993` denotes `9007199254740992`, while the
    parser keeps the exact Python integer; converting that would append digits the program never
    produces. Round-tripping through `float` is what separates the two cases.
    """
    if isinstance(node, JsStringLiteral):
        return node.value
    ok, value = extract_literal_value(node)
    if not ok or isinstance(value, list):
        return None
    if isinstance(value, int) and not isinstance(value, bool) and float(value) != value:
        return None
    return to_string(value)


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

    @property
    def reaching(self) -> ReachingModel:
        assert self._cache is not None
        return self._cache.reaching

    def _global_object_alias_base(self, member: JsMemberExpression) -> bool:
        """
        Whether *member*'s base is a local single-assigned to the global object whose value reaches this
        read unchanged — the `var g = globalThis || {}; g.String` idiom. The value must be established
        before the read (`ReachingModel.value_preserved`), so collapsing `g.String` to `String` cannot
        turn a not-yet-assigned `undefined.String` into a different result. The bare syntactic-alias case
        (`globalThis.String`) is handled by `global_alias_member_name`; this covers only the local alias.
        """
        base = member.object
        if not isinstance(base, JsIdentifier) or self.model.global_alias_member_name(member) is not None:
            return False
        binding = self.model.resolve(base)
        if binding is None:
            return False
        value = self.model.singular_value(binding)
        if value is None or self.effects.intrinsic_of(value) is not GLOBAL_OBJECT:
            return False
        return self.reaching.value_preserved(binding, value, base)

    def visit_JsScript(self, node: JsScript):
        """
        Attach the shared model cache for the whole script, then rewrite with the models held for the
        length of the pass. Rebuilding them per rewrite is what made deobfuscation cost the product of
        tree size and rewrite count; a fold gate is consulted on nearly every rewrite, so each rewrite
        paid for a full rebuild of the semantic and effect models.

        Holding them is sound because this pass cannot loosen the facts those models report. It only ever
        removes bindings, never adds one, so a name reported as locally bound stays bound and reading
        shadowing from a held model can only over-preserve a global-alias access, never collapse one a
        local now captures. In the same way it cannot reveal an intrinsic as patched: an install is
        attributed to every name its target may denote, before any fold collapses the target to a plain
        name, so `_globals_written` and `global_pristine` already account for the rewrites this pass
        performs. Were that not so, a held model would report a patched built-in as pristine and admit a
        fold against it.

        "Every name its target may denote" spans two kinds of collapse, and both must already be accounted
        for. One is syntactic — `0 || Math` names `Math` before the fold that reduces it — and the other is
        an alias: `var m = Math; m.floor = f` names `Math` though the assignment mentions only `m`, so
        inlining the alias reveals nothing the held set lacked. Attribution followed the syntax alone until
        the alias step was added, which is exactly the stale-permissive case this argument rules out.

        A write need not be in the file at all for the same argument to be needed. An intrinsic handed to
        code whose writes cannot be enumerated — `patch(Math)` for an unresolvable `patch` — is recorded as
        written when it *escapes*, and escaping is decided through the same value-forwarding forms, so a
        fold that collapses `p(0 || Math)` to `p(Math)` finds the name already recorded. What the pass can do
        is remove an escape, by deleting a dead branch containing one; that shrinks the set, which is the
        direction a held answer may safely be stale in.

        The same argument covers the freshness the effect model reports for a container base. A binding is
        judged fresh only when this pass owns every value it takes, and the pass adds no value to any binding;
        the array guarantee that an allocating method's result depends on is withdrawn by a write to
        `constructor` or `__proto__`, where a key this pass cannot read counts as possibly naming one. Folding
        a computed key to a literal therefore moves that answer from withdrawn to withdrawn — never from
        granted to withdrawn — which is the direction a held model may be stale in.
        """
        self._cache = model_cache(self, node)
        with self._cache.pinned():
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
        bare-assignment form namespace flattening leaves, not only declarations. The value reads
        `undefined` until whatever establishes it — a declarator initializer, a class declaration, or a
        lone assignment — has run, so a `key in name` whose establishing node does not run before the read
        is left unresolved rather than fold away the `TypeError` a premature read would throw.
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
        if not self.dominance.binding_established_before(binding, right):
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
        state = self._own_property_stores(binding, right)
        if state is None:
            return None
        present, any_store = state
        if key in present:
            return True
        if any_store:
            return None
        return False

    def _own_property_stores(self, binding: Binding, read: Node) -> tuple[set[str], bool] | None:
        """
        The own-property state of *binding*'s value at *read*: a pair `(present, any_store)`. *present* is
        the property names a store (`name.k = ...`, `name['k'] = ...`) provably installs before *read*
        runs and that no `delete name.k` can remove; a store that runs after *read* cannot make the key
        present at it, and a key that may be deleted — or that shares the binding with a `delete` of an
        unbounded computed key — is withheld. *any_store* records whether the value receives any
        own-property store at all, so the caller only concludes absence for a value that receives none.
        References are resolved through the model so the set is shadowing-correct. `None` when a store or
        delete targets a computed key that is not a string literal, since the own-property set is then
        unbounded and no `in` membership can be decided.
        """
        stores: list[tuple[str, JsMemberExpression]] = []
        deleted: set[str] = set()
        unbounded_delete = False
        any_store = False
        for ref in self.model.references(binding):
            member = ref.parent
            if not isinstance(member, JsMemberExpression) or member.object is not ref:
                continue
            prop = member.property
            if member.computed:
                name = prop.value if isinstance(prop, JsStringLiteral) else None
            elif isinstance(prop, JsIdentifier):
                name = prop.name
            else:
                name = None
            parent = member.parent
            if isinstance(parent, JsAssignmentExpression) and strip_parens(parent.left) is member:
                if name is None:
                    return None
                any_store = True
                stores.append((name, member))
            elif (
                isinstance(parent, JsUnaryExpression)
                and parent.operator == 'delete'
                and strip_parens(parent.operand) is member
            ):
                if name is None:
                    unbounded_delete = True
                else:
                    deleted.add(name)
        present: set[str] = set()
        for name, member in stores:
            if name in deleted or unbounded_delete:
                continue
            if self.dominance.runs_before(member, read):
                present.add(name)
        return present, any_store

    def visit_JsBinaryExpression(self, node: JsBinaryExpression):
        self.generic_visit(node)
        if node.left is None or node.right is None:
            return None
        op = node.operator
        left_str = string_value(node.left)
        right_str = string_value(node.right)
        if op == '+' and left_str is not None and right_str is not None:
            return make_string_literal(left_str + right_str)
        if op == '+' and (merged := self._merge_concat_tail(node)) is not None:
            return merged
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

    def _merge_concat_tail(self, node: JsBinaryExpression) -> JsBinaryExpression | None:
        """
        Reassociate `(x + 'a') + 'b'` into `x + 'ab'`. Splitting a string across a `+` chain is a common
        concealment, and because `+` is left-associative the chain nests as `((x + 'a') + 'b') + 'c'`, so
        no single node ever has two literal operands and pairwise folding alone never reduces it.

        Merging is legal exactly when the inner node's right operand is a *string* literal. That makes
        the inner `+` a concatenation whatever `x` is, so the outer operand appends to the same string the
        unmerged chain would build, and both forms convert `x` once. When the inner right operand is a
        number the pair cannot be reduced at all: `x + 1 + 2` is `10` for `x = 7` but `'712'` for
        `x = '7'`, so neither `x + 3` nor `x + '12'` is the chain. The number is left where it binds.

        `x` is not converted here and need not be statically known, so a call or an object with a
        side-effecting `valueOf` is fine — it stays in place and still runs exactly once.
        """
        inner = node.left
        if not isinstance(inner, JsBinaryExpression) or inner.operator != '+':
            return None
        if inner.left is None or (head := string_value(inner.right)) is None:
            return None
        if (tail := concat_string(node.right)) is None:
            return None
        return JsBinaryExpression(
            operator='+',
            left=inner.left,
            right=make_string_literal(head + tail),
        )

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

    def _fold_parseint(self, node: JsCallExpression) -> JsNumericLiteral | None:
        if len(node.arguments) < 1:
            return None
        if not self.effects.call_is_foldable(node):
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

    def _try_fold_static_method(self, node: JsCallExpression) -> Node | None:
        callee = node.callee
        if not isinstance(callee, JsMemberExpression):
            return None
        if not isinstance(callee.object, JsIdentifier):
            return None
        static_name = callee.object.name
        if static_name not in STATIC_OBJECTS:
            return None
        method_name = access_key(callee)
        if method_name is None:
            return None
        builtin = BUILTIN_REGISTRY.get((static_name, method_name))
        if builtin is None:
            return None
        if not self.effects.call_is_foldable(node):
            return None
        args = [_node_to_value(a) for a in node.arguments]
        if any(a is _UNCONVERTIBLE for a in args):
            return None
        try:
            result = builtin(args)
        except Exception:
            return None
        return value_to_node(result)

    def _try_fold_free_function(self, node: JsCallExpression) -> Node | None:
        callee = node.callee
        if not isinstance(callee, JsIdentifier):
            return None
        builtin = BUILTIN_REGISTRY.get((None, callee.name))
        if builtin is None:
            return None
        if not self.effects.call_is_foldable(node):
            return None
        args = [_node_to_value(a) for a in node.arguments]
        if any(a is _UNCONVERTIBLE for a in args):
            return None
        try:
            result = builtin(args)
        except Exception:
            return None
        return value_to_node(result)

    def _try_fold_instance_method(self, node: JsCallExpression) -> Node | None:
        callee = node.callee
        if not isinstance(callee, JsMemberExpression):
            return None
        method_name = access_key(callee)
        if method_name is None or method_name in ('split', 'join'):
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
        if not self.effects.call_is_foldable(node, receiver_type=type(receiver)):
            return None
        args = [_node_to_value(a) for a in node.arguments]
        if any(a is _UNCONVERTIBLE for a in args):
            return None
        try:
            result = builtin(receiver, args)
        except Exception:
            return None
        return value_to_node(result)

    def _try_fold_split(self, node: JsCallExpression) -> JsArrayExpression | None:
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
        if not self.effects.call_is_foldable(node, receiver_type=str):
            return None
        parts = obj_str.split(sep) if sep else utf16_code_units(obj_str)
        return JsArrayExpression(
            elements=[make_string_literal(p) for p in parts],
        )

    def _try_fold_join(self, node: JsCallExpression) -> JsStringLiteral | None:
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
        if not self.effects.call_is_foldable(node, receiver_type=list):
            return None
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
            and (self.model.global_alias_member_name(node) is not None or self._global_object_alias_base(node))
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
        if node.operator == '||' and self.effects.intrinsic_of(node.left) is not None:
            return node.left
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
