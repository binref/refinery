"""
JavaScript syntax normalization transforms.
"""
from __future__ import annotations

from refinery.lib.scripts import Expression, Node, Transformer
from refinery.lib.scripts.js.analysis.assignment import DefiniteAssignmentModel
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.dominance import DominanceModel
from refinery.lib.scripts.js.analysis.effects import GLOBAL_OBJECT, EffectModel
from refinery.lib.scripts.js.analysis.environment import (
    GUARANTEED_GLOBAL_TYPEOF,
    GUARANTEED_GLOBALS,
)
from refinery.lib.scripts.js.analysis.model import (
    FUNCTION_NODES,
    SAME_REALM_GLOBAL_OBJECT_ALIASES,
    Binding,
    BindingKind,
    SemanticModel,
    is_constructed_or_invoked,
    is_invocation_target,
    is_member_write_target,
)
from refinery.lib.scripts.js.analysis.reaching import ReachingModel
from refinery.lib.scripts.js.deobfuscation.helpers import (
    OBJECT_PROTOTYPE_MEMBERS,
    RELATIONAL_OPS,
    UNARY_OPS,
    MemberRead,
    access_key,
    allocated_object_type,
    converts_uninterceptably,
    denoted_value,
    escape_js_string,
    eval_binary_op,
    extract_literal_value,
    is_literal,
    is_nullish,
    is_simple_expression,
    is_truthy,
    is_valid_identifier,
    is_valid_property_key,
    make_numeric_literal,
    make_string_literal,
    numeric_value,
    read_data_property,
    spelled_for_the_callee_position,
    string_value,
    try_inline_trivial_function,
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
    JsBooleanLiteral,
    JsCallExpression,
    JsClassDeclaration,
    JsClassExpression,
    JsConditionalExpression,
    JsExpressionStatement,
    JsFunctionExpression,
    JsIdentifier,
    JsLogicalExpression,
    JsMemberExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsProperty,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsStringLiteral,
    JsUnaryExpression,
    callee_form_sensitive,
    strip_parens,
)
from refinery.lib.scripts.js.numbers import exact_integer
from refinery.lib.scripts.js.options import runs_as_module
from refinery.lib.scripts.js.precedence import parens_required
from refinery.lib.scripts.js.strict import joins_directive_prologue, spelling_states

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


_UNCONVERTIBLE = object()


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
    """
    if isinstance(node, JsStringLiteral):
        return node.value
    ok, value = extract_literal_value(node)
    if not ok or isinstance(value, list):
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
    def assignment(self) -> DefiniteAssignmentModel:
        assert self._cache is not None
        return self._cache.assignment

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
        if not isinstance(base, JsIdentifier) or self._names_a_global(member) is not None:
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

    def _alias_collapse_is_sound(
        self, member: JsMemberExpression, base: JsIdentifier, name: str
    ) -> bool:
        """
        Whether collapsing `<global-alias>.name` — base *base*, property *name* — to the bare `name`
        preserves both throws the access can raise, so the rewrite drops neither. The binding of *name*
        is resolved once and answers both.

        The property must be defined, so the `undefined` a resolvable read yields where the property is
        absent does not become a `ReferenceError`: a free name must be one the specification mandates on
        the global object (`GUARANTEED_GLOBALS`); a name the program itself defines as a global (an
        implicit global) exists only after its establishing write, so it is admitted only when a write
        is proven to run before this read — interprocedurally, so a top-level write still covers a read
        inside a function invoked after it, but strictly, so a same-statement or earlier read is
        declined.

        The base must resolve, so the `ReferenceError` an absent host raises reading it is not dropped:
        a base the language mandates in every host (`globalThis`) or a bound local never throws
        (`SemanticModel.read_may_throw`). A host-conditional alias (`window`, `self`, `top`, `frames`,
        `global`) may not resolve — but where *name* is a global the program itself defines rather than
        a specification intrinsic, its establishing write was made through this same alias and so
        already resolved it on every path that reaches this read, which is exactly the case the property
        check admits by finding a binding.
        """
        binding = self.model.lookup(name, self.model.scope_of(member))
        if binding is None:
            if name not in GUARANTEED_GLOBALS:
                return False
            return not self.model.read_may_throw(base)
        return self.assignment.definitely_assigned_at(binding, member)

    def _names_a_global(self, member: JsMemberExpression) -> str | None:
        """
        The global *member* names, read under the execution model this run was asked for and only
        where the base names this realm's global object. Every fold this pass makes on the strength
        of an access naming a global asks it this way, since a rewrite it drives is one an analyst
        runs the file under that model.

        `top` and `frames` name another document's global object, so a property on one is not the
        property a bare name in this file reads and a fold that treats the two as one turns an
        `undefined` into a `ReferenceError`. They are read as global-object bases all the same
        wherever the answer only keeps code; a rewrite is the case where it does not.
        """
        base = strip_parens(member.object)
        if isinstance(base, JsIdentifier) and base.name not in SAME_REALM_GLOBAL_OBJECT_ALIASES:
            return None
        return self.model.global_alias_member_name(
            member, module_scope=runs_as_module(self.options, self.model.root))

    def _resolve_in(self, node: JsBinaryExpression, key: str) -> bool | None:
        """
        Statically resolve `key in name` by asking the model what value *name* holds. A sole function,
        an empty class, or an empty object literal has a bounded property set — the built-in members of
        its type plus the own properties the binding is assigned — so membership is decidable; any other
        value, or one whose own-property set cannot be bounded, yields `None`. The binding is
        resolved through the model, so the answer is shadowing-correct across scopes and recognizes
        the bare-assignment form namespace flattening leaves, not only declarations. The value
        reads `undefined` until whatever establishes it — a declarator initializer, a class
        declaration, or a lone assignment — has run, so a `key in name` whose establishing node does
        not run before the read is left unresolved rather than fold away the `TypeError` a premature
        read would throw.

        Bounded is a claim about the prototype chain and holds only while the file leaves that chain
        alone, so **both** answers need the chain asked about, and both ask it the same way. A name
        the tables do not list is there once `Object.prototype.z = 9` has run, and a name they do
        list is gone once a `delete` has removed it, so neither side is free and neither may be
        answered under a surface the other refuses under. The tables are asked for the whole
        property set and not the inherited half `property_provably_absent` enumerates, an own
        `length` and `prototype` included, so the membership question stays this one's and only the
        chain question is shared. A class constructor is a function value, and its chain is a
        function's.
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
            members, receiver_type = _FUNCTION_PROPERTIES, JsFunctionExpression
        elif isinstance(value, (JsClassDeclaration, JsClassExpression)):
            if value.super_class is not None:
                return None
            if value.body is not None and value.body.body:
                return None
            members, receiver_type = _FUNCTION_PROPERTIES, JsFunctionExpression
        elif isinstance(value, JsObjectExpression) and not value.properties:
            members, receiver_type = _EMPTY_OBJECT_PROPERTIES, dict
        else:
            return None
        if key in members:
            return True if self.effects.read_chain_intact(receiver_type) else None
        state = self._own_property_stores(binding, right)
        if state is None:
            return None
        present, any_store = state
        if key in present:
            return True
        if any_store:
            return None
        if not self.effects.read_chain_intact(receiver_type):
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
        if op == 'in' and isinstance(node.left, JsStringLiteral) and node.left.value is not None:
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
        fn = strip_parens(node.callee)
        if isinstance(fn, JsFunctionExpression):
            replacement = try_inline_trivial_function(fn, node.arguments, transformer=self)
            if replacement is None:
                return None
            return spelled_for_the_callee_position(node, replacement)
        return (
            self._try_fold_static_method(node)
            or self._try_fold_free_function(node)
            or self._try_fold_instance_method(node)
            or self._try_fold_split(node)
            or self._try_fold_join(node)
        )

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
        args = [self._node_to_value(a) for a in node.arguments]
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
        args = [self._node_to_value(a) for a in node.arguments]
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
        receiver = self._node_to_value(callee.object)
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
        args = [self._node_to_value(a) for a in node.arguments]
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
            if not isinstance(e, JsStringLiteral) or e.value is None:
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

    def _discarding(
        self,
        node: Expression,
        test: Expression,
        kept: Expression | None,
    ) -> Expression | None:
        """
        *kept* in place of *node*, preceded by *test* where dropping the latter would change what the
        program does. Two separate reasons it may have to stay.

        Evaluating it is an effect: a fold that picks a branch answers from the test's *value* and has
        no further use for it, but the test may call, or read a property whose getter runs.
        `JsDeadCodeElimination` keeps a statement test for the same reason and in the same way.

        And *node* may be what a call invokes, in which case removing the operator around *kept*
        changes the receiver: `(1 ? o.m : g)()` invokes with no receiver, where a bare `o.m()` binds
        `o`, and `(1 ? eval : g)(s)` is an indirect eval where a bare `eval(s)` is a direct one. The
        sequence is what preserves that — `(0, o.m)()` is the idiom for calling without a receiver —
        so a form-sensitive branch keeps it even when the test does nothing at all.
        """
        if kept is None:
            return None
        receiver_sensitive = is_invocation_target(node) and callee_form_sensitive(kept)
        if not receiver_sensitive and self.effects.is_side_effect_free(
            test, discarded=True, reads_may_throw=True, read_established=self._read_established
        ):
            return kept
        return JsSequenceExpression(expressions=[test, kept])

    def _read_established(self, node: JsIdentifier) -> bool:
        assert self._cache is not None
        return self._cache.read_established(node)

    def visit_JsConditionalExpression(self, node: JsConditionalExpression):
        self.generic_visit(node)
        if node.test is None:
            return None
        truthy = is_truthy(node.test, self.model)
        if truthy is None:
            return None
        return self._discarding(node, node.test, node.consequent if truthy else node.alternate)

    def visit_JsSequenceExpression(self, node: JsSequenceExpression):
        self.generic_visit(node)
        if not node.expressions:
            return None
        filtered = [
            e for i, e in enumerate(node.expressions)
            if i == len(node.expressions) - 1
            or not is_simple_expression(e)
            or self.effects.read_throws(e, self._read_established)
        ]
        if len(filtered) == len(node.expressions):
            return None
        if len(filtered) == 1:
            if is_invocation_target(node) and callee_form_sensitive(filtered[0]):
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
        """
        Replace an access by what it reads, where that is decided and standing in its place means the
        same thing.

        A target that is assigned, updated, deleted, or destructured is not such a place at all: it
        is somewhere to store into, a constant is not, and every arm below is refused there.

        Where the value is applied, the arms part company, because they write down different things.
        The alias arm writes another way of naming the same function, so it has only to keep the
        receiver a call reads off a member and the scope a direct `eval` needs. The arms that write a
        constant have nothing to keep: a constant is neither callable nor a constructor, so the
        application throws whatever they do, and folding only changes which text the `TypeError`
        names — which is why they refuse a `new` the alias arm is free to fold under.
        """
        self.generic_visit(node)
        in_read_position = not is_member_write_target(node)
        reads_a_value = in_read_position and not is_constructed_or_invoked(node)
        if (
            not node.computed
            and isinstance(node.object, JsIdentifier)
            and isinstance(node.property, JsIdentifier)
            and (self._names_a_global(node) is not None or self._global_object_alias_base(node))
            and not self._resolves_to_local(node, node.property.name)
            and self._alias_collapse_is_sound(node, node.object, node.property.name)
        ):
            if in_read_position and not is_invocation_target(node):
                return node.property
            return None
        if reads_a_value:
            if (folded := self._folded_string_property(node)) is not None:
                return folded
            if (folded := self._folded_array_length(node)) is not None:
                return folded
        if node.computed and node.object is not None and node.property is not None:
            if (
                reads_a_value
                and isinstance(node.object, JsArrayExpression)
                and isinstance(node.property, JsNumericLiteral)
            ):
                idx = exact_integer(node.property.value)
                elements = node.object.elements
                if (
                    idx is not None
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

    def _fresh_object_type(self, operand: Node | None) -> str | None:
        """
        The `typeof` of the object *operand* allocates, when creating it has no other effect — `None`
        otherwise. The type is `allocated_object_type`'s syntactic answer; the freedom from effects is
        asked with the value discarded, because that is what folding does with it. Only the type or the
        truthiness survives, and the object itself does not.
        """
        kind = allocated_object_type(operand)
        if kind is None:
            return None
        node = strip_parens(operand)
        if node is None:
            return None
        free = self.effects.is_side_effect_free(
            node, discarded=True, reads_may_throw=True, read_established=self._read_established)
        return kind if free else None

    def _member_key(self, node: JsMemberExpression) -> str | None:
        """
        The property name the access at *node* reads, or `None` when nothing decides it. A dot access
        is named by its identifier and a computed one by the string its key converts to, which is the
        rule the interpreter's `_member_key` applies to an evaluated key and the reason a numeric one
        is asked with `denoted_value` rather than `string_value`: `'abc'[1]` reads the property named
        `'1'`, and a reader that only recognized a string key would decide every index access to be
        undecidable.

        A key that is not a primitive is refused however well its value is known, because naming the
        property is what converts it and an array or an object converts through a prototype method
        the file can replace. `Array.prototype.join = () => '2'` makes `'abc'[[1]]` read `'c'`, so a
        reader that spelled the key `'1'` from the element would answer with the wrong character.
        """
        if not node.computed:
            return node.property.name if isinstance(node.property, JsIdentifier) else None
        known, key = denoted_value(node.property, self.model)
        if not known or not converts_uninterceptably(key):
            return None
        return to_string(key)

    def _folded_string_property(self, node: JsMemberExpression) -> Expression | None:
        """
        The value a property read on a constant string denotes, as a node, or `None` when the read is
        not one this decides. `'abc'.length` is `3` and `'abc'[1]` is `'b'`, both own properties of the
        string that no prototype can shadow, so reading them needs no assumption about the chain.

        Only a string is read here. An array literal's index is already answered by handing back the
        element node, which keeps the spelling the file wrote it with, and its `length` is a function
        of the literal's shape rather than of any value. A string has no such node to hand back: the
        character at an index is a value the file never spelled.

        The object is asked with `denoted_value`, which decides a literal, a global value name, and an
        operator over either — every one of them free of effects — so nothing is discarded by
        replacing the access with what it reads, and no separate effect gate is needed.

        An index answers a string, and a string is the one value whose spelling a statement position
        reads: standing alone at the top of a body it is a directive. `'abc'[0];` is an ordinary
        statement that ends a Directive Prologue, and `'a';` continues one, which would make a
        `'use strict'` below it govern the file it merely stood in. Such a read is left alone.
        """
        key = self._member_key(node)
        if key is None:
            return None
        known, obj = denoted_value(node.object, self.model)
        if not known or not isinstance(obj, str):
            return None
        outcome, value = read_data_property(obj, key)
        if outcome is not MemberRead.FOUND:
            return None
        if isinstance(value, str) and self._stands_in_a_directive_prologue(node):
            return None
        return value_to_node(value)

    def _stands_in_a_directive_prologue(self, node: Node) -> bool:
        """
        Whether *node* is the whole of a statement that a Directive Prologue would take in were it
        spelled as a string literal. `joins_directive_prologue` decides that of the statement; what is
        decided here is that *node* is the whole of one.

        The brackets a read stands in are climbed through rather than trusted to keep it out of the
        prologue: `('abc'[0]);` is not a directive, but nothing keeps the printer from spelling the
        folded literal without them, and then it is.
        """
        cursor: Node = node
        statement = cursor.parent
        while isinstance(statement, JsParenthesizedExpression):
            cursor, statement = statement, statement.parent
        if not isinstance(statement, JsExpressionStatement):
            return False
        if strip_parens(statement.expression) is not node:
            return False
        return joins_directive_prologue(statement)

    def _folded_array_length(self, node: JsMemberExpression) -> Expression | None:
        """
        The `length` of an array literal, as a node, or `None` when the literal does not decide it.
        This is the one property a value domain cannot answer: `[a, b, c]` and `[1, , 3]` denote no
        value the folder can hold, because an element is not a literal or is not there at all, yet
        each is three elements long whatever those elements turn out to be. The count is read off the
        syntax, where the parser records an elision as an element that is absent and a trailing comma
        as no element at all, exactly as the language counts them.

        A spread is the one element whose count is not the literal's to know — `[...'abc']` is three
        elements from one — so a literal holding any is declined rather than counted wrong. That
        stays stated here even though the effect gate below happens to refuse a spread too: what
        makes a spread wrong is the count, not the iterating, and a later effect model that learned
        to trust iterating an array would otherwise start answering `[...[1, 2]].length` with `1`.

        Only the length survives, so the array and every element in it is discarded, and evaluating
        an element may therefore do nothing at all. Every element must be a literal or an elision,
        which is the strongest thing the folder can say and the only one that is true: asking
        `is_side_effect_free` instead — the question `_fresh_object_type` asks of an allocation —
        answers yes for a name no binding resolves and for an operator that runs `valueOf`, so
        `[zzz].length` would print `1` where the file threw a `ReferenceError` and `[+o].length`
        would swallow what reading `o` writes.
        """
        if self._member_key(node) != 'length':
            return None
        array = strip_parens(node.object)
        if not isinstance(array, JsArrayExpression):
            return None
        if any(isinstance(element, JsSpreadElement) for element in array.elements):
            return None
        if not all(element is None or is_literal(element) for element in array.elements):
            return None
        return value_to_node(len(array.elements))

    def _node_to_value(self, node: Node | None) -> object:
        """
        The Python equivalent of *node* for `BUILTIN_REGISTRY` dispatch, or the module-level sentinel
        `_UNCONVERTIBLE` when nothing decides what the node denotes.
        """
        known, value = denoted_value(node, self.model)
        return value if known else _UNCONVERTIBLE

    def _deletion_is_unobservable(self, node: JsUnaryExpression) -> bool:
        """
        Whether the `delete` at *node* removes a property that nothing in the program can read, so that
        the deletion is a dead store and only its result — `true`, the answer for every configurable and
        every absent property — remains. The object literal keeps the property, which is sound precisely
        because no reader of it survives; editing the literal instead would have to be ordered against
        every read, while leaving it needs no ordering at all.

        The object must be a container held by a local that nothing else can reach: a single unwritten
        declaration bound to a freshly allocated literal, immutable across the rest of the program, and
        referenced only through statically named properties other than the deleted one. That last
        condition is what rules out every reader — a method call, a spread, a `for-in`, or an escape into
        a call would each be able to observe the property, and none of them is a named read.
        """
        member = strip_parens(node.operand)
        if not isinstance(member, JsMemberExpression):
            return False
        base = member.object
        key = access_key(member)
        if key is None or not isinstance(base, JsIdentifier):
            return False
        binding = self.model.resolve(base)
        if binding is None or binding.writes or len(binding.declarations) != 1:
            return False
        value = self.model.singular_value(binding)
        if not isinstance(value, (JsObjectExpression, JsArrayExpression)):
            return False
        if not self.effects.binding_is_immutable_container(binding, exclude=node):
            return False
        for reference in self.model.references(binding):
            if reference is base:
                continue
            access = reference.parent
            if not isinstance(access, JsMemberExpression) or access.object is not reference:
                return False
            if access_key(access) in (None, key):
                return False
        return True

    def _typeof_guaranteed_global(self, operand: Node | None) -> str | None:
        """
        The string `typeof <operand>` yields when *operand* is a bare read of a name the specification
        mandates on the global object (`GUARANTEED_GLOBAL_TYPEOF`) that the program leaves pristine and
        does not shadow at this site — `None` otherwise. Such a name resolves in every host to a value
        of a fixed type, so its `typeof` is host-independent, unlike a host-conditional alias (`window`,
        `self`, …) whose `typeof` is `'undefined'` where the host omits it and an object where it does
        not. This is what lets a `typeof globalThis !== 'undefined'` guard fold to `true`, so
        `refinery.lib.scripts.js.deobfuscation.deadcode.JsDeadCodeElimination` can prune the arm it
        protects and a global-object finder reduce to `return globalThis`. Pristineness is
        `refinery.lib.scripts.js.analysis.effects.EffectModel.trusted_intrinsic`, which refuses a name
        the program reassigns, shadows anywhere, or could reach through a reflection surface — any of
        which could give `typeof` a different answer.
        """
        node = strip_parens(operand)
        if not isinstance(node, JsIdentifier) or node.name not in GUARANTEED_GLOBAL_TYPEOF:
            return None
        if self.effects.trusted_intrinsic(node) is None:
            return None
        return GUARANTEED_GLOBAL_TYPEOF[node.name]

    def visit_JsUnaryExpression(self, node: JsUnaryExpression):
        """
        Fold a unary operator against its operand. Everything that is a function of the operand's value
        is answered by the shared `UNARY_OPS` kernel, so that a fold performed here and the same
        operator applied by the interpreter cannot disagree; what is left is the two questions a value
        cannot answer — the type of an object whose identity no literal spells, and whether a `delete`
        may be dropped. A third, `typeof` of a pristine guaranteed global, is a value the operator hides
        rather than one the operand denotes, so it is decided by name (`_typeof_guaranteed_global`).

        A value whose spelling still needs a unary operator is left alone. `-Infinity` and `void 0` are
        how those two values are written, so folding one of them produces the expression it replaces:
        no operator is removed, and the pass would rewrite the same node for as long as it is allowed
        to run. Declining says the operand was already written in the shortest form it has.
        """
        self.generic_visit(node)
        operand = node.operand
        if operand is None:
            return None
        op = node.operator
        if op == 'delete':
            return JsBooleanLiteral(value=True) if self._deletion_is_unobservable(node) else None
        kind = self._fresh_object_type(operand)
        if kind is not None:
            if op == 'typeof':
                return make_string_literal(kind)
            if op == '!':
                return JsBooleanLiteral(value=False)
        if op == 'typeof':
            typed = self._typeof_guaranteed_global(operand)
            if typed is not None:
                return make_string_literal(typed)
        apply = UNARY_OPS.get(op)
        if apply is None:
            return None
        known, value = denoted_value(operand, self.model)
        if not known:
            return None
        folded = value_to_node(apply(value))
        if isinstance(folded, JsUnaryExpression):
            return None
        return folded

    def visit_JsStringLiteral(self, node: JsStringLiteral):
        """
        Spell a literal the shortest way that denotes the same text, where the spelling it was
        given states nothing of its own.

        Two spellings state something. One the source never closed has no spelling at all, and
        writing one hands it the quote nobody wrote — the file stops being the file that was read.
        And a spelling a rule reads may not be traded for one the same rule reads differently: an
        escape hiding a space in `'use\\x20strict'` is what keeps that line from being a directive,
        and re-spelling it makes every line behind it strict code.
        """
        if not node.terminated or node.value is None:
            return None
        quote = node.raw[0] if node.raw else '\''
        rebuilt = quote + escape_js_string(node.value, quote) + quote
        if rebuilt == node.raw:
            return None
        if spelling_states(rebuilt[1:-1]) != spelling_states(node.body):
            return None
        node.raw = rebuilt
        self.mark_changed()
        return None

    def visit_JsLogicalExpression(self, node: JsLogicalExpression):
        self.generic_visit(node)
        if node.left is None or node.right is None:
            return None
        if node.operator == '||' and self.effects.intrinsic_of(node.left) is not None:
            return node.left
        op = node.operator
        if op == '??':
            nullish = is_nullish(node.left, self.model)
            if nullish is None:
                return None
            return self._discarding(node, node.left, node.right) if nullish else node.left
        truthy = is_truthy(node.left, self.model)
        if truthy is None:
            return None
        if op == '&&':
            return self._discarding(node, node.left, node.right) if truthy else node.left
        if op == '||':
            return node.left if truthy else self._discarding(node, node.left, node.right)
        return None
