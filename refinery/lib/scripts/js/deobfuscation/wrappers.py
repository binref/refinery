"""
Inline trivial function call wrappers.

A call wrapper is a small function whose only purpose is to forward a call to another function
after rearranging or arithmetically transforming its arguments. This is a common obfuscation
technique that adds a layer of indirection around every call site. The transformer detects these
wrappers and substitutes each call site with the inlined return expression.
"""
from __future__ import annotations

from collections import Counter
from typing import NamedTuple

from refinery.lib.scripts import (
    Node,
    _remove_from_parent,
    _replace_in_parent,
)
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import SemanticModel, is_use_position
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    arguments_substitutable,
    expression_a_call_answers,
    is_closed_expression,
    is_literal,
    is_simple_expression,
    names_used_under_a_nested_scope,
    substitute_params,
)
from refinery.lib.scripts.js.model import (
    JsCallExpression,
    JsFunctionDeclaration,
    JsIdentifier,
    JsScript,
)


class _WrapperInfo(NamedTuple):
    """
    Describes a detected call wrapper function. *multi_use* holds the parameters read more than once
    by the return expression: substituting anything but a simple, identity-stable argument for one
    of these would evaluate the argument once per read, splitting one value into distinct copies.
    *deferred* holds the parameters read inside a function nested in the return expression, where a
    substituted argument would no longer evaluate at the call but on each later run of that body;
    only a literal argument reads the same there. *unused* holds the parameters the return
    expression never reads, whose argument the inline drops: a dropped argument that may throw a
    `ReferenceError` would mute the throw the call raised, so its inline is refused.
    """
    node: JsFunctionDeclaration
    name: str
    param_names: list[str]
    return_expression: Node
    multi_use: frozenset[str]
    deferred: frozenset[str]
    unused: frozenset[str]


def _detect_wrapper(node: JsFunctionDeclaration) -> _WrapperInfo | None:
    """
    Test whether a function declaration is a trivial wrapper. Two forms are recognized:

    1. **Call wrappers** (one or more parameters): the body is a single return of a call expression
       whose arguments are closed over the wrapper's parameters and literal constants.
    2. **Constant functions** (zero parameters): the body is a single return of an expression that
       is closed (no free variables — only literal constants).

    Neither is recognized where a call to the function answers a wrapper around the return
    expression rather than the expression itself, which
    `refinery.lib.scripts.js.deobfuscation.helpers.expression_a_call_answers` decides.
    """
    if node.id is None:
        return None
    answered = expression_a_call_answers(node)
    if answered is None:
        return None
    expr, param_names = answered
    if param_names:
        if not isinstance(expr, JsCallExpression):
            return None
        if not isinstance(expr.callee, JsIdentifier):
            return None
        allowed_names = set(param_names) | {expr.callee.name}
        for arg in expr.arguments:
            if not is_closed_expression(arg, allowed_names):
                return None
    else:
        if not is_closed_expression(expr, set()):
            return None
    uses = Counter(
        n.name for n in expr.walk()
        if isinstance(n, JsIdentifier) and is_use_position(n)
    )
    multi_use = frozenset(name for name in param_names if uses[name] > 1)
    deferred = frozenset(param_names) & names_used_under_a_nested_scope(expr)
    unused = frozenset(name for name in param_names if uses[name] == 0)
    return _WrapperInfo(node, node.id.name, param_names, expr, multi_use, deferred, unused)


def _collect_wrappers(root: Node) -> dict[str, _WrapperInfo]:
    """
    Walk the entire AST and collect all function declarations that qualify as call wrappers.
    """
    wrappers: dict[str, _WrapperInfo] = {}
    for node in root.walk():
        if isinstance(node, JsFunctionDeclaration):
            info = _detect_wrapper(node)
            if info is not None:
                wrappers[info.name] = info
    return wrappers


class JsCallWrapperInliner(ScriptLevelTransformer):
    """
    Detect trivial call wrapper functions and inline them at every call site the wrapper's value has
    reached. A function declared in the scope it names has that value before any statement runs, so
    every call site qualifies; one Annex B copies into the scope around a block has it only from the
    declaration onwards, and a call written before that reads `undefined` and throws.
    """

    def _process_script(self, node: JsScript):
        wrappers = _collect_wrappers(node)
        if not wrappers:
            return
        with model_cache(self, node).pinned() as cache:
            inlined = self._inline_the_calls_the_wrappers_reach(node, wrappers, cache)
        if not inlined:
            return
        kept = self._wrappers_to_keep(node, wrappers)
        for name, info in wrappers.items():
            if name not in kept:
                _remove_from_parent(info.node)
        self.mark_changed()

    def _inline_the_calls_the_wrappers_reach(
        self, node: JsScript, wrappers: dict[str, _WrapperInfo], cache: ModelCache,
    ) -> bool:
        """
        Replace every call the wrappers of *wrappers* reach with the expression it forwards to, and
        report whether any was replaced.

        The models are read from a cache the caller holds pinned, because each replacement advances
        the tree's mutation counter and an unpinned read would rebuild all of them per call site.
        Nothing this loop does makes a model it reads more permissive: a replaced call is gone, and
        no declaration moves, so a call site it has not reached yet is ordered exactly as it was.
        """
        effects = cache.effects
        dominance = cache.dominance
        by_node = {id(info.node): info for info in wrappers.values()}
        for dead in self._self_forwarding_wrappers(wrappers, by_node, effects):
            del by_node[dead]
        inlined = False
        for ast_node in list(node.walk()):
            if not isinstance(ast_node, JsCallExpression):
                continue
            target = effects.static_callee(ast_node)
            if target is None:
                continue
            info = by_node.get(id(target))
            if info is None:
                continue
            if not dominance.established_before(target, ast_node):
                continue
            if not arguments_substitutable(ast_node.arguments, info.param_names):
                continue
            if not all(effects.is_side_effect_free(a) for a in ast_node.arguments):
                continue
            if any(
                name in info.unused
                and not effects.is_side_effect_free(
                    argument,
                    reads_may_throw=True,
                    read_established=cache.read_established,
                )
                for name, argument in zip(info.param_names, ast_node.arguments)
            ):
                continue
            if not all(
                is_simple_expression(argument)
                for name, argument in zip(info.param_names, ast_node.arguments)
                if name in info.multi_use
            ):
                continue
            if not all(
                is_literal(argument)
                for name, argument in zip(info.param_names, ast_node.arguments)
                if name in info.deferred
            ):
                continue
            if not self._forwarded_callee_reaches(cache.model, info, ast_node):
                continue
            replacement = substitute_params(
                info.return_expression,
                info.node.params,
                ast_node.arguments,
                transformer=self,
            )
            _replace_in_parent(ast_node, replacement)
            inlined = True
        return inlined

    @staticmethod
    def _forwarded_callee_reaches(
        model: SemanticModel, info: _WrapperInfo, call: JsCallExpression,
    ) -> bool:
        """
        Whether the free name the wrapper's return expression calls resolves, from *call*'s scope,
        to the same binding it reads at the wrapper — so that the forwarded name does not get
        captured by a local of that name at the destination. A callee that is one of the wrapper's
        own parameters is substituted by the argument and carries no name into the destination, and
        a callee that is not a bare name — a constant wrapper's body may call through a
        literal — carries none either; neither places a constraint.
        """
        expr = info.return_expression
        if not isinstance(expr, JsCallExpression):
            return True
        callee = expr.callee
        if not isinstance(callee, JsIdentifier) or callee.name in info.param_names:
            return True
        return model.lookup(callee.name, model.scope_of(call)) is model.resolve(callee)

    @staticmethod
    def _self_forwarding_wrappers(
        wrappers: dict[str, _WrapperInfo],
        by_node: dict[int, _WrapperInfo],
        effects: EffectModel,
    ) -> set[int]:
        """
        The wrapper declaration nodes that lie on a cycle of wrapper-to-wrapper forwarding, where
        inlining would never bottom out: a wrapper whose body forwards to itself, directly or through
        a chain of other wrappers (`W -> V -> W`). Each call wrapper forwards to at most one statically
        resolvable callee, so the forwarding graph is functional and a node lies on a cycle exactly
        when following its single edge returns to it. Such a wrapper is left un-inlined; inlining it
        would regenerate an equivalent call on every pass and the fold loop would never terminate.
        """
        edge: dict[int, int | None] = {}
        for info in wrappers.values():
            expr = info.return_expression
            target = effects.static_callee(expr) if isinstance(expr, JsCallExpression) else None
            edge[id(info.node)] = id(target) if target is not None and id(target) in by_node else None
        on_cycle: set[int] = set()
        visited: set[int] = set()
        for start in edge:
            if start in visited:
                continue
            path: list[int] = []
            index: dict[int, int] = {}
            cursor: int | None = start
            while cursor is not None and cursor not in visited:
                visited.add(cursor)
                index[cursor] = len(path)
                path.append(cursor)
                cursor = edge.get(cursor)
            if cursor is not None and cursor in index:
                on_cycle.update(path[index[cursor]:])
        return on_cycle

    @staticmethod
    def _wrappers_to_keep(
        node: JsScript, wrappers: dict[str, _WrapperInfo]
    ) -> set[str]:
        """
        The wrapper names still referenced after inlining, so the rest may be removed. A wrapper is
        kept when its name is referenced from live code: code outside every wrapper body, or the body
        of a wrapper that is itself kept. The keep-set is grown to a fixpoint so that a wrapper reached
        only from another surviving (un-inlined, e.g. arity-mismatched) wrapper is retained rather than
        deleted into a dangling call. A reference inside a body that will itself be removed does not
        count, since that body goes away with it.
        """
        kept: set[str] = set()
        changed = True
        while changed:
            changed = False
            dead_body_ids: set[int] = set()
            for name, info in wrappers.items():
                if name not in kept:
                    for n in info.node.walk():
                        dead_body_ids.add(id(n))
            for n in node.walk():
                if id(n) in dead_body_ids:
                    continue
                if isinstance(n, JsIdentifier) and n.name in wrappers and n.name not in kept:
                    kept.add(n.name)
                    changed = True
        return kept
