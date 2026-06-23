"""
Remove the self-defending ReDoS anti-tamper pattern injected by javascript-obfuscator.

The obfuscator inserts a guard function that calls

    toString().search('(((.+)+)+)+$')

on itself. The catastrophic-backtracking regex causes the JS engine to hang when the code has been
reformatted (e.g. by a pretty-printer), acting as an anti-tamper check. This transformer detects
the signature regex string after all other deobfuscation has completed and surgically removes the
guard call, its variable declarator, and the associated factory function.
"""
from __future__ import annotations

from refinery.lib.scripts import _remove_from_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    binding_has_references,
    remove_declarator,
)
from refinery.lib.scripts.js.model import (
    JsBlockStatement,
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionExpression,
    JsIdentifier,
    JsScript,
    JsStringLiteral,
    JsVariableDeclaration,
    JsVariableDeclarator,
)

_REDOS_SIGNATURE = '(((.+)+)+)+$'


class JsRemoveReDoS(ScriptLevelTransformer):
    """
    Detect and remove the self-defending ReDoS pattern by its signature regex string.
    """

    def _process_script(self, node: JsScript):
        for literal in list(node.walk()):
            if (
                isinstance(literal, JsStringLiteral)
                and _REDOS_SIGNATURE in literal.value
            ):
                self._remove_pattern(literal, node)

    def _remove_pattern(self, redos_literal: JsStringLiteral, root: JsScript) -> None:
        guard_decl = redos_literal.parent
        while guard_decl is not None and not isinstance(guard_decl, JsVariableDeclarator):
            guard_decl = guard_decl.parent
        if guard_decl is None or not isinstance(guard_decl.id, JsIdentifier):
            return
        if not isinstance(guard_decl.init, JsCallExpression):
            return
        callee = guard_decl.init.callee
        if isinstance(callee, JsIdentifier):
            factory_name = callee.name
        elif isinstance(callee, JsFunctionExpression):
            factory_name = None
        else:
            return
        guard_name = guard_decl.id.name
        co_names: set[str] = set()
        if factory_name is None:
            for arg in guard_decl.init.arguments:
                if isinstance(arg, JsIdentifier):
                    co_names.add(arg.name)
        var_decl = guard_decl.parent
        if not isinstance(var_decl, JsVariableDeclaration):
            return
        body_parent = var_decl.parent
        if isinstance(body_parent, JsScript):
            body = body_parent.body
        elif isinstance(body_parent, JsBlockStatement):
            body = body_parent.body
        else:
            return
        for stmt in list(body):
            if (
                isinstance(stmt, JsExpressionStatement)
                and isinstance(stmt.expression, JsCallExpression)
                and isinstance(stmt.expression.callee, JsIdentifier)
                and stmt.expression.callee.name == guard_name
                and not stmt.expression.arguments
            ):
                _remove_from_parent(stmt)
        remove_declarator(guard_decl)
        cleanup_names = {factory_name} if factory_name is not None else co_names
        for name in cleanup_names:
            model = model_cache(self, root).model
            for stmt in list(body):
                if not isinstance(stmt, JsVariableDeclaration):
                    continue
                for d in list(stmt.declarations):
                    if (
                        isinstance(d, JsVariableDeclarator)
                        and isinstance(d.id, JsIdentifier)
                        and d.id.name == name
                    ):
                        binding = model.binding_of(d.id)
                        if not binding_has_references(model, binding):
                            remove_declarator(d)
        self.mark_changed()
