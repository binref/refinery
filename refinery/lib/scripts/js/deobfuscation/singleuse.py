"""
Unwrap a function the whole script exists to call once.

A one-shot wrapper is a function declaration at the script's top level whose only reference is a
bare statement, at that same top level, invoking it. The body is the payload; the declaration and
the invocation are the machinery. This pass moves the body to the invocation and deletes both in
one edit, one wrapper per pass invocation, so the pipeline re-runs it while any wrapper remains.
"""
from __future__ import annotations

from refinery.lib.scripts import set_body
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    is_direct_eval_call,
    own_arguments_binding,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    a_host_reaches_the_binding,
    body_returns_undefined,
    definitely_answers_the_completion,
    inlined_declarations_safe,
    nothing_still_names,
    preserve_script_end_value,
    references_new_target,
    references_receiver_this,
    sanitize_inlined_body,
    walk_scope,
)
from refinery.lib.scripts.js.model import (
    JsCallExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsScript,
    Statement,
)
from refinery.lib.scripts.js.options import (
    is_host_entrypoint,
    preserves_script_return,
    runs_as_module,
)
from refinery.lib.scripts.js.strict import declares_use_strict


class JsSingleUseFunctionInliner(ScriptLevelTransformer):
    """
    Move the body of a top-level function the script invokes exactly once to that invocation. A
    plain call at statement position discards the completion value, so the move keeps every
    observable the body produces; what it changes is only where the body's own bindings live, and
    the move is admitted exactly where that changes nothing a name can tell.
    """

    def _process_script(self, node: JsScript) -> None:
        """
        Unwrap at most one wrapper per pass, holding the models pinned: the loop stops at the
        first edit, so no model answer is read after the rewrite it would describe.
        """
        cache = model_cache(self, node)
        with cache.pinned():
            for statement in node.body:
                if not isinstance(statement, JsFunctionDeclaration):
                    continue
                if self._unwrap(statement, node, cache):
                    return

    def _unwrap(self, declaration: JsFunctionDeclaration, root: JsScript, cache: ModelCache) -> bool:
        """
        Whether *declaration* is a one-shot wrapper this pass unwrapped, performing the edit and
        reporting it. Every gate refuses rather than repairs: the only safe move is the one that
        changes nothing a name can tell.

        The reference gates hold the shape — the name is read exactly once, as the callee of a
        bare top-level call, written nowhere, exported nowhere, reached by no host the analyst
        named, and named by nothing outside the declaration and the invocation, so nothing
        survives the edit that could miss the function. The tampering gate holds the multiplicity
        — the one invocation executes at most once, so the moved body runs exactly as often as
        the call did. The body gates hold what a splice at statement position cannot reproduce —
        a receiver, `arguments`, `new.target`, a strict prologue, a nested `return`, or a direct
        `eval` that resolves in the wrapper's scope rather than the script's — and the arguments
        of the call must be droppable, since the call evaluates them and nothing reads them. The
        declaration gate holds the move itself: every binding the body declares lands in the
        script's own scope without capturing or colliding, no opaque surface stands anywhere
        that could re-invoke the wrapper by name once it is gone, and none of the landed names
        is one the analyst declared a host reaches — a name the script declares shadows what the
        host put there, which a binding inside the wrapper never did.
        """
        model = cache.model
        if (
            declaration.id is None
            or declaration.body is None
            or declaration.params
            or declaration.generator
            or declaration.is_async
        ):
            return False
        binding = model.binding_of(declaration.id)
        if (
            binding is None
            or binding.exported
            or binding.declarations != [declaration.id]
            or binding.scope is not model.root_scope
        ):
            return False
        invoked = self._single_top_level_invocation(binding, root)
        if invoked is None:
            return False
        call, statement = invoked
        if not nothing_still_names(model, [declaration, statement]):
            return False
        if a_host_reaches_the_binding(model, binding, self.options):
            return False
        if model.reflection_surface_sites(binding):
            return False
        if not cache.tampering.at_most_once(call):
            return False
        if not all(
            cache.effects.is_side_effect_free(
                argument, None,
                call_established=cache.call_established, discarded=True,
                reads_may_throw=True, read_established=cache.read_established,
                coercions_may_write=True,
            )
            for argument in call.arguments
        ):
            return False
        body = declaration.body
        if declares_use_strict(body):
            return False
        if references_receiver_this(body) or references_new_target(body):
            return False
        arguments_binding = own_arguments_binding(model, declaration)
        if arguments_binding is not None and (
            arguments_binding.reads
            or arguments_binding.writes
            or arguments_binding.dynamic_refs
            or arguments_binding.indefinite_writes
        ):
            return False
        if any(
            is_direct_eval_call(node)
            for node in walk_scope(declaration, include_root_body=True)
            if isinstance(node, JsCallExpression)
        ):
            return False
        wrapper_scope = model.function_scope(declaration)
        if wrapper_scope is None:
            return False
        if not inlined_declarations_safe(wrapper_scope, model, model.root_scope):
            return False
        if not runs_as_module(self.options, root) and any(
            is_host_entrypoint(self.options, name)
            for name in wrapper_scope.bindings
        ):
            return False
        statements = sanitize_inlined_body(list(body.body))
        if statements is None:
            return False
        if preserves_script_return(self.options):
            returns_undefined = body_returns_undefined(body.body)
            at_script_end = not any(
                definitely_answers_the_completion(later)
                for later in root.body[root.body.index(statement) + 1:]
            )
            statements = preserve_script_end_value(
                statements,
                returns_undefined=returns_undefined,
                at_script_end=at_script_end,
            )
        self._replace_invocation_with_body(root, declaration, statement, statements)
        self.mark_changed()
        return True

    @staticmethod
    def _single_top_level_invocation(
        binding: Binding, root: JsScript,
    ) -> tuple[JsCallExpression, JsExpressionStatement] | None:
        """
        The one call that invokes *binding*'s function — a plain call, in a bare expression
        statement of the script's own body, through the function's name read exactly once — or
        `None`. The statement position is what makes the move an identity for control flow: an
        invocation written under an `if`, inside a loop, or nested in another expression does not
        run unconditionally at that position, and a `new` expression or a read that hands the
        function elsewhere is not the call this pass replaces.
        """
        if len(binding.reads) != 1 or binding.writes:
            return None
        read = binding.reads[0]
        call = read.parent
        if not isinstance(call, JsCallExpression) or call.callee is not read:
            return None
        statement = call.parent
        if (
            not isinstance(statement, JsExpressionStatement)
            or statement.expression is not call
            or statement.parent is not root
        ):
            return None
        return call, statement

    @staticmethod
    def _replace_invocation_with_body(
        root: JsScript,
        declaration: JsFunctionDeclaration,
        statement: JsExpressionStatement,
        statements: list[Statement],
    ) -> None:
        """
        Splice *statements* where the wrapper's invocation *statement* stands and drop the
        declaration, in one body assignment, so no reader of the tree observes either edit without
        the other. The splice keeps the invocation's position, which is the moment the body already
        runs; the declaration takes no statement with it but its own, so the statements between
        the two keep their distance to the body.

        The comments the wrapper's block carried behind its last statement stand in the payload,
        not on the machinery, so they land behind the spliced statements — on the statement that
        follows them, or on the file's tail where none does — which is the position a parse of
        the spliced text would have given them.
        """
        invoked_at = root.body.index(statement)
        declared_at = root.body.index(declaration)
        kept = [
            other for other in root.body
            if other is not declaration and other is not statement
        ]
        body_lands_at = invoked_at - (1 if declared_at < invoked_at else 0)
        set_body(root, [*kept[:body_lands_at], *statements, *kept[body_lands_at:]])
        trailing = declaration.body.trailing_comments if declaration.body is not None else []
        if trailing:
            follower = body_lands_at + len(statements)
            if follower < len(root.body):
                root.body[follower].leading_comments[:0] = trailing
            else:
                root.trailing_comments[:0] = trailing
