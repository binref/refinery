"""
Evaluate pure JavaScript functions called with constant arguments and replace call sites with
computed results.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from refinery.lib.scripts.js.deobfuscation.helpers import Value

from refinery.lib.scripts import Node, Transformer, _remove_from_parent, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.effects import EffectModel
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    SemanticModel,
    pattern_identifiers,
)
from refinery.lib.scripts.js.deobfuscation.admission import CallAdmission, is_evaluable
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    a_host_reaches_the_binding,
    binding_has_references,
    extract_literal_value,
    remove_declarator,
    replace_with_value,
    substitute_params,
    value_to_node,
)
from refinery.lib.scripts.js.deobfuscation.interpreter import (
    InterpreterError,
    IrreducibleExpression,
    JsInterpreter,
    _ThrowSignal,
)
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsCallExpression,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsScript,
    JsVariableDeclarator,
    strip_parens,
)

_FuncNode = JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression


class JsFunctionEvaluator(ScriptLevelTransformer):
    """
    Evaluate pure JavaScript functions called with constant arguments, replacing call sites with
    computed results. Handles named function calls and IIFEs.
    """

    def __init__(self):
        super().__init__()
        self._script: JsScript | None = None
        self._call_counts: dict[int, int] = {}
        self._resolved_counts: dict[int, int] = {}
        self._failed_counts: dict[int, int] = {}

    def _process_script(self, node: JsScript) -> None:
        """
        Decide every fold of one invocation against the model snapshot it opened with, holding the
        cache pinned through analysis and evaluation. The pin's obligation holds in one direction
        only, and every read obeys it: a fold replaces a call with its value or a substituted clone
        of a body expression, which only ever deletes — a callee reference, the effects the call
        carried, a tampering site it contained — so each held answer stays the stricter one and a
        later fold declines where a fresh model might have proceeded. The dominance a fold reads to
        know the callee's value is established before the call is a statement-order fact, which no
        expression replacement moves, and a spliced clone lands exactly where the call stood and
        carries only names `_substitution_would_break` has already bound identically at that spot,
        so no held fact is revealed more permissive by the splice. The held model has never
        resolved the names of such a clone, so a later fold running the code that holds it reads
        none of them off the model and declines instead.

        The removal of resolved definitions runs after the pin is released, against the model the
        cache rebuilds over the post-evaluation tree: whether anything still names a function is a
        structural fact the folds themselves change — each one deletes the references that kept
        the callee alive, and a spliced clone can name a binding the entry snapshot never saw —
        so this decision cannot be made against the held model without deleting a live function
        or holding a dead one back forever.
        """
        self._script = node
        self._call_counts.clear()
        self._resolved_counts.clear()
        self._failed_counts.clear()
        cache = model_cache(self, node)
        with cache.pinned():
            admission = CallAdmission(cache, node)
            self._evaluate_calls(node, admission)
        self._remove_resolved_definitions(node, admission)

    def _evaluate_calls(self, script: JsScript, admission: CallAdmission) -> None:
        for node in list(script.walk_in_order()):
            if not isinstance(node, JsCallExpression):
                continue
            if node.callee is None:
                continue
            callee = strip_parens(node.callee)
            if isinstance(callee, JsIdentifier):
                self._try_named_call(node, admission)
            elif isinstance(callee, (JsFunctionExpression, JsArrowFunctionExpression)):
                self._try_iife(node, callee, admission)
            elif isinstance(callee, JsMemberExpression):
                self._try_method_chain(node, admission)

    def _try_method_chain(self, node: JsCallExpression, admission: CallAdmission) -> None:
        """
        Evaluate a method call whose value the interpreter can compute — the `[66, 79].map(f).join('')`
        decoder shape and everything it composes from. Unlike a call to a named function, there is no
        function node to run with arguments: the call *is* the expression, so it goes to
        `eval_expression` and the result replaces it.

        Walking outermost-first means the longest chain is attempted before any of its links, so a
        whole decoder collapses in one step and the inner links are gone before they are reached.
        Admission is the shared gate's decision alone, asked at the call
        (`refinery.lib.scripts.js.analysis.cache.ModelCache.trust_at`); this adds no question of its
        own, because every one it would ask — is the prototype intact, does a callback write outside
        itself, is an argument effectful — the gate already asks.
        """
        if not admission.effects.call_is_foldable(node, trust=admission.trust_at(node)):
            return
        self._evaluate_expression_and_replace(node, admission.interpreter_at(node))

    def _evaluate_expression_and_replace(self, node: JsCallExpression, interpreter: JsInterpreter) -> bool:
        """
        Evaluate *node* as a standalone expression and replace it with the result. Returns whether the
        replacement happened. The *interpreter* is the one
        `refinery.lib.scripts.js.deobfuscation.admission.CallAdmission.interpreter_at` builds for
        every fold, so a function the expression calls back into is resolved only where it is in
        place when *node* runs, just as a named call is.

        `_ThrowSignal` is caught alongside the interpreter's own refusals: a JavaScript exception raised
        inside the evaluated expression is the program's business, not a value this fold may produce, and it
        reaches here as its own exception type rather than an `InterpreterError`. An `IrreducibleExpression`
        is a refusal too — the parameter substitution that makes it useful at a call site has no meaning for
        an expression that takes no parameters.
        """
        try:
            result = interpreter.eval_expression(node)
        except (InterpreterError, IrreducibleExpression, _ThrowSignal):
            return False
        if not replace_with_value(node, result):
            return False
        self.mark_changed()
        return True

    def _try_named_call(self, node: JsCallExpression, admission: CallAdmission) -> None:
        func = admission.callee(node)
        if func is None:
            return
        func_id = id(func)
        self._call_counts[func_id] = self._call_counts.get(func_id, 0) + 1
        interpreter = admission.interpreter_at(node)
        args = self._extract_constant_args(node.arguments, interpreter)
        if args is None:
            return
        success = self._evaluate_and_replace(
            node, func, args, interpreter, admission.effects, gate_unresolved=True
        )
        if success:
            self._resolved_counts[func_id] = self._resolved_counts.get(func_id, 0) + 1
        else:
            self._failed_counts[func_id] = self._failed_counts.get(func_id, 0) + 1

    def _try_iife(
        self,
        node: JsCallExpression,
        func: JsFunctionExpression | JsArrowFunctionExpression,
        admission: CallAdmission,
    ) -> None:
        if not admission.effects.summary_of(func).is_literal_replaceable:
            return
        known = admission.known_names(admission.effects.model.scope_of(node), func)
        if not is_evaluable(func, known, admission.effects.model):
            return
        interpreter = admission.interpreter_at(node)
        args = self._extract_constant_args(node.arguments, interpreter)
        if args is None:
            return
        self._evaluate_and_replace(node, func, args, interpreter, admission.effects, gate_unresolved=False)

    def _evaluate_and_replace(
        self,
        node: JsCallExpression,
        func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
        args: list,
        interpreter: JsInterpreter,
        effects: EffectModel,
        gate_unresolved: bool,
    ) -> bool:
        """
        Run *interpreter*, the one
        `refinery.lib.scripts.js.deobfuscation.admission.CallAdmission.interpreter_at` built for
        *node*, on *func* with *args* and, on success, replace *node* with the result. Returns True
        if the call site was resolved (either to a value or a substituted expression).
        """
        try:
            result = interpreter.execute(func, args)
        except IrreducibleExpression as irr:
            if gate_unresolved and self._is_unresolved_call(irr.node):
                return False
            if not effects.summary_of(func).is_expression_replaceable:
                # Splicing one body expression into the call site discards the rest of the body, so this
                # exit needs a stricter admission than the literal one that follows: the dropped statements
                # must carry no effect, and the spliced expression is not a fresh object the way a literal
                # is, so a mutation the body baked into its returned container cannot come along.
                return False
            if self._substitution_would_break(irr.node, func, node):
                return False
            replacement = self._substitute_params_in_clone(irr.node, func, args, self)
            if replacement is None:
                return False
            _replace_in_parent(node, replacement)
            self.mark_changed()
            return True
        except InterpreterError:
            return False
        if not replace_with_value(node, result):
            return False
        self.mark_changed()
        return True

    def _function_is_removable(self, model: SemanticModel, func: _FuncNode) -> bool:
        """
        Whether *func*'s definition can be deleted: it has no surviving static reference and cannot be
        reached by a runtime name lookup. A function named inside a `with` body or otherwise reflected
        (`model.reflection_can_reach`) must be kept even once every direct call has folded away — the
        `with`-body call still needs the binding. This mirrors the reflection gate the unused-code
        remover applies, so both transforms keep the same functions.

        A function the caller declared to be a host entrypoint is likewise never removable: a host calls
        it by name from outside the file, so no reference here can prove it dead. Both transforms consult
        the same declaration, or they would disagree about which functions survive.

        An exported binding is never removable for the same reason the other removal sweeps keep it:
        an importer reads its value across the module boundary once the module has run, so no
        reference here can prove it dead, and deleting the declarator would leave an `export` naming
        a binding the module no longer declares.
        """
        names = model.function_names(func)
        if names is None:
            return False
        exclude = self._function_exclude_node(func)
        for binding in names.bindings:
            if self._is_host_entrypoint(model, binding):
                return False
            if binding.exported:
                return False
            if binding_has_references(model, binding, exclude=exclude):
                return False
            if model.reflection_can_reach(binding):
                return False
        return True

    def _is_host_entrypoint(self, model: SemanticModel, binding: Binding) -> bool:
        """
        Whether *binding* names a function the caller declared a host invokes, and is one a host could
        actually reach — a top-level declaration under the script execution model.
        """
        return a_host_reaches_the_binding(model, binding, self.options)

    def _remove_resolved_definitions(self, script: JsScript, admission: CallAdmission) -> None:
        removed: set[int] = set()
        while True:
            model = model_cache(self, script).model
            before = len(removed)
            for func in admission.functions:
                func_id = id(func)
                if func_id in removed:
                    continue
                call_count = self._call_counts.get(func_id, 0)
                if call_count == 0:
                    continue
                resolved = self._resolved_counts.get(func_id, 0)
                failed = self._failed_counts.get(func_id, 0)
                if (resolved + failed) < call_count:
                    continue
                name = self._function_name(func)
                if name is None:
                    continue
                if self._function_is_removable(model, func):
                    self._remove_function(func)
                    removed.add(func_id)
                    self.mark_changed()
            for func in admission.functions:
                func_id = id(func)
                if func_id in removed:
                    continue
                if not admission.is_pure(func):
                    continue
                name = self._function_name(func)
                if name is None:
                    continue
                call_count = self._call_counts.get(func_id, 0)
                if call_count == 0:
                    continue
                if self._function_is_removable(model, func):
                    self._remove_function(func)
                    removed.add(func_id)
                    self.mark_changed()
            if len(removed) == before:
                break

    @staticmethod
    def _function_name(func: _FuncNode) -> str | None:
        if isinstance(func, JsFunctionDeclaration):
            return func.id.name if isinstance(func.id, JsIdentifier) else None
        declarator = func.parent
        if isinstance(declarator, JsVariableDeclarator) and isinstance(declarator.id, JsIdentifier):
            return declarator.id.name
        return None

    @staticmethod
    def _function_exclude_node(func: _FuncNode) -> Node:
        if isinstance(func, JsFunctionDeclaration):
            return func
        declarator = func.parent
        if isinstance(declarator, JsVariableDeclarator):
            return declarator
        return func

    def _remove_function(self, func: _FuncNode) -> None:
        if isinstance(func, JsFunctionDeclaration):
            _remove_from_parent(func)
        else:
            declarator = func.parent
            if isinstance(declarator, JsVariableDeclarator):
                remove_declarator(declarator)
            else:
                _remove_from_parent(func)

    def _extract_constant_args(
        self,
        arguments: list,
        interpreter: JsInterpreter,
    ) -> list[Value] | None:
        """
        The values of a call's *arguments*, or `None` when one of them is not known: a literal, or a
        name that holds a constant when the call runs. The name is read by the *interpreter* that
        runs the call, through
        `refinery.lib.scripts.js.deobfuscation.interpreter.JsInterpreter.constant_of`, so an
        argument naming a table is the same object a read of that name in the body answers, as it
        is in the program.
        """
        args: list[Value] = []
        for arg in arguments:
            known, value = extract_literal_value(arg)
            if not known and isinstance(arg, JsIdentifier):
                known, value = interpreter.constant_of(arg)
            if not known:
                return None
            args.append(value)
        return args

    def _is_unresolved_call(self, node: Node) -> bool:
        """
        Check whether the irreducible expression contains any function call. If so, the wrapper
        inliner or string-array resolver should handle it — the evaluator should not substitute
        parameters into a call that it couldn't fully evaluate.
        """
        for child in node.walk():
            if isinstance(child, JsCallExpression):
                return True
        return False

    def _substitution_would_break(self, node: Node, func: _FuncNode, call_site: Node) -> bool:
        """
        Whether splicing *node* — an irreducible sub-expression of *func*'s body — into *call_site* by
        parameter substitution would change behavior. Substitution replaces each parameter with its
        original argument value and discards the rest of the body, so it is unsafe when *node*:

        - writes a parameter, which would place the argument value at a write target (`delete p`
          becomes `delete <literal>`, `(p = 5)` becomes `(<literal> = 5)`);
        - reads a parameter that *func* reassigns — statically, or through a `with` body or direct
          `eval` — whose value at the irreducible point is no longer the original argument the
          substitution would supply;
        - references a name bound inside *func* but declared outside *node* — a body local (including a
          destructured or `catch` binding), a nested declaration, `arguments`, or the function
          expression's own name — which has no binding once the body is discarded, leaving a dangling
          reference;
        - references a name that resolves outside *func*, or to no binding at all, but which a
          same-named local in scope at *call_site* would recapture, so the spliced reference would bind
          to a different declaration there than it does in *func*.

        A binding *node* itself introduces travels with it and stays intact. Every reference is resolved
        through the model, so shadowing and destructuring are exact; a free name whose read crosses a
        `with` in *func* is treated as unsafe, since its runtime target cannot be matched at *call_site*.
        """
        script = self._script
        if script is None:
            return True
        model = model_cache(self, script).model
        call_scope = model.scope_of(call_site)
        if call_scope is None:
            return True
        param_bindings = {
            binding
            for param in func.params
            for ident in pattern_identifiers(param)
            if (binding := model.binding_of(ident)) is not None
        }
        for child in node.walk():
            if not isinstance(child, JsIdentifier) or not model.is_reference(child):
                continue
            binding = model.resolve(child)
            if binding is None:
                if model.read_has_dynamic_effect(child):
                    return True
                if model.lookup(child.name, call_scope) is not None:
                    return True
                continue
            if not binding.declared_within(func):
                if model.lookup(child.name, call_scope) is not binding:
                    return True
                continue
            if binding in param_bindings:
                if not model.binding_never_reassigned(binding):
                    return True
                continue
            if binding.declared_within(node):
                continue
            return True
        return False

    @staticmethod
    def _substitute_params_in_clone(
        node: Node,
        func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
        args: list[Value],
        transformer: Transformer,
    ) -> Node | None:
        """
        A clone of *node* with every parameter of *func* replaced by the argument the call handed it,
        or None where a parameter *node* reads has nothing to be replaced by.

        A parameter is left standing when the value handed to it has no faithful literal form, and a
        parameter that is not a plain name binds no single node to substitute at all. Either way it
        keeps its own name, and a name spliced into the call site reads whatever is bound to it there
        rather than the value the call made. Refusing leaves the call standing, which reduces less
        and states nothing false.
        """
        params: list[Node] = []
        arguments: list[Node] = []
        standing: set[str] = set()
        for index, param in enumerate(func.params):
            argument = None
            if isinstance(param, JsIdentifier):
                argument = value_to_node(args[index] if index < len(args) else None)
            if argument is None:
                standing.update(ident.name for ident in pattern_identifiers(param))
                continue
            params.append(param)
            arguments.append(argument)
        for child in node.walk():
            if isinstance(child, JsIdentifier) and child.name in standing:
                return None
        return substitute_params(node, params, arguments, transformer=transformer)
