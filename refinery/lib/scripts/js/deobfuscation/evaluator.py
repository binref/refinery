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
    Scope,
    SemanticModel,
    call_supplies_an_arguments_object,
    pattern_identifiers,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    GLOBAL_VALUE_NAMES,
    ScriptLevelTransformer,
    a_host_reaches_the_binding,
    binding_constant,
    binding_has_references,
    extract_literal_value,
    is_reference,
    names_global_value,
    references_receiver_this,
    remove_declarator,
    replace_with_value,
    substitute_params,
    value_to_node,
    walk_scope,
)
from refinery.lib.scripts.js.deobfuscation.interpreter import (
    InterpreterError,
    IrreducibleExpression,
    JsInterpreter,
    _ThrowSignal,
    is_runtime_name,
    names_runtime_builtin,
)
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsCatchClause,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNumericLiteral,
    JsReturnStatement,
    JsScript,
    JsStringLiteral,
    JsSwitchCase,
    JsSwitchStatement,
    JsVariableDeclaration,
    JsVariableDeclarator,
    strip_parens,
)

_FuncNode = JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression


def _is_value_closed(
    func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
    known: set[str],
    model: SemanticModel,
) -> bool:
    """
    Check whether a function's body is closed enough for the interpreter to evaluate a call to
    it: it references only its own parameters, names declared within its body, the names in
    *known* (a function already proven pure or a binding holding a constant), registry built-ins,
    and well-known globals. This is the *value* precondition — every name the interpreter needs is
    resolvable — and is deliberately separate from the *effect* precondition that a call writes no
    observable state, which `refinery.lib.scripts.js.analysis.effects.EffectModel` decides. A body
    that is a single switch-return (globalConcealing shape) qualifies even when its return
    expressions reference external names, because the irreducible fallback substitutes the
    parameters into them.
    """
    for param in func.params:
        if not isinstance(param, JsIdentifier):
            return False
    body = func.body
    if body is None:
        return True
    local_names = {p.name for p in func.params if isinstance(p, JsIdentifier)}
    _collect_declared_names(body, local_names)
    if isinstance(func, JsFunctionDeclaration) and isinstance(func.id, JsIdentifier):
        local_names.add(func.id.name)
    elif isinstance(func, JsFunctionExpression) and isinstance(func.id, JsIdentifier):
        local_names.add(func.id.name)
    if references_receiver_this(body):
        return False
    if _is_switch_return_pattern(body, local_names):
        return True
    for node in walk_scope(body):
        if isinstance(node, JsIdentifier) and is_reference(node) and node.name not in local_names:
            name = node.name
            if name in known:
                continue
            if names_runtime_builtin(node, model) or names_global_value(node, model):
                continue
            if name == 'arguments' and call_supplies_an_arguments_object(model, func):
                continue
            return False
    return True


def _is_switch_return_pattern(body, local_names: set[str]) -> bool:
    """
    Check whether the function body is a switch statement where every case returns an expression.
    This is the globalConcealing pattern where return expressions may reference external names
    but the dispatch logic itself is pure (switch on a parameter).
    """
    if not isinstance(body, JsBlockStatement):
        return False
    stmts = body.body
    if not stmts:
        return False
    switch = stmts[0]
    if not isinstance(switch, JsSwitchStatement):
        return False
    for remaining in stmts[1:]:
        if isinstance(remaining, JsReturnStatement) and remaining.argument is None:
            continue
        return False
    if switch.discriminant is None:
        return False
    if isinstance(switch.discriminant, JsIdentifier):
        if switch.discriminant.name not in local_names:
            return False
    elif not _all_refs_local(switch.discriminant, local_names):
        return False
    if not switch.cases:
        return False
    for case in switch.cases:
        if not isinstance(case, JsSwitchCase):
            return False
        if case.test is not None and not isinstance(case.test, (JsStringLiteral, JsNumericLiteral)):
            return False
        case_body = case.body
        if len(case_body) != 1:
            return False
        stmt = case_body[0]
        if not isinstance(stmt, JsReturnStatement) or stmt.argument is None:
            return False
    return True


def _all_refs_local(node: Node, local_names: set[str]) -> bool:
    for child in node.walk():
        if isinstance(child, JsIdentifier) and is_reference(child):
            if child.name not in local_names:
                return False
    return True


def _collect_declared_names(body, names: set[str]) -> None:
    if not isinstance(body, JsBlockStatement):
        return
    for node in walk_scope(body):
        if isinstance(node, JsVariableDeclaration):
            for decl in node.declarations:
                if isinstance(decl, JsVariableDeclarator) and isinstance(decl.id, JsIdentifier):
                    names.add(decl.id.name)
        if isinstance(node, JsFunctionDeclaration) and isinstance(node.id, JsIdentifier):
            names.add(node.id.name)
        if isinstance(node, JsCatchClause) and isinstance(node.param, JsIdentifier):
            names.add(node.param.name)


def _unresolved_names(
    func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
    known: set[str],
    model: SemanticModel,
) -> set[str]:
    """
    Return the set of external names referenced by *func* that are not locally declared, not in
    *known*, and not well-known globals or runtime names. Names that are plain-assigned (`=`)
    within the function body AND also read within the same body are treated as implicit locals
    (obfuscator temporaries like `rr = expr; ... use(rr)`) and excluded. Names that are only
    plain-assigned but never read are also excluded (write-only temps). Compound-assigned names
    (`+=`, `|=`, etc.) that were NOT also plain-initialized are always retained — they perform a
    read-modify-write of the external binding and are never a local temp.
    """
    body = func.body
    if body is None:
        return set()
    local_names = {p.name for p in func.params if isinstance(p, JsIdentifier)}
    _collect_declared_names(body, local_names)
    if isinstance(func, JsFunctionDeclaration) and isinstance(func.id, JsIdentifier):
        local_names.add(func.id.name)
    elif isinstance(func, JsFunctionExpression) and isinstance(func.id, JsIdentifier):
        local_names.add(func.id.name)
    plain_assigned: set[str] = set()
    compound_assigned: set[str] = set()
    read: set[str] = set()
    host_supplied: set[str] = set()
    claimed: set[str] = set()
    for node in walk_scope(body, include_root_body=True):
        if not isinstance(node, JsIdentifier) or not is_reference(node):
            continue
        name = node.name
        if name in local_names:
            continue
        if isinstance(node.parent, JsAssignmentExpression) and node.parent.left is node:
            if node.parent.operator == '=':
                plain_assigned.add(name)
            else:
                compound_assigned.add(name)
                read.add(name)
        else:
            read.add(name)
            if names_runtime_builtin(node, model) or names_global_value(node, model):
                host_supplied.add(name)
            elif name == 'arguments' and call_supplies_an_arguments_object(model, func):
                host_supplied.add(name)
            elif name in GLOBAL_VALUE_NAMES or is_runtime_name(name):
                claimed.add(name)
    external_names: set[str] = set()
    for name in read - plain_assigned:
        if name in known:
            continue
        if name in host_supplied and name not in claimed:
            continue
        external_names.add(name)
    return external_names


def _is_evaluable(
    func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
    known: set[str],
    model: SemanticModel,
) -> bool:
    """
    Whether every name a call to *func* reads has an answer, given the *known* names: its body is
    value-closed (`_is_value_closed`), or it is a function expression or an arrow that reads no
    receiver `this` and whose other free names are only temporaries it assigns before reading them
    (`_unresolved_names`).
    """
    if _is_value_closed(func, known, model):
        return True
    return (
        not isinstance(func, JsFunctionDeclaration)
        and func.body is not None
        and not references_receiver_this(func.body)
        and not _unresolved_names(func, known, model)
    )


class JsFunctionEvaluator(ScriptLevelTransformer):
    """
    Evaluate pure JavaScript functions called with constant arguments, replacing call sites with
    computed results. Handles named function calls and IIFEs.
    """

    def __init__(self):
        super().__init__()
        self._script: JsScript | None = None
        self._effects: EffectModel | None = None
        self._functions: list[_FuncNode] = []
        self._pure_nodes: set[int] = set()
        self._binding_constants: dict[Binding, tuple[bool, Value]] = {}
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
        self._effects = None
        self._functions = []
        self._pure_nodes.clear()
        self._binding_constants.clear()
        self._call_counts.clear()
        self._resolved_counts.clear()
        self._failed_counts.clear()
        cache = model_cache(self, node)
        with cache.pinned():
            self._analyze_purity(node)
            self._evaluate_calls(node)
        self._remove_resolved_definitions(node)

    def _collect_named_functions(self, script: JsScript) -> list[_FuncNode]:
        """
        Every function the model resolves a name to unambiguously: a function declaration, a
        `var`/`let`/`const` declarator initializer, or a hoisted `var` assigned a function exactly once
        (`var f; f = function(){}`, the form namespace flattening leaves). This is
        `EffectModel.unambiguous_function`, the same filter the interpreter resolves nested callees
        through, so every name a call site can reach is a candidate for purity analysis here. Anonymous
        functions and names that held a value and were then reassigned are excluded, because the model
        resolves no single function for them.
        """
        effects = self._effects
        if effects is None:
            return []
        model = effects.model
        functions: list[_FuncNode] = []
        for node in script.walk():
            if not isinstance(node, _FuncNode):
                continue
            if effects.unambiguous_function(model.invocation_binding(node)) is node:
                functions.append(node)
        return functions

    def _known_names(self, scope: Scope | None, func: _FuncNode) -> set[str]:
        """
        The names *func*'s body reads that resolve, from *scope* outward, to something a call to
        *func* can be evaluated with: a function already proven pure, or a binding that holds a
        constant (`_binding_constant`) no write inside *func* establishes. A nearer binding wins: a
        name rebound below the scope that holds the pure function or the constant — a parameter or
        a local — shadows it and is not known, matching how the name resolves inside the body being
        analyzed. Only the names the body reads are asked about: the question is asked for every
        function on every round of `_analyze_purity`, and a scope may hold thousands of names that
        no body reads. Whether the constant is in place when a call runs is asked for each call,
        through the callback of the interpreter `_interpreter_at` builds.
        """
        effects = self._effects
        body = func.body
        if effects is None or body is None:
            return set()
        model = effects.model
        names: set[str] = set()
        read = {
            node.name for node in walk_scope(body, include_root_body=True)
            if isinstance(node, JsIdentifier) and is_reference(node)
        }
        for name in read:
            current = scope
            while current is not None and name not in current.bindings:
                current = current.parent
            if current is None:
                continue
            binding = current.bindings[name]
            function = effects.unambiguous_function(binding)
            if function is not None and id(function) in self._pure_nodes:
                names.add(name)
                continue
            if not self._binding_constant(binding)[0]:
                continue
            sites = model.binding_establishment_sites(binding)
            if sites is None or any(site is func or site.is_descendant_of(func) for site in sites):
                continue
            names.add(name)
        return names

    def _binding_constant(self, binding: Binding) -> tuple[bool, Value]:
        """
        The constant *binding* holds once established, as
        `refinery.lib.scripts.js.deobfuscation.helpers.binding_constant` answers it, asked once per
        binding for each invocation.
        """
        effects = self._effects
        if effects is None:
            return False, None
        cached = self._binding_constants.get(binding)
        if cached is None:
            cached = binding_constant(effects, binding, self.options)
            self._binding_constants[binding] = cached
        return cached

    def _constant_at(self, binding: Binding | None, call: JsCallExpression) -> tuple[bool, Value]:
        """
        The constant *binding* holds while *call* runs, as `(True, value)`, or `(False, None)`: the
        binding must hold a constant (`_binding_constant`) that is in place before *call* runs. This
        is the question the interpreter asks through its *constant* callback for a free name the
        folded body reads, and the one a constant argument of *call* is resolved by.
        """
        if binding is None:
            return False, None
        known, value = self._binding_constant(binding)
        if not known:
            return False, None
        cache = self._cache_for(call)
        if cache is None or not cache.dominance.binding_established_before(binding, call):
            return False, None
        return True, value

    def _analyze_purity(self, script: JsScript) -> None:
        self._effects = model_cache(self, script).effects
        self._functions = self._collect_named_functions(script)
        changed = True
        while changed:
            changed = False
            for func in self._functions:
                if id(func) in self._pure_nodes:
                    continue
                if not self._effects.summary_of(func).is_literal_replaceable:
                    continue
                known = self._known_names(self._effects.model.function_scope(func), func)
                if _is_evaluable(func, known, self._effects.model):
                    self._pure_nodes.add(id(func))
                    changed = True

    def _evaluate_calls(self, script: JsScript) -> None:
        for node in list(script.walk_in_order()):
            if not isinstance(node, JsCallExpression):
                continue
            if node.callee is None:
                continue
            callee = strip_parens(node.callee)
            if isinstance(callee, JsIdentifier):
                self._try_named_call(node)
            elif isinstance(callee, (JsFunctionExpression, JsArrowFunctionExpression)):
                self._try_iife(node, callee)
            elif isinstance(callee, JsMemberExpression):
                self._try_method_chain(node)

    def _try_method_chain(self, node: JsCallExpression) -> None:
        """
        Evaluate a method call whose value the interpreter can compute — the `[66, 79].map(f).join('')`
        decoder shape and everything it composes from. Unlike a call to a named function, there is no
        function node to run with arguments: the call *is* the expression, so it goes to
        `eval_expression` and the result replaces it.

        Walking outermost-first means the longest chain is attempted before any of its links, so a whole
        decoder collapses in one step and the inner links are gone before they are reached. Admission is
        the shared gate's decision alone; this adds no question of its own, because every one it would ask
        — is the prototype intact, does a callback write outside itself, is an argument effectful — the gate
        already asks.
        """
        effects = self._effects
        if effects is None or not effects.call_is_foldable(node):
            return
        self._evaluate_expression_and_replace(node)

    def _evaluate_expression_and_replace(self, node: JsCallExpression) -> bool:
        """
        Evaluate *node* as a standalone expression and replace it with the result. Returns whether the
        replacement happened. The interpreter is the one `_interpreter_at` builds for every fold, so
        a function the expression calls back into is resolved only where it is in place when *node*
        runs, just as a named call is.

        `_ThrowSignal` is caught alongside the interpreter's own refusals: a JavaScript exception raised
        inside the evaluated expression is the program's business, not a value this fold may produce, and it
        reaches here as its own exception type rather than an `InterpreterError`. An `IrreducibleExpression`
        is a refusal too — the parameter substitution that makes it useful at a call site has no meaning for
        an expression that takes no parameters.
        """
        interpreter = self._interpreter_at(node)
        try:
            result = interpreter.eval_expression(node)
        except (InterpreterError, IrreducibleExpression, _ThrowSignal):
            return False
        if not replace_with_value(node, result):
            return False
        self.mark_changed()
        return True

    def _interpreter_at(self, call: JsCallExpression) -> JsInterpreter:
        """
        The interpreter every fold of *call* runs in. It is anchored at *call* and handed the
        tampering oracle, so the trust questions its arms ask are answered for the moment this call
        runs rather than the whole program — the decoder a file carries before the call it blocks
        still refuses it, the one guaranteed to run after does not. It asks this evaluator whether a
        function it resolves is in place (`_established_before`) at the point it names, and knows a
        name declared outside the function it runs only as the constant `_constant_at` finds that
        name holding when *call* runs.
        """
        cache = self._cache_for(call)
        return JsInterpreter(
            effects=self._effects,
            anchor=call,
            tampering=cache.tampering if cache is not None else None,
            established=self._established_before,
            constant=lambda binding: self._constant_at(binding, call),
        )

    def _cache_for(self, node: Node):
        """
        The model cache of the script holding *node*, for the anchor the interpreter's trust
        questions are asked through — or `None` where no script holds it, leaving the interpreter
        unanchored and its trust questions on their no-anchor arms.
        """
        script = self._script
        if script is None or not node.is_descendant_of(script):
            return None
        return model_cache(self, script)

    def _established_before(self, func: Node, reference: Node) -> bool:
        """
        Whether *func*'s value is installed before *reference* runs, where *reference* is a call or
        a read of the function's name. A function declaration is hoisted, so it is always
        established; a declarator initializer (`const`/`let`/`var f = function(){}`) is in place
        only once its declarator has run, and a lone assignment (`f = function(){}`, the form
        namespace flattening leaves) only once that assignment has run. A premature call to either
        reads a value that is absent — a temporal dead zone `ReferenceError`, or the hoisted
        `undefined` a `var` call throws a `TypeError` on — which the interpreted body must not
        silently replace with a result. The model names the establishing nodes; dominance decides
        whether they all precede *reference*.
        """
        script = self._script
        if script is None:
            return False
        return model_cache(self, script).dominance.established_before(func, reference)

    def _try_named_call(self, node: JsCallExpression) -> None:
        if self._effects is None:
            return
        func = self._effects.static_callee(node)
        if func is None or id(func) not in self._pure_nodes:
            return
        if node.is_descendant_of(func):
            return
        if not self._established_before(func, node):
            return
        func_id = id(func)
        self._call_counts[func_id] = self._call_counts.get(func_id, 0) + 1
        interpreter = self._interpreter_at(node)
        args = self._extract_constant_args(node.arguments, interpreter)
        if args is None:
            return
        success = self._evaluate_and_replace(node, func, args, interpreter, gate_unresolved=True)
        if success:
            self._resolved_counts[func_id] = self._resolved_counts.get(func_id, 0) + 1
        else:
            self._failed_counts[func_id] = self._failed_counts.get(func_id, 0) + 1

    def _try_iife(
        self,
        node: JsCallExpression,
        func: JsFunctionExpression | JsArrowFunctionExpression,
    ) -> None:
        if self._effects is None or not self._effects.summary_of(func).is_literal_replaceable:
            return
        known = self._known_names(self._effects.model.scope_of(node), func)
        if not _is_evaluable(func, known, self._effects.model):
            return
        interpreter = self._interpreter_at(node)
        args = self._extract_constant_args(node.arguments, interpreter)
        if args is None:
            return
        self._evaluate_and_replace(node, func, args, interpreter, gate_unresolved=False)

    def _evaluate_and_replace(
        self,
        node: JsCallExpression,
        func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
        args: list,
        interpreter: JsInterpreter,
        gate_unresolved: bool,
    ) -> bool:
        """
        Run *interpreter*, the one `_interpreter_at` built for *node*, on *func* with *args* and, on
        success, replace *node* with the result. Returns True if the call site was resolved (either
        to a value or a substituted expression).
        """
        try:
            result = interpreter.execute(func, args)
        except IrreducibleExpression as irr:
            if gate_unresolved and self._is_unresolved_call(irr.node):
                return False
            if not self._effects.summary_of(func).is_expression_replaceable:
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
        binding = model.naming_binding(func)
        if binding is None:
            return False
        if self._is_host_entrypoint(model, binding):
            return False
        if binding.exported:
            return False
        exclude = self._function_exclude_node(func)
        return (
            not binding_has_references(model, binding, exclude=exclude)
            and not model.reflection_can_reach(binding)
        )

    def _is_host_entrypoint(self, model: SemanticModel, binding: Binding) -> bool:
        """
        Whether *binding* names a function the caller declared a host invokes, and is one a host could
        actually reach — a top-level declaration under the script execution model.
        """
        return a_host_reaches_the_binding(model, binding, self.options)

    def _remove_resolved_definitions(self, script: JsScript) -> None:
        removed: set[int] = set()
        while True:
            model = model_cache(self, script).model
            before = len(removed)
            for func in self._functions:
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
            for func in self._functions:
                func_id = id(func)
                if func_id in removed:
                    continue
                if func_id not in self._pure_nodes:
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
            owner = binding.scope.node
            if owner is not func and not owner.is_descendant_of(func):
                if model.lookup(child.name, call_scope) is not binding:
                    return True
                continue
            if binding in param_bindings:
                if not model.binding_never_reassigned(binding):
                    return True
                continue
            if owner is node or owner.is_descendant_of(node):
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
