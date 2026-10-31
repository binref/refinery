"""
Which calls of named functions the interpreter may run, and the interpreter a run of one gets. The
function evaluator folds the calls this admits, and the recovery of state machines runs them on the
values a machine computes.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from refinery.lib.scripts.js.analysis.cache import ModelCache
    from refinery.lib.scripts.js.values import Value

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.effects import AnchoredTrust, EffectModel
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    Scope,
    SemanticModel,
    call_supplies_an_arguments_object,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    binding_constant,
    held_constant,
    is_reference,
    names_global_value,
    references_receiver_this,
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
    FUNCTION_NODES,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsBlockStatement,
    JsCallExpression,
    JsCatchClause,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsFunctionNode,
    JsIdentifier,
    JsMemberExpression,
    JsReturnStatement,
    JsScript,
    JsSwitchCase,
    JsSwitchStatement,
    JsVariableDeclaration,
    JsVariableDeclarator,
    strip_parens,
)
from refinery.lib.scripts.js.values import GLOBAL_VALUE_NAMES


def _is_value_closed(
    func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
    known: set[str],
    model: SemanticModel,
) -> bool:
    """
    Check whether a function's body is closed enough for the interpreter to evaluate a call to
    it: every part of it a call computes (`_computed_parts`) references only its own parameters,
    names declared within its body, the names in *known* (a function already proven pure or a
    binding holding a constant), registry built-ins, and well-known globals. This is the *value*
    precondition — every name the interpreter needs is resolvable — and is deliberately separate
    from the *effect* precondition that a call writes no observable state, which
    `refinery.lib.scripts.js.analysis.effects.EffectModel` decides.
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
    for part in _computed_parts(body):
        for node in walk_scope(part):
            if not isinstance(node, JsIdentifier) or not is_reference(node) or node.name in local_names:
                continue
            name = node.name
            if name in known:
                continue
            if names_runtime_builtin(node, model) or names_global_value(node, model):
                continue
            if name == 'arguments' and call_supplies_an_arguments_object(model, func):
                continue
            return False
    return True


def _computed_parts(body: Node) -> list[Node]:
    """
    The parts of a function's *body* a call computes, which is all of it but for one shape: a body
    that opens with a switch whose every case is one `return` of an expression, a lookup by key. A
    case's expression may read names the call cannot resolve, because a return of an expression
    the interpreter cannot reduce is spliced into the call site with the parameters substituted;
    the discriminant, the case tests and every statement after the switch are computed.
    """
    if not isinstance(body, JsBlockStatement) or not body.body:
        return [body]
    switch, *after = body.body
    if not isinstance(switch, JsSwitchStatement) or switch.discriminant is None or not switch.cases:
        return [body]
    tests: list[Node] = []
    for case in switch.cases:
        if not isinstance(case, JsSwitchCase) or len(case.body) != 1:
            return [body]
        returned = case.body[0]
        if not isinstance(returned, JsReturnStatement) or returned.argument is None:
            return [body]
        if case.test is not None:
            tests.append(case.test)
    return [switch.discriminant, *tests, *after]


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
    *known*, and not well-known globals or runtime names. A name the body only assigns with `=`
    and never reads is left out, a write-only temporary. A name it reads is kept, whether or not
    it also assigns it first: another run of the function, or code outside it, may read what it
    stores, which the effect summary decides
    (`refinery.lib.scripts.js.analysis.effects.EffectModel`), and a compound assignment (`+=`,
    `|=`) reads the external binding it writes.
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
            if node.parent.operator != '=':
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
    for name in read:
        if name in known:
            continue
        if name in host_supplied and name not in claimed:
            continue
        external_names.add(name)
    return external_names


def is_evaluable(
    func: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
    known: set[str],
    model: SemanticModel,
) -> bool:
    """
    Whether every name a call to *func* reads has an answer, given the *known* names: its body is
    value-closed (`_is_value_closed`), or it is a function expression or an arrow that reads no
    receiver `this` and whose other free names it only ever assigns and never reads
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


class CallAdmission:
    """
    Which calls of named functions the interpreter may run, for the tree one effect model was built
    over. A function is admitted where its summary lets a call be replaced by its value and every
    name its body reads resolves to an admitted function or to a binding holding a constant that
    the body does not establish itself (`known_names`), which is a fixpoint over every function a
    name resolves to unambiguously. A call of one is admitted where it does not stand in the
    function's own body and the name it reads the callee through holds the function before it
    runs (`callee`). The interpreter that runs it is anchored at the call (`interpreter_at`).

    The admission answers for the effect model it is built over, `effects`, and asks the cache for
    the dominance and tampering models built beside it. A holder builds it where the tree is the one
    that model was built over, and a new one where the cache holds another effect model: what it
    derived from one tree is not an answer about another.
    """

    def __init__(self, cache: ModelCache, script: JsScript):
        self.cache = cache
        self.script = script
        self.effects: EffectModel = cache.effects
        self._constants: dict[Binding, tuple[bool, Value]] = {}
        self._chains: dict[int, tuple[JsCallExpression, Value]] = {}
        self._pure: set[int] = set()
        self.functions = self._collect_named_functions(script)
        changed = True
        while changed:
            changed = False
            for func in self.functions:
                if id(func) in self._pure:
                    continue
                if not self.effects.summary_of(func).is_literal_replaceable:
                    continue
                known = self.known_names(self.effects.model.function_scope(func), func)
                if is_evaluable(func, known, self.effects.model):
                    self._pure.add(id(func))
                    changed = True

    def is_pure(self, func: JsFunctionNode) -> bool:
        """
        Whether a call of *func* may be run where it is in place.
        """
        return id(func) in self._pure

    def holds(self, node: Node) -> bool:
        """
        Whether *node* is part of the tree the admission answers for. A question about any other
        node is refused, or answered on the interpreter's no-anchor arms.
        """
        return node.is_descendant_of(self.script)

    def trust_at(self, node: Node) -> AnchoredTrust | None:
        """
        The trust questions at *node*, or `None` for a node outside the tree.
        """
        return self.cache.trust_at(node) if self.holds(node) else None

    def callee(self, call: JsCallExpression) -> JsFunctionNode | None:
        """
        The function *call* runs, where the call is admitted: its static callee is admitted, the
        call does not stand in that function's own body, and the name it reads the callee through
        holds the function before the call runs (`callee_established_before`).
        """
        func = self.effects.static_callee(call)
        if func is None or not self.is_pure(func):
            return None
        if call.is_descendant_of(func) or not self.callee_established_before(call):
            return None
        return func

    def _collect_named_functions(self, script: JsScript) -> list[JsFunctionNode]:
        """
        Every function the model resolves a name to unambiguously: a function declaration, a
        `var`/`let`/`const` declarator initializer, or a hoisted `var` assigned a function exactly
        once (`var f; f = function(){}`, the form namespace flattening leaves). This is
        `EffectModel.unambiguous_function`, the same filter the interpreter resolves nested callees
        through, so every name a call site can reach is a candidate for purity analysis here.
        Anonymous functions and names that held a value and were then reassigned are excluded,
        because the model resolves no single function for them.
        """
        effects = self.effects
        model = effects.model
        functions: list[JsFunctionNode] = []
        for node in script.walk():
            if not isinstance(node, FUNCTION_NODES):
                continue
            names = model.function_names(node)
            if names is not None and effects.unambiguous_function(names.own) is node:
                functions.append(node)
        return functions

    def known_names(self, scope: Scope | None, func: JsFunctionNode) -> set[str]:
        """
        The names *func*'s body reads that resolve, from *scope* outward, to something a call to
        *func* can be evaluated with: a function already proven pure, or a binding that holds a
        constant (`binding_constant`) no write inside *func* establishes. A nearer binding wins: a
        name rebound below the scope that holds the pure function or the constant — a parameter or a
        local — shadows it and is not known, matching how the name resolves inside the body being
        analyzed. Only the names the body reads are asked about: the question is asked for every
        function on every round of the purity fixpoint, and a scope may hold thousands of names that
        no body reads. Whether the constant is in place when a call runs is asked for each call,
        through the callback of the interpreter `interpreter_at` builds.
        """
        effects = self.effects
        body = func.body
        if body is None:
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
            if function is not None and id(function) in self._pure:
                names.add(name)
                continue
            if not self.binding_constant(binding)[0]:
                continue
            sites = model.binding_establishment_sites(binding)
            if sites is None or any(site is func or site.is_descendant_of(func) for site in sites):
                continue
            names.add(name)
        return names

    def binding_constant(self, binding: Binding) -> tuple[bool, Value]:
        """
        The constant *binding* holds once established, as
        `refinery.lib.scripts.js.deobfuscation.helpers.binding_constant` answers it for a value the
        text spells; where its one value is a method chain, the value the fold of that chain
        computes where it stands (`method_chain_value`), which the text need not be able to hold:
        a table of more strings than a fold may write, split from one string, is read without being
        written out. Asked once per binding for the admission's lifetime; a binding whose chain
        reads it back is no constant.
        """
        cached = self._constants.get(binding)
        if cached is None:
            self._constants[binding] = (False, None)
            cached = binding_constant(self.effects, binding)
            if not cached[0]:
                chain = strip_parens(self.effects.model.singular_value(binding))
                if isinstance(chain, JsCallExpression):
                    known, value = self.method_chain_value(chain)
                    if known:
                        cached = held_constant(self.effects, binding, value)
            self._constants[binding] = cached
        return cached

    def method_chain_value(self, call: JsCallExpression) -> tuple[bool, Value]:
        """
        The value *call*, a method call, computes where it stands, as `(True, value)`, or
        `(False, None)`: the shared gate admits it with the trust at *call*
        (`refinery.lib.scripts.js.analysis.effects.EffectModel.call_is_foldable`) and the
        interpreter every fold runs in (`interpreter_at`) computes it. A JavaScript exception the
        call raises is the program's business and no value. A value computed is kept for the
        admission's lifetime: the chain a binding is given is asked for again where the fold of
        every call reaches it.
        """
        if not self.holds(call) or not isinstance(strip_parens(call.callee), JsMemberExpression):
            return False, None
        if (kept := self._chains.get(id(call))) is not None and kept[0] is call:
            return True, kept[1]
        if not self.effects.call_is_foldable(call, trust=self.trust_at(call)):
            return False, None
        try:
            value = self.interpreter_at(call).eval_expression(call)
        except (InterpreterError, IrreducibleExpression, _ThrowSignal):
            return False, None
        self._chains[id(call)] = call, value
        return True, value

    def constant_at(self, binding: Binding | None, call: JsCallExpression) -> tuple[bool, Value]:
        """
        The constant *binding* holds while *call* runs, as `(True, value)`, or `(False, None)`: the
        binding must hold a constant (`binding_constant`) that is in place before *call* runs. This
        is the question the interpreter asks through its *constant* callback for a free name the
        folded body reads, and the one a constant argument of *call* is resolved by.
        """
        if binding is None:
            return False, None
        known, value = self.binding_constant(binding)
        if not known:
            return False, None
        if not self.holds(call) or not self.cache.dominance.binding_established_before(binding, call):
            return False, None
        return True, value

    def interpreter_at(self, call: JsCallExpression) -> JsInterpreter:
        """
        The interpreter every fold of *call* runs in. It is anchored at *call* and handed the
        tampering oracle, so the trust questions its arms ask are answered for the moment this call
        runs rather than the whole program — the decoder a file carries before the call it blocks
        still refuses it, the one guaranteed to run after does not. It asks this admission whether
        the name it resolves a function through holds it (`binding_established_before`) at the
        point it names, and knows a name declared outside the function it runs only as the constant
        `constant_at` finds that name holding when *call* runs.
        """
        return JsInterpreter(
            effects=self.effects,
            anchor=call,
            tampering=self.cache.tampering if self.holds(call) else None,
            established=self.binding_established_before,
            constant=lambda binding: self.constant_at(binding, call),
        )

    def callee_established_before(self, call: JsCallExpression) -> bool:
        """
        Whether the name *call* reads its callee through holds the function before *call* runs. A
        function declaration is hoisted, so it is in place from the start of its scope, but the copy
        Annex B makes of one declared in a block only once the declaration has run; a declarator
        initializer (`const`/`let`/`var f = function(){}`) is in place only once its declarator has
        run, and a lone assignment (`f = function(){}`, the form namespace flattening leaves) only
        once that assignment has run. A premature call reads a value that is absent — a temporal
        dead zone `ReferenceError`, or the hoisted `undefined` a `var` call throws a `TypeError` on
        — which the interpreted body must not silently replace with a result.
        """
        return self.cache.dominance.callee_established_before(call)

    def binding_established_before(self, binding: Binding, reference: Node) -> bool:
        """
        Whether the one value *binding* holds is in place before *reference* runs.
        """
        return self.cache.dominance.binding_established_before(binding, reference)
