"""
A per-run cache of the AutoIt3 analysis models. The deobfuscation pipeline builds one cache over
the script being transformed and shares it across every transform in a run, rebuilding the models
only after that script's tree changes — whether a transform announces the change through
`refinery.lib.scripts.Transformer.changed` or an in-pass mutation advances the script's
`refinery.lib.scripts.tree_version` counter. The version tracking, invalidation, and
transformer-reuse mechanism live in `refinery.lib.scripts.modelcache.ModelCacheBase`; this module
declares the model slots, their build wiring, and the facts composed over several of them.
"""
from __future__ import annotations

from collections.abc import Mapping

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.aliases import Au3AliasModel, build_alias_model
from refinery.lib.scripts.au3.analysis.existence import (
    Au3ExistenceModel,
    Au3ProbeMemo,
    build_existence_model,
    call_target,
    parse_payload,
)
from refinery.lib.scripts.au3.analysis.usage import (
    Au3UsageModel,
    ERROR_MACROS,
    build_usage_model,
    callee_census,
)
from refinery.lib.scripts.au3.analysis.propagation import (
    Au3PropagationModel,
    build_propagation_model,
)
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel, build_scope_model
from refinery.lib.scripts.au3.analysis.values import Kind, literal_value, to_string
from refinery.lib.scripts.au3.model import (
    Au3Call,
    Au3Directive,
    Au3EnumDeclaration,
    Au3FunctionDeclaration,
    Au3Macro,
    Au3MemberAccess,
    Au3Script,
    Au3StringLiteral,
    Au3VariableDeclaration,
    Expression,
)
from refinery.lib.scripts.modelcache import ModelCacheBase


class Au3ModelCache(ModelCacheBase):
    """
    Lazily builds and memoizes the analysis models for one root script — the scope model the
    transforms ask which storage a write targets and which names are constant, the existence
    census the summary refinement leans on, the alias map the indirection rewrite reads, the
    propagation model the constant substitution reads, and the usage model the dead-code
    elimination reads — each dropped, together, whenever this root's tree changes. The probes
    the census makes are remembered for the whole run instead: their answers depend on what each
    probe reads, not on the tree version. Beside the models, the cache owns the facts composed
    over several of them — `entry_is_open`, whether the script runs from its own top-level
    statements rather than from outside the tree, and `may_read_error_state`, whether the script
    may read the interpreter's `@error` or `@extended` at run time.
    """

    _SLOTS = (
        '_scopes',
        '_existence',
        '_aliases',
        '_propagation',
        '_usage',
    )

    root: Au3Script
    _scopes: Au3ScopeModel | None
    _existence: Au3ExistenceModel | None
    _aliases: Au3AliasModel | None
    _propagation: Au3PropagationModel | None
    _usage: Au3UsageModel | None

    def __init__(self, root: Node, options: object | None = None):
        super().__init__(root, options)
        self._probes = Au3ProbeMemo()

    @property
    def scopes(self) -> Au3ScopeModel:
        return self._lazy('_scopes', lambda: build_scope_model(self.root))

    @property
    def existence(self) -> Au3ExistenceModel:
        """
        The names a global may take when the root runs, and whether the tree may make every
        implicit write fatal by setting `MustDeclareVars`.
        """
        return self._lazy(
            '_existence',
            lambda: build_existence_model(self.root, self.scopes, self._probes),
        )

    @property
    def aliases(self) -> Au3AliasModel:
        """
        The per-scope map of variables that provably name one function, cut by every name a
        rebinding write — an `Assign`, a code-running `Execute`, or a script function call — may
        cost, which the propagation summaries feed.
        """
        return self._lazy('_aliases', lambda: build_alias_model(
            self.root, self.scopes, self.propagation.summaries))

    @property
    def propagation(self) -> Au3PropagationModel:
        """
        The value at every variable read and the may-write summary of every script function, over
        the scope model's binding answers.
        """
        return self._lazy(
            '_propagation',
            lambda: build_propagation_model(self.root, self.scopes, self.existence),
        )

    @property
    def usage(self) -> Au3UsageModel:
        """
        What the script does with its names — the call counts, purity, channels, spellings, and
        storage bindings the dead-code elimination asks — over the scope model's bindings and the
        propagation walk's may-write summaries.
        """
        return self._lazy('_usage', lambda: build_usage_model(
            self.root, self.scopes, self.propagation.summaries))

    @property
    def entry_is_open(self) -> bool:
        """
        Whether the root runs from its own top-level statements: it holds a statement that is
        neither a declaration, a function definition nor a directive, and no include — read from
        the scope model in both spellings the parser answers with, and from the unread text the
        usage model holds — because an included file's contents are called from outside the tree.
        """
        if self.scopes.holds_an_include:
            return False
        if self.usage.holds_unread_include():
            return False
        for statement in self.root.body:
            if not isinstance(statement, (
                Au3VariableDeclaration,
                Au3EnumDeclaration,
                Au3FunctionDeclaration,
                Au3Directive,
            )):
                return True
        return False

    @property
    def may_read_error_state(self) -> bool:
        """
        Whether the script may read the interpreter's `@error` or `@extended` at run time: a read
        of either macro anywhere in the tree, a callee computed at run time — which may name
        `Execute` over a payload no walk reads — an include, whose contents no fact of the tree
        holds, or an `Execute` the tree spells, in text the parser could not read included, whose
        payload is not provably free of such a read. Entering a user function clears both (probe9
        A17/A17b), so a pass that replaces a call with its value drops a write a later read may
        observe.
        """
        census = callee_census(self.root, self.usage.functions, self.usage.unparsed)
        if census.reads_error_macros or census.computed_callee:
            return True
        if self.scopes.holds_an_include or self.usage.holds_unread_include():
            return True
        if any(
            'execute' in facts.identifiers
            for facts in self.usage.unparsed.values()
        ):
            return True
        return any(
            isinstance(node, Au3Call)
            and _call_may_read_error_state(node, self.usage.functions)
            for node in self.root.walk()
        )


def _call_may_read_error_state(
    call: Au3Call,
    functions: Mapping[str, Au3FunctionDeclaration],
) -> bool:
    """
    Whether *call* may read `@error` or `@extended` through a payload it dispatches: a callee
    computed at run time may name `Execute`, and an `Execute`, or a `Call` over the name, runs the
    payload its argument spells — a `Call` whose name folds to a literal is read for the callee
    `call_target` resolves the name to, and one whose name does not fold, or whose resolution
    refuses, may dispatch anything. A call to a script function reads nothing this walk has to
    find: its body stands in the tree, where the census reads it.
    """
    callee = ast.direct_callee(call)
    if callee is None:
        return not isinstance(ast.unwrap_parens(call.callee), Au3MemberAccess)
    if callee.name in functions:
        return False
    if callee.name == 'execute':
        if len(call.arguments) != 1:
            return True
        return not _payload_free_of_error_state(call.arguments[0], functions)
    if callee.name == 'call':
        function_names = frozenset(functions)
        name = literal_value(
            call.arguments[0] if call.arguments else None,
            function_names,
        )
        spelling = None if name is None or name.kind is not Kind.STRING else to_string(name)
        if spelling is None:
            return True
        target = call_target(spelling, call.arguments[1:], function_names)
        if target is None:
            return True
        if target != 'execute':
            return False
        return not _payload_free_of_error_state(
            call.arguments[1] if len(call.arguments) > 1 else None,
            functions,
        )
    return False


def _payload_free_of_error_state(
    argument: Expression | None,
    functions: Mapping[str, Au3FunctionDeclaration],
) -> bool:
    """
    Whether an `Execute` payload provably reads neither `@error` nor `@extended`: a string
    literal that parses to an expression free of both, where every dispatch the parse holds —
    an `Execute`, or a `Call` over the name, inside the payload — hands its own literal to the
    same question, so a payload that runs a payload may read through the one inside. Any other
    shape may read either: an unparseable payload is still code AutoIt may run, this parser's
    refusal is not AutoIt's. An empty payload answers `""` at run time and reads nothing.
    """
    literal = ast.unwrap_parens(argument) if argument is not None else None
    if not isinstance(literal, Au3StringLiteral):
        return False
    expression = parse_payload(literal.value)
    if expression is None:
        return not literal.value.strip()
    for node in expression.walk():
        if isinstance(node, Au3Macro) and node.name in ERROR_MACROS:
            return False
        if isinstance(node, Au3Call) and _call_may_read_error_state(node, functions):
            return False
    return True


def model_cache(transformer: Transformer, root: Node) -> Au3ModelCache:
    """
    The pipeline's shared `Au3ModelCache` for *root* when one is attached to *transformer* and
    built over that same root, otherwise a fresh cache stashed back onto *transformer* for reuse
    within its single-pass lifetime. See
    `refinery.lib.scripts.modelcache.ModelCacheBase.for_transformer`.
    """
    return Au3ModelCache.for_transformer(transformer, root)
