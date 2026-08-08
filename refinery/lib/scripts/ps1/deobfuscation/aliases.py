"""
The one pass that rewrites a command name to the command it denotes, and then deletes the alias
definitions nothing needs any more.

Command identity — which command a name runs, following aliases, honoring the precedence that makes a
default alias beat a script function, and refusing a name that denotes nothing or cannot be resolved —
is answered once by `refinery.lib.scripts.ps1.analysis.commands.Ps1CommandModel`. This pass reads that
answer and does the rewrite; it holds none of the relation itself. Two passes used to split it, one
resolving script `Set-Alias` definitions and the other the built-in alias and cmdlet tables, and they
could disagree about the same name; now there is a single rewriter and a single model behind it.

A name is rewritten only when the model resolves it to a concrete command:

- an alias (`CommandKind.ALIAS`) is replaced by the command it resolves to, whether it was defined by
  a script `Set-Alias` or is one of the built-in aliases;
- a cmdlet (`CommandKind.CMDLET`) is rewritten to its canonical spelling, which normalizes casing.

Everything else is left exactly as written, which is always meaning-preserving: a name the model
reports as denoting nothing (an alias cycle, a wildcard target, a use its definition does not reach)
or as unknown (a computed name, a `Set-Alias` colliding with a built-in, a `-Force`/`-Option`
rebind) runs the same in the emitted script as in the input, because the surrounding definitions come
along unchanged.

**The definitions go once nothing needs them.** A surviving `Set-Alias` keeps the type world open and
costs script-wide junk removal, and an obfuscated loader puts one first, so deleting it is what makes
the rest of the script readable. The removal is a batch: either every alias definition in the script
goes or none does, because a definition that stays keeps the world open and would make the others'
removal pointless, and because two definitions of the same name decide each other's meaning.

The batch is taken only when all of the following hold. Each is a question about the language, so
each is asked of a model; what this pass owns is which questions and the conjunction.

1. **Nothing denotes through it.** No invocation left in the tree implicates the definition —
   `Ps1CommandModel.implicated_definitions`. This is asked after the rewrite has run to fixpoint, so
   a use that still implicates one is a use the model refused to resolve.
2. **It only binds.** `Ps1CommandModel.binding_only_definition` — the statement's whole effect is
   that the name becomes bound.
3. **No mention of the name survives.** The rewrite reaches uses, not mentions, and
   `Ps1CommandModel.introspected_names` reports the names the script reads back out of the alias
   table. A reader this cannot enumerate reports every name and stops the batch.
4. **Nothing can see the table from outside.** The world must be closed but for the alias bindings
   themselves (`Ps1TypeWorld.closed_but_for_alias_bindings`), no surviving invocation may do
   anything to the world (`Ps1CommandModel.world_role`) except be one of these definitions, no name
   may be exported (`Ps1CallGraph.exports_a_name`), and every alias definition in the tree must be
   one this batch is taking — a definition the model could not read is one this pass cannot account
   for, and it would keep the world open anyway.
5. **The engine state is not read back.** A `Set-Alias` that succeeds sets `$?`, so removing one lets
   an earlier failure through to a later read of it (`Ps1CommandModel.reads_command_success`). This
   is a refusal rather than a fix: every statement remover in this package has the same exposure, and
   the general answer belongs beside removal rather than here.

All five are asked of the script as a whole and answered about what *it* can see. A caller that
dot-sources this script gets its aliases in its own scope, and can therefore tell that a definition
is gone however thoroughly nothing inside the script could — the same assumption
`refinery.lib.scripts.ps1.analysis.callgraph.Ps1CallGraph.is_readable` makes about a module's
exports, named here because the conditions above would otherwise read as covering it.
"""
from __future__ import annotations

from typing import Sequence

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache, model_cache
from refinery.lib.scripts.ps1.analysis.commands import AliasDefinition, CommandKind
from refinery.lib.scripts.ps1.analysis.world import WorldRole
from refinery.lib.scripts.ps1.ast import standalone_command_statement
from refinery.lib.scripts.ps1.deobfuscation.helpers import set_command_name
from refinery.lib.scripts.ps1.deobfuscation.removal import Ps1RemovalPlans
from refinery.lib.scripts.ps1.deobfuscation.substitution import carried_redirections
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation, Ps1Script


class Ps1AliasInlining(Transformer):
    """
    Rewrite each command name to the command it denotes, as answered by
    `refinery.lib.scripts.ps1.analysis.commands.Ps1CommandModel`, and delete the alias definitions
    that answer is no longer reached through.
    """

    def visit(self, node: Node):
        if not isinstance(node, Ps1Script):
            return None
        if self._rewrite_names(node):
            self.mark_changed()
            return None
        if self._remove_definitions(node):
            self.mark_changed()
        return None

    def _rewrite_names(self, root: Ps1Script) -> bool:
        commands = model_cache(self, root).commands
        rewritten = False
        for invocation in list(root.walk()):
            if not isinstance(invocation, Ps1CommandInvocation):
                continue
            if invocation.name is None:
                continue
            denotation = commands.denotation(invocation)
            if denotation.target is None:
                continue
            if denotation.kind not in (CommandKind.ALIAS, CommandKind.CMDLET):
                continue
            rewritten = set_command_name(invocation, denotation.target) or rewritten
        return rewritten

    def _remove_definitions(self, root: Ps1Script) -> bool:
        """
        Delete every alias definition, or none. The rewrite has settled by the time this runs, so
        every model here is read over the tree the emitted script will be.
        """
        cache = model_cache(self, root)
        definitions = list(cache.commands.every_alias_definition())
        if not definitions or not self._nothing_watches_the_table(root, cache, definitions):
            return False
        introspected = cache.commands.introspected_names()
        if introspected is None:
            return False
        needed = self._implicated_anywhere(root, cache)
        for definition in definitions:
            if id(definition.node) in needed or definition.name in introspected:
                return False
            if not cache.commands.binding_only_definition(definition):
                return False
        plans = Ps1RemovalPlans()
        for definition in definitions:
            statement = standalone_command_statement(definition.node)
            if statement is None or carried_redirections(statement) or not plans.propose(statement):
                plans.abandon()
                return False
        if len(plans.accepted) != len(definitions):
            plans.abandon()
            return False
        return plans.commit()

    @staticmethod
    def _implicated_anywhere(root: Ps1Script, cache: Ps1ModelCache) -> set[int]:
        """
        Every definition some invocation's denotation still depends on, by node identity — gate 1 of
        the module documentation, answered for the whole script in one walk because the question is
        asked of every definition and the answer is the same walk each time.
        """
        return {
            id(definition.node)
            for invocation in root.walk()
            if isinstance(invocation, Ps1CommandInvocation)
            for definition in cache.commands.implicated_definitions(invocation)
        }

    def _nothing_watches_the_table(
        self,
        root: Ps1Script,
        cache: Ps1ModelCache,
        definitions: Sequence[AliasDefinition],
    ) -> bool:
        """
        Whether the alias table is visible only to the script as written — gates 4 and 5.

        The invocation scan is what the world model cannot do: it reads a name one hop through the
        built-in alias table, so a leak the script reaches through its own alias is invisible there
        and `Ps1CommandModel.world_role` is where that is answered. An invocation whose role is
        `IDENTITY` is allowed exactly when it is one of the definitions being taken, which is also
        the check that catches a defining command this pass never recognized as one.

        The batch arrives here rather than being asked for again, so the set the `IDENTITY`
        exemption is granted from is the same one the caller vetoes over. The gates are asked in
        order of what they cost: the two whole-tree walks come after the verdicts the models already
        hold, since a script with any other opener refuses without either of them being run.
        """
        if not cache.closed_world.closed_but_for_alias_bindings:
            return False
        if cache.call_graph.exports_a_name:
            return False
        if cache.commands.reads_command_success():
            return False
        taken = {id(definition.node) for definition in definitions}
        for invocation in root.walk():
            if not isinstance(invocation, Ps1CommandInvocation):
                continue
            role = cache.commands.world_role(invocation)
            if role is WorldRole.NONE:
                continue
            if role is WorldRole.IDENTITY and id(invocation) in taken:
                continue
            return False
        return True
