"""
The one pass that rewrites a command name to the command it denotes.

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

Alias definitions are left in place. A surviving `Set-Alias` keeps the type world open and costs
script-wide junk removal, so deleting a definition all of whose uses are resolved is worth doing — but
it is a name-keyed removal that has to clear the same reachability and export gates the function
evaluator's definition removal clears, and it is scheduled separately from this rewrite.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.ps1.analysis.cache import model_cache
from refinery.lib.scripts.ps1.analysis.commands import CommandKind
from refinery.lib.scripts.ps1.deobfuscation.helpers import set_command_name
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation, Ps1Script


class Ps1AliasInlining(Transformer):
    """
    Rewrite each command name to the command it denotes, as answered by
    `refinery.lib.scripts.ps1.analysis.commands.Ps1CommandModel`.
    """

    def visit(self, node: Node):
        if not isinstance(node, Ps1Script):
            return None
        commands = model_cache(self, node).commands
        for invocation in list(node.walk()):
            if not isinstance(invocation, Ps1CommandInvocation):
                continue
            if invocation.name is None:
                continue
            denotation = commands.denotation(invocation)
            if denotation.target is None:
                continue
            if denotation.kind not in (CommandKind.ALIAS, CommandKind.CMDLET):
                continue
            if set_command_name(invocation, denotation.target):
                self.mark_changed()
        return None
