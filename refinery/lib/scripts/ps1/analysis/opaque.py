"""
The writes no reading of one script attributes to a name.

Every layer above reasons about a name through its occurrences, so a write with no occurrence
anywhere is a write that layer folds straight across. There are two ways a script performs one, and
they arrive from opposite directions:

- it addresses the name as a *string* it computes, which
  `refinery.lib.scripts.ps1.analysis.naming` recognises — `Set-Variable $n 'v'`;
- it runs *code this analysis never sees* — `Invoke-Expression $c`, `. 'stage2.ps1'`, `. $sb` —
  which may write anything at all.

To a consumer they are one fact: at this point, some binding of this scope may have changed and
nothing says which. `writes_nobody_can_attribute` is that one question, and it is the only thing a
consumer should have to ask.

This says nothing about *when*: a read that reaches its write without passing the point observes
what it always would have. The fact is a property of the point, not of the enclosing scope — a
scope-level mark deadlocks, since marking a scope in doubt for an `Invoke-Expression` stops the
payload variable folding, so the call never becomes literal, never expands, and the mark never
lifts.

A spelling this does not resolve is not a call declared harmless; it is one whose effect is unknown,
so a miss here performs a corruption where a miss in a grant table such as
`refinery.lib.scripts.ps1.analysis.effects` merely withholds a rewrite. That is also why no
`refinery.lib.scripts.ps1.analysis.world.Ps1TypeWorld` is consulted: a script that shadows `iex`
runs something else, and something else is opaque too.

**Only the scope the code stands in.** Measured on 5.1 (`temp/ps1/census_measurements.md`): `&`
opens a child scope, so `& 'stage2.ps1'` and `& $sb` leave the caller's `$x` alone, and so does
`$ExecutionContext.InvokeCommand.InvokeScript('$x = 1')` — which runs in a scope of its own however
much it looks like `Invoke-Expression`. All three are deliberately absent. Two narrow holes are left
and both are measured rather than assumed: a *qualified* write from inside one of them, since
`& { $script:x = 1 }` does reach the caller, and the `useLocalScope = $false` overload
`InvokeScript($false, $sb, $null, $null)`, which reaches it as well. Each is recorded as a hole
rather than paid for by treating every call operator as a caller-scope write.
"""
from __future__ import annotations

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.naming import Ps1NameTarget, unreadable_name_target
from refinery.lib.scripts.ps1.ast import binds_parameter, resolve_command_name
from refinery.lib.scripts.ps1.model import (
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ScriptBlock,
)

#: Commands that run arbitrary code supplied as data, in the scope of whatever calls them. Resolved
#: through `refinery.lib.scripts.ps1.ast.resolve_command_name`, so `iex` arrives here canonical.
#:
#: `Start-Job` and `Start-ThreadJob` are absent although
#: `refinery.lib.scripts.ps1.analysis.world` counts them: they run their block in another runspace,
#: which has no access to these variables at all.
_UNREADABLE_CODE_COMMANDS = frozenset({
    'invoke-expression',
})

#: `Invoke-Command` runs its block in the caller's scope only when told to, so the switch is part of
#: what makes the call opaque. Without it the command opens a child scope; with it the block may be
#: an expression this analysis never reads — `Invoke-Command -NoNewScope -ScriptBlock $sb` — which
#: `refinery.lib.scripts.ps1.analysis.blocks` cannot place, since no block node stands there at all.
_NO_NEW_SCOPE_COMMANDS = frozenset({
    'invoke-command',
})


def writes_nobody_can_attribute(node: Node) -> bool:
    """
    Whether *node* performs a write no reading of the source attributes to a name, landing in the
    scope *node* stands in.

    The two sources are one fact to a consumer, so they are answered together: a command addressing
    a name it computes, and a call running code this analysis never sees.
    """
    if isinstance(node, Ps1CommandInvocation):
        if unreadable_name_target(node) is Ps1NameTarget.LOCAL:
            return True
    return runs_unreadable_code(node)


def runs_unreadable_code(node: Node) -> bool:
    """
    Whether *node* runs code this analysis never sees, in the scope *node* stands in.

    A dot-invocation of anything but an inline block is one, and the target is not what decides it:
    `. 'stage2.ps1'` runs a file, `. $sb` runs whatever the expression yields, and `. f` runs a
    function's body *in the caller's scope* rather than the child scope an ordinary call opens — all
    three measured — so even a function this tree defines writes somewhere no call graph here
    accounts for. Only `. { … }` is exempt, because its body is written where it runs and every
    layer already reads it.

    `.\\tool.exe` is not a dot-invocation at all. The dot there opens a relative path and the command
    runs as any other external program does, in a scope of its own; PowerShell dot-sources only when
    the operator stands apart from its target. The parser carries that distinction, giving a path no
    invocation operator at all.
    """
    if not isinstance(node, Ps1CommandInvocation):
        return False
    command = resolve_command_name(node)
    if command in _UNREADABLE_CODE_COMMANDS:
        return True
    if command in _NO_NEW_SCOPE_COMMANDS and _binds_switch(node, 'nonewscope'):
        return True
    return (
        node.invocation_operator == '.'
        and node.name is not None
        and not isinstance(node.name, Ps1ScriptBlock)
    )


def _binds_switch(node: Ps1CommandInvocation, parameter: str) -> bool:
    """
    Whether *node* is written with a switch that binds *parameter*, given in full, lowercased and
    without its dash. PowerShell binds any unambiguous abbreviation, which
    `refinery.lib.scripts.ps1.ast.binds_parameter` is the rule for.
    """
    for argument in node.arguments:
        if not isinstance(argument, Ps1CommandArgument):
            continue
        if argument.kind is not Ps1CommandArgumentKind.SWITCH:
            continue
        if binds_parameter(argument.name, parameter):
            return True
    return False
