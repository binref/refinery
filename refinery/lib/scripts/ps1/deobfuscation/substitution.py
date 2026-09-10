"""
The single route by which a PowerShell cleanup pass puts one part of the tree in another's place.

`refinery.lib.scripts.ps1.deobfuscation.removal` owns the other half of the same question: what a
pass takes *out* of a statement list. Both routes exist so the rule about what a rewrite must not
throw away — a redirection that would be dropped — lives in one place rather than at every site that
could break it.

The entry points are named for the slot the node sits in — a direct field, one entry of a child
list, the whole of one — rather than for the passes that reach them, because the slot is the only
thing they differ in. `substituted` is named for none of them: a pass that decides by returning a
replacement from `visit_X` never touches a slot, because
`refinery.lib.scripts.Transformer.generic_visit` installs the answer for it, so what it asks for is
a verdict rather than an edit. `substitute_statement` is the exception in that it edits nothing
itself: a statement list is a body, a body is edited as a batch, and
`refinery.lib.scripts.ps1.deobfuscation.removal.Ps1RemovalPlan` is that batch. It is here so that a
pass substituting inside a body has an owner to ask rather than a `refinery.lib.scripts.BodyEdit` to
build, and it refuses an empty replacement: whether a statement may go is the other module's
question, and answering it here would be a route around every guard that module holds.

The two owners divide by what the pass is claiming, and the division is what makes the rule below
sound. A substitution claims the value is unchanged, so everything the original did still has to
happen. A removal claims the code does not run at all — `Ps1DeadCodeElimination` resolving a
constant `if` deletes the branch that was never taken, redirections and all — and that claim is
`refinery.lib.scripts.ps1.deobfuscation.removal.Ps1RemovalPlan`'s to check. One rule over both would
refuse the second for no reason.
"""
from __future__ import annotations

from collections.abc import Iterable

from refinery.lib.scripts import (
    Node,
    Statement,
    _replace_in_parent,
    reattach,
    set_child,
    set_child_list,
)
from refinery.lib.scripts.ps1.deobfuscation.removal import Ps1RemovalPlan

#: What every entry point below accepts on either side of a substitution: a node, nothing, or a
#: list of either. A pass that splits one statement into several has a list on one side and a single
#: node on the other, and nothing about the rule changes between the two.
Part = Node | None | Iterable['Part']


def _nodes(part: Part) -> Iterable[Node]:
    """
    Every node `part` holds, however deeply it is wrapped.

    The unwrapping follows `Part` rather than the list and tuple two callers happen to pass:
    a shape this did not unwrap yields nothing, and nothing on the `removed` side of
    `may_substitute` is a redirection-free original — the one answer this module must never give by
    accident.
    """
    if isinstance(part, Node):
        yield part
    elif isinstance(part, Iterable) and not isinstance(part, (str, bytes)):
        for item in part:
            yield from _nodes(item)


def carried_redirections(*parts: Part) -> list:
    """
    Every redirection written anywhere in the subtrees at `parts`.

    The whole subtree is read and not the nodes themselves, because the carrier is rarely the node a
    pass is holding: `iex 'x' > C:\\o.txt` writes the redirection on the invocation, and a pass
    replacing the expression statement around it is handed a node whose own list is empty. The list
    is read by name rather than matched against the model types known to carry one, so a carrier
    added later is covered without being enumerated here — and the failure of the alternative is
    asymmetric, since a carrier this did not recognize reads as nothing being lost.
    """
    found = []
    for part in parts:
        for node in _nodes(part):
            for descendant in node.walk():
                found.extend(getattr(descendant, 'redirections', None) or ())
    return found


def may_substitute(removed: Part, installed: Part, moved: Part = ()) -> bool:
    """
    Whether `installed` may take the place of `removed` without losing what the original wrote.

    A replacement expression carries no redirections, so folding `f > C:\\log` into the value `f`
    returns puts that value on the console and leaves the file uncreated — PowerShell opens the
    target as it sets the redirection up, so even a command that writes nothing touches the file.
    Every spelling is refused, including merges like `f 2>&1` that neither move output nor open a
    file, because nothing here can know the replacement reproduces them. Survival is decided by node
    identity, not equality: a rebuilt redirection is refused though it wrote the same thing, the
    conservative direction.

    `moved` names nodes the caller lifts out of `removed` and re-installs elsewhere in the same edit
    — `Ps1ExpandableStringHoist` hoists an assignment carrying a redirection out of a string — so a
    redirection that leaves and returns is not counted lost. Nothing checks the claim; the caller
    owes it, the way `refinery.lib.scripts.ps1.deobfuscation.removal.Ps1RemovalPlans.propose_in`
    owes the list it names.
    """
    lost = carried_redirections(removed)
    if not lost:
        return True
    kept = {id(redirection) for redirection in carried_redirections(installed, moved)}
    return all(id(redirection) in kept for redirection in lost)


def _release(part: Part) -> bool:
    """
    Put everything `part` holds back in order and report the refusal.

    Building a replacement adopts the parts of the original it reuses, so a rejected one leaves
    those parts standing in the tree while naming a holder that does not hold them, and everything
    that reads upward from inside one then walks out of the tree.
    `refinery.lib.scripts.ps1.deobfuscation.removal.Ps1RemovalPlan.propose` makes the same repair
    for the same reason.
    """
    for node in _nodes(part):
        reattach(node)
    return False


def substituted(old: Node, new: Node | None, moved: Part = ()) -> Node | None:
    """
    The replacement a `visit_X` method may return for `old`, or `None` to leave it standing.

    This is the route with no slot to edit: `refinery.lib.scripts.Transformer.generic_visit`
    installs whatever a `visit_X` returns, so by the time the node reaches a slot the pass has
    already decided, and a pass that keeps bookkeeping on the way cannot express the refusal as an
    early return. Asking here is the same rule the other entry points hold, answered one step
    earlier.

    A refused replacement is released for the reason `_release` gives: building it adopted the parts
    of `old` it reuses, and those parts are still standing in the tree.
    """
    if new is None:
        return None
    if not may_substitute(old, new, moved):
        _release(old)
        return None
    return new


def substitute(old: Node, new: Node, moved: Part = ()) -> bool:
    """
    Put `new` where `old` stands, reporting whether it landed. Refused when the swap would lose a
    redirection; see `may_substitute`, whose `moved` argument this forwards.

    `old` may sit in a direct field, in a child list, or in a tuple inside one, and the search is
    the same one a removal makes, so a pass that found its node by walking the tree does not have to
    know which of the three it is looking at.

    A slot that is not found is a refusal like any other, and it is released the same way: the
    caller has built `new` over parts of `old` either way, and reporting the two the same while
    repairing only one leaves the caller no way to tell which it got.
    """
    if not may_substitute(old, new, moved):
        return _release(old)
    if not _replace_in_parent(old, new):
        return _release(old)
    return True


def substitute_field(parent: Node, attr: str, new: Node | None) -> bool:
    """
    Put `new` in the single-node field `parent.<attr>`, reporting whether it landed.

    A `None` clears the field, which is how a pass drops an optional sub-node: a loop's condition
    that has been proved constant, or the expression of a statement whose work has been folded into
    a neighbour. Clearing is where the rule earns its keep here — what leaves is everything the
    field held and what arrives is nothing at all.
    """
    old = getattr(parent, attr, None)
    if not may_substitute(old, new):
        return _release(old)
    set_child(parent, attr, new)
    return True


def substitute_list(parent: Node, attr: str, items: list) -> bool:
    """
    Replace the contents of the child list `parent.<attr>` with `items`, reporting whether they
    landed.

    The new contents are given whole rather than as a diff, so a reordering and a wholesale rewrite
    arrive here in the same shape, and what either of them takes out of the tree is read off the two
    lists rather than taken from the caller's account of it.
    """
    old = list(getattr(parent, attr, None) or [])
    if not may_substitute(old, items):
        return _release(old)
    set_child_list(parent, attr, items)
    return True


def substitute_statement(
    container: Node,
    statement: Statement,
    replacement: list[Statement],
    moved: Part = (),
) -> bool:
    """
    Put `replacement` where `statement` stands in `container.body`, reporting whether the body
    moved.

    `replacement` has to hold something. A pass that wants the statement gone opens a
    `refinery.lib.scripts.ps1.deobfuscation.removal.Ps1RemovalPlan` itself, because the guards that
    decide whether a statement may go belong to that class, and every one of them would be skipped
    by a caller that spelled its removal as a substitution with nothing on the other side.

    The rule is asked of the statement against the whole replacement list and not against any one
    entry of it, because a pass that splits one statement into several routinely puts the redirected
    part in a different entry than the value.
    """
    if not replacement:
        raise ValueError('an empty replacement is a removal; open a Ps1RemovalPlan for it')
    if not may_substitute(statement, replacement, moved):
        return _release(statement)
    plan = Ps1RemovalPlan(container, faults=None)
    plan.propose(statement, replacement)
    return plan.commit()
