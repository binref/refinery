"""
The environment drive as a storage of its own, which every layer that reasons about an `$env:` name
reads.

A store to the drive is not a store of the value written: the drive converts what it is handed to
the text it holds, and what that text is can depend on the host. Which values settle to one text
on every host is `refinery.lib.scripts.ps1.analysis.values.invariant_text`'s question, measured and
answered there — the value layer and the type layer both read the drive's conversion through
`as_the_env_drive_holds`, so the two refuse the same stores by construction rather than by
coincidence, and a layer that answered a double's type where the value layer refused its text
cannot fold a read the other kept. What this module owns beyond that conversion is the shape of a
read the preserving model keeps, asked of a read spelled `$env:` or of the name alone.
"""
from __future__ import annotations

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.dataflow import Ps1VariableFlow
from refinery.lib.scripts.ps1.analysis.model import Ps1SemanticModel
from refinery.lib.scripts.ps1.analysis.values import invariant_text, make_string_literal, read
from refinery.lib.scripts.ps1.data import named_type
from refinery.lib.scripts.ps1.model import Expression, Ps1ScopeModifier, Ps1Variable
from refinery.lib.scripts.ps1.options import environment_is_preserved

#: The type every value an `$env:` store is converted to on its way in, which is the string the
#: drive holds and nothing else.
ENV_DRIVE_TYPE = named_type('System.String')


def as_the_env_drive_holds(value: Expression) -> Expression | None:
    """
    The literal an `$env:` store leaves behind, which is the string the drive converted the value
    to rather than the value itself: measured, `$env:q = 5` reads back `'5'` and `$env:q = $true`
    reads back `'True'`. A stored empty string removes the name rather than holding one, so a read
    after it observes `$null` — a removal this refuses to model rather than answer with the empty
    string the conversion computes. `None` as well where the conversion is not one the domain
    settles, which a collection never is: the string it becomes needs the session's `$OFS`, and so
    does any value whose text the host's culture renders — `invariant_text` is the one measured
    answer to that question, and it is where this asks.
    """
    held = invariant_text(read(value))
    if held is None or held == '':
        return None
    return make_string_literal(held)


def stores_the_environment_name(name: str, semantic: Ps1SemanticModel) -> bool:
    """
    Whether the script stores the environment variable *name*, which is the question a read
    spelled some other way than `$env:` has to ask before it may fold to what the engine gave the
    name: the `$env:` spelling answers it by looking at the occurrence, and this answers it by the
    name. An `$env:` occurrence and a command that addresses the name as a string both count, and
    both land on the one process-wide binding the drive holds, at the script scope.
    """
    binding = semantic.root_scope.bindings.get(F'env:{name.lower()}')
    return binding is not None and bool(binding.writes)


def reads_a_stored_environment_name(node: Node, flow: Ps1VariableFlow) -> bool:
    """
    Whether *node* reads an `$env:` name the script stores somewhere. That is the shape the
    preserving model keeps a read for: the environment is then the script's interface, and a
    spelling this model does not read — a `Set-Content` onto the drive, a .NET method — may have
    rewritten the name between the store and the read. A name the script never stores is not that
    shape, so a read of one still folds to the default the engine gave it.
    """
    for occurrence in node.walk():
        if not isinstance(occurrence, Ps1Variable):
            continue
        if occurrence.scope is not Ps1ScopeModifier.ENV:
            continue
        binding = flow.semantic.binding_of(occurrence)
        if binding is not None and binding.writes:
            return True
    return False


def takes_a_read_the_environment_owns(
    node: Node,
    flow: Ps1VariableFlow | None,
    options: object | None,
) -> bool:
    """
    Whether replacing *node* wholesale takes a read of an `$env:` name the script stores with it,
    which is the question a fold that answers something off an expression it replaces has to
    refuse on: under the preserving model the environment is the script's interface, and a
    spelling this analysis does not read — a `Set-Content` onto the drive, a .NET method — may
    have rewritten the name between the store and the read. `False` as well where no flow is at
    hand or the model is the folding one, which owes no read its name.
    """
    if flow is None or not environment_is_preserved(options):
        return False
    return reads_a_stored_environment_name(node, flow)
