"""
The environment drive as a storage of its own, which every layer that reasons about an `$env:` name
reads.

A store to the drive is not a store of the value written: the drive converts what it is handed to
the text it holds, and what that text is can depend on the host. This module owns the conversion and
the question of which values settle to one text on every host, so that the value layer and the type
layer refuse the same stores by construction rather than by coincidence — a layer that answered a
double's type where the value layer refused its text would fold a read the other had kept.
"""
from __future__ import annotations

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.dataflow import Ps1VariableFlow
from refinery.lib.scripts.ps1.analysis.values import (
    UNKNOWN,
    Ps1Constant,
    convert,
    read,
    render,
    resolve_expression_type,
)
from refinery.lib.scripts.ps1.data import named_type
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName
from refinery.lib.scripts.ps1.model import Expression, Ps1ScopeModifier, Ps1Variable

#: The type every value an `$env:` store is converted to on its way in, which is the string the
#: drive holds and nothing else.
ENV_DRIVE_TYPE = named_type('System.String')

#: The types whose conversion to text is the same on every host: a string is itself, a char and a
#: boolean have one spelling each, and the integer types are written in full digits. A double, a
#: single and a decimal do not — their text is the host's culture, so measured on one,
#: `$env:q = 5.5` reads back `'5.5'` where another writes `'5,5'` — and any other type is one this
#: refuses rather than guesses at.
_TEXT_SETTLES_EVERYWHERE = frozenset(
    named_type(F'System.{name}')
    for name in (
        'String',
        'Char',
        'Boolean',
        'SByte',
        'Byte',
        'Int16',
        'UInt16',
        'Int32',
        'UInt32',
        'Int64',
        'UInt64',
    )
)


def text_settles_everywhere(typed: Ps1TypeName | None) -> bool:
    """
    Whether a value of type *typed* becomes one text on every host, which is `False` as well where
    no type is named: a value whose type the domain cannot read is one whose text it cannot either.
    """
    return typed is not None and typed in _TEXT_SETTLES_EVERYWHERE


def as_the_env_drive_holds(value: Expression) -> Expression | None:
    """
    The literal an `$env:` store leaves behind, which is the string the drive converted the value
    to rather than the value itself: measured, `$env:q = 5` reads back `'5'` and `$env:q = $true`
    reads back `'True'`. A stored empty string removes the name rather than holding one, so a read
    after it observes `$null` — a removal this refuses to model rather than answer with the empty
    string the conversion computes. `None` as well where the conversion is not one the domain
    settles, which a collection never is: the string it becomes needs the session's `$OFS`. `None`
    as well where the value's type is one whose text depends on the host, which
    `text_settles_everywhere` refuses.
    """
    if not text_settles_everywhere(resolve_expression_type(value)):
        return None
    outcome = convert(read(value), ENV_DRIVE_TYPE)
    if outcome.may_throw or outcome.value is UNKNOWN:
        return None
    rendered = render(outcome.value)
    if rendered is None:
        return None
    fact = read(rendered)
    if isinstance(fact, Ps1Constant) and fact.type == ENV_DRIVE_TYPE and fact.payload == '':
        return None
    return rendered


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
