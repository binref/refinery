"""
The handler table of the emulator: one handler per macro command the interpreter answers, drawn
from the per-category registries, with the guarantee that every name it holds is a command the
registry knows, and the table of the commands an expression reads by a handler of its own.
"""
from __future__ import annotations

from refinery.lib.scripts.xlm.commands import XLM_COMMANDS
from refinery.lib.scripts.xlm.handlers.control import CONTROL_HANDLERS, EXPRESSION_HANDLERS
from refinery.lib.scripts.xlm.handlers.functions import FUNCTION_HANDLERS
from refinery.lib.scripts.xlm.handlers.lookups import LOOKUP_HANDLERS
from refinery.lib.scripts.xlm.handlers.mutate import MUTATION_HANDLERS
from refinery.lib.scripts.xlm.handlers.strings import STRING_HANDLERS
from refinery.lib.scripts.xlm.handlers.system import SYSTEM_HANDLERS

HANDLERS = {
    **CONTROL_HANDLERS,
    **FUNCTION_HANDLERS,
    **STRING_HANDLERS,
    **LOOKUP_HANDLERS,
    **MUTATION_HANDLERS,
    **SYSTEM_HANDLERS,
}

_UNREGISTERED = (set(HANDLERS) | set(EXPRESSION_HANDLERS)) - set(XLM_COMMANDS)
assert not _UNREGISTERED, F'handlers without a command registry entry: {sorted(_UNREGISTERED)}'
