"""
The handler table of the emulator: one handler per macro command the interpreter answers, drawn
from the per-category registries, with the guarantee that every name it holds is a command the
registry knows.
"""
from __future__ import annotations

from refinery.lib.scripts.xlm.commands import XLM_COMMANDS
from refinery.lib.scripts.xlm.handlers.control import CONTROL_HANDLERS
from refinery.lib.scripts.xlm.handlers.functions import FUNCTION_HANDLERS
from refinery.lib.scripts.xlm.handlers.lookups import LOOKUP_HANDLERS
from refinery.lib.scripts.xlm.handlers.strings import STRING_HANDLERS

HANDLERS = {
    **CONTROL_HANDLERS,
    **FUNCTION_HANDLERS,
    **STRING_HANDLERS,
    **LOOKUP_HANDLERS,
}

_UNREGISTERED = set(HANDLERS) - set(XLM_COMMANDS)
assert not _UNREGISTERED, F'handlers without a command registry entry: {sorted(_UNREGISTERED)}'
