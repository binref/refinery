"""
The handler table of the emulator: one handler per macro command the interpreter answers, drawn
from the per-category registries, with the guarantee that every name it holds is a command the
registry knows.
"""
from __future__ import annotations

from refinery.lib.scripts.xlm.commands import XLM_COMMANDS
from refinery.lib.scripts.xlm.handlers.control import CONTROL_HANDLERS

HANDLERS = dict(CONTROL_HANDLERS)

_UNREGISTERED = set(HANDLERS) - set(XLM_COMMANDS)
assert not _UNREGISTERED, F'handlers without a command registry entry: {sorted(_UNREGISTERED)}'
