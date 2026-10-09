from __future__ import annotations

from typing import TYPE_CHECKING

from refinery.lib.emulator.abstract import MemAccess
from refinery.lib.shared.unicorn import unicorn as uc

if TYPE_CHECKING:
    from unicorn.unicorn import Uc


def unmap_all(engine: Uc):
    """
    Unmaps every memory region of the given unicorn engine. Its memory holds a copy of the emulated
    data, while the engine itself may wait for the cycle collector.
    """
    for begin, end, _ in list(engine.mem_regions()):
        engine.mem_unmap(begin, end - begin + 1)


def get_access_map():
    return {
        uc.UC_MEM_READ           : MemAccess.Read,
        uc.UC_MEM_READ_AFTER     : MemAccess.Read | MemAccess.After,
        uc.UC_MEM_READ_UNMAPPED  : MemAccess.Read | MemAccess.Unmapped,
        uc.UC_MEM_READ_PROT      : MemAccess.Read | MemAccess.Denied,
        uc.UC_MEM_FETCH          : MemAccess.Execute,
        uc.UC_MEM_FETCH_UNMAPPED : MemAccess.Execute | MemAccess.Unmapped,
        uc.UC_MEM_FETCH_PROT     : MemAccess.Execute | MemAccess.Denied,
        uc.UC_MEM_WRITE          : MemAccess.Write,
        uc.UC_MEM_WRITE_UNMAPPED : MemAccess.Write | MemAccess.Unmapped,
        uc.UC_MEM_WRITE_PROT     : MemAccess.Write | MemAccess.Denied,
    }
