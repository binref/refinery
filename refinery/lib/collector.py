"""
Python frees an object that is part of a reference cycle only when its cycle collector runs, and the
collector runs after a number of new objects, not bytes. Data that such a cycle refers to can
therefore pile up while a unit works through large inputs. The `CollectionTrigger` of this module
runs the collector when the memory of the process has grown by a fixed amount since its last run;
units call `collect_when_grown` after each chunk they hand on.
"""
from __future__ import annotations

import gc
import sys
import time

from typing import Callable

__all__ = [
    'CollectionTrigger',
    'collect_when_grown',
    'committed_memory',
]

if sys.platform == 'win32':
    import ctypes

    class _ProcessMemoryCounters(ctypes.Structure):
        """
        The structure `PROCESS_MEMORY_COUNTERS_EX` of the Windows API.
        """
        _fields_ = [
            ('cb', ctypes.c_uint32),
            ('PageFaultCount', ctypes.c_uint32),
            ('PeakWorkingSetSize', ctypes.c_size_t),
            ('WorkingSetSize', ctypes.c_size_t),
            ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
            ('QuotaPagedPoolUsage', ctypes.c_size_t),
            ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
            ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
            ('PagefileUsage', ctypes.c_size_t),
            ('PeakPagefileUsage', ctypes.c_size_t),
            ('PrivateUsage', ctypes.c_size_t),
        ]

    def _memory_reader() -> Callable[[], int]:
        """
        Reads the private bytes of the process.
        """
        kernel32 = ctypes.WinDLL('kernel32')
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        query = kernel32.K32GetProcessMemoryInfo
        query.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ProcessMemoryCounters), ctypes.c_uint32]
        query.restype = ctypes.c_int
        process = kernel32.GetCurrentProcess()
        counters = _ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        pointer = ctypes.byref(counters)

        def read() -> int:
            if not query(process, pointer, counters.cb):
                raise ctypes.WinError()
            return counters.PrivateUsage

        return read

elif sys.platform == 'linux':
    import os

    def _memory_reader() -> Callable[[], int]:
        """
        Reads the size of the data segment of the process.
        """
        page_size = os.sysconf('SC_PAGE_SIZE')

        def read() -> int:
            with open('/proc/self/statm', 'rb') as statm:
                return int(statm.read().split()[5]) * page_size

        return read

elif sys.platform == 'darwin':
    import resource

    def _memory_reader() -> Callable[[], int]:
        """
        Reads the peak of the resident memory of the process, which still grows when garbage pushes
        the process past its previous peak.
        """
        def read() -> int:
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        return read

else:
    def _memory_reader() -> Callable[[], int]:
        raise NotImplementedError(F'The memory of a process cannot be read on {sys.platform}.')


def _working_reader() -> Callable[[], int] | None:
    """
    The memory reader of this system if it works, otherwise `None`.
    """
    try:
        read = _memory_reader()
        read()
    except Exception:
        return None
    return read


_read = _working_reader()


def committed_memory() -> int | None:
    """
    The committed memory of the process in bytes, or `None` if it cannot be read on this system.
    """
    if (read := _read) is None:
        return None
    return read()


class CollectionTrigger:
    """
    Calling the trigger runs a full collection when the committed memory of the process has grown by
    `growth` bytes since the last collection that the trigger ran, or since it first read the
    memory. The memory is read at most once in every `interval` seconds, so a call usually costs
    one reading of the clock.
    """
    def __init__(self, growth: int = 64 << 20, interval: float = 0.005):
        self.growth = growth
        self.interval = interval
        self._checked = 0.0
        self._baseline: int | None = None

    def __call__(self) -> bool:
        """
        Runs a collection if the memory has grown enough and returns whether it did.
        """
        now = time.monotonic()
        if now - self._checked < self.interval:
            return False
        self._checked = now
        if (memory := committed_memory()) is None:
            return False
        if (baseline := self._baseline) is None or memory < baseline:
            self._baseline = memory
            return False
        if memory - baseline < self.growth:
            return False
        gc.collect()
        self._baseline = committed_memory()
        return True


collect_when_grown = CollectionTrigger()
"""
The trigger that units call after each chunk they hand on.
"""
