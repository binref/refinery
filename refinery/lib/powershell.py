#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows-specific module to determine whether the current Python process is running in a PowerShell process.
"""
from __future__ import annotations

import ctypes
import os

_PS1_MAGIC = B'[BRPS1]:'


class NotWindows(RuntimeError):
    pass


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize',              ctypes.c_uint32),                 # noqa
        ('cntUsage',            ctypes.c_uint32),                 # noqa
        ('th32ProcessID',       ctypes.c_uint32),                 # noqa
        ('th32DefaultHeapID',   ctypes.POINTER(ctypes.c_ulong)),  # noqa
        ('th32ModuleID',        ctypes.c_uint32),                 # noqa
        ('cntThreads',          ctypes.c_uint32),                 # noqa
        ('th32ParentProcessID', ctypes.c_uint32),                 # noqa
        ('pcPriClassBase',      ctypes.c_long),                   # noqa
        ('dwFlags',             ctypes.c_uint32),                 # noqa
        ('szExeFile',           ctypes.c_char * 260),             # noqa
    ]


def get_parent_processes():
    try:
        k32 = ctypes.windll.kernel32
    except AttributeError:
        raise NotWindows
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    snap = k32.CreateToolhelp32Snapshot(2, 0)
    if not snap:
        raise RuntimeError('could not create snapshot')
    try:
        def NextProcess():
            return k32.Process32Next(snap, ctypes.byref(entry))
        if not k32.Process32First(snap, ctypes.byref(entry)):
            raise RuntimeError('could not iterate processes')
        processes = {
            entry.th32ProcessID: (
                entry.th32ParentProcessID,
                bytes(entry.szExeFile).decode('latin1')
            ) for _ in iter(NextProcess, 0)
        }
    finally:
        k32.CloseHandle(snap)
    pid = os.getpid()
    while pid in processes:
        pid, path = processes[pid]
        yield path


def is_powershell_process() -> bool:
    if os.name != 'nt':
        return False
    try:
        for process in get_parent_processes():
            name, _ = os.path.splitext(process)
            name = name.lower()
            if name == 'cmd':
                return False
            if name == 'powershell':
                return True
            if name == 'pwsh':
                return True
    except NotWindows:
        pass
    return False


class Ps1Wrapper:
    WRAPPED = False

    def __new__(cls, stream):
        sb = stream.buffer
        if stream.isatty() or sb.isatty():
            return sb
        return super().__new__(cls)

    def __init__(self, stream):
        if self is stream:
            return
        self.stream = stream.buffer

    def __getattr__(self, key):
        return getattr(self.stream, key)

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *a):
        return self.stream.__exit__(*a)


class PS1OutputWrapper(Ps1Wrapper):
    _header_written = False

    def write(self, data):
        if not data:
            return
        import base64
        if not self._header_written:
            self.stream.write(_PS1_MAGIC)
            self._header_written = True
            if not Ps1Wrapper.WRAPPED:
                EV = 'REFINERY_SUPPRESS_PS1_WARNING'
                ev = os.environ.get(EV, '0')
                ev = int(ev) if ev.isdigit() else bool(ev)
                if not ev:
                    import logging
                    logging.getLogger('root').critical(
                        U'WARNING: PowerShell has no support for binary pipelines or streaming. Binary Refinery '
                        U'uses an unreliable and slow workaround: It is strongly recommended to use the command '
                        U'processor instead. Proceed at your own peril!\n'
                        U'- To get more information: https://github.com/binref/refinery/issues/5\n'
                        F'- To disable this warning: $env:{EV}=1'
                    )
        view = memoryview(data)
        size = 1 << 15
        for k in range(0, len(view), size):
            self.stream.write(base64.b16encode(view[k:k + size]))


class PS1InputWrapper(Ps1Wrapper):

    _init = True

    def read(self, size=None):
        return self.read1(size)

    def read1(self, size=None):
        if size is None:
            size = -1
        if self._init:
            if 0 < size < len(_PS1_MAGIC):
                raise RuntimeError(F'Unexpectedly small initial read: {size}')
            self._init = False
            length = len(_PS1_MAGIC)
            header = self.stream.read(length)
            if header != _PS1_MAGIC:
                return header + self.stream.read(max(size - length, -1))
            Ps1Wrapper.WRAPPED = True
        if Ps1Wrapper.WRAPPED:
            if size > 0:
                size *= 2
            import base64
            return base64.b16decode(self.stream.read(size).strip())
        else:
            return self.stream.read(size)


def bandaid(codec) -> bool:
    if not is_powershell_process():
        return False

    import io
    import sys

    sys.stdout = io.TextIOWrapper(
        PS1OutputWrapper(sys.stdout), codec, line_buffering=False, write_through=True)
    sys.stdin = io.TextIOWrapper(
        PS1InputWrapper(sys.stdin), codec, line_buffering=False)

    return True
