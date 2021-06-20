#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows-specific module to determine whether the current Python process is running in a PowerShell process.
"""
from __future__ import annotations

import ctypes
import functools
import os

from typing import Iterable, get_type_hints


class NotWindows(RuntimeError):
    pass


class FieldsFromTypeHints(type(ctypes.Structure)):
    def __new__(cls, name, bases, namespace):
        class AnnotationDummy:
            __annotations__ = namespace.get('__annotations__', {})
        annotations = get_type_hints(AnnotationDummy)
        namespace['_fields_'] = list(annotations.items())
        return type(ctypes.Structure).__new__(cls, name, bases, namespace)


class PROCESSENTRY32(ctypes.Structure, metaclass=FieldsFromTypeHints):
    dwSize              : ctypes.c_uint32
    cntUsage            : ctypes.c_uint32
    th32ProcessID       : ctypes.c_uint32
    th32DefaultHeapID   : ctypes.POINTER(ctypes.c_ulong)
    th32ModuleID        : ctypes.c_uint32
    cntThreads          : ctypes.c_uint32
    th32ParentProcessID : ctypes.c_uint32
    pcPriClassBase      : ctypes.c_long
    dwFlags             : ctypes.c_uint32
    szExeFile           : ctypes.c_char * 260


def get_parent_processes() -> Iterable[str]:
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
        if not k32.Process32First(snap, ctypes.byref(entry)):
            raise RuntimeError('could not iterate processes')
        processes = {
            entry.th32ProcessID: (
                entry.th32ParentProcessID,
                bytes(entry.szExeFile).decode('latin1')
            ) for _ in iter(
                functools.partial(k32.Process32Next, snap, ctypes.byref(entry)), 0)
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
    except NotWindows:
        pass
    return False
