"""
Windows-specific module to determine whether the current Python process is running in a PowerShell process.
"""
from __future__ import annotations

import ctypes
import enum
import os

from pathlib import PureWindowsPath
from typing import TextIO

from refinery.lib.environment import environment, logger

_PS1_MAGIC = B'[BRPS1]:'
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class TH32CS(enum.IntEnum):
    SNAPMODULE  = 0x8 # noqa
    SNAPPROCESS = 0x2 # noqa


class NotWindows(RuntimeError):
    """
    PowerShell support is only available on Windows; this exception is raised when the operating
    system is something else.
    """


class PROCESSENTRY32(ctypes.Structure):
    """
    The [PROCESSENTRY32](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32) structure.
    """
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


class MODULEENTRY32(ctypes.Structure):
    """
    The [MODULEENTRY32](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-moduleentry32) structure.
    """
    _fields_ = [
        ('dwSize',              ctypes.c_uint32),                 # noqa
        ('th32ModuleID',        ctypes.c_uint32),                 # noqa
        ('th32ProcessID',       ctypes.c_uint32),                 # noqa
        ('GlblcntUsage',        ctypes.c_uint32),                 # noqa
        ('ProccntUsage',        ctypes.c_uint32),                 # noqa
        ('modBaseAddr',         ctypes.POINTER(ctypes.c_uint8)),  # noqa
        ('modBaseSize',         ctypes.c_uint32),                 # noqa
        ('hModule',             ctypes.POINTER(ctypes.c_ulong)),  # noqa
        ('szModule',            ctypes.c_char * 256),             # noqa
        ('szExePath',           ctypes.c_char * 260),             # noqa
    ]


def get_parent_processes(__cache: list[list[str]] = []):
    """
    Returns a list of file paths that identify the images of all our parent processes.
    """
    if __cache:
        return __cache[0]
    try:
        k32 = ctypes.windll.kernel32
    except AttributeError:
        raise NotWindows

    HANDLE = ctypes.c_void_p
    BOOL = ctypes.c_int
    DWORD = ctypes.c_uint32

    k32.CreateToolhelp32Snapshot.restype = HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = DWORD, DWORD
    k32.Process32First.restype = BOOL
    k32.Process32First.argtypes = HANDLE, ctypes.POINTER(PROCESSENTRY32)
    k32.Process32Next.restype = BOOL
    k32.Process32Next.argtypes = HANDLE, ctypes.POINTER(PROCESSENTRY32)
    k32.Module32First.restype = BOOL
    k32.Module32First.argtypes = HANDLE, ctypes.POINTER(MODULEENTRY32)
    k32.CloseHandle.restype = BOOL
    k32.CloseHandle.argtypes = HANDLE,

    def resolve_path(pid: int, name: bytes) -> str:
        modsnap = k32.CreateToolhelp32Snapshot(TH32CS.SNAPMODULE, pid)
        if modsnap and modsnap != _INVALID_HANDLE_VALUE:
            mod = MODULEENTRY32()
            mod.dwSize = ctypes.sizeof(MODULEENTRY32)
            if k32.Module32First(modsnap, ctypes.byref(mod)):
                name = mod.szExePath
            k32.CloseHandle(modsnap)
        return bytes(name).decode('latin1')

    processes: dict[int, tuple[int, bytes]] = {}
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    snap = k32.CreateToolhelp32Snapshot(TH32CS.SNAPPROCESS, 0)

    if snap and snap != _INVALID_HANDLE_VALUE:
        try:
            running = k32.Process32First(snap, ctypes.byref(entry))
            while running:
                cpid = entry.th32ProcessID
                ppid = entry.th32ParentProcessID
                if cpid != ppid:
                    processes[cpid] = ppid, bytes(entry.szExeFile)
                running = k32.Process32Next(snap, ctypes.byref(entry))
        finally:
            k32.CloseHandle(snap)

    pid = os.getpid()
    loop_detection = set()
    paths: list[str] = []
    while pid in processes and pid not in loop_detection:
        loop_detection.add(pid)
        ppid, name = processes[pid]
        paths.append(resolve_path(pid, name))
        pid = ppid
    __cache.append(paths)
    return paths


def _detect_powershell(paths: list[str]) -> bool:
    """
    Classifies a parent-process path chain (nearest ancestor first) and returns whether the
    controlling shell is powershell.
    """
    for path in paths:
        stem = PureWindowsPath(path.lower()).stem
        if stem in ('cmd', 'bash'):
            return False
        if stem in ('powershell', 'pwsh'):
            return True
    return False


def _detect_binref_support(paths: list[str]) -> bool:
    """
    Classifies a parent-process path chain (nearest ancestor first) and returns whether the
    controlling shell is known to support binary refinery pipelines natively. PowerShell only
    does so starting with version 7.4; the version is read from the WindowsApps package
    directory name when it is available.
    """
    for path in paths:
        path = PureWindowsPath(path.lower())
        stem = path.stem
        if stem in ('cmd', 'bash'):
            return True
        for part in path.parts:
            if not part.startswith('microsoft.powershell'):
                continue
            try:
                version = tuple(map(int, part.split('_')[1].split('.')))
            except Exception:
                continue
            if version[:2] >= (7, 4):
                return True
        if stem in ('powershell', 'pwsh'):
            return False
    return True


def is_powershell(__cache: list[bool] = []) -> bool:
    """
    Returns whether refinery currently runs under powershell.
    """
    if __cache:
        return __cache[0]
    result = False
    if os.name == 'nt':
        try:
            result = _detect_powershell(get_parent_processes())
        except NotWindows:
            pass
    __cache.append(result)
    return result


def shell_supports_binref(__cache: list[bool] = []) -> bool:
    """
    This checks whether the current shell is known to support binary refinery natively. This
    requires full binary and streaming STDIN/STDOUT. PowerShell 7.4 does have this, so does
    the command interpreter. If the operating system is not Windows, the shell is assumed to
    be compatible.
    """
    if __cache:
        return __cache[0]
    result = True
    if os.name == 'nt':
        try:
            result = _detect_binref_support(get_parent_processes())
        except NotWindows:
            pass
    __cache.append(result)
    return result


class Ps1Wrapper:
    """
    Boilerplace for the STDIN and STDOUT wrappers.
    """
    WRAPPED: bool = False

    def __new__(cls, stream: TextIO):
        sb = stream.buffer
        if stream.isatty() or sb.isatty():
            return sb
        return super().__new__(cls)

    def __init__(self, stream: TextIO):
        self.stream = stream.buffer

    def __getattr__(self, key):
        return getattr(self.stream, key)

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *a):
        return self.stream.__exit__(*a)


class PS1OutputWrapper(Ps1Wrapper):
    """
    The PowerShell STDOUT compatibility wrapper. It takes the binary output and hex encodes it.
    This data is then prefixed by a special (printable) magic sequence.
    """
    _header_written = False

    def write(self, data):
        if not data:
            return 0
        import base64
        if not self._header_written:
            self.stream.write(_PS1_MAGIC)
            self._header_written = True
            if not Ps1Wrapper.WRAPPED and not environment.silence_ps1_warning.value:
                logger(__name__).critical(
                    'WARNING: PowerShell has no support for binary pipelines or streaming. Binary Refinery '
                    'uses an unreliable and slow workaround: It is strongly recommended to use the command '
                    'processor instead. Proceed at your own peril!\n'
                    F'- To silence this warning: $env:{environment.silence_ps1_warning.key}=1\n'
                    F'- To disable the band-aid: $env:{environment.disable_ps1_bandaid.key}=1\n'
                    '- To get more information: https://github.com/binref/refinery/issues/5'
                )
        view = memoryview(data)
        size = 1 << 15
        for k in range(0, len(view), size):
            self.stream.write(base64.b16encode(view[k:k + size]))
        return len(data)


class PS1InputWrapper(Ps1Wrapper):
    """
    The PowerShell STDIN compatibility wrapper. If it receives data prefixed with the correct magic
    sequence, it will hex-decode the remaining data and forward the binary result.
    """
    _init = True

    def read(self, size=None):
        return self.read1(size)

    def read1(self, size=None):
        if size is None:
            size = -1
        if size == 0:
            return B''
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
            return base64.b16decode(self.stream.read(size).translate(None, b' \t\r\n\v\f'))
        else:
            return self.stream.read(size)


def bandaid(codec) -> bool:
    """
    This function will invoke `refinery.lib.powershell.shell_supports_binref` to check whether
    the bandaid is necessary. If so, it uses the IO wrappers in this module to wrap STDIN/STDOUT
    in a compatibility layer that will make refinery work, albeit poorly.
    """
    if shell_supports_binref():
        return False

    import io
    import sys

    sys.stdout = io.TextIOWrapper(
        PS1OutputWrapper(sys.stdout), codec, line_buffering=False, write_through=True)
    sys.stdin = io.TextIOWrapper(
        PS1InputWrapper(sys.stdin), codec, line_buffering=False)

    return True
