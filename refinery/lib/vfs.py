#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Certain libraries insist to read data from a file on disk which has to be specified by passing
a file path, and sometimes they will not accept a stream object or any other way to input data to
them. This module implements a **virtual file system** which allows us to pass in-memory data to
these libraries without having to actually write anything to disk. It works by hooking the
standard library functions `builtins.open`, `os.stat`, and `mmap.mmap`.
"""
from __future__ import annotations

import builtins
import os
import io
import stat
import tempfile
import uuid
import threading
import mmap

from typing import ByteString, Dict, Optional
from refinery.lib.structures import MemoryFile


class VirtualFile:
    """
    Represents a file in the virtual file system. It is linked to a `refinery.lib.vfs.VirtualFileSystem`
    and may be initialized with a chunk of binary data. It is possible to leave `data` as `None`,
    specificall to create a virtual file that would be written to, rather than read from. In that case,
    the data written to the virtual file can be extracted as a binary string later. Additionally, it
    is possible to specify a file extension that the virtual file should use in its randomly generated
    path; this is useful in case the reader insists on a specific file extension or uses the file
    extension to deduce a mode of operation.
    """
    name: str
    path: str
    node: int
    data: Optional[MemoryFile]

    def __init__(self, fs: VirtualFileSystem, data: Optional[ByteString] = None, extension: Optional[str] = None):
        extension = extension and F'.{extension}' or ''
        self.uuid = uuid.uuid4()
        self.name = F'{self.uuid!s}{extension}'
        self.data = data
        fs.install(self)

    @property
    def node(self) -> int:
        return self.uuid.fields[1]

    def mmap(self, length: int = 0, offset: int = 0) -> memoryview:
        """
        Emulate the result of an `mmap` call to the virtual file.
        """
        view = memoryview(self.data)
        if length:
            view = view[offset:offset + length]
        return MemoryFile(view)

    def open(self, mode: str) -> MemoryFile:
        """
        Open the virtual file.
        """
        if self.data is None and 'w' in mode:
            self.data = bytearray()
        fd = MemoryFile(self.data, read_as_bytes=True, fileno=self.node)
        fd.name = self.path
        return fd

    def __len__(self):
        if self.data is None:
            raise FileNotFoundError
        return len(self.data)

    def __fspath__(self):
        return self.path

    @property
    def path(self):
        """
        Returns the absolute path to this virtual file. The virtual file is given a randomly
        generated, uuid-formatted file name in the system's temporary directory.
        """
        return os.path.join(tempfile.gettempdir(), self.name)

    def stat(self):
        """
        Return a stat result for this virtual file. It has all permission bits set and accurately
        reports the size of the file.
        """
        if self.data is None:
            raise FileNotFoundError(F'virtual file does not exist: {self.name}')
        M = stat.S_IMODE(0xFFFF) | stat.S_IFREG
        S = len(self.data)
        return os.stat_result((
            M,  # ST_MODE
            0,  # ST_INO
            0,  # ST_DEV
            1,  # ST_NLINK
            0,  # ST_UID
            0,  # ST_GID
            S,  # ST_SIZE
            0,  # ST_ATIME
            0,  # ST_MTIME
            0,  # ST_CTIME
        ))


class VirtualFileSystem:
    """
    The main class and context handler for a virtual file system. It implements the hooking of
    system library functions and maps any number of `refinery.lib.vfs.VirtualFile` instances to
    randomly generated file paths. It is used as follows:

        with VirtualFileSystem() as vfs:
            vf = VirtualFile(vfs, data, 'exe')
            parsed = external_library.open(vf.path)

    A `refinery.lib.vfs.VirtualFile` is given a UUID-based random name, and any query to the
    virtual file system that does not correspond to a known `refinery.lib.vfs.VirtualFile` will
    be forwarded to the original `builtins.open`, `os.stat`, or `mmap.mmap` function.

    Nevertheless, units should attempt to spend **as little time as possible** inside the context
    handler; hooking builtin, file system related functions is a dangerous business.
    """

    _VFS_LOCK = threading.Lock()

    def __init__(self):
        self._lock: threading.RLock = threading.RLock()
        self._by_name: Dict[str, VirtualFile] = {}
        self._by_node: Dict[int, VirtualFile] = {}

    def install(self, file: VirtualFile):
        """
        Add a new virtual file into the file system. This function is called by the constructor
        of `refinery.lib.vfs.VirtualFile` and usually does not have to be called manually.
        """
        with self._lock:
            self._by_name[file.name] = file
            self._by_node[file.node] = file

    def __enter__(self):
        """
        The context handler for the virtual file system initializes all hooks and releases them
        when the context is left.
        """
        self._VFS_LOCK.acquire()

        def hook_open(file, *args, **kwargs):
            try:
                with self._lock:
                    vf = self._by_name[os.path.basename(file)]
            except BaseException:
                return self._builtins_open(file, *args, **kwargs)
            else:
                return vf.open(args[0])

        def hook_stat(file):
            try:
                with self._lock:
                    vf = self._by_name[os.path.basename(file)]
            except BaseException:
                return self._os_stat(file)
            else:
                return vf.stat()

        def hook_mmap(fileno, length: int, *args, **kwargs):
            try:
                with self._lock:
                    vf = self._by_node[fileno]
            except BaseException:
                return self._mmap_mmap(fileno, length, *args, **kwargs)
            else:
                return vf.mmap(length, kwargs.get('offset', 0))

        self._builtins_open = builtins.open
        self._os_stat = os.stat
        self._mmap_mmap = mmap.mmap
        self._io_open = io.open
        builtins.open = hook_open
        io.open = hook_open
        os.stat = hook_stat
        mmap.mmap = hook_mmap
        return self

    def __exit__(self, *args):
        builtins.open = self._builtins_open
        os.stat = self._os_stat
        mmap.mmap = self._mmap_mmap
        io.open = self._io_open
        self._VFS_LOCK.release()
        return False
