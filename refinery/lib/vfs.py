#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import builtins
import os
import stat
import tempfile
import uuid
import threading
import mmap

from typing import ByteString, Dict, Optional
from refinery.lib.structures import MemoryFile


class VirtualFile:
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
        class bv(bytearray):
            def close(self): pass
        view = memoryview(self.data)
        if length:
            view = view[offset:offset + length]
        return bv(view)

    def open(self, mode: str) -> MemoryFile:
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
        return os.path.join(tempfile.gettempdir(), self.name)

    def stat(self):
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
    def __init__(self):
        self._lock: threading.RLock = threading.RLock()
        self._by_name: Dict[str, VirtualFile] = {}
        self._by_node: Dict[int, VirtualFile] = {}

    def install(self, file: VirtualFile):
        with self._lock:
            self._by_name[file.name] = file
            self._by_node[file.node] = file

    def __enter__(self):
        def hook_open(file, *args, **kwargs):
            try:
                with self._lock:
                    vf = self._by_name[os.path.basename(file)]
            except KeyError:
                return self._open(file, *args, **kwargs)
            else:
                return vf.open(args[0])

        def hook_stat(file):
            try:
                with self._lock:
                    vf = self._by_name[os.path.basename(file)]
            except KeyError:
                return self._stat(file)
            else:
                return vf.stat()

        def hook_mmap(fileno, length: int, *args, **kwargs):
            try:
                with self._lock:
                    vf = self._by_node[fileno]
            except KeyError:
                return self._mmap(fileno, length, *args, **kwargs)
            else:
                return vf.mmap(length, kwargs.get('offset', 0))

        self._open = builtins.open
        self._stat = os.stat
        self._mmap = mmap.mmap
        builtins.open = hook_open
        os.stat = hook_stat
        mmap.mmap = hook_mmap
        return self

    def __exit__(self, *args):
        builtins.open = self._open
        os.stat = self._stat
        mmap.mmap = self._mmap
        return False
