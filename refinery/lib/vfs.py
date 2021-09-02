#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import builtins
import os
import stat
import tempfile
import uuid
import threading

from typing import ByteString, Dict, Optional
from refinery.lib.structures import MemoryFile


class VirtualFile:
    name: str
    data: Optional[MemoryFile]

    def __init__(self, fs: VirtualFileSystem, data: Optional[ByteString] = None, extension: Optional[str] = None):
        extension = extension and F'.{extension}' or ''
        self.name = F'{uuid.uuid4()!s}{extension}'
        self.data = data
        fs.install(self)

    def open(self) -> MemoryFile:
        fd = MemoryFile(self.data, read_as_bytes=True)
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
        self._disk: Dict[str, VirtualFile] = {}

    def install(self, file: VirtualFile):
        with self._lock:
            self._disk[file.name] = file

    def __enter__(self):
        def hook_open(file, *args, **kwargs):
            try:
                with self._lock:
                    vf = self._disk[os.path.basename(file)]
            except KeyError:
                return self._open(file, *args, **kwargs)
            else:
                return vf.open()

        def hook_stat(file):
            try:
                with self._lock:
                    vf = self._disk[os.path.basename(file)]
            except KeyError:
                return self._stat(file)
            else:
                return vf.stat()

        self._open = builtins.open
        self._stat = os.stat
        builtins.open = hook_open
        os.stat = hook_stat
        return self

    def __exit__(self, *args):
        builtins.open = self._open
        os.stat = self._stat
        return False
