#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Optional, Union

import builtins
import contextlib
import hashlib
import io
import os
import sys
import re
import logging
import stat
import fnmatch
import shlex

os.environ['REFINERY_TERM_SIZE'] = '120'

from refinery.lib.meta import SizeInt
from refinery.lib.loader import load_pipeline
from refinery.units import Executable
from test import SampleStore

logging.disable(logging.CRITICAL)
Executable.Entry = '__DEMO__'

try:
    from IPython.core import magic
except ImportError:
    def register_line_magic(x): return x
    def register_cell_magic(x): return x
else:
    def register_line_magic(f): # noqa
        return magic.register_line_magic(magic.no_var_expand(f))
    def register_cell_magic(f): # noqa
        return magic.register_line_cell_magic(magic.no_var_expand(f))


class FakeTTY:
    def __getattr__(self, k):
        return getattr(sys.stdout, k)

    def isatty(self):
        return True

    def write(self, b: Union[str, bytes]):
        with contextlib.suppress(AttributeError):
            b = b.decode('utf8')
        sys.stdout.write(b)


store = SampleStore()
_open = builtins.open
_stat = os.stat
_root = os.path.abspath(os.getcwd())


def _virtual_fs_stat(name):
    try:
        data = store.cache[name]
    except KeyError:
        return _stat(name)
    M = stat.S_IMODE(0xFFFF) | stat.S_IFREG
    S = len(data)
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


def _virtual_fs_open(name, mode='r', *args, **kwargs):
    path = os.path.abspath(name)
    directory = os.path.abspath(os.path.dirname(path))
    file_name = os.path.basename(path)

    if 'b' not in mode or directory != _root:
        return _open(name, mode, *args, **kwargs)

    if 'r' in mode:
        try:
            return io.BytesIO(store.cache[file_name])
        except KeyError:
            return _open(name, mode)

    class VFS(io.BytesIO):
        def close(self) -> None:
            store.cache[file_name] = self.getvalue()
            return super().close()

    return VFS()


builtins.open = _virtual_fs_open
os.stat = _virtual_fs_stat
io.open = _virtual_fs_open
sys.stderr = sys.stdout


@register_cell_magic
def emit(line: str, cell=None):
    if cell is not None:
        line = line + re.sub(R'[\r\n]+\s*', '\x20', cell)
        line = re.sub(R'(?<=\[|\])\x20*\|', '|', line)
    load_pipeline.cache_clear()
    load_pipeline(F'emit {line}') | FakeTTY()


@register_line_magic
def ls(line: str = ''):
    for name, data in store.cache.items():
        print(F'{SizeInt(len(data))!r}', hashlib.sha256(data).hexdigest().lower(), name)


@register_line_magic
def rm(line: str):
    patterns = shlex.split(line, posix=True)
    for name in list(store.cache.keys()):
        if any(fnmatch.fnmatch(name, pattern) for pattern in patterns):
            store.cache.pop(name, None)


def store_sample(hash: str, name: Optional[str] = None):
    store.download(hash)
    if name is None:
        name = hash
    store.cache[name] = store.cache.pop(hash)


def store_clear():
    store.cache.clear()
