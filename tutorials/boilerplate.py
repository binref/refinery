#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Union

import builtins
import contextlib
import hashlib
import io
import os
import sys
import stat

from refinery.lib.meta import SizeInt
from refinery.lib.loader import load_pipeline
from test import SampleStore

try:
    from IPython.core import magic
except ImportError:
    def register_line_magic(x): return x
else:
    def register_line_magic(f):
        setattr(f, magic.MAGIC_NO_VAR_EXPAND_ATTR, True)
        return magic.register_line_magic(f)


class FakeTTY:
    def __getattr__(self, k):
        return getattr(sys.stdout, k)

    def isatty(self):
        return True

    def write(self, b: Union[str, bytes]):
        with contextlib.suppress(AttributeError):
            b = b.decode('utf8')
        sys.stdout.write(b)


os.environ['REFINERY_TERMSIZE'] = '120'

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


@register_line_magic
def emit(line: str):
    load_pipeline(F'emit {line}') | FakeTTY()


@register_line_magic
def ls(line: str):
    for name, data in store.cache.items():
        print(F'{SizeInt(len(data))!r}', hashlib.sha256(data).hexdigest().lower(), name)


def store_sample(name: str, hash: str):
    store.download(hash)
    store.cache[name] = store.cache.pop(hash)
