#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Union

import builtins
import contextlib
import hashlib
import io
import os
import sys

from refinery.lib.meta import SizeInt
from refinery.lib.loader import load_pipeline
from test import SampleStore

try:
    from IPython.core.magic import register_line_magic
except ImportError:
    def register_line_magic(x): return x


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
_root = os.path.abspath(os.getcwd())


def _virtual_fs_open(name, mode='r'):
    path = os.path.abspath(name)
    directory = os.path.abspath(os.path.dirname(path))
    file_name = os.path.basename(path)

    if 'b' not in mode or directory != _root:
        return _open(name, mode)

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
