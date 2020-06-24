#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package containing several sub-packages for various data formats.
"""
import fnmatch
import re
import os
import collections

from zlib import adler32
from typing import ByteString, Iterable, Callable, Union

from .. import arg, Unit
from ...lib.argformats import virtualaddr


def pathspec(expression):
    """
    Normalizes a path which is separated by backward or forward slashes to be
    separated by forward slashes.
    """
    return '/'.join(re.split(R'[\\\/]', expression))


class UnpackResult:

    def get_data(self) -> ByteString:
        if callable(self.data):
            self.data = self.data()
        return self.data

    def __init__(self, path: str, data: Union[ByteString, Callable[[], ByteString]]):
        self.path = path
        self.data = data


class EndOfStringNotFound(ValueError):
    def __init__(self):
        super().__init__('end of string could not be determined')


class PathExtractorUnit(Unit, abstract=True):

    def __init__(self, *paths: arg(
        metavar='path', nargs='*', default=['*'], type=pathspec, help=(
            'Wildcard pattern for the name of the item to be extracted. Each item is returned'
            ' as a separate output of this unit. Paths may contain wildcards. The default is '
            'a single asterix, which means that every item will be extracted.')),
        list: arg.switch('-l', help='Return all matching paths as UTF8-encoded output chunks.') = False,
        join: arg.switch('-j', help='Join path names from container with previous path names.') = False,
        **keywords
    ):
        super().__init__(paths=paths, list=list, join=join, **keywords)

    def _check_reachable(self, path: str) -> bool:
        for pattern in self.args.path:
            stops = [k for k, c in enumerate(pattern) if c in '/*?'] + [None]
            for stop in stops:
                if fnmatch.fnmatch(path, pattern[:stop]):
                    return True

    def _check_path(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, pattern) for pattern in self.args.paths)

    def unpack(self, data: ByteString) -> Iterable[UnpackResult]:
        raise NotImplementedError

    def process(self, data: ByteString) -> ByteString:

        if self.args.join:
            try:
                root = data['path']
            except (KeyError, TypeError):
                root = ''

        results = []
        paths = collections.defaultdict(set)

        for result in self.unpack(data):
            if self._check_path(result.path):
                if not self.args.list:
                    result.get_data()
                results.append(result)

        for pattern in self.args.paths:
            self.log_debug('checking pattern:', pattern)
            for result in results:
                path = result.path
                if not fnmatch.fnmatch(path, pattern):
                    continue
                csum = adler32(result.get_data())
                if path in paths:
                    if csum in paths[path]:
                        continue
                    self.log_warn('duplicate path with different contents:', path)
                paths[path].add(csum)
                if self.args.join:
                    path = os.path.join(root, path)
                if self.args.list:
                    yield path.encode(self.codec)
                    continue
                else:
                    self.log_info(path)
                yield dict(
                    data=result.get_data(),
                    path=path
                )


class MemoryExtractorUnit(Unit, abstract=True):

    def __init__(
        self,
        offset: arg(type=virtualaddr,
            help='Specify virtual offset as either .section:OFFSET or just a virtual address in hex.'),
        end : arg('-e', group='END', type=virtualaddr,
            help='Read bytes until this offset, which has to be located after the starting offset.') = None,
        take  : arg.number('-t', group='END', help='The number of bytes to read.') = 0,
        utf16 : arg.switch('-u', group='END', help='Read the memory at the given offset as an UTF16 string.') = False,
        ascii : arg.switch('-a', group='END', help='Read the memory at the given offset as an ASCII string.') = False
    ):
        if sum(1 for p in (end, take, utf16, ascii) if p) > 1:
            raise ValueError('Only one of end, take, utf16, and ascii may be specified.')
        return self.superinit(super(), **vars())

    def _read_from_memory(self, data, offset_oracle):
        start, end = offset_oracle(self.args.offset)
        if self.args.end:
            end, _ = offset_oracle(self.args.end)
            if end < start:
                raise ValueError(
                    F'The end offset 0x{end:08X} lies {start-end} bytes '
                    F'before the start offset 0x{start:08X}.'
                )
        elif self.args.take:
            end = start + self.args.take
        elif self.args.ascii:
            end = data.find(B'\0', start)
            if end < 0:
                raise EndOfStringNotFound
        elif self.args.utf16:
            for end in range(start, len(data), 2):
                if not data[end] and not data[end + 1]:
                    break
            else:
                raise EndOfStringNotFound
        return data[start:end]
