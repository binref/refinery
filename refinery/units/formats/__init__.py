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
from ...lib.tools import isbuffer


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


class PathPattern:
    def __init__(self, pp, regex=False):
        if isinstance(pp, re.Pattern):
            self.stops = []
            self.pattern = pp
        else:
            if not regex:
                self.stops = [pp[:k] for k, c in enumerate(pp) if c in '/*?']
                pp = fnmatch.translate(pp)
            self.pattern = re.compile(pp)

    def reach(self, path):
        if not self.stops:
            return True
        for stop in self.stops:
            if fnmatch.fnmatch(path, stop):
                return True
        return False

    def check(self, path):
        return self.pattern.fullmatch(path)


class PathExtractorUnit(Unit, abstract=True):

    def __init__(self, *paths: arg(
        metavar='path', nargs='*', default=['*'], type=pathspec, help=(
            'Wildcard pattern for the name of the item to be extracted. Each item is returned'
            ' as a separate output of this unit. Paths may contain wildcards. The default is '
            'a single asterix, which means that every item will be extracted.')),
        list : arg.switch('-l', help='Return all matching paths as UTF8-encoded output chunks.') = False,
        join : arg.switch('-j', help='Join path names from container with previous path names.') = False,
        regex: arg.switch('-r', help='Use regular expressions instead of wildcard patterns.') = False,
        **keywords
    ):
        super().__init__(patterns=[PathPattern(p) for p in paths], list=list, join=join, **keywords)

    def _check_reachable(self, path: str) -> bool:
        return any(p.reach(path) for p in self.args.patterns)

    def _check_data(self, item: UnpackResult) -> bool:
        if not isbuffer(item.get_data()):
            self.log_warn('discarding item with invalid contents.')
            return False
        return True

    def _check_path(self, item: UnpackResult) -> bool:
        if not isinstance(item.path, str):
            if not self._check_data(item):
                return False
            else:
                from ...lib.mime import file_extension_from_data
                self.__unknown += 1
                self.log_warn('received an attachment without file name!')
                ext = file_extension_from_data(item.data)
                item.path = F'UNKNOWN{self.__unknown:02d}.{ext}'
        if not any(p.check(item.path) for p in self.args.patterns):
            return False
        elif self.args.list:
            return True
        return self._check_data(item)

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
        self.__unknown = 0

        for result in self.unpack(data):
            if self._check_path(result): results.append(result)

        for p in self.args.patterns:
            for result in results:
                path = result.path
                if not p.check(path):
                    continue
                if not self.args.list:
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
                yield self.labelled(result.get_data(), path=path)


class MemoryExtractorUnit(Unit, abstract=True):

    def __init__(
        self,
        offset: arg(type=virtualaddr,
            help='Specify virtual offset as either .section:OFFSET or just a virtual address in hex.'),
        count : arg.number(metavar='count', help='The maximum number of bytes to read.') = 0,
        marker: arg('-t', group='END', help='Read the memory until the specified marker is read.') = B'',
        utf16 : arg.switch('-u', group='END', help='Read the memory at the given offset as an UTF16 string.') = False,
        ascii : arg.switch('-a', group='END', help='Read the memory at the given offset as an ASCII string.') = False,
    ):
        if sum(1 for t in (marker, utf16, ascii) if t) > 1:
            raise ValueError('Only one of utf16, ascii, and marker may be specified.')
        if utf16: marker = B'\0\0'
        if ascii: marker = B'\0'

        return super().__init__(offset=offset, count=count, marker=marker)

    def _get_buffer_range(self, data, offset):
        return 0, 0

    def process(self, data):
        start, end = self._get_buffer_range(data, self.args.offset)
        if self.args.marker:
            end = start - 1
            blocksize = len(self.args.marker) 
            while True:
                end = data.find(self.args.marker, end + 1)
                if (end < start): raise EndOfStringNotFound
                if (end - start) % blocksize == 0:
                    break
        if self.args.count:
            lbound = start + self.args.count
            end = lbound if end is None else min(end, lbound)
        return data[start:end]
