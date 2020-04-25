#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package containing several sub-packages for various data formats.
"""
import fnmatch
import re

from .. import arg, Unit
from ...lib.argformats import virtualaddr


def pathspec(expression):
    """
    Normalizes a path which is separated by backward or forward slashes to be
    separated by forward slashes.
    """
    return '/'.join(re.split(R'[\\\/]', expression))


class EndOfStringNotFound(ValueError):
    def __init__(self):
        super().__init__('end of string could not be determined')


class PathExtractorUnit(Unit, abstract=True):

    def __init__(self, *paths: arg(
        metavar='path', nargs='*', default=['*'], type=pathspec, help=(
            'A path from which data is to be extracted. Each item is returned '
            'as a separate output of this unit. Paths may contain wildcards. '
            'The default is a single asterix, which means that every item will '
            'be extracted.')
    )):
        super().__init__(paths=paths)

    def _check_reachable(self, path: str) -> bool:
        for pattern in self.args.path:
            stops = [k for k, c in enumerate(pattern) if c in '/*?'] + [None]
            for stop in stops:
                if fnmatch.fnmatch(path, pattern[:stop]):
                    return True

    def _check_path(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, pattern) for pattern in self.args.paths)


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
