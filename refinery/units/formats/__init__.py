#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package containing several sub-packages for various data formats.
"""
import fnmatch
import re

from .. import Unit
from ...lib.argformats import number, virtualaddr


def pathspec(expression):
    """
    Normalizes a path which is separated by backward or forward slashes to be
    separated by forward slashes.
    """
    return '/'.join(re.split(R'[\\\/]', expression))


class EndOfStringNotFound(ValueError):
    def __init__(self):
        super().__init__('end of string could not be determined')


class PathExtractorUnit(Unit):

    @classmethod
    def interface(cls, argp):
        argp.add_argument('paths', metavar='path', nargs='*', default=['*'], type=pathspec, help=(
            'A path from which data is to be extracted. Each item is returned '
            ' as a separate output of this unit. Paths may contain wildcards. '
            'The default is a single asterix, which means that every item will '
            'be extracted.'
        ))
        return super().interface(argp)

    def _check_reachable(self, path: str) -> bool:
        for pattern in self.args.path:
            stops = [k for k, c in enumerate(pattern) if c in '/*?'] + [None]
            for stop in stops:
                if fnmatch.fnmatch(path, pattern[:stop]):
                    return True

    def _check_path(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, pattern) for pattern in self.args.paths)


class MemoryExtractorUnit(Unit):

    @classmethod
    def interface(cls, argp):
        limit = argp.add_mutually_exclusive_group()
        limit.add_argument('-t', '--take', type=number[1:], default=0,
            help='The number of bytes to read.')
        limit.add_argument('-e', '--end', type=virtualaddr, default=None,
            help='Read bytes until this offset, which has to be located after the starting offset.')
        limit.add_argument('-a', '--ascii', action='store_true',
            help='Read the memory at the given offset as an ASCII string.')
        limit.add_argument('-u', '--utf16', action='store_true',
            help='Read the memory at the given offset as an UTF16 string.')
        argp.add_argument('offset', type=virtualaddr,
            help='Specify virtual offset as either .section:OFFSET or just a virtual address in hex.')
        return super().interface(argp)

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
