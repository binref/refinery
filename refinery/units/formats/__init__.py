#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package containing several sub-packages for various data formats.
"""
import fnmatch
import re

from .. import Unit


def pathspec(expression):
    """
    Normalizes a path which is separated by backward or forward slashes to be
    separated by forward slashes.
    """
    return '/'.join(re.split(R'[\\\/]', expression))


class ExtractorUnit(Unit):

    def interface(self, argp):
        argp.add_argument('paths', metavar='path', nargs='+', type=pathspec,
            help=(
                'A path from which data is to be extracted. Each item is returned '
                ' as a separate output of this unit. Paths may contain wildcards.'
            )
        )
        return super().interface(argp)

    def _check_reachable(self, path: str) -> bool:
        for pattern in self.args.path:
            stops = [k for k, c in enumerate(pattern) if c in '/*?'] + [None]
            for stop in stops:
                if fnmatch.fnmatch(path, pattern[:stop]):
                    return True

    def _check_path(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, pattern) for pattern in self.args.paths)
