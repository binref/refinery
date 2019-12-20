#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io
import re
import fnmatch

try:
    from Registry.Registry import Registry
except ModuleNotFoundError:
    Registry = None

from .. import Unit
from ...lib.types import INF


def pathspec(expression):
    """
    Parses a path into a tuple of its components.
    """
    return re.split(R'[\\\/]', expression)


class winreg(Unit):
    """
    Extract values from a Windows registry hive.
    """
    def interface(self, argp):
        argp.add_argument('paths', metavar='path', nargs='+', type=pathspec,
            help=(
                'Path to a value from which data is to be extracted. '
                'Each value is returned as a separate output of this '
                'unit. Paths may contain wildcards.'
            )
        )
        return super().interface(argp)

    def _check(self, *path) -> bool:
        distance = INF
        for target in self.args.paths:
            if len(path) > len(target):
                distance = min(distance, len(target) - len(path))
                continue
            if all(fnmatch.fnmatch(*t) for t in zip(path, target)):
                return True
        return False

    def _walk(self, key, *path):
        if not self._check(*path):
            return
        if path:
            self.log_debug('enter', '\\'.join(path))
        for value in key.values():
            matching = self._check(*path, value.name())
            if self.log_info() and matching or self.log_debug():
                self.output('value', '\\'.join((*path, value.name())))
            if matching:
                self.log_debug('match')
                yield value.raw_data()
        for subkey in key.subkeys():
            yield from self._walk(subkey, *path, subkey.name())

    def process(self, data):
        with io.BytesIO(data) as stream:
            yield from self._walk(Registry(stream).root())
