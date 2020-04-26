#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from fnmatch import fnmatch

from .... import arg, Unit
from .....lib.dotnet.header import DotNetHeader, ParserEOF
from .....lib.dotnet.resources import NetStructuredResources, NoManagedResource


class dnrc(Unit):
    """
    Extracts all .NET resources whose name matches any of the given patterns
    and outputs them.
    """

    def __init__(
        self,
        *needles: arg(metavar='pattern', nargs='*', type=str, default=['*'], help=(
            'A wildcard pattern for the name of a .NET resource. By default, all resources are extracted.')),
        sort: arg.switch('-s', help='Sort the resourcey by name rather than by order of appearance.') = False,
        raw: arg('-r', action='count', help=(
            'Specify once to not deserialize the entries of managed resources. '
            'Use twice to not parse managed resources at all.')) = 0
    ):
        self.superinit(super(), **vars())

    def _check(self, major: str, minor: str = ''):
        return any(
            fnmatch(subject, needle) for subject in [
                major, minor, F'{major}.{minor}'
            ]
            for needle in self.args.needles
            if isinstance(needle, str)
        )

    def process(self, data):
        header = DotNetHeader(data)

        if not header.resources:
            if self._list:
                return
            raise ValueError('This file contains no resources.')

        if self.args.sort:
            header.resources.sort(key=lambda r: r.Name)

        for resource in header.resources:
            try:
                managed = False if self.args.raw > 1 else NetStructuredResources(resource.Data)
            except (NoManagedResource, ParserEOF):
                managed = False

            if not managed:
                if managed is False and self._check(resource.Name):
                    yield resource.Data
                self.log_info(resource.Name)
                continue

            for entry in managed:
                if entry.Error:
                    self.log_warn(F'entry {resource.Name}.{entry.Name} carried error message: {entry.Error}')
                else:
                    self.log_debug(F'entry {resource.Name}.{entry.Name}')

                if not self._check(resource.Name, entry.Name):
                    continue

                self.log_info(F'{resource.Name}.{entry.Name}')

                if self.args.raw:
                    yield entry.Data
                    continue
                if isinstance(entry.Value, bytes):
                    yield entry.Value
                    continue
                try:
                    yield str(entry.Value).encode(self.codec)
                except Exception:
                    self.log_warn('unable to encode resource value of type', entry.Value)
