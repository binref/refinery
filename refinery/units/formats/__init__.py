#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package containing several sub-packages for various data formats.
"""
import fnmatch
import re
import collections

from zlib import adler32
from typing import ByteString, Iterable, Callable, Union

from .. import arg, Unit
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

    def __init__(self, path: str, data: Union[ByteString, Callable[[], ByteString]], **meta):
        self.path = path
        self.data = data
        self.meta = meta


class EndOfStringNotFound(ValueError):
    def __init__(self):
        super().__init__('end of string could not be determined')


class PathPattern:
    def __init__(self, pp, fuzzy=False, regex=False):
        if isinstance(pp, re.Pattern):
            self.stops = []
            self.pattern = pp
            return
        elif not regex:
            if fuzzy and not pp.startswith('*') and not pp.endswith('*'):
                pp = F'*{pp}*'
            self.stops = [stop for stop in re.split(R'(.*?[/*?])', pp) if stop]
            pp = fnmatch.translate(pp)
        self.pattern = re.compile(pp)

    def reach(self, path):
        if not any(self.stops):
            return True
        for stop in self.stops:
            if fnmatch.fnmatch(path, stop):
                return True
        return False

    def check(self, path):
        return self.pattern.fullmatch(path)

    def __repr__(self):
        return F'<PathPattern:{"//".join(self.stops) or "RE"}>'


class PathExtractorUnit(Unit, abstract=True):

    def __init__(self, *paths: arg(
        metavar='path', nargs='*', default=['*'], type=pathspec, help=(
            'Wildcard pattern for the name of the item to be extracted. Each item is returned'
            ' as a separate output of this unit. Paths may contain wildcards. The default is '
            'a single asterix, which means that every item will be extracted.')),
        list : arg.switch('-l', help='Return all matching paths as UTF8-encoded output chunks.') = False,
        join : arg.switch('-j', help='Join path names from container with previous path names.') = False,
        regex: arg.switch('-r', help='Use regular expressions instead of wildcard patterns.') = False,
        fuzzy: arg.switch('-z', help='Wrap wildcard expressions in asterixes automatically '
            '(no effect on regular expressions).') = False,
        meta: arg('-m', metavar='NAME',
            help='Name of the meta variable to receive the extracted path. The default value is "{default}".') = b'path',
        **keywords
    ):
        paths = paths or ['*']
        super().__init__(
            patterns=[
                PathPattern(p, fuzzy, regex)
                for p in paths
            ],
            list=list,
            join=join,
            meta=meta,
            **keywords
        )

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
        results = []
        metavar = self.args.meta.decode(self.codec)
        paths = collections.defaultdict(set)
        self.__unknown = 0

        try:
            root = data[metavar]
        except KeyError:
            root = ''

        for result in self.unpack(data):
            if self._check_path(result): results.append(result)

        for p in self.args.patterns:
            for result in results:
                path = result.path
                if '\\' in path:
                    path = '/'.join(path.split('\\'))
                if not p.check(path):
                    continue
                if not self.args.list:
                    csum = adler32(result.get_data())
                    if path in paths:
                        if csum in paths[path]:
                            continue
                        self.log_warn('duplicate path with different contents:', path)
                    paths[path].add(csum)
                if self.args.join and root:
                    if '\\' in root:
                        root = '/'.join(root.split('\\'))
                    path = F'{root}/{path}'
                if self.args.list:
                    yield path.encode(self.codec)
                    continue
                else:
                    self.log_info(path)
                result.meta[metavar] = path
                yield self.labelled(result.get_data(), **result.meta)
