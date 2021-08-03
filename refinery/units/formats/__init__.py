#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package containing several sub-packages for various data formats.
"""
import abc
import collections
import fnmatch
import os
import re
import uuid

from zlib import adler32
from typing import ByteString, Iterable, Callable, List, Union

from .. import arg, Unit
from ...lib.meta import metavars, ByteStringWrapper


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
    def __init__(self, pp, regex=False, strict=False):
        if isinstance(pp, re.Pattern):
            self.stops = []
            self.pattern = pp
            return
        elif not regex:
            if not strict and not pp.startswith('*') and not pp.endswith('*'):
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

    _STRICT_PATH_MATCHING = False

    def __init__(self, *paths: arg(
        metavar='path', nargs='*', default=(), type=pathspec, help=(
            'Wildcard pattern for the name of the item to be extracted. Each item is returned'
            ' as a separate output of this unit. Paths may contain wildcards. The default is '
            'a single wildcard, which means that every item will be extracted.')),
        list : arg.switch('-l', help='Return all matching paths as UTF8-encoded output chunks.') = False,
        join_path : arg.switch('-j', group='PATH', help='Join path names from container with previous path names.') = False,
        drop_path : arg.switch('-d', group='PATH', help='Do not modify the path variable for output chunks.') = False,
        regex: arg.switch('-r', help='Use regular expressions instead of wildcard patterns.') = False,
        path: arg('-P', metavar='NAME',
            help='Name of the meta variable to receive the extracted path. The default value is "{default}".') = b'path',
        **keywords
    ):
        strict = getattr(self.__class__, '_STRICT_PATH_MATCHING', False)
        paths = paths or (['.*'] if regex else ['*'])
        super().__init__(
            patterns=[PathPattern(p, regex, strict) for p in paths],
            list=list,
            join=join_path,
            drop=drop_path,
            path=path,
            **keywords
        )

    def _check_reachable(self, path: str) -> bool:
        return any(p.reach(path) for p in self.args.patterns)

    @abc.abstractmethod
    def unpack(self, data: ByteString) -> Iterable[UnpackResult]:
        raise NotImplementedError

    def process(self, data: ByteString) -> ByteString:
        metavar = self.args.path.decode(self.codec)
        meta = metavars(data)
        occurrences = collections.defaultdict(int)
        checksums = collections.defaultdict(set)
        results: List[UnpackResult] = list(self.unpack(data))

        try:
            root = ByteStringWrapper(meta[metavar], self.codec)
        except KeyError:
            root = ''
        else:
            root = '/'.join(root.string.split('\\')).rstrip('/')

        for result in results:
            path = '/'.join(result.path.split('\\'))
            if not path:
                from ...lib.mime import FileMagicInfo
                self.log_warn('received an attachment without file name!')
                ext = FileMagicInfo(result.get_data()).extension
                path = F'[unknown].{ext}'
            result.path = path
            occurrences[path] += 1

        for result in results:
            path = result.path
            if occurrences[path] > 1:
                checksum = adler32(result.get_data())
                if checksum in checksums[path]:
                    continue
                checksums[path].add(checksum)
                counter = len(checksums[path])
                base, extension = os.path.splitext(path)
                width = len(str(occurrences[path]))
                if any(F'{base}.v{c:0{width}d}{extension}' in occurrences for c in range(occurrences[path])):
                    result.path = F'{base}.{uuid.uuid4()}{extension}'
                else:
                    result.path = F'{base}.v{counter:0{width}d}{extension}'

        for p in self.args.patterns:
            for result in results:
                path = result.path
                if not p.check(path):
                    continue
                if self.args.join and root:
                    path = F'{root}/{path}'
                if self.args.list:
                    yield self.labelled(path.encode(self.codec), **result.meta)
                    continue
                else:
                    self.log_info(path)
                if not self.args.drop:
                    result.meta[metavar] = path
                yield self.labelled(result.get_data(), **result.meta)
