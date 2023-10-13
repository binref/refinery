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

from pathlib import Path
from zlib import adler32
from typing import ByteString, Iterable, Callable, List, Union, Optional

from refinery.units import Arg, Unit
from refinery.lib.meta import metavars, ByteStringWrapper, LazyMetaOracle


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

    def __init__(self, _br__path: str, _br__data: Union[ByteString, Callable[[], ByteString]], **_br__meta):
        self.path = _br__path
        self.data = _br__data
        self.meta = _br__meta
        for key in [key for key, value in _br__meta.items() if value is None]:
            del _br__meta[key]


class EndOfStringNotFound(ValueError):
    def __init__(self):
        super().__init__('end of string could not be determined')


class PathPattern:
    def __init__(self, pp: Union[str, re.Pattern], regex=False, fuzzy=0):
        if isinstance(pp, re.Pattern):
            self.stops = []
            self.pattern = pp
            return
        elif not regex:
            self.stops = [stop for stop in re.split(R'(.*?[/*?])', pp) if stop]
            pp, _, _ = fnmatch.translate(pp).partition(r'\Z')
        p1 = re.compile(pp)
        p2 = re.compile(F'.*?{pp}')
        self.matchers = [p1.fullmatch, p2.fullmatch, p1.search]
        self.fuzzy = fuzzy

    def reach(self, path):
        if not any(self.stops):
            return True
        for stop in self.stops:
            if fnmatch.fnmatch(path, stop):
                return True
        return False

    def check(self, path, fuzzy=0):
        fuzzy = min(max(fuzzy, self.fuzzy), 2)
        return self.matchers[fuzzy](path)

    def __repr__(self):
        return F'<PathPattern:{"//".join(self.stops) or "RE"}>'


class PathExtractorUnit(Unit, abstract=True):

    _custom_path_separator = '/'
    _current_meta: Optional[LazyMetaOracle]

    def __init__(
        self,
        *paths: Arg.Binary(metavar='path', nargs='*', help=(
            'Wildcard pattern for the path of the item to be extracted. Each item is returned '
            'as a separate output of this unit. Paths may contain wildcards; The default '
            'argument is a single wildcard, which means that every item will be extracted. If '
            'a given path yields no results, the unit performs increasingly fuzzy searches '
            'with it. This can be disabled using the --exact switch.')),
        format: Arg('-f', type=str, help=(
            'A format expression to be applied for computing the path of an item. This must use '
            'metadata that is available on the item. The default format can be accessed as the '
            'format expression "{}".')) = None,
        list: Arg.Switch('-l',
            help='Return all matching paths as UTF8-encoded output chunks.') = False,
        join_path: Arg.Switch('-j', group='PATH',
            help='Join path names from container with previous path names.') = False,
        drop_path: Arg.Switch('-d', group='PATH',
            help='Do not modify the path variable for output chunks.') = False,
        fuzzy: Arg.Counts('-z', group='MATCH', help=(
            'Specify once to add a leading wildcard to each patterns, twice to also add a '
            'trailing wildcard.')) = 0,
        exact: Arg.Switch('-e', group='MATCH',
            help='Path patterns never match on substrings.') = False,
        regex: Arg.Switch('-r',
            help='Use regular expressions instead of wildcard patterns.') = False,
        path: Arg('-P', metavar='NAME', help=(
            'Name of the meta variable to receive the extracted path. The default value is '
            '"{default}".')) = b'path',
        **keywords
    ):
        super().__init__(
            paths=paths,
            list=list,
            join=join_path,
            drop=drop_path,
            path=path,
            fuzzy=fuzzy,
            exact=exact,
            regex=regex,
            format=format,
            **keywords
        )

        self._current_meta = None

    @property
    def _patterns(self):
        paths = self.args.paths
        if not paths:
            if self.args.regex:
                paths = ['.*']
            else:
                paths = [u'*']
        else:
            def to_string(t):
                if isinstance(t, str):
                    return t
                return t.decode(self.codec)
            paths = [to_string(p) for p in paths]
        for path in paths:
            self.log_debug('path:', path)
        return [
            PathPattern(
                path,
                self.args.regex,
                self.args.fuzzy,
            ) for path in paths
        ]

    def _format_path(self, path: str, *args, **kwargs) -> str:
        format = self.args.format
        meta = self._current_meta
        if format is None or meta is None:
            return path
        try:
            return meta.format_str(format, self.codec, args, kwargs)
        except KeyError:
            self.log_debug('missing variable error while formatting path:', path)
        return path

    @abc.abstractmethod
    def unpack(self, data: ByteString) -> Iterable[UnpackResult]:
        raise NotImplementedError

    def process(self, data: ByteString) -> ByteString:
        self._current_meta = meta = metavars(data)
        results: List[UnpackResult] = list(self.unpack(data))

        patterns = self._patterns

        metavar = self.args.path.decode(self.codec)
        occurrences = collections.defaultdict(int)
        checksums = collections.defaultdict(set)
        root = Path('.')

        def normalize(_path: str) -> str:
            path = Path(_path.replace('\\', '/'))
            try:
                path = path.relative_to('/')
            except ValueError:
                pass
            path = root / path
            path = path.as_posix()
            path = path.replace('/', self._custom_path_separator)
            return path

        if self.args.join:
            try:
                root = ByteStringWrapper(meta[metavar], self.codec)
            except KeyError:
                pass

        for result in results:
            path = normalize(result.path)
            if not path:
                from refinery.lib.mime import FileMagicInfo
                ext = FileMagicInfo(result.get_data()).extension
                name = uuid.uuid4()
                path = F'{name}.{ext}'
                self.log_warn(F'read chunk with empty path; using generated name {path}')
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
                self.log_warn(F'read chunk with duplicate path; deduplicating to {result.path}')

        for p in patterns:
            for fuzzy in range(3):
                done = self.args.exact
                for result in results:
                    path = result.path
                    if not p.check(path, fuzzy):
                        continue
                    done = True
                    if self.args.list:
                        yield self.labelled(path.encode(self.codec), **result.meta)
                        continue
                    if not self.args.drop:
                        result.meta[metavar] = path
                    try:
                        data = result.get_data()
                    except Exception as error:
                        if self.log_debug():
                            raise
                        self.log_warn(F'extraction failure for {path}: {error!s}')
                    else:
                        self.log_debug(F'extraction success for {path}')
                        yield self.labelled(data, **result.meta)
                if done or self.args.fuzzy:
                    break
