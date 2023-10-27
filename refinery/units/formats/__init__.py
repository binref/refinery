#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A package containing several sub-packages for various data formats.
"""
from __future__ import annotations

import abc
import collections
import fnmatch
import os
import re
import uuid

from pathlib import Path
from zlib import adler32
from collections import Counter
from typing import ByteString, Iterable, Callable, List, Union, Optional

from refinery.units import Arg, Unit
from refinery.lib.meta import metavars, ByteStringWrapper, LazyMetaOracle
from refinery.lib.xml import XMLNodeBase


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

    def __init__(
        self,
        *paths: Arg.Binary(metavar='path', nargs='*', help=(
            'Wildcard pattern for the path of the item to be extracted. Each item is returned '
            'as a separate output of this unit. Paths may contain wildcards; The default '
            'argument is a single wildcard, which means that every item will be extracted. If '
            'a given path yields no results, the unit performs increasingly fuzzy searches '
            'with it. This can be disabled using the --exact switch.')),
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
            **keywords
        )

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

    @abc.abstractmethod
    def unpack(self, data: ByteString) -> Iterable[UnpackResult]:
        raise NotImplementedError

    def process(self, data: ByteString) -> ByteString:
        meta = metavars(data)
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


class XMLToPathExtractorUnit(PathExtractorUnit, abstract=True):
    def __init__(
        self, *paths,
        format: Arg('-f', type=str, metavar='F', help=(
            'A format expression to be applied for computing the path of an item. This must use '
            'metadata that is available on the item. The current tag can be accessed as {0}. If '
            'no format is specified, the unit attempts to derive a good attribute from the XML '
            'tree to use for generating paths.'
        )) = None,
        list=False, join_path=False, drop_path=False, fuzzy=0, exact=False, regex=False,
        path=b'path', **keywords
    ):
        super().__init__(
            *paths,
            format=format,
            list=list,
            path=path,
            join_path=join_path,
            drop_path=drop_path,
            fuzzy=fuzzy,
            exact=exact,
            regex=regex,
            **keywords
        )

    @staticmethod
    def _normalize_val(attr: str):
        _bad = '[/\\$&%#:.]'
        attr = attr.replace('[', '(')
        attr = attr.replace(']', ')')
        attr = re.sub(F'\\s*{_bad}+\\s+', ' ', attr)
        attr = re.sub(F'\\s*{_bad}+\\s*', '.', attr)
        return attr.strip()

    @staticmethod
    def _normalize_key(attribute: str):
        _, _, a = attribute.rpartition(':')
        return a

    def _make_path_builder(
        self,
        meta: LazyMetaOracle,
        root: XMLNodeBase
    ) -> Callable[[XMLNodeBase, Optional[int]], str]:

        path_attributes = Counter()

        def walk(node: XMLNodeBase):
            total = 1
            for key, val in node.attributes.items():
                if re.fullmatch(R'[-\s\w+,.;@(){}]{1,64}', self._normalize_val(val)):
                    path_attributes[key] += 1
            for child in node.children:
                total += walk(child)
            return total

        total = walk(root)

        if not path_attributes:
            path_attribute = None
            count = 0
        else:
            path_attribute, count = path_attributes.most_common(1)[0]
            if 3 * count <= 2 * total:
                path_attribute = None

        nkey = self._normalize_key
        nval = self._normalize_val
        node_format = self.args.format

        def path_builder(node: XMLNodeBase, index: Optional[int] = None) -> str:
            attrs = node.attributes
            if node_format and meta:
                try:
                    return meta.format_str(
                        node_format,
                        self.codec,
                        node.tag, **{
                            nkey(key): nval(val)
                            for key, val in attrs.items()
                        }
                    )
                except KeyError:
                    pass
            if path_attribute is not None and path_attribute in attrs:
                return self._normalize_val(attrs[path_attribute])
            out = node.tag
            if index is not None:
                out = F'{out}({index})'
            return nval(out)

        return path_builder
