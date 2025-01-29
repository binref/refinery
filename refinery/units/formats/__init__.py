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

from zlib import adler32
from collections import Counter
from typing import ByteString, Iterable, Callable, List, Union, Optional

from refinery.units import Arg, Unit, RefineryPartialResult, RefineryPotentialUserError
from refinery.lib.meta import metavars, ByteStringWrapper, LazyMetaOracle
from refinery.lib.xml import XMLNodeBase
from refinery.lib.tools import exception_to_string


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
    def __init__(self, query: Union[str, re.Pattern], regex=False, fuzzy=0):
        self.query = query
        self.regex = regex
        self.fuzzy = fuzzy
        self.compile()

    def compile(self, **kw):
        query = self.query
        if isinstance(query, re.Pattern):
            self.stops = []
            self.pattern = query
            return
        elif not self.regex:
            self.stops = re.split(R'([/*?]+)', query)
            query, _, _ = fnmatch.translate(query).partition(r'\Z')
        p1 = re.compile(query, **kw)
        p2 = re.compile(F'.*?{query}')
        self.matchers = [p1.fullmatch, p2.fullmatch, p1.search]

    def reach(self, path):
        if not any(self.stops):
            return True
        for stop in self.stops[0::2]:
            if fnmatch.fnmatch(path, F'*{stop}'):
                return True
        return False

    def check(self, path, fuzzy=0):
        fuzzy = min(max(fuzzy, self.fuzzy), 2)
        return self.matchers[fuzzy](path)

    def __repr__(self):
        return F'<PathPattern:{"".join(self.stops) or "RE"}>'


class PathExtractorUnit(Unit, abstract=True):

    CustomPathSeparator = None
    """
    This class variable can be overwritten by child classes to change the path separator from the
    default forward slash to something else.
    """

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
        join_path: Arg.Switch('-j', group='PATH', help=(
            'Join path names with the previously existing one. If the previously existing path has '
            'a file extension, it is removed. Then, if that path already exists on disk, a numeric '
            'extension is appended to avoid conflict with the file system.')) = False,
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

    def _get_path_separator(self) -> str:
        return self.CustomPathSeparator or '/'

    @property
    def _patterns(self):
        paths = self.args.paths
        if not paths:
            if self.args.regex:
                paths = ['.*']
            else:
                paths = [u'*']
        else:
            def to_string(t: Union[str, bytes]) -> str:
                if isinstance(t, str):
                    return t
                try:
                    return t.decode(self.codec)
                except Exception as E:
                    raise RefineryPotentialUserError(
                        F'invalid path pattern of length {len(t)};'
                        U' if that path exists on disk, these are the file contents.'
                        U' to prevent this, specify s:path.txt rather than path.txt.'
                    ) from E
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
        root = ''
        uuid = 0

        def path_exists(p: str):
            try:
                return os.path.exists(p) and not os.path.isdir(p)
            except Exception:
                return False

        def get_data(result: UnpackResult):
            try:
                data = result.get_data()
            except RefineryPartialResult as error:
                if not self.args.lenient:
                    raise
                result.data = data = error.partial
            return data

        def _uuid():
            nonlocal uuid
            crc = meta['crc32'].decode('ascii').upper()
            uid = uuid
            uuid += 1
            return F'_{crc}.{uid:04X}'

        def normalize(_path: str) -> str:
            pathsep = self.CustomPathSeparator
            pattern = '[\\\\/]'
            if pathsep is None:
                pathsep = '/'
            else:
                pattern = re.escape(pathsep)
            parts = re.split(pattern, F'{root}{pathsep}{_path}')
            while True:
                for k, part in enumerate(parts):
                    if not part.strip('.'):
                        break
                else:
                    break
                size = len(part)
                j = max(k - size, 0)
                del parts[j:k + 1]
            path = pathsep.join(parts)
            return path

        if self.args.join:
            try:
                root = str(ByteStringWrapper(meta[metavar], self.codec))
            except KeyError:
                pass
            if path_exists(root):
                root, _, rest = root.rpartition('.')
                root = root or rest
            _rr = root
            _rk = 1
            while path_exists(root):
                root = F'{_rr}.{_rk}'

        for result in results:
            path = normalize(result.path)
            if not path:
                from refinery.lib.mime import FileMagicInfo
                path = _uuid()
                ext = FileMagicInfo(get_data(result)).extension
                if ext != 'bin':
                    path = F'{path}.{ext}'
                self.log_warn(F'read chunk with empty path; using generated name {path}')
            result.path = path
            occurrences[path] += 1

        for result in results:
            path = result.path
            if occurrences[path] > 1:
                checksum = adler32(get_data(result))
                if checksum in checksums[path]:
                    continue
                checksums[path].add(checksum)
                counter = len(checksums[path])
                base, extension = os.path.splitext(path)
                width = len(str(occurrences[path]))
                if any(F'{base}.v{c:0{width}d}{extension}' in occurrences for c in range(occurrences[path])):
                    result.path = F'{base}.{_uuid()}{extension}'
                else:
                    result.path = F'{base}.v{counter:0{width}d}{extension}'
                self.log_warn(F'read chunk with duplicate path; deduplicating to {result.path}')

        if len({r.path.lower() for r in results}) == len(results):
            for p in patterns:
                p.compile(flags=re.IGNORECASE)

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
                        chunk = get_data(result)
                    except Exception as error:
                        if self.log_debug():
                            raise
                        self.log_warn(F'extraction failure for {path}: {exception_to_string(error)}')
                    else:
                        self.log_debug(F'extraction success for {path}')
                        yield self.labelled(chunk, **result.meta)
                if done or self.args.fuzzy:
                    break


class XMLToPathExtractorUnit(PathExtractorUnit, abstract=True):
    def __init__(
        self, *paths,
        format: Arg('-f', type=str, metavar='F', help=(
            'A format expression to be applied for computing the path of an item. This must use '
            'metadata that is available on the item. The current tag can be accessed as {{tag}}. '
            'If no format is specified, the unit attempts to derive a good attribute from the XML '
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

        nfmt = self.args.format
        nkey = self._normalize_key
        nval = self._normalize_val
        nmap = {}

        if nfmt is None:
            def rank_attribute(attribute: str):
                length = len(attribute)
                scount = length - len(re.sub(r'\s+', '', attribute))
                return (1 / length, scount)

            def walk(node: XMLNodeBase):
                candidates = [
                    candidate for candidate, count in Counter(
                        key for child in node.children for key, val in child.attributes.items()
                        if len(val) in range(2, 65) and re.fullmatch(R'[-\s\w+,.;@()]+', nval(val))
                    ).items()
                    if count == len(node.children) == len(
                        {child.attributes[candidate] for child in node.children})
                ]
                if not candidates:
                    attr = None
                else:
                    candidates.sort(key=rank_attribute)
                    attr = candidates[0]
                for child in node.children:
                    nmap[child.path] = attr
                    walk(child)

            walk(root)

        def path_builder(node: XMLNodeBase) -> str:
            attrs = node.attributes
            if nfmt and meta is not None:
                try:
                    symbols = {nkey(key): nval(val) for key, val in attrs.items()}
                    return meta.format_str(nfmt, self.codec, node.tag, symbols)
                except KeyError:
                    pass
            try:
                return nval(attrs[nmap[node.path]])
            except KeyError:
                index = node.index
                name = nval(node.tag)
                if index is not None:
                    name = F'{name}/{index}'
                return name

        return path_builder
