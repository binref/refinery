"""
A package containing several sub-packages for various data formats.
"""
from __future__ import annotations

import abc
import collections
import codecs
import fnmatch
import re

from zlib import adler32
from collections import Counter
from typing import ByteString, Iterable, Callable, List, Union, Optional

from refinery.units import Arg, Unit, Chunk, RefineryPartialResult, RefineryPotentialUserError
from refinery.lib.meta import metavars, ByteStringWrapper, LazyMetaOracle
from refinery.lib.xml import XMLNodeBase
from refinery.lib.tools import exception_to_string
from refinery.lib.json import BytesAsArrayEncoder, BytesAsStringEncoder
from refinery.lib.loader import load


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
    """
    This unit is a path extractor which extracts data from a hierarchical structure. Each extracted
    item is emitted as a separate chunk and has attached to it a meta variable that contains its
    path within the source structure. The positional arguments to the command are patterns that can
    be used to filter the extracted items by their path. To view only the paths of all chunks, use
    the listing switch:

        emit something | <this> --list

    Otherwise, extracted items are written to the standard output port and usually require a frame
    to properly process. In order to dump all extracted data to disk, the following pipeline can be
    used:

        emit something | <this> [| dump {path} ]
    """

    CustomPathSeparator = None
    """
    This class variable can be overwritten by child classes to change the path separator from the
    default forward slash to something else.
    """

    def __init__(
        self,
        *paths: Arg.PathVar(metavar='path', nargs='*', help=(
            'Wildcard pattern for the path of the item to be extracted. Each item is returned '
            'as a separate output of this unit. Paths may contain wildcards; The default '
            'argument is a single wildcard, which means that every item will be extracted. If '
            'a given path yields no results, the unit performs increasingly fuzzy searches '
            'with it. This can be disabled using the --exact switch.')),
        list: Arg.Switch('-l',
            help='Return all matching paths as UTF8-encoded output chunks.') = False,
        join_path: Arg.Switch('-j', group='PATH', help=(
            'Join path names with the previously existing one.')) = False,
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
            def check_pattern(t: Union[str, bytes]) -> str:
                try:
                    if len(t) >= 0x1000:
                        raise OverflowError
                    if not isinstance(t, str):
                        t = codecs.decode(t, self.codec)
                except Exception as E:
                    raise RefineryPotentialUserError(
                        F'Invalid path pattern of length {len(t)}.') from E
                else:
                    return t
            paths = [check_pattern(p) for p in paths]
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
    def unpack(self, data: Chunk) -> Iterable[UnpackResult]:
        raise NotImplementedError

    def process(self, data: Chunk) -> ByteString:
        meta = metavars(data)
        results: List[UnpackResult] = list(self.unpack(data))

        patterns = self._patterns

        metavar = self.args.path.decode(self.codec)
        occurrences = collections.defaultdict(int)
        checksums = collections.defaultdict(set)
        root = ''
        uuid = 0

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
                slash = self._get_path_separator()
                if any(F'{result.path}{slash}{c}' in occurrences for c in range(occurrences[path])):
                    counter = _uuid()
                result.path = F'{result.path}{slash}{counter}'
                self.log_info(F'read chunk with duplicate path; deduplicating to {result.path}')

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
                    name = F'{index}.{name}'
                return name

        return path_builder


class JSONEncoderUnit(Unit, abstract=True):
    """
    An abstract unit that provides the interface for displaying parsed data as JSON. By default,
    binary data is converted to latin1 strings.
    """

    EncoderBase = BytesAsStringEncoder

    def __init__(
        self,
        encode: Arg.String('-e', group='BIN', metavar='U', help=(
            'Select an encoder unit used to represent binary data in the JSON output. This unit '
            'must be reversible and produce UTF8 encoded string output when operated in reverse.'
            ' Common examples are hex and b64.')) = None,
        digest: Arg.String('-d', group='BIN', metavar='U', help=(
            'Select a hashing unit to digest all byte strings: Instead of the data, only the hash '
            'will be displayed.')) = None,
        arrays: Arg.Switch('-a', group='BIN', help=(
            'Encode all byte strings as integer arrays. These arrays will have unsigned integer '
            'entires between 0 and 255.')) = False,
        **keywords
    ):
        if sum(1 for x in (encode, digest, arrays) if x) > 1:
            raise ValueError('Can only set one option for byte string encoding.')
        super().__init__(encode=encode, digest=digest, arrays=arrays, **keywords)

    def to_json(self, obj) -> bytes:
        def UnitEncoderFactory(unit: Unit):
            class Encoder(self.EncoderBase):
                def encode_bytes(self, obj):
                    return obj | unit | str
            return Encoder
        if self.args.arrays:
            encoder = BytesAsArrayEncoder
        elif u := self.args.encode:
            encoder = UnitEncoderFactory(load(u, reverse=True))
        elif u := self.args.digest:
            encoder = UnitEncoderFactory(load(u, text=True))
        else:
            encoder = self.EncoderBase

        with encoder as enc:
            return enc.dumps(obj).encode(self.codec)
