"""
A package containing several sub-packages for various data formats.
"""
from __future__ import annotations

import abc
import codecs
import collections
import fnmatch
import re

from collections import Counter
from zlib import adler32

from refinery.lib import json as libjson
from refinery.lib.argformats import pathvar
from refinery.lib.loader import load
from refinery.lib.meta import ByteStringWrapper, LazyMetaOracle, metavars
from refinery.lib.tools import exception_to_string, get_terminal_size
from refinery.lib.types import Callable, Iterable, Param, buf, isbuffer
from refinery.lib.xml import XMLNodeBase
from refinery.units import Arg, Chunk, RefineryPartialResult, RefineryPotentialUserError, Unit


def pathspec(expression):
    """
    Normalizes a path which is separated by backward or forward slashes to be
    separated by forward slashes.
    """
    return '/'.join(re.split(R'[\\\/]', expression))


class UnpackResult:

    def get_data(self) -> buf:
        if callable(self.data):
            self.data = self.data()
        return self.data

    def __init__(self, _br__path: str, _br__data: buf | Callable[[], buf], **_br__meta):
        self.path = _br__path
        self.data = _br__data
        self.meta = _br__meta
        for key in [key for key, value in _br__meta.items() if value is None]:
            del _br__meta[key]


class EndOfStringNotFound(ValueError):
    def __init__(self):
        super().__init__('end of string could not be determined')


class PathPattern:
    def __init__(self, query: str, regex=False, exclude=False):
        self.query = query
        self.regex = regex
        self.exclude = exclude
        self.compile()

    def compile(self, **kw):
        query = self.query
        self.stops = []
        if not self.regex:
            self.stops = re.split(R'([/*?]+)', query)
            query, _, _ = fnmatch.translate(query).partition(r'\Z')
        p1 = re.compile(query, **kw)
        p2 = re.compile(F'.*?{query}')
        self.matchers = [p1.fullmatch, p2.fullmatch, p1.search]

    def reach(self, path: str):
        """
        A heuristic over-approximation of whether the pattern can select any file for extraction
        that has the given path as a parent; it is used to prune subtrees. For exact wildcard
        matching it is sound: it may return `True` spuriously, but it does not return `False` while
        a matching file could still exist below `path`. It does not model fuzzy matching (`-z`),
        under which a multi-component pattern can match a path below one for which this returns
        `False`. Regular expressions are not analyzed and always return `True`. An exclusion pattern
        cannot select a file for extraction and therefore always returns `False`. Subtree pruning
        is driven entirely by the inclusion patterns.
        """
        if self.exclude:
            return False
        if len(self.stops) <= 1:
            return True
        for stop in self.stops[0::2]:
            if fnmatch.fnmatch(path, F'*{stop}*'):
                return True
        return False

    def check(self, path, fuzzy=0):
        fuzzy = min(fuzzy, 2)
        return bool(self.matchers[fuzzy](path))

    def __repr__(self):
        return F'<PathPattern:{"".join(self.stops) or "RE"}>'


class PathExtractorUnit(Unit, abstract=True):
    """
    This unit extracts items with an associated virtual path from a container; each extracted item
    is emitted as a separate chunk with a corresponding meta variable named "path".

    Positional arguments to <this> are patterns to filter the extracted items. Use the `-x` flag to
    add an exclusion pattern. To extract all files with a foo or bar extension, but none that has
    the word "temp" in its path:

        <this> .foo .bar -x temp

    To view only the paths of all chunks, use the listing switch:

        emit data | ... | <this> -l

    Otherwise, extracted items are written to the standard output port and usually require a frame
    to properly process. In order to dump all extracted data to disk, the following pipeline can be
    used:

        emit data | ... | <this> [| dump extracted/{path} ]

    The value `{path}` is a placeholder which is substituted by the virtual path of the extracted
    item. When using <this> to unpack a file on disk, the following pattern can be useful:

        ef pack.bin [| <this> -j | d2p ]

    The unit `refinery.ef` is also a path extractor. By specifying `-j` (or `--join`), the paths of
    extracted items are combined. Here, `refinery.d2p` is a shortcut for `dump {path}`. It
    deconflicts the joined paths with the local file system: If `pack.bin` contains items `one.txt`
    and `two.txt`, the following local file tree would be the result:

        pack.bin
        pack/one.txt
        pack/two.txt

    Finally, the `-d` (or `--drop`) switch can be used to not create (or alter) the path metadata
    at all, which is useful in cases where path metadata from a previous unit should be preserved.
    """

    CustomJoinBehaviour = '{root}{sep}{path}'
    """
    This class variable can be overwritten to change how paths are joined.
    """

    CustomPathSeparator = None
    """
    This class variable can be overwritten by child classes to change the path separator from the
    default forward slash to something else.
    """

    def __init__(
        self,
        *paths: Param[str, Arg.FsPath(metavar='pattern', nargs='*', help=(
            'A path pattern selecting items to extract; each match becomes a separate output chunk.'
            ' The default is a single wildcard and extracts everything. Queries that yield no match'
            ' are retried with increasing fuzziness unless the exact matching option is set.'))],
        exclude: Param[list | None, Arg('-x', metavar='P', action='append', type=pathvar, help=(
            'Adds an exclusion pattern P: Matching paths are not emitted at all. Exclusions also '
            'use increasing fuzziness if they exclude nothing.'))] = None,
        list: Param[bool, Arg.Switch('-l',
            help='Return all matching paths as UTF8-encoded output chunks.')] = False,
        join_path: Param[bool, Arg.Switch('-j', group='PATH', help=(
            'Join path names with the previously existing one.'))] = False,
        drop_path: Param[bool, Arg.Switch('-d', group='PATH',
            help='Do not modify the path variable for output chunks.')] = False,
        fuzzy: Param[int, Arg.Counts('-z', group='MATCH', help=(
            'Adds a leading wildcard to each pattern, use -zz to also add a trailing one.'))] = 0,
        exact: Param[bool, Arg.Switch('-e', group='MATCH',
            help='Path patterns never match on substrings.')] = False,
        regex: Param[bool, Arg.Switch('-r',
            help='Use regular expressions instead of wildcard patterns.')] = False,
        path: Param[buf, Arg('-P', metavar='NAME', help=(
            'Name of the meta variable to receive the extracted path. The default value is '
            '"{default}".'))] = b'path',
        **keywords
    ):
        super().__init__(
            paths=paths,
            exclude=exclude,
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
        def check_pattern(t: str) -> str:
            try:
                if len(t) >= 0x1000:
                    raise OverflowError
            except Exception as E:
                raise RefineryPotentialUserError(
                    F'Invalid path pattern of length {len(t)}.') from E
            else:
                return t
        paths = self.args.paths
        if not paths:
            paths = ['.*'] if self.args.regex else ['*']
        else:
            paths = [check_pattern(p) for p in paths]
        patterns = [
            PathPattern(path, self.args.regex) for path in paths
        ]
        for query in self.args.exclude or ():
            patterns.append(PathPattern(check_pattern(query), self.args.regex, exclude=True))
        return patterns

    def _select(self, pattern: PathPattern, results: list[UnpackResult]) -> list[UnpackResult]:
        """
        Returns the results whose path is matched by the given pattern. If the pattern matches
        nothing and neither exact nor fuzzy matching is configured, its fuzziness is increased
        until at least one result matches.
        """
        matches = []
        for fuzzy in range(min(self.args.fuzzy, 2), 3):
            matches = [r for r in results if pattern.check(r.path, fuzzy)]
            if matches or self.args.exact or self.args.fuzzy:
                break
        return matches

    @abc.abstractmethod
    def unpack(self, data: Chunk) -> Iterable[UnpackResult]:
        raise NotImplementedError

    def process(self, data: Chunk) -> buf:
        meta = metavars(data)
        results: list[UnpackResult] = list(self.unpack(data))

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
            if (pathsep := self.CustomPathSeparator):
                pattern = re.escape(pathsep)
            else:
                pattern = '[\\\\/]'
                pathsep = '/'
            parts = re.split(pattern, self.CustomJoinBehaviour.format(
                root=root, sep=pathsep, path=_path))
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

        includes = [p for p in patterns if not p.exclude]
        excludes = [p for p in patterns if p.exclude]

        if excludes:
            discard = set()
            for x in excludes:
                discard.update(self._select(x, results))
            results = [r for r in results if r not in discard]

        for p in includes:
            for result in self._select(p, results):
                path = result.path
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
                    message = exception_to_string(error)
                    if path not in message:
                        message = F'extraction failure for {path}: {exception_to_string(error)}'
                    self.log_warn(message)
                else:
                    self.log_debug(F'extraction success for {path}')
                    yield self.labelled(chunk, **result.meta)


class XMLToPathExtractorUnit(PathExtractorUnit, abstract=True):
    def __init__(
        self, *paths,
        format: Param[str | None, Arg.String('-f', metavar='F', help=(
            'A format expression to be applied for computing the path of an item. This must use '
            'metadata that is available on the item. The current tag can be accessed as {{tag}}. '
            'If no format is specified, the unit attempts to derive a good attribute from the XML '
            'tree to use for generating paths.'
        ))] = None,
        list=False, join_path=False, drop_path=False, fuzzy=0, exact=False, regex=False,
        path=b'path', exclude=None, **keywords
    ):
        super().__init__(
            *paths,
            format=format,
            exclude=exclude,
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
        a = attribute.rpartition(':')[2]
        a = re.sub(r'[^\w]+', '_', a)
        return a

    def _make_path_builder(
        self,
        meta: LazyMetaOracle,
        root: XMLNodeBase
    ) -> Callable[[XMLNodeBase], str]:

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
                children = node.children
                __tags = set()
                for child in children:
                    if (tag := child.tag) not in __tags:
                        __tags.add(tag)
                        continue
                    candidates = [
                        candidate for candidate, count in Counter(
                            key for child in children for key, val in child.attributes.items()
                            if len(val) in range(2, 65) and re.fullmatch(R'[-\s\w+,.;@()]+', nval(val))
                        ).items()
                        if count == len(children) == len(
                            {child.attributes[candidate] for child in children})
                    ]
                    break
                else:
                    candidates = None
                if not candidates:
                    attr = None
                else:
                    candidates.sort(key=rank_attribute)
                    attr = candidates[0]
                for child in children:
                    nmap[child.path] = attr
                    walk(child)

            walk(root)

        def path_builder(node: XMLNodeBase) -> str:
            if node.tag is None:
                raise ValueError(F'Attempt to format node without a tag: {node!r}')
            attrs = node.attributes
            if nfmt and meta is not None:
                try:
                    symbols = {nkey(key): nval(val) for key, val in attrs.items()}
                    return meta.format_str(nfmt, self.codec, [node.tag], symbols)
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


class JSONTableUnit(Unit, abstract=True):

    def __init__(
        self,
        tabular: Param[bool, Arg.Switch('-t', group='OUT',
            help='Do not output JSON but a flattened ASCII table.')] = False,
        minimal: Param[bool, Arg.Switch('-m', group='OUT',
            help='Minify the JSON output instead of pretty-printing.')] = False,
        **kwargs
    ):
        super().__init__(tabular=tabular, minimal=minimal, **kwargs)

    @abc.abstractmethod
    def json(self, data: Chunk) -> dict | None:
        ...

    def process(self, data: Chunk):
        if not (parsed := self.json(data)):
            return None
        if not self.args.tabular:
            pretty = not self.args.minimal
            yield libjson.dumps(parsed, pretty=pretty)
        else:
            import textwrap
            table = list(libjson.flattened(parsed))
            width = max(len(key) for key, _ in table)
            tsize = get_terminal_size() - width - 4
            for key, value in table:
                if isinstance(value, str):
                    value = value.strip()
                    if not value.isprintable() and all(ord(c) < 0x100 for c in value):
                        value = value.encode('latin1').hex(':')
                elif isinstance(value, libjson.datetime):
                    value = value.isoformat(' ', 'seconds')
                else:
                    value = str(value).rstrip()
                value = textwrap.wrap(value, tsize)
                it = iter(value)
                try:
                    item = next(it)
                except StopIteration:
                    continue
                yield F'{key:<{width}} : {item}'.encode(self.codec)
                for wrap in it:
                    yield F'{"":<{width + 3}}{wrap}'.encode(self.codec)


class JSONEncoderUnit(Unit, abstract=True):
    """
    An abstract unit that provides the interface for displaying parsed data as JSON. By default,
    binary data is converted to latin1 strings.
    """
    def __init__(
        self,
        encode: Param[str | None, Arg.String('-e', group='BIN', metavar='U', help=(
            'Select an encoder unit used to represent binary data in the JSON output. This unit '
            'must be reversible and produce UTF8 encoded string output when operated in reverse.'
            ' Common examples are hex and b64.'))] = None,
        digest: Param[str | None, Arg.String('-d', group='BIN', metavar='U', help=(
            'Select a hashing unit to digest all byte strings: Instead of the data, only the hash '
            'will be displayed.'))] = None,
        arrays: Param[bool, Arg.Switch('-a', group='BIN', help=(
            'Encode all byte strings as integer arrays. These arrays will have unsigned integer '
            'entires between 0 and 255.'))] = False,
        **keywords
    ):
        if sum(1 for x in (encode, digest, arrays) if x) > 1:
            raise ValueError('Can only set one option for byte string encoding.')
        super().__init__(encode=encode, digest=digest, arrays=arrays, **keywords)

    def to_json(self, obj, checks: bool = True) -> bytes:
        if self.args.arrays:
            _byte_converter = list
        elif u := self.args.encode:
            def _encode(o: buf):
                return o | unit | str
            unit = load(u, reverse=True)
            _byte_converter = _encode
        elif u := self.args.digest:
            def _digest(o: buf):
                return o | unit | str
            unit = load(u, test=True)
            _byte_converter = _digest
        else:
            def _str_encode(o: buf):
                return codecs.decode(o, encoding='latin1')
            _byte_converter = _str_encode

        def default(o: buf):
            if isbuffer(o):
                return _byte_converter(o)
            return libjson.standard_conversions(o)

        return libjson.dumps(obj, tojson=default, checks=checks)
