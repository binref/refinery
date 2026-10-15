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

from refinery.lib import json as libjson
from refinery.lib.argformats import pathvar
from refinery.lib.loader import load
from refinery.lib.meta import (
    MV,
    ByteStringWrapper,
    LazyMetaOracle,
    check_variable_names_of_unit,
    metavars,
)
from refinery.lib.tools import HandOver, exception_to_string, get_terminal_size
from refinery.lib.types import Callable, Iterable, NamedTuple, Param, buf, isbuffer
from refinery.lib.xml import XMLNodeBase
from refinery.units import Arg, Chunk, RefineryPartialResult, RefineryPotentialUserError, Unit


def pathspec(expression):
    """
    Normalizes a path which is separated by backward or forward slashes to be
    separated by forward slashes.
    """
    return '/'.join(re.split(R'[\\\/]', expression))


def number_repeated_names(names: list[str], separator: str = '/') -> list[str]:
    """
    Returns the given names in their order, with a number appended to every name that occurs more
    than once: the copies of a name are counted in order, and a number is skipped when the numbered
    name would be equal to another given name or to an earlier numbered one. No two returned names
    are equal. Path extractors use this for repeated paths and for repeated names of groups, such as
    two tables or archives with one name.
    """
    occurrences = Counter(names)
    taken = set(occurrences)
    counters: Counter[str] = Counter()
    numbered: list[str] = []
    for name in names:
        if occurrences[name] < 2:
            numbered.append(name)
            continue
        while True:
            counters[name] += 1
            candidate = F'{name}{separator}{counters[name]}'
            if candidate not in taken:
                break
        taken.add(candidate)
        numbered.append(candidate)
    return numbered


class UnpackResult:

    def get_data(self) -> buf:
        if (data := self.data) is None:
            raise RuntimeError(F'The data of {self.path} was already handed out.')
        if callable(data):
            self.data = data = data()
        return data

    def release(self):
        """
        Drops the data of this result; it cannot be retrieved afterwards.
        """
        self.data = None

    def __init__(self, _br__path: str, _br__data: buf | Callable[[], buf], **_br__meta):
        check_variable_names_of_unit(_br__meta)
        self.path = _br__path
        self.data: buf | Callable[[], buf] | None = _br__data
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

    def compile(self):
        query = self.query
        self.stops = []
        if not self.regex:
            self.stops = re.split(R'([/*?]+)', query)
            query = fnmatch.translate(query)
            for anchor in (R'\Z', R'\z'):
                query = query.removesuffix(anchor)
        p1 = re.compile(query)
        p2 = re.compile(F'.*?{query}')
        p3 = re.compile(query, re.IGNORECASE)
        self.matchers = [p1.fullmatch, p2.fullmatch, p1.search]
        self.matchers_ignoring_case = [p3.fullmatch, p2.fullmatch, p3.search]

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

    def check(self, path, fuzzy=0, ignorecase=False):
        fuzzy = min(fuzzy, 2)
        matchers = self.matchers_ignoring_case if ignorecase else self.matchers
        return bool(matchers[fuzzy](path))

    def __repr__(self):
        return F'<PathPattern:{"".join(self.stops) or "RE"}>'


class _Selectable(NamedTuple):
    result: UnpackResult
    names: tuple[str, ...]
    ignorecase: bool


def _caseless(name: str) -> str:
    """
    Folds the case of the given name at least as far as a case-insensitive regular expression does:
    Two names that such an expression cannot tell apart get the same result.
    """
    return name.casefold().replace(chr(0x131), 'i').replace(chr(0x307), '')


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
    item. When several items have the same path, each of them gets a number appended to its path in
    the order in which <this> lists them, and a pattern that matches the path before the number
    selects all of them. When using <this> to unpack a file on disk, the following pattern can be
    useful:

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
            '"{default}".'))] = MV.PATH.encode(),
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

    def _select(self, pattern: PathPattern, candidates: list[_Selectable]) -> list[UnpackResult]:
        """
        Returns the results that the given pattern matches by one of their names. If the pattern
        matches nothing and neither exact nor fuzzy matching is configured, its fuzziness is
        increased until at least one result matches.
        """
        matches = []
        for fuzzy in range(min(self.args.fuzzy, 2), 3):
            matches = [
                candidate.result for candidate in candidates
                if any(pattern.check(name, fuzzy, candidate.ignorecase) for name in candidate.names)
            ]
            if matches or self.args.exact or self.args.fuzzy:
                break
        return matches

    @abc.abstractmethod
    def unpack(self, data: Chunk) -> Iterable[UnpackResult]:
        raise NotImplementedError

    def _get_data(self, result: UnpackResult) -> buf:
        try:
            return result.get_data()
        except RefineryPartialResult as error:
            if not self.args.lenient:
                raise
            self.log_warn(F'extracting {result.path} despite an error: {error!s}')
            result.data = data = error.partial
            return data

    def _data_unless_unreadable(self, result: UnpackResult) -> buf | None:
        """
        The data of the given result, or `None` if reading it fails; the failure is reported when
        the result is extracted.
        """
        try:
            return self._get_data(result)
        except Exception:
            return None

    def _number_repeated_paths(self, results: list[UnpackResult]) -> dict[UnpackResult, str]:
        """
        Appends a number to the path of every result whose path repeats, as `number_repeated_names`
        does. Returns the path that each numbered result had before.
        """
        paths = number_repeated_names([result.path for result in results], self._get_path_separator())
        bases: dict[UnpackResult, str] = {}
        for result, path in zip(results, paths):
            if path == result.path:
                continue
            bases[result] = result.path
            result.path = path
            self.log_info(F'read chunk with duplicate path; deduplicating to {path}')
        return bases

    @staticmethod
    def _selectable(
        results: list[UnpackResult],
        bases: dict[UnpackResult, str],
    ) -> list[_Selectable]:
        """
        Pairs every result with the names by which a pattern selects it: its path and, for a
        numbered result, its path before the number as given in `bases`. A pattern ignores case for
        a result unless one of these names differs only by case from a name of a result that has
        another path before the number.
        """
        owners: dict[str, set[str]] = collections.defaultdict(set)
        for result in results:
            base = bases.get(result, result.path)
            owners[_caseless(result.path)].add(base)
            owners[_caseless(base)].add(base)
        ambiguous = {base for shared in owners.values() if len(shared) > 1 for base in shared}
        selectable = []
        for result in results:
            if (base := bases.get(result)) is None:
                names = (result.path,)
                base = result.path
            else:
                names = (result.path, base)
            selectable.append(_Selectable(result, names, base not in ambiguous))
        return selectable

    def _selection(self, data: Chunk, metavar: str) -> collections.deque[UnpackResult]:
        """
        Unpacks the input and returns the results that the path patterns select, in the order in
        which they are extracted. A result appears once for every pattern that selects it.
        """
        meta = metavars(data)
        results: list[UnpackResult] = list(self.unpack(data))

        patterns = self._patterns

        root = ''
        uuid = 0

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
                parents = max(len(part) - 1, 0)
                del parts[max(k - parents, 0):k + 1]
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
                ext = 'bin'
                if (content := self._data_unless_unreadable(result)) is not None:
                    ext = FileMagicInfo(content).extension
                if ext != 'bin':
                    path = F'{path}.{ext}'
                self.log_warn(F'read chunk with empty path; using generated name {path}')
            result.path = path

        bases = self._number_repeated_paths(results)
        candidates = self._selectable(results, bases)

        includes = [p for p in patterns if not p.exclude]
        excludes = [p for p in patterns if p.exclude]

        if excludes:
            discard = set()
            for x in excludes:
                discard.update(self._select(x, candidates))
            candidates = [c for c in candidates if c.result not in discard]

        return collections.deque(result for p in includes for result in self._select(p, candidates))

    def _extract(self, result: UnpackResult, release: bool) -> Chunk | None:
        path = result.path
        try:
            data = self._get_data(result)
        except Exception as error:
            if self.log_debug():
                raise
            message = exception_to_string(error)
            if path not in message:
                message = F'extraction failure for {path}: {message}'
            if isinstance(error, RefineryPartialResult):
                message = F'{message} (use -L to extract it anyway)'
            self.log_warn(message)
            return None
        self.log_debug(F'extraction success for {path}')
        if release:
            result.release()
        return self.labelled(data, **result.meta)

    def process(self, data: Chunk):
        metavar = self.args.path.decode(self.codec)
        selection = self._selection(data, metavar)
        remaining = Counter(selection)
        while selection:
            result = selection.popleft()
            last = remaining[result] == 1
            if last:
                del remaining[result]
            else:
                remaining[result] -= 1
            path = result.path
            if self.args.list:
                yield self.labelled(path.encode(self.codec), **result.meta)
                continue
            if not self.args.drop:
                result.meta[metavar] = path
            yield from HandOver(self._extract(result, release=last))


def read_parts(
    unit: Unit,
    data: buf,
    extractor: type[PathExtractorUnit],
    *names: str,
) -> list[Chunk | None]:
    """
    Unpacks the given container once with the given extractor and returns, for each given name, the
    first item that the extractor lists under this name, or `None` if there is none or it cannot be
    read. A name that differs only by case or by backslashes in place of forward slashes is used
    when no item has the exact name. No other item is read. The given unit warns when more than one
    item has a name and reports why an item cannot be read.
    """
    def folded(name: str) -> str:
        return name.replace('\\', '/').lower()
    items = list(extractor().unpack(Chunk.Wrap(data)))
    parts: list[Chunk | None] = []
    for name in names:
        if not (named := [item for item in items if item.path == name]):
            named = [item for item in items if folded(item.path) == folded(name)]
        if not named:
            parts.append(None)
            continue
        if (count := len(named)) > 1:
            unit.log_warn(F'the input has {count} items named {name}; reading the first one')
        try:
            parts.append(Chunk.Wrap(named[0].get_data()))
        except Exception as error:
            unit.log_info(F'failed to read {name}: {exception_to_string(error)}')
            parts.append(None)
    return parts


def read_part(
    unit: Unit,
    data: buf,
    extractor: type[PathExtractorUnit],
    name: str,
) -> Chunk | None:
    """
    The result of `read_parts` for a single name.
    """
    [part] = read_parts(unit, data, extractor, name)
    return part


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
        path=MV.PATH.encode(), exclude=None, **keywords
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

    @staticmethod
    def _rank_attribute(attribute: str):
        length = len(attribute)
        scount = length - len(re.sub(r'\s+', '', attribute))
        return (1 / length, scount)

    @classmethod
    def _map_path_attributes(cls, node: XMLNodeBase, nmap: dict):
        """
        Maps the path of every node below the given one to the attribute that names it among its
        siblings, or to `None` if there is no such attribute.
        """
        nval = cls._normalize_val
        children = node.children
        tags = set()
        for child in children:
            if (tag := child.tag) not in tags:
                tags.add(tag)
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
            candidates.sort(key=cls._rank_attribute)
            attr = candidates[0]
        for child in children:
            nmap[child.path] = attr
            cls._map_path_attributes(child, nmap)

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
            self._map_path_attributes(root, nmap)

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
