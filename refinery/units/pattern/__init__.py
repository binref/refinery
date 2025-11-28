"""
Pattern matching based extraction and substitution units.
"""
from __future__ import annotations

import re

from hashlib import blake2b
from itertools import islice
from typing import TYPE_CHECKING

from refinery.lib.patterns import formats, indicators
from refinery.lib.tools import bounds
from refinery.lib.types import INF, Callable, Iterable, Param, buf
from refinery.units import Arg, Unit

if TYPE_CHECKING:
    from typing import Tuple
    MT = Tuple[int, re.Match[bytes]]
    MB = re.Match[bytes]


class PatternExtractorBase(Unit, abstract=True):

    def __init__(
        self,
        min: Param[int, Arg.Number('-n', help='Matches must have length at least N.')] = 1,
        max: Param[int, Arg.Number('-m', help='Matches must have length at most N.')] = 0,
        len: Param[int, Arg.Number('-e', help='Matches must be of length exactly N.')] = 0,
        stripspace: Param[bool, Arg.Switch('-x', help=(
            'Strip all whitespace from input before data is extracted.'
        ))] = False,
        duplicates: Param[bool, Arg.Switch('-r', help=(
            'Yield every (transformed) Match, even when it was found before.'
        ))] = False,
        longest: Param[bool, Arg.Switch('-l', help=(
            'Pick longer results first. The output will be sorted by length unless the --take '
            'option is specified, in which case the longest K results will be returned in order '
            'of appearance.'
        ))] = False,
        take: Param[int, Arg.Number('-t', metavar='K', help=(
            'Return only the first K occurrences in order of appearance. If --longest is '
            'specified, the K longest results will be returned in order of appearance within '
            'the input.'
        ))] = 0,
        **keywords
    ):
        keywords.setdefault('ascii', True)
        keywords.setdefault('utf16', True)
        super().__init__(
            min=min,
            max=max or INF,
            len=len,
            stripspace=stripspace,
            duplicates=duplicates,
            longest=longest,
            take=take or INF,
            **keywords
        )

    def matches(self, data: buf, pattern: buf | re.Pattern[bytes]):
        """
        Searches the input data for the given regular expression pattern. If the
        argument `utf16` is `True`, search for occurrences where a zero byte
        is between every character of the match. The `ascii` option allows to
        control whether normal matching results are also returned.
        """
        if not isinstance(pattern, re.Pattern):
            pattern = re.compile(pattern)
        if self.args.ascii:
            for match in pattern.finditer(data):
                yield match.start(), match
        if self.args.utf16:
            from refinery.lib.patterns import alphabet, pattern_with_size_limits
            sizes = self._getbounds()
            utf16 = alphabet('.\\0', prefix='(.?)', token_size=2, flags=re.DOTALL)
            utf16 = pattern_with_size_limits(utf16, max(1, sizes.min), abs(sizes.max))
            for zm in utf16.bin.finditer(data):
                a, b = zm.span(0)
                if zm[2] and data[(a := a + 1)]:
                    b += 1
                for match in pattern.finditer(bytes(data[a:b:2])):
                    start = a + match.start() * 2
                    yield start, match

    def _getbounds(self):
        if (n := self.args.len) > 0:
            return bounds[n]
        else:
            n = self.args.min
            m = self.args.max
            return bounds[n:m]

    def _prefilter(self, matches: Iterable[MT]) -> Iterable[MT]:
        barrier = set()
        taken = 0
        sizes = self._getbounds()
        dedup = not self.args.duplicates
        maxtake = self.args.take
        longest = self.args.longest
        for offset, match in matches:
            hit = memoryview(match[0])
            if not hit or sizes and len(hit) not in sizes:
                continue
            if dedup:
                uid = blake2b(hit, digest_size=8).digest()
                if uid in barrier:
                    continue
                barrier.add(uid)
            yield offset, match
            taken += 1
            if not longest and taken >= maxtake:
                break

    def _postfilter(self, matches: Iterable[MT]) -> Iterable[MT]:
        if (t := self.args.take) is not INF:
            if self.args.longest:
                result = matches
                if not isinstance(result, (list, tuple)):
                    result = list(result)
                indices = sorted(
                    range(len(result)),
                    key=lambda k: len(result[k][1][0]),
                    reverse=True)
                for k in sorted(islice(indices, t)):
                    yield result[k]
            else:
                yield from islice(matches, t)
        elif self.args.longest:
            def sortkey(m: MT):
                return m[1].end() - m[1].start()
            yield from sorted(matches, key=sortkey, reverse=True)
        else:
            yield from matches

    def matchfilter(self, matches: Iterable[MT]) -> Iterable[MT]:
        yield from self._postfilter(self._prefilter(matches))

    def matches_filtered(
        self,
        data: buf,
        pattern: buf | re.Pattern,
        *transforms: int | buf | Callable[[MB], buf | None],
        expose_named_groups: bool = False,
    ):
        """
        This is a wrapper for `AbstractRegexUint.matches` which filters the
        results according to the given commandline arguments. Returns a
        dictionary mapping its position (start, end) in the input data to the
        filtered and transformed match that was found at this position.
        """
        if self.args.stripspace:
            data = re.sub(BR'\s+', B'', data)
        if not transforms:
            transforms = 0,
        for k, (offset, match) in enumerate(self.matchfilter(self.matches(memoryview(data), pattern))):
            for transform in transforms:
                kwargs: dict = {
                    'offset': offset
                }
                if callable(transform):
                    transformed = transform(match)
                    if transformed is None:
                        continue
                else:
                    if isinstance(transform, int):
                        transformed = match[transform]
                    else:
                        transformed = transform
                    if expose_named_groups:
                        for key, value in match.groupdict().items():
                            if key.startswith('__'):
                                continue
                            if value is None:
                                value = B''
                            kwargs[key] = value
                chunk = self.labelled(transformed, **kwargs)
                chunk.set_next_batch(k)
                yield chunk


class PatternExtractor(PatternExtractorBase, abstract=True):
    def __init__(
        self, min=1, max=0, len=0, stripspace=False, duplicates=False, longest=False, take=0,
        ascii: Param[bool, Arg.Switch('-u', '--no-ascii', group='AvsU', help='Search for UTF16 encoded patterns only.')] = True,
        utf16: Param[bool, Arg.Switch('-a', '--no-utf16', group='AvsU', help='Search for ASCII encoded patterns only.')] = True,
        **keywords
    ):
        super().__init__(
            min=min,
            max=max,
            len=len,
            stripspace=stripspace,
            duplicates=duplicates,
            longest=longest,
            take=take,
            ascii=ascii,
            utf16=utf16,
            **keywords
        )


class RegexUnit(Unit, abstract=True):

    def __init__(
        self,
        fullmatch: Param[bool, Arg.Switch('-U', help=(
            'Regular expressions are matched against the full input, not substrings of it.'))] = False,
        multiline: Param[bool, Arg.Switch('-M', help=(
            'Caret and dollar in regular expressions match the beginning and end of a line and '
            'a dot does not match line breaks.'))] = False,
        ignorecase: Param[bool, Arg.Switch('-I', help=(
            'Ignore capitalization for alphabetic characters in regular expressions.'))] = False,
        **keywords
    ):
        flags = re.MULTILINE if multiline else re.DOTALL
        if ignorecase:
            flags |= re.IGNORECASE
        super().__init__(flags=flags, fullmatch=fullmatch, **keywords)

    def _make_matcher(self, pattern: str | buf | None, default=None):
        if pattern is None:
            return default
        regex = Arg.AsRegExp(self.codec, pattern, self.args.flags)
        if self.args.fullmatch:
            return regex.fullmatch
        else:
            return regex.search


_FMT = ',\x20'.join(p.name for p in formats)
_IOC = ',\x20'.join(p.name for p in indicators)


class SingleRegexUnit(RegexUnit, abstract=True):
    def __init__(
        self,
        regex: Param[str, Arg.RegExp(help=(
            'A regular expression to match. Besides standard Python syntax, this also supports the '
            'extension (??P) where P is any named pattern known to refinery. For example, (??date) '
            'will match on any string that looks like a date. The following are all currently '
            'available pattern names: {}, {}.'
        ).format(_IOC, _FMT))],
        count: Param[int, Arg.Number('-c', help=(
            'Specify the maximum number of operations to perform.'
        ))] = 0,
        fullmatch=False,
        multiline=False,
        ignorecase=False,
        **keywords
    ):
        super().__init__(
            regex=regex,
            count=count,
            fullmatch=fullmatch,
            multiline=multiline,
            ignorecase=ignorecase,
            **keywords
        )

    @property
    def regex(self):
        return Arg.AsRegExp(self.codec, self.args.regex, self.args.flags)


class SingleRegexTransformUnit(SingleRegexUnit, abstract=True):
    """
    Besides the syntax `{k}` to insert the `k`-th match group, the unit supports processing the
    contents of match groups with arbitrary refinery units and other multibin handlers. To do so,
    use the following syntax:

        {match-group:handlers}

    where `handlers` is an optional reverse multibin expression that is used to post-process the
    binary data from the match. For example, `{2:hex:b64}` represents the base64-decoding of the
    hex-decoding of the second match group.
    """
