"""
Pattern matching based extraction and substitution units.
"""
from __future__ import annotations

import re

from hashlib import blake2b
from itertools import islice
from typing import TYPE_CHECKING

from refinery.lib.types import AST, INF, Callable, Iterable, Param, buf
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
        len: Param[int, Arg.Number('-e', help='Matches must be of length N.')] = 0,
        stripspace: Param[bool, Arg.Switch('-x', help='Strip all whitespace from input data.')] = False,
        duplicates: Param[bool, Arg.Switch('-r', help='Yield every (transformed) Match, even when it was found before.')] = False,
        longest: Param[bool, Arg.Switch('-l', help=(
            'Pick longer results first. The output will be sorted by length unless the --take option is specified, '
            'in which case the longest K results will be returned in order of appearance.'))] = False,
        take: Param[int, Arg.Number('-t', metavar='K', help=(
            'Return only the first K occurrences in order of appearance. If --longest is specified, the K longest '
            'results will be returned in order of appearance within the input.'))] = 0,
        **keywords
    ):
        keywords.setdefault('ascii', True)
        keywords.setdefault('utf16', True)
        super().__init__(
            min=min,
            max=max or INF,
            len=len or AST,
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
            for zm in re.finditer(BR'(.?)((?:.\0)+)', data, flags=re.DOTALL):
                a, b = zm.span(2)
                # Look one character further if there is evidence that this is UTF16-BE
                b += bool(zm[1] and data[a])
                for match in pattern.finditer(bytes(data[a:b:2])):
                    start = a + match.start() * 2
                    yield start, match

    def _prefilter(self, matches: Iterable[MT]) -> Iterable[MT]:
        barrier = set()
        taken = 0
        for offset, match in matches:
            hit = memoryview(match[0])
            if not hit or len(hit) != self.args.len or len(hit) < self.args.min or len(hit) > self.args.max:
                continue
            if not self.args.duplicates:
                uid = int.from_bytes(blake2b(hit, digest_size=8).digest(), 'big')
                if uid in barrier:
                    continue
                barrier.add(uid)
            yield offset, match
            taken += 1
            if not self.args.longest and taken >= self.args.take:
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
        self, min=1, max=None, len=None, stripspace=False, duplicates=False, longest=False, take=None,
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


class SingleRegexUnit(RegexUnit, abstract=True):

    def __init__(
        self,
        regex: Param[str, Arg.RegExp(help='Regular expression to match.')],
        count: Param[int, Arg.Number('-c', help='Specify the maximum number of operations to perform.')] = 0,
        fullmatch=False, multiline=False, ignorecase=False, **keywords
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
