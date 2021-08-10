#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pattern matching based extraction and substitution units.
"""
import re

from typing import Iterable, Optional, Callable, Union, ByteString, Dict
from itertools import islice
from hashlib import blake2b

from ...lib.types import INF, AST
from ...lib.argformats import regexp
from .. import arg, Unit


class PatternExtractorBase(Unit, abstract=True):

    def __init__(
        self,
        min        : arg.number('-n', help='Matches must have length at least N.') = 1,
        max        : arg.number('-N', help='Matches must have length at most N.') = None,
        len        : arg.number('-E', help='Matches must be of length N.') = None,
        stripspace : arg.switch('-S', help='Strip all whitespace from input data.') = False,
        duplicates : arg.switch('-D', help='Yield every (transformed) Match, even when it was found before.') = False,
        longest    : arg.switch('-l', help='Sort results by length.') = False,
        take       : arg.number('-t', help='Return only the first N occurrences in order of appearance.') = None,
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

    def matches(self, data: ByteString, pattern: Union[ByteString, re.Pattern]):
        """
        Searches the input data for the given regular expression pattern. If the
        argument `utf16` is `True`, search for occurrences where a zero byte
        is between every character of the match. The `ascii` option allows to
        control whether normal matching results are also returned.
        """
        if not isinstance(pattern, re.Pattern):
            pattern = re.compile(pattern)
        if self.args.ascii:
            yield from pattern.finditer(data)
        if self.args.utf16:
            for zm in re.findall(BR'(?:.\0)+', data, flags=re.DOTALL):
                yield from pattern.finditer(zm[::2])

    def _prefilter(self, matches: Iterable[re.Match]) -> Iterable[re.Match]:
        barrier = set()
        taken = 0
        for match in matches:
            hit = memoryview(match[0])
            if not hit or len(hit) != self.args.len or len(hit) < self.args.min or len(hit) > self.args.max:
                continue
            if not self.args.duplicates:
                uid = int.from_bytes(blake2b(hit, digest_size=8).digest(), 'big')
                if uid in barrier:
                    continue
                barrier.add(uid)
            yield match
            taken += 1
            if not self.args.longest and taken >= self.args.take:
                break

    def _postfilter(self, matches: Iterable[re.Match]) -> Iterable[re.Match]:
        result = matches
        if self.args.longest and self.args.take and self.args.take is not INF:
            try:
                length = len(result)
            except TypeError:
                result = list(result)
                length = len(result)
            indices = sorted(range(length), key=lambda k: len(result[k][0]), reverse=True)
            for k in sorted(islice(indices, abs(self.args.take))):
                yield result[k]
        elif self.args.longest:
            yield from sorted(result, key=len, reverse=True)
        elif self.args.take:
            yield from islice(result, abs(self.args.take))

    def matchfilter(self, matches: Iterable[re.Match]) -> Iterable[re.Match]:
        yield from self._postfilter(self._prefilter(matches))

    def matches_filtered(
        self,
        data: ByteString,
        pattern: Union[ByteString, re.Pattern],
        *transforms: Optional[Iterable[Callable[[re.Match], Optional[Union[Dict, ByteString]]]]]
    ) -> Iterable[Union[Dict, ByteString]]:
        """
        This is a wrapper for `AbstractRegexUint.matches` which filters the
        results according to the given commandline arguments. Returns a
        dictionary mapping its position (start, end) in the input data to the
        filtered and transformed match that was found at this position.
        """
        def funcify(t):
            def const(m): return t
            return t if callable(t) else const

        transforms = [funcify(f) for f in transforms] or [lambda m: m[0]]

        if self.args.stripspace:
            data = re.sub(BR'\s+', B'', data)
        for match in self.matchfilter(self.matches(memoryview(data), pattern)):
            for transform in transforms:
                t = transform(match)
                if t is not None: yield t


class PatternExtractor(PatternExtractorBase, abstract=True):
    def __init__(
        self, min=1, max=None, len=None, stripspace=False, duplicates=False, longest=False, take=None,
        ascii: arg.switch('-u', '--no-ascii', group='AvsU', help='Search for UTF16 encoded patterns only.') = True,
        utf16: arg.switch('-a', '--no-utf16', group='AvsU', help='Search for ASCII encoded patterns only.') = True,
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
        self, regex: arg(type=regexp, help='Regular expression to match.'),
        multiline: arg.switch('-M',
            help='Caret and dollar match the beginning and end of a line, a dot does not match line breaks.') = False,
        ignorecase: arg.switch('-I',
            help='Ignore capitalization for alphabetic characters.') = False,
        count: arg.number('-c', help='Specify the maximum number of operations to perform.') = 0,
        **keywords
    ):
        flags = re.MULTILINE if multiline else re.DOTALL
        if ignorecase:
            flags |= re.IGNORECASE
        super().__init__(regex=regex, flags=flags, count=count, **keywords)

    @property
    def regex(self):
        flags = self.args.flags
        regex = self.args.regex
        if isinstance(regex, str):
            regex = regex.encode(self.codec)
        return re.compile(regex, flags=flags)
