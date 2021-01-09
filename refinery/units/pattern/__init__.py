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
from ...lib.loader import load_commandline
from .. import arg, Unit


class TransformSubstitutionFactory:
    """
    Produces a substitution callable for `refinery.resub` and `refinery.rex`.

    This substitution callable supports refinery operations to be applied to
    match groups. The format `fmt` can contain expressions of the form `$0`,
    `$1`, etc. to be substituted by the corresponding match group from the
    regular expression. Additionally, more complex expressions are supported
    which allow application of arbitrary refinery units to the match group.
    For example, the expression
    ```
    $(1 | hex | add 0x12 | gz)
    ```
    takes the match group with index 1, hex decodes it, adds the value `0x12`
    to every byte and then decompresses it using gzip. To escape a dollar
    symbol, prefix it with an additional dollar symbol.

    Expressions can be nested: For example, `$(1 | snip :$2)` would assume
    that the second match group is an integer k and return only the first k
    bytes of the first match group.
    """

    @staticmethod
    def unescape(s): return re.sub(RB'(\$+)\$', lambda m: m[1], s)

    def __init__(self, formatting, meta, root=True):
        class PipeLine:
            def __init__(self, argument, seam, pipeline):
                if argument.isdigit():
                    self.indexarg = True
                    self.argument = int(argument, 10)
                else:
                    self.indexarg = False
                    self.argument = argument
                self.blueprints = [TransformSubstitutionFactory(command, meta, root=False) for command in pipeline]
                self.seam = TransformSubstitutionFactory.unescape(seam)

            def __call__(self, match):
                if self.indexarg:
                    data = match.group(self.argument)
                else:
                    data = match.groupdict().get(self.argument)
                    if data is None: data = meta[self.argument]
                for blueprint in self.blueprints:
                    unit = blueprint(match)
                    data = unit(data)
                return self.seam + data

        if not isinstance(formatting, str):
            formatting = formatting.decode('unicode-escape')

        formatting = formatting.encode('latin-1', 'backslashreplace')
        escapes = {m.start() + 1 for m in re.finditer(BR'\$\$', formatting)}
        pipelines = []
        offset = stop = 0
        pattern = re.compile(BR'\$(\w+|\(\w+)')

        while True:
            expression = pattern.search(formatting, stop)
            if not expression:
                break
            start, stop = expression.span()
            if start in escapes:
                continue
            argument = expression[1]
            if argument.startswith(B'('):
                level = 1
                poles = [expression.start() + 2]
                while level > 0:
                    if stop > len(formatting):
                        raise ValueError(F'unbalanced parentheses at {stop} for expression: {formatting}')
                    if formatting[stop:stop + 1] == B'(':
                        level += 1
                    if formatting[stop:stop + 1] == B')':
                        level -= 1
                    if formatting[stop:stop + 1] == B'|' and level == 1:
                        poles.append(stop + 1)
                    stop += 1

                poles.append(stop)
                pipeline = [
                    formatting[a:b - 1].decode('UTF8').strip()
                    for a, b in zip(poles, poles[1:])
                ]
                argument = pipeline.pop(0)
            else:
                pipeline = []

            pipelines.append(PipeLine(
                argument,
                formatting[offset:start],
                pipeline
            ))
            offset = stop

        assert offset or not pipelines
        self.root = root
        self.pipelines = pipelines
        self.epilog = self.unescape(formatting[offset:])
        self.unitcache = None

    def __call__(self, match):
        if self.pipelines:
            result = B''.join(p(match) for p in self.pipelines) + self.epilog
        else:
            unit = self.unitcache
            if unit:
                return unit
            result = self.epilog
        if self.root:
            return result
        self.unitcache = unit = load_commandline(result.decode('utf8'))
        return unit


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
            for zm in re.findall(BR'(?:.\0)+', data):
                for match in pattern.finditer(zm[::2]):
                    yield match

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
        if isinstance(regex, str):
            regex = regex.encode(self.codec)
        super().__init__(regex=re.compile(regex, flags=flags), count=count, **keywords)
