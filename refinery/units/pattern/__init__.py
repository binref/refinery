#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pattern matching based extraction and substitution units.
"""
import re

from typing import Dict, Tuple, Iterable, Optional, Callable, Union, ByteString
from itertools import islice

from ...lib.types import INF, AST
from ...lib.argformats import regexp
from .. import Unit, arg


def _lazy_load(cmd: bytes):
    from ...lib.loader import load_commandline
    return load_commandline(cmd.decode('UTF8'))


def TransformSubstitutionFactory(fmt):
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

    def unescape_dollars(s):
        return re.sub(RB'(\$+)\$', lambda m: m.group(1), s)

    class PipeLine:
        def __init__(self, argument, seam, pipeline):
            if not argument.isdigit():
                raise ValueError(F'argument "{argument}" is not a digit!')

            def parse_pipeline():
                for command in pipeline:
                    unit = TransformSubstitutionFactory(command)
                    if type(unit) == bytes:
                        unit = _lazy_load(unit)
                    yield unit

            self.argument = int(argument, 10)
            self.seam = unescape_dollars(seam)
            self.units = list(parse_pipeline())

        def __call__(self, match):
            data = match.group(self.argument)
            for unit in self.units:
                try:
                    data = unit(data)
                except AttributeError:
                    unit = _lazy_load(unit(match))
                    data = unit(data)
            return self.seam + data

    try:
        fmt = fmt.decode('UNICODE_ESCAPE')
    except AttributeError:
        if type(fmt) != str:
            raise

    fmt = fmt.encode('UTF8')
    escapes = {m.start() + 1 for m in re.finditer(BR'\$\$', fmt)}
    processors = []
    offset = stop = 0
    pattern = re.compile(BR'\$(\d+|\(\d+)')

    while True:
        expression = pattern.search(fmt, stop)
        if not expression:
            break
        start, stop = expression.span()
        if start in escapes:
            continue
        argument = expression.group(1)
        if not argument.isdigit():
            level = 1
            poles = [expression.start() + 2]
            while level > 0:
                if stop > len(fmt):
                    raise ValueError(F'unbalanced parentheses at {stop} for expression: {fmt}')
                if fmt[stop:stop + 1] == B'(':
                    level += 1
                if fmt[stop:stop + 1] == B')':
                    level -= 1
                if fmt[stop:stop + 1] == B'|' and level == 1:
                    poles.append(stop + 1)
                stop += 1

            poles.append(stop)
            pipeline = [
                fmt[a:b - 1].decode('UTF8').strip()
                for a, b in zip(poles, poles[1:])
            ]

            argument = pipeline.pop(0)
        else:
            pipeline = []

        processors.append(PipeLine(
            argument,
            fmt[offset:start],
            pipeline
        ))
        offset = stop

    epilog = unescape_dollars(fmt[offset:])

    if not offset:
        transformation = epilog
    else:
        def transformation(match):
            return B''.join(p(match) for p in processors) + epilog

    return transformation


class PatternExtractorBase(Unit, abstract=True):

    def __init__(
        self,
        min        : arg.number('-n', help='Matches must have length at least N.') = 1,
        max        : arg.number('-N', help='Matches must have length at most N.') = None,
        len        : arg.number('-E', help='Matches must be of length N.') = None,
        whitespace : arg.switch('-w', help='Strip all whitespace from input data.') = False,
        unique     : arg.switch('-q', help='Yield every (transformed) Match only once.') = False,
        longest    : arg.switch('-l', help='Sort results by length before picking.') = False,
        take       : arg.number('-t', help='Return only the first N occurrences.') = None,
    ):
        super().__init__(
            min=min,
            max=max or INF,
            len=len or AST,
            whitespace=whitespace,
            unique=unique,
            ascii=True,
            utf16=True,
            longest=longest,
            take=take or INF
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
            d0 = data[0::2]
            d1 = data[1::2]
            for match in pattern.finditer(d0):
                if not any(d1[match.start() + 0 : match.end() + 0]):
                    yield match
            for match in pattern.finditer(d1):
                if not any(d0[match.start() + 1 : match.end() + 1]):
                    yield match

    def matches_filtered(
        self,
        data: ByteString,
        pattern: Union[ByteString, re.Pattern],
        transforms: Optional[Iterable[Union[ByteString, Callable[[re.Match], ByteString]]]] = None,
        early_abort: bool = True
    ) -> Iterable[Tuple[Tuple[int, int], bytes]]:
        """
        This is a wrapper for `AbstractRegexUint.matches` which filters the
        results according to the given commandline arguments. Returns a
        dictionary mapping its position (start, end) in the input data to the
        filtered and transformed match that was found at this position.
        """
        barrier = set()
        taken = 0
        transforms = transforms or [lambda m: m.group(0)]

        if self.args.whitespace:
            data = re.sub(BR'\s+', B'', data)
        for match in self.matches(data, pattern):
            for transform in transforms:
                hit = transform(match) if callable(transform) else transform
                if hit is None or len(hit) != self.args.len or len(hit) < self.args.min or len(hit) > self.args.max:
                    continue
                if self.args.unique:
                    uid = hash(hit)
                    if uid in barrier:
                        continue
                    barrier.add(uid)
                yield match.span(), hit
                if early_abort:
                    taken += 1
                    if not self.args.longest and taken >= self.args.take:
                        break

    def matches_filtered_cached(
        self,
        data: ByteString,
        pattern: Union[ByteString, re.Pattern],
        transforms: Optional[Iterable[Union[ByteString, Callable[[re.Match], ByteString]]]] = None,
        early_abort: bool = True,
        matches: Optional[dict] = None,
    ) -> Dict[Tuple[int, int], bytes]:
        if matches is None:
            matches = {}
        matches.update(self.matches_filtered(data, pattern, transforms, early_abort))
        return matches

    def matches_finalize(self, matches: Iterable[Tuple[Tuple[int, int], bytes]]) -> Iterable[bytes]:
        """
        Returns the final result of a dictionary of matches according to the
        settings provided via the command line interface.
        """
        result = (d for _, d in matches)
        if self.args.longest:
            result = sorted(result, key=len, reverse=True)
        if self.args.take:
            end = None if self.args.take is INF else self.args.take
            result = islice(result, end)
        yield from result

    def matches_processed(
        self,
        data: ByteString,
        pattern: Union[ByteString, re.Pattern],
        transforms: Optional[Iterable[Union[ByteString, Callable[[re.Match], ByteString]]]] = None
    ) -> Iterable[bytes]:
        """
        A convenience function that acts as the composition of:

        1. `PatternExtractor.matches_filtered` and
        2. `PatternExtractor.matches_finalize`
        """
        yield from self.matches_finalize(self.matches_filtered(data, pattern, transforms))


class PatternExtractor(PatternExtractorBase, abstract=True):
    def __init__(
        self, min=1, max=None, len=None, whitespace=False, unique=False, longest=False, take=None,
        ascii: arg.switch('-u', '--no-ascii', group='AvsU', help='Search for UTF16 encoded patterns only.') = True,
        utf16: arg.switch('-a', '--no-utf16', group='AvsU', help='Search for ASCII encoded patterns only.') = True,
    ):
        super().__init__(
            min=min,
            max=max,
            len=len,
            whitespace=whitespace,
            unique=unique,
            longest=longest,
            take=take
        )
        self.args.ascii = ascii
        self.args.utf16 = utf16


class RegexUnit(PatternExtractorBase, abstract=True):

    def __init__(
        self, regex : arg(type=regexp, help='Regular expression to match.'),
        # TODO: Use positional only in Python 3.8
        # /,
        multiline   : arg.switch('-M', help='caret and dollar match the beginning and end of a line, the dot does not match line breaks.') = False,
        ignorecase  : arg.switch('-I', help='ignore capitalization for alphabetic characters.') = False,
        utf16       : arg.switch('-u', help='search for unicode patterns instead of ascii.') = False,
        min=1, max=None, len=None, whitespace=False, unique=False, longest=False, take=None
    ):
        super().__init__(
            min=min,
            max=max,
            len=len,
            whitespace=whitespace,
            unique=unique,
            longest=longest,
            take=take
        )

        self.args.utf16 = utf16
        self.args.ascii = not utf16

        regex_flags = B'm' if multiline else B's'
        if ignorecase: regex_flags += B'i'

        if isinstance(regex, str):
            regex = regex.encode(self.codec)

        self.args.regex = B'(?%s)%s' % (regex_flags, regex)
