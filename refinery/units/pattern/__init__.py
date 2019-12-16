#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pattern matching based extraction and substitution units.
"""
import re

from typing import Dict, Tuple, Iterable
from itertools import islice

from ...lib.types import INF, AST
from ...lib.argformats import number, regexp
from .. import Unit


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


class AbstractRegexUnit(Unit, abstract=True):

    def matches(self, data: bytes, pattern, ascii=True, utf16=True):
        """
        Searches the input data for the given regular expression pattern. If the
        argument `utf16` is `True`, search for occurrences where a zero byte
        is between every character of the match. The `ascii` option allows to
        control whether normal matching results are also returned.
        """
        if isinstance(pattern, bytes):
            pattern = re.compile(pattern)
        if ascii:
            yield from pattern.finditer(data)
        if utf16:
            d0 = data[0::2]
            d1 = data[1::2]
            for match in pattern.finditer(d0):
                high_bytes = d1[match.start() + 0 : match.end() + 0]
                a, b = match.span()
                if high_bytes == B'\0' * (b - a):
                    yield match
            for match in pattern.finditer(d1):
                high_bytes = d0[match.start() + 1 : match.end() + 1]
                a, b = match.span()
                if high_bytes == B'\0' * (b - a):
                    yield match


class PatternExtractorBase(AbstractRegexUnit, abstract=True):

    def interface(self, argp):
        argp = super().interface(argp)

        filters = argp.add_argument_group('Match Filters')
        filters.add_argument('-n', '--min', type=number, metavar='N', default=1, help='Matches must have length at least N.')
        filters.add_argument('-N', '--max', type=number, metavar='N', default=INF, help='Matches must have length at most N.')
        filters.add_argument('-E', '--len', type=number, metavar='N', default=AST, help='Matches must be of length N.')
        filters.add_argument('-w', '--whitespace', action='store_true', help='Strip all whitespace from input data.')
        filters.add_argument('-q', '--unique', action='store_true', help='Yield every (transformed) Match only once.')

        filters.set_defaults(ascii=True, utf16=True)

        selectors = argp.add_argument_group('Match Selectors')
        selectors.add_argument('-l', '--longest', action='store_true',
            help='Sort results by length before picking.')

        mode = selectors.add_mutually_exclusive_group()
        mode.add_argument('-t', '--take', type=number[1:], metavar='N', default=INF,
            help='Return the first N occurrences.')
        mode.add_argument('-p', '--pick', type=number, metavar='k', default=None,
            help='Pick the pattern occurrence at index k, starting at 0.')

        return filters

    def matches_filtered(
        self,
        data: bytes,
        pattern,
        transform=None,
        early_abort=True
    ) -> Iterable[Tuple[Tuple[int, int], bytes]]:
        """
        This is a wrapper for `AbstractRegexUint.matches` which filters the
        results according to the given commandline arguments. Returns a
        dictionary mapping its position (start, end) in the input data to the
        filtered and transformed match that was found at this position.
        """
        barrier = set()
        taken = 0

        if self.args.whitespace:
            data = re.sub(BR'\s+', B'', data)
        for match in self.matches(data, pattern, self.args.ascii, self.args.utf16):
            if not transform:
                s = match.group(0)
            else:
                try:
                    s = transform(match)
                except TypeError:
                    s = transform
            if len(s) < self.args.min or len(s) > self.args.max or len(s) != self.args.len:
                continue
            if self.args.unique:
                h = hash(s)
                if h in barrier:
                    continue
                barrier.add(h)
            yield match.span(), s
            if early_abort:
                taken += 1
                if not self.args.longest and taken >= self.args.take:
                    break

    def matches_filtered_cached(
        self,
        data: bytes,
        pattern,
        transform=None,
        early_abort=True,
        matches=None,
    ) -> Dict[Tuple[int, int], bytes]:
        if not isinstance(matches, dict):
            matches = {}
        matches.update(self.matches_filtered(data, pattern, transform, early_abort))
        return matches

    def matches_finalize(self, matches: Iterable[Tuple[Tuple[int, int], bytes]]) -> Iterable[bytes]:
        """
        Returns the final result of a dictionary of matches according to the
        settings provided via the command line interface.
        """
        result = (d for _, d in matches)
        if self.args.longest:
            end = None if self.args.take is INF else self.args.take
            result = islice(sorted(result, key=len, reverse=True), end)
        if self.args.pick:
            result = islice(result, self.args.pick, self.args.pick + 1)
        yield from result

    def matches_processed(
        self,
        data: bytes,
        pattern,
        transform=None
    ) -> Iterable[bytes]:
        """
        A convenience function that acts as the composition of:

        1. `PatternExtractor.matches_filtered` and
        2. `PatternExtractor.matches_finalize`
        """
        yield from self.matches_finalize(self.matches_filtered(data, pattern, transform))


class PatternExtractor(PatternExtractorBase, abstract=True):
    def interface(self, argp):
        filters = super().interface(argp)
        switch = filters.add_mutually_exclusive_group()
        switch.add_argument(
            '-u', '--only-utf16',
            action='store_false',
            dest='ascii',
            help='Search for UTF16 encoded patterns only.'
        )
        switch.add_argument(
            '-a', '--only-ascii',
            action='store_false',
            dest='utf16',
            help='Search for ASCII encoded patterns only.'
        )
        return argp


class RegexUnit(PatternExtractorBase, abstract=True, helpdoc=True):
    """
    - You can use YARA type hexadecimal pattern syntax. For example, `yara:7?[1-5]E8`
      translates to `[\\x70-\\x7F].{1,5}\\xE8`.
    - To excape a raw string, use `escape:ok?`, which would yield `ok\\?`.
    """

    def interface(self, argp, regex_default=None):
        mode = argp.add_argument_group(
            'Regular Expression Flags',
            'The DOTALL flag is set by default and has to be '
            'disabled rather than enabled.'
        )
        mode.add_argument('-M', '--multiline', action='store_const', default=B'', const=B'm')
        mode.add_argument('-A', '--notdotall', dest='dotall', action='store_const', default=B's', const=B'')
        mode.add_argument('-I', '--ignorecase', action='store_const', default=B'', const=B'i')

        regex = dict(
            type=regexp,
            help='Regular expression to match.'
        )
        if regex_default:
            regex.update(dict(
                default=regex_default,
                nargs='?'
            ))

        argp.add_argument('regex', **regex)

        filters = super().interface(argp)
        filters.add_argument(
            '-u', '--utf16',
            action='store_true',
            default=False,
            help='Search for UTF-16 encoded patterns instead of ASCII.'
        )
        return argp

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.args.ascii = not self.args.utf16
        flags = B''.join(getattr(self.args, flag)
            for flag in ('ignorecase', 'multiline', 'dotall'))
        if flags:
            self.args.regex = B'(?%s)%s' % (flags, self.args.regex)
