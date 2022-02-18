#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List, Match

from refinery.lib.argformats import utf8
from refinery.lib.meta import metavars
from refinery.units.pattern import arg, RegexUnit, PatternExtractor


class rex(RegexUnit, PatternExtractor):
    """
    A binary grep which can apply a transformation to each match. Each match is an individual output.
    Besides the syntax `{k}` to insert the `k`-th match group, the unit supports processing the
    contents of match groups with arbitrary refinery units. To do so, use the following F-string-like
    syntax:

        {match-group:pipeline}

    where `:pipeline` is an optional pipeline of refinery commands as it would be specified on
    the command line. The value of the corresponding match is post-processed with this command.
    """
    def __init__(
        self, regex,
        # TODO: Use positional only in Python 3.8
        # /,
        *transformation: arg(type=utf8, help=(
            'An optional sequence of transformations to be applied to each match. '
            'Each transformation produces one output in the order in which they   '
            'are given. The default transformation is {0}, i.e. the entire match.  '
        )),
        unicode: arg.switch('-u', help='Also find unicode strings.') = False,
        unique: arg.switch('-q', help='Yield every (transformed) match only once.') = False,
        multiline=False, ignorecase=False, min=1, max=None, len=None, stripspace=False,
        longest=False, take=None
    ):
        super().__init__(
            regex=regex,
            transformation=transformation,
            unicode=unicode,
            unique=unique,
            multiline=multiline,
            ignorecase=ignorecase,
            min=min,
            max=max,
            len=len,
            stripspace=stripspace,
            longest=longest,
            take=take,
            utf16=unicode,
            ascii=True,
            duplicates=not unique
        )

    def process(self, data):
        meta = metavars(data)
        self.log_debug('regular expression:', self.regex)
        transformations = []
        specs: List[bytes] = list(self.args.transformation)
        if not specs:
            specs.append(B'{0}')
        for spec in specs:
            def transformation(match: Match, s=spec.decode(self.codec)):
                symb: dict = match.groupdict()
                args: list = [match.group(0), *match.groups()]
                used = set()
                item = meta.format(s, self.codec, args, symb, True, True, used)
                for variable in used:
                    symb.pop(variable, None)
                symb.update(offset=match.start())
                for name, value in meta.items():
                    symb.setdefault(name, value)
                return self.labelled(item, **symb)
            transformations.append(transformation)
        yield from self.matches_filtered(memoryview(data), self.regex, *transformations)
