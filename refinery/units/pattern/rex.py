#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ...lib.argformats import utf8
from ...lib.meta import metavars
from . import arg, RegexUnit, PatternExtractor


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
        utf16 = unicode          # noqa
        ascii = True             # noqa
        duplicates = not unique  # noqa
        del unicode
        del unique
        self.superinit(super(), **vars())

    def process(self, data):
        meta = metavars(data)
        self.log_debug('regular expression:', self.regex)

        def make_transformations(specs):
            for spec in specs:
                def transformation(match, s=spec.decode(self.codec)):
                    symb: dict = match.groupdict()
                    args: list = [match.group(0), *match.groups()]
                    used = set()
                    item = meta.format(s, self.codec, args, symb, True, True, used)
                    for variable in used:
                        symb.pop(variable, None)
                    for name, value in meta.items():
                        symb.setdefault(name, value)
                    return self.labelled(item, **symb)
                yield transformation

        yield from self.matches_filtered(
            memoryview(data), self.regex, *make_transformations(self.args.transformation))
