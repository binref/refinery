#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ...lib.argformats import utf8
from . import arg, RegexUnit, PatternExtractor, TransformSubstitutionFactory


class rex(RegexUnit, PatternExtractor):
    """
    A binary grep which can apply a transformation to each match. Each match is an individual output.
    """
    def __init__(
        self, regex,
        # TODO: Use positional only in Python 3.8
        # /,
        *transformation: arg(type=utf8, help=(
            'An optional sequence of transformations to be applied to each match. '
            'Each transformation produces one output in the order in which they   '
            'are given. The default transformation is $0, i.e. the entire match.  '
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
        try:
            meta = data.meta
        except AttributeError:
            meta = {}
        self.log_debug('regular expression:', self.args.regex)
        transformations = [TransformSubstitutionFactory(t, meta) for t in self.args.transformation] or [lambda m: m[0]]
        transformations = [lambda m, mt=t: self.labelled(mt(m), **m.groupdict()) for t in transformations]
        yield from self.matches_filtered(memoryview(data), self.args.regex, *transformations)
