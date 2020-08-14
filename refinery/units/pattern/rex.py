#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ...lib.argformats import utf8
from . import arg, RegexUnit, PatternExtractor, TransformSubstitutionFactory


class rex(RegexUnit, PatternExtractor):
    """
    A binary grep which can apply a transformation to each match. Each match is an
    individual output and standard forking settings apply. Two additional special
    multibin handlers are available for regular expressions:
    """
    @classmethod
    def _xmeta(cls, t):
        def meta_transform(match):
            data = t(match) if callable(t) else t
            return cls.labelled(data, **match.groupdict())
        return meta_transform

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
        transformation = [self._xmeta(TransformSubstitutionFactory(t)) for t in transformation]
        if not transformation:
            transformation.append(self._xmeta(lambda m: m[0]))
        utf16 = unicode          # noqa
        ascii = True             # noqa
        duplicates = not unique  # noqa
        del unicode
        del unique
        self.superinit(super(), **vars())

    def process(self, data):
        self.log_debug('regular expression:', self.args.regex)
        yield from self.matches_filtered(memoryview(data), self.args.regex, *self.args.transformation)
