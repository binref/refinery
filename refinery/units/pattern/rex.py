#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ...lib.argformats import utf8
from . import arg, RegexUnit, TransformSubstitutionFactory


class rex(RegexUnit):
    """
    A binary grep which can apply a transformation to each match. Each match is an
    individual output and standard forking settings apply. Two additional special
    multibin handlers are available for regular expressions:
    """
    @staticmethod
    def _xmeta(t):
        def meta_transform(match):
            meta = match.groupdict()
            data = t(match) if callable(t) else t
            meta.update(data=data)
            return meta
        return meta_transform

    def __init__(self, regex,
        # TODO: Use positional only in Python 3.8
        # /,
        *transformation: arg(type=utf8, help=(
            'An optional sequence of transformations to be applied to each match. '
            'Each transformation produces one output in the order in which they   '
            'are given. The default transformation is $0, i.e. the entire match.  '
        )),
        multiline=False, ignorecase=False, min=1, max=None, len=None, stripspace=False,
        unique=False, longest=False, take=None, utf16=False
    ):
        self.superinit(super(), **vars())
        self.args.transforms = [
            self._xmeta(TransformSubstitutionFactory(t))
            for t in transformation
        ]
        if not self.args.transforms:
            self.args.transforms.append(self._xmeta(lambda m: m[0]))

    def process(self, data):
        self.log_debug('regular expression:', self.args.regex)
        yield from self.matches_filtered(
            memoryview(data),
            self.args.regex,
            *self.args.transforms
        )
