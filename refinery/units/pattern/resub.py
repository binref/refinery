#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ...lib.argformats import utf8
from . import arg, RegexUnit, TransformSubstitutionFactory


class resub(RegexUnit):
    """
    A unit for performing substitutions based on a binary regular expression
    pattern. Besides the usual syntax `$k` to insert the `k`-th match group,
    the unit supports processing the contents of match groups with arbitrary
    refinery units (see `refinery.units.pattern.TransformSubstitutionFactory`).
    """
    def __init__(self, regex,
        subst: arg('subst', type=utf8, help=(
            'Substitution value: use $1 for group 1, $0 for entire match. '
            'Matches are removed (replaced by an empty string) by default.'
        )) = B'',
        multiline=False,
        ignorecase=False,
        count=0
    ):
        super().__init__(regex=regex, subst=subst, multiline=multiline, ignorecase=ignorecase, count=count)

    def process(self, data):
        self.log_info('pattern:', self.args.regex)
        self.log_info('replace:', self.args.subst)
        try:
            meta = data.meta
        except AttributeError:
            meta = {}
        repl = TransformSubstitutionFactory(self.args.subst, meta)
        sub = self.args.regex.sub
        if self.args.count:
            from functools import partial
            sub = partial(sub, count=self.args.count)
        return sub(repl, data)
