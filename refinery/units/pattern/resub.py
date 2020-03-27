#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

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
        # TODO: Use positional only in Python 3.8
        # /,
        multiline=False, ignorecase=False, min=1, max=None, len=None,
        stripspace=False, unique=False, longest=False, take=None, utf16=False
    ):
        self.superinit(super(), **vars())
        self.args.subst = subst

    def process(self, data):
        self.log_info('pattern:', self.args.regex)
        self.log_info('replace:', self.args.subst)
        return re.sub(self.args.regex, TransformSubstitutionFactory(self.args.subst), data)
