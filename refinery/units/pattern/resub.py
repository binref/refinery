#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from ...lib.argformats import utf8
from . import RegexUnit, TransformSubstitutionFactory


class resub(RegexUnit):
    """
    A unit for performing substitutions based on a binary regular expression
    pattern. Besides the usual syntax `$k` to insert the `k`-th match group,
    the unit supports processing the contents of match groups with arbitrary
    refinery units (see `refinery.units.pattern.TransformSubstitutionFactory`).
    """

    def interface(self, argp):
        super().interface(argp)
        argp.add_argument('subst', type=utf8, nargs='?', default=B'',
            help='substitution, use $1 for group 1, $0 for entire match. Matches get removed by default.')
        return argp

    def process(self, data):
        self.log_info('pattern:', self.args.regex)
        self.log_info('replace:', self.args.subst)
        return re.sub(self.args.regex, TransformSubstitutionFactory(self.args.subst), data)
