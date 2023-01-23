#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Match

from refinery.lib.meta import metavars
from refinery.units.pattern import Arg, RegexUnit


class resub(RegexUnit):
    """
    A unit for performing substitutions based on a binary regular expression pattern. Besides the
    syntax `{k}` to insert the `k`-th match group, the unit supports processing the contents of
    match groups with arbitrary refinery units. To do so, use the following F-string-like syntax:

        {match-group:handlers}

    where `:handlers` is an optional reverse multibin expression that is used to post-process the
    binary data from the match. For example, `{2:hex:b64}` represents the base64-decoding of the
    hex-decoding of the second match group.
    """
    def __init__(
        self,
        regex: Arg(help='Regular expression to be searched and replaced. The default is "{default}".') = '\\s+',
        subst: Arg('subst', help=(
            'Substitution value: use {1} for group 1, {0} for entire match. Matches are removed '
            '(replaced by an empty string) by default.'
        )) = B'',
        multiline=False,
        ignorecase=False,
        count=0
    ):
        super().__init__(regex=regex, subst=subst, multiline=multiline, ignorecase=ignorecase, count=count)

    def process(self, data):
        def repl(match: Match):
            return meta.format_bin(spec, self.codec, [match[0], *match.groups()], match.groupdict())
        self.log_info('pattern:', getattr(self.regex, 'pattern', self.regex))
        self.log_info('replace:', self.args.subst)
        meta = metavars(data)
        spec = self.args.subst.decode('ascii', 'backslashreplace')
        substitute = self.regex.sub
        if self.args.count:
            from functools import partial
            substitute = partial(substitute, count=self.args.count)
        return substitute(repl, data)
