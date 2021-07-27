#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ...lib.argformats import utf8
from ...lib.meta import metavars
from . import arg, RegexUnit


class resub(RegexUnit):
    """
    A unit for performing substitutions based on a binary regular expression pattern. Besides the
    syntax `{k}` to insert the `k`-th match group, the unit supports processing the contents of
    match groups with arbitrary refinery units. To do so, use the following F-string-like syntax:

        {match-group:pipeline}

    where `:pipeline` is an optional pipeline of refinery commands as it would be specified on
    the command line. The value of the corresponding match is post-processed with this command.
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
        def repl(match):
            return meta.format_bin(spec, self.codec, match.group(0), *match.groups(), **match.groupdict())
        self.log_info('pattern:', self.regex)
        self.log_info('replace:', self.args.subst)
        meta = metavars(data)
        spec = self.args.subst.decode(self.codec)
        sub = self.regex.sub
        if self.args.count:
            from functools import partial
            sub = partial(sub, count=self.args.count)
        return sub(repl, data)
