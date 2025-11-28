from __future__ import annotations

from typing import Match

from refinery.lib.meta import metavars
from refinery.lib.types import Param, buf
from refinery.units.pattern import Arg, SingleRegexTransformUnit


class resub(SingleRegexTransformUnit, docs=(
    '{0}\n\nSubstitutions are interpreted as format strings: {SingleRegexTransformUnit}'
)):
    """
    A unit for performing substitutions based on a binary regular expression pattern.
    """
    def __init__(
        self,
        regex: Param[str, Arg(
            help='Regular expression to be searched and replaced. The default is "{default}".')
        ] = '\\s+',
        subst: Param[buf, Arg('subst', help=(
            'Substitution value: use {1} for group 1, {0} for entire match. The default value is '
            'an empty string, i.e. matches are removed from the input by default.'
        ))] = B'',
        multiline=False, ignorecase=False, count=0
    ):
        super().__init__(
            regex=regex,
            subst=subst,
            multiline=multiline,
            ignorecase=ignorecase,
            count=count,
        )

    def process(self, data):
        def repl(match: Match):
            d = match.groupdict()
            for k in list(d):
                if k[:2] == k[-2:] == '__':
                    del d[k]
            r = meta.format_bin(spec, self.codec, [match[0], *match.groups()], match.groupdict())
            self.log_debug('substitution:', repr(r), clip=True)
            return r
        self.log_info('pattern:', getattr(self.regex, 'pattern', self.regex))
        self.log_info('replace:', self.args.subst)
        meta = metavars(data)
        spec = self.args.subst.decode('ascii', 'backslashreplace')
        substitute = self.regex.sub
        if self.args.count:
            from functools import partial
            substitute = partial(substitute, count=self.args.count)
        return substitute(repl, data)
