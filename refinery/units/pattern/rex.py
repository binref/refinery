from __future__ import annotations

from typing import Match

from refinery.lib.meta import ByteStringWrapper, metavars
from refinery.lib.types import Param
from refinery.units import Chunk
from refinery.units.pattern import Arg, PatternExtractor, SingleRegexUnit

_FORWARD_VAR = '.'


class rex(SingleRegexUnit, PatternExtractor):
    """
    Short for Regular Expression eXtractor: A binary grep which can apply a transformation to each
    match. Each match is an individual output. Besides the syntax `{k}` to insert the `k`-th match
    group, the unit supports processing the contents of match groups with arbitrary refinery units.
    To do so, use the following F-string-like syntax:

        {match-group:pipeline}

    where `:pipeline` is an optional pipeline of refinery commands as it would be specified on
    the command line. The value of the corresponding match is post-processed with this command. The
    unit also supports the special output format `{%s}` which represents the input data.
    """
    def __init__(
        self, regex,
        /,
        *transformation: Param[str, Arg.String(help=(
            'An optional sequence of transformations to be applied to each match. '
            'Each transformation produces one output in the order in which they '
            'are given. The default transformation is {0}, i.e. the entire match.'
        ))],
        unicode: Param[bool, Arg.Switch('-u', help='Also find unicode strings.')] = False,
        unique: Param[bool, Arg.Switch('-q', help='Yield every (transformed) match only once.')] = False,
        multiline=False, ignorecase=False, min=1, max=None, len=None, stripspace=False,
        longest=False, take=None
    ):
        super().__init__(
            regex=regex,
            transformation=transformation,
            unicode=unicode,
            unique=unique,
            multiline=multiline,
            ignorecase=ignorecase,
            min=min,
            max=max,
            len=len,
            stripspace=stripspace,
            longest=longest,
            take=take,
            utf16=unicode,
            ascii=True,
            duplicates=not unique
        )

    def process(self, data):
        meta = metavars(data)
        wrap = ByteStringWrapper.Wrap(data)
        self.log_debug('regular expression:', getattr(self.regex, 'pattern', self.regex))
        transformations = []
        specs: list[str] = list(self.args.transformation)
        if not specs:
            specs.append('{0}')
        for spec in specs:
            if spec.startswith('{') and spec.endswith('}') and (group := spec[1:-1]).isdigit():
                transformations.append(int(group))
            else:
                def transformation(match: Match, s=spec):
                    symb: dict = {
                        key: (value or b'') for key, value in match.groupdict().items()
                        if not key.startswith('__')}
                    args: list = [match.group(0), *match.groups()]
                    used = set()
                    for key, value in symb.items():
                        if value is None:
                            symb[key] = B''
                    symb[_FORWARD_VAR] = wrap
                    item = meta.format(s, self.codec, args, symb, True, True, used)
                    assert not isinstance(item, str)
                    used.update(key for key, value in symb.items() if not value)
                    used.add(_FORWARD_VAR)
                    for variable in used:
                        symb.pop(variable, None)
                    symb.update(offset=match.start())
                    chunk = Chunk(item, meta=symb)
                    return chunk
                transformations.append(transformation)
        yield from self.matches_filtered(
            memoryview(data),
            self.regex,
            *transformations,
            expose_named_groups=True
        )


if __doc := rex.__doc__:
    rex.__doc__ = __doc % _FORWARD_VAR
