from __future__ import annotations

from typing import Match

from refinery.lib.meta import ByteStringWrapper, metavars
from refinery.lib.types import Param
from refinery.units import Chunk
from refinery.units.pattern import Arg, PatternExtractor, SingleRegexTransformUnit

_FORWARD_VAR = '.'


class rex(SingleRegexTransformUnit, PatternExtractor, docs=(
    '{0}\n\nTransformations are interpreted as format strings: {SingleRegexTransformUnit}'
    F' The unit also supports the format `{{{{{_FORWARD_VAR}}}}}` to represent the input data.'
)):
    """
    Short for Regular Expression eXtractor: A binary grep which can apply a transformation to each
    match. Each match is an individual output.
    """
    def __init__(
        self, regex,
        /,
        *transformation: Param[str, Arg.String(help=(
            'An optional sequence of transformations to be applied to each match. Each '
            'transformation produces one output in the order in which they are given. The default '
            'transformation is {0}, which represents the entire match.'
        ))],
        unicode: Param[bool, Arg.Switch('-u', help=(
            'Also find unicode strings, i.e. occurrences of pattern where all characters are '
            'separated by null bytes.'
        ))] = False,
        unique: Param[bool, Arg.Switch('-q', help=(
            'Yield every (transformed) match only once and discard duplicates.'
        ))] = False,
        min=1, max=0, len=0,
        multiline=False, ignorecase=False, stripspace=False, longest=False, take=0
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
                        if not (key[:2] == key[-2:] == '__')
                    }
                    args: list = [match.group(0), *match.groups()]
                    used = set()
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
