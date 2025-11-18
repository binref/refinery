from __future__ import annotations

import itertools
import re

from refinery.lib.meta import metavars
from refinery.lib.tools import bounds
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class bruteforce(Unit):
    """
    Generates all possible combinations of letters in a given alphabet. For each generated string,
    one copy of each input chunk is generated and populated with a meta variable containing that
    string. This can be used for simple brute forcing checks.
    """
    def __init__(
        self,
        name: Param[str, Arg.String(help='Name of the meta variable to be populated.')],
        length: Param[int | slice, Arg.Bounds(metavar='length', intok=True, help=(
            'Specifies the interval of characters to brute force, default is {default}.'
        ))] = slice(1, None),
        format: Param[str | None, Arg.String(help=(
            'Optional format expression for the output string. The format sequence "{0}" is the '
            'current brute force string, the sequence "{1}" represents the input data.'
        ))] = None,
        alphabet: Param[buf | None, Arg.Binary('-a', group='ALPH', help=(
            'The alphabet from which to choose the letters. Entire byte range by default.'
        ))] = None,
        pattern: Param[str | None, Arg.RegExp('-r', group='ALPH',
            help='Provide a regular expression pattern to define the alphabet.')] = None,
        printable: Param[bool, Arg.Switch('-p', group='ALPH',
            help='Equivalent to --pattern=[\\s\\x20-\\x7E]')] = False,
        digits: Param[bool, Arg.Switch('-d', group='ALPH',
            help='Equivalent to --pattern=\\d')] = False,
        identifier: Param[bool, Arg.Switch('-i', group='ALPH',
            help='Equivalent to --pattern=\\w')] = False,
        letters: Param[bool, Arg.Switch('-l', group='ALPH',
            help='Equivalent to --pattern=[a-zA-Z]')] = False,
    ):
        options = sum(1 for x in [printable, digits, identifier, letters] if x)

        if options > 1 or options and pattern:
            raise ValueError('Invalid selection.')

        if printable:
            pattern = '[\\s\\x20-\\x7E]'
        if digits:
            pattern = '\\d'
        if identifier:
            pattern = '\\w'
        if letters:
            pattern = '[a-zA-Z]'

        super().__init__(
            name=name,
            length=length,
            format=format,
            alphabet=alphabet,
            pattern=pattern,
        )

    def _alphabet(self) -> bytes:
        if (alphabet := self.args.alphabet):
            return alphabet
        else:
            alphabet = bytes(range(0x100))
        if not (pattern := self.args.pattern):
            return alphabet
        if isinstance((regex := Arg.AsRegExp(self.codec, pattern, flags=re.DOTALL)), re.Pattern):
            if (alphabet := B''.join(regex.findall(alphabet))):
                return alphabet
        raise ValueError(F'Invalid regular expression: {pattern}')

    def process(self, data: bytearray):
        format_spec: str = self.args.format
        meta = metavars(data)
        name = self.args.name
        kwargs: dict[str, buf | None] = {name: None}

        for length in bounds[self.args.length]:
            self.log_info(F'generating {length} digits')
            if not isinstance(length, int) or length < 0:
                raise ValueError(F'Unable to brute force {length} characters.')
            for string in itertools.product(self._alphabet(), repeat=length):
                string = bytes(string)
                if format_spec:
                    string = meta.format_bin(format_spec, self.codec, [string, data])
                kwargs[name] = string
                yield self.labelled(data, **kwargs)
