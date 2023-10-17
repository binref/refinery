#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import itertools

from refinery.units import Arg, Unit
from refinery.lib.meta import metavars
from refinery.lib.tools import integers_of_slice


class bruteforce(Unit):
    """
    Generates all possible combinations of letters in a given alphabet. For each generated string,
    one copy of each input chunk is generated and populated with a meta variable containing that
    string. This can be used for simple brute forcing checks.
    """
    def __init__(
        self,
        name  : Arg.String(help='Name of the meta variable to be populated.'),
        length: Arg.Bounds(metavar='length', help=(
            'Specifies the range of characters to brute force, default is {default}.'
        )) = slice(1, None),
        format: Arg.String(help=(
            'Optional format expression for the output string. The format sequence "{0}" is the '
            'current brute force string, the sequence "{1}" represents the input data.'
        )) = None,
        alphabet  : Arg.Binary('-a', group='ALPH', help=(
            'The alphabet from which to choose the letters. Entire byte range by default.'
        )) = None,
        pattern   : Arg.RegExp('-r', group='ALPH',
            help='Provide a regular expression pattern to define the alphabet.') = None,
        printable : Arg.Switch('-p', group='ALPH',
            help='Equivalent to --pattern=[\\s\\x20-\\x7E]') = False,
        digits    : Arg.Switch('-d', group='ALPH',
            help='Equivalent to --pattern=\\d') = False,
        identifier: Arg.Switch('-i', group='ALPH',
            help='Equivalent to --pattern=\\w') = False,
        letters   : Arg.Switch('-l', group='ALPH',
            help='Equivalent to --pattern=[a-zA-Z]') = False,
    ):
        options = sum(1 for x in [printable, digits, identifier, letters] if x)

        if options > 1 or options and pattern:
            raise ValueError('Invalid selection.')

        if printable:
            pattern = b'[\\s\\x20-\\x7E]'
        if digits:
            pattern = b'\\d'
        if identifier:
            pattern = b'\\w'
        if letters:
            pattern = b'[a-zA-Z]'

        super().__init__(
            name=name,
            length=length,
            format=format,
            alphabet=alphabet,
            pattern=pattern,
        )

    def _alphabet(self) -> bytes:
        alphabet = self.args.alphabet
        if alphabet:
            return alphabet
        alphabet = bytes(range(0x100))
        pattern = self.args.pattern
        if not pattern:
            return alphabet
        alphabet = B''.join(re.findall(pattern, alphabet, flags=re.DOTALL))
        if alphabet:
            return alphabet
        raise ValueError(F'Invalid regular expression: {pattern}')

    def process(self, data: bytearray):
        format_spec: str = self.args.format
        meta = metavars(data)
        name = self.args.name
        kwargs = {name: None}

        for length in integers_of_slice(self.args.length):
            self.log_info(F'generating {length} digits')
            if not length or length <= 0:
                raise ValueError(F'Unable to brute force {length} characters.')
            for string in itertools.product(self._alphabet(), repeat=length):
                string = bytes(string)
                if format_spec:
                    string = meta.format_bin(format_spec, self.codec, [string, data])
                kwargs[name] = string
                yield self.labelled(data, **kwargs)
