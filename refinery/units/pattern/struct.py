#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Unit, arg
from ...units.strings.cfmt import ByteStringWrapper
from ...lib.structures import StructReader


class struct(Unit):
    """
    Read structured data from the beginning of a chunk and store the extracted fields in chunk meta variables.
    The structure format is specified in Python struct format, and all remaining arguments to this unit are the
    names of the variables that receive the values from this struct.
    """
    def __init__(
        self,
        spec: arg(type=str, help=(
            'Specify the structure format in Python struct syntax. For example, the string LLxxH will read '
            'two unsigned 32bit integers, then skip two bytes, and then read one unsigned 16bit integer from '
            'the input data. Three variable names have to be specified to hold these parsed values. The unit '
            'defaults to using native byte order with no alignment. The unit supports the additional format '
            'characters uUaA for reading null-terminated wide and ascii strings. If the format character is '
            'uppercase, the string is decoded as UTF-16LE and LATIN1, respectively.'
        )),
        *variables: arg(metavar='variable', type=str, help=(
            'The names of the variables to receive the fields of the parsed struct, in the same order as they '
            'appear in the data.'
        )),
        keep: arg.switch('-k', help='Do not strip the parsed struct from the output data.') = False
    ):
        super().__init__(spec=spec, variables=variables, keep=keep)

    def _readspec(self, data):
        spec = self.args.spec
        if not any(spec.startswith(f) for f in '<@=!>'):
            spec = F'={spec}'
        meta = ByteStringWrapper.FormatMap(data, self.codec)
        spec = spec.format_map(meta)
        spec = re.split('([auAU])', spec)
        results = []
        with StructReader(data) as reader:
            for format in spec:
                if not format:
                    continue
                elif format in 'aA':
                    encoding = None
                    if format.isupper():
                        encoding = 'latin-1'
                    results.append(reader.read_c_string(encoding))
                elif format in 'uU':
                    encoding = None
                    if format.isupper():
                        encoding = 'utf-16le'
                    results.append(reader.read_w_string(encoding))
                else:
                    results.extend(reader.read_struct(format))
            return reader.tell(), results

    def process(self, data: bytearray):
        size, values = self._readspec(data)
        names = self.args.variables
        if len(values) != len(names):
            raise ValueError(F'Extracted {len(values)} fields, but {len(names)} variable names were given.')
        if not self.args.keep:
            data[:size] = []
        return self.labelled(data, **dict(zip(names, values)))
