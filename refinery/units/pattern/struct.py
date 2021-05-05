#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct as struct_

from .. import Unit, arg
from ...units.strings.cfmt import ByteStringWrapper


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
            'defaults to using native byte order with no alignment.'
        )),
        *variables: arg(metavar='variable', type=str, help=(
            'The names of the variables to receive the fields of the parsed struct, in the same order as they '
            'appear in the data.'
        )),
        keep: arg.switch('-k', help='Do not strip the parsed struct from the output data.') = False
    ):
        super().__init__(spec=spec, variables=variables, keep=keep)

    def process(self, data: bytearray):
        try:
            spec = self.args.spec
            if not any(spec.startswith(f) for f in '<@=!>'):
                spec = F'={spec}'
            meta = ByteStringWrapper.FormatMap(data, self.codec)
            spec = spec.format_map(meta)
            size = struct_.calcsize(spec)
        except struct_.error:
            raise ValueError(F'The format {spec} is not a valid Python struct definition.')
        if len(data) < size:
            raise ValueError(F'The specified structure occupies {size} bytes, but the input chunk only contains {len(data)} bytes.')
        values = struct_.unpack(spec, data[:size])
        names = self.args.variables
        if len(values) != len(names):
            raise ValueError(F'Extracted {len(values)} fields, but {len(names)} variable names were given.')
        if not self.args.keep:
            data[:size] = []
        return self.labelled(data, **dict(zip(names, values)))
