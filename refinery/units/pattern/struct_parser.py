#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import string
import itertools
import re

from refinery.units import Arg, Unit, Chunk

from refinery.lib.meta import SizeInt, metavars, check_variable_name
from refinery.lib.structures import StructReader, StreamDetour
from refinery.lib.argformats import ParserError, PythonExpression, numseq
from refinery.lib.types import INF


def identity(x):
    return x


_REST_MARKER = '#'


class struct(Unit):
    """
    Read structured data from the beginning of a chunk and store the extracted fields in chunk meta
    variables. The structure format is specified in extended Python struct format, and all
    remaining arguments to this unit are the names of the variables that receive the values from
    this struct. The extended struct format supports all field types supported by Python, as well
    as the following:

    - `a` for null-terminated ASCII strings,
    - `u` to read encoded, null-terminated UTF16 strings,
    - `w` to read decoded, null-terminated UTF16 strings,
    - `g` to read Microsoft GUID values,
    - `E` to read 7-bit encoded integers.

    For example, the string `LLxxHaa` will read two unsigned 32bit integers, then skip two bytes,
    then read one unsigned 16bit integer, then two null-terminated ASCII strings. The unit defaults
    to using native byte order with no alignment. The `spec` parameter may additionally contain
    format expressions of the following form:

    {name[!alignment]:format}

    The `alignment` parameter is optional. It must be an expression that evaluates to an integer
    value. The current data pointer is aligned to a multiple of this value before reading the field.
    The `format` can either be an integer expression specifying a number of bytes to read, or any
    format string. If `name` is specified for an extracted field, its value is made available as a
    meta variable under the given name. For example, the expression `LLxxH{foo:a}{bar:a}` would be
    parsed in the same way as the previous example, but the two ASCII strings would also be stored
    in meta variables under the names `foo` and `bar`, respectively. The `format` string of a named
    field is itself parsed as a foramt string expression, where all the previously parsed fields
    are already available. For example, `I{:{}}` reads a single 32-bit integer length prefix and
    then reads as many bytes as that prefix specifies.

    A second format string expression is used to specify the output format. For example, the format
    string `LLxxH{foo:a}{bar:a}` together with the output format `{foo}/{bar}` would parse data as
    before, but the output body would be the concatnation of the field `foo`, a forward slash, and
    the field `bar`. Variables used in the output expression are not included as meta variables. As
    format fields in the output expression, one can also use `{1}`, `{2}` or `{-1}` to access
    extracted fields by index. The value `{0}` represents the entire chunk of structured data. By
    default, the output format `{%s}` is used, which represents either the last byte string field
    that was extracted, or the entire chunk of structured data if none of the fields were extracted.

    Reverse `refinery.lib.argformats.multibin` expressions can be used to post-process the fields
    included in any output format. For example, `{F:b64:zl}` will be the base64-decoded and inflate-
    decompressed contents of the data that was read as field `F`.

    Finally, it is possible to specify a byte alignment by using the syntax `{field!T:a:b:c}` where
    the letter `T` is either a single digit specifying the alignment, or a single letter variable
    that holds the byte alignment value in the current metadata.
    """

    def __init__(
        self,
        spec: Arg(type=str, help='Structure format as explained above.'),
        *outputs: Arg(metavar='output', type=str, help='Output format as explained above.'),
        multi: Arg.Switch('-m', help=(
            'Read as many pieces of structured data as possible intead of just one.')) = False,
        count: Arg.Number('-c', help=(
            'A limit on the number of chunks to read in multi mode; default is {default}.')) = INF,
        until: Arg('-u', metavar='E', type=str, help=(
            'An expression evaluated on each chunk in multi mode. New chunks will be parsed '
            'only if the result is nonzero.')) = None,
        format: Arg.String('-f', metavar='F', help=(
            'Optionally specify a format string expression to auto-name extracted fields without a '
            'given name. The format string accepts the field {{c}} for the type code and {{n}} for '
            'the variable index.')) = None,
        name: Arg.String('-n', metavar='VAR', group='FIELDS', help=(
            U'Equivalent to --format=VAR{{n}}.')) = None,
        more: Arg.Switch('-M', help=(
            'After parsing the struct, emit one chunk that contains the data that was left '
            'over in the buffer. If no data was left over, this chunk will be empty.')) = False
    ):
        if name:
            format = format or F'{name}{{n}}'
        outputs = outputs or [F'{{{_REST_MARKER}}}']
        super().__init__(spec=spec, outputs=outputs, until=until, format=format, count=count, multi=multi, more=more)

    def process(self, data: Chunk):
        formatter = string.Formatter()
        field_format: str | None = self.args.format
        until = self.args.until
        until = until and PythonExpression(until, all_variables_allowed=True)
        reader = StructReader(memoryview(data))
        checkpoint = 0
        mainspec = self.args.spec
        byteorder = mainspec[:1]
        if byteorder in '<@=!>':
            mainspec = mainspec[1:]
        else:
            byteorder = '='

        def fixorder(spec):
            if spec[0] not in '<@=!>':
                spec = byteorder + spec
            return spec

        previously_existing_variables = set(metavars(data).variable_names())

        it = itertools.count() if self.args.multi else (0,)
        for index in it:

            field_counter = 0
            checkpoint = reader.tell()

            if reader.eof:
                break
            if index >= self.args.count:
                break

            meta = metavars(data)
            meta.ghost = True
            meta.index = index

            args = []
            last = None
            self.log_debug(F'starting new read at: 0x{checkpoint:08X}')

            try:
                for prefix, name, spec, conversion in formatter.parse(mainspec):
                    name: str
                    spec: str = spec and spec.strip()
                    if prefix:
                        fields = reader.read_struct(fixorder(prefix))
                        if field_format is not None:
                            codes = re.findall('[?cbBhHiIlLqQnNefdspPauwgk]', prefix)
                            if len(codes) != len(fields):
                                codes = 'v' * len(fields)
                            for code, field in zip(codes, fields):
                                code = 'b' if code == '?' else code.lower()
                                v = field_format.format_map({'c': code, 'n': field_counter})
                                meta[v] = field
                                field_counter += 1
                        args.extend(fields)

                    if name is None:
                        continue

                    field_counter += 1

                    if name and not name.isdecimal():
                        check_variable_name(name)

                    if conversion:
                        _aa = reader.tell()
                        reader.byte_align(PythonExpression.Evaluate(conversion, meta))
                        _ab = reader.tell()
                        if _aa != _ab:
                            self.log_info(F'aligned from 0x{_aa:X} to 0x{_ab:X}')

                    spec, _, pipeline = spec.partition(':')

                    if spec:
                        spec = meta.format_str(spec, self.codec, args)

                    if spec:
                        try:
                            _exp = PythonExpression.Evaluate(spec, meta)
                        except ParserError:
                            pass
                        else:
                            spec = _exp

                    if spec == '':
                        last = value = reader.read()
                    elif isinstance(spec, int):
                        if spec < 0:
                            spec += reader.remaining_bytes
                        if spec < 0:
                            raise ValueError(F'The specified negative read offset is {-spec} beyond the cursor.')
                        last = value = reader.read_bytes(spec)
                    else:
                        value = reader.read_struct(fixorder(spec))
                        if not value:
                            self.log_debug(F'field {name} was empty, ignoring.')
                            continue
                        if len(value) > 1:
                            self.log_info(F'parsing field {name} produced {len(value)} items reading a tuple')
                        else:
                            value = value[0]

                    if pipeline:
                        value = numseq(pipeline, reverse=True, seed=value)
                    args.append(value)

                    if name == _REST_MARKER:
                        raise ValueError(F'Extracting a field with name {_REST_MARKER} is forbidden.')
                    elif name.isdecimal():
                        index = int(name)
                        limit = len(args) - 1
                        if index > limit:
                            self.log_warn(F'cannot assign index field {name}, the highest index is {limit}')
                        else:
                            args[index] = value
                        continue
                    elif name:
                        meta[name] = value

                if until and until(meta):
                    self.log_info(F'the expression ({until}) evaluated to true; aborting.')
                    break

                with StreamDetour(reader, checkpoint) as detour:
                    full = reader.read(detour.cursor - checkpoint)
                if last is None:
                    last = full

                outputs = []
                symbols = dict(meta)
                symbols[_REST_MARKER] = last

                for template in self.args.outputs:
                    used = set()
                    outputs.append(meta.format(template, self.codec, [full, *args], symbols, True, used=used))
                    for key in used:
                        if key in previously_existing_variables:
                            continue
                        meta.discard(key)

                for output in outputs:
                    chunk = Chunk(output)
                    chunk.meta.update(meta)
                    chunk.set_next_batch(index)
                    yield chunk

            except EOFError:
                break

        leftover = len(reader) - checkpoint

        if not leftover:
            return
        elif self.args.more:
            reader.seekset(checkpoint)
            yield reader.read()
        else:
            leftover = repr(SizeInt(leftover)).strip()
            self.log_info(F'discarding {leftover} left in buffer')


struct.__doc__ %= _REST_MARKER
