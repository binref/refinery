#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import datetime
import string
import itertools

from .. import Unit, arg

from ...lib.meta import ByteStringWrapper, SizeInt, metavars
from ...lib.structures import EOF, StructReader
from ...lib.argformats import ParserError, PythonExpression
from ...lib.types import INF
from ...lib.tools import isbuffer


def identity(x):
    return x


class struct(Unit):
    """
    Read structured data from the beginning of a chunk and store the extracted fields in chunk meta variables.
    The structure format is specified in extended Python struct format, and all remaining arguments to this unit
    are the names of the variables that receive the values from this struct. The extended struct format supports
    all field types supported by Python, as well as the following:

    - `a` for null-terminated ASCII strings,
    - `u` for null-terminated UTF16 strings,
    - `$` only as the last character, to read all remaining data.

    For example, the string `LLxxHaa$` will read two unsigned 32bit integers, then skip two bytes, then read one
    unsigned 16bit integer, then two null-terminated ASCII strings and finally, all data that remains. The unit
    defaults to using native byte order with no alignment.

    The `spec` parameter may additionally contain named fields `{name:format}`. Here, `format` can either be an
    integer expression specifying a number of bytes to read, or any single format string character. Parsing
    such a field will make the parsed data available as a meta variable under the given name. For example, the
    expression `LLxxH{foo:a}{bar:a}$` would parse the same data as the previous example, but the two ASCII
    strings would also be output as meta variables under the names `foo` and `bar`, respectively.

    The `format` string of a named field is itself parsed as a foramt string expression, where all the previously
    parsed fields are already available. For example, `L{:{0}}` reads a single 32-bit integer length prefix and
    then reads as many bytes as that prefix specifies.

    The output arguments are refinery-specific binary format strings that control what the unit outputs:

    - `{0}` places the entire processed data at this position in the output.
    - `{1}` places the first extracted field at this position in the output.
    - `{-1}` places the last extracted field at this position in the output.
    - `{F}` places the field named `F` at this position in the output.
    - `{$}` represents the last named field or dollar symbol that was parsed.

    The format specifications of binary format strings are refinery pipelines. For example, `{F:b64|zl}` will be
    the base64-decoded and inflate-decompressed contents of the data that was read as field `F`.
    """
    def __init__(
        self,
        spec: arg(type=str, help='Structure format as explained above.'),
        *outputs: arg(metavar='output', type=str, help='Output format as explained above.'),
        until: arg('-u', metavar='E', type=str, help=(
            'An expression evaluated on each chunk. Continue parsing only if the result is nonzero.')) = None,
        count: arg.number('-c', help=(
            'A limit on the number of chunks to read. The default is {default}.')) = INF,
    ):
        outputs = outputs or ['{$}']
        super().__init__(spec=spec, outputs=outputs, until=until, count=count)

    def process(self, data: bytearray):
        formatter = string.Formatter()
        until = self.args.until
        until = until and PythonExpression(until, all_variables_allowed=True)
        reader = StructReader(memoryview(data))
        mainspec = self.args.spec
        byteorder = mainspec[:1]
        if byteorder in '<!=@>':
            mainspec = mainspec[1:]
        else:
            byteorder = '='

        mainspec, dollar, _empty = mainspec.partition('$')
        if _empty:
            raise ValueError('The format string {mainspec}${end} is invalid, a dollar symbol must be the last character.')
        if dollar:
            mainspec += '{}'

        for index in itertools.count():

            if reader.eof:
                break
            if index >= self.args.count:
                break

            meta = metavars(data, ghost=True)
            meta['index'] = index
            args = []
            last = None
            checkpoint = reader.tell()

            try:
                for prefix, name, spec, conversion in formatter.parse(mainspec):
                    if prefix:
                        args.extend(reader.read_struct(byteorder + prefix))
                    if name is None:
                        continue
                    if spec:
                        spec = meta.format_str(spec, self.codec, *args)
                    try:
                        spec = PythonExpression.evaluate(spec, meta)
                    except ParserError:
                        pass
                    if not spec:
                        value = reader.read()
                    elif isinstance(spec, int):
                        value = reader.read_bytes(spec)
                    else:
                        value = reader.read_struct(byteorder + spec)
                        if not value:
                            self.log_warn(F'field {name} was empty, ignoring.')
                            continue
                        if len(value) > 1:
                            self.log_warn(F'parsing field {name} produced {len(value)} items, discarding all but the first one')
                        value = value[0]
                    if conversion == 'u':
                        value = value.decode('utf-16le')
                    if conversion == 's':
                        value = value.decode('utf8')
                    if conversion == 'a':
                        value = value.decode('latin1')
                    if conversion == 't':
                        value = datetime.datetime.utcfromtimestamp(value).isoformat(' ', 'seconds')
                    if isbuffer(value):
                        last = ByteStringWrapper(value)
                    elif isinstance(value, ByteStringWrapper):
                        last = value
                    args.append(value)
                    if name.isdecimal():
                        index = int(name)
                        limit = len(args) - 1
                        if index > limit:
                            self.log_warn(F'cannot assign index field {name}, the highest index is {limit}')
                        else:
                            args[index] = value
                        continue
                    elif name:
                        meta[name] = value

                if until and not until(meta):
                    self.log_info(F'the expression ({until}) evaluated to zero; aborting.')
                    break

                size = reader.tell() - checkpoint
                reader.seek(checkpoint)

                for template in self.args.outputs:
                    full = reader.read(size)
                    if last:
                        last = last.binary
                    else:
                        for k in range(len(args) - 1, -1, -1):
                            if isbuffer(args[k]):
                                last = args[k]
                                break
                        else:
                            last = B''
                    output = meta.format_bin(template, self.codec, full, *args, **{'$': last})
                    for _, key, _, _ in formatter.parse(template):
                        meta.pop(key, None)
                    yield self.labelled(output, **meta)

            except EOF:
                leftover = repr(SizeInt(len(reader) - checkpoint)).strip()
                self.log_info(F'discarding {leftover} left in buffer')
                break
