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
            'characters u and a for reading null-terminated wide and ascii strings. '
            'Additionally, this string can contain format string expressions such as "{foo:8}", to read 8 '
            'bytes and store the result in a meta variable called "foo", or "{bar:H}" to extract an unsigned '
            '16-bit integer into a meta variable called "bar". When a format expression is parsed, all '
            'preceeding fields of the structure are available already. Fields that are extracted without '
            'assigning a name are available as positional expressions. For example, the spec "xLxx{:{0}}" '
            'will skip a byte, read a 32bit integer N, skip two more bytes, and then read N bytes. To read all '
            'remaining bytes from the data, specify a field without format, i.e. "{}".'
        )),
        *outputs: arg(metavar='output', type=str, help=(
            'Optional format string expressions containing any of the extracted struct fields. The following '
            'special format items are available: {/} denotes the last field that was extracted using a format '
            'string expression, and {=} denotes all bytes that were read. The default output is {/}.'
        )),
        until: arg('-u', metavar='E', type=str, help=(
            'An expression evaluated on each chunk. Continue parsing only if the result is nonzero.')) = None,
        count: arg.number('-c', help=(
            'A limit on the number of chunks to read. The default is {default}.')) = INF,
    ):
        outputs = outputs or ['{/}']
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
                    output = meta.format_bin(template, self.codec,
                        *args, **{'=': full, '/': last})
                    for _, key, _, _ in formatter.parse(template):
                        meta.pop(key, None)
                    yield self.labelled(output, **meta)

            except EOF:
                leftover = repr(SizeInt(len(reader) - checkpoint)).strip()
                self.log_info(F'discarding {leftover} left in buffer')
                break
