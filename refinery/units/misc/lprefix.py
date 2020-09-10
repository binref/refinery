#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from struct import unpack, calcsize

from .. import Unit, arg
from ...lib.structures import StructReader, EOF
from ...lib.types import INF
from ...lib.argformats import PythonExpression


class lprefix(Unit):
    """
    Parse length-prefixed data. The unit repeatedly reads a length prefix from the input data and then
    reads a number of bytes given by the length prefix. The prefix is used as a Python struct expression
    but may only contain one format character that converts to a number when unpacked. However, using
    alignment operations and filler bytes represented by the format character "x" can help parse more
    complicated length prefixes. If no byte order is specified in the prefix format, the unit uses little
    endian (no byte alignment).
    """
    def __init__(
        self,
        prefix: arg(nargs='?', type=str,
            help='Choose a Python format string to extract the prefix, default is "{default}".') = 'L',
        limit: arg.number('limit', metavar='limit',
            help='Only decode up to a given number of chunks and treat the rest as leftover data.') = INF,
        strict: arg.switch('-t', help='Discard any leftover data with invalid length prefix.') = False,
        header: arg('-H', action='count', default=0, help=(
            'Treat the parsed prefix as part of the body. Specify twice to automatically add the size of '
            'the prefix to the calculated length (i.e. the parsed length from the header specifies the '
            'length of the chunk body, but the output should include both head and body.'
        )) = 0,
        derive: arg('-d', metavar='d(N)', type=str, help=(
            'Provide an arithmetic Python expression involving the variable N which represents the length '
            'prefix that was read. The value of this expression is used as the actual number of bytes. '
            'The default expression is "N".')) = None
    ):
        if not prefix:
            raise ValueError('an empty prefix was specified')
        if prefix[0] not in '<!=@>':
            prefix = F'<{prefix}'
        try:
            assert unpack(prefix, calcsize(prefix) * B'\0') == (0,)
        except Exception:
            raise ValueError('invalid format string: {prefix}')
        super().__init__(
            strict=strict,
            prefix=prefix,
            derive=derive,
            limit=limit,
            header=int(header)
        )

    def process(self, data):
        try:
            meta = data.meta
        except AttributeError:
            meta = {}
        parse = PythonExpression(self.args.derive or 'N', 'N', *meta)
        hsize = calcsize(self.args.prefix) if self.args.header > 1 else 0
        with StructReader(memoryview(data)) as mf:
            try:
                count = size = 0
                while not mf.eof:
                    position = mf.tell()
                    if count >= self.args.limit:
                        raise EOF
                    size = mf.read_struct(self.args.prefix, unwrap=True)
                    size = parse(N=size, **meta)
                    if self.args.header:
                        size += hsize
                        mf.seek(position)
                    self.log_info(F'reading chunk of size: {size}')
                    yield mf.read(size)
                    count += 1
            except EOF as eof:
                if len(eof.rest) < size:
                    self.log_info(F'attempted to read 0x{size:X} bytes, got only 0x{len(eof.rest):X}.')
                if self.args.strict:
                    return
                mf.seek(position)
                yield mf.read()
