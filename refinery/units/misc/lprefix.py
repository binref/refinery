#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from struct import unpack, calcsize

from .. import Unit, arg
from ...lib.structures import StructReader, EOF
from ...lib.types import INF
from ...lib.argformats import PythonExpression


class lprefix(Unit):
    """
    Parse length-prefixed data. The unit repeatedly reads a length prefix from the input data and then reads a number of bytes given by
    the length prefix. The prefix is used as a Python struct expression but may only contain one format character that converts to a number
    when unpacked. However, using alignment operations and filler bytes represented by the format character "x" can help parse more
    complicated length prefixes. If no byte order is specified in the prefix format, the unit uses little endian (no byte alignment).
    """
    def __init__(
        self,
        prefix: arg(nargs='?', type=str,
            help='Choose a Python format string to extract the prefix, default is "{default}".') = 'L',
        count : arg.number('-c', help='Only decode up to {varname} chunks and treat the rest as leftover data.') = INF,
        strict: arg.switch('-S', help='Discard any leftover data with invalid length prefix.') = False,
        single: arg.switch('-s', help='Equivalent to --strict --count=1.') = False,
        header: arg.switch('-H', help='Do not strip the header from the data but include it in the output.') = False,
        derive: arg('-d', metavar='d(N,H)', type=str, help=(
            'Provide an arithmetic Python expression involving the variables N and H, which represents the length prefix that was read '
            'and the size of the header, respectively. The value of this expression is used as the actual number of bytes. The default '
            'expression is "N".')) = None
    ):
        if single:
            strict = True
            count = 1
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
            header=header,
            count=count,
        )

    def process(self, data):
        try:
            meta = data.meta
        except AttributeError:
            meta = {}
        parse = PythonExpression(self.args.derive or 'N', 'N', 'H', *meta)
        hsize = calcsize(self.args.prefix)
        with StructReader(memoryview(data)) as mf:
            count = size = position = 0
            try:
                while not mf.eof:
                    position = mf.tell()
                    if count >= self.args.count:
                        raise EOF
                    size = mf.read_struct(self.args.prefix, unwrap=True)
                    size = parse(N=size, H=hsize, **meta)
                    if self.args.header:
                        mf.seek(position)
                    self.log_info(F'reading chunk of size: {size}')
                    yield mf.read(size)
                    count += 1
            except EOF as eof:
                if self.args.strict or count >= self.args.count:
                    return
                if len(eof.rest) < size:
                    self.log_warn(F'attempted to read 0x{size:X} bytes, got only 0x{len(eof.rest):X}.')
                mf.seek(position)
                yield mf.read()
