#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.structures import StructReader, MemoryFile
from refinery.units import Unit

import itertools


class xtmagtape(Unit):
    """
    Extract files from SIMH magtape files.
    """
    def process(self, data: bytearray):
        reader = StructReader(data)

        for r in itertools.count():
            buffer = MemoryFile()

            for k in itertools.count():
                try:
                    head = reader.peek(4)
                    size = reader.read_integer(24)
                    mark = reader.read_byte()
                except EOFError:
                    self.log_info('end of file while reading chunk header, terminating')
                    return
                if not any(head):
                    if k == 0:
                        return
                    break
                if mark != 0:
                    self.log_warn(F'error code 0x{mark:02X} in record {r}.{k}')
                buffer.write(reader.read(size))
                if reader.peek(4) != head:
                    if reader.tell() % 2 and reader.peek(5)[1:] == head:
                        padding = reader.read_byte()
                        if padding != 0:
                            self.log_info(F'nonzero padding byte in record {r}.{k}')
                    else:
                        raise ValueError('Invalid footer, data is corrupted.')
                reader.seekrel(4)

            yield buffer.getbuffer()
