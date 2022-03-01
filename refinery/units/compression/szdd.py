#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.structures import StructReader
from refinery.units import Unit


class szdd(Unit):
    """
    Extract files from SZDD archives.
    """
    def process(self, data):
        with StructReader(data) as archive:
            if archive.read(8) != b'SZDD\x88\xF0\x27\x33':
                if not self.args.lenient:
                    raise ValueError('signature missing')
                self.log_fail('the header signature is invalid, this is likely not an SZDD archive')
            if archive.read_byte() != 0x41:
                raise ValueError('Unsupported compression mode')
            # ignore the missing file extension letter:
            archive.seekrel(1)
            output_len = archive.u32()
            window_pos = 0x1000 - 0x10
            output_pos = 0
            output = bytearray(output_len)
            window = bytearray(0x1000)
            for k in range(len(window)):
                window[k] = 0x20
            while not archive.eof:
                control = archive.read_byte()
                for cb in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80):
                    if archive.eof:
                        break
                    if control & cb:
                        output[output_pos] = window[window_pos] = archive.read_byte()
                        output_pos += 1
                        window_pos += 1
                        window_pos &= 0xFFF
                    else:
                        match_pos = archive.read_byte()
                        match_len = archive.read_byte()
                        match_pos |= (match_len & 0xF0) << 4
                        match_len = (match_len & 0x0F) + 3
                        match_pos &= 0xFFF
                        for _ in range(match_len):
                            window[window_pos] = window[match_pos]
                            output[output_pos] = window[window_pos]
                            output_pos += 1
                            window_pos += 1
                            match_pos += 1
                            window_pos &= 0xFFF
                            match_pos &= 0xFFF
            return output
