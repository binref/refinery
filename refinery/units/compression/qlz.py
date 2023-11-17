#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit, RefineryPartialResult
from refinery.lib.meta import SizeInt


_HASH_VALUES             = 0x1000  # noqa
_HASH_MASK               = 0x0FFF  # noqa
_UNCONDITIONAL_MATCHLEN  = 6       # noqa
_UNCOMPRESSED_END        = 4       # noqa


class qlz(Unit):
    """
    This unit implements QuickLZ decompression levels 1 and 3.
    """

    def process(self, data):
        source = memoryview(data)
        head = source[0]
        clvl = (head >> 2) & 0x3

        if head & 2:
            self.log_info('long header detected')
            size = int.from_bytes(source[5:9], 'little')
            source = source[9:]
        else:
            self.log_info('short header detected')
            size = source[3]
            source = source[3:]
        if head & 1 != 1:
            self.log_warn('header indicates that data is uncompressed, returning remaining data')
            return source
        else:
            self.log_info(F'compression level {clvl}, decompressed size {SizeInt(size)!r}')

        def fetchhash():
            return int.from_bytes(destination[hashvalue + 1:hashvalue + 4], byteorder='little')

        codeword = 1
        destination = bytearray()
        hashtable = [0] * _HASH_VALUES
        hashvalue = -1
        last_matchstart = size - _UNCONDITIONAL_MATCHLEN - _UNCOMPRESSED_END - 1
        fetch = 0

        if clvl == 2:
            raise ValueError("This version only supports level 1 and 3")
        while source:
            if codeword == 1:
                codeword = int.from_bytes(source[:4], byteorder='little')
                source = source[4:]
                if len(destination) <= last_matchstart:
                    c = 3 if clvl == 1 else 4
                    fetch = int.from_bytes(source[:c], byteorder='little')
            if codeword & 1:
                codeword = codeword >> 1
                if clvl == 1:
                    hash = (fetch >> 4) & 0xFFF
                    offset = hashtable[hash]
                    if fetch & 0xF:
                        matchlen = (fetch & 0xF) + 2
                        source = source[2:]
                    else:
                        matchlen = source[2]
                        source = source[3:]
                else:
                    if (fetch & 3) == 0:
                        delta = (fetch & 0xFF) >> 2
                        matchlen = 3
                        source = source[1:]
                    elif (fetch & 2) == 0:
                        delta = (fetch & 0xFFFF) >> 2
                        matchlen = 3
                        source = source[2:]
                    elif (fetch & 1) == 0:
                        delta = (fetch & 0xFFFF) >> 6
                        matchlen = ((fetch >> 2) & 15) + 3
                        source = source[2:]
                    elif (fetch & 127) != 3:
                        delta = (fetch >> 7) & 0x1FFFF
                        matchlen = ((fetch >> 2) & 0x1F) + 2
                        source = source[3:]
                    else:
                        delta = fetch >> 15
                        matchlen = ((fetch >> 7) & 255) + 3
                        source = source[4:]
                    offset = (len(destination) - delta) & 0xFFFFFFFF

                for i in range(offset, offset + matchlen):
                    destination.append(destination[i])

                if clvl == 1:
                    fetch = fetchhash()
                    while hashvalue < len(destination) - matchlen:
                        hashvalue += 1
                        hash = ((fetch >> 12) ^ fetch) & _HASH_MASK
                        hashtable[hash] = hashvalue
                        fetch = fetch >> 8 & 0xFFFF
                        try:
                            fetch |= destination[hashvalue + 3] << 16
                        except IndexError:
                            pass
                    fetch = int.from_bytes(source[:3], byteorder='little')
                else:
                    fetch = int.from_bytes(source[:4], byteorder='little')
                hashvalue = len(destination) - 1
            else:
                if len(destination) <= last_matchstart:
                    destination.append(source[0])
                    source = source[1:]
                    codeword = codeword >> 1
                    if clvl == 1:
                        while hashvalue < len(destination) - 3:
                            fetch2 = fetchhash()
                            hashvalue += 1
                            hash = ((fetch2 >> 12) ^ fetch2) & _HASH_MASK
                            hashtable[hash] = hashvalue
                        fetch = fetch >> 8 & 0xFFFF | source[2] << 16
                    else:
                        fetch = fetch >> 8 & 0xFFFF
                        fetch |= source[2] << 16
                        fetch |= source[3] << 24
                else:
                    while len(destination) <= size - 1:
                        if codeword == 1:
                            source = source[4:]
                            codeword = 0x80000000
                        destination.append(source[0])
                        source = source[1:]
                        codeword = codeword >> 1
                    break
        if len(destination) != size:
            raise RefineryPartialResult(
                F'Header indicates decompressed size 0x{size:X}, but 0x{len(destination):X} bytes '
                F'were decompressed.', destination)
        return destination
