#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pefile import PE, PEFormatError
from struct import unpack

from ..formats import arg, PathExtractorUnit, UnpackResult
from ...units.formats.pe.pemeta import pemeta
from ..formats.pe import get_pe_size


class carve_pe(PathExtractorUnit):
    """
    Extracts anything from the input data that looks like a Portable
    Executable (PE) file.
    """
    def __init__(
        self, *paths, list=False, join=False,
        recursive: arg.switch('-r', help='Extract PE files that are contained in already extracted PEs.') = False,
        keep_root: arg.switch('-R', help='If the input chunk is itself a PE, include it as an output chunk.') = False,
        memdump  : arg.switch('-m', help='Use the virtual memory layout of a PE file to calculate its size.') = False,
        fileinfo : arg.switch('-f', help='Use the PE meta information to deduce a file name meta variable.') = False
    ):
        super().__init__(
            *paths,
            list=list,
            join=join,
            recursive=recursive,
            keep_root=keep_root,
            memdump=memdump,
            fileinfo=fileinfo,
        )

    def unpack(self, data):
        cursor = 0
        mv = memoryview(data)

        while True:
            p = data.find(B'MZ', cursor)
            if p < cursor: break
            cursor = p + 2
            k, = unpack('H', mv[p + 0x3C:p + 0x3E])
            if mv[p + k:p + k + 2] != B'PE':
                continue
            try:
                pe = PE(data=data[p:], fast_load=True)
            except PEFormatError as err:
                self.log_debug('parsing of PE header at 0x{p:08X} failed:', err)
                continue

            pesize = get_pe_size(pe, memdump=self.args.memdump)
            pedata = mv[p:p + pesize]
            info = {}
            if self.args.fileinfo:
                try: info = pemeta.parse_file_info(pe) or {}
                except Exception: pass
            try:
                path = info['OriginalFilename']
            except KeyError:
                extension = 'exe' if pe.is_exe() else 'dll' if pe.is_dll() else 'sys'
                path = F'carve-0x{p:08X}.{extension}'

            if p > 0 or self.args.keep_root:
                yield UnpackResult(path, pedata, offset=p)
                self.log_info(F'extracted PE file of size 0x{pesize:08X} from 0x{p:08X}')
            else:
                self.log_info(F'ignored root file of size 0x{pesize:08X} from 0x{p:08X}')

            if not p or self.args.recursive:
                cursor += pe.OPTIONAL_HEADER.SizeOfHeaders
            else:
                cursor += pesize
