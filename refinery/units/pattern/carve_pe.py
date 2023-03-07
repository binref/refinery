#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pefile import PE, PEFormatError
from struct import unpack

from refinery.units.formats import Arg, PathExtractorUnit, UnpackResult
from refinery.units.formats.pe import get_pe_size
from refinery.units.formats.pe.pemeta import pemeta


class carve_pe(PathExtractorUnit):
    """
    Extracts anything from the input data that looks like a Portable
    Executable (PE) file.
    """
    def __init__(
        self, *paths, list=False, join_path=False, drop_path=False, path=b'name',
        recursive: Arg.Switch('-r', help='Extract PE files that are contained in already extracted PEs.') = False,
        keep_root: Arg.Switch('-k', help='If the input chunk is itself a PE, include it as an output chunk.') = False,
        memdump  : Arg.Switch('-m', help='Use the virtual memory layout of a PE file to calculate its size.') = False,
        fileinfo : Arg.Switch('-f', help='Use the PE meta information to deduce a file name meta variable.') = False
    ):
        super().__init__(
            *paths,
            list=list,
            join_path=join_path,
            drop_path=drop_path,
            path=path,
            recursive=recursive,
            keep_root=keep_root,
            memdump=memdump,
            fileinfo=fileinfo,
        )

    def unpack(self, data):
        cursor = 0
        mv = memoryview(data)

        while True:
            offset = data.find(B'MZ', cursor)
            if offset < cursor: break
            cursor = offset + 2
            ntoffset = mv[offset + 0x3C:offset + 0x3E]
            if len(ntoffset) < 2:
                return
            ntoffset, = unpack('H', ntoffset)
            if mv[offset + ntoffset:offset + ntoffset + 2] != B'PE':
                self.log_debug(F'invalid NT header signature for candidate at 0x{offset:08X}')
                continue
            try:
                pe = PE(data=data[offset:], fast_load=True)
            except PEFormatError as err:
                self.log_debug(F'parsing of PE header at 0x{offset:08X} failed:', err)
                continue

            pesize = get_pe_size(pe, memdump=self.args.memdump)
            pedata = mv[offset:offset + pesize]
            info = {}
            if self.args.fileinfo:
                pe_meta_parser = pemeta()
                try:
                    info = pe_meta_parser.parse_version(pe) or {}
                except Exception as error:
                    self.log_warn(F'Unable to obtain file information: {error!s}')
                try:
                    info.update(pe_meta_parser.parse_header(pe) or {})
                except Exception:
                    pass
            try:
                path = info['OriginalFilename']
            except KeyError:
                try:
                    path = info['ExportName']
                except KeyError:
                    extension = 'exe' if pe.is_exe() else 'dll' if pe.is_dll() else 'sys'
                    path = F'carve-0x{offset:08X}.{extension}'

            if offset > 0 or self.args.keep_root:
                yield UnpackResult(path, pedata, offset=offset)
                self.log_info(F'extracted PE file of size 0x{pesize:08X} from 0x{offset:08X}')
            else:
                self.log_info(F'ignored root file of size 0x{pesize:08X} from 0x{offset:08X}')
                continue

            if not offset or self.args.recursive:
                cursor += pe.OPTIONAL_HEADER.SizeOfHeaders
            else:
                cursor += pesize - 2
