#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import zlib
from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.lib.dotnet.types import (
    Box,
    Byte,
    StreamReader,
    StringPrimitive,
    UInt32,
    UInt64,
    ParserEOF
)


class BundleFileEntry():
    def __init__(self, data, offset, size, compressed_size, ftype, rel_path):
        self.Name = rel_path
        self.Data = self.get_data(self.reader(data), offset, size, compressed_size, ftype)
    
    def get_data(self, reader, offset, size, compressed_size, ftype):
        reader.seek(offset)

        if compressed_size:
            compressed_data = reader.read(compressed_size)
            return self._decompress(compressed_data)
            
        else:
            return reader.read(size)
    
    def reader(self, data):
        return StreamReader(data)
    
    def _decompress(self, data):
        if data[0] == 0x78 or data[0:2] == B'\x1F\x8B':
            mode_candidates = [15 | 0x20, -15, 0]
        else:
            mode_candidates = [-15, 15 | 0x20, 0]
        for mode in mode_candidates:
            try:
                z = zlib.decompressobj(mode)
                return z.decompress(data)
            except zlib.error:
                pass
        raise ValueError('could not detect any zlib stream.')

class DotNetSingleFileBundle:
    """
    Ported to Python from sfextract .NET project
    https://github.com/Droppers/SingleFileExtractor/tree/main
    """
    def __init__(self, data, pe=None, parse_resources=True):
        try:
            self.data = data
            self.manifest_offset = self._find_bundle_manifest_offset()
            self.resources = []
            self._parse_bundle_manifest()
        except IndexError:
            if not data: raise

    _bundle_signature = bytes([
        # 32 bytes represent the bundle signature: SHA-256 for ".net core bundle"
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
        0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
        0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae
    ])

    def _find_bundle_manifest_offset(self) -> int:
        bundle_sig_offset = self.data.find(self._bundle_signature, 0)
        if bundle_sig_offset < 0:
            # Didn't find the single file app signature
            raise ValueError("Can't find valid Bundle Manifest offset. Is this a .NET Bundle?")
        return int.from_bytes(self.data[bundle_sig_offset-8:bundle_sig_offset], "little")

    def _parse_bundle_manifest(self):
        def parse(reader):
            reader.seek(self.manifest_offset)

            major_version = reader.expect(UInt32)
            minor_version = reader.expect(UInt32)
            file_count = reader.expect(UInt32)
            bundle_hash = reader.expect(StringPrimitive)

            if major_version >= 2:
                reader.expect(UInt64) # depsOffset
                reader.expect(UInt64) # depsSize
                reader.expect(UInt64) # runtimeConfigOffset
                reader.expect(UInt64) # runtimeConfigSize
                flags = reader.expect(UInt64) # flags

            for file in range(file_count):
                try:
                    offset = reader.expect(UInt64)
                    size = reader.expect(UInt64)
                    compressed_size = 0

                    if major_version >= 6:
                        compressed_size = reader.expect(UInt64)

                    ftype = reader.expect(Byte)
                    rel_path = reader.expect(StringPrimitive)

                    entry = BundleFileEntry(self.data, offset, size, compressed_size, ftype, rel_path)

                    yield Box(
                        Name=entry.Name,
                        Data=entry.Data
                    )
                except ParserEOF:
                    yield Box(
                        Name='Empty',
                        Data=B''
                    )
        self.files = list(parse(self.reader(self.data)))

    def reader(self, data):
        return StreamReader(data)

class dnsfx(PathExtractorUnit):
    """
    Extract .NET single file application
    https://github.com/Droppers/SingleFileExtractor/tree/main
    """        

    def unpack(self, data):
        bundle = DotNetSingleFileBundle(data)

        for file in bundle.files:
            yield UnpackResult(file.Name, file.Data)