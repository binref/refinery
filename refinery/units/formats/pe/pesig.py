from __future__ import annotations

import struct

from refinery.lib import lief
from refinery.units import RefineryPartialResult, Unit


class pesig(Unit):
    """
    Extracts the contents of the IMAGE_DIRECTORY_ENTRY_SECURITY entry of a PE file,
    i.e. the digital signatures in DER format.
    """
    def process(self, data: bytearray):
        view = memoryview(data)
        pe = lief.load_pe_fast(view)
        security = pe.data_directory(lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE)
        self.log_info(F'signature offset: 0x{security.rva:08X}')
        self.log_info(F'signature length: 0x{security.size:08X}')
        if security.rva == 0 or security.size == 0:
            raise ValueError('IMAGE_DIRECTORY_ENTRY_SECURITY is corrupt.')
        sgnoff = security.rva + 8
        sgnend = sgnoff + security.size
        length, _, _ = struct.unpack('<IHH', view[sgnoff - 8:sgnoff])
        signature = view[sgnoff:sgnend]
        if len(signature) + 8 != length:
            raise RefineryPartialResult(
                F'Found {len(signature) + 8} bytes of signature, but length should be {length}.',
                partial=signature)
        return signature
