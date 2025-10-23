"""
A package containing Portable Executable (PE) file related units.
"""
from __future__ import annotations

from refinery.lib import lief
from refinery.lib.tools import NoLoggingProxy
from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


def get_pe_size(
    pe: buf | lief.PE.Binary,
    overlay=True,
    sections=True,
    directories=True,
    certificate=True,
    memdump=False,
) -> int:
    """
    This fuction determines the size of a PE file, optionally taking into account the PE overlay
    computation, section information, data directory information, and certificate entries.
    """
    if not isinstance(pe, (NoLoggingProxy, lief.PE.Binary)):
        pe = lief.load_pe_fast(pe)

    overlay_value = overlay and pe.overlay_offset or 0

    sections_value = sections and max((
        s.pointerto_raw_data + s.sizeof_raw_data
        for s in pe.sections
    ), default=0) or 0

    memdump_value = memdump and max((
        s.virtual_address + s.virtual_size
        for s in pe.sections
    ), default=0) or 0

    try:
        cert_entry = pe.data_directory(lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE)
    except LookupError:
        cert_entry = None
        certificate = False

    if certificate and cert_entry:
        # The certificate overlay is given as a file offset
        # rather than a virtual address.
        cert_value = cert_entry.rva + cert_entry.size
    else:
        cert_value = 0

    if directories:
        directories_value = max((
            pe.rva_to_offset(d.rva) + d.size
            for d in pe.data_directories
            if d.type != lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE
        ), default=0)
        directories_value = max(directories_value, cert_value)
    else:
        directories_value = 0

    return max(
        overlay_value,
        sections_value,
        directories_value,
        memdump_value
    )


class OverlayUnit(Unit, abstract=True):
    def __init__(
        self,
        certificate: Param[bool, Arg.Switch('--cert', '-c',
            help='Include digital signatures for the size computation.')] = False,
        directories: Param[bool, Arg.Switch('--dirs', '-d',
            help='Include data directories for size computation.')] = False,
        memdump: Param[bool, Arg.Switch('-m', help='Assume that the file data was a memory-mapped PE file.')] = False,
        **other
    ):
        super().__init__(certificate=certificate, directories=directories, memdump=memdump, **other)

    def _get_size(self, data):
        return get_pe_size(
            data,
            directories=self.args.directories,
            certificate=self.args.certificate,
            memdump=self.args.memdump
        )
