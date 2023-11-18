#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import datetime

from refinery.lib.structures import MemoryFile
from refinery.units.formats.archive import Arg, ArchiveUnit

_ISO_FILE_SYSTEMS = ['udf', 'joliet', 'rr', 'iso', 'auto']


class xtiso(ArchiveUnit):
    """
    Extract files from a ISO archive.
    """
    def __init__(
        self,
        *paths, list=False, join_path=False, drop_path=False, fuzzy=0, exact=False, regex=False,
        path=b'path', date=b'date',
        fs: Arg.Choice('-s', metavar='TYPE', choices=_ISO_FILE_SYSTEMS, help=(
            'Specify a file system ({choices}) extension to use. The default setting {default} will automatically '
            'detect the first of the other available options and use it.')) = 'auto'
    ):
        if fs not in _ISO_FILE_SYSTEMS:
            raise ValueError(F'invalid file system {fs}: must be udf, joliet, rr, iso, or auto.')
        super().__init__(
            *paths,
            list=list,
            join_path=join_path,
            drop_path=drop_path,
            fuzzy=fuzzy,
            exact=exact,
            regex=regex,
            path=path,
            date=date,
            fs=fs
        )

    @ArchiveUnit.Requires('pycdlib', 'arc', 'default', 'extended')
    def _pycdlib():
        import pycdlib
        import pycdlib.dates

        def fixed_parse(self, datestr):
            datestr = datestr[:-3] + b'00\0'
            return original_parse(self, datestr)

        original_parse = pycdlib.dates.VolumeDescriptorDate.parse
        pycdlib.dates.VolumeDescriptorDate.parse = fixed_parse
        return pycdlib

    @staticmethod
    def _strip_revision(name: str):
        base, split, revision = name.partition(';')
        return base if split and revision.isdigit() else name

    def unpack(self, data):
        if not self.handles(data):
            self.log_warn('The data does not look like an ISO file.')
        with MemoryFile(data, read_as_bytes=True) as stream:
            iso = self._pycdlib.PyCdlib()
            iso.open_fp(stream)
            fs = self.args.fs
            if fs != 'auto':
                mkfacade = {
                    'iso'    : iso.get_iso9660_facade,
                    'udf'    : iso.get_udf_facade,
                    'joliet' : iso.get_joliet_facade,
                    'rr'     : iso.get_rock_ridge_facade,
                }
                facade = mkfacade[fs]()
            elif iso.has_udf():
                self.log_info('using format: udf')
                facade = iso.get_udf_facade()
            elif iso.has_joliet():
                self.log_info('using format: joliet')
                facade = iso.get_joliet_facade()
            elif iso.has_rock_ridge():
                self.log_info('using format: rr')
                facade = iso.get_rock_ridge_facade()
            else:
                self.log_info('using format: iso')
                facade = iso.get_iso9660_facade()

            for root, _, files in facade.walk('/'):
                root = root.rstrip('/')
                for name in files:
                    name = name.lstrip('/')
                    path = F'{root}/{name}'
                    try:
                        info = facade.get_record(path)
                        date = info.date
                    except Exception:
                        info = None
                        date = None
                    else:
                        date = datetime.datetime(
                            date.years_since_1900 + 1900,
                            date.month,
                            date.day_of_month,
                            date.hour,
                            date.minute,
                            date.second,
                            tzinfo=datetime.timezone(datetime.timedelta(minutes=15 * date.gmtoffset))
                        )

                    def extract(info=info, path=path):
                        if info:
                            buffer = MemoryFile(bytearray(info.data_length))
                        else:
                            buffer = MemoryFile(bytearray())
                        facade.get_file_from_iso_fp(buffer, path)
                        return buffer.getvalue()

                    yield self._pack(self._strip_revision(path), date, extract)

    @classmethod
    def handles(cls, data: bytearray) -> bool:
        return any(data[k] == B'CD001' for k in (
            slice(0x8001, 0x8006),
            slice(0x8801, 0x8806),
            slice(0x9001, 0x9006),
        ))
