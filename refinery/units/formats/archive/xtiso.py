#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pycdlib
import pycdlib.dr
import pycdlib.dates
import datetime

from ....lib.structures import MemoryFile
from . import arg, ArchiveUnit


def _fix_VolumeDescriptorDate_parse(self, datestr):
    datestr = datestr[:-3] + b'00\0'
    return _original_VolumeDescriptorDate_parse(self, datestr)


_original_VolumeDescriptorDate_parse = pycdlib.dates.VolumeDescriptorDate.parse
pycdlib.dates.VolumeDescriptorDate.parse = _fix_VolumeDescriptorDate_parse


_ISO_FILE_SYSTEMS = ['udf', 'joliet', 'rr', 'iso', 'auto']


class xtiso(ArchiveUnit):
    """
    Extract files from a ISO archive.
    """
    def __init__(self, *paths, list=False, join_path=False, drop_path=False, path=b'path', date=b'date',
        fs: arg.choice('-s', metavar='TYPE', choices=_ISO_FILE_SYSTEMS, help=(
            'Specify a file system ({choices}) extension to use. The default setting {default} will automatically '
            'detect the first of the other available options and use it.')) = 'auto'
    ):
        if fs not in _ISO_FILE_SYSTEMS:
            raise ValueError(F'invalid file system {fs}: must be udf, joliet, rr, iso, or auto.')
        super().__init__(*paths, list=list, join_path=join_path, drop_path=drop_path, path=path, date=date, fs=fs)

    def unpack(self, data):
        with MemoryFile(data) as stream:
            iso = pycdlib.PyCdlib()
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
                facade = iso.get_udf_facade()
            elif iso.has_joliet():
                facade = iso.get_joliet_facade()
            elif iso.has_rock_ridge():
                facade = iso.get_rock_ridge_facade()
            else:
                facade = iso.get_iso9660_facade()

            for root, _, files in facade.walk('/'):
                root = root.rstrip('/')
                for name in files:
                    name = name.lstrip('/')
                    path = F'{root}/{name}'
                    try:
                        info = facade.get_record(path)
                    except Exception:
                        info = None
                        date = None
                    else:
                        date = datetime.datetime(
                            info.date.years_since_1900 + 1900,
                            info.date.month,
                            info.date.day_of_month,
                            info.date.hour,
                            info.date.minute,
                            info.date.second,
                            tzinfo=datetime.timezone(datetime.timedelta(minutes=15 * info.date.gmtoffset))
                        )

                    def extract(info=info):
                        if info:
                            buffer = MemoryFile(bytearray(info.data_length))
                        else:
                            buffer = MemoryFile(bytearray())
                        facade.get_file_from_iso_fp(buffer, path)
                        return buffer.getvalue()

                    yield self._pack(path, date, extract)
