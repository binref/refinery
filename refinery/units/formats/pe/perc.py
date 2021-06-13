#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import enum
import pefile
import re

from .. import UnpackResult, PathExtractorUnit


class RSRC(enum.IntEnum):
    CURSOR        = 0x01  # noqa
    BITMAP        = 0x02  # noqa
    ICON          = 0x03  # noqa
    MENU          = 0x04  # noqa
    DIALOG        = 0x05  # noqa
    STRING        = 0x06  # noqa
    FONTDIR       = 0x07  # noqa
    FONT          = 0x08  # noqa
    ACCELERATOR   = 0x09  # noqa
    RCDATA        = 0x0A  # noqa
    MESSAGETABLE  = 0x0B  # noqa
    VERSION       = 0x10  # noqa
    DLGINCLUDE    = 0x11  # noqa
    PLUGPLAY      = 0x13  # noqa
    VXD           = 0x14  # noqa
    ANICURSOR     = 0x15  # noqa
    ANIICON       = 0x16  # noqa
    HTML          = 0x17  # noqa
    MANIFEST      = 0x18  # noqa


class perc(PathExtractorUnit):
    """
    Extract PE file resources.
    """
    def __init__(self, *paths, list=False, join_path=False, drop_path=False, regex=False, path=b'path'):
        def fixpath(p: str):
            if regex or not p.isidentifier():
                return p
            return re.compile(FR'^.*?{re.escape(p)}.*$')
        super().__init__(*(fixpath(p) for p in paths),
            list=list, join_path=join_path, drop_path=drop_path, path=path)

    def _search(self, pe, directory, level=0, *parts):
        if level >= 3:
            self.log_warn(F'unexpected resource tree level {level + 1:d}')
        for entry in directory.entries:
            if entry.name:
                identifier = str(entry.name)
            elif level == 0 and entry.id in iter(RSRC):
                identifier = RSRC(entry.id).name
            elif entry.id is not None:
                identifier = str(entry.id)
            else:
                self.log_warn(F'resource entry has name {entry.name} and id {entry.id} at level {level + 1:d}')
                continue
            if entry.struct.DataIsDirectory:
                yield from self._search(pe, entry.directory, level + 1, *parts, identifier)
            else:
                path = '/'.join((*parts, identifier))
                yield UnpackResult(path, data=lambda p=pe, e=entry:
                    p.get_data(e.data.struct.OffsetToData, e.data.struct.Size))

    def unpack(self, data):
        pe = pefile.PE(data=data)
        try:
            yield from self._search(pe, pe.DIRECTORY_ENTRY_RESOURCE)
        except AttributeError:
            pass
