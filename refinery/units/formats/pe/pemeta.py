#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pefile
import json

from ... import Unit


class pemeta(Unit):
    """
    Extract metadata from PE files.
    """

    def _ensure_string(self, x):
        if not isinstance(x, str):
            x = repr(x) if not isinstance(x, bytes) else x.decode(self.codec, 'backslashreplace')
        return x

    def _parse_pedict(self, bin):
        return dict((
            self._ensure_string(key),
            self._ensure_string(val)
        ) for key, val in bin.items())

    def process(self, data):

        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

        try:
            FileInfoList = pe.FileInfo
        except AttributeError:
            return

        for FileInfo in FileInfoList:
            for FileInfoEntry in FileInfo:
                if not hasattr(FileInfoEntry, 'StringTable'):
                    continue
                for StringTableEntry in FileInfoEntry.StringTable:
                    StringTableEntryParsed = self._parse_pedict(StringTableEntry.entries)
                    StringTableEntryParsed['LangID'] = self._ensure_string(StringTableEntry.LangID)
                    return json.dumps(
                        StringTableEntryParsed, sort_keys=True, indent=4, ensure_ascii=False
                    ).encode(self.codec)
