#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from struct import pack
from zlib import crc32

from ..... import Unit
from .....lib.dotnet.header import DotNetHeader
from .....lib.spamsum import spamsum


class dnimphash(Unit):
    """
    Compute the .NET Import Hash
    """

    @staticmethod
    def _spamsum(stringlist):
        hashlist = [crc32(s.encode('utf-16le')) for s in stringlist]
        return spamsum(pack(F'<{len(hashlist):d}I', *hashlist))

    def process(self, data):
        t = DotNetHeader(data, parse_resources=False).meta.Streams.Tables
        mlist = list(sorted(set(
            F'{t.ModuleRef[r.ImportScope.Index - 1].Name}::{r.ImportName}'
            for r in t.ImplMap if r.ImportScope.RowType == 0x1A
        )))
        alist = list(sorted(set(
            F'{r.TypeNamespace}::{r.TypeName}'
            for r in t.TypeRef if r.ResolutionScope.RowType == 0x23
        )))
        if self.log_debug():
            for m in mlist:
                self.log_debug(m)
            for a in alist:
                self.log_debug(a)
        return B':'.join((
            self._spamsum(alist),
            self._spamsum(mlist)
        ))
