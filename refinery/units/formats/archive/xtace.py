#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import ArchiveUnit
from ....lib.thirdparty import acefile
from ....lib.structures import MemoryFile


class xtace(ArchiveUnit):
    """
    Extract files from an ACE archive.
    """
    def unpack(self, data):
        ace = acefile.open(MemoryFile(data, read_as_bytes=True))
        for member in ace.getmembers():
            member: acefile.AceMember
            comment = {} if not member.comment else {'comment': member.comment}
            yield self._pack(
                member.filename,
                member.datetime,
                lambda a=ace, m=member: a.read(m, pwd=self.args.pwd),
                **comment
            )
