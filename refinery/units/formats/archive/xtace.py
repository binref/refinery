#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import acefile

from . import ArchiveUnit
from ....lib.structures import MemoryFile


class xtace(ArchiveUnit):
    """
    Extract files from an ACE archive.
    """
    def unpack(self, data):
        with MemoryFile(data, read_as_bytes=True) as stream:
            with acefile.open(stream) as ace:
                for member in ace.getmembers():
                    member: acefile.AceMember
                    comment = {} if not member.comment else {'comment': member.comment}
                    yield self._pack(
                        member.filename,
                        member.datetime,
                        lambda a=ace: a.read(member, pwd=self.args.pwd),
                        **comment
                    )
