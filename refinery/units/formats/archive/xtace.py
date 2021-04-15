#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import acefile

from .. import arg, PathExtractorUnit, UnpackResult
from ....lib.structures import MemoryFile


class xtace(PathExtractorUnit):
    """
    Extract files from an ACE archive.
    """
    def __init__(
        self, *paths, list=False, join=False, meta=b'path',
        pwd: arg('-p', help='Optionally specify an extraction password.') = B''
    ):
        super().__init__(*paths, list=list, join=join, pwd=pwd)

    def unpack(self, data):
        with MemoryFile(data, read_as_bytes=True) as stream:
            with acefile.open(stream) as ace:
                for member in ace.getmembers():
                    member: acefile.AceMember
                    kw = dict(date=member.datetime.isoformat(' ', 'seconds'))
                    if member.comment:
                        kw['comment'] = member.comment
                    yield UnpackResult(member.filename, lambda a=ace: a.read(member, pwd=self.args.pwd), **kw)
