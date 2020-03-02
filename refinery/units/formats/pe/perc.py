#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pefile
from fnmatch import fnmatch

from ... import Unit


class rsrc:
    RESOURCE_TYPES = {
        'CURSOR': 1,
        'BITMAP': 2,
        'ICON': 3,
        'MENU': 4,
        'DIALOG': 5,
        'STRING': 6,
        'FONTDIR': 7,
        'FONT': 8,
        'ACCELERATOR': 9,
        'RCDATA': 10,
        'MESSAGETABLE': 11,
        'VERSION': 16,
        'DLGINCLUDE': 17,
        'PLUGPLAY': 19,
        'VXD': 20,
        'ANICURSOR': 21,
        'ANIICON': 22,
        'HTML': 23,
        'MANIFEST': 24,
    }

    @staticmethod
    def to_name(number):
        for key in rsrc.RESOURCE_TYPES:
            if rsrc.RESOURCE_TYPES[key] == number:
                return key
        return str(number)

    def __init__(self, path):
        self.root = False
        self.needles = tuple(
            self._parse(k, x)
            for k, x in enumerate(path.split('/'))
        )

    def relax(self):
        return rsrc(F'*/{self}')

    def __str__(self):
        return '/'.join(self.to_name(x) for x in self.needles)

    def _parse(self, index, s):
        if not index:
            try:
                translation = self.RESOURCE_TYPES[s]
            except KeyError:
                pass
            else:
                self.root = True
                return translation
        try:
            return int(s, 0)
        except ValueError:
            pass
        return s


class perc(Unit):
    """
    Extract PE file resources.
    """

    @classmethod
    def interface(cls, argp):
        argp.add_argument(metavar='entry', dest='entries', type=rsrc, nargs='*',
            help='A resource path for the resource to be extracted. May contain numeric '
                 'literals and name strings with wildcards.')
        return super().interface(argp)

    def _match(self, level, needle, e):
        if e.id == needle or str(e.id) == needle:
            return True
        if level == 0 and rsrc.to_name(needle) == str(e.name):
            return True
        elif fnmatch(str(e.name), str(needle)):
            return True
        return False

    def _search(self, pe, directory, needles, level=0, path=('.rsrc',)):
        try:
            needle = needles[level]
        except IndexError:
            if level >= 3:
                self.log_warn(F'unexpected resource tree level {level + 1:d}')
            needle = '*'

        for e in directory.entries:
            if self._match(level, needle, e):
                id_string = e.id if level else rsrc.to_name(e.id)
                new_path = path + (str(e.name if e.name else id_string),)
                if e.struct.DataIsDirectory:
                    yield from self._search(pe, e.directory, needles, level + 1, new_path)
                elif needles:
                    yield pe.get_data(e.data.struct.OffsetToData, e.data.struct.Size)
                else:
                    yield '/'.join(new_path[1:]).encode('UTF8')

    def process(self, data):
        pe = pefile.PE(data=data)
        if not self.args.entries:
            yield from self._search(pe, pe.DIRECTORY_ENTRY_RESOURCE, [])
            return
        for arg in self.args.entries:
            while len(arg.needles) <= 3:
                self.log_info('searching pattern:', str(arg))
                yield from self._search(pe, pe.DIRECTORY_ENTRY_RESOURCE, arg.needles)
                arg = arg.relax()
