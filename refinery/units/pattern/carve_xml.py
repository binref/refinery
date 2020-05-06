#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import defusedxml.minidom

from typing import Optional
from contextlib import suppress

from .. import Unit


class XMLTag:
    def __init__(self, tag: str):
        match = re.search(R'\A<([/\?]?)([^\W\d][-:\.\w]*)', tag)
        if not match:
            raise ValueError
        self.name = match[2]
        self.mod = match[1]
        self.delta = {'/': -1, '?': 0}.get(self.mod, 1)

    def __repr__(self) -> str:
        return F'<{self.mod}{self.name}>'


class XMLCarver:
    _MAX_TAG_SIZE = 400

    def __init__(self, data):
        self.data = data
        self.cursor = 0

    def __iter__(self):
        return self

    def _try_decode(self, data: bytes) -> Optional[str]:
        def printable(s):
            return re.sub('\\s+', '', s).isprintable()

        for codec in ('UTF8', 'CP1252', 'LATIN-1'):
            with suppress(UnicodeDecodeError):
                decoded = data.decode(codec)
                if printable(decoded): return decoded
        if len(data) % 2 == 1:
            data = data + B'\0'
        with suppress(UnicodeDecodeError):
            decoded = data.decode('UTF-16LE')
            if printable(decoded): return decoded

    def _seek_tag(self, start):
        quote = None
        escaped = False
        for end in range(start + 1, min(start + self._MAX_TAG_SIZE, len(self.data))):
            if not quote:
                if self.data[end] == B'>'[0]:
                    return end + 1
                elif self.data[end] == B'<'[0]:
                    return None
                elif self.data[end] in B''''"''':
                    quote = self.data[end]
            elif escaped:
                escaped = False
            elif self.data[end] == B'\\'[0]:
                escaped = True
            elif self.data[end] == quote:
                quote = None

    def _read_tag(self):
        end = self._seek_tag(self.cursor)
        if end is None:
            return None
        decoded = self._try_decode(self.data[self.cursor:end])
        if decoded is None:
            return None
        try:
            tag = XMLTag(decoded)
        except ValueError:
            return None
        else:
            self.cursor = end
            return tag

    def _find_xml_end(self, tag):
        stack = 1
        while stack:
            self.cursor = self.data.find(B'<', self.cursor)
            if self.cursor < 0:
                return False
            t = self._read_tag()
            if t is None:
                return False
            if t.name == tag.name:
                stack += t.delta
        return True

    def __next__(self):
        while True:
            start = self.data.find(B'<', self.cursor)
            if start < 0:
                raise StopIteration
            self.cursor = start
            tag = self._read_tag()
            if tag and tag.mod == '?' and tag.name.lower() == 'xml':
                self.cursor = self.data.find(B'<', self.cursor)
                if self.cursor < 0:
                    raise StopIteration
                tag = self._read_tag()
            if tag is None:
                self.cursor += 1
                continue
            if self._find_xml_end(tag):
                try:
                    decoded = self._try_decode(self.data[start:self.cursor])
                    if decoded is not None:
                        defusedxml.minidom.parseString(decoded)
                        return decoded.encode(Unit.codec)
                except Exception:
                    pass
            self.cursor = start + 1


class carve_xml(Unit):
    """
    Extracts anything from the input data that looks like XML.
    """

    def process(self, data):
        yield from XMLCarver(data)
