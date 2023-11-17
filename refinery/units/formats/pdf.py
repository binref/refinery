#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Optional, Set, TYPE_CHECKING, cast
from itertools import islice

if TYPE_CHECKING:
    from pypdf.generic import EncodedStreamObject

from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.lib.tools import NoLogging
from refinery.lib.structures import MemoryFile


def isdict(object):
    return isinstance(object, dict) or all(hasattr(object, method) for method in ['items', 'values', 'keys'])


class xtpdf(PathExtractorUnit):
    """
    Extract objects from PDF documents.
    """
    @PathExtractorUnit.Requires('pypdf>=3.1.0', 'formats', 'default')
    def _pypdf2():
        import pypdf
        import pypdf.generic
        return pypdf

    def _walk(self, blob, memo: Optional[Set[int]] = None, *path):
        while isinstance(blob, self._pypdf2.generic.IndirectObject):
            try:
                blob = blob.get_object()
            except Exception:
                break
        if memo is None:
            memo = {id(blob)}
        elif id(blob) in memo:
            return
        else:
            memo.add(id(blob))
        try:
            name = blob['/F']
            blob = blob['/EF']['/F']
        except Exception:
            pass
        else:
            path = *path[:-1], F'/{name}'
        try:
            if TYPE_CHECKING:
                blob: EncodedStreamObject = cast(EncodedStreamObject, blob)
            extract = blob.get_data
        except AttributeError:
            pass
        else:
            yield UnpackResult(''.join(path), extract, kind='object')
            return

        if isinstance(blob, self._pypdf2.generic.ByteStringObject):
            yield UnpackResult(''.join(path), blob, kind='bytes')
            return
        if isinstance(blob, self._pypdf2.generic.TextStringObject):
            yield UnpackResult(''.join(path), blob.encode(self.codec), kind='string')
            return

        if isinstance(blob, (
            self._pypdf2.generic.BooleanObject,
            self._pypdf2.generic.ByteStringObject,
            self._pypdf2.generic.FloatObject,
            self._pypdf2.generic.NameObject,
            self._pypdf2.generic.NullObject,
            self._pypdf2.generic.NumberObject,
            self._pypdf2.generic.RectangleObject,
        )):
            # unhandled PDF objects
            return

        if isinstance(blob, self._pypdf2.generic.TreeObject):
            blob = list(blob)

        pdf = self._pypdf2.generic.PdfObject

        if isinstance(blob, list):
            if (
                len(blob) % 2 == 0
                and all(isinstance(key, str) for key in islice(iter(blob), 0, None, 2))
                and all(isinstance(key, pdf) for key in islice(iter(blob), 1, None, 2))
            ):
                blob = dict(zip(*([iter(blob)] * 2)))
            else:
                for key, value in enumerate(blob):
                    yield from self._walk(value, memo, *path, F'/{key}')
                return

        if not isdict(blob):
            return

        for key, value in blob.items():
            if not isinstance(key, str):
                continue
            if not key.startswith('/'):
                key = F'/{key}'
            yield from self._walk(value, memo, *path, key)

    def unpack(self, data):
        with MemoryFile(data, read_as_bytes=True) as stream:
            with NoLogging():
                pdf = self._pypdf2.PdfReader(stream)
                catalog = pdf.trailer['/Root']
                yield from self._walk(catalog)

    @classmethod
    def handles(self, data: bytearray) -> Optional[bool]:
        return data.startswith(B'%PDF-')
