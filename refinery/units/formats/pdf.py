from __future__ import annotations

import re

from itertools import islice
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from pypdf.generic import EncodedStreamObject
    from pymupdf import Page

from refinery.lib.mime import get_cached_file_magic_info
from refinery.lib.structures import MemoryFile
from refinery.lib.tools import NoLogging
from refinery.units.formats.archive import ArchiveUnit, UnpackResult


def isdict(object):
    return isinstance(object, dict) or all(hasattr(object, method) for method in ['items', 'values', 'keys'])


class xtpdf(ArchiveUnit):
    """
    Extract objects from PDF documents.
    """
    @ArchiveUnit.Requires('pypdf>=3.1.0', ['formats', 'default', 'extended'])
    def _pypdf2():
        import pypdf
        import pypdf.generic
        return pypdf

    @ArchiveUnit.Requires('pymupdf', ['formats', 'default', 'extended'])
    def _mupdf():
        import os
        for setting in ('PYMUPDF_MESSAGE', 'PYMUPDF_LOG'):
            os.environ[setting] = F'path:{os.devnull}'
        import pymupdf
        return pymupdf

    def _walk_raw(self, blob, memo: set[int] | None = None, *path):
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
            def unhex(match):
                return bytes.fromhex(match[1]).decode('latin1')
            name = re.sub('#([0-9a-fA-F]{2})', unhex, name)
            path = *path[:-1], F'/{name}'
        try:
            def extract():
                with NoLogging():
                    return get_data()
            if TYPE_CHECKING:
                blob = cast(EncodedStreamObject, blob)
            get_data = blob.get_data
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
                    yield from self._walk_raw(value, memo, *path, F'/{key}')
                return

        if not isdict(blob):
            return

        assert isinstance(blob, dict)

        for key, value in blob.items():
            if not isinstance(key, str):
                continue
            if not key.startswith('/'):
                key = F'/{key}'
            yield from self._walk_raw(value, memo, *path, key)

    def unpack(self, data):
        try:
            mu = self._mupdf.open(stream=data, filetype='pdf')
        except Exception:
            mu = password = None
        else:
            if password := self.args.pwd or None:
                if mu.is_encrypted:
                    mu.authenticate(password)
                else:
                    self.log_warn('This PDF document is not protected; ignoring password argument.')
                    password = None
            elif mu.is_encrypted:
                raise ValueError('This PDF is password protected.')

        with MemoryFile(data, output=bytes) as stream:
            with NoLogging():
                pdf = self._pypdf2.PdfReader(stream, password=password)
                catalog = pdf.trailer['/Root']
                yield from self._walk_raw(catalog, None, 'raw')

        if mu is None:
            return

        for k in range(len(mu)):
            with NoLogging(NoLogging.Mode.ALL):
                try:
                    page: Page = mu[k]
                    text = page.get_textpage()
                except Exception:
                    continue
            yield UnpackResult(F'parsed/page{k}.html', text.extractHTML().encode(self.codec))
            yield UnpackResult(F'parsed/page{k}.json', text.extractJSON().encode(self.codec))
            yield UnpackResult(F'parsed/page{k}.txt', text.extractText().encode(self.codec))
            for j, image in enumerate(page.get_images(), 1):
                xref = image[0]
                base = mu.extract_image(xref)
                data = base['image']
                info = get_cached_file_magic_info(data)
                yield UnpackResult(F'parsed/page{k}/img{j}.{info.extension}', data)

    @classmethod
    def handles(cls, data: bytearray) -> bool | None:
        return data.startswith(B'%PDF-')
