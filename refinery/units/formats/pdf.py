from __future__ import annotations

import json
import re

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pikepdf import Object
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
    @ArchiveUnit.Requires('pikepdf==9.2.1', ['formats', 'default', 'extended'])
    def _pikepdf():
        import pikepdf
        return pikepdf

    @ArchiveUnit.Requires('pymupdf', ['formats', 'default', 'extended'])
    def _mupdf():
        import os
        for setting in ('PYMUPDF_MESSAGE', 'PYMUPDF_LOG'):
            os.environ[setting] = F'path:{os.devnull}'
        import pymupdf
        return pymupdf

    def _walk_raw(self, blob: Object, memo: list[Object] | None = None, *keys):
        if memo is None:
            memo = [blob]
        elif blob in memo:
            return
        else:
            memo.append(blob)

        try:
            name = blob['/F']
            blob = blob['/EF']['/F']
        except Exception:
            pass
        else:
            def unhex(match):
                return bytes.fromhex(match[1]).decode('latin1')
            name = re.sub('#([0-9a-fA-F]{2})', unhex, str(name))
            keys = *keys, F'/{name}'

        pike = self._pikepdf
        meta = {}
        path = ''.join(keys)
        done = set()

        if isinstance(blob, pike.Dictionary):
            nested = {}
            for key, value in blob.items():
                if isinstance(value, pike.Name):
                    value = str(value)
                if isinstance(value, (int, float, str, bool)):
                    key = key.lstrip('/')
                    meta[key] = value
                    continue
                nested[key] = value
                done.add(key)
            for key, value in nested.items():
                yield from self._walk_raw(value, memo, *keys, key)
            if meta:
                yield UnpackResult(path, blob.to_json(dereference=True))
                return
        elif isinstance(blob, pike.Array):
            for key, value in enumerate(iter(blob)):
                if isinstance(value, pike.Object):
                    yield from self._walk_raw(value, memo, *keys, F'/{key}')
            return

        try:
            buffer = blob.get_stream_buffer()
        except Exception:
            try:
                buffer = blob.get_raw_stream_buffer()
            except Exception:
                buffer = None
        if buffer or buffer:
            yield UnpackResult(path, bytearray(buffer))
        elif isinstance(blob, pike.String):
            yield UnpackResult(path, bytes(blob))
        elif isinstance(blob, pike.Object):
            yield UnpackResult(path, blob.to_json())

    def unpack(self, data):
        try:
            mu = self._mupdf.open(stream=data, filetype='pdf')
        except Exception:
            mu = None
            password = ''
        else:
            if password := self.args.pwd or '':
                if mu.is_encrypted:
                    mu.authenticate(password)
                else:
                    self.log_warn('This PDF document is not protected; ignoring password argument.')
                    password = ''
            elif mu.is_encrypted:
                raise ValueError('This PDF is password protected.')

        with MemoryFile(data, output=bytes) as stream:
            pdf = self._pikepdf.open(stream, password=password)
            yield from self._walk_raw(pdf.trailer, None, 'raw')

        if mu is None:
            return

        if (md := mu.metadata) and (md := {k: v for k, v in md.items() if v}):
            md = json.dumps(md, indent=4)
            yield UnpackResult('parsed/meta.json', md.encode(self.codec))

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
