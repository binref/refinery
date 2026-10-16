from __future__ import annotations

import codecs
import functools
import re

from itertools import islice
from typing import TYPE_CHECKING, Callable, Generic, TypeVar, cast

if TYPE_CHECKING:
    from pikepdf import Object, Pdf
    from pymupdf import Document, TextPage
    from pypdf.generic import EncodedStreamObject

from refinery.lib import json
from refinery.lib.meta import MV
from refinery.lib.structures import MemoryFile
from refinery.lib.tools import NoLogging, exception_to_string
from refinery.units.formats.archive import ArchiveUnit, UnpackResult

_T = TypeVar('_T')


def isdict(object):
    return isinstance(object, dict) or all(hasattr(object, method) for method in ['items', 'values', 'keys'])


class _Deferred(Generic[_T]):
    """
    Reads a value from an open PDF document when it is first asked for and keeps it, so that the
    outputs which share it read it only once. It holds on to the given document, which has to stay
    open until then.
    """
    __slots__ = '_document', '_read', '_value'

    def __init__(self, document: object, read: Callable[[], _T]):
        self._document = document
        self._read = read
        self._value: _T | None = None

    def __call__(self) -> _T:
        if (value := self._value) is None:
            value = self._value = self._read()
        return value


def _stream_contents(stream: Object) -> bytearray:
    """
    The decoded data of the given PDF stream, or its raw data if it cannot be decoded.
    """
    with NoLogging():
        try:
            buffer = stream.get_stream_buffer()
        except Exception:
            buffer = stream.get_raw_stream_buffer()
    return bytearray(buffer)


def _text_page(document: Document, page: int) -> TextPage:
    """
    The text of the given page of the given document, as pymupdf lays it out.
    """
    with NoLogging(NoLogging.Mode.ALL):
        return document[page].get_textpage()


_PDF_NAME_OR_REFERENCE = re.compile(r'/([^\s/\[\]<>(){}%]+)|(\d+)\s+\d+\s+R')


def _image_filters(document: Document, xref: int) -> list[str]:
    """
    The names of the compression filters of the image with the given cross-reference number, in
    the order in which they apply, read as mupdf reads them: the abbreviation `F` takes precedence
    over the key `Filter`, references are resolved, and a reference to an object that does not exist
    is null. An item of the filter array that is not a name gives an empty name.
    """
    def resolved(number: str) -> str:
        if not 0 < (n := int(number)) < document.xref_length():
            return 'null'
        return document.xref_object(n, compressed=True)

    def resolved_name(number: str) -> str:
        if (item := resolved(number)).startswith('/'):
            return item[1:]
        return ''

    for key in ('F', 'Filter'):
        kind, value = document.xref_get_key(xref, key)
        if kind != 'null':
            break
    if kind == 'xref':
        value = resolved(value.split()[0])
    elif kind not in ('name', 'array'):
        return []
    if not value.startswith(('/', '[')):
        return []
    return [name or resolved_name(number) for name, number in _PDF_NAME_OR_REFERENCE.findall(value)]


def _image_extension(document: Document, xref: int) -> str:
    """
    The file extension of the image with the given cross-reference number as pymupdf extracts it:
    an image with a JPEG 2000 filter anywhere among its filters comes out as JPEG 2000, one whose
    last filter is JPEG comes out as JPEG, and every other image is converted to PNG.
    """
    filters = _image_filters(document, xref)
    if 'JPXDecode' in filters:
        return 'jp2'
    if filters and filters[-1] in ('DCTDecode', 'DCT'):
        return 'jpg'
    return 'png'


class xtpdf(ArchiveUnit):
    """
    Extract objects from PDF documents.
    """
    # @ArchiveUnit.Requires('pypdf>=3.1.0')
    # def _pypdf2():
    #     import pypdf
    #     import pypdf.generic
    #     return pypdf

    @ArchiveUnit.Requires('pikepdf<=9.5', 1)
    def _pikepdf():
        import pikepdf
        return pikepdf

    @ArchiveUnit.Requires('pymupdf', 1)
    def _mupdf():
        import os
        for setting in ('PYMUPDF_MESSAGE', 'PYMUPDF_LOG'):
            os.environ[setting] = F'path:{os.devnull}'
        import pymupdf
        return pymupdf

    def _walk_pypdf2(self, blob, memo: set[int] | None = None, *path):
        lib = self._pypdf2

        while isinstance(blob, lib.generic.IndirectObject):
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
            yield UnpackResult(''.join(path), extract, **{MV.TYPE: 'object'})
            return

        if isinstance(blob, lib.generic.ByteStringObject):
            yield UnpackResult(''.join(path), blob, **{MV.TYPE: 'bytes'})
            return
        if isinstance(blob, lib.generic.TextStringObject):
            yield UnpackResult(
                ''.join(path),
                blob.encode(self.codec),
                **{MV.TYPE: 'string'}
            )
            return

        if isinstance(blob, (
            lib.generic.BooleanObject,
            lib.generic.ByteStringObject,
            lib.generic.FloatObject,
            lib.generic.NameObject,
            lib.generic.NullObject,
            lib.generic.NumberObject,
            lib.generic.RectangleObject,
        )):
            # unhandled PDF objects
            return

        if isinstance(blob, lib.generic.TreeObject):
            blob = list(blob)

        pdf = lib.generic.PdfObject

        if isinstance(blob, list):
            if (
                len(blob) % 2 == 0
                and all(isinstance(key, str) for key in islice(iter(blob), 0, None, 2))
                and all(isinstance(key, pdf) for key in islice(iter(blob), 1, None, 2))
            ):
                blob = dict(zip(*([iter(blob)] * 2)))
            else:
                for key, value in enumerate(blob):
                    yield from self._walk_pypdf2(value, memo, *path, F'/{key}')
                return

        if not isdict(blob):
            return

        assert isinstance(blob, dict)

        for key, value in blob.items():
            if not isinstance(key, str):
                continue
            if not key.startswith('/'):
                key = F'/{key}'
            yield from self._walk_pypdf2(value, memo, *path, key)

    def _walk_pike(
        self,
        document: Pdf,
        blob: Object,
        memo: dict[tuple[int, int], _Deferred[bytearray] | None],
        *keys,
    ):
        """
        Walks the given object of the given PDF document and hands out what it contains below the
        given path; a stream is decoded only when it is extracted. The memo maps every indirect
        object that was walked to the reader of its stream, or to `None` if it has none: An object
        reached a second time is not walked again, but a stream that a file specification embeds
        comes out under every name that embeds it, decoded only once.
        """
        pike = self._pikepdf

        def indirect(node) -> tuple[int, int] | None:
            if isinstance(node, pike.Object) and node.is_indirect:
                return node.objgen
            return None

        if (objgen := indirect(blob)) is not None:
            if objgen in memo:
                return
            memo[objgen] = None

        try:
            name = blob['/F']
            embedded = blob['/EF']['/F']
        except Exception:
            pass
        else:
            def unhex(match):
                return bytes.fromhex(match[1]).decode('latin1')
            name = re.sub('#([0-9a-fA-F]{2})', unhex, str(name))
            keys = *keys, F'/{name}'
            if (objgen := indirect(embedded)) is not None:
                if objgen in memo:
                    if (contents := memo[objgen]) is not None:
                        yield UnpackResult(''.join(keys), contents)
                    return
                memo[objgen] = None
            blob = embedded

        path = ''.join(keys)

        if isinstance(blob, pike.Array):
            for key, value in enumerate(iter(blob)):
                if isinstance(value, pike.Object):
                    yield from self._walk_pike(document, value, memo, *keys, F'/{key}')
        elif isinstance(blob, pike.Stream):
            contents = _Deferred(document, lambda b=blob: _stream_contents(b))
            if (objgen := indirect(blob)) is not None:
                memo[objgen] = contents
            yield UnpackResult(path, contents)
        elif isinstance(blob, pike.String):
            yield UnpackResult(path, bytes(blob))
        elif isinstance(blob, pike.Object):
            if isinstance(blob, pike.Dictionary):
                for key, value in blob.items():
                    if isinstance(value, pike.Object) and not isinstance(value, pike.Name):
                        yield from self._walk_pike(document, value, memo, *keys, key)
            yield UnpackResult(F'{path}.json', blob.to_json(dereference=True))

    def unpack(self, data):
        if not (password := self.args.pwd):
            password = None
            password_raw = b''
            password_str = r''
        elif isinstance(password, (bytes, bytearray, memoryview)):
            password_raw = password
            password_str = codecs.decode(password, self.codec)
        elif isinstance(password, str):
            password_raw = codecs.encode(password, self.codec)
            password_str = password
        else:
            raise TypeError('The password argument is not a (byte) string.')
        try:
            mu = self._mupdf.open(stream=data, filetype='pdf')
        except Exception:
            mu = None
        else:
            if password:
                if mu.is_encrypted:
                    try:
                        mu.authenticate(password_str)
                    except Exception:
                        mu.authenticate(password_raw)
                else:
                    self.log_warn('This PDF document is not protected; ignoring password argument.')
                    password = None
                    password_str = r''
                    password_raw = b''
            elif mu.is_encrypted:
                raise ValueError('This PDF is password protected.')

        with MemoryFile(data, output=bytes) as stream, NoLogging():
            try:
                pdf = self._pikepdf.open(stream, password=password_raw)
                yield from self._walk_pike(pdf, pdf.trailer, {}, 'raw')
            except Exception:
                raise
                pdf = self._pypdf2.PdfReader(stream, password=password)
                yield from self._walk_pypdf2(pdf.trailer, None, 'raw')

        if mu is None:
            return

        if (md := mu.metadata) and (md := {k: v for k, v in md.items() if v}):
            yield UnpackResult('parsed/meta.json', lambda m=md: json.dumps(m))

        codec = self.codec
        extractors: list[tuple[str, Callable[[TextPage], str]]] = [
            ('html', lambda t: t.extractHTML()),
            ('json', lambda t: t.extractJSON()),
            ('txt', lambda t: t.extractText()),
        ]
        layout = functools.lru_cache(maxsize=1)(functools.partial(_text_page, mu))

        for k in range(len(mu)):
            for extension, extract in extractors:
                yield UnpackResult(
                    F'parsed/page{k}.{extension}', lambda e=extract, k=k: e(layout(k)).encode(codec)
                )
            try:
                with NoLogging(NoLogging.Mode.ALL):
                    images = [(xref, _image_extension(mu, xref)) for xref, *_ in mu.get_page_images(k)]
            except Exception as error:
                self.log_warn(F'failed to list the images of page {k}: {exception_to_string(error)}')
                continue
            for j, (xref, extension) in enumerate(images, 1):
                yield UnpackResult(
                    F'parsed/page{k}/img{j}.{extension}', lambda x=xref: mu.extract_image(x)['image']
                )

    @classmethod
    def handles(cls, data) -> bool | None:
        return data[:5] == B'%PDF-'
