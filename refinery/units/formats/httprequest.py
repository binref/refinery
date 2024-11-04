#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Union, Dict, List

from cgi import parse_header, FieldStorage
from email.message import Message
from enum import Enum
from urllib.parse import parse_qs

from refinery.units import Unit
from refinery.lib.structures import MemoryFile


class _Fmt(str, Enum):
    RawBody = ''
    UrlEncode = 'application/x-www-form-urlencoded'
    Multipart = 'multipart/form-data'


class httprequest(Unit):
    """
    Parses HTTP request data, as you would obtain from a packet dump. The unit extracts
    POST data in any format; each uploaded file is emitted as a separate chunk.
    """
    def process(self, data):
        def header(line: bytes):
            name, colon, data = line.decode('utf8').partition(':')
            if colon:
                yield (name.strip().lower(), data.strip())

        head, _, body = data.partition(b'\r\n\r\n')
        request, *headers = head.splitlines(False)
        headers = dict(t for line in headers for t in header(line))
        method, path, _, *rest = request.split()

        info = {}
        mode = _Fmt.RawBody

        if rest:
            self.log_warn('unexpected rest data while parsing HTTP request:', rest)

        if method == b'GET' and not body:
            mode = _Fmt.UrlEncode
            body = path.partition(B'?')[1]
        if method == b'POST' and (ct := headers.get('content-type', None)):
            ct, info = parse_header(ct)
            mode = _Fmt(ct)

        def chunks(upload: Dict[Union[str, bytes], List[bytes]]):
            for key, values in upload.items():
                if not isinstance(key, str):
                    key = key.decode('utf8')
                for value in values:
                    yield self.labelled(value, name=key)

        if mode is _Fmt.RawBody:
            yield body
            return
        if mode is _Fmt.Multipart:
            boundary = info['boundary']
            headers = Message()
            headers.set_type(F'{_Fmt.Multipart.value}; boundary={boundary}')
            try:
                headers['Content-Length'] = info['CONTENT-LENGTH']
            except KeyError:
                pass
            fs = FieldStorage(MemoryFile(body, read_as_bytes=True),
                headers=headers, environ={'REQUEST_METHOD': method.decode()})
            for name in fs:
                fields = fs[name]
                if not isinstance(fields, list):
                    fields = [fields]
                for field in fields:
                    field: FieldStorage
                    chunk = self.labelled(field.value)
                    if fn := field.filename:
                        chunk.meta['name'] = fn
                    yield chunk
        if mode is _Fmt.UrlEncode:
            yield from chunks(parse_qs(body, keep_blank_values=1))

    @classmethod
    def handles(self, data: bytearray) -> bool | None:
        return data.startswith(B'POST ') or data.startswith(B'GET ')
