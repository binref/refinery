#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Union, Dict, List
from email.parser import BytesParser
from enum import Enum
from urllib.parse import parse_qs

from refinery.units import Unit
from refinery.lib.tools import isbuffer


def _parseparam(parameter: str):
    while parameter[:1] == ';':
        parameter = parameter[1:]
        end = parameter.find(';')
        while end > 0 and (parameter.count('"', 0, end) - parameter.count('\\"', 0, end)) % 2:
            end = parameter.find(';', end + 1)
        if end < 0:
            end = len(parameter)
        f = parameter[:end]
        yield f.strip()
        parameter = parameter[end:]


def _parse_header(line: str):
    parts = _parseparam(F';{line}')
    key = next(parts)
    pdict = {}
    for p in parts:
        i = p.find('=')
        if i < 0:
            continue
        name = p[:i].strip().lower()
        value = p[i + 1:].strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
            value = value.replace('\\\\', '\\').replace('\\"', '"')
        pdict[name] = value
    return key, pdict


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

        mode = _Fmt.RawBody

        if rest:
            self.log_warn('unexpected rest data while parsing HTTP request:', rest)

        if method == b'GET' and not body:
            mode = _Fmt.UrlEncode
            body = path.partition(B'?')[1]
        if method == b'POST' and (ct := headers.get('content-type', None)):
            ct, _ = _parse_header(ct)
            try:
                mode = _Fmt(ct)
            except ValueError:
                mode = _Fmt.RawBody

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
            _, _, message_data = data.partition(b'\n')
            msg = BytesParser().parsebytes(message_data)
            for part in msg.walk():
                payloads = part.get_payload(decode=True)
                if not isinstance(payloads, list):
                    payloads = [payloads]
                for payload in payloads:
                    if not isbuffer(payload):
                        continue
                    if name := part.get_filename():
                        payload = self.labelled(payload, name=name)
                    yield payload

        if mode is _Fmt.UrlEncode:
            yield from chunks(parse_qs(body, keep_blank_values=1))

    @classmethod
    def handles(self, data: bytearray) -> bool | None:
        return data.startswith(B'POST ') or data.startswith(B'GET ')
