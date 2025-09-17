from __future__ import annotations

from typing import NamedTuple
from urllib.parse import urlunparse

from refinery.units import Unit
from refinery.units.formats.httpresponse import httpresponse
from refinery.units.formats.pcap import pcap


class _HTTP_Request(NamedTuple):
    url: str
    src: str
    dst: str


class _HTTPParseError(ValueError):
    pass


def _parse_http_request(stream: bytearray):
    dst: bytes = stream['dst']
    host, _, port = dst.partition(B':')
    lines = stream.splitlines(False)
    headers = iter(lines)
    path, _ = next(headers).rsplit(maxsplit=1)
    _, path = path.split(maxsplit=1)
    for header in headers:
        name, colon, value = header.partition(B':')
        if not colon:
            continue
        if name.lower() == B'host':
            host, _, p = value.strip().partition(B':')
            if p and p != port:
                raise _HTTPParseError(F'http header suggests port {p}, but connection was to port {port}')
    if int(port) != 80:
        host = B':'.join((host, port))
    return _HTTP_Request(
        urlunparse((B'http', host, path, None, None, None)),
        stream['src'],
        stream['dst'],
    )


class pcap_http(Unit):
    """
    Extracts HTTP payloads from packet capture (PCAP) files.
    """
    def process(self, data):
        http_parser = httpresponse()
        requests: list[_HTTP_Request] = []
        responses: list[bytearray] = []

        def lookup(src, dst):
            for k, request in enumerate(requests):
                if request.src == dst and request.dst == src:
                    requests.pop(k)
                    return self.labelled(data, url=request.url)
            return None

        for stream in data | pcap():
            try:
                data = http_parser.process(stream)
            except Exception:
                try:
                    rq = _parse_http_request(stream)
                    requests.append(rq)
                except _HTTPParseError as E:
                    self.log_info(F'error parsing http request: {E!s}')
                except Exception:
                    pass
                continue
            if not data:
                continue
            src, dst = stream['src'], stream['dst']
            item = lookup(src, dst)
            if item is None:
                responses.append((src, dst, data))
                continue
            yield item

        while responses:
            src, dst, data = responses.pop()
            item = lookup(src, dst)
            yield data if item is None else item
