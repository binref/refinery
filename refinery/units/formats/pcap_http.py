#!/usr/bin/env python3
# -*- coding: utf - 8 -* -
from typing import List, NamedTuple
from contextlib import suppress

from refinery.units import Unit
from refinery.units.formats.httpresponse import httpresponse
from refinery.units.formats.pcap import pcap

from urllib.parse import urlunparse


class _HTTP_Request(NamedTuple):
    url: str
    src: str
    dst: str


def _parse_http_request(stream: bytearray):
    src: bytes = stream['src']
    host, _, port = src.partition(B':')
    lines = stream.splitlines(False)
    headers = iter(lines)
    path, _ = next(headers).rsplit(maxsplit=1)
    _, path = path.split(maxsplit=1)
    for header in headers:
        name, colon, value = header.partition(B':')
        if not colon:
            continue
        if name.lower() == B'host':
            host = value.strip()
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
    pcap = pcap()

    def process(self, data):
        http_parser = httpresponse()
        requests: List[_HTTP_Request] = []
        responses: List[bytearray] = []

        def lookup(src, dst):
            for k, request in enumerate(requests):
                if request.src == dst and request.dst == src:
                    requests.pop(k)
                    return self.labelled(data, url=request.url)
            return None

        for stream in self.pcap.process(data):
            try:
                data = http_parser.process(stream)
            except Exception:
                with suppress(Exception):
                    rq = _parse_http_request(stream)
                    requests.append(rq)
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
