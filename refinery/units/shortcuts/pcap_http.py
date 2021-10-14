#!/usr/bin/env python3
# -*- coding: utf - 8 -* -
from typing import List, NamedTuple
from refinery.units import Unit
from refinery.units.formats.httpresponse import httpresponse
from refinery.units.formats.pcap import pcap
from refinery.lib.structures import MemoryFile

from http.server import BaseHTTPRequestHandler
from urllib.parse import urlunparse


class SockWrapper(MemoryFile):
    def sendall(self, _): pass
    def makefile(self, *_): return self


class ApatheticRequestHandler(BaseHTTPRequestHandler):

    # silence all log output
    def log_message(self, *_) -> None: pass

    # provide empty handler for every type of HTTP request
    def __getattr__(self, attr: str):
        if attr.startswith('do_'):
            return lambda *_: None
        raise AttributeError


class _HTTP_Request(NamedTuple):
    url: str
    src: str
    dst: str


def _parse_http_request(stream):
    try:
        src: bytes = stream['src']
        host, _, port = src.decode('utf8').partition(':')
        port = int(port)
        with SockWrapper(stream) as sock:
            parsed = ApatheticRequestHandler(sock, (host, port), None)
        netloc = parsed.headers.get('Host', host)
        if port != 80:
            netloc = F'{netloc}:{port}'
        return _HTTP_Request(
            urlunparse(['http', netloc, parsed.path, None, None, None]),
            stream['src'],
            stream['dst'],
        )
    except Exception:
        return None


class pcap_http(Unit):
    """
    Extracts HTTP payloads from packet capture (PCAP) files.
    """
    pcap = pcap()

    def process(self, data):
        http_parser = httpresponse()
        requests: List[_HTTP_Request] = []

        for stream in self.pcap.process(data):
            try:
                data = http_parser.process(stream)
            except Exception:
                request = _parse_http_request(stream)
                if request:
                    requests.append(request)
                continue
            if not data:
                continue
            keywords = {}
            for k, request in enumerate(requests):
                if request.src == stream['dst'] and request.dst == stream['src']:
                    requests.pop(k)
                    keywords['url'] = request.url
                    break
            yield self.labelled(data, **keywords)
