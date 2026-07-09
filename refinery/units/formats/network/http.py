from __future__ import annotations

from typing import Iterable, NamedTuple, cast
from urllib.parse import urlunparse

from refinery.lib.frame import Chunk
from refinery.units import Unit
from refinery.units.formats.httpresponse import httpresponse


class _HTTP_Request(NamedTuple):
    url: bytes
    src: bytes
    dst: bytes


class _HTTPParseError(ValueError):
    pass


def _parse_http_request(stream: Chunk):
    dst = cast(bytes, stream['dst'])
    host, _, port = dst.rpartition(B':')
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
    components = (B'http', bytes(host), bytes(path), b'', b'', b'')
    return _HTTP_Request(
        urlunparse(components),
        cast(bytes, stream['src']),
        cast(bytes, stream['dst']),
    )


class http(Unit):
    """
    Extracts HTTP payloads from reassembled TCP streams.

    The intended usage is the pipeline `pcap [| tcp | http ]`, where `refinery.pcap` extracts
    packets, `refinery.tcp` reassembles the TCP conversations, and this unit parses the HTTP
    requests and responses. Each extracted HTTP response body is emitted with the requested URL
    attached as the `url` variable.
    """
    @classmethod
    def handles(cls, data) -> bool | None:
        from refinery.units.formats.network.pcap import pcap
        return pcap.handles(data)

    def filter(self, chunks: Iterable[Chunk]):
        carrier: Chunk | None = None
        streams: list[Chunk] = []
        for chunk in chunks:
            if not chunk.visible:
                yield chunk
                continue
            if carrier is None:
                carrier = chunk
            streams.append(chunk)
        if carrier is None:
            return
        carrier.temp = streams
        yield carrier

    def process(self, data: Chunk):
        streams: list[Chunk] = data.temp if data.temp is not None else [data]
        http_parser = httpresponse()
        requests: list[_HTTP_Request] = []
        responses: list[Chunk] = []

        def lookup(body: Chunk) -> bool:
            src, dst = body['src'], body['dst']
            for k, request in enumerate(requests):
                if request.src == dst and request.dst == src:
                    requests.pop(k)
                    body.meta['url'] = request.url
                    return True
            return False

        for stream in streams:
            try:
                body = http_parser.process(stream)
            except Exception:
                try:
                    requests.append(_parse_http_request(stream))
                except _HTTPParseError as E:
                    self.log_info(F'error parsing http request: {E!s}')
                except Exception:
                    pass
                continue
            if not body:
                continue
            body = self.labelled(
                body,
                src=stream['src'],
                dst=stream['dst'],
                stream=stream['stream'],
            )
            if lookup(body):
                yield body
            else:
                responses.append(body)

        while responses:
            body = responses.pop()
            lookup(body)
            yield body
