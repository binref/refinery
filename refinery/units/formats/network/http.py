from __future__ import annotations

from typing import Iterable, NamedTuple, cast
from urllib.parse import urlunparse

from refinery.lib.frame import Chunk
from refinery.lib.meta import MV
from refinery.lib.types import Param
from refinery.units import Arg, Unit
from refinery.units.formats.httpresponse import httpresponse
from refinery.units.formats.httprequest import httprequest


class _HTTP_Request(NamedTuple):
    url: bytes
    src: bytes
    dst: bytes


class _HTTPParseError(ValueError):
    pass


def _parse_http_request(stream: Chunk):
    dst = cast(bytes, stream[MV.DST])
    host, _, port = dst.rpartition(B':')
    if (eoh := stream.find(B'\r\n\r\n')) < 0:
        eoh = None
    lines = stream[:eoh].splitlines(False)
    headers = iter(lines)
    path, _ = next(headers).rsplit(maxsplit=1)
    _, path = path.split(maxsplit=1)
    for header in headers:
        if not header:
            break
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
        cast(bytes, stream[MV.SRC]),
        cast(bytes, stream[MV.DST]),
    )


class http(Unit):
    """
    Extracts HTTP payloads from reassembled TCP streams.

    The intended usage is the pipeline `pcap [| tcp | http ]`, where `refinery.pcap` extracts
    packets, `refinery.tcp` reassembles the TCP conversations, and this unit parses the HTTP
    requests and responses. Each extracted HTTP response body is emitted with the requested URL
    attached as the `url` variable.
    """
    def __init__(
        self,
        requests : Param[bool, Arg.Switch('-r', group='R', help='show only data from requests')] = False,
        responses: Param[bool, Arg.Switch('-q', group='R', help='show only response bodies')] = False,
    ):
        if not requests and not responses:
            requests = responses = True
        super().__init__(requests=requests, responses=responses)

    @classmethod
    def handles(cls, data) -> bool | None:
        return httpresponse.handles(data) or httprequest.handles(data)

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
        x_resp = self.args.responses
        x_reqt = self.args.requests
        p_resp = httpresponse()
        p_reqt = httprequest()
        requests: list[_HTTP_Request] = []
        responses: list[Chunk] = []

        def lookup(body: Chunk) -> bool:
            src, dst = body[MV.SRC], body[MV.DST]
            for k, request in enumerate(requests):
                if request.src == dst and request.dst == src:
                    requests.pop(k)
                    body.meta[MV.URL] = request.url
                    return True
            return False

        for stream in streams:
            if x_resp and p_resp.handles(stream):
                try:
                    body = p_resp.process(stream)
                except Exception:
                    body = None
                if body is None:
                    continue
                body = self.labelled(
                    body,
                    **{
                        MV.SRC: stream[MV.SRC],
                        MV.DST: stream[MV.DST],
                        MV.STREAM: stream[MV.STREAM],
                    }
                )
                if lookup(body):
                    yield body
                else:
                    responses.append(body)

            if p_reqt.handles(stream):
                try:
                    rq = _parse_http_request(stream)
                except Exception as E:
                    self.log_info(F'error parsing http request: {E!s}')
                    continue
                else:
                    requests.append(rq)
                if not x_reqt:
                    continue
                try:
                    meta: dict = {
                        MV.SRC: rq.src,
                        MV.DST: rq.dst,
                        MV.URL: rq.url,
                        MV.STREAM: stream[MV.STREAM],
                    }
                    for body in p_reqt.process(stream):
                        yield self.labelled(body, **meta)
                except Exception:
                    continue

        while responses:
            body = responses.pop()
            lookup(body)
            yield body
