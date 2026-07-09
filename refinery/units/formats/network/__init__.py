from __future__ import annotations

from typing import Iterable

from refinery.lib.frame import Chunk
from refinery.lib.pcap import IPProtocol, TransportSegment, parse_transport_segment
from refinery.units import Unit


class StreamReassemblyUnit(Unit, abstract=True):
    """
    Abstract base for units that reassemble transport-layer streams from the network-layer
    packet chunks emitted by `refinery.pcap`. The unit collects all packets in the current
    frame, parses each into a `refinery.lib.pcap.TransportSegment` of a given
    `refinery.lib.pcap.IPProtocol`, and delegates emission to the abstract method `_emit`.
    Chains such as `pcap [| tcp ]` or `pcap [| udp ]` are the intended usage.
    """
    _PROTOCOL: IPProtocol

    @classmethod
    def handles(cls, data) -> bool | None:
        from refinery.units.formats.network.pcap import pcap
        return pcap.handles(data)

    def _emit(self, segments: list[TransportSegment]) -> Iterable:
        raise NotImplementedError

    def filter(self, chunks: Iterable[Chunk]):
        carrier: Chunk | None = None
        payloads: list[memoryview] = []
        for chunk in chunks:
            if not chunk.visible:
                yield chunk
                continue
            if carrier is None:
                carrier = chunk
            payloads.append(memoryview(chunk))
        if carrier is None:
            return
        for stale in ('link', 'time'):
            carrier.meta.discard(stale)
        carrier.temp = payloads
        yield carrier

    def process(self, data: Chunk):
        payloads: list[memoryview] = data.temp if data.temp is not None else [memoryview(data)]
        segments: list[TransportSegment] = []
        for payload in payloads:
            segment = parse_transport_segment(payload, self._PROTOCOL)
            if segment is not None:
                segments.append(segment)
        yield from self._emit(segments)
