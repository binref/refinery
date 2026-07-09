from __future__ import annotations

from refinery.lib.pcap import IPProtocol, TransportSegment, reassemble_udp
from refinery.units.formats.network import StreamReassemblyUnit


class udp(StreamReassemblyUnit):
    """
    Extracts UDP datagrams from the network-layer packets emitted by `refinery.pcap`.

    The intended usage is the pipeline `pcap [| udp ]`. Each UDP datagram is emitted as one chunk
    in the order in which it was captured, with the source and destination socket address attached
    as the variables `src` and `dst`. Because every UDP payload is a message boundary in its own
    right, no stream reassembly across datagrams is performed.
    """
    _PROTOCOL = IPProtocol.UDP

    def _emit(self, segments: list[TransportSegment]):
        for datagram in reassemble_udp(iter(segments)):
            yield self.labelled(
                datagram.payload,
                src=F'{datagram.src_addr}:{datagram.src_port}',
                dst=F'{datagram.dst_addr}:{datagram.dst_port}',
            )
