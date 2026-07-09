from __future__ import annotations

import datetime

from refinery.lib.pcap import iter_captured_packets, iter_network_layers
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class pcap(Unit):
    """
    Extracts packets from packet capture (PCAP and PCAP-NG) files.

    Each packet is emitted as an individual chunk, in the order in which it was captured. By
    default, the unit unwraps the link layer and emits the network-layer bytes of each packet, i.e.
    the data starting at the IP header.

    The unit attaches the capture timestamp as the `time` variable and the name of the link layer
    type as the `link` variable to each emitted chunk. To reassemble transport-layer streams, pipe
    the packets into `refinery.tcp` or `refinery.udp`.
    """
    _PCAP_MAGICS = {
        B'\xD4\xC3\xB2\xA1',
        B'\xA1\xB2\xC3\xD4',
        B'\x4D\x3C\xB2\xA1',
        B'\xA1\xB2\x3C\x4D',
        B'\x0A\x0D\x0D\x0A',
    }

    @classmethod
    def handles(cls, data) -> bool | None:
        if bytes(data[:4]) in cls._PCAP_MAGICS:
            return True

    def __init__(
        self,
        link: Param[bool, Arg.Switch('-l', help=(
            'Emit the raw link-layer frame of each packet instead of the network layer.'
        ))] = False,
    ):
        super().__init__(link=link)

    def process(self, data):
        if self.args.link:
            for packet in iter_captured_packets(data):
                yield self._pack(packet.frame, packet.link_type.name, packet.seconds)
        else:
            for packet in iter_network_layers(data):
                yield self._pack(packet.payload, packet.link_type.name, packet.seconds)

    def _pack(self, payload, link: str, seconds: float | None):
        meta = {'link': link}
        if seconds is not None:
            try:
                when = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
            except (ValueError, OSError, OverflowError):
                pass
            else:
                meta['time'] = when.isoformat(' ', 'seconds')
        return self.labelled(bytes(payload), **meta)
