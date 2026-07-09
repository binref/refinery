from __future__ import annotations

from refinery.lib.pcap import IPProtocol, TransportSegment, reassemble_tcp
from refinery.lib.types import Param
from refinery.units import Arg
from refinery.units.formats.network import StreamReassemblyUnit


class tcp(StreamReassemblyUnit):
    """
    Reassembles TCP streams from the network-layer packets emitted by `refinery.pcap`.

    The intended usage is `pcap [| tcp ]`. The unit emits the parts of each TCP conversation, with
    source and destination socket address provided as the meta variables `src` and `dst`, as well
    as the variable `stream` which identifies the conversation. The parts are returned in the order
    in which the bytes were exchanged. When `--merge` is specified, the unit instead collects all
    bytes going forward and backwards, respectively, and emits these as two chunks for each TCP
    conversation.
    """
    _PROTOCOL = IPProtocol.TCP

    def __init__(
        self,
        merge: Param[bool, Arg.Switch('-m', help=(
            'Merge both parts of each TCP conversation into one chunk.'
        ))] = False,
        client: Param[bool, Arg.Switch('-c', group='D', help=(
            'Show only the client part of each conversation.'
        ))] = False,
        server: Param[bool, Arg.Switch('-s', group='D', help=(
            'Show only the server part of each conversation.'
        ))] = False,
    ):
        super().__init__(merge=merge, client=client, server=server)

    @staticmethod
    def _conversation(datagram) -> frozenset:
        return frozenset((
            (datagram.src_addr, datagram.src_port),
            (datagram.dst_addr, datagram.dst_port),
        ))

    def _emit(self, segments: list[TransportSegment]):
        merge = self.args.merge
        client = self.args.client
        server = self.args.server

        datagrams = reassemble_tcp(iter(segments))
        streams: dict[frozenset, int] = {}
        clients: dict[frozenset, tuple[str, int]] = {}

        for datagram in datagrams:
            key = self._conversation(datagram)
            if key not in streams:
                streams[key] = len(streams)
                clients[key] = (datagram.src_addr, datagram.src_port)

        def is_forward(datagram) -> bool:
            key = self._conversation(datagram)
            return clients[key] == (datagram.src_addr, datagram.src_port)

        def visible(datagram) -> bool:
            forward = is_forward(datagram)
            if server and forward:
                return False
            if client and not forward:
                return False
            return True

        def labels(datagram):
            return {
                'src': F'{datagram.src_addr}:{datagram.src_port}',
                'dst': F'{datagram.dst_addr}:{datagram.dst_port}',
                'stream': streams[self._conversation(datagram)],
            }

        if not merge:
            for datagram in datagrams:
                if visible(datagram):
                    yield self.labelled(datagram.payload, **labels(datagram))
            return

        forward_parts: dict[frozenset, list] = {}
        reverse_parts: dict[frozenset, list] = {}
        for datagram in datagrams:
            key = self._conversation(datagram)
            bucket = forward_parts if is_forward(datagram) else reverse_parts
            bucket.setdefault(key, []).append(datagram)

        for key in streams:
            for bucket in (forward_parts, reverse_parts):
                parts = bucket.get(key)
                if not parts:
                    continue
                head = parts[0]
                if not visible(head):
                    continue
                payload = bytearray()
                for part in parts:
                    payload.extend(part.payload)
                yield self.labelled(payload, **labels(head))
