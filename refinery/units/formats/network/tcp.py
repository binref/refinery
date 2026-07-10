from __future__ import annotations

from refinery.lib.pcap import IPProtocol, TcpFlag, TransportSegment, reassemble_tcp
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
    conversation. The client and server side of a conversation are told apart by the TCP handshake
    when it was captured; otherwise the endpoint with the higher port number is taken to be the
    client. This matters only for the `--client` and `--server` filters and for which side is
    emitted first under `--merge`.
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

    def _identify_clients(
        self,
        segments: list[TransportSegment],
    ) -> dict[frozenset, tuple[str, int]]:
        """
        Determines the client endpoint of every TCP conversation. The handshake is authoritative:
        the sender of a bare `SYN` is the client, and the sender of a `SYN`-`ACK` is the server.
        When no handshake was captured, the endpoint with the higher port number is assumed to be
        the client, since servers usually listen on the lower, well-known port. If even the ports
        are equal, the source of the first observed segment is used as a last resort.
        """
        clients: dict[frozenset, tuple[str, int]] = {}
        endpoints: dict[frozenset, tuple[tuple[str, int], tuple[str, int]]] = {}
        for segment in segments:
            src = segment.src_addr, segment.src_port
            dst = segment.dst_addr, segment.dst_port
            key = self._conversation(segment)
            endpoints.setdefault(key, (src, dst))
            if key in clients:
                continue
            if segment.flags & TcpFlag.SYN:
                clients[key] = dst if segment.flags & TcpFlag.ACK else src
        for key, (src, dst) in endpoints.items():
            if key in clients:
                continue
            if src[1] == dst[1]:
                clients[key] = src
            else:
                clients[key] = src if src[1] > dst[1] else dst
        return clients

    def _emit(self, segments: list[TransportSegment]):
        merge = self.args.merge
        client = self.args.client
        server = self.args.server

        clients = self._identify_clients(segments)
        datagrams = reassemble_tcp(iter(segments))
        streams: dict[frozenset, int] = {}

        for datagram in datagrams:
            key = self._conversation(datagram)
            if key not in streams:
                streams[key] = len(streams)

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
