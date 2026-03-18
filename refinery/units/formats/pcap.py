from __future__ import annotations

import dataclasses

from refinery.lib.pcap import TcpDatagram, reassemble_tcp_streams
from refinery.lib.structures import MemoryFile
from refinery.lib.types import Param
from refinery.units import Arg, Unit


@dataclasses.dataclass
class Conversation:
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int

    @classmethod
    def FromDatagram(cls, d: TcpDatagram):
        return cls(d.src_addr, d.dst_addr, d.src_port, d.dst_port)

    @property
    def src(self):
        return F'{self.src_addr}:{self.src_port}'

    @property
    def dst(self):
        return F'{self.dst_addr}:{self.dst_port}'

    def __hash__(self):
        return hash(frozenset((
            (self.src_addr, self.src_port),
            (self.dst_addr, self.dst_port))))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __str__(self):
        return F'[{self.src}] --> [{self.dst}]'

    def src_to_dst(self):
        return {'src': self.src, 'dst': self.dst}

    def dst_to_src(self):
        return {'src': self.dst, 'dst': self.src}


class pcap(Unit):
    """
    TCP stream reassembly from packet capture (PCAP and PCAP-NG) files.

    By default, the unit emits the parts of each TCP conversation, attaching several pieces of
    metadata to each such output: Included are the source and destination socket address as
    well as the variable `stream` which identifies the conversation which it was part of. The
    chunks are returned in the order that the bytes were exchanged between source and
    destination. When the `--merge` parameter is specified, the unit instead collects all bytes
    going forward and backwards, respectively, and emitting these as two chunks, for each TCP
    conversation that took place.
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
        if data[:4] in cls._PCAP_MAGICS:
            return True

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

    def process(self, data):
        merge = self.args.merge
        client = self.args.client
        server = self.args.server

        tcp = reassemble_tcp_streams(data)
        self.log_debug(F'assembled {len(tcp)} datagrams')

        count, convo = 0, None
        src_buffer = MemoryFile()
        dst_buffer = MemoryFile()

        def commit():
            if src_buffer.tell():
                if not server:
                    assert convo is not None
                    yield self.labelled(src_buffer.getvalue(), **convo.src_to_dst())
                src_buffer.truncate(0)
            if dst_buffer.tell():
                if not client:
                    assert convo is not None
                    yield self.labelled(dst_buffer.getvalue(), **convo.dst_to_src())
                dst_buffer.truncate(0)

        for datagram in tcp:
            this_convo = Conversation.FromDatagram(datagram)
            if this_convo != convo:
                if count and merge:
                    yield from commit()
                count = count + 1
                convo = this_convo
            assert convo is not None
            if not datagram.payload:
                continue
            if not merge:
                yield self.labelled(
                    datagram.payload, **this_convo.src_to_dst(), stream=count)
            elif this_convo.src == convo.src:
                src_buffer.write(datagram.payload)
            elif this_convo.dst == convo.src:
                dst_buffer.write(datagram.payload)
            else:
                raise RuntimeError(
                    F'direction of packet {convo!s} in conversation {count} is unknown')

        yield from commit()
