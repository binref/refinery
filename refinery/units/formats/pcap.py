#!/usr/bin/env python3
# -*- coding: utf - 8 -* -
from __future__ import annotations

from typing import List, Union, TYPE_CHECKING

from refinery.units import Arg, Unit
from refinery.lib.vfs import VirtualFileSystem, VirtualFile
from refinery.lib.structures import MemoryFile
from refinery.lib.tools import NoLogging

import dataclasses

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from pcapkit.foundation.reassembly.data.tcp import Datagram, DatagramID
    from pcapkit.foundation.extraction import Packet
    TIPAddr = Union[IPv4Address, IPv6Address]


@dataclasses.dataclass
class Conversation:
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int
    ack: int

    @classmethod
    def FromID(cls, stream_id: DatagramID):
        src, sp = stream_id.src
        dst, dp = stream_id.dst
        return cls(str(src), str(dst), sp, dp, stream_id.ack)

    @property
    def src(self):
        return F'{self.src_addr}:{self.src_port}'

    @property
    def dst(self):
        return F'{self.dst_addr}:{self.dst_port}'

    def __hash__(self):
        return hash(frozenset((
            (self.src, self.src_port),
            (self.dst, self.dst_port))))

    def swapped(self):
        cls = self.__class__
        return cls(self.dst_addr, self.src_addr, self.dst_port, self.src_port)

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
    Performs TCP stream reassembly from packet capture (PCAP) files. By default, the unit emits the parts of
    each TCP conversation, attaching several pieces of metadata to each such output: Included are the source
    and destination socket address as well as the variable `stream` which identifies the conversation which
    it was part of. The chunks are returned in the order that the bytes were exchanged between source and
    destination. When the `--merge` parameter is specified, the unit instead collects all bytes going forward
    and backwards, respectively, and emitting these as two chunks, for each TCP conversation that took place.
    """

    def __init__(
        self,
        merge: Arg.Switch('-m', help='Merge both parts of each TCP conversation into one chunk.') = False,
        client: Arg.Switch('-c', group='D', help='Show only the client part of each conversation.') = False,
        server: Arg.Switch('-s', group='D', help='Show only the server part of each conversation.') = False,
    ):
        super().__init__(merge=merge, client=client, server=server)

    @Unit.Requires('pypcapkit[scapy]>=1.3', 'all')
    def _pcapkit():
        with NoLogging():
            import importlib
            importlib.import_module('scapy.layers.tls.session')
            import pcapkit
            return pcapkit

    @Unit.Requires('scapy', 'all')
    def _scapy():
        import scapy
        import scapy.packet
        return scapy

    def process(self, data):
        pcapkit = self._pcapkit
        merge = self.args.merge

        with NoLogging(), VirtualFileSystem() as fs:
            vf = VirtualFile(fs, data, 'pcap')
            pcap = pcapkit.extract(
                fin=vf.path,
                engine=pcapkit.Scapy,
                store=True,
                nofile=True,
                extension=False,
                ip=True,
                tcp=True,
                reassembly=True,
                reasm_strict=True,
            )
            tcp: List[Datagram] = list(pcap.reassembly.tcp)
            tcp.sort(key=lambda p: min(p.index, default=0))

        count, convo = 0, None
        src_buffer = MemoryFile()
        dst_buffer = MemoryFile()

        self.log_debug(F'extracted {len(pcap.frame)} packets, assembled {len(tcp)} datagrams')
        PT = self._scapy.packet

        def payload(packet: Packet):
            ok = (bytes, bytearray, PT.Raw)
            no = (PT.NoPayload, PT.Padding)
            circle = set()
            while True:
                try:
                    inner = packet.payload
                except AttributeError:
                    break
                if isinstance(packet, ok) and not isinstance(packet, no):
                    return packet.original
                if id(inner) in circle:
                    break
                packet = inner
                circle.add(id(inner))
            return B''

        def sequence(i: int):
            packet = pcap.frame[i - 1]
            while len(packet):
                try:
                    return packet.seq
                except AttributeError:
                    pass
                try:
                    packet = packet.payload
                except AttributeError:
                    break
            return 0

        client = self.args.client
        server = self.args.server

        def commit():
            if src_buffer.tell():
                if not server:
                    yield self.labelled(src_buffer.getvalue(), **convo.src_to_dst())
                src_buffer.truncate(0)
            if dst_buffer.tell():
                if not client:
                    yield self.labelled(dst_buffer.getvalue(), **convo.dst_to_src())
                dst_buffer.truncate(0)

        for datagram in tcp:
            this_convo = Conversation.FromID(datagram.id)
            if this_convo != convo:
                if count and merge:
                    yield from commit()
                count = count + 1
                convo = this_convo

            data = bytearray()
            for index in sorted(datagram.index, key=sequence):
                data.extend(payload(pcap.frame[index - 1]))
            if not data:
                continue
            if not merge:
                yield self.labelled(data, **this_convo.src_to_dst(), stream=count)
            elif this_convo.src == convo.src:
                src_buffer.write(data)
            elif this_convo.dst == convo.src:
                dst_buffer.write(data)
            else:
                raise RuntimeError(F'direction of packet {convo!s} in conversation {count} is unknown')

        yield from commit()
