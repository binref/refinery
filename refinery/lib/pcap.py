from __future__ import annotations

import ipaddress
import logging

from enum import IntEnum, IntFlag
from typing import NamedTuple

from refinery.lib.structures import EOF, Struct, StructReader

logger = logging.getLogger(__name__)


class LinkType(IntEnum):
    NULL = 0
    ETHERNET = 1
    LINUX_SLL = 113
    RAW_IP = 228


class EtherType(IntEnum):
    IPv4 = 0x0800
    IPv6 = 0x86DD
    VLAN = 0x8100


class IPProtocol(IntEnum):
    TCP = 6
    UDP = 17


class TcpFlag(IntFlag):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


class FlowKey(NamedTuple):
    src_addr: str
    src_port: int
    dst_addr: str
    dst_port: int
    ack: int


class TcpSegment(NamedTuple):
    seq: int
    data: bytes
    packet_index: int


class TcpDatagram(NamedTuple):
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int
    payload: bytearray
    first_packet_index: int


def _read_pcap_global_header(reader: StructReader) -> LinkType:
    if (magic := reader.u32()) in (0xA1B2C3D4, 0xA1B23C4D):
        reader.bigendian = False
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        reader.bigendian = True
    else:
        raise ValueError(F'invalid PCAP magic: 0x{magic:08X}')
    reader.u16()  # version_major
    reader.u16()  # version_minor
    reader.i32()  # thiszone
    reader.u32()  # sigfigs
    reader.u32()  # snaplen
    link_type = LinkType(reader.u32())
    return link_type


def _iter_pcap_classic(reader: StructReader):
    link_type = _read_pcap_global_header(reader)
    while not reader.eof:
        try:
            reader.u32()  # ts_sec
            reader.u32()  # ts_usec
            incl_len = reader.u32()
            reader.u32()  # orig_len
        except EOF:
            break
        try:
            packet_data = reader.read_exactly(incl_len)
        except EOF:
            break
        yield link_type, memoryview(packet_data)


def _iter_pcap_ng(reader: StructReader):
    interfaces: list[LinkType] = []

    while not reader.eof:
        try:
            block_start = reader.tell()
            block_type = reader.u32()
            block_length = reader.u32()
        except EOF:
            break
        body_length = block_length - 12
        if body_length < 0:
            break

        if block_type == 0x0A0D0D0A:
            bom = reader.u32()
            if bom == 0x1A2B3C4D:
                needs_swap = reader.bigendian
                reader.bigendian = False
            elif bom == 0x4D3C2B1A:
                needs_swap = not reader.bigendian
                reader.bigendian = True
            else:
                raise ValueError(F'invalid PCAP-NG byte order magic: 0x{bom:08X}')
            if needs_swap:
                block_length = int.from_bytes(
                    block_length.to_bytes(4, 'big'), 'little')
            body_length = block_length - 12
            reader.u16()  # version_major
            reader.u16()  # version_minor
            reader.u64()  # section_length
            remaining = body_length - (reader.tell() - block_start - 8)
            if remaining > 0:
                reader.read_exactly(remaining)
        elif block_type == 0x00000001:
            lt = LinkType(reader.u16())
            reader.u16()  # reserved
            reader.u32()  # snap_len
            interfaces.append(lt)
            remaining = body_length - 8
            if remaining > 0:
                reader.read_exactly(remaining)
        elif block_type == 0x00000006:
            iface_id = reader.u32()
            reader.u32()  # timestamp_high
            reader.u32()  # timestamp_low
            captured_len = reader.u32()
            reader.u32()  # original_len
            if iface_id < len(interfaces):
                lt = interfaces[iface_id]
            else:
                lt = LinkType.ETHERNET
            try:
                packet_data = reader.read_exactly(captured_len)
            except EOF:
                break
            yield lt, memoryview(packet_data)
            padded = (captured_len + 3) & ~3
            skip = padded - captured_len
            remaining = body_length - 20 - padded
            if skip > 0:
                reader.read_exactly(skip)
            if remaining > 0:
                reader.read_exactly(remaining)
        else:
            try:
                reader.read_exactly(body_length)
            except EOF:
                break

        try:
            reader.u32()  # trailing block length
        except EOF:
            break


def _parse_link_layer(
    link_type: LinkType, frame: memoryview
) -> tuple[EtherType, memoryview] | None:
    if link_type == LinkType.ETHERNET:
        if len(frame) < 14:
            return None
        etype = int.from_bytes(frame[12:14], 'big')
        payload = frame[14:]
        while etype == EtherType.VLAN:
            if len(payload) < 4:
                return None
            etype = int.from_bytes(payload[2:4], 'big')
            payload = payload[4:]
        try:
            et = EtherType(etype)
        except ValueError:
            return None
        if et not in (EtherType.IPv4, EtherType.IPv6):
            return None
        return et, payload
    elif link_type == LinkType.NULL:
        if len(frame) < 4:
            return None
        family = int.from_bytes(frame[:4], 'little')
        if family == 2:
            return EtherType.IPv4, frame[4:]
        elif family in (24, 28, 30):
            return EtherType.IPv6, frame[4:]
        return None
    elif link_type == LinkType.LINUX_SLL:
        if len(frame) < 16:
            return None
        etype = int.from_bytes(frame[14:16], 'big')
        try:
            et = EtherType(etype)
        except ValueError:
            return None
        if et not in (EtherType.IPv4, EtherType.IPv6):
            return None
        return et, frame[16:]
    elif link_type == LinkType.RAW_IP:
        if len(frame) < 1:
            return None
        version = frame[0] >> 4
        if version == 4:
            return EtherType.IPv4, frame
        elif version == 6:
            return EtherType.IPv6, frame
        return None
    return None


class _IPv4Header(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.bigendian = True
        ihl = (reader.u8() & 0x0F) * 4
        if ihl < 20:
            raise ValueError
        self.dscp_ecn = reader.u8()
        total_length = reader.u16()
        self.identification = reader.u16()
        frag_offset = reader.u16() & 0x1FFF
        if frag_offset != 0:
            raise ValueError
        self.ttl = reader.u8()
        self.protocol = IPProtocol(reader.u8())
        self.header_checksum = reader.u16()
        self.src = str(ipaddress.IPv4Address(reader.read_bytes(4)))
        self.dst = str(ipaddress.IPv4Address(reader.read_bytes(4)))
        if ihl > 20:
            reader.read_exactly(ihl - 20)
        remaining = total_length - ihl
        if remaining > reader.remaining_bytes:
            remaining = reader.remaining_bytes
        self.payload = reader.read_exactly(max(remaining, 0))


class _IPv6Header(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.bigendian = True
        self.version_traffic_flow = reader.u32()
        payload_length = reader.u16()
        next_header = reader.u8()
        self.hop_limit = reader.u8()
        self.src = str(ipaddress.IPv6Address(reader.read_bytes(16)))
        self.dst = str(ipaddress.IPv6Address(reader.read_bytes(16)))
        payload_size = min(payload_length, reader.remaining_bytes)
        payload_start = reader.tell()
        extension_headers = {0, 43, 44, 50, 51, 60, 135, 139, 140}
        while next_header in extension_headers:
            if next_header == 44:
                raise ValueError
            ext_next = reader.u8()
            ext_len = (reader.u8() + 1) * 8
            if ext_len > 2:
                reader.read_exactly(ext_len - 2)
            next_header = ext_next
        self.protocol = IPProtocol(next_header)
        consumed = reader.tell() - payload_start
        remaining = max(payload_size - consumed, 0)
        self.payload = reader.read_exactly(remaining)


class _TcpHeader(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.bigendian = True
        self.src_port = reader.u16()
        self.dst_port = reader.u16()
        self.seq = reader.u32()
        self.ack = reader.u32()
        data_offset = ((reader.u8() >> 4) & 0x0F) * 4
        if data_offset < 20:
            raise ValueError
        self.flags = TcpFlag(reader.u8())
        self.window_size = reader.u16()
        self.checksum = reader.u16()
        self.urgent_pointer = reader.u16()
        if data_offset > 20:
            reader.read_exactly(data_offset - 20)
        self.payload = reader.read_exactly(reader.remaining_bytes)


class _TcpStream:
    def __init__(self):
        self.segments: list[TcpSegment] = []

    def add(self, seq: int, data: bytes, packet_index: int):
        if data:
            self.segments.append(TcpSegment(seq, data, packet_index))

    def reassemble(self) -> bytearray:
        if not self.segments:
            return bytearray()
        self.segments.sort(key=lambda s: (s.seq, s.packet_index))
        result = bytearray()
        next_seq = self.segments[0].seq
        for seg in self.segments:
            if seg.seq + len(seg.data) <= next_seq:
                continue
            if seg.seq < next_seq:
                trimmed = seg.data[next_seq - seg.seq:]
            else:
                trimmed = seg.data
            result.extend(trimmed)
            next_seq = seg.seq + len(seg.data)
        return result


def reassemble_tcp_streams(data: bytes | bytearray | memoryview) -> list[TcpDatagram]:
    view = memoryview(data)
    reader = StructReader(view)
    magic = bytes(view[:4])
    reader.bigendian = False

    if magic == b'\x0A\x0D\x0D\x0A':
        packet_iter = _iter_pcap_ng(reader)
    else:
        packet_iter = _iter_pcap_classic(reader)

    flows: dict[FlowKey, _TcpStream] = {}
    flow_first_packet: dict[FlowKey, int] = {}
    packet_index = 0

    for link_type, frame in packet_iter:
        packet_index += 1
        try:
            result = _parse_link_layer(link_type, frame)
            if result is None:
                continue
            ether_type, ip_data = result
            if ether_type == EtherType.IPv4:
                ip = _IPv4Header.Parse(ip_data)
            elif ether_type == EtherType.IPv6:
                ip = _IPv6Header.Parse(ip_data)
            else:
                continue
            if ip.protocol != IPProtocol.TCP:
                continue
            tcp = _TcpHeader.Parse(ip.payload)
            key = FlowKey(
                ip.src, tcp.src_port, ip.dst, tcp.dst_port, tcp.ack)
            if key not in flow_first_packet:
                flow_first_packet[key] = packet_index
            payload_bytes = bytes(tcp.payload)
            if payload_bytes:
                if key not in flows:
                    flows[key] = _TcpStream()
                flows[key].add(tcp.seq, payload_bytes, packet_index)
        except Exception:
            logger.debug('failed to parse packet %d', packet_index, exc_info=True)
            continue

    datagrams: list[TcpDatagram] = []
    for key, stream in flows.items():
        payload = stream.reassemble()
        if payload:
            first_idx = flow_first_packet.get(
                key, min(s.packet_index for s in stream.segments))
            datagrams.append(TcpDatagram(
                key.src_addr, key.dst_addr, key.src_port, key.dst_port,
                payload, first_idx,
            ))

    datagrams.sort(key=lambda d: d.first_packet_index)
    return datagrams
