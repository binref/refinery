from __future__ import annotations

import ipaddress
import logging

from enum import IntEnum, IntFlag
from typing import Iterator, NamedTuple

from refinery.lib.structures import EOF, Struct, StructReader

logger = logging.getLogger(__name__)


class LinkType(IntEnum):
    UNKNOWN = -1
    NULL = 0
    ETHERNET = 1
    LINUX_SLL = 113
    RAW_IP = 228

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


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
    data: memoryview
    packet_index: int


class CapturedPacket(NamedTuple):
    link_type: LinkType
    frame: memoryview
    seconds: float | None


class NetworkPacket(NamedTuple):
    ether_type: EtherType
    payload: memoryview
    link_type: LinkType
    seconds: float | None


class TransportSegment(NamedTuple):
    protocol: IPProtocol
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: TcpFlag
    payload: memoryview


class Datagram(NamedTuple):
    protocol: IPProtocol
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int
    payload: bytearray


def _read_pcap_global_header(reader: StructReader) -> tuple[LinkType, float]:
    if (magic := reader.u32()) == 0xA1B2C3D4:
        reader.bigendian = False
        ts_scale = 1e-6
    elif magic == 0xA1B23C4D:
        reader.bigendian = False
        ts_scale = 1e-9
    elif magic == 0xD4C3B2A1:
        reader.bigendian = True
        ts_scale = 1e-6
    elif magic == 0x4D3CB2A1:
        reader.bigendian = True
        ts_scale = 1e-9
    else:
        raise ValueError(F'invalid PCAP magic: 0x{magic:08X}')
    reader.u16()  # version_major
    reader.u16()  # version_minor
    reader.i32()  # thiszone
    reader.u32()  # sigfigs
    reader.u32()  # snaplen
    link_type = LinkType(reader.u32())
    return link_type, ts_scale


def _iter_pcap_classic(reader: StructReader) -> Iterator[CapturedPacket]:
    try:
        link_type, ts_scale = _read_pcap_global_header(reader)
    except EOF:
        return
    while not reader.eof:
        try:
            ts_sec = reader.u32()
            ts_frac = reader.u32()
            incl_len = reader.u32()
            reader.u32()  # orig_len
        except EOF:
            break
        try:
            packet_data = reader.read_exactly(incl_len)
        except EOF:
            break
        seconds = ts_sec + ts_frac * ts_scale
        yield CapturedPacket(link_type, memoryview(packet_data), seconds)


def _read_ng_timestamp_scale(options: memoryview, bigendian: bool) -> float:
    order = 'big' if bigendian else 'little'
    offset = 0
    scale = 1e-6
    while offset + 4 <= len(options):
        code = int.from_bytes(options[offset + 0:offset + 2], order)
        size = int.from_bytes(options[offset + 2:offset + 4], order)
        offset += 4
        if code == 0:
            break
        if code == 9 and size >= 1 and offset < len(options):
            resolution = options[offset]
            if resolution & 0x80:
                scale = 2.0 ** -(resolution & 0x7F)
            else:
                scale = 10.0 ** -resolution
        offset += (size + 3) & ~3
    return scale


def _iter_pcap_ng(reader: StructReader) -> Iterator[CapturedPacket]:
    interfaces: list[tuple[LinkType, float]] = []

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

        try:
            if block_type == 0x0A0D0D0A:
                interfaces.clear()
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
                remaining = body_length - 8
                if remaining > 0:
                    options = memoryview(reader.read_exactly(remaining))
                else:
                    options = memoryview(b'')
                scale = _read_ng_timestamp_scale(options, reader.bigendian)
                interfaces.append((lt, scale))
            elif block_type == 0x00000006:
                iface_id = reader.u32()
                timestamp_high = reader.u32()
                timestamp_low = reader.u32()
                captured_len = reader.u32()
                reader.u32()  # original_len
                if iface_id < len(interfaces):
                    lt, scale = interfaces[iface_id]
                else:
                    lt, scale = LinkType.ETHERNET, 1e-6
                packet_data = reader.read_exactly(captured_len)
                seconds = ((timestamp_high << 32) | timestamp_low) * scale
                yield CapturedPacket(lt, memoryview(packet_data), seconds)
                padded = (captured_len + 3) & ~3
                skip = padded - captured_len
                remaining = body_length - 20 - padded
                if skip > 0:
                    reader.read_exactly(skip)
                if remaining > 0:
                    reader.read_exactly(remaining)
            else:
                reader.read_exactly(body_length)
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
        extension_headers = {0, 43, 44, 60, 135, 139, 140}
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


class _UdpHeader(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.bigendian = True
        self.src_port = reader.u16()
        self.dst_port = reader.u16()
        length = reader.u16()
        self.checksum = reader.u16()
        payload_length = length - 8
        if payload_length < 0 or payload_length > reader.remaining_bytes:
            payload_length = reader.remaining_bytes
        self.payload = reader.read_exactly(payload_length)


def _seq_delta(a: int, b: int) -> int:
    """
    Computes the signed 32-bit distance from TCP sequence number `b` to `a`, i.e. the value of
    `a - b` interpreted modulo 2**32 as a signed integer. This mirrors the semantics of the
    Wireshark `LT_SEQ`/`GT_SEQ` comparison macros and orders sequence numbers correctly across a
    wraparound, as long as the true distance between the two values is less than 2**31.
    """
    d = (a - b) & 0xFFFFFFFF
    return d - 0x100000000 if d & 0x80000000 else d


class _TcpStream:
    def __init__(self):
        self.segments: list[TcpSegment] = []

    def add(self, seq: int, data: memoryview, packet_index: int):
        if data:
            self.segments.append(TcpSegment(seq, data, packet_index))

    def reassemble(self) -> bytearray:
        if not self.segments:
            return bytearray()
        anchor = self.segments[0].seq
        ordered = sorted(
            self.segments,
            key=lambda s: (_seq_delta(s.seq, anchor), s.packet_index),
        )
        result = bytearray()
        next_off = _seq_delta(ordered[0].seq, anchor)
        for seg in ordered:
            off = _seq_delta(seg.seq, anchor)
            if off + len(seg.data) <= next_off:
                continue
            if off < next_off:
                trimmed = seg.data[next_off - off:]
            else:
                trimmed = seg.data
            result.extend(trimmed)
            next_off = off + len(seg.data)
        return result


def iter_captured_packets(
    data: bytes | bytearray | memoryview
) -> Iterator[CapturedPacket]:
    """
    Iterates over the raw link-layer frames of a classic PCAP or PCAP-NG capture. The capture
    format is selected based on the file magic. Each `CapturedPacket` carries the frame bytes,
    the interface `LinkType`, and the capture timestamp in epoch seconds when available.
    """
    view = memoryview(data)
    reader = StructReader(view)
    reader.bigendian = False
    if bytes(view[:4]) == b'\x0A\x0D\x0D\x0A':
        yield from _iter_pcap_ng(reader)
    else:
        yield from _iter_pcap_classic(reader)


def iter_network_layers(
    data: bytes | bytearray | memoryview
) -> Iterator[NetworkPacket]:
    """
    Iterates over the network-layer payloads of a capture by unwrapping the link layer of each
    captured packet using `refinery.lib.pcap.iter_captured_packets`. Frames whose link layer
    does not carry IPv4 or IPv6 are skipped.
    """
    for packet in iter_captured_packets(data):
        try:
            result = _parse_link_layer(packet.link_type, packet.frame)
        except Exception:
            logger.debug('failed to parse link layer', exc_info=True)
            continue
        if result is None:
            continue
        ether_type, payload = result
        yield NetworkPacket(ether_type, payload, packet.link_type, packet.seconds)


def parse_transport_segment(
    network_payload: bytes | bytearray | memoryview,
    protocol: IPProtocol,
) -> TransportSegment | None:
    """
    Parses a single network-layer payload (starting at the IP header) into a `TransportSegment`
    of the requested `IPProtocol`. The IP version is detected from the header, and `None` is
    returned when the payload does not parse or does not carry the requested protocol.
    """
    view = memoryview(network_payload)
    if not view:
        return None
    version = view[0] >> 4
    try:
        if version == 4:
            ip = _IPv4Header.Parse(view)
        elif version == 6:
            ip = _IPv6Header.Parse(view)
        else:
            return None
        if ip.protocol != protocol:
            return None
        if protocol == IPProtocol.TCP:
            tcp = _TcpHeader.Parse(ip.payload)
            return TransportSegment(
                IPProtocol.TCP,
                ip.src,
                ip.dst,
                tcp.src_port,
                tcp.dst_port,
                tcp.seq,
                tcp.ack,
                tcp.flags,
                tcp.payload,
            )
        else:
            udp = _UdpHeader.Parse(ip.payload)
            return TransportSegment(
                IPProtocol.UDP,
                ip.src,
                ip.dst,
                udp.src_port,
                udp.dst_port,
                0,
                0,
                TcpFlag(0),
                udp.payload,
            )
    except Exception:
        logger.debug('failed to parse network-layer packet', exc_info=True)
        return None


def iter_transport(
    data: bytes | bytearray | memoryview,
    protocol: IPProtocol,
) -> Iterator[TransportSegment]:
    """
    Iterates over the `TransportSegment`s of the requested `IPProtocol` in a capture, combining
    `refinery.lib.pcap.iter_network_layers` with `refinery.lib.pcap.parse_transport_segment`.
    """
    for packet in iter_network_layers(data):
        segment = parse_transport_segment(packet.payload, protocol)
        if segment is not None:
            yield segment


def reassemble_tcp(segments: Iterator[TransportSegment]) -> list[Datagram]:
    """
    Reassembles a sequence of TCP `TransportSegment`s into `Datagram`s. Segments are grouped by
    their four-tuple and acknowledgement number so that each half of every exchange is emitted
    as a separate `Datagram`, ordered by the position of the first contributing segment.
    """
    flows: dict[FlowKey, _TcpStream] = {}
    first_index: dict[FlowKey, int] = {}
    for index, segment in enumerate(segments):
        key = FlowKey(
            segment.src_addr,
            segment.src_port,
            segment.dst_addr,
            segment.dst_port,
            segment.ack,
        )
        if key not in first_index:
            first_index[key] = index
        if segment.payload:
            flows.setdefault(key, _TcpStream()).add(segment.seq, segment.payload, index)
    datagrams: list[tuple[int, Datagram]] = []
    for key, stream in flows.items():
        payload = stream.reassemble()
        if payload:
            datagrams.append((first_index[key], Datagram(
                IPProtocol.TCP,
                key.src_addr,
                key.dst_addr,
                key.src_port,
                key.dst_port,
                payload,
            )))
    datagrams.sort(key=lambda item: item[0])
    return [datagram for _, datagram in datagrams]


def reassemble_udp(segments: Iterator[TransportSegment]) -> list[Datagram]:
    """
    Collects a sequence of UDP `TransportSegment`s into `Datagram`s. Each UDP payload is a
    message boundary in its own right, so every segment with a payload becomes one `Datagram`,
    preserving capture order.
    """
    datagrams: list[Datagram] = []
    for segment in segments:
        if segment.payload:
            datagrams.append(Datagram(
                IPProtocol.UDP,
                segment.src_addr,
                segment.dst_addr,
                segment.src_port,
                segment.dst_port,
                bytearray(segment.payload),
            ))
    return datagrams
