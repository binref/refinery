import base64
import lzma
import pytest

from refinery.lib.pcap import (
    Datagram,
    IPProtocol,
    iter_captured_packets,
    iter_network_layers,
    iter_transport,
    reassemble_tcp,
    _read_ng_timestamp_scale,
    _seq_delta,
)

from .. import TestUnitBase
from . import test_http


def _import_http_sample() -> bytes:
    return test_http.TestHTTP._HTTP_SAMPLE_01


_PCAPNG_SAMPLE = lzma.decompress(base64.b85decode(
    '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;1V+i_+0=61K)#t#K}YG'
    'cgSLU?>dk6jYaLrYn;Eshef9Ha8#IyV~BO8IB{2Uq!*vd1uhp-'
    'C*2V*l#YiTUQL!~{Le9&arp^cG_azeEmev3iVMA93gTF+O^;IY'
    'H6j*ARay#M=l5iMDg-^8Rcf?xDTY^qoCVvJR$<ak1rlVGRE^bb'
    '^J`gmClb#1m84bGu<ts>okMZps+UY{i=C*nZtY9~I`pdKtnz{('
    '#N(=|P0F|9-Wh&_$JAL$z}6f&)C5!RNDy&d-<w_u<8G`FXN>zZ'
    '>O^oF!Inb*1T<W3VnomY=6h)B$}0k%Wv8aj*>&3&GBcaD+d(DS'
    '2JPmD6*LhF#LY7k-*FE<%`y32B^<6Dh4y7|FZOp~%kYBX!xYBE'
    'DNlj$$Rmu5C*7IIS?DebV&w?LbCNP&&|OYK*kBD3W~UPRUjc;0'
    't9v{-o}>}*@1*;*)%47FKW(XMj%lOQ6c|XHYIlG@vbJORGLm>L'
    '(@77YZkfP${a<aBAP3PS?+oqZPH&UFi9zqGTpG6zq^FjNohC$}'
    'HMdp^wY0wNWmH|H^PDp;W69O>A6*!*;{FOFIw|Vc>UZp-d~wZu'
    'm#ZDHE#cIW`IhS=dd=iGSYI^JDq*ERv`zy27;@(W<p?BG$j^k#'
    '9ZLK8om1R)RZf5fsbTa=F<J^lFkLtRd9WUE=dXkbVxFkW;4`l-'
    'VGe8m_JPKn?<39n26?VLkc>ZK&c9U%5hN9id~sfHp{9?=HYsUm'
    'h!nuIrI$E$g$3{8?z|FzloKV98NbAi-oCUAa*};*lZiXRiFG*l'
    'NNuz9&43+%t6S}&omi!jCnHXVjcM3muGjCTIqF@(0`$`qZ^BYa'
    'zZZ2%qs!Ik;Q}z&j6r8gzor$Ak@H}JqFny|K*nU?s>HXeq{6&Q'
    'uJNz+EobtS8>1=fX13FSLQxg+AX1S&Lo}@m(}IGe(PE4tC+Z|e'
    'EzJTasa`|j3?$N-MhF)Y=-9@Y`E6^IA%P0ekw=wFI5>;L8;&l+'
    'K|mKVnR@9Fp-A<RuK5Dnnr>FCi*{mFmTuDOFtD`<(n>OgpDt50'
    'MNQ@)J$bVe!Bff;^u6#Hc!|U6C5McbjT6$1G#M<+P|`WheIN^q'
    '7Za=G9bIUx{GXrl!9zMW@BFy5xVJ)c#L=&w7f%gv1yQbcV3b&P'
    'fH9D&Suy1%;ZHHaDFLgNhjK+@w=}nM=s&dQc-Ige?95k#+B}P}'
    'We0DX6;&ov3+3lgq9~_)T{^O<%PL^v(mJKLy<;i?;^JJb#gEe<'
    'FpFy2gsnl2q5r9)uk6x|z_-%QEE5)-<q26upo&4H&YyLV{-Q}k'
    'Hth9Xh<j`)e-D{L_)*shf`OqIR`$ET01b7~M&w6(n6y6b(7REH'
    'Fz1=Cgz=G|VL%8eQykCbx#{Lde}lG6L=0t9)zY^cy&Os%-a#&#'
    'y@Go;+b3h-)J<`OS48(S<pvisic*UwB}G7(B!^O8xY})m$iRH+'
    '{W+k;hhM0G4qk2G0$s{W<4D+A&vt-F3Wn3<3vDN9H6d100dm!-'
    'yj|8~lF*cfNf(fu^a+D5Ud0`m8cD_HwDxJvgU9H%cGw=LddIbm'
    'hJluW?nIOe9FlER2Edw>P&0#mE|8jr0+GL!#ohLgBvK`d_2BDz'
    '(>j)02D`=rRyIpu9B;sXWsJV(3rj{sRyQ&NRxC?tFGy>g(J^Rq'
    'DkVRG@LxEP{+pe#R(+A3p!pqf+6&+8T{TnWC+VZi8gdWf9gBX_'
    'WfB9PP>}7Rmf#FsMuizB@&1e;B$>WiFHuEXcic!P=k@_V2E&U+'
    'utsmCj)pkG2B~mx&d1Ol=ESsi$kFy`46e~q1BOl?-{xLJICROD'
    't@QC$b-@!kZTQbTtc-W51C~r*`hUbZhGTYDJYitd@!BXq86YAH'
    'ohy^xnzrO>!|o_XKEw;juu-_638DA+@a}-*%HL8JgLf&)&W7`%'
    '8XV<-ZQGg%94pBG5!QD}C#LQ<6+dobKo&4&%HPgVfbP>@Epmj$'
    'vq}r^;yK~aqZ!^lRYN}8mbX#=QrQxYws!T;jg$76+skh{ZB<jA'
    '?|^+LhLEr#lsx^VVJkr`J-ljjQXB!&GVE5nqn4zOcji_qN~`9m'
    ';DvhGJ-Oe9V^cwhTzc1~2k+$C%C?C@An=TE<!V)5{@Am|?MS-A'
    'J;?iEN9#~&sUvf;ElI{3PhZu8-y5G|U3l{RK{@u)l{xICUeXv`'
    '2B2LIPbyjfr50k65YKI6o_+%wKpwLE49jdg4f3ZZ)$mkb_R7Wd'
    '(V915xF0ycXMpXO>N8#BxTsd8hw?ra{u4Fxqw$C}P|eUJ^c$1X'
    '-x1*)bM|7EAOWuwW<dY|#{r$))skQ900EQ^v?Krk7zxH#vBYQl'
    '0ssI200dcD'))


class TestPCAP(TestUnitBase):

    @pytest.mark.xdist_group(name='pcap')
    def test_network_layer_packet_count(self):
        packets = _PCAPNG_SAMPLE | self.load() | [bytes]
        self.assertEqual(len(packets), 40)

    @pytest.mark.xdist_group(name='pcap')
    def test_network_layer_labels(self):
        chunks = list(_PCAPNG_SAMPLE | self.load())
        self.assertEqual(chunks[0]['link'], 'ETHERNET')
        self.assertEqual(chunks[0]['time'], '2024-07-24 18:37:37+00:00')

    @pytest.mark.xdist_group(name='pcap')
    def test_link_layer_mode_preserves_all_frames(self):
        frames = list(iter_captured_packets(_PCAPNG_SAMPLE))
        emitted = _PCAPNG_SAMPLE | self.load(link=True) | [bytes]
        self.assertEqual(emitted, [bytes(f.frame) for f in frames])

    @pytest.mark.xdist_group(name='pcap')
    def test_handles_accepts_bytearray_and_memoryview(self):
        unit = self.load()
        self.assertTrue(unit.handles(_PCAPNG_SAMPLE))
        self.assertTrue(unit.handles(bytearray(_PCAPNG_SAMPLE)))
        self.assertTrue(unit.handles(memoryview(bytes(_PCAPNG_SAMPLE))))

    @pytest.mark.xdist_group(name='pcap')
    def test_out_of_range_timestamp_does_not_crash(self):
        patched = bytearray(_PCAPNG_SAMPLE)
        patched[344:348] = (0xFFFFFFFF).to_bytes(4, 'little')
        chunks = list(patched | self.load())
        self.assertEqual(len(chunks), 40)
        self.assertNotIn('time', chunks[0].meta)

    @pytest.mark.xdist_group(name='pcap')
    def test_network_layer_is_link_layer_suffix(self):
        for frame, network in zip(
            iter_captured_packets(_PCAPNG_SAMPLE),
            iter_network_layers(_PCAPNG_SAMPLE),
        ):
            self.assertEqual(
                bytes(network.payload),
                bytes(frame.frame)[-len(network.payload):],
            )



def _reassemble_tcp(data) -> list[Datagram]:
    return reassemble_tcp(iter_transport(data, IPProtocol.TCP))


class TestPCAPRobustness(TestUnitBase):

    _PCAP_CLASSIC = _import_http_sample()

    def test_unsupported_link_type_pcapng_yields_nothing(self):
        self.assertGreater(len(_reassemble_tcp(_PCAPNG_SAMPLE)), 0)
        patched = bytearray(_PCAPNG_SAMPLE)
        patched[196:198] = (105).to_bytes(2, 'little')
        self.assertEqual(_reassemble_tcp(patched), [])

    def test_unsupported_link_type_classic_yields_nothing(self):
        self.assertGreater(len(_reassemble_tcp(self._PCAP_CLASSIC)), 0)
        patched = bytearray(self._PCAP_CLASSIC)
        patched[20:24] = (105).to_bytes(4, 'little')
        self.assertEqual(_reassemble_tcp(patched), [])

    def test_truncated_pcapng_never_raises(self):
        failures = []
        for n in range(len(_PCAPNG_SAMPLE) + 1):
            try:
                _reassemble_tcp(_PCAPNG_SAMPLE[:n])
            except Exception:
                failures.append(n)
        self.assertEqual(failures, [])

    def test_truncated_classic_never_raises(self):
        failures = []
        for n in range(len(self._PCAP_CLASSIC) + 1):
            try:
                _reassemble_tcp(self._PCAP_CLASSIC[:n])
            except Exception:
                failures.append(n)
        self.assertEqual(failures, [])

    def test_empty_input_yields_nothing(self):
        self.assertEqual(_reassemble_tcp(b''), [])

    def test_seq_delta_wraparound(self):
        self.assertEqual(_seq_delta(5, 3), 2)
        self.assertEqual(_seq_delta(3, 5), -2)
        self.assertEqual(_seq_delta(7, 7), 0)
        self.assertEqual(_seq_delta(0, 0xFFFFFFFF), 1)
        self.assertEqual(_seq_delta(0xFFFFFFFF, 0), -1)
        self.assertEqual(_seq_delta(0x00000004, 0xFFFFFFFC), 8)

    def test_reassembly_survives_sequence_wraparound(self):
        segments = list(iter_transport(_PCAPNG_SAMPLE, IPProtocol.TCP))
        baseline = [bytes(d.payload) for d in reassemble_tcp(iter(segments))]

        flows: dict[tuple, list[int]] = {}
        for segment in segments:
            if segment.payload:
                key = (
                    segment.src_addr,
                    segment.src_port,
                    segment.dst_addr,
                    segment.dst_port,
                    segment.ack,
                )
                flows.setdefault(key, []).append(segment.seq)
        multi = [seqs for seqs in flows.values() if len(seqs) > 1]
        self.assertGreater(len(multi), 0)

        boundary = min(min(seqs) for seqs in multi)
        shift = (0x100000000 - boundary - 8) & 0xFFFFFFFF
        shifted = [
            segment._replace(seq=(segment.seq + shift) & 0xFFFFFFFF)
            for segment in segments
        ]
        wrapped = [bytes(d.payload) for d in reassemble_tcp(iter(shifted))]
        self.assertEqual(wrapped, baseline)

    def test_truncated_tsresol_option_falls_back_to_default(self):
        truncated = memoryview(b'\x09\x00\x01\x00')
        self.assertEqual(_read_ng_timestamp_scale(truncated, False), 1e-6)
        wellformed = memoryview(b'\x09\x00\x01\x00\x09\x00\x00\x00')
        self.assertEqual(_read_ng_timestamp_scale(wellformed, False), 1e-9)


def _ipv6_packet(next_header: int, payload: bytes) -> bytes:
    # RFC 8200 sec 3: 40-byte fixed header. 2001:db8::/32 is the RFC 3849 documentation prefix.
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    header = bytes((0x60, 0, 0, 0)) + len(payload).to_bytes(2, 'big')
    header += bytes((next_header, 0x40))
    return header + src + dst + payload


def _hop_by_hop(next_header: int) -> bytes:
    # RFC 8200 sec 4.3: Hdr Ext Len 0 spans 8 octets; tail is a PadN option (type 1, length 4).
    return bytes((next_header, 0, 1, 4, 0, 0, 0, 0))


def _tcp_segment(src_port: int, dst_port: int, payload: bytes) -> bytes:
    # RFC 793: 20-byte header, data offset 5 words, flags PSH|ACK.
    header = src_port.to_bytes(2, 'big') + dst_port.to_bytes(2, 'big')
    header += (1).to_bytes(4, 'big') + (0).to_bytes(4, 'big')
    header += bytes((0x50, 0x18, 0xFF, 0xFF, 0, 0, 0, 0))
    return header + payload


def _classic_pcap_raw_ip(ip_packet: bytes) -> bytes:
    # libpcap classic format, little-endian, link type 228 (RAW_IP): frame is the bare IP packet.
    header = bytes.fromhex('d4c3b2a1')
    header += (2).to_bytes(2, 'little') + (4).to_bytes(2, 'little')
    header += bytes(8) + (0x40000).to_bytes(4, 'little') + (228).to_bytes(4, 'little')
    record = bytes(8) + len(ip_packet).to_bytes(4, 'little') * 2
    return header + record + ip_packet


class TestPCAPv6ExtensionHeaders(TestUnitBase):

    _TCP_PAYLOAD = b'RFC8200-IPv6-EXT'

    def _reassemble(self, ip_next_header: int):
        # The ESP/AH cases reuse a walkable Hop-by-Hop+TCP body so that wrongly walking
        # them as extension headers would surface a (bogus) datagram instead of nothing.
        body = _hop_by_hop(IPProtocol.TCP) + _tcp_segment(49152, 80, self._TCP_PAYLOAD)
        packet = _ipv6_packet(ip_next_header, body)
        return _reassemble_tcp(_classic_pcap_raw_ip(packet))

    def test_hop_by_hop_extension_is_traversed(self):
        self.assertEqual(self._reassemble(0), [Datagram(
            protocol=IPProtocol.TCP,
            src_addr='2001:db8::1',
            dst_addr='2001:db8::2',
            src_port=49152,
            dst_port=80,
            payload=bytearray(self._TCP_PAYLOAD),
        )])

    def test_esp_is_not_walked_as_extension_header(self):
        self.assertEqual(self._reassemble(50), [])

    def test_ah_is_not_walked_as_extension_header(self):
        self.assertEqual(self._reassemble(51), [])
