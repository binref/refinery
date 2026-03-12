from __future__ import annotations

import base64
import json
import lzma
import struct

from uuid import UUID

from .. import TestUnitBase

from refinery.lib.lnk import LnkFile
from refinery.lib.lnk.extradata import ExtraData, ExtraDataBlock
from refinery.lib.lnk.flags import DriveType, ShowCommand, HotKeyLow
from refinery.lib.lnk.header import ShellLinkHeader
from refinery.lib.lnk.linkinfo import LinkInfo
from refinery.lib.structures import StructReader

_LNK_CLSID = UUID('00021401-0000-0000-C000-000000000046')

_SAMPLES = {
    'basic.lnk': lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;0AXBDqR3305AX{KfwF4ZyvBQY}kO5TlVs?c5P%SCo+#`34KoE@Ywer@{JJ`4pM3Z$W;wx'
        B'Nb^>$P63A;%h!ti{>sAvG-M4`3EZ?`fh*eypffB9(HeDCCijJZB0B2Tb}8w<@?HaZF4KmQvH?y>bbllCF}vkGADab)xy|roDjLf5'
        B'?2=SkQYg+Ow9ItsEg}2N&uFjM-8BKU3y$m%^BN`$F~21w!)vJ69`ug0ECW8vCJcfuAAJT%0aKxvuGt#CmzyLzo#X%e$it<D)^;D?'
        B'oD-3$y^h)QAS^!wS0W(<^qHhI{g1@~=ge5~Ejet?Ew7S6OxftBTymT9kQ<l5b=$QzTL~i!MxT2b3AWjAnsX3m6*V$046<;Y({bBW'
        B'mHs%x2B?j>07qJc>Z^mjyCSAKuKM4oHisZ4R(nD7teABbpFR+urUEDrV1E`UaDtT&X)<}uS@K^DnS;frAz(Mgp6i9f?0+hAgX7CM'
        B'VP|`RvYJ*bm7*d1*`NuiZ;sKigwn`hVq90~=cd_=^FUFy7p+=#XQ;0p9N@T`Xgl0+`3tNHzzOYiWZE1MLo?6YJeR9mXpneVR{RTR'
        B'hlM|FzY(F-YI&3AEV09qBWzQCT)%fQD@%k6>JT=f_C|zQXcbL3$ms5EI)=EhdZSc!h{)g8AhRr+h*m_rx~VX46fRza0#;kqqsO?H'
        B'bC}miIgBG)dn#tXXT^#i)cl`Um*~)P00000=^Grhj>;Qi00G7X_zVC5m`JR<vBYQl0ssI200dcD'
    )),
    'hotkey_maximized.lnk': lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~&qm@?8KX05AX{KfwF4ZyvBQNF4j&lT`BI5U+#7cS!0Kd(Rm#_A`wHp4BW*!UH76uM}wM'
        B'#!fXMTle`HcrnX$@H7zW_Scq*ZA=rPTjjEHyAjl~N908Bq%>l-8RSs~a!RC$pbD_AR6LLpZ=jREES}Q^2aFT5xH=PXKg<nxgc~?M'
        B'cLVe4L{COF8hhw<4_L&g%y<abV3TgiQ9=XTF~6P8Eo6)LVw1G<DJ~h{epw_4*l{zNk>OiRY*yP+im!?Q^2ZsfxowhC`upT!b=&)u'
        B'37$OlL47boWepW8;4`=nT8l$3_NG(rJ@r3q*Ptu4+ZZPKol5v+Dko;JK;gF%Lp)Z`QdCRHTCqI!^m&sD*oEI@xXA%OfCGPv8PIzB'
        B'2Y*N1?Dj2Rl$Z^uJ)ihe_R{<MA;xf+UB!(u-Rc7y|3vyW6nn?yzwxR>hvq*RL$L33F!A={k6=9D#mrWQ^42LG5g%wNFYh_eipH7)'
        B'-K9d7P6ugHB2#IJa74-yUZFBp8&)6<K8hxg+=4<#Upc#@<*EZV>Bt1<%fs}xQD9}DsAwx7vPtx+Te;=pz}M9;#DT~@nH$3R`E0Jj'
        B'Ji!oJh_UheQpdFrp4?WSJo{_Db+J2|eCxi8l*@7-2_jBmb{xJGd2kf=nb`%1000003Dr{5bJz#-00E8!%mx4exhi=ovBYQl0ssI2'
        B'00dcD'
    )),
    'minimized.lnk': lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~&AY<y`<K05AX{KfwF4ZyvBQNF4j&lT`BI5U+#7cSz_UEj~T~k3f+J4qPtjGFSWB5pzG%'
        B'1lYl*chF+<8$p(%Qj|Y!tNx#}T*!^<VKH8<a+`Z0DV3YiptV>t=!?I7{F;$^lO&f2@wIw9=eiJ~u%antd0+m|Gddn^>{=k31A)%d'
        B'fJ<q^8beOnk3tacK3YJUz$kaJb1sZ6)~qQJ{wxymf>H%hgCC#B3y3EXdn~g0{R+7Xo0CVy3souU#EJch;fh!s*#{A4DD-pN4;Dq6'
        B'cg7CDWA{2{KR)CO;fW5w@zeka30e78mweZ<7CkBG^X^`n)_KrVt8O#6<Rk)OoF3>0k#rm&DUdzDM}A>e$*6K?x00gJyd(kDU(8ds'
        B'^x!Y+P044i8?c+vNi8j8q(`Qs{kabgTH&u<RbdCsjfoa=F1s5W?R=Xj!pi*mNr|q&;v{tX%$27Esd>*C*aQ&aDmWdbRuhZkg!+Sp'
        B'1SPBv^5ZeW7&(DA^O%SgPSb8i0%P>Kf9O``b)b}j5WC1`Wi^q*mvV<NLWzXo1`!Cmdo$#SJx&EE01*J#vC^f*uH@Ndvu7M~;>Ks)'
        B'gHszc8%%?Zc!0$+te#@y%AYs@JI(&d3$}?PA7HGY;{kdA00000zhEtcF4o`A00Dsnz6JmQd+-?=vBYQl0ssI200dcD'
    )),
    'pylnk3_ansi_strings.lnk': lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~hz{cwGP{05AX{KfwF4ZyvBQCvl1>Hx-L$CQB6^%4wbfG)R5f%dw`cP?*igZ7($TP&OG('
        B'>(R`|)+a(BQ1#Vx^X)4=V27S6{^*TZO6OWd$pIS4q0|@LGRK;FK7~mryvQ*YX6zH-r^pW_?8E8lq_M<ba8c~94!{5aez-XbzMkG)'
        B'00EQ%#sL5T)p8~(vBYQl0ssI200dcD'
    )),
    'pylnk3_cnrl.lnk': lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~g8ZOkDsb05AX{KfwF4ZyvBQLsDsH;h^Qv=E{sZa^SS*%i11R8sR-{L;G*MUM*hU`Xmcf'
        B'Y9eY6vpn>ansTE>c47B;+%<(++ZKBVowk<%Komx!5J{RP00C&20RR91UQ#%IvBYQl0ssI200dcD'
    )),
    'pylnk3_env_var.lnk': lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~+AzkzD{L05AX{KfwF4ZyvBQLsDsH;h^Qv=E{sZa^SS*%j+lMWv>jKu>0B{5*7JMCIKm?'
        B'haB62sw*lRj7!;?E)$wxg8o^>c$b>n(672xS1reTf&t`2+176~=l688o@?`+vxg~1T^*yKzOa0&BpDJ6p;bCSlVdMqt++LCPob^4'
        B'Ymb~&o3Gx`l$r;D8PEU#00000o+3M5uT4vw00FH5uLl4Ci{S7}vBYQl0ssI200dcD'
    )),
    'pylnk3_icon_env.lnk': lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~+Azl3f5M05AX{KfwF4ZyvBQLsDsH;h^Qv=E{sZa^SS*%j+lMWv>jKu>0B{5*7JMCIKm?'
        B'haB62sw*lRj7!;?E)$wxg8o^>c$b>n(672xS1reTf&(-3cMaq_*30$|6H<TQbVR>q3}kQc7R%(aBp6tQaojeWX5yoEQjdMDh(FWz'
        B'&7HA3@0;SC4;@Dlo~OfT00000CTV-T0{5{d00FK6uLl4CC6Z*#vBYQl0ssI200dcD'
    )),
    'pylnk3_local_linkinfo.lnk': lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~gNeSX}@n05AX{KfwF4ZyvBQLsDsH;h^Qv=E{sZa^SS*%lDOhv#(N^E~&1=nHK3BceCQH'
        B'hF)U$5X#9Wses4}ZYP{-&<dRM$x&G*t83v;hgDlbdT1oa5yt=kU_d#GqkzhL00DHJ0RR91&L7OevBYQl0ssI200dcD'
    )),
    'pylnk3_unicode_strings.lnk': lzma.decompress(base64.b85decode(
        B'{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~l86rd<Fg05AX{KfwF4ZyvBQY;uWcx6Kn^si+nz>8s4B2%5^L8lqO1um|HC0IS(Nu77as'
        B'e&+DjFeQG~)fqqk=&-7vPsRnM4etR@N7A10cGca^5)ssI9f8t9A;PA0m~AJYb~lHko+T0RD!nzis<6eQ#0F53?QN+}U62EvW~6Pg'
        B'==1HZ;>$52@^)#j_UR2}kqKXbzjl*}Jn_DBdbNkAO%OgS000004CLpWtW?=b00F`Qr2+r|i+?2BvBYQl0ssI200dcD'
    )),
}


def _u32(v: int) -> bytes:
    return struct.pack('<I', v)


def _lnk_header(
    flags: int = 0,
    file_attributes: int = 0,
    show_command: int = 1,
    hot_key_low: int = 0,
    hot_key_high: int = 0,
    creation_time: int = 0,
    accessed_time: int = 0,
    modified_time: int = 0,
    file_size: int = 0,
    icon_index: int = 0,
) -> bytearray:
    buf = bytearray()
    buf += _u32(0x4C)
    buf += _LNK_CLSID.bytes_le
    buf += _u32(flags)
    buf += _u32(file_attributes)
    buf += struct.pack('<Q', creation_time)
    buf += struct.pack('<Q', accessed_time)
    buf += struct.pack('<Q', modified_time)
    buf += _u32(file_size)
    buf += struct.pack('<i', icon_index)
    buf += _u32(show_command)
    buf += bytes([hot_key_low, hot_key_high])
    buf += b'\x00' * 10
    assert len(buf) == 0x4C
    return buf


def _extra_block(signature: int, payload: bytes) -> bytearray:
    size = 8 + len(payload)
    return bytearray(_u32(size) + _u32(signature) + payload)


def _extra_terminal() -> bytearray:
    return bytearray(_u32(0))


def _load_sample(name: str) -> bytes:
    return _SAMPLES[name]


class TestLNK(TestUnitBase):

    def test_real_world_with_datetime_entries(self):
        data = self.download_sample('03160be7cb698e1684f47071cb441ff181ff299cb38429636d11542ba8d306ae')
        result = data | self.load() | json.loads
        self.assertEqual(result['header']['creation_time'], '2021-12-26 21:31:16+00:00')
        self.assertEqual(result['header']['accessed_time'], '2022-06-03 12:49:55+00:00')
        self.assertEqual(result['header']['modified_time'], '2021-12-26 21:31:16+00:00')
        self.assertEqual(result['data']['command_line_arguments'], '019338921.dll,DllInstall')
        result = data | self.load(tabular=True) | [str]
        result = [entry.partition(':') for entry in result]
        result = {k.strip(): v.strip() for k, _, v in result}
        self.assertEqual(result['header.creation_time'], '2021-12-26 21:31:16+00:00')
        self.assertEqual(result['header.accessed_time'], '2022-06-03 12:49:55+00:00')
        self.assertEqual(result['header.modified_time'], '2021-12-26 21:31:16+00:00')
        self.assertEqual(result['data.command_line_arguments'], '019338921.dll,DllInstall')

    def test_real_world_regression(self):
        data = self.download_sample('e80e7382eb4ce1868a24bcad0743f754cd92fbfd1dbfe38acd9e0f3755a44215')
        result = data | self.load() | json.loads
        self.assertEqual(result['link_info']['local_base_path'], 'C:\\Windows\\System32\\wscript.exe')

    def test_basic_header(self):
        data = _load_sample('basic.lnk')
        result = data | self.load(details=True) | json.loads
        hdr = result['header']
        self.assertEqual(hdr['show_command'], 'Normal')
        self.assertEqual(hdr['hot_key_low'], 'Unset')
        self.assertIsInstance(hdr['creation_time'], str)
        self.assertIsInstance(hdr['accessed_time'], str)
        self.assertIsInstance(hdr['modified_time'], str)
        self.assertIn('Archive', hdr['file_attributes'])
        self.assertGreater(hdr['file_size'], 0)
        self.assertEqual(hdr['clsid'], str(_LNK_CLSID))

    def test_basic_linkinfo(self):
        data = _load_sample('basic.lnk')
        result = data | self.load(details=True) | json.loads
        li = result['link_info']
        self.assertEqual(
            li['local_base_path'], r'C:\Windows\notepad.exe')
        vol = li['volume_id']
        self.assertEqual(vol['drive_type'], 'Fixed')
        self.assertIsInstance(vol['volume_label'], str)
        self.assertTrue(len(vol['volume_label']) > 0)

    def test_basic_stringdata(self):
        data = _load_sample('basic.lnk')
        result = data | self.load() | json.loads
        sd = result['data']
        self.assertEqual(sd['description'], 'Notepad Shortcut')
        self.assertEqual(sd['command_line_arguments'], '/A testfile.txt')
        self.assertEqual(sd['working_directory'], r'C:\Windows')
        self.assertEqual(sd['icon_location'], r'C:\Windows\notepad.exe')

    def test_basic_extra_data(self):
        data = _load_sample('basic.lnk')
        result = data | self.load(details=True) | json.loads
        extra = result['extra_data']
        names = set()
        for block in extra:
            if 'type' in block:
                names.add(block['type'])
            elif 'machine_id' in block:
                names.add('tracker')
            elif 'special_folder_id' in block:
                names.add('special_folder')
            elif 'known_folder_id' in block:
                names.add('known_folder')
        for expected in ('tracker', 'special_folder', 'known_folder', 'property_store'):
            self.assertIn(expected, names)

    def test_basic_size_and_carve(self):
        data = _load_sample('basic.lnk')
        lnk = LnkFile(data)
        self.assertEqual(lnk.size, len(data))
        carved = data | self.ldu('carve_lnk') | bytes
        self.assertEqual(carved, data)

    def test_hotkey_maximized(self):
        data = _load_sample('hotkey_maximized.lnk')
        result = data | self.load(details=True) | json.loads
        hdr = result['header']
        self.assertEqual(hdr['show_command'], 'Maximized')
        self.assertEqual(hdr['hot_key_low'], 'KeyN')
        self.assertIn('Control', hdr['hot_key_high'])
        self.assertIn('Alt', hdr['hot_key_high'])

    def test_minimized(self):
        data = _load_sample('minimized.lnk')
        result = data | self.load(details=True) | json.loads
        hdr = result['header']
        self.assertEqual(hdr['show_command'], 'MinimizedNoActive')

    def test_pylnk3_ansi_strings(self):
        data = _load_sample('pylnk3_ansi_strings.lnk')
        result = data | self.load(details=True) | json.loads
        hdr = result['header']
        self.assertNotIn('IsUnicode', hdr['link_flags'])
        sd = result['data']
        self.assertEqual(sd['description'], 'ANSI description')
        self.assertEqual(sd['command_line_arguments'], '--ansi-flag')
        self.assertEqual(sd['working_directory'], r'C:\Windows')

    def test_pylnk3_unicode_strings(self):
        data = _load_sample('pylnk3_unicode_strings.lnk')
        result = data | self.load(details=True) | json.loads
        hdr = result['header']
        self.assertIn('IsUnicode', hdr['link_flags'])
        sd = result['data']
        self.assertEqual(sd['description'], 'Unicode description')
        self.assertEqual(sd['command_line_arguments'], '--unicode-flag')
        self.assertEqual(sd['working_directory'], r'C:\Windows')
        self.assertEqual(sd['icon_location'], r'C:\Windows\notepad.exe')

    def test_pylnk3_local_linkinfo(self):
        data = _load_sample('pylnk3_local_linkinfo.lnk')
        result = data | self.load(details=True) | json.loads
        li = result['link_info']
        self.assertEqual(
            li['local_base_path'], r'C:\Program Files\App\app.exe')
        self.assertIsNotNone(li.get('volume_id'))
        self.assertEqual(li['volume_id']['drive_type'], 'Fixed')
        self.assertEqual(li['volume_id']['volume_label'], 'OS')

    def test_pylnk3_cnrl(self):
        data = _load_sample('pylnk3_cnrl.lnk')
        result = data | self.load(details=True) | json.loads
        li = result['link_info']
        cnrl = li['common_network_relative_link']
        self.assertEqual(cnrl['net_name'], r'\\fileserver\share')
        self.assertIsNone(cnrl['device_name'])

    def test_pylnk3_env_var(self):
        data = _load_sample('pylnk3_env_var.lnk')
        result = data | self.load(details=True) | json.loads
        extra = result.get('extra_data', [])
        types = [b.get('type') for b in extra]
        self.assertIn('environment_variable', types)

    def test_pylnk3_icon_env(self):
        data = _load_sample('pylnk3_icon_env.lnk')
        result = data | self.load(details=True) | json.loads
        extra = result.get('extra_data', [])
        types = [b.get('type') for b in extra]
        self.assertIn('icon_environment', types)

    def test_details_mode(self):
        data = _load_sample('basic.lnk')
        result = data | self.load(details=True) | json.loads
        self.assertIn('target_id_list', result)
        self.assertIn('extra_data', result)
        default = data | self.load() | json.loads
        self.assertNotIn('target_id_list', default)
        self.assertNotIn('extra_data', default)

    def test_tabular_mode(self):
        data = _load_sample('basic.lnk')
        result = data | self.load(tabular=True) | [str]
        result = [entry.partition(':') for entry in result]
        table = {k.strip(): v.strip() for k, _, v in result}
        self.assertIn('header.show_command', table)
        self.assertIn('data.description', table)
        self.assertEqual(table['data.description'], 'Notepad Shortcut')

    def test_header_invalid_size(self):
        bad = bytearray(_lnk_header())
        bad[0:4] = _u32(0xFF)
        with self.assertRaises(ValueError):
            ShellLinkHeader(StructReader(memoryview(bad)))

    def test_header_invalid_clsid(self):
        bad = bytearray(_lnk_header())
        bad[4:20] = b'\x00' * 16
        with self.assertRaises(ValueError):
            ShellLinkHeader(StructReader(memoryview(bad)))

    def test_header_invalid_show_command(self):
        data = _lnk_header(show_command=0xDEAD)
        reader = StructReader(memoryview(bytearray(data)))
        hdr = ShellLinkHeader(reader)
        self.assertEqual(hdr.show_command, ShowCommand.Normal)

    def test_header_invalid_hotkey(self):
        data = _lnk_header(hot_key_low=0xFF)
        reader = StructReader(memoryview(bytearray(data)))
        hdr = ShellLinkHeader(reader)
        self.assertEqual(hdr.hot_key_low, HotKeyLow.Unset)

    def test_header_filetime_overflow(self):
        data = _lnk_header(creation_time=0xFFFFFFFFFFFFFFFF)
        reader = StructReader(memoryview(bytearray(data)))
        hdr = ShellLinkHeader(reader)
        self.assertIsNone(hdr.creation_time)

    def test_header_json_skips_underscore(self):
        data = _lnk_header()
        reader = StructReader(memoryview(bytearray(data)))
        hdr = ShellLinkHeader(reader)
        hdr._internal = 'hidden'
        info = hdr.__json__()
        self.assertNotIn('_internal', info)

    def test_extra_truncated(self):
        data = bytearray(_u32(20) + b'\x00\x00\x00')
        reader = StructReader(memoryview(data))
        ed = ExtraData.parse(reader)
        self.assertEqual(len(ed.blocks), 0)

    def test_extra_unknown_block(self):
        payload = b'\xDE\xAD\xBE\xEF' * 4
        data = bytearray(_extra_block(0xA000FFFF, payload))
        data += _extra_terminal()
        reader = StructReader(memoryview(data))
        ed = ExtraData.parse(reader)
        self.assertEqual(len(ed.blocks), 1)
        block: ExtraDataBlock = ed.blocks[0]
        self.assertIsNone(block.data)
        info = block.__json__()
        self.assertIn('signature', info)
        self.assertEqual(info['signature'], '0xA000FFFF')

    def test_linkinfo_invalid_drive_type(self):
        flags = 0x01
        header_size = 0x1C
        vol_label = b'C\x00'
        vol_id_body = bytearray()
        vol_id_body += _u32(0xFF)
        vol_id_body += _u32(0x12345678)
        vol_id_body += _u32(0x10)
        vol_id_body += vol_label
        vol_id = _u32(4 + len(vol_id_body)) + vol_id_body
        local_base_path = b'C:\\test.exe\x00'
        common_suffix = b'\x00'
        vol_id_offset = header_size
        local_bp_offset = vol_id_offset + len(vol_id)
        cnrl_offset = 0
        suffix_offset = local_bp_offset + len(local_base_path)
        link_info_header = bytearray()
        link_info_header += _u32(header_size)
        link_info_header += _u32(flags)
        link_info_header += _u32(vol_id_offset)
        link_info_header += _u32(local_bp_offset)
        link_info_header += _u32(cnrl_offset)
        link_info_header += _u32(suffix_offset)
        body = vol_id + local_base_path + common_suffix
        total = 4 + len(link_info_header) + len(body)
        data = bytearray(_u32(total)) + link_info_header + body
        reader = StructReader(memoryview(bytearray(data)))
        li = LinkInfo(reader)
        self.assertEqual(li.volume_id.drive_type, DriveType.Unknown)
