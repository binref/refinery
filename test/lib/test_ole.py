"""
Tests for the OLE2 Compound Binary File parser in refinery.lib.ole.file.

The test samples were generated using the Windows Structured Storage API
(pythoncom.StgCreateDocfile) and cross-validated with olefile.
"""
from __future__ import annotations

import base64
import datetime
import lzma
import struct
import unittest

from refinery.lib.ole.file import (
    OleFile, OleFileError, NotOleFileError, OleMetadata,
    STGTY, MAGIC, filetime_to_datetime, is_ole_file, _clsid,
)
from refinery.lib.structures import MemoryFile


class TestOleSamples:
    """
    Namespace for LZMA-compressed, base85-encoded OLE2 test samples.
    """
    BASIC = lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;0gZ#!Ce4oGrk;#Fn3_|q=YI!3><bRg7T4u+=$95;r+#m`TAhXaLF|q)MDX}+Ig64f19|'
        '-a=&L_Yjw`(ZiH2wQdhXOT=B6oA;h2p<Z!fq;O^;Zb~$GOx9TS`%EBFI!+2<4l7Rr9F8m$4)h{1rj6@5^l?r_N4P2N=^&*NtZ?>'
        '<k1qeuX?*o~k`j=A9Qfb$3;2XNiYe|6dM1M5kVRAaW%Xuq5+_?7ci8j0W0Lx5#c@^y;deTHt&O{@n%H`hx00000s1-x=UWaN^00'
        'G?rfD`}#3s2*wvBYQl0ssI200dcD'
    ))

    NESTED = lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;0yl&23-JXGrk;#Fn3_|q=YI!3><bRg7T4u+=$95;r+#m`TAhXaLF|q)MDX}+IXh-5_S{'
        'x*Np|)l7IN#DJlDT#2T%kz8E7yK3Xk>5dc7#ExI(^_R#ncuje$U9Zl6*%`AO0Bh`Eb!hZpMNDGi8>rc?lj)&3Fd|6>Bk20(%o9f'
        'Sp(KwF@>`R*73?NO(q8Mi5{;hfN93||T36<|`RsSw{$>o0$Y0R=N@E%q}J3XTj3qmwcC%~yiC2hxug?g8mVsHHsw(VDO0VR!taY'
        '3@Asb7gN=%>+27uol4)b{TkCp=lw7=5tVThmb7Q|u15sto?nBpo77%5_=3*;()3=bT@{00000XKe|!H}$m~00E)`fEWM(t8*<9v'
        'BYQl0ssI200dcD'
    ))

    MINISTREAM = lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;3@wA{9OQOGrk;#Fn3_|q=YI!3><bRg7T4u+=$95;r+#m`TAhXaLF|q)MDX}+Ig6FY63R'
        'Si(Xoe1GnQco1wfy8fd1i|F~LQ2w@``Fl!7oCV1%1mcQX-O{^Fs0zs{}BJ;L<ok^~nEVExsG(*-wC0;Gox<dx}>BUVncC3h*m;5'
        'qTAqCS59<gQ>Z@=33$2Xbn<A<YDoPLYH`vAhP9PQx-@GJr$khF-uc{)UF{>Psi0b{FiRL%_x1GbVgfi(d}5qTiy^wTM`7Q4x?_y'
        'Jfrw+8qb2rlk4{GTn#sL5P#@wNLhH`2y!`mtl{;guRigCcF829%7%?7RQ~H#Ckrq<{|N00Ec+fK&hg#3M}3vBYQl0ssI200dcD'
    ))

    PROPERTIES = lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;0gZ$cU=HzGrk;#Fn3_|q=YI!3><bRg7T4u+=$95;r+#m`TAhXaLF|q)MDX}+Ig64f19|'
        '-a=&L_Yjw`(ZiH2wQdhXOT=B6oA;h2p<Z>7J==XBNi5KonLXqLDy?NHBjZU_4?}PiRW17J$K<rB%;enD}5k#(xrCPX~1OPvTG~A'
        'YZ**spP`rD0wA$aVp#wbG_TvU46j6X%aP4lWseZa4~zHgH-P2R2&;(`t(&S!D@4(R4)?4g3r^q}^wVChgyvp-jAVUOL+EpVp1g@'
        '@TuQ<ysrtq*co#zo^IOv`qd($t|zvaxt~$WkS~P{w-}DmN#GZ^s7N?hv3P&=W1?^`5(|w&6diEej9B{&)Nk`)n}~Nx@M`x8{bAR'
        'jb}hVYCU|q^qZb)I<mV#WJgDj5RmArBg#1Wo6_jh#2$h-=cBoh1E?MdeQ(8GFeBJr{s9N1Kwth1>!Fh52G^jb|3mKO*|cVEPg<b'
        '-KHU*py1;xU;qFBAjFzt#3K6Q00EN&fD`}#cXx5=vBYQl0ssI200dcD'
    ))

    WRITABLE = lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;3fY6z+C`nGrk;#Fn3_|q=YI!3><bRg7T4u+=$95;r+#nk0a8eq~LS${8{I^?nQc>2TUB'
        '9GxeI+;~y^8KM^4>h(&BQvY^=Ysl{~maZ#SEU*$ncf35qE{;%6}F%Vk6qvSoQ6PW21f!tU}OoXQw?Zs;15(yZRGnOIGqaazogoo'
        '`H!GlnpBC*`O1gN#I8>Pb7PCefWzIB@zuiK&XXdK@G>Y#krdJO$fk*tmV3^<^+QslwT9Vg9dsV1IzkBa~R-6L57j0gLB00G<qfJ'
        '^`YrsEI~vBYQl0ssI200dcD'
    ))

    WRITE_MINI = lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;3@wA;avb|Grk;#Fn3_|q=YI!3><bRg7T4u+=$95;r+#m`TAhXaLF|q)MDX}+Ig6FY63R'
        'Si(Xoe1GnQco1wfy8fd1i|F~LQ2w@``Fl!7oCV1%1mcQX-O{^Fs0zs{}BJ;L<ok^~nEVExsG(+!U`|gLN__#^j_Mcb|cGs{MzJ8'
        'njO%Mz0;p@xM5j<J84*|7}eXHb8#M(K!PL{Z*nDvh4fb>_qcJr5EgW>s-M1(eeF0@2beH8-i`5DzFHFyfxn*y##0fgS@FV#96r5'
        'VtP;yu|@Tilj&H#u$>Tu9Ua000004Z<x@Ft}ET00I30fK&hg{m0eOvBYQl0ssI200dcD'
    ))

    TIMESTAMPS = lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;0gZ#y<GrkGrk;#Fn3_|q=YI!3><bRg7T4u+=$95;r+#m`TAhXaLF|q)MDX}+Ig64f19|'
        '-a=&L_Yjw`(ZiH2wQdhXOT=B6oA;h2p<Z!fq;JuY4%z~7Uu|Rwx@0l|1Z!7ESR$U9{c!epcBhsN^$*M9CLe*FHHg|*f!i68SUzF'
        'cjY#$CE_6jr37ng9(T$fqQ3z|dxjs@Tmvzz1d72}*)>X@`Ho$QZLS6Sx*Cq2*PsIiIT55OUfjpHBy00000v><L%3zc}800G$nfD'
        '`}#9Sw3lvBYQl0ssI200dcD'
    ))

    CLSID = lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;0gZ#yj=ijGrk;#Fn3_|q=YI!3><bRg7T4u+=$95;r+#m`TAhXaLF|q)MDX}+Ig64f19|'
        '-a=&L_Yjw`(ZiH2wQdhXOT=B6oA;h2p<Z!fq;JuY4%z~7Uu|Rwx@0l{}aa)6Xu28v{mGVMBTcj1aAl#PG0e<iO;}OP*`u5yO|C5'
        '2z5RcdMHJDK<AWH{wQA(sGPG?T>+Df+8=f&-GJL*-oHyy2M{bvN-?0d8;WETxKs3dvoy$)~J^xgmf)_q0w?sehN00GzmfD`}#xZ'
        'W=IvBYQl0ssI200dcD'
    ))

    RICH_PROPERTIES = lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;0yl(NnHSFGrk;#Fn3_|q=YI!3><bRg7T4u+=$95;r+#m`TAhXaLF|q)MDX}+Ig5~&Mtx'
        'iWUSfMSFQmUQA^jSDRvV3xb`_3*O-E3SdXnm1X#wVG{-%TKR=#V49l!jb9r5Ba%fL&7!_0Qh#x|uidfBV8kFH9?J)YanXw_)n@C'
        '^&`t3cBU-3(-m<f0XChzm;wz7UvKtX?*_49wf+Z$L%m?@HJC0xMEV4z!p%YZ*EAA<PdB798hF>&$)_7$jg8X2)$o&wVmR34}A7b'
        'NYC*3EqHj`#HYlzb!egW@-1Iaw#%2z=Y9uWLd{&WUy93D!$a5PW_NL$t<i!0@7tqa1^sw1oa|h#P3cSPRtICsO8V>|CnhMS?(Xa'
        'N-m_j@9t9$|+9A@VFIYURsrBLPBMRkHOhVDu+Jgk=bF9I|om}nhJo`O-tH^IVdcD<AtKi=h*APX24WHy@!Z-!cP+&0j19pi*kR0'
        '3fcAV+E_4iKV%F1#7T++GCWo8RfNCI6v5I?g;6cQ&XOyQzrBI=ZddlU<uMrV=^gC%D?uM_S~~BxZZ(=N9$Q)<8e9*of8-wBqP>;'
        'UPOcl3GG`I3ad%Ek*a>T4baJ;Jo#HUj<S%t#t?*kDRQvjt86>*)dND31F2QXIDU|>8+Mvz>%_%Z-JG{;rJPes>8`dsS&vG}BUwq'
        'o<C7kV|NBw32Ay<8(L$~3%F>$Wm(Afg6@7mFJug{mnco{0$a<7gAOu>HVCFX^XPqSi^W=jsMwj}@n00000toV9-PY4Wa00HF$fE'
        'WM(-@Gu7vBYQl0ssI200dcD'
    ))

    EXTRA_TYPES = lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;0gZ$VqE}eGrk;#Fn3_|q=YI!3><bRg7T4u+=$95;r+#m`TAhXaLF|q)MDX}+Ig64f19|'
        '-a=&L_Yjw`(ZiH2wQdhXOT=B6oA;h2p<Z!fq-=$Znz;XAUL(k2OB3rJfCQKiFqG8S@z9qS6_q_hwv;d69S83i4rYIxY1~s)2D#3'
        'gP7~z(4f7e(j0HHPIAwi7+yOxV8>sWf}CheOw`)8_b3B#FNMnY08#V*%U-Z#M5Nf`N>R<eFVGX%i`Q@SD%DY0gio)S5o^EC5<Ou'
        '*#i;Yit;eP!&&S2wE?bO7Dy)Cb$DqP1zwijG_Cx<9F^5=Rhqq8Xff$b+somf0prlyNF=@WY`Yd%;-AqM}nJ-yA~g;@{GV+i7B4U'
        'Q^5+dm-Qmh>h8C4hv-zbTGLiCS<W>;iZZdXMAYZ2RU%KCg;xRssjjWQqx!mO<M5>0>&*7${+Z?X%kwyOa+i~00000>qlpfAKvv?'
        '00I62fD`}#LqdCCvBYQl0ssI200dcD'
    ))


class TestOleFile(unittest.TestCase):
    """Public API tests against authentic OLE samples."""

    # --- Construction & validation ---

    def test_reject_non_ole_data(self):
        with self.assertRaises(NotOleFileError):
            OleFile(b'This is not an OLE file at all, just some text data here!!' * 50)

    def test_reject_too_small(self):
        with self.assertRaises(NotOleFileError):
            OleFile(MAGIC + b'\x00' * 100)

    def test_reject_invalid_type(self):
        with self.assertRaises(TypeError):
            OleFile(12345)

    def test_construct_from_memoryview(self):
        ole = OleFile(memoryview(TestOleSamples.BASIC))
        self.assertEqual(ole.openstream('TestStream').read(),
            b'Hello, OLE World! This is a test stream with known content.')

    def test_construct_from_bytearray(self):
        ole = OleFile(bytearray(TestOleSamples.BASIC))
        self.assertEqual(ole.openstream('TestStream').read(),
            b'Hello, OLE World! This is a test stream with known content.')

    def test_construct_from_memoryfile(self):
        mf = MemoryFile(memoryview(TestOleSamples.BASIC))
        ole = OleFile(mf)
        self.assertEqual(ole.openstream('TestStream').read(),
            b'Hello, OLE World! This is a test stream with known content.')

    def test_context_manager(self):
        with OleFile(TestOleSamples.BASIC) as ole:
            data = ole.openstream('TestStream').read()
        self.assertEqual(data, b'Hello, OLE World! This is a test stream with known content.')

    def test_is_ole_file(self):
        self.assertTrue(is_ole_file(TestOleSamples.BASIC))
        self.assertFalse(is_ole_file(b'Not an OLE file'))

    # --- Basic parsing (BASIC sample) ---

    def test_basic_listdir(self):
        ole = OleFile(TestOleSamples.BASIC)
        self.assertEqual(ole.listdir(), [['TestStream']])

    def test_basic_stream_content(self):
        ole = OleFile(TestOleSamples.BASIC)
        self.assertEqual(ole.openstream('TestStream').read(),
            b'Hello, OLE World! This is a test stream with known content.')

    def test_basic_exists(self):
        ole = OleFile(TestOleSamples.BASIC)
        self.assertTrue(ole.exists('TestStream'))
        self.assertFalse(ole.exists('NonExistent'))

    def test_basic_get_type(self):
        ole = OleFile(TestOleSamples.BASIC)
        self.assertEqual(ole.get_type('TestStream'), STGTY.STREAM)
        self.assertEqual(ole.get_type('NonExistent'), STGTY.EMPTY)

    def test_basic_get_size(self):
        ole = OleFile(TestOleSamples.BASIC)
        self.assertEqual(ole.get_size('TestStream'), 59)

    def test_basic_root_entry_name(self):
        ole = OleFile(TestOleSamples.BASIC)
        self.assertEqual(ole.get_rootentry_name(), 'Root Entry')

    # --- Nested storages (NESTED sample) ---

    def test_nested_streams(self):
        ole = OleFile(TestOleSamples.NESTED)
        names = ['/'.join(s) for s in ole.listdir()]
        self.assertIn('RootStream', names)
        self.assertIn('Storage1/Sub1Stream', names)
        self.assertIn('Storage1/SubStorage/DeepStream', names)
        self.assertIn('Storage2/Sub2Stream', names)

    def test_nested_storages(self):
        ole = OleFile(TestOleSamples.NESTED)
        entries = ole.listdir(streams=False, storages=True)
        names = ['/'.join(e) for e in entries]
        self.assertIn('Storage1', names)
        self.assertIn('Storage2', names)
        self.assertIn('Storage1/SubStorage', names)

    def test_nested_listdir_both(self):
        ole = OleFile(TestOleSamples.NESTED)
        both = ole.listdir(streams=True, storages=True)
        names = ['/'.join(e) for e in both]
        self.assertIn('RootStream', names)
        self.assertIn('Storage1', names)

    def test_nested_listdir_neither(self):
        ole = OleFile(TestOleSamples.NESTED)
        self.assertEqual(ole.listdir(streams=False, storages=False), [])

    def test_nested_read_streams(self):
        ole = OleFile(TestOleSamples.NESTED)
        self.assertEqual(ole.openstream('RootStream').read(), b'root-level-data')
        self.assertEqual(ole.openstream('Storage1/Sub1Stream').read(), b'storage1-stream-data')
        self.assertEqual(ole.openstream('Storage1/SubStorage/DeepStream').read(), b'deep-nested-data')
        self.assertEqual(ole.openstream('Storage2/Sub2Stream').read(), b'storage2-stream-data')

    def test_nested_backslash_path(self):
        ole = OleFile(TestOleSamples.NESTED)
        self.assertEqual(ole.openstream('Storage1\\SubStorage\\DeepStream').read(), b'deep-nested-data')

    def test_nested_storage_type(self):
        ole = OleFile(TestOleSamples.NESTED)
        self.assertEqual(ole.get_type('Storage1'), STGTY.STORAGE)
        self.assertEqual(ole.get_type('Storage1/Sub1Stream'), STGTY.STREAM)

    # --- Mini-stream (MINISTREAM sample) ---

    def test_ministream_read(self):
        ole = OleFile(TestOleSamples.MINISTREAM)
        self.assertEqual(ole.openstream('SmallStream').read(), b'Mini stream test data - small!')
        self.assertEqual(ole.openstream('BigStream').read(), b'X' * 8192)

    def test_ministream_sizes(self):
        ole = OleFile(TestOleSamples.MINISTREAM)
        self.assertEqual(ole.get_size('SmallStream'), 30)
        self.assertEqual(ole.get_size('BigStream'), 8192)

    # --- Properties (PROPERTIES sample) ---

    def test_properties_summary(self):
        ole = OleFile(TestOleSamples.PROPERTIES)
        props = ole.getproperties('\x05SummaryInformation')
        self.assertEqual(props[1], 1252)  # codepage (VT_I2)
        self.assertEqual(props[2], 'Test Document Title')
        self.assertEqual(props[3], 'Test Subject')
        self.assertEqual(props[4], 'Test Author Name')
        self.assertEqual(props[5], 'test, ole, binary')

    def test_properties_docsummary(self):
        ole = OleFile(TestOleSamples.PROPERTIES)
        props = ole.getproperties('\x05DocumentSummaryInformation')
        self.assertEqual(props[2], 'Testing')
        self.assertEqual(props[15], 'Test Company Inc.')

    def test_properties_convert_time(self):
        ole = OleFile(TestOleSamples.PROPERTIES)
        props = ole.getproperties('\x05SummaryInformation', convert_time=True)
        self.assertEqual(props[2], 'Test Document Title')

    def test_properties_stream_content(self):
        ole = OleFile(TestOleSamples.PROPERTIES)
        self.assertEqual(ole.openstream('ContentStream').read(), b'document content')

    # --- Metadata ---

    def test_metadata(self):
        ole = OleFile(TestOleSamples.PROPERTIES)
        meta = ole.get_metadata()
        self.assertEqual(getattr(meta, 'title'), 'Test Document Title')
        self.assertEqual(getattr(meta, 'author'), 'Test Author Name')
        self.assertEqual(getattr(meta, 'subject'), 'Test Subject')
        self.assertEqual(getattr(meta, 'keywords'), 'test, ole, binary')
        self.assertEqual(getattr(meta, 'company'), 'Test Company Inc.')
        self.assertEqual(getattr(meta, 'category'), 'Testing')
        self.assertEqual(getattr(meta, 'codepage'), 1252)

    def test_metadata_dump(self):
        ole = OleFile(TestOleSamples.PROPERTIES)
        result = ole.get_metadata().dump()
        self.assertIsInstance(result, dict)
        self.assertEqual(result['title'], 'Test Document Title')
        self.assertEqual(result['category'], 'Testing')

    def test_metadata_cached(self):
        ole = OleFile(TestOleSamples.PROPERTIES)
        self.assertIs(ole.get_metadata(), ole.get_metadata())

    def test_metadata_absent(self):
        ole = OleFile(TestOleSamples.BASIC)
        meta = ole.get_metadata()
        self.assertIsNone(getattr(meta, 'title'))
        self.assertIsNone(getattr(meta, 'author'))

    def test_metadata_defaults(self):
        meta = OleMetadata()
        self.assertIsNone(getattr(meta, 'title'))
        self.assertEqual(meta.dump(), {})

    # --- Timestamps (TIMESTAMPS sample) ---

    def test_timestamps(self):
        ole = OleFile(TestOleSamples.TIMESTAMPS)
        self.assertEqual(ole.openstream('TimedStorage/Data').read(), b'timestamp test')
        mtime = ole.getmtime('TimedStorage')
        ctime = ole.getctime('TimedStorage')
        self.assertIsInstance(mtime, datetime.datetime)
        self.assertIsInstance(ctime, datetime.datetime)
        assert mtime is not None
        assert ctime is not None
        self.assertGreater(mtime.year, 2000)
        self.assertGreater(ctime.year, 2000)

    # --- CLSID (CLSID sample) ---

    def test_clsid(self):
        ole = OleFile(TestOleSamples.CLSID)
        self.assertEqual(ole.openstream('ClsidStorage/Data').read(), b'clsid test')
        self.assertEqual(ole.getclsid('ClsidStorage'), '12345678-1234-5678-9abc-def012345678')

    # --- Write (WRITABLE, WRITE_MINI samples) ---

    def test_write_regular_stream(self):
        data = bytearray(TestOleSamples.WRITABLE)
        ole = OleFile(data)
        self.assertEqual(ole.openstream('WritableStream').read(), b'AAAA' * 2048)
        ole.write_stream('WritableStream', b'ZZZZ' * 2048)
        self.assertEqual(OleFile(data).openstream('WritableStream').read(), b'ZZZZ' * 2048)

    def test_write_mini_stream(self):
        data = bytearray(TestOleSamples.WRITE_MINI)
        ole = OleFile(data)
        self.assertEqual(ole.openstream('MiniWritable').read(), b'BBBB' * 64)
        ole.write_stream('MiniWritable', b'CCCC' * 64)
        self.assertEqual(OleFile(data).openstream('MiniWritable').read(), b'CCCC' * 64)

    def test_write_same_data_is_idempotent(self):
        data = bytearray(TestOleSamples.WRITABLE)
        original = bytes(data)
        OleFile(data).write_stream('WritableStream', b'AAAA' * 2048)
        self.assertEqual(data, original)

    # --- Error paths ---

    def test_open_nonexistent_raises(self):
        ole = OleFile(TestOleSamples.BASIC)
        with self.assertRaises(OleFileError):
            ole.openstream('DoesNotExist')

    def test_get_size_nonexistent_raises(self):
        ole = OleFile(TestOleSamples.BASIC)
        with self.assertRaises(OleFileError):
            ole.get_size('DoesNotExist')

    def test_open_storage_as_stream_raises(self):
        ole = OleFile(TestOleSamples.NESTED)
        with self.assertRaises(OleFileError):
            ole.openstream('Storage1')

    def test_write_wrong_size_raises(self):
        ole = OleFile(bytearray(TestOleSamples.WRITABLE))
        with self.assertRaises(OleFileError):
            ole.write_stream('WritableStream', b'too short')

    def test_write_nonexistent_raises(self):
        ole = OleFile(bytearray(TestOleSamples.WRITABLE))
        with self.assertRaises(OleFileError):
            ole.write_stream('NoSuchStream', b'data')

    def test_write_storage_raises(self):
        ole = OleFile(bytearray(TestOleSamples.NESTED))
        with self.assertRaises(OleFileError):
            ole.write_stream('Storage1', b'data')

    def test_getclsid_missing_raises(self):
        ole = OleFile(TestOleSamples.BASIC)
        with self.assertRaises(OleFileError):
            ole.getclsid('NoSuchEntry')

    def test_getmtime_missing(self):
        self.assertIsNone(OleFile(TestOleSamples.BASIC).getmtime('NoSuchEntry'))

    def test_getctime_missing(self):
        self.assertIsNone(OleFile(TestOleSamples.BASIC).getctime('NoSuchEntry'))

    def test_getproperties_nonexistent_raises(self):
        with self.assertRaises(OleFileError):
            OleFile(TestOleSamples.BASIC).getproperties('NoSuchStream')

    def test_getproperties_non_property_stream(self):
        self.assertEqual(OleFile(TestOleSamples.BASIC).getproperties('TestStream'), {})

    def test_getproperties_short_stream(self):
        # NESTED RootStream is only 15 bytes, below the 28-byte property minimum
        self.assertEqual(OleFile(TestOleSamples.NESTED).getproperties('RootStream'), {})

    # --- Rich property types (RICH_PROPERTIES sample) ---

    def test_rich_integer_properties(self):
        ole = OleFile(TestOleSamples.RICH_PROPERTIES)
        props = ole.getproperties('\x05SummaryInformation')
        self.assertEqual(props[14], 42)
        self.assertEqual(props[15], 1500)
        self.assertEqual(props[16], 8500)

    def test_rich_filetime_converted(self):
        ole = OleFile(TestOleSamples.RICH_PROPERTIES)
        props = ole.getproperties('\x05SummaryInformation', convert_time=True)
        self.assertIsInstance(props[12], datetime.datetime)
        self.assertIsInstance(props[13], datetime.datetime)
        self.assertEqual(props[12], datetime.datetime(2024, 1, 1, 0, 0))
        self.assertEqual(props[13], datetime.datetime(2024, 6, 15, 12, 0))

    def test_rich_filetime_raw(self):
        ole = OleFile(TestOleSamples.RICH_PROPERTIES)
        props = ole.getproperties('\x05SummaryInformation', convert_time=False)
        self.assertIsInstance(props[12], int)
        self.assertIsInstance(props[13], int)

    def test_rich_boolean_properties(self):
        ole = OleFile(TestOleSamples.RICH_PROPERTIES)
        props = ole.getproperties('\x05DocumentSummaryInformation')
        self.assertIs(props[11], True)
        self.assertIs(props[16], False)

    def test_rich_vector_variant(self):
        ole = OleFile(TestOleSamples.RICH_PROPERTIES)
        props = ole.getproperties('\x05DocumentSummaryInformation')
        self.assertIsInstance(props[12], list)
        self.assertEqual(props[12], ['Title', 1, 'Slide', 2])

    def test_rich_vector_lpstr(self):
        ole = OleFile(TestOleSamples.RICH_PROPERTIES)
        props = ole.getproperties('\x05DocumentSummaryInformation')
        self.assertIsInstance(props[13], list)
        self.assertEqual(props[13], ['Part One', 'Part Two', 'Part Three'])

    def test_rich_docsummary_integers(self):
        ole = OleFile(TestOleSamples.RICH_PROPERTIES)
        props = ole.getproperties('\x05DocumentSummaryInformation')
        self.assertEqual(props[4], 50000)
        self.assertEqual(props[5], 200)
        self.assertEqual(props[6], 25)

    def test_rich_string_properties(self):
        ole = OleFile(TestOleSamples.RICH_PROPERTIES)
        props = ole.getproperties('\x05SummaryInformation')
        self.assertEqual(props[2], 'Rich Props Title')
        self.assertEqual(props[4], 'Rich Author')
        self.assertEqual(props[18], 'TestApp')

    def test_rich_content_stream(self):
        ole = OleFile(TestOleSamples.RICH_PROPERTIES)
        self.assertEqual(ole.openstream('ContentStream').read(), b'rich properties content')

    # --- Extra property types (EXTRA_TYPES sample) ---

    def test_extra_r4_property(self):
        ole = OleFile(TestOleSamples.EXTRA_TYPES)
        props = ole.getproperties('\x05ExtraTypes')
        self.assertAlmostEqual(props[2], 3.14, places=2)

    def test_extra_r8_property(self):
        ole = OleFile(TestOleSamples.EXTRA_TYPES)
        props = ole.getproperties('\x05ExtraTypes')
        self.assertAlmostEqual(props[3], 2.718281828, places=6)

    def test_extra_i8_property(self):
        ole = OleFile(TestOleSamples.EXTRA_TYPES)
        props = ole.getproperties('\x05ExtraTypes')
        self.assertEqual(props[4], -9999999999)

    def test_extra_ui8_property(self):
        ole = OleFile(TestOleSamples.EXTRA_TYPES)
        props = ole.getproperties('\x05ExtraTypes')
        self.assertEqual(props[5], 18446744073709551000)

    def test_extra_ui1_property(self):
        ole = OleFile(TestOleSamples.EXTRA_TYPES)
        props = ole.getproperties('\x05ExtraTypes')
        self.assertEqual(props[6], 255)

    def test_extra_ui4_property(self):
        ole = OleFile(TestOleSamples.EXTRA_TYPES)
        props = ole.getproperties('\x05ExtraTypes')
        self.assertEqual(props[7], 4294967295)

    def test_extra_clsid_property(self):
        ole = OleFile(TestOleSamples.EXTRA_TYPES)
        props = ole.getproperties('\x05ExtraTypes')
        self.assertEqual(props[8], '12345678-1234-5678-9abc-def012345678')

    def test_extra_blob_property(self):
        ole = OleFile(TestOleSamples.EXTRA_TYPES)
        props = ole.getproperties('\x05ExtraTypes')
        self.assertEqual(bytes(props[9]), b'\xDE\xAD\xBE\xEF' * 4)

    def test_extra_lpwstr_property(self):
        ole = OleFile(TestOleSamples.EXTRA_TYPES)
        props = ole.getproperties('\x05ExtraTypes')
        self.assertIn('Unicode', props[10])
        self.assertIn('\xe9', props[10])


class TestOleUtilities(unittest.TestCase):

    def test_filetime_to_datetime_known_value(self):
        filetime = (1700000000 + 11644473600) * 10_000_000
        dt = filetime_to_datetime(filetime)
        assert dt is not None
        self.assertEqual(dt.year, 2023)
        self.assertEqual(dt.month, 11)
        self.assertEqual(dt.day, 14)

    def test_filetime_to_datetime_zero(self):
        self.assertIsNone(filetime_to_datetime(0))

    def test_filetime_to_datetime_negative(self):
        self.assertIsNone(filetime_to_datetime(-1))

    def test_filetime_to_datetime_overflow(self):
        self.assertIsNone(filetime_to_datetime(0x7FFFFFFFFFFFFFFF))

    def test_clsid_known_value(self):
        clsid_bytes = bytes.fromhex('78563412341278569ABCDEF012345678')
        self.assertEqual(_clsid(clsid_bytes), '12345678-1234-5678-9abc-def012345678')

    def test_clsid_from_memoryview(self):
        clsid_bytes = bytes.fromhex('78563412341278569ABCDEF012345678')
        self.assertEqual(_clsid(memoryview(clsid_bytes)), '12345678-1234-5678-9abc-def012345678')

    def test_clsid_all_zeros(self):
        self.assertEqual(_clsid(b'\x00' * 16), '')

    def test_clsid_wrong_length(self):
        self.assertEqual(_clsid(b'\x01\x02\x03'), '')


class TestOleCorruptedData(unittest.TestCase):
    """
    Tests using modified authentic OLE data for error-specific code paths.
    Per CLAUDE.md: "It is permitted to use code to modify authentic test data
    in order to cover error-specific code paths."
    """

    def test_corrupted_root_entry(self):
        """Set root directory entry type to EMPTY → OleFileError."""
        data = bytearray(TestOleSamples.BASIC)
        ole = OleFile(bytes(data))
        dir_offset = ole._sector_size * (ole._first_dir_sector + 1)
        data[dir_offset + 66] = STGTY.EMPTY
        with self.assertRaises(OleFileError):
            OleFile(data)

    def test_corrupted_property_section_offset(self):
        """Set the property set section offset past EOF → getproperties returns {}."""
        data = bytearray(TestOleSamples.PROPERTIES)
        ole = OleFile(data)
        raw = bytearray(ole.openstream('\x05SummaryInformation').read())
        struct.pack_into('<I', raw, 44, len(raw) + 100)
        # Replace the stream data in-place is impractical, but we can test
        # _parse_property_set directly since it's used by getproperties
        from refinery.lib.ole.file import _parse_property_set
        self.assertEqual(_parse_property_set(memoryview(raw), False, []), {})

    def test_corrupted_property_num_sections_zero(self):
        """Set num_sections to 0 in property stream → returns {}."""
        from refinery.lib.ole.file import _parse_property_set
        ole = OleFile(TestOleSamples.PROPERTIES)
        raw = bytearray(ole.openstream('\x05SummaryInformation').read())
        struct.pack_into('<I', raw, 24, 0)
        self.assertEqual(_parse_property_set(memoryview(raw), False, []), {})

    def test_writable_has_no_ministream(self):
        """The WRITABLE sample has no mini-FAT, exercising the empty ministream path."""
        ole = OleFile(TestOleSamples.WRITABLE)
        ole._load_ministream()
        self.assertEqual(ole._minifat, [])
        self.assertEqual(ole._ministream, bytearray())

    def test_truncated_sector_padded(self):
        data = bytearray(TestOleSamples.MINISTREAM)
        # Truncate so that the last referenced sector is incomplete.
        # The FAT sector (sector 0) is at offset 512; we move the DIFAT entry
        # to point at the last sector, then truncate the file mid-sector.
        # The DIFAT starts at byte 76 in the header; DIFAT[0] is at offset 76.
        last_full_sector = (len(data) - 512) // 512 - 1  # last 0-indexed sector
        struct.pack_into('<I', data, 76, last_full_sector)
        data = data[:-200]
        ole = OleFile(data)
        self.assertTrue(ole.exists('SmallStream') or ole.exists('BigStream'))
