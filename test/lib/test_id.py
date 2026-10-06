import base64
import codecs
import itertools
import lzma
import unittest

from refinery.lib import id as idlib

from .. import TestBase


class TestIDLib(TestBase):

    def test_image_detection(self):
        png = base64.b85decode(
            'iBL{Q4GJ0x0000DNk~Le0000G0000G1Oos70PWr4QUCw|0drDELIAGL9O(c600d`2O+f$vv5yP<VFdsH01{A4R7L+cFd_#AD+vey'
            '000UC0Tl!T`4U9`00009a7bBm000id000id0mpBsWB>pF8FWQhbW?9;ba!ELWdKlNX>N2bPDNB8H7+qOF)@k=7R~?w0JvpXNoGk&'
            'DgX!o000F58UY0W0RR91N&o-=8vz9X0RR91QUCw|C;<Zi0RR910ssI2F#!Sq5dZ)HS^xk5X@>*=0RR91YybcN00000U;qFB0RR91'
            'U;qFB0RR91P+@6qbS_RsR3J4jF)lGN000930FVa&1ONa4FfubR0iXi_0RR910RR911)u}~0RR91mH+?%000000ssL30ssU6002@s'
            'H~<0w2LJ>B001yCFfafB000Ix)N`_raytM307gkfK~xyiV_<**K|vt~ML|J91`|P11rb3(X9hzCMgc(v24O4=xEf<)Lk1BM6NoNB'
            'MneXO8UhT6VxTUNrAkadOJM*2e;^3K@XyYj00000NkvXXu0mjf'
        )
        self.assertEqual(idlib.get_image_format(png), idlib.Fmt.PNG)
        jpg = png | self.ldu('imgto', 'jpeg') | bytes
        self.assertEqual(idlib.get_image_format(jpg), idlib.Fmt.JPG)
        bmp = jpg | self.ldu('imgto', 'bmp') | bytes
        self.assertEqual(idlib.get_image_format(bmp), idlib.Fmt.BMP)
        gif = bmp | self.ldu('imgto', 'gif') | bytes
        self.assertEqual(idlib.get_image_format(gif), idlib.Fmt.GIF)
        ico = png | self.ldu('imgto', 'ico') | bytes
        self.assertEqual(idlib.get_image_format(ico), idlib.Fmt.ICO)

    def test_detect_unicode(self):
        data = B'H\0e\0l\0l\0o\0,\0\x20\0W\0r\0l\0d\0!\0\0\0'
        enc = idlib.guess_text_encoding(data)
        self.assertIsNotNone(enc)
        assert enc is not None
        self.assertEqual(enc.step, 2)

    def test_all_pyc_magics(self):
        from refinery.lib.shared.xdis import xdis

        mismatches = [
            (magic, version) for magic, version in xdis.magics.versions.items()
            if idlib.PycMagicPattern.fullmatch(magic) is None
        ]
        errors = '\n'.join([
            F'- {magic.hex().upper()} for version {version}' for magic, version in mismatches
        ])
        self.assertListEqual(mismatches, [],
            msg=F'the following pyc magics were not matches:\n{errors}')

    def test_buffer_containment(self):
        base = bytearray(range(20, 100))
        view = memoryview(base)

        for hl, hx, hs in itertools.product(range(10), range(10), (1, 2, 3)):
            hu = hl + hx
            for nl, nx, ns in itertools.product(range(10), range(10), (1, 2, 3)):
                nu = nl + nx
                h_slice = slice(hl, hu, hs)
                n_slice = slice(nl, nu, ns)
                n_view = view[n_slice]
                h_view = view[h_slice]
                n_base = base[n_slice]
                h_base = base[h_slice]
                goal = h_base.find(n_base)
                msg = F'offset of [{nl}:{nu}:{ns}] in [{hl}:{hu}:{hs}] was {{}}, should be {goal}'
                test = idlib.buffer_offset(h_view, n_view)
                self.assertEqual(goal, test, F'buffer {msg}'.format(test))
                if (test := idlib.slice_offset(h_slice, n_slice)) is not None:
                    self.assertEqual(goal, test, F'sliced {msg}'.format(test))

    def test_comparison(self):
        self.assertLessEqual(idlib.Fmt.PE, idlib.Fmt.PE32CUI)
        self.assertLessEqual(idlib.Fmt.MACHO, idlib.Fmt.MACHO32BE)
        self.assertNotEqual(idlib.Fmt.PE, idlib.Fmt.ELF)
        self.assertNotEqual(idlib.Fmt.PE32DLL, idlib.Fmt.PE32CUI)
        self.assertNotEqual(idlib.Fmt.JSON, idlib.Fmt.REG)
        self.assertLessEqual(idlib.Fmt.ZIP, idlib.Fmt.DOCX)
        self.assertFalse(idlib.Fmt.OFFICE <= idlib.Fmt.TEXT)
        self.assertLessEqual(idlib.Fmt.OFFICE, idlib.Fmt.DOCX)

    def test_not_json_regression(self):
        a = B'Acceptance of the QuoVadis Root CA 3 Cerbmpicate'
        self.assertNotEqual(idlib.get_structured_data_type(a), idlib.Fmt.JSON)

    def test_utf8_with_some_chinese(self):
        data = lzma.decompress(base64.b85decode(
            '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;1c`>&RqaBn@VT6Qap3bx>&56zVd_~`)P2oAJkw%ze<3(>QD^Ovz;cYPxXb?Jx~w+N$6{a'
            '_0wsJK~L)j?O4Pp3@a!Xq$tB=@iepwXg8Qpjf^4x2c`a=uDO=gyJO!e$}>|e74yXI<&NLBD_Yn`k(z)Vdub~tyrSpO@lHyL5aN)T'
            'CH5|^P|12}8=Bz-Dh_8UUL#ZI>Yghv4;a*TnT!YBSpXSgqmqe_S#qq3t8ISPqp^_^8T^y6Z<Rfsf$Af;8tIOhJXHZ=<Kwe0wJB@t'
            '{o2urh9VUQ$|H04z>V)Pqyw2RjlRCwSj%70=U-l3z_UGoLsCOvynNEDOgrg!+14JiMEuT^Md`vza(oaoq|m+iBe?rBo3sH3sR+K}'
            'd<mvz5SR1c`-5TL72%?+aG8*cz)qM@6a`=f>g!*hPZ8DI7=N}y7@Z`W4c%qpOgIiMx<Y`StATT`v=&S<B#{=zYF}r~xq(icIwN1H'
            '%cC!BQ5wHQUa+M<Fe#hceQ7P*Llw&FM$_FFlanYq-t16#8fsJHlFS7#rrgD(&xhib28GVh^N%meKKM&ri{p~i<8XsG2l3K6BjR7|'
            '1|^nlCECeD*dnKCbD{r-xdO;|tZzZs(0K9>)|azF{>aVZ66G70{EJ=Df$~*sTaTMN;#YC4F_F;KTH=5@3$wj?eUkga-U)i~rggHW'
            'L;itX{pGT=%h42CR`oGF@dC*#UGanq@|4;b!^cwy7Rjz;wPGBsEne~v)HZH1UGvA}QegMKz_ml0hKz0#OdQ20%)HzhL$rcZi|FHk'
            '^AN1Cu#lzH>gyTHo;O<$`ofsw)cT}H9{c{jh>tncG5gKbI_8#asT2GmJLokpSz$=?`V%(!|NG-O!0?`$6Y6S(yW_3&t++a}2_<as'
            'Jl{o``Ubg@UlEUjki#n2#{DbT8y$(Z=2e(vJjv3@ewMy!pksm}wuwEAsBD*J=avKP+6D!TgVOvxSPen-DR=2|W#n5+7mcp3+k2>K'
            'I(gMBn>34)018f_Pw#Pw>S4#ZpMu@0KlV=USIm?d*-Dmq(WFh_yOcN~Ckj6b!C%wK*mNf?N}ms@FDvk56HC%H<TLNAUE9CeHOkY%'
            'H*2kw0QO6uKu>V%hmPR%w};nEl&+4#>^+_Jej4wbW~D=b*aQDx0R;kQ2v_c21DkR;t>P!hq4Oh^(N`xQ&_GAr^9n-4VW>p^cJg06'
            ';Y0%rU?k{~5#bdt=!@og;c74L*(XF;f-HG07srom8*U$lP(Yk=r5N;tLjv_p>@TQakY5A~P!#Xo`WZBniZwo<@xD>b6TO!5?SUO~'
            '#m;ehKt1@k_VtyP#-um{sKt`=5Qcb$DgF15FM#fxN({>vTQZ!yO}Zi6#@wT*`2Q3Wa9k(oE8bZ74j<McE%jL)JUAH`NmDKHRrA#v'
            '7mc>})kBDuGeEe8VvHjZHOIm?c$JeK$SYi|_CJ*6CYee@<)jiqDS_O*6^pE(EMi_n?(zciMT!iG)s2u_1>r-pcd^-smtCG1z{)U}'
            'Mi7rrQMM~0k@C;oem>^YMqJL*jbM+ePZIG;M7vi*hPczIM!&|s_TT{N53#?Xb$lqVIfsyl2K<s?LzH3PI#vPm;cvVo5n8mKL*G#`'
            '>ESLv@~%U{uZ*0Crc6AH{iKOhoU+GuOT3-T%%Ze}B7PqLWsOQBzI3A#CVY>(tY7DYCs}o=@4>p*Hdg_Qs9}gkZaF>WV}dQI+!P+?'
            '6ae%ib*j23z0i<r?(Eo(Mu}AV+q>P9WxR}Jub)?-3E*J-$yGC7a1&>_RiThzdExC_vz7go>Sf0Yr6+)W>?|$BnGW%ed7FN-0vrs^'
            '*2ZDj9uE=8pyri;zJcRa+<%|Zf{_n6rH16^63q}KvR-F-@ri-<+F2E$O*<9I?m<+@zbq+>pBtXRxp!d1Bij>g%AaGjj-P!#=?Yj;'
            'fkQ;cNcR4Z_n!4$)<N|f_3KrA_OA3*<;WUqj8cbRg_~ZVV-NyGom2$}-^<|kpNzoX!|gR=3%!Lb!eYtR^j<zd4UlM5g$7PXHxGdx'
            'A|5#q6Ie>JTnt~UCV+f`Z!#w$!a-HW3>0eUi>_3L!#^$Yr`spPg3gaA`<mIg+KNW*KorU7G2GD3!ZXMXZ*+dxCutDIHX-fa&9kfW'
            'QGy;skof-*Ti`7F6Rd|G-n=$Lml*R4NqE87_|Yxxe_=Pl<VU02S}6DQ>^zaE7HiL%`D8?G{}^jfFacY&#5;|<8a67Q-j&R#1`^W#'
            '5-(mB##YpvryhhjiU0rrOG}wSFu_BN00HU^{UrbZ`C^d9vBYQl0ssI200dcD'
        ))
        self.assertEqual(idlib.get_structured_data_type(data), idlib.Fmt.UTF08)

    def test_elf_detection(self):
        data = self.download_sample('c5ba314fbf02989af9e2b5edb48626aede10f2d4569095a542ed0f2033068117')
        result = idlib.get_structured_data_type(data)
        self.assertLessEqual(idlib.Fmt.ELF, result)

    def test_zip_detection(self):
        data = self.download_sample('e90b970c5e5ddf821d6f9f4d7d710d6dc01d59b517e8fb39da726803dc52b5ad')
        result = idlib.get_structured_data_type(data)
        self.assertLessEqual(idlib.Fmt.ZIP, result)

    def test_pdf_detection(self):
        data = self.download_sample('302c0d553c9e7f2561864d79022b780a53ec0a5927e8962d883b88dde249d044')
        result = idlib.get_structured_data_type(data)
        self.assertEqual(result, idlib.Fmt.PDF)

    def test_pe_detection(self):
        data = self.download_sample('ff4ef0ee0915af58ea1388f72730c63c746856a64760e17e4fcdfc559a8b4555')
        result = idlib.get_structured_data_type(data)
        self.assertEqual(result, idlib.Fmt.PE32GUI)

    def test_macho_detection(self):
        data = self.download_sample('6c121f2b2efa6592c2c22b29218157ec9e63f385e7a1d7425857d603ddef8c59')
        result = idlib.get_structured_data_type(data)
        self.assertEqual(result, idlib.Fmt.MACHO64BE)

    def test_structured_data_json(self):
        data = b'{"key": "value"}'
        result = idlib.get_structured_data_type(data)
        self.assertEqual(result, idlib.Fmt.JSON)

    def test_structured_data_xml(self):
        data = b'<?xml version="1.0"?><root/>'
        result = idlib.get_structured_data_type(data)
        self.assertEqual(result, idlib.Fmt.XML)

    def test_fmt_extension_values(self):
        self.assertEqual(idlib.Fmt.PE.extension, 'exe')
        self.assertEqual(idlib.Fmt.ELF.extension, 'elf')
        self.assertEqual(idlib.Fmt.MACHO.extension, 'macho')
        self.assertEqual(idlib.Fmt.PDF.extension, 'pdf')
        self.assertEqual(idlib.Fmt.PNG.extension, 'png')
        self.assertEqual(idlib.Fmt.ZIP.extension, 'zip')
        self.assertEqual(idlib.Fmt.JSON.extension, 'json')
        self.assertEqual(idlib.Fmt.HTM.extension, 'html')
        self.assertEqual(idlib.Fmt.GZIP.extension, 'gz')
        self.assertEqual(idlib.Fmt.PE32DLL.extension, 'dll')
        self.assertEqual(idlib.Fmt.PE32SYS.extension, 'sys')

    def test_guess_text_encoding_ascii(self):
        data = b'Hello, World! This is a plain ASCII text string for testing purposes.'
        enc = idlib.guess_text_encoding(data)
        self.assertIsNotNone(enc)
        assert enc is not None
        self.assertEqual(enc.step, 1)
        self.assertEqual(enc.bom, 0)

    def test_guess_text_encoding_utf16_bom(self):
        data = b'\xFF\xFE' + 'Hello World'.encode('utf-16le')
        enc = idlib.guess_text_encoding(data)
        self.assertIsNotNone(enc)
        assert enc is not None
        self.assertEqual(enc.codec, 'utf-16le')
        self.assertEqual(enc.bom, 2)
        self.assertEqual(enc.step, 2)

    def test_guess_text_encoding_utf8_bom(self):
        data = b'\xEF\xBB\xBF' + b'Hello World, this is a longer text that ensures the encoding detection passes the ascii ratio threshold easily.'
        enc = idlib.guess_text_encoding(data)
        assert enc is not None
        self.assertEqual(enc.codec, 'utf8')
        self.assertEqual(enc.bom, 3)
        self.assertEqual(enc.step, 1)

    def test_text_holding_format_characters_reads_back_as_what_it_holds(self):
        """
        A soft hyphen, a zero width non-joiner and a right-to-left mark are written into text on
        purpose; the soft hyphen is two bytes in UTF-8 and the other two are three, and a legacy
        single byte codec reads each of those bytes as its own character. A guess that counts them
        as evidence against UTF-8 therefore answers a codec under which the document is mojibake,
        and every reader of the guess then works on a different text than the file holds.
        """
        text = (
            F'A soft{chr(0x00AD)}hyphen may break a long word, a joiner of zero'
            F'{chr(0x200C)}width may stand between two letters, and a mark'
            F'{chr(0x200F)}may turn the writing direction around.'
        )
        data = text.encode('utf8')
        enc = idlib.guess_text_encoding(data)
        assert enc is not None
        self.assertEqual(text, codecs.decode(data[enc.bom:], enc.codec))

    def test_text_holding_astral_plane_characters(self):
        text = F'the sample drops {chr(0x1F4F8) * 10} in every note it writes, and nothing else.'
        enc = idlib.guess_text_encoding(text.encode('utf8'))
        assert enc is not None
        self.assertEqual(enc.codec, 'utf8')

    def test_short_private_use_run_at_the_end_of_a_clean_document(self):
        note = (
            'the analyst notes every address the sample would have contacted, and writes it down. '
        )
        text = note * 5000 + chr(0xE000) * 1400
        data = text.encode('utf8')
        enc = idlib.guess_text_encoding(data)
        assert enc is not None
        self.assertEqual(enc.codec, 'utf8')
        self.assertEqual(text, codecs.decode(data[enc.bom:], enc.codec))

    def test_null_region_wider_than_the_window_gaps(self):
        note = (
            'the analyst notes every address the sample would have contacted, and writes it down. '
        )
        notes = (note * 5000).encode('ascii')
        damaged = notes[:len(notes) - 0x10000] + b'\x00' * 0x10000
        self.assertIsNone(idlib.guess_text_encoding(damaged))
        clean = idlib.guess_text_encoding(notes)
        assert clean is not None
        self.assertEqual(clean.codec, 'utf8')

    def test_format_gates_reject_a_binary_body_behind_the_header(self):
        body = bytes(range(0x100)) * 0x40
        self.assertTrue(idlib.is_likely_xml(B'<?xml version="1.0"?><root/>'))
        self.assertFalse(idlib.is_likely_xml(B'<?xml version="1.0"?><root/>' + body))
        self.assertTrue(idlib.is_likely_htm(B'<html><body>hello world</body></html>'))
        self.assertFalse(idlib.is_likely_htm(B'<html><body>' + body))
        self.assertTrue(idlib.is_likely_plist(B'<?xml version="1.0"?><!DOCTYPE plist'))
        self.assertFalse(idlib.is_likely_plist(B'<?xml version="1.0"?><!DOCTYPE plist' + body))

    def test_utf16_document_with_a_null_padded_tail(self):
        note = (
            'the analyst notes every address the sample would have contacted, and writes it down. '
        )
        data = B'\xFF\xFE' + (note * 1000).encode('utf-16le') + b'\x00' * 0x4000
        self.assertIsNone(idlib.guess_text_encoding(data))

    def test_utf16_document_with_lone_surrogate_halves(self):
        line = 'var greeting = "hello there"; console.log(greeting); '
        text = (line * 3000).replace('hello', F'{chr(0xD800)}hello', 40)
        data = B'\xFF\xFE' + text.encode('utf-16le', 'surrogatepass')
        enc = idlib.guess_text_encoding(data)
        assert enc is not None
        self.assertEqual(enc.codec, 'utf-16le')
        self.assertEqual(text, codecs.decode(data[enc.bom:], 'utf-16le', 'surrogatepass'))

    def test_sample_count_zero_reads_only_the_first_window(self):
        note = (
            'the analyst notes every address the sample would have contacted, and writes it down. '
        )
        damaged = (note * 200).encode('ascii') + b'\x00' * 0x10000
        head_only = idlib.guess_text_encoding(damaged, sample_count=0)
        assert head_only is not None
        self.assertEqual(head_only.codec, 'utf8')
        self.assertIsNone(idlib.guess_text_encoding(damaged))

    def test_window_size_zero_raises(self):
        with self.assertRaises(ValueError):
            idlib.guess_text_encoding(b'anything', window_size=0)

    def test_sample_count_above_the_span_reads_every_position(self):
        span = 0xF00
        self.assertListEqual(
            idlib._window_offsets(span + 0x100, 0x100, 0x1000000, 1),
            list(range(span + 1)))

    def test_utf7_mark_offset_skips_the_dash_that_closes_it(self):
        text = 'hello world, said the analyst, and wrote it down.'
        data = F'{chr(0xFEFF)}{text}'.encode('utf7')
        enc = idlib.guess_text_encoding(data)
        assert enc is not None
        self.assertEqual(enc.codec, 'utf7')
        self.assertEqual(text, codecs.decode(data[enc.bom:], enc.codec))

    def test_damage_over_the_budget_at_the_end_of_the_document(self):
        damaged = b'A' * 97000 + b'\x00' * 3000
        self.assertIsNone(idlib.guess_text_encoding(damaged))

    def test_utf7_document_whose_first_window_ends_inside_a_shifted_run(self):
        text = 'Hello plain text here. ' + '你好' * 3000 + ' more plain text.'
        data = F'{chr(0xFEFF)}{text}'.encode('utf7')
        enc = idlib.guess_text_encoding(data)
        assert enc is not None
        self.assertEqual(enc.codec, 'utf7')
        self.assertEqual(F'{chr(0xFEFF)}{text}', codecs.decode(data, 'utf7'))

    def test_utf7_document_with_a_shifted_run_under_a_middle_window(self):
        text = 'plain ascii notes. ' * 6000 + '你好' * 6000 + 'plain ascii notes again. ' * 6000
        data = F'{chr(0xFEFF)}{text}'.encode('utf7')
        enc = idlib.guess_text_encoding(data)
        assert enc is not None
        self.assertEqual(enc.codec, 'utf7')
        self.assertEqual(text, codecs.decode(data[enc.bom:], enc.codec))

    def test_utf7_document_with_a_binary_tail(self):
        data = b'+/v8-' + b'analysis of the sample follows. ' * 200 + bytes(range(0x100)) * 64
        self.assertIsNone(idlib.guess_text_encoding(data))

    def test_window_size_that_is_not_a_multiple_of_the_character_size(self):
        utf16 = B'\xFF\xFE' + ('word ' * 2000).encode('utf-16le')
        utf32 = B'\xFF\xFE\x00\x00' + ('word ' * 2000).encode('utf-32le')
        for data, window_size, codec in (
            (utf16, 4096, 'utf-16le'),
            (utf16, 4097, 'utf-16le'),
            (utf16, 4098, 'utf-16le'),
            (utf16, 4100, 'utf-16le'),
            (utf32, 4097, 'utf-32le'),
            (utf32, 4098, 'utf-32le'),
            (utf32, 4100, 'utf-32le'),
        ):
            with self.subTest(codec=codec, window_size=window_size):
                enc = idlib.guess_text_encoding(data, window_size=window_size)
                assert enc is not None
                self.assertEqual(enc.codec, codec)

    def test_utf32_document_with_invalid_values_at_the_starts_of_its_windows(self):
        data = bytearray(B'\xFF\xFE\x00\x00' + ('a' * 48000).encode('utf-32le'))
        invalid = (0x110000).to_bytes(4, 'little')
        for offset in idlib._window_offsets(len(data), 0x1000, 10, 4)[1:]:
            data[offset:offset + 4] = invalid
        self.assertIsNone(idlib.guess_text_encoding(bytes(data)))

    def test_dropping_format_characters_does_not_admit_a_byte_dense_blob_as_text(self):
        """
        A legacy codec maps almost every byte to a letter, so the evidence that a byte dense blob
        is not text is the handful of control and format characters a few of its bytes decode to.
        Dropping the format characters, so that a document holding them reads back as itself, must
        not cost that evidence: an authentic document reads as text, and the same document with
        every byte complemented is a control sparse blob no reader may take for a single byte
        encoding merely because a legacy codec spells its bytes out as letters.
        """
        document = (
            'The analyst opened the captured sample in a sandbox, read the strings it carried, '
            'and wrote a short note about the network addresses it would have contacted at run time.'
        ).encode('ascii')
        assert len(document) % 2 == 1  # route the complement through the per-codec scoring loop
        plain = idlib.guess_text_encoding(document)
        assert plain is not None
        self.assertEqual(plain.codec, 'utf8')
        self.assertIsNone(idlib.guess_text_encoding(bytes(b ^ 0xFF for b in document)))

    @unittest.expectedFailure
    def test_utf16_without_a_mark_is_found_by_the_text_it_decodes_to(self):
        """
        Without a byte order mark, UTF-16 is looked for in the bytes rather than in the text they
        decode to: the high byte of every unit must fall outside printable ASCII, the range 0x20
        to 0x7E that holds space, the digits and the punctuation as well as the letters. That is
        true of Latin script, whose high byte is zero, and false of any character from U+2000 up,
        whose high byte lands inside that range. A document holding typographic quotation marks or
        one CJK word is therefore not recognized at all, and every reader of the guess then works
        on the bytes as though they were a single byte encoding.
        """
        texts = {
            'typographic punctuation': (
                F'var greeting = {chr(0x201C)}hello there{chr(0x201D)}, said the '
                F'{chr(0x2018)}man{chr(0x2019)} standing under the awning {chr(0x2014)} and left.'
            ),
            'a CJK string literal': (
                F'var s = "{chr(0x4F60) * 6}"; console.log(s + " and some plain ASCII besides");'
            ),
        }
        for name, text in texts.items():
            with self.subTest(name):
                data = text.encode('utf-16le')
                enc = idlib.guess_text_encoding(data)
                assert enc is not None
                self.assertEqual(text, codecs.decode(data, enc.codec))

    def test_binary_data_is_not_text(self):
        self.assertIsNone(idlib.guess_text_encoding(bytes(range(0x100)) * 8))

    def test_structured_data_html_tag(self):
        data = b'<html><head><title>Test</title></head><body>Hello</body></html>'
        result = idlib.get_structured_data_type(data)
        self.assertEqual(result, idlib.Fmt.HTM)

    def test_structured_data_html_doctype(self):
        data = b'<!DOCTYPE html>\n<html><body>Test</body></html>'
        result = idlib.get_structured_data_type(data)
        self.assertEqual(result, idlib.Fmt.HTM)

    def test_structured_data_html_body_tag(self):
        data = b'<body>Some content here with enough text to be identified</body>'
        result = idlib.get_structured_data_type(data)
        self.assertEqual(result, idlib.Fmt.HTM)

    def test_structured_data_registry_text(self):
        data = b'Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Test]\r\n'
        result = idlib.get_structured_data_type(data)
        self.assertEqual(result, idlib.Fmt.REG_TEXT)

    def test_structured_data_registry_hive(self):
        data = b'regf' + b'\x00' * 60
        result = idlib.get_structured_data_type(data)
        self.assertEqual(result, idlib.Fmt.REG_HIVE)
