import base64
import itertools
import lzma

from refinery.lib import id as idlib

from .. import TestBase


class TestIDLib(TestBase):

    def test_detect_unicode(self):
        data = B'H\0e\0l\0l\0o\0,\0\x20\0W\0r\0l\0d\0!\0\0\0'
        enc = idlib.guess_text_encoding(data)
        self.assertIsNotNone(enc)
        self.assertEqual(enc.step, 2)

    def test_all_pyc_magics(self):
        from refinery.lib.shared import xdis
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
        a = B'Acceptance of the QuoVadis Root CA 3 Certificate'
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
