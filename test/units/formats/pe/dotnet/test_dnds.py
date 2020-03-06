#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import base64
import zlib

from .... import TestUnitBase


class TestDotNetDeserializer(TestUnitBase):

    def test_real_world_01(self):
        unit = self.load(encoder='hex')
        data = json.loads(unit(zlib.decompress(base64.b85decode(
            'c-muNWME+U4+J0@1bCQ$L||}baY<^fo=Z_;d1hX^jzU;!QE_H|o~@Cd0SM|SIG5&>loqAh=B1XF6eZ^9C<K%y<zyy%r&fmKXQ$@b'
            'CK(u~nWmYi85*XT8YCJgvVzPPMKxB>DYGOuu>d5);*waB$j$_^o0Azx@Pi0$AeX5#z|WnRONtA~=k@e(2?EjrAk4uAB;`N<PXy^s'
            'cl32+VA$Bt{U?zX$X7`A2=ZlMs8VBKXlP+z_yrVdc)`F>YQVtoDuIE)Y6b&?c)^@qfi?^bjMF?_978PpmtMZB?OZ5x{NsE1gRL>0'
            'DwCE^s-FIjanf>?^D1rj2iCR<IGsI_T)fS=M|6^KwSc(x<ZDOF(heKE$=fGyCd)6rJZ8_Yb@%Ju-~T!HmWEXCKW@=4Gq@wU)9Sv9'
            'X)5M#xNu7SreWkxr+D6{E6utiez)9Q`mtRpOm%}eZ`7%`MvhN?HIjC6?3pq3K%7a2=JI0ZRki&2?0WS#mau$V<mi1<HannLvS#YJ'
            'n)9!V`c}I?{P4$b_v0P1#&cu%rTS~KHtc-&{NjS8Ysv((?rztwmgy*X!}oHV>_5-FXRQ??_P+9$`<m5LA~wgld79B}o`CW?;d{3G'
            'I5>Zwdmz((*s43d!<_$Qy3G4X2cUcu%L@CicDbKJw>F)%KIPvs(Y~fe-Lly`<3do?WIn04>wfd@d&Xj)JLkE1MECk+uX7E2yis0j'
            '<Ckq|o0?Xq&ph8w*I4xPYvcP4{cO5Rujq<x-gj^2;z+wA63YK(6e)qcb29W+-5(vpnO+Omw+WqI<|X8%?rtzy%VbH*o}ZufSH(=Z'
            '$GG}%TSn6%(Qlw6>FMg{vd$@?i5mc8JO-@'
        ))))
        self.assertEqual(len(data), 3)
        self.assertEqual(
            data[1]['Data']['LibraryName'],
            'System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a'
        )
        self.assertEqual(
            data[2]['Data']['ClassInfo']['ClassName'],
            'System.Drawing.Bitmap'
        )
        self.assertEqual(
            bytes.fromhex(data[2]['Data']['Members']['Data'])[:6],
            B'\x89PNG\r\n'
        )

    def test_real_world_02(self):
        unit = self.load()
        data = json.loads(unit(zlib.decompress(base64.b85decode(
            'c-pN~-EP`Q6gEvrK)b76wAx**S}96;(TjjE7#k$Ak{KKbxG@3a2&a+Pj3>eNF#a18!>UprU>~B-*_&NYlbcPl7c2EhKF8y4zVmOc'
            'z;WE)xiHJ*#}~O$W}#zKG)3{+h3NReKyl&*<fKvMTh)5Cc6<O*Ow$;h5R}r`#>WTabb(zsLK{8s5ji0##=Fet=fZT8P_(Lo0AmDc'
            '?k1`B5kavFtE!vOKlrPwe}$`l2%Hq>QNK$P*Vj9F7JHVP=a3Yw#NDEjwZ3<?%W*$H7y9a&HK9~0Gb$_M%U=a<pB=uPcG>g#IU=K#'
            '8T`{uk(p;N?dQO&&ROqw-?F+k^j&g$>LTp?(&?te!RYb#x19+}s2x)fq=Y_3-*iB*TG_-=UGjwbYiE)Yjld_sZ;TaUM3M6}oR-os'
            'r79w~bom&~i)Sq;KdS6L^KV@%6iUoC9`>nR%+*Uag1uaQeR25i&+hEJrz*X($)}H=y|$|;Lx%^IAdBo=;+ZYlX3JHUp|{>R8(A|3'
            '{B%MxVas1?5cK%2uUllOMO(Sv?+s(~(({!u9E``oN>hSi=wom04O1u7jqJiY8;Hg*nF+IzwbYV1CKO197*P$+1whBQ2+Rn-@Zzju'
            '0%fHrLD!txY6LU55L=gSI*_A_(e|`EH^J@NowXB7ahjFhB8vuXaYHbydr0B+@p?Gyn^pz(hv!S)^Nh*VQ{vN6+HZ+s1h$nJ${#!p'
            'EChi7b88U&F53icxpJ=R7qU4vYAwF&iOo1RK`MiWD>aoY7)<b3wFkV{3kLW?U$zvD4;sF2jOw}&Eomi@<gg)$?MO*tw6sD+b?4{K'
            'O1+Vr$Q9{XC>aLO`=)Il9dTSY|IdrXr+axny`BHq%U6~Y+z}ku4syT}K|e`XWeYyMafL#e&0Bhy_a0mC_czFCN|Id@#D*mBwVV2)'
            'C7@c~(ORP|I#6_OpwMm$aIf@#ZvXHPLWyjR'
        ))))
        self.assertEqual([r['Type'] for r in data], [
            'SerializedStreamHeader',
            'BinaryLibrary',
            'SystemClassWithMembersAndTypes',
            'MemberReference',
            'ObjectNullMultiple256',
            'ClassWithMembersAndTypes'
        ])

        data = data[~0]['Data']['Members']

        self.assertEqual(
            data['<Bundle>k__BackingField']['Members']['_downloadedChecksum'],
            'fed577a04637410f2b84e0b680396dc6dfc4994c'
        )
        self.assertEqual(
            data['<CommandLine>k__BackingField'],
            R'"${BUNDLEDIR}\java.exe" -oxqaaaarUa6aZ8iEhpjvydyAOVH1SRnx4z1WOcCD1BkT_nJOqzA2GDJrZWjkEPcHPPomOEoJpkljY'
            R'jJudpTVxQ_IH6VJsU4UK_hOsYlntC7V6qtOlY4CtPgeCUn1bjrx-ZCEmEEoBZSaLqcxcb68WiuHAqQKzFBYZCgviU9s_Ed5-DbxqH9'
            R'6ynlc2jeE1TPvJJGZ_-cGJNh1jjVRSjErFKuG866qCz-rcAMjOCb44nCZzVnTwxyo9A-NLTQAZPV081Bj65rrZCuAC3i75ExoHRlPL'
            R'aH1jDoHlQTh8EO1o3kkVK2T4qht-s7Ap3769qEsreh_pELiYNdmLfA5ei6tIp7VVCTGZaa##'
        )
