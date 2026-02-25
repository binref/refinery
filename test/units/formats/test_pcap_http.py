import base64
import lzma
import pytest

from .. import TestUnitBase


class TestPCAP_HTTP(TestUnitBase):

    @pytest.mark.xdist_group(name='pcap')
    def test_pe_extraction_from_pcap(self):
        _url = 'http:''/''/ncdn.nb6dsl.neufbox.neuf''.fr/nb6dsl_Vers%203.3.4_ter/nb6-3.3.4_ter.sha256sum'
        test = self._HTTP_SAMPLE_01 | self.load() | {'url': str}
        self.assertIn(_url, test)
        self.assertEqual(test[_url], '\n'.join((
            '#',
            '# UUID: 27f4b1e0-6628-49cb-b59b-dc2234dc0e5d',
            '#',
            '# NB6 3.3.4 sha256sum',
            '#',
            '3ece945cf370ff987ea184f3ac859d590b0a830d74949e8aa0c71900663d4d6c  NB6-BOOTLOADER-R3.2.4',
            '62797705144e82b7c44963aa8ea13442d12057e7d01f33ed67bfab3f6d4e70d5  NB6-MAIN-R3.3.4',
            '0ea220adfb9dd1c845d9ec0e3d537aab281b5d45ba51b3688c69074225dd8cb4  NB6-CONFIG-R3.3.4.2',
            'f00d0b3b8e6a88efaac18f80967e83c49b3454bbe26764a70a0dbfee3973442d  NB6-RESCUE-R3.1.8',
            'd6f592f35abe6e9914fe1b14560b764ee23c846d6c9b5bdecd3300a2b3afeb25  NB6-ADSL-A2pD035p',
            '',
        )))

    _HTTP_SAMPLE_01 = lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;38-Y8C?KsFww|;i}(qft&`+7X*#5AM+vz|?vIlAcSxgBy$jVU@e=E&xs^mrjuP=4FB6DW'
        '2iS_i%27GtTqh?Oi0EBZOrb{6sPg7D;$0^o93;&5XNgI^qCh}z3#<Udwt!r1oBKim^AJ)dXHWg>^0#ECtOC4f%+)Y$V5nH>Js)TN'
        'Qj8LmeJ9!h24TKtz$H5_iXD|0k+cqR?~TyjC;tH_YhPYAwW+Tb4{L_GR31}Rk%ydWE=wF^*-Td*b(8NO?^PX5eGj6W6-DsJ99V(q'
        's+q`Fn4{)(3$GAkuDL-V0I0x0@*_&DQX+Ypx9etw5btj2LPax}RT;c&uhKxxnAY?RyzGAaFc=w?LRAEuLY)?QS+|x|K^a~DlP4}B'
        'PgdEAU-m(S;AeIqWSDNMNkqbg|E&f3N|DT-x#T#GM-&bDa6oy4Zb-a+NHDC3M-P65$kFy-mLDpCgx1hh-D^OHfZhc{uq0=JFqeV0'
        'bdCTuw9QO#sEWKMNPK+w#pb%IJRNgsvm{I&HNN<Ic%nn_^eHGCpJ`<{$z_uj37|a+TmXdV?yrk0HWEwi{-Fp9M-X2X+JuagkE?*i'
        'g5IrkrG|(gJOf<Shmv7m{I$?8Gvq`($}r;6$KQIWWiF~7Qt>_RLLnb_JGjl|r>cFjB7OfztgE<jk&K@q;4I-f<41?Rw@0-3_cP|X'
        'sx6qAAF9m)l^fXknjARkkq$)x;2q@_06z)L)DK+vu)eD#=B1kS!C9zf3ebN%9k+%hbsmV&D~}_{h^L-VW@#Ve>G`eTh-5}1mvWq<'
        'r`@`*Up3IVXJ|RXmNC5tA+^IzlIM8J4+m;oL6eIF9OCoQ+&coSq5uy(-7slgJxx|;KRMe#=djsCei#P;=-$MsH$hCpNohy`C>b5*'
        'UQc}d-m$hy!lD)Ef0MfrPwt&`G3U`vg1-h}bqWU{S7`oW;<z$m7Gl3YrUX7EGvX(2XRr4NrBx&Sl`sQTNPpr_yCFi>jigmA_LQdO'
        'Xup2t3^aGTUY2%o_Ll?=9JKP9J!fuZ!}hRA%I%Kk__A&qowKIZ*P%oa8!E#+mxCTln(PdVGz)kPi8f~vA1~9nNC}vIYa)({qk4h~'
        'I1NM;qW^m~#V$Xro076C^BMCTJP-hI3aJt+RM6AeCoMzc5>j}CybJK9%8g9LJ?SH=2bW>&f~zekPMz%(K7^!PYm+K>w-&NDgBb+R'
        'Zou1S9EpwQ5D3~AHQy>+YiJ5#ei<<x&j`aO?(0OJlVL;N+xT_xrQt*7?o|hB&_l~DD4@%*^SY&M4)Cbo&3oW~k(g7VMOCyhe9)Gm'
        'cHlq9Xo%45`imRz<xnrJ?)&G_140sh{1GKu-M4FAqVk-`G}xWR>6*<^s63d@GdT5j+%~N%kj<`8R%OJ9B*~M$&K>rmUfJ+l06o5P'
        '=$+#(Uj#4D$xA$n*VS6`RV#ZJEm>?R5%`DTxAqf7AUdg);~=&2__Hny;;9|j?^Ltwf18>nU7Hz51PevPTkx83<V}P6{=vzOFJ$Qt'
        'u#IGLVvYE4ns=BQ%dK^3*Fp8%jH<_)LfSB>8!VzfWmPexsmzU?YZRUSlI8Ou-hN`;W&+pJcCq>)HA!jc?L5Ty*gz2!^Ctkc>-KX>'
        'zIuTzTsRbV;$)#V87)?th7&!ckyx_5H*FygFBsYnAXcCz!lMKS`H5;gwEml$I&w-xuo4ATwpg}LVAq;|C^m6?d7&+7)<TBlrP{Z2'
        '4+@Wz;6ydpIRANDLsju8piEB1=!22-tSwLCNn_1uRThE|tF`bo1d3|3GK-eaBv6yH3#-DZB=*w4^UDxrC>_RpRq}P5eWM&hHF2cL'
        'VI*u2nfGwdqlw{)7fw51CP;17Glq#SUiX|qVBZRHUKOO|qy=WaMRcVSCHx3&!M=DCC;n8CH%#YUy(^1<pg0RM7eAEoF&lMUecw6z'
        'C&e3=ce!K6HsBRaR@Et#br)Dc5|LTb`2Mneydmdh=v|emEQ*-hqO1k@vS<0$32w&H@CK3{fPA*-+P+MiZC>|SNwtU%7|1=b`{5ip'
        'Sq5<l+019FFE5C(a$#)GYL8`Il4=#LV5DJ;#L6*eKQs|MpXD`&pXU@y0LXoJZOu|56ca^JZ}dBEF|Z#;bDa1n!!|H=^0b^c{s#c4'
        'mErknPswduojSLkmc-4UdQJs7Kzj3m9-HYO4L=Ys2q(ZZz`7q$zO}V`?cI8Nf2*c+8^f*9kWl9zM-R84SNL9|M(vvzhxW1%@+jBP'
        'Eu+$!7~K$@4`x=7@p~l&om;w=cN`1IDyqIi7xuAWABDG7+!W5tF2HC1G4A>RT3-&!O<odth1pncCA&O|CW`<XQ;_J#FGTEQk0QVV'
        'ml_V(dy|v&3iz-E544!)Z03r0-40S1B{)V)IZH*j_AM0}Lo@}-^q;p;_q4?(P5*u#u1sLSeWh<(L^vzzN%oZ>h^(&E!&F3M-LrGM'
        'ab6Hi`4BAJ=Lf(m+2i*|s?E)Aq}1)N#Hw9E>-!5pMq3FH)-3>t4eDLlAbi#>a8&sQ3eqg^WN-V5uPWS;c1&Wv&%Dv%BdG)wv_7kC'
        'iZ{`TM_`{JW8cBTC3H)H)!Z>Uod;}*E@C03>_-YJ@AW@0RelSz9Lv@`K~J%7Y%g!vKK^hSaw|vqY%aID{tA}@`ASxB%#iUnK(+Z0'
        'xQZw@ZiExk@A?)IO{`Cf5OX*KOU8oFAp!UuY?PYtpqRSo2ovCzMqJTpmbKrG{Y<o}%C^u{$0p5R-4<<<$?ej)N8Q)f%2Tz5j|U@W'
        'GA`uh^Xv?BDWPa|pCt~X9iiN*m~z&%jExq0Nil}(HRfS&Y-wxP-^LzF$J8qIl|s?ovuyITm*!e~hdMgekqh38`&1`QW9|jZk7O@v'
        '>c%Jr<o<fyznvLR?z{+1cu}!9Nq|{#S<1^Bh_zwFv^H|vh*T10BF{~Z2^P;zPJt<e%kCs`1_BW)-2gOV#5#9o!7~}kk|ETSqv|NS'
        'wsS5$vA{PDS0YOTZ#hYaAL5|3cxFeg7N;|GIxbxkI{a(2+ZTO)49u~KsHwt8+j{S}vAR4BC!t!i`wVO@I72?t(htW2W5r_=NvkBI'
        'J|*T(Wd6;2LZEyekz-haW)y1XM|#s6&DDW;EEm9X26qM@THR$PPJOtXAIGJteyqWonlEG<97<%t?WjvrC7Je@<?WArDR>j5rgHf9'
        's^(nGqWE-CZedg*=Z)nW^o`NADc=ned2nZatBa+BTH`VId;3Gv^!RbZgD+IQ>v;-K_BdgbtB;CS!A?%K8WG6N^@!swDHLRoD`;s>'
        '<pG|6jwgKzk(lMKW}xu)5-fuQ<R`=ccN5^C4)?9rpg7>0*viVcV4tOr#kc8tZ0W+!@}AyeEs(%|YK_s5_07nX%B|7tw78>Q9Wqjo'
        '(DkmAB>}sKhS#9e(VkUgU)MhWsc2afMOe}WV-$d`i?9R-AEih2F#g%G%L3K=yXFN3N_qM}SAeMIwu*NQxbN*UL_im}j)h7nsVOnD'
        'S#2Pu#-3sMoMm?nt(dbV^dRg5LH(c78hHRa6sYS43+ZR?&pv7CMaeV$h~Vql_<)vhD0{oUq?9;HlkQad@MbpBkqkC|qD=kveF4}N'
        'y_f=+^x#CSt3(n9Rb};YC5kCeYKYJ;<Ve?C+T!2+Zea4c+%C*+(D8WfX|`5Ad41ZC%gw@{0rj7vDz0#g5ZGi#9#(1o2GTxOPbP^='
        'KK{@hw4@pE%-~|k`kY!SXBFM{g<92=8xfn)<H-Ow;T1rhNzZXsOb>5%NKiE&kGL|i``L?y?&cOOF;=OzfMd%dwuM!o3*YY*CpoJA'
        'n>66g7Ey&p@;{U=zY)ZHqs;;Y58&|V*Ta>6AwSW~EtT#BWn<;*G#fwtM5|fr3T#VqN#M6r?G=n!-45x!iui!-dld0gV)MPb;KJsJ'
        'R-l@~6)aY)GCa{cn**ty;B8V{SY%3zJEz~fE!HgW{|6Qh<N%mjDw?d@mpiNs@x(|VXcPkNcQjc!3kO%=CvTRii>5sVHrIXU9&k{C'
        'om~yOTs|fM00000i<!6cK?dTa00Ffa=|lhk_Ms*PvBYQl0ssI200dcD'
    ))