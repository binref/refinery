import base64
import lzma
import pytest

from .. import TestUnitBase


class TestUDP(TestUnitBase):

    @classmethod
    def _sample(cls) -> bytes:
        return _UDP_SAMPLE_DATA

    @pytest.mark.xdist_group(name='pcap')
    def test_datagram_count_and_endpoints(self):
        pipeline = self.load_pipeline('pcap [| udp ]')
        chunks = list(self._sample() | pipeline)
        endpoints = [(chunk['src'], chunk['dst'], len(chunk)) for chunk in chunks]
        self.assertEqual(endpoints, [
            ('172.20.0.2:64095', '8.8.8.8:53', 49),
            ('172.20.0.2:54338', '8.8.8.8:53', 34),
            ('8.8.8.8:53', '172.20.0.2:64095', 186),
            ('8.8.8.8:53', '172.20.0.2:54338', 129),
        ])

    @pytest.mark.xdist_group(name='pcap')
    def test_query_datagram_contains_hostname(self):
        pipeline = self.load_pipeline('pcap [| udp ]')
        chunks = list(self._sample() | pipeline)
        self.assertIn(B'\x09microsoft\x03com', bytes(chunks[0]))


_UDP_SAMPLE_DATA = lzma.decompress(base64.b85decode(
    '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;3mHjs9gXB1K)!wy`5c`Vk@mWZIJ25So&G>*SJHsO?L5>awEX~8-5$`=;BsoDuRHu+PMih'
    '1qZQB=+Yz^Jz0Y4Cta+Ll?N*<n0aLSPNnfWcS|D?0<wttbLDBNU|c!Fq6rKgM}yG_%fr7z`@33)wHry=OHrWl+jUJK4^U$sBIb~4'
    '{Y{9w?M`xE<!N}n*RFCI0Mn<&x#cEhh=094!X3hc?%lR~?k~g}?4n==5H4v+=ujs#>eB3zl=!T%aVc2OP@ueLhMD>KQZ>I{U;jBY'
    'jXQqo8a&vjl9OVmI6{yftV(B)3|pdxuUvpvY`_~&0%~xKp%}PoIJ#~EacwzedowIDE(B)yjjO992KOo(zjfwvGUM4xO!0i57bbcQ'
    'l$njjUF0>c>}QbiGc(g`_=ShnEh$iRR*6^;o;^*>C0{?}i@w!ZhWHgw!NCkmULA5_UPigvxYj}~@W-8oi>~s9luA-AyTxVU!xP_='
    '_}7*M8R$sTimyfHrxs9L;EBM}S}t?<LrjtU;grPEvMwe<DZn%6D^+=v^ZeEqc}*sH1<J|UX=Z_ZRUBE?-k;FLs#nXtdbbG0Qi3l('
    '6RW(_p3(27UhoC1NtG@YKfe|oNK~Vtb8%&znxpoAlg5TK_~Ijz2Rsg7fUB^he^B{wOH7^`x791BuRh(*7GV5CVr|PGO_)*-Vr}WD'
    'Gjm{woh#Q0Ih*C{alY9qq9L+7YG-JnF5u;1YY!UzJ|(s#a#a#v{DSEF6}a-faa;Q*zo-dSSX9tBkm28e8(U`Bk28Ci7&F?!L)<H3'
    'M47D8*aao7SM;;cVD){>sonhkmIJ2^-Qk{cKS!O3%d)v7Xq$CDP@ZUmWAFuL+Eq0QFC!inx+3wlzIs{b)dZ_lUd%?S+$d)!1l~G-'
    '0)=Wnb65=DRDN?=@;&EEmF$uATGnvM0bBo;eF}ZyulC3tNh_@!fGQPToq*T8^1(1l$>t{`uA>CTg5ak!uIyr#f~nI4csV#`k36nw'
    'P9~kT4){IgYH_rhzK`Y)GvNU$>MOJI^X#qIqknh|QQx&OoX7Nz<zSpCGXt4rEi_99s}fScJ%6_q@rr%WXogapJHKvW5}?zsLJQcC'
    '0Gy(&gH`w}Q@Ka7hbG|>jE`f#CHERK6F>_3#bOkFl^0vMt}UfS)i@2AIbWI3i(?lXD~04E&sm4b#?`(bLS-R+P2?opbp{N12|za}'
    's7U0OpkB)0>MiH20uskv4YUQYDyq++TN243L8oR*tNa0QSUNh;`)hhZ=}VzEZ=7$UR8Iz)`vwI{s11(kXelLx5^e#(a4>#XY+YTy'
    '0%DJby^B%wO^yC2+7`B^P0GCS_JWaVsyadA;(F$;4xP`M)7FhMl^K<5xwh6G$(s}UQaTCuR6W<RY)wj>cH}ykb6b8uBr)C3XZy^g'
    '4<h2yIg`WNUsgKg{^98|>;GsX^)2qvvm91S?H@q%qK+E}+4Mr?vvVW+ge%GsJ_fp2b^(i55sM|2gQIk0LJ2M=X8I?>pTizzuAU3U'
    'ya}YE9@&Pa*1t7OMU3WKf_RC$(UYAHtvf^{^Gnz-dK7YtVW0db9@0sbb^z05b&O}bzZYg`O|3#wux^seiSBCHMuHJ8dj!He+RyZh'
    'sXU?D{~VIF_C^1$k~9&93T2zB7Wz6==5A!-SnhQn@7mGS1nd)diLl%ZkO7Y2=KYi91Yvr)EwBLC`4Y$6Jcd^SSGWo;4|sE{(?i1N'
    't~<8uR72$;kWZC|>9@Le(jU)C1rTfQLic?mz`;#MMH-hw;JHRbp^6UH%6xsB_*)e*%IZWG;nce=;Ko?=%_v!N2C&j|<gj-!NOYrT'
    'A{u_KG!eD4RZ_3V>^?Jw(Szjfi6^Vad18Fh79t$K_d@3{CjYSiAWEJSs#3UZ{PMwU{;sDLkZr~1vTDnTK#f(kmy)zKe!tfT_Vcqh'
    '5N@Hyu;t5}q-F{uq|K2p(bf2NgS8pPz8&e+_RDBYNQWlehWRGh(%TK-cbo0wmJEeOYPbY){`+_dg0!M)KDiNFfFH)Kyyv`B!|YxP'
    'hOSNdYBOuo$iP1~9U-!ROjj#`Qa55IaQH&1;)ZsSB|P*|0|=ol0^y>ssgx0;80G@Zl4m;6-0=Xu=t^^gwSJxKud*;3H@DLnGzOf1'
    'tnFr$VSP|SvsWJTtmg&q!VICJp)Hs5NcC4NCA3Vk)&YyobsK80C1L1M-SLjeoB-AZwr`R5A1sMzuyxC4p1v_hEAn&@iv3-G&xhVs'
    '<(JbCj_p?92Ihs3#n~<wR!faypV?}}5YO7UXmcvU>~}c8N$PJY$L_cbEEAnRfdfhm+50FgO53+dUhd-lVB7QHO7|Q*-ufzaR_=98'
    'WbL>2hbizV$afp<@OMj^X7ktiMZ!v<%dZJ!(2Iw3;KTcBODVukSC(?0@mLcfmHX|uG4=QAvZWJ8S<fh!)?+lb!xKqJl_de=NpAVO'
    'q{;lu0Lrqy)rvRjcKrE$7g_04Ac%v=H+Q>EH}c~~e-~I*ryA^>_qDZzh8TT!*r;E=n9bUU0!;Zzu3(UOR+!s)9wGzA(gsJBn{sE3'
    ';1yh8V`)|**V!*2yTvJcs*Qfjw(tE_Om1$Wg(yIp#K=?pqzr^3A>AIhUp`Zckj(}K?r*m%)W)BU_96BhQQPwsqiMI~H`ZqquGnmh'
    'l@qowr2I4|hZ9y&>&qcM3an_I?^aO`dXP!_3nBiy-JgV;RW0GUoY8%AF%A>AqE|R)r=hz}7K^464T%hi0`NOLPzIyf$~4%PooVBY'
    'e@P37n}ywy-Fk5wkToYoB_iLlUcSUA`uT&dx9`<i{$XBuj-xjM9+(#v<X=!w@B5v!%;7*PB>o?+p-ZUATxUPT1>6;6M?j4G8+~yV'
    'u_jlY!IcphCdP8R4;<Xki^dF<6ki%@2Xp!Pe`pEBtDV3#n9^TH2+=D{>9T5ejPr|91DLV**B~PHd$!?KB#>3}0CPYJ=#qN+(D0zj'
    'x{5a!2>#cU-Lv25Cp=N45Jk5!h;f}1^$02{I|Mq5$gL_Nq5+Y>(V&5CiG#gwOHgLRcZhE|O%c2JZfIE4h%xGNAs6)~OKvnAfokEW'
    '_@32SMJ{~g$US?)ySVJHQfybk5QvGKlqT6o3loFB-R)evjxdshr;cZ+g$X`??Q4efHr}L!CUx=`8yVgJ8vu)UrG(t&Qqz;yA;X3R'
    '-;#}=OgQpniD{;!K-yv&6$D0(V{_K@cqB2?R4qlVJ(gyJK8nLxs*oE_$3=`F^T|Zs@UPo%=oZ;zr|z8b@~uOLv&9CY%didN#z;CY'
    'b7X~MDj&lJuz}05%yNU$q{s`0a`6V)pbLaW-3<J3Fu50W#!KHH^e7pzE?VajenU|HNFZ)p2~lE=;LSx%7?In{Zu)wd6{aY3&<)bo'
    ')$0hK4?v22t|zb8HVPX{n)vB?K19b|6tbvG+cRIPL3N+<%c{94Y$ae)42l0y#u6X|v-Qq(;T%YlrBx;wkA;U20C!-|;1NL&h@Yp!'
    '^1B&*p$vB9OMRmLfJYZ1ve(u&=2&c1Mni9KRLNY@2m8UyAl@jAOE4YqxkO}qt}o@J<N6u_bgr#Zzxr-w^~EQBW_?bCRcDKzPrUJM'
    '+NRK(*xanEsya68+-(nKcRL@r5!seikowjrV=INpmX#7eNEV=*GB#(DB1r*L22V;E%UJJv*YPY>Ts5S+d!<!o%_f~nV0s_--1u{+'
    's7j;(OG#dmr5*R8xE@#kq@$^gWXe6BGx1W3J1O)!#H=g-Uj0(&2iL^M+QI$G$#LCfU7d3_1y=nae%URh276Y~>I-k1toGFLI1sEp'
    'o}%B-k9hIii%J-@g%<p|ecnrEqZ@8XVx7Ye5T|J{L?*U_kYi6FdYmB%;+HgVbV(grgWm~Bv2f2)B=m$Ko<3u*GZFWR^~>1c9=sNO'
    'Awk?#;R^p_JPoA3>SecB0Oi^8afbTn(%E22m|}^zaWJ^xUnYU)^NW&aQ$q*LVA`to92q_?W^a6S<-#hhe+MQ}gv_)%`W`Y58-Fn9'
    'x|1Qwa|ab=MgpWnUEu<<2jHvEgKIZu*Io&Bq672M0})A-S<NOVK{hfbd=7zq_<Slp!yN`s%8(6Uu@Aa@&Lsn68T=QpFKr7P)$Z+Q'
    'Zb>@wrS5xGYh%`vzi#B>o5rmS(%!K>JPR`Wvz0J&!<Km>CRSeELybV);uXyBI-7`8{PZ5~EIp4{nT>L&Us*O~QQpF<=d+cdZ(|91'
    'JMm$SME=RCf|^f(ZuTGQYd^cF9uZr=&a~bW0A+D>HVpG}hHpT6igtzy=l~Q_DN#Ec5}qa4b#^CosGL5!(R`F=oTyzNrYqZYyq`%+'
    'FSXEkL>S0HqzFuvlwFK#sqCPIq~jjYZJN4#_O}wfP;|vYz^3my!}iGZB>|g*PB?bpEIWb*4@~jfA!^4*@aelIW6*g}&fnt}Kx_hS'
    '{&|D%!}9WSF+MJ!Y4}WSsNj85^h!!Mzrt{T@7`sOEUO%Ws{!=N@Xv_o;`rL4^<tNO-~)Be7Fo=k;H+>PG<_aGIXg$1O!2(s`MF8p'
    '%r2#4qMIS*Isv94x&XKK`?#eD=e)hnp0$b}DV_LS;s+06s-3q6tAT|hNHS~c++PLcUjBMGn5J9IiwMi6(_Rr;n+1<tJZZy5T<Q6e'
    'o|^)`P(^%_7WFCt6;BeLf8@UfQKP@Mc;%I@=`bd%PqPC_1#gjdqcNnau2L=-_4k~Uj6;m6m#~rJugz%h4)VZFTN|LDmTYjC%Nvod'
    'o^>TDb6|6WRd4-_&j*-^eBs3@_+?GE?5Ij6y)Y%yg_yyula+R#C*-_{-R(sx;f#?bp$V@E<R-0>3(o)#t{y3A$qmS}Vta15bYi=0'
    '$p$JOX1+A$3N*^bx;#$1tKtp$fP5wZjr!@@FC#4%GDqec^n;FLFS0&HoM@!TGOfF2mt=eL4SQ06%(`zF)XXaTxhw%5u8Memks`=d'
    '$2k&nOw})gNc?YXqos3ObFwx7M6s`Hhco1H^H4h+W>WqmZJm+E)F*+lY9c-N8Rb$r%IyGaAybUqxB0mrH85OAxS9rH*c|x~nlu6A'
    'NNK_2+lYRu&fV%l>~A&?GKP&*DRO9wCMPT#FLop?qxAf~B^A}c)Xz1<+~mw&ffx~R(*iW@Rz;ftPTf4rTBYi0Wawz~UH-tZ;{{=D'
    ');m>PJ4Z#9iS4vXa0Wx-lV1N`0dOgiCcR_JlB8D1I<y;6O{Inwr*+g&w1X^mA7@f8Ts%5q6(C>OGX68*pgN)!IyhO{lhDEmW1`2>'
    'PBb*HcIFZO)$4=f>&r4zk#?$YFVLdvOvpSb^gTIF+ct2!Se<|m)%bOnH*2rrO)`*oIk?Oq0{Kfq%!hCxf=0xg{Vqi0V+)PZAFJaw'
    'h2Up0ZwZ9@COCNl@3Vm$vw+B|7P^22eB}GDPcEk)MDPRBgp*z6)6%|_90UsoXr23ZmhV$|$MAxG9a1e!@k9G+Vn#kfW!#-9EUpg4'
    'a_N#7q&<;KMK}OPrDclAn*$M?K_M=>0B-;`<|LA{?FL<xsgI*7p`IPGk5?jY#r|J9!@ppDcqQ~}tUj8UocNJ?&E2T61Wz+1bRxC>'
    '%pZ+7{R*+CbCE{A{GI1(Hn-u>HwrjD)RRVWg%J_1tz_qbO@kzDot}kXJ{z0A<iNF3@1!2iiU(S?%6yKRV^#V{&0?BT0P@P|TMbo}'
    'V~ZQvFNTQN-eqDU7B3qOsd(LPyb+2WPf9V!$xOt%1?E3v?cPvQV%_%))>1Bg?XR=aa0Nb%hM&t(qkFQlQsf%L&j3)ON6y8FX^<YD'
    '0G;HR&HXvS<qok@GjzTiPF1FCW4U-B9W)t3y43Oixt$=~FW!W-98*o;F4c(z)%`m5>Z?(vc!|*2%(>2E4_fhiB)H!IVXF}jQsf!G'
    '00G1!z)b)EJ}pAQvBYQl0ssI200dcD'
))
