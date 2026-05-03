from __future__ import annotations

import base64
import lzma

from .. import TestUnitBase

from test.units.formats.archive.test_xtrar import TEST_JTR_RAR3


TEST_PDF_SAMPLES = {
    'r2_rc4_40': lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~x{Uhg|>?lmvuut)#~#y2PZ(!g=)}SXWe=utp-bGcTnbYGd?9uvc3VUrb9da(DolsirHE'
        'Qc|Fx@!^p)!n_q&P8&ik5P>BozgUf<)?F4TGUWLJJu#`fg5D8>2nLoK-oT)qdiXdNHK-eN#e2DoB0T}%wq+R7%p(oG@Jr6;dab6P'
        '-#F=;!(p=}J*OG#;7ywLIv?L%rDvNf1e7egbRyyBJ!!Q+^Y|d(;%Swo?QVtuJG#6AYQN;Ha*MruzCZJp-P=w8+q+t+6J3OI!?1L)'
        'ZR_9^tEwERizwx{t?8yr3f9d}ELC>#{vMZxC?7iQn-9d|Uc(26308DI#xFU$;~I9E%4XSt7tgiuY!_fTIJp`do-PKrxETnbdy??y'
        '+h&pk#qtjUdGS&R*E?d}kX8Uxu9eIoCtuc{)`%8jK@d^xp_E0G@7(ATU2%!3Nf8eP_AQ=usCT9$6~Rl|s?}RY<i!?+WIk@CsVvIV'
        '3k6Y9Anuct?NK9wZ>%dJfS@{}ApigXRXGx}F@H3>00E-|kOcq$0`B&pvBYQl0ssI200dcD'
    )),
    'r3_rc4_128': lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~y5XiCq8^lmvuut)#~%aArbfT}Lw5BdHm4Y5v}TJpB<1jRpd`Y6e1UIV;Oi+v%Wwd?fcl'
        'xP@6Acx}VGB6~fE)eHq7<8|d~PG=?BQ?6G<GX6kHKmkC$f>I9OXSN_B*VwYkiM)80TH2$#wtrN2C)E(4&+Id63}fB~n^Fg15YdOc'
        '+L$fqa=|F>BV!&^rkD4=NoP&E^B1DrbjkxIy;2=lEb6ovyWrXHda#pHuYQ8C6|JTHOjMn4`<KLZu<P^+-NU+q&fEQ6@-amL#agL)'
        'zChN){pE*^G=5sMT4vlGPMaS(1;1VJ00@()QO=6)Q$pBbYZOAxFZIUi{Xk873~YH^3fiG1I<~x>!wayYyEouQ2RCi&ptSCX&blm;'
        '8t#p2uvp|6q34%k>yYY4@1X=Ax$49wy7l~?AVBBa74d`5G-@CgBwO0#FId4A30QOO61O#JCfj@Di*A?Mong#%Fe9T*@~_R4J`L2b'
        'Z`XAe>bpy_XL!E!6Sniel-|wEt*!t700000%~I74zd>%b00E@~lLY_(@uC`JvBYQl0ssI200dcD'
    )),
    'r4_aes_128': lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~#Rex?KPglmvuut)#~)!LmYST}Lw5BdHm4Y5v}TJpB<1jRpd`Y6e1UIV;Oi+v%Wwd?fcl'
        'xP@6Acx}VGB6~fE)eHq7<8|d~PG=?BQ?6G<GX6kHKmkC$f>I9OXSN_B*VwYkiM)80TH2$#wtrN2C)E(4&+Id63}fB~n^C~N0Ut<f'
        'x|QR-x5QP@SbhH*rOrJ2%HVfuf{{y%J=C0D0ODi`eS__?IWsg=65SP;snT~F{>A}8GL_DxBoIr+7i?=Gngw?}i)5LiY*$*YG)u)P'
        '2?3~50jCyo4_sd=*OvLnImoomIh=sN031s6cBP<Z?UjP3!_9Gc*s|@Z?~xqSgK4yAk4)I2a!f}Dc#e^OpxN87)pEem*xdekfs3Bj'
        '!|VmwDFOPY%L7nRlDFxzKN4A@{YbAZEPX(k?NU^)3I0oehsRu$99hXbGF3{JK$L!BNNI$KvQ92v9iJvOAXve9M;3JsHIbVFbrepM'
        '_qkb3zON)IEUZXYS;79|w=5<6LlQFSP2LeRc|>^AuVb}F5H^DFWk2=)v;V6V1_6~LwG5Qb?YN`Ph3&pxid`Vp82{iR00000Z71%Q'
        'Sn(U|00Gtm?*#w=y23@svBYQl0ssI200dcD'
    )),
    'r4_aes_nometa': lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~$B##$5mslmvuut)#~)!LmYST}Lw5BdHm4Y5v}TJpB<1jRpd`Y6e1UIV;Oi+v%Wwd?fcl'
        'xP@6Acx}VGB6~fE)eHq7<8|d~PG=?BQ?6G<GX6kHKmkC$f>I9OXSN_B*VwYkiM)80TH2$#wtrN2C)E(4&+Id63}fB~n^C~N0Ut<f'
        'x|QR-x5QP@SbhH*rOrJ2%HVfuf{{y%J=C0D0ODi`eS__?IWsg=65RJ5rGZXH`nFt2f#%eKvR+Riho-^K;^mH0`(8$)F{X|W*C(Jb'
        'QG;lU7ka<0lqo(Lg&`3=C&;^ne6X7a?;%z$Mb9zVDNh#w)(%_`)<VX<rE>w%%iGaE?qu1$vo4(GB<MkswR>Za?P6x9ao)b4iSUX|'
        'M<AWXUSPmUTJaH^AakUklZ=7z2HhqRWWRO|yC@d$xk#DDultv*UPEs8TiR#GGb0cJeG=3@l<gM^#Am{Xv0L{7BY$u_-4m`Rx83o%'
        'Ry#rOlB1e1^-fK+qq<M9o^m!!!yT(8{->e!dpC)F`>ko9$FVK#_(HLy=!l+ImSc4$#zz9EgLeUp1d2MR7Y*UWdi)zkPS1%l*QbR$'
        ';uypL00000K2$VT>YU^x00H6yh6Vrt(SgPjvBYQl0ssI200dcD'
    )),
    'r5_aes_256': lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~=cFeO&+&lmvuut)#~+YF2W#y+<<GBdHm4Y5v}TJpB<1hnUc^)9jmT`G*Vmy<96za|nJ$'
        '!soYB8l|G()gQ1WZ@HP`d>$W{V`O*V>`Ykg6lHI5+`b}wYESHU(-U?Dz3H?`O6YiUKM<gL&989A(|YI|S<SJYqk*@>Bn_qz)DUGh'
        '<psufGZ_&b#t`GHoLoVb7G(GIdoCBz&nSpq>12`BIsQ=@+Q{k?FcyDuzyoGCqP0Q2Ah{Ff!8MY&hY$Fy7Mxi+LkerK_>w8EU=$w6'
        'FhJO0B4R5r?k|TVl$Nj*w=4$6v=}ha8h9786bVx%ju|+^ZvmKKM)omuod$Kh0sP@oRV*EeSz?i^jjn6jk+_uiBeQRI<N|E8N}SD9'
        ')qNg-`6mubWh_0+v}!sf)E&v=ZXRbA!b;Z6F27b$AZY=<1}!mKT=39y^UClNM=p2U4^nxW<CUf1{@$1D&HMqjDg#C?BZp)fECN=h'
        'HpmHsK_TEtpax|{HLiHy&h;3C7hyjov&UhQe*TAJkkYZ7CI=%rW1{*xFa!Hpyfd9>859zX&V%r1Dr|k_$Aew&!~~@G>F28E`-c1$'
        '*Yoam`xa#K(DvWPabax|ZwZY}5CfKHVR_;tMr7YwaqWAUxiP&Tq}m+`>tW+_I_=3+p_+>1LuXUdHMmA|Kae6We1aDS{{uz$HWO_*'
        'v3}oHachjBgn*uJ^Zbpm9j4mf!0eCs!m+@;G#ZOQ3J8mo+BAj+e!nMBH1Iaj+}5X6mC(<LrJ2ubQP|wtKuV*_%Kexp+Yl=D7UY9>'
        'MKEyOPe&Tj+Vo=~uD>{OEgOKO&rw{6Fvb7?00000OSi%IdEoIq00Ef=sR#f75gV)zvBYQl0ssI200dcD'
    )),
    'r6_aes_256': lzma.decompress(base64.b85decode(
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~=cFeq8_(lmvuut)#~+YF2W#y+<<GBdHm4Y5v}TJpB<1hnUc^)9jmT`G*Vmy<96za|nJ$'
        '!soYB8l|G()gQ1WZ@HP`d>$W{ZqSv!wuI~r@F>CMtt+r}hM@1U9Yz1--hZO{HPnqS=|EgJ5A|7faw$=``B2$S`$~xG$>WSf0L&_z'
        'D-NTRwK}H2``pb`DH$&MI5mo8R*dUJEXi0Rn_wu-Hnb0TY#*y(=0qp9EBAv<5?Nhl^l29W7bw*PgGe2e))luOqf)~Fi_^lt@awh;'
        'a7QtiD#Xn-h)J^<KgS+cVcJMPCaeF!pI&6tLhd=7$*SC|mFvyR`FE2p1CA6a844m~_{4ftUaYJ^qi#2=gznb?$`nmsv2he%HB0X_'
        '2SKubRDf(57bXPMI2`BtZ#)<I{kfp^Tq!Gvs9z&AS^&C^$`*&jTuK^}B;Mf2OY@sXco;hb;~&^NS#4~a2Gd4zKD^t#rMv5KAyax4'
        '3JH4o$AFvG6eQ6Lq-@z5-n+e4wn!C<OrITW)#M~)b}S@6$6YxLuyXhgtt0-67U3dUR1ts8esstxx$21D5to)?dg26{!8hy`v8^lo'
        '89c=k<4!4s!pOYJ>8VBx74{G+lt-+Pi#o+<9<TtPBhw&oh`W8NfH*VNPB~cz@BU+7d5)99Qo*IurCx7EZ?`R2?kU<*Xf9=WUWyP='
        '$%e<$GeiNe5)ZUR9Qp-Z;=J&>t2f&MH0?;svMglIVxRc`n~r8kXFqyU0rcsV$HrLMbkM7C>l4I_bXyc?Oc+-2wI-H9K}B^Byk3TA'
        'BNIn_5AyjkAVmiS%^rG#ewZd-rFEnJHfpZ`00000x54dQuuh?o00Ei>sR#f7ziBv$vBYQl0ssI200dcD'
    )),
}


TEST_7Z_ARCHIVES = {
    'header_encrypted_copy': base64.b85decode(
        'H+sCUCma9-KkyF{umAu600000F8}}l00000aD*<O%J1z(H5lx!7u#H(Lx~H|V#)Zm7AVI<g08KpBA;Ect}lDRas=Asuu$e%GO;Ze'
        'p_3o6nI!$ex~cwG=x7SyNdnEIQ-;?OLjfU9HP{*wvG(Rzu{`HxwUboLga`BW65fN(AkjI5|HO=jK6L?(0Au2wh@EUddnET)yGc;S'
        'c}heeHk3R8y=(wn1P2{#LDk@MKwLYmgTE*k-n?@=XEG4Kl##Gaq}fVtY!^+17X~l^34nkA2MYlJ0VD?T2LTdO57tkykR`cj`HYYr'
        'sJ<o&x(sp(0VgiF`v3p'
    ),
    'file_encrypted_copy': base64.b85decode(
        'H+sCUCma9-G<rbSFaQ7m00000asU7T000007**|<3nd!F?2GH;zcxUxEG80P_*!9808xTqmpbW=eu2F3Zp~5Rw5CO6SS+{yknuiQ'
        '0R#pB0SPbw2MYlJ0wf0U2LTdO58@J1L_T;WoZJVLIia943jqKD01PN700;^JeP1=<000F683O<S01+1ea{y%kV*qjhWdL*lE&y}@'
        'cmQ+&000>T000006bb<V?%zOSG}_z&6$SwSAOHXW000'
    ),
    'file_encrypted_lzma2': base64.b85decode(
        'H+sCUCma9-v`g9BFaQ7m00000asU7T00000O#=amd@*!Q9e3Pgxa<@8>Rt<Wk=oJ8m&!C6JXy5|^*`D{jCJb`_CQj36kE}ao+c^R'
        '0R#pB0SPbw2MYlJ0wf0U2LTdO4+M}!cv1iSeb1~c3}AyC4Iv=`0096DEGPg73ITmzHQ@jN1pyfW01+1ea{y%kV*qjhWdL*lE&y}@'
        'cmQ+&000>T000006bb<V?%zOSG}_z&6$SwSAOHXW000'
    ),
}


class TestMeowRAR(TestUnitBase):
    """
    Regression tests for RAR hash extraction, verified end-to-end with hashcat.
    """

    def _hashes(self, name: str) -> list[str]:
        data = TEST_JTR_RAR3[name]
        unit = self.load()
        return [bytes(chunk).decode() for chunk in data | unit]

    def test_rar3_hp(self):
        hashes = self._hashes('hp0.rar')
        self.assertEqual(hashes, [
            '$RAR3$*0*c9dea41b149b53b4*fcbdb66122d8ebdb32532c22ca7ab9ec',
        ])

    def test_rar3_file_encrypted_produces_no_hash(self):
        self.assertEqual(self._hashes('p0.rar'), [])
        self.assertEqual(self._hashes('pm0.rar'), [])

    def test_rar3_dosrar_produces_no_hash(self):
        self.assertEqual(self._hashes('dosrar.rar'), [])

    def test_rar5_file_encrypted(self):
        hashes = self._hashes('rar5-fp0-password.rar')
        self.assertEqual(hashes, [
            '$rar5$16$6581324c2e7258fe8cd39adacfedd207$15$429dec3132d4abac07d25a9ec6dc7c15$8$d72cf7a47e70987f',
        ])

    def test_rar5_header_encrypted(self):
        hashes = self._hashes('rar5-hp0-password.rar')
        self.assertEqual(hashes, [
            '$rar5$16$37526a0922b4adcc32f8fed5d51bb6c8$15$8955617d9b801def51d734095bb8ecdb$8$9f0b23c98ebb3653',
        ])


class TestMeow7z(TestUnitBase):
    """
    Regression tests for 7z hash extraction, verified end-to-end with hashcat mode 11600.
    """

    def _hash(self, name: str) -> str:
        data = TEST_7Z_ARCHIVES[name]
        unit = self.load()
        return bytes(data | unit | bytearray).decode()

    def test_header_encrypted_copy(self):
        self.assertEqual(self._hash('header_encrypted_copy'), (
            '$7z$0$19$0$$16$d64fb19025b968f98c901ea8be260aba$4223151655$128$114$a1931fb19924fdc1baa9fe57e8680ae04'
            '902cda35386d7114301214e35d81a12b1f6e658b13ce765b59354cc8407f3f512de83ce20d13984ffc48c863e75018e0063e'
            '29e889d6c3f7b24f757bb4950c6794a442036943c01bd6c005c04071d6c41d5e073405c3bad83bf2818debc733b673210bf9'
            '491b04da4d94a6e6c174d85'
        ))

    def test_file_encrypted_copy(self):
        self.assertEqual(self._hash('file_encrypted_copy'), (
            '$7z$0$19$0$$16$e21252443e78259cdc079439a1a0330b$3778371453$48$40$0b251ac4ec8bebe3bf3640af2c26125ff85'
            'a615300518260973ae98e7e81bcf06ecd51e2b4a64565582cb7ff90f13e59'
        ))

    def test_file_encrypted_lzma2(self):
        self.assertEqual(self._hash('file_encrypted_lzma2'), (
            '$7z$2$19$0$$16$0490457851fffc7dcfac2c0c60831c0d$3778371453$48$40$7c31744d1d77dc63b8ec13f9ea5e0b7691d'
            'ad1c997ca341a3c59b507f53fda418c75eb0df6405279145bd18d9e2629d7$40$00'
        ))


class TestMeowPDF(TestUnitBase):
    """
    Regression tests for PDF hash extraction, verified end-to-end with hashcat.
    """

    def _hash(self, name: str) -> str:
        data = TEST_PDF_SAMPLES[name]
        unit = self.load()
        return bytes(data | unit | bytearray).decode()

    def test_r2_rc4_40(self):
        self.assertEqual(self._hash('r2_rc4_40'), (
            '$pdf$1*2*40*-12*1*16*007101116490ea814acd2eead5311cdc*32*e1aa9266a08cc945f56b402e2bdc47c2f5aad0eaaa1'
            '6d2685f575d41d43aa597*32*842e9696ecdf13a829f3b63c5b9614cc6254b7e0385b247bab90a508179c0340'
        ))

    def test_r3_rc4_128(self):
        self.assertEqual(self._hash('r3_rc4_128'), (
            '$pdf$2*3*128*-1028*1*16*007101116490ea814acd2eead5311cdc*32*3f6a80e9deb5f8d858a0b59356efe7180122456a'
            '91bae5134273a6db134c87c4*32*408b37bcf12da873d7f2840f3c1b917a023961ded4c8164d38e46e9655e66775'
        ))

    def test_r4_aes_128(self):
        self.assertEqual(self._hash('r4_aes_128'), (
            '$pdf$4*4*128*-1028*1*16*007101116490ea814acd2eead5311cdc*32*3f6a80e9deb5f8d858a0b59356efe7180122456a'
            '91bae5134273a6db134c87c4*32*408b37bcf12da873d7f2840f3c1b917a023961ded4c8164d38e46e9655e66775'
        ))

    def test_r4_aes_128_no_encrypt_metadata(self):
        self.assertEqual(self._hash('r4_aes_nometa'), (
            '$pdf$4*4*128*-1028*0*16*007101116490ea814acd2eead5311cdc*32*37d7e497a546bb43039bfa62a6129c300122456a'
            '91bae5134273a6db134c87c4*32*408b37bcf12da873d7f2840f3c1b917a023961ded4c8164d38e46e9655e66775'
        ))

    def test_r5_aes_256(self):
        self.assertEqual(self._hash('r5_aes_256'), (
            '$pdf$5*5*256*-1028*1*16*f4376428e2fa7a99a76201508a5e2f73*48*5cde016c908fb9df97e879332741d8d55fd0c979'
            '8c301b837a333ed8cbae2c8bf42e28656ef18db1764144181ac4f56e*48*f45cb69d2898bf6440e5e27271ebe73dc4fce6e6'
            '8dc2ff317fd2f43eedff2e055f6064f05d744407723d0714bc5ad490*32*32485f0096a641402bc07968eda2777ee6e969a1'
            '3ca4aecd9313483babf47b96*32*ed0f4298ef2ef95df4ee0aef4cdbcc8c1382515a115b948246b4e20c35fa25ae'
        ))

    def test_r6_aes_256(self):
        self.assertEqual(self._hash('r6_aes_256'), (
            '$pdf$5*6*256*-1028*1*16*007101116490ea814acd2eead5311cdc*48*1011d27f4c83418e85d10c355a2f73fe23b62413'
            '9eabaa734ebb6fbfc7641347ce5b918d715798a02c864db1b7f54b05*48*ec3fab5f898aa31d80b8aff9e73a2ef3518bab3a'
            '35c2299009923b814fe930829340e46df6d820640dc9aead98ae6008*32*5e79b8fc7676132e75cf08231d665b1964fe9a61'
            '1b06fac348d7b8deca604490*32*00dc43258d5db63f91089df8a491cc32e16f50e4fc2665ff25e938f0174b7fc8'
        ))


TEST_OFFICE_SAMPLES = {
    'doc_rc4_cryptoapi' : 'e5dd0f4c6d0a972abdac1dd21b5dc4ea177e84273a6decf3997f6a49b7ec0bed',
    'docx_agile'        : 'cdcbbbd7676384514b280200a3deab7d69e57010353b7e1bf96956a07690e0ff',
    'ppt_rc4_cryptoapi' : 'fd5de8e6396021bd604307d62c724d27f04d06b6aef2cf6450c749cfdd43acd0',
    'xls_rc4_cryptoapi' : '4908a2b6b37f0c16ff3d7ce7b397623d7fcfaca4c4411905755ff512c39d9da5',
    'xlsx_agile'        : 'c8cbea1bf23c50afb4f906b7de313dc34b6460d68d087e774825a9afbeecc300',
}


class TestMeowOffice(TestUnitBase):
    """
    Regression tests for Office hash extraction, verified end-to-end with hashcat.
    """

    def _hash(self, name: str) -> str:
        data = self.download_sample(TEST_OFFICE_SAMPLES[name])
        unit = self.load()
        return bytes(data | unit | bytearray).decode()

    def test_xls_rc4_cryptoapi(self):
        self.assertEqual(self._hash('xls_rc4_cryptoapi'), (
            '$oldoffice$4*c3ea28dadef93812cb1f21cab3947b36*82bfcfd8ecebbb39efd2e7be2dda4b01*d19aa1c83630665f1d949'
            'e97595a7c4fe9ef2a19'
        ))

    def test_doc_rc4_cryptoapi(self):
        self.assertEqual(self._hash('doc_rc4_cryptoapi'), (
            '$oldoffice$4*df93fd49cd8c7c25ddbbe482b820613d*e6790cac855857e4d87bf7a7dc89ae7d*74825d189d841a62223de'
            '3c4e3277d885efd5e58'
        ))

    def test_ppt_rc4_cryptoapi(self):
        self.assertEqual(self._hash('ppt_rc4_cryptoapi'), (
            '$oldoffice$4*3fc75fb41823acfd17856047987af272*77bc5ba7060057c49b6a32444b35e105*5a502109d169b89200771'
            'c0a5b64928cb2922f56'
        ))

    def test_xlsx_agile(self):
        self.assertEqual(self._hash('xlsx_agile'), (
            '$office$*2013*100000*256*16*142f2fcaa18a56b0312770af77988733*d18a4617b3893caadea94483a8f9e76f*e4d563'
            '9bee63467ba6512cc40d4c440edd8014bb3b352e6a2b7328e816ce72fb'
        ))

    def test_docx_agile(self):
        self.assertEqual(self._hash('docx_agile'), (
            '$office$*2013*100000*256*16*8d0d3bed2b3e292adc73ddab62a27568*c2c318e0f563193e2d901e0ba6aa1a49*f9c0f1'
            '6497b946eeccb6ca63373f68b3b3039721cdbe3101c22c3c761e69490e'
        ))


TEST_ZIP_SAMPLES = {
    'aes256': base64.b85decode(
        'P)h>@GXMbqV*t&WqFev~0021v0012T000UA3jlLvV{&D5E_8Tw0htE?0suip0{{TLH~)3tEfBPpfc%hZY#}5=#p1{;^<A{Y{X9R?'
        '!0r7j<B;Pnc6uR<@kb(41NQ5Pu6it<4|%mrP)h*<KL9fT0RUqF&6%QH00000IRF3v9RL6T3IHzv00000001BW000000047kV{&D5'
        'E_8Tw3IHGg000000RR{PNHMV=SK8bG000000000000000000000htE?0suip0{{R}O9ci1000010097J0001N0000000'
    ),
    'zipcrypto_stored': base64.b85decode(
        'P)h>@6aWDL000S`qFna)$jvDL0012T000UA0047kV{&D5E_8Twp7{@t$4{pBDjU@={UpwCgDVHJcgiF_ZBpO&A9Hz9m3sOjb6c1O'
        'T~JE_0zUv000961012F;T=w|L%_#r?0384T015yA000000000W000000001UWn*$>bS`vwbWlqL1^@s60096205|{u08sz{0000'
    ),
    'zipcrypto_deflated': base64.b85decode(
        'P)h>@6aWDL2mlG3qFg-;v`K*g005-`000jF003-nZf9R}Wn*$>bS`vwbl*D~V$nAZo)mc9##w+<BY5ETgy9iH2UeOcqJ^wy1bFV;'
        '>9L@!IZ06#d$z$50QNw1hkSJHEO>9B9b|63lQQO?sIdh+9yA@6@Xc2_4jxBeet4|haR*vtFoaDauFX8&%$4u#-(5u+8LQ1p1A{KV'
        'A$GY#(nCUZEeg%NN0LxW0Rle&6aWDL2mlG3qFg-;v`K*g005-`000jF0000000000AOHXW00000Y;SI7Uvp(+a%FTbba-@7O9ci1'
        '000010096!000240000000'
    ),
}


class TestMeowZIP(TestUnitBase):
    """
    Regression tests for ZIP hash extraction, verified end-to-end with hashcat.
    AES-256 uses mode 13600, ZipCrypto stored uses mode 17210, deflated uses mode 17200.
    """

    def _hashes(self, name: str) -> list[str]:
        data = TEST_ZIP_SAMPLES[name]
        unit = self.load()
        return [bytes(chunk).decode() for chunk in data | unit]

    def test_aes256(self):
        hashes = self._hashes('aes256')
        self.assertEqual(hashes, [(
            '$zip2$*0*3*0*bc37ff75df2d10b49680fc906a6c2124*43c5*1d*e2c82cf55db4c4fd3c3fd2c0edfd2be390e32e767a218c'
            'f147225303f6*eb88ae7a2c9e0f79b54c*$/zip2$'
        )])

    def test_zipcrypto_stored(self):
        hashes = self._hashes('zipcrypto_stored')
        self.assertEqual(hashes, [(
            '$pkzip2$1*1*2*0*29*1d*cdc8f8f6*0*28*0*29*cdc8*9c09*9ef90f8fc74fa6f72a1bd52ffd24ce70832b07b277ca243e6'
            'd52dff71f737952957afa22735b98065d*$/pkzip2$'
        )])

    def test_zipcrypto_deflated(self):
        hashes = self._hashes('zipcrypto_deflated')
        self.assertEqual(hashes, [(
            '$pkzip2$1*1*2*0*81*a5*49b40c3d*0*2d*8*81*49b4*9c09*df3b1a62d1370d9e1478ddc65980532378e0f584e11144075'
            '69a2ea285ac670478eedce9b1a0ac394951167bb6c11100f64074877c74ed2c786fa11d646ebd9332e69fa8b1053c1e341d9'
            '6f0cd57390e1e475f7e78acdc71075a6430844d22aecd3cdecc95efecdf5d451919abcd4b03832ebf2176b943d24342752d0'
            'acdbc4792*$/pkzip2$'
        )])
