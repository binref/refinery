#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase
from ..compression import KADATH1


class TestBase85(TestUnitBase):
    def test_encode_decode_kadath(self):
        unit = self.load()
        goal = KADATH1.encode('latin1')
        data = (
            BR'ra{q-wGV8ezdN=hqEKDNz!%xaavxNTBy/Fnwo8l&zdNl2z!pblxK@r6vrcK5y&13jB0a$bBA]zWvqYP#'
            BR'BzbYawGV8ezdN=hCvtLnxK@rczEES%xK$Y%vrVd9aA}Hky?j-gBzkMcaztseAa9)gwN({4zxK4mwGUV2'
            BR'xj@AfwPz*1v}u=>vScB3azC{Iavf*WazkRewmYT3vqYP#y&sGdy<vdqBrC4evr#G}azCZoBzbkdB9hww'
            BR'wPPECCwhejaA}mgy&.cIBy/rdy?mVsay/taz/fD3wmY*kayPd#ayPq2xK$Y%vSDf[xjVcbz!pbnwOD3['
            BR'wft.$A:&&@efG1Fy<6xgeN&dfx(mG)azbLmzGGr3zGu}sw/#5kx(!c1BzkkcB8VedC{3*sayYwfvpQH4'
            BR'ADLYgwPF#5zE:(ewPzy9zdNl2xjk*>wO#MuayPd#aA}KgwGV5oA+e*7B0bsdA:@=%zF783wPSccwO@S3'
            BR'wO=6<vru66BAg@7B0a[ewftt$z/Y#rz7PNjwmYT3B-IwvayPd#azD1qA^n^GByxolwPF#dzxJOdwNPB&'
            BR'zF78jz*cm:aA}Hky?j-czxK1xwO2*6zF%MqxM))9wft@fz/xoeay/k4zdm6!aARseA=Svww/#b9wft]h'
            BR'z!s5kvqYP#z!@@bAaJD[wN(]@vpB4:B0bd8A:&%fA+PA7az++lBzLIhy*?i)B0bykazk.6B8#QHv@C*='
            BR'y?mVuaw3U$CvtLnvixe[C4CXpz!pblxK@r0z!9]JayMy8vqYW=A+cwiw/#eqAaK6cvqE6dA=(krwPR#o'
            BR'vqYP#vix5@vrl98z!rZ2zeTDpvqE5@D2m20y&.iKo)H/4wPA5sxMXi9ayO.$B-X:uBrC1kay/kaB.2Lo'
            BR'vpBd$BrC0mw)]d>y&sDqaA.NBx(!0gwN({2z/]@tvqfQvayPd#ayPsllT+1SwPw]mBz(8dayYw5vrug0'
            BR'wPI]nvqYP#wQ5f9v@#c%BrCHtaARp9BrC43y&%/vA:-G&wft&1A:-]#BrCWswPzu8B9zhmBrCZBaARJA'
            BR'xLzraBzbkdAbPD6zEEA)C{3Kkwft@oB8UYdB7DFjw/$I#zeTGqeP$Mux(^%0wft-2zeTDuefG4FwGU@2'
            BR'x(k5iw/$]dB95KDxLzu%B1wCxzE:(ixK@r6vpS[WzFs03az$+4wft#jaAhd9v}u=>xjkH(aA}HcBrCHt'
            BR'v}u=@vpQG?zxJwiwPI^bwGUA0wft-czdNQbz/{azAbn@)wI9@')
        self.assertEqual(data |  unit | bytes, goal)
        self.assertEqual(goal | -unit | bytes, data)

    def test_short_string(self):
        unit = self.load()
        test = b"ra]?=ltpsCA^n^9wObT]wPA5sA+e&%zE)(iBzbkdmRM:KB95J>x(mv1x>que"
        goal = b"The Binary Refinery refines the Finest Binaries!"
        self.assertEqual(test |  unit | bytes, goal)
        self.assertEqual(goal | -unit | bytes, test)
