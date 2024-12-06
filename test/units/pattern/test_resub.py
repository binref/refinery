#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestRegexSubstitution(TestUnitBase):

    def test_real_world_obfuscated_code(self):
        autoit_obfuscated = '''
        Func lwmmqmcfqg($vdata, $vcryptkey)
            Local $__g_acryptinternaldata[nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("Z3HQHwba"), 8)]
            Local $tbuff
            Local $ttempstruct
            Local $iplaintextsize
            Local $vreturn
            Local $e = Execute
            Local $b = $e(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("TBcwikuolltnBKaXRCvPyrmryuExoTwTdFoJhmYZYSXetpmsANtrqziMqtItanxlgpHOPP"), 5))
            $vdata = $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("n0xORjC42ZklD69yUXZ6EceMm61aNxH72uLfv79ijBJ54jpqI6FMYFD53iare74Brqw72niBl69LgbR6EbsWi67ytvY28CTBh24hmlx76ndBJ44XGiE61nhOH74SYYI61KgyQ29Mep"), 3)))
            Local $aret = $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("Y0cCxzKxCoo4Yk4jxYstp6uoCKMOdfD6xLCJWFxLw4kR3ugGdGZ6sf1HoAmKe6AnCxUVlyW6WyCMfMSwZ2NA8gymJmI2kq2iYtodB4EL1rnWCCS6YZ4hUKtri7Ia6zDbfza6pR1eQjYru7Lh0BeBlvx6ok9NFAOZZ3zR3TEQYmL3qy2FxYCsH2mAECQidSe6bW4qmovFr6FbCSyQqhV6QNCcqOAnr2GM2AXSJFy2oWCtWCyjT2NV0wAsiMs2HW2vpAnpi6Zb2CFGUDW6tWFUnKyOd6jrFsRdRhA6HxCvjQJiG2La2aHwnSr2AsCWSgeYI2rI0IXfrjt2Ch2ihYmEN4nK3JNcWbz7av2kLqIKZ7nC9IarJDq7gt0PJFKpo7in4WPEuCG4iv1KZwiaX6jU3vWUmuH7Se1imgQRf7vQ5DOCKdz6bs9Wsrrms7rY2kUzsQs6PW5ZTwTOE4es3GxDJGQ6vZFbyUOuS6QaEIGVlqA7KD4GEyGNE6ri5ZGOVOS7uI8AoytYB7HB4WGDYYb2GT2zzNlkM2XPClvHlzM2pV0NqlLmF2eQ2xRXYDk6XT8VOAShx6ni1JmRfmB6jVEIkQLMG6uu4wNuVoM6BZCneYxlN6px5Ddcstd2WZAbVHzhH2PM2FLtkXt2XsCSyLwHj2ul0sJVCia2sC2vNqqnR3gb0MGPCEA2JF2jbgFHS2rzCVPAYED2Em0RbSgte2aG2jVrDhh7ss0QyzZvu7dn4RsVCQX7ii2CNbYKL2ec2AxaXNS2nOChnWeYR2WF0EcYMlQ2My2JFMUbi3FU0XvUXya2yG2gIFJfK2LECwfqIAq2Ks0Cdlmkm2ZT2CBivKG7DZ0redhHs7yc4IetcDU7Gw2BwLwlv2tl2ldJJat2QpCrICMel2Jc0JcFITp2Iw2MiVjKn3Wg0rVLPyC2Op2dlOlAS2pUCiCNsrs2WL0MOVkOf2Eg2vmMQaE6gU4pPoEtW7Uw7aBTLWo6ZdFzMyntB7YD2heHFzT6eZ4TCvdEr2QS2yNUErK2HTCiBnSrA2OT0LMqRwX2ho2tDwMpZ3Iv2guvOTl3xt4OqxSrh2sm2CsOFmV2bZCfYfghd2Ju0SksfWz2zA2XiOGtw6lP4jNKGYi7Lc7wnTNil6KqFczhXzQ7cN2OPTmRF6iv4QYmqww2Jc2pzZlMr2LMCxRYXYp2tO0XKktNl2Ry2xSFnaU3ft0ejQQYa7wq8HTEnOX4Al6yZemGp3Ep0AoIZgl3dx0ETLGgQ3WD0tfnSpK3Ad0TbSuJn3PT0axFlIj3VX0GKpdce3IU0bMDjZz2Ql2eNojHo2qi9rfESB"), 5)))
            $__g_acryptinternaldata[nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("k2QjJkAc"), 8)] = $aret[nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("K1VWn"), 5)]
            $aret = $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("x0htbrUxaFhTD4WXLQr4tgZky6pTSgCCZJJqp6rdJyQCRHxoy4herkn3znRZv6QgpXe1adZZL6KGrjZCxFVHk6epamtCFLeoo2zJnZJ8unEim2SGmPs2xuSTI4spgEf1Dbvwt6MYkUC4kgiWl7oKIDe6PxhAZ6lnWWy1vqhSH7YKkNO0xtKeM6bjgkY9pBCvI3cmwof3pMlYL3SkBOB2bMUsk2kzvpPEBMYpx6zaZQu4Jheqb6zdZsBCNRfJl6XZRbiCmCHst2ALnzK2CLgot2LcSngCrAuqx2SyMjy0xdqZs2qukJq2zdoFp6yPMCJ2JOKJi6vKJxVFQsPNg6cNOYyFbMbDD6mAFCiCpzDxK2ouIoI2sZPzx2mNIpCCaMNOw2fMHhi0TXasV2sDFjl2Oyfpz4CTdOQ3XNcUW7bZgKx2gPzhk7AftZu9cuWKd7kYnID0RKRdV7ZAEpW4IBHDw4grVQt3cTJuV7mkyYY2ToDWN6DxEQk5KgxuT6ZMzcM1UrtNK7whvUK4anGRH6lIUAy5QOklN4hJQXi8jLmYG6GUTCf1iBtuw7TfQoL3Zaaix6IBgca8zzmEZ2CEzEN2JbogX2VfnrhCTQFgI2alPxe0dlSvG2ebuhs2oDcoJ6SrDUS8QGyok6sGeZN1eDuPB6NxiOvEnauXe6eBvEq4gtXUy6oVhXzCFJhDp6ZYbtl5EEhlR2TSUtJ2oBOdt2kwWSGCQiigm2KvFpG0LbKcM2upfmG4uCYDY5bunPTFHnVxc5XnuDvFDInoh6lQbtE7YbpMd5NnKiSFVtMbs6nuHHy1rSKrY4GyqPI3IijnR7uPRIo2oacsb7bNucm9ecDMl7GKRbF0xhCrj7HLuSD4Fzspx4ZdiPL9dXduF6WdxkHETJMqg7wDTQq4JfRhN6PXFTI5RkGTI7cEwnf2wPnUU6oglduEigSWF6vnqDI1copFW6zrdKcCiANtB4oJwUg4lIkhB6VCaBu1ZIoXR7RmRec4EgJzu6PYqiW1ByKgz5ucOuUByWJjU2laveo2KrUDz3lEpYD2MNeKv2sgPNO2wrXQG5uIoqUDKMCNe2YoKMVCWRLeg2OKNFN0YhHpw2tVOfr2ujvjq7ZcAIH5GitDX6rVQFv9ptbdM6uOFGJEsVSYl7mWUiE4fLfFe2VBjvb2ODSpx2qtjhcCshqDM2IQhka0JIMLk2KnXYL2ZsDWG3DgUGr0FFrZW7cStOo8KTJnt3DUHDK0sjYkj3wikzF0CmQqV3jDpTS0vLIeS3lijNl0zdKyI3Umhan8DvOdb3TRnxQ0jKoNy3OnGCB0jXypB3DNhgi3JiClw2ShgQB2nPtZB2MULjuCSYgUq2NMmFO0mneph2YBSLR2YvFvl7KJXWH0TamVk7oqlek4mUSDN7YcMUA2BWUrZ2WzVPH2RbfIn2RUUcqCTmHZw2uiSDJ0pLXKL2bznBk2zUEji3eDexs0VLVAN2bcXKQ2TFlXW2HlUknCQsjPW2jNYut0XEZyY2pQjoi2RxXdf6CBIxX4tWRDz7fVyQA7gsdlM6uhnxfFSvlBp7MbdrV2MkBMX6tkzhD4zKJpp2FqLAx2egCjB2SdBrxCOidmp2UgGkb0NOkYv2CWWSy2MwGgO3cfAjt0CSbGU2NWTlJ2uwJtj2GtgyeCAbCvB2HwpGj0KdmKj2glqwz2QJmyC6SCwxu8dZVDS6gSaEX1gojWF6KMzgxEjNgIv6BLAiy4jEujK6HAuPRCcFTvk6tchPQ5lrZxh2vpzWgAxqbds2XFZbF2VeIlS2nKvoTCMRjBH2lsNku0kEOPa2yHAUf2SfcpL3zwgpX0gbgap2wEuUA2MtEOa2fUhxk9tlQO"), 6)))
            $hcrypthash = $aret[nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("y5YWkY"), 6)]
            $tbuff = $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("v0pdxTxKyikWzEA4TllE4bqRIClWh6KSqTChWYHjixY6ckXKCZALtHeOU5kuHw3tnqEhFlA7hpMO4IspKnafZ7tHwD2vnEFEWyX7PbqQ5KtBXZHjR6nwEZ3VKRKozXz7qNAl4xuBlRKRT4CzJD3lbBMXzlI7jFOi2OmHPEDQT6tPWb5PfQdfefT6anJc1vncqbVdn7Gsec4eEfyJtKS6fZWh5feUFZaPn2DEmi8cCBylDOi2Bnxa2bUVHdKkQ6Ruwv2yivfDAPB7rXXg9hthCLiZe7HTjx4uGXTtrsL6ffDN5fDzayAzK5XoZvBRnZiVDqr2yxiI2iIgzerVb2QucF0WEKgtVnx2HBtc6ecwCoFVg2uRUp0RkvFtEUa4LtyZ2mLjDKHkB6OEDz9SZDLzLYb6KUkCEDSBcHACt6EXsb1jdVNgpOD7HWCB2uPeAVExc7aHbg9SyAOCffO4GBpQCuOEUfoZv6QAYM5mtezzlyJ6boNOEpPnbQaNO2zovA8JiylhbLC2AnJp4MoGucBgT7BpGp6KUYPmjxm4Yeaq3QXEzDZMp7GYvE2YtYyhfHh7Cinx9RmoQpEcO7nPqm0JTxbdIAE7YURo4EOCSXSin4jGkMBZZjbVGpk6DlaY5nfCUITTs7vAOl9ovHvgKyz2IlSE9BcmSEFEa2Ndpj0ctjQNkTd2Lxug6UoZTNPYF2NYHH0qAPqWKkB2GXld2ejwxSuAp5IfTKDPhSYFrEP2mcaw2TNoaNXfn2DVWI9ohwsxBR"), 7)))
            $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("F0HHYxecc4Oso4SJA6ZiJCHNo6kAWClxj5qlb3twW7LLO4lvh7Kov2EDz7UgQ5fvx6Kyl3BCX7JiV4ROO5WBu3xSg6mMN5yBw7wTg4Rwr4ptk4xdJ6ikj1Nqc7AMT4bhh6OeW1JJT2Xkl8JoE2MqS4udB7xdy4hLP4vXz2PkY7LdV5ryc6KVg6sra6WXZ6zFB2IKfCErE2TJg0MHn4ATh5knY7rJU8ipK6lue5OxL6rQW3Ayg7lSH5pqY7OvY4YTs6jsL5WBI2Ugz8XvS2LzF2RVu3urz1Vay2sqC2tvU2bln9FME2oAvCrnf2wHo0qPE2ATX4bdD7rsO6KMD4LGa3jFV7nEG2VaC7dyD9tty7bKb0cxT7IXA4TKN4nQEBhSG6bFN5kTD7SxF9eux2yAY9Cp"), 4)))
            $aret = $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("B0iIHxBhV4UtT4hkx6vGwCroL6RqyCkzO4DCC3uKP6lav1zRx6txlCqYi6HexCYXC2KdG8LER2IcY2fTx4jsz1Kdv6PbW4qyx7sZA6VpD6FQF1GAK7WiA0OeR6ezO9Fng3aJX3Vbi3FfT2FIs2NRNEcuA6ssd4VPn6XvBCyeM6LjNCGTU2ofK2UWB2AqRCNhB2FEb0VOm2UDf2GJx6BhG2yHt6xFgFosO6wQYFYcu6nwjCAAt2VKQ2paM2wOICoMs2juB0CXp2luQ2xNY4aOv3MLS7hna2XmD7eDh9EUS7dfI0IFo7zTL4FUo4wDx8MSP6DQK1Ypg7hrM3tYx6AIH8HYt4iQs4rHm6tgC1JMA7LfS4dsB6QIf1nBA2VCf2lnF2FhPCbdd2JWL0iXE2feY2Sli6pfW8QGR6oOV1eSw6THIEeXE6CLJ4WOu6kpHCwBh6QCD5IwW2BiP2pxN2diECpop2hWa0aUQ2RZT4QbF6mKS8QNO4ktL3OlD7Nom2fWS7BQu9FRo7Igp0Xmq7HDL4nKc4Vun8upF6keT1Fxn7DdL3Lao6TKh8gDI2gyNCiUg2eSZ0Bjk2aeG2mpu7JVD3JbU7CFW4zWu7RVo2Rfn7KSb5fmA6tOb3Wak7uIG4hNx2wFxAoTg2vkF2Oej2ZWJCXsC2isD0ncP2eSf4Ole7IOJ4aqU4ZQV2bVK7JVf5erX6pBX6UEZ6CUi6aIK2ZahCqAG2Fay0CPY2XgH2HTE6Ajz4kiY7KHn7wKY6ILYFukc7VCs2RZZ6lYn4XZX2aru2Yea2rkoCsJG2QSI0dat4vAC4qeM6KlJCkAy6IKmCSqv5gDK3AxD7TnC4HMB7xRI2yUB7NVK5TIn6KRH3ZQK7bTx4Xmw4cjv7qyx6ZKD5Jhm7QQJ4Vle5uln3GWQ6xWt9srf7EDaAkLW6Wfw5YMt2jka8zUJ2hBG4BsC7NJW4cFs4sdG2exF7eMF5fNZ6ZIw6Ltw6bpY6qkL2KZD9CYX2azTCiEf2Nne0Ivu2ndb2kHC6Pfb4PzB7TUb7YVU6nbcFNIF7dfq2GqY6Urt4gdc2SJz2SBN2zVLCjSP2Sdo0tkU2vSa2Bwg3oLi1IdV2qHm2MyG2auv9mP"), 4)))
            $aret = $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("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"), 6)))
            $vreturn = $aret[nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("y5YWkY"), 6)]
            $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("s0dxS4X4Y6jCq6tCc4t3o6z1f6rCj6lCc2q8T2f2g4v1R6d4n7D6R6X1u7g0f6f9X3z3S3q2z2xEw6I4Z6MCE6fCn2c2o2YCe2d0Z2r2u6r2W6XFm6oFJ6VCs2t2Z2vCO2J0C2f2Z4s3l7F2t7k9g7U0R7l4p4L4O6T5S7q3h7n4L7F2d6VFE7L9o4b8p6F1N7i3R6e8A2J2y2lCS2U0Y2K2k6C8G6a1y6YEg6z4b6ICO6A5Y2X2b2ECo2A0q2r4u6b8H4i3U7L2k7F9U7G0y7N4p4a8U6b1P7D3m6Q8u2Q9"), 2)))
            $vcryptkey = $vreturn
            $tbuff = $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("e0xUgqD44HXur6CdPGJ6CVGXn53nFbV74jkaX72cPAl75nwAe63xOCd74exHz43Jjgj72lgkr65wcZT61kuiT74GaJg65FdlD28JlKs22JicG62dlfD79RLar74toXo65xUdP5BHXuV22gUqx20cAGb26Zint20QPWe42XCrF69YNih6EwfPf61QlWO72fznN79lAnL4CaSjG65oyVB6EOSPP28sXrx24dBMn76AlUD44COUc61WTCJ74reqO61qTHb29Qrea20EVWn2BQjCZ20mLMG22YEPU31geWM30WXJC30NHiw30Txzv22cZkf20ZMaU26swtf20fQYB22cuyU5DzEfu22ZAsh29VGm"), 3)))
            $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("O0DPxNYQGVK4Tk4crmoWs6tfCUdeXvg6gECGeAfyN5Rj3QDuELd7jo4oBMhIw7oL2PMTkIt7GG5lorFfl6pN3DGAPtU7QP4QgtfLv5jZ3Pjpamb6wg5oZwPmJ7DE4yFLQHR4Vz4ErvmRu6Qa1sQeCpa7Bo4TFjVsC6HB1PMdQUr2xT8QiojeP2UK4WtJsKo7xa4WndMgg4bz2uCKiig7BA5LzsSnK6Er6zwkIMq6ao6DxOdMm2JlCoKgNZB2pL0iysoAN4Mf5MHjKBn7dT8vfbiUn6yX5gZqzLS6Yq3zDHrpo7pl5izLFtK7aZ4ndgvlR6ug5vTAOYU2Um8TbJkDd2gl2pLpnXd3wT1rxYOTF2IC2AUIvrn2ob9yafiWv2KpCuvwfGJ2rg0gGWwpt2Of4gcTJCU7CL6nywDIX4vO4IYNJrW6Rc1BkCHZM7eS4ApMTPN6aa1lStkJy2jo9IHkVJ"), 5)))
            $aret = $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("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"), 6)))
            $iplaintextsize = $aret[nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("q6yMySvX"), 8)]
            $ttempstruct = $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("b0hwxMQIwOv4cH4BbkjOg6aKCTktvgf6EiCNpuEgj5wA3HiKGiE7Dv4erUoLY7Lo2OCWqsp7gM5zBMGba6RY3kgeYZb7oU4xChnBX4PP3fSEhIH7rG2YiCcUU6Ew5WAaRKp6mN1bVNNJk7cs4wvMIbQ6dJ5yBosWA2dM8kFYXNF2Qx2RGfMUX6NE2JXGYqV7fW9RLwoCq7bt4BYRfPf6rf5okfjCo5bRBkmncMV2pf2CvZtAv2Ab0MTEyVP2dh6abfkSt2Cv0frjEaH2fZ4LNijGF6TY9EQKvfW5vD0GlJtXN6IFCDuTdKB6eW1FjNbpB6Vt9HOiDAQ6JgEgUWvub5YM4dcekqO6DP5OalMIN7Ft8ppQZke7Ne4mdLghB5Di3BllYXD6TK9tlLprY7TXACFoMFb6yy5zdpKzH2mW0cHXBaW2mgBfqWTnN2Ox0OFKWrd2Zq2mXNZik3Mi1oPyRSW2fr2IZSkpL2mf0SlPbAE2Zq6GOhZOx2Vn0NZEYuF2rX2sjZEEa5boDHqkyji2Kk2IlphJD2KgCecElGL2mo0ShtuCm4FV4Tgmgod6ewCtMoTIO6PKCsZZYAI5Wp3vrEBeI7vp4upGwVS7aD2HMYyXg7dt5jjsNvV6kH3wsKMcr7lD4ZnqYmP4AS7vsYvAs6Px5KVnYiU7zI4ZYeZMa5po0uYashg7uF4AzJCPH7EP2msdwYu2en8iNOqtG2VB4jFDUVp7DW4IIAUoT4SX2pztIvQ7AT5mZTTel6td6IFebZt6wK6HpPMWy2Pk9qdVgXF2TN9jIFqB"), 5)))
            $vreturn = $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("K0wwGoxpxnWQcjO4asnw2OjiYOgIN6rDPM9wiLpfTFz6SxbVEsHFdNUqs6RNSU1glDpODBY7iBLt2aYwHnQXW7InTV9aJTXMCtF4QRmZDTjeoWAwK6WLgm9SLGBpexY6sIwn4raRGhUOK2lxcu8nHUIqhke4cgRt4iEMlTEaA6mRxECWdSbXJCg6iLHCCqQOLXQiP5jXtZ3jyBHXLUa7JppU4gckTEfNz7XKXC2KPHwIaom7jTaN5DZlXqRBH6AtaQ3GvlEjjZm7byAm4FdDiaWhw4bXHB7ncofJDVj6oqLC5siqAUbab7ZZUl4XyQEMDTE4OkPv4WgAYdJcQ6sBrI1ZwCzwIZo7icpl4WfRlXAxE6Tuzx1tdYpWsVe2gIbm8wEGGLMHn2RogH4XelSDwdf7webc4vylphHgp5EEFa4TYPgnLjc6wqdZ5QmPjEXgA6cDUpDIxejICRT7zLDK0fZJlukAy5VmAR3UGDgXbAQ7dZCf4MTcUZSGq7JFay2hocrDhRN7Xngn5LMeYLEtb6XDii3HElcGVaL7FEEp4lyYWIOso2MPpnCUSHFLXwk2GUGW0mKBCmCcf4IPzZ5VfvikTUu7oxVM8IfKIHKef6sCuV5ImbKmAhl6ShJp3RCmmzIBY7PPre5wxuYKXtc7kaHC4hkgOpNAp6wUVQ5csKKBfXT2uwPp8KnpVOING2VkfS2qjsboxoA3cenh1aSWFdKim2VRyf2muZOgKjH2mrrk9NrRXIkPH2zhyN9uBeLboFV2LmCbCUMqSuWan2alOQ0RpCkbqym2vMJM2iWiYMepC3PPgO1DoQdHNZt2NoJk2pKmuOQPY2cEjlCepjWWynb2Jnuy0jJJimuSv2NxLw4FhqyACQA6FEUc9jxROaVJG5pOLe0GPdIMMpR6ENfqCGcyHxQYe6ogrD1UhtSOXQP6wlVt9arpsogLF6SAPuEgZXzpEzR5xaOS4IZxHwtBj6HFRX5GlbIVrxb7SZuh8RpHSMucD7dxuG4lYKyyKkZ5hzxJ3nJiGcoQp6Epzf9lRHmCtUc7qVYjAZcsIOViJ6rYJY5tXrohFqH2yERN9tmhnfcg"), 7)))
            $aret = $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("Z0DkNNHaxHWJtBhJuiw4OMlEtC4alfAuPWrVP6KBoiUjCOxJhxtXlIZ6irSbLyCXcRbhHfUkB4ejxhGA3mArOuMEMDD6BiGEZt1QmQlrsCCIm6gdoNnACZWlSjXdesz6YVfwngCHOkkrUiZkr2BsfAXp8cbVKSHjTmt2lmUgWl2GZpaccIRqL4AkvLZS1jVYdbdOdxB6Ryived4GuWGkWNSUL7yBgZXB6BCNyiSjMSb6ZZljiu1hUfaPThbwa7sjeNXY0ApBgIGVdwc6EyXOGk9qRSMtWMUtF3xgzzHe3DZCWICMZmx3YLoJei2QCdnukeFnv2BOIOEwEYBrxMKCpEE6oUYBfk4wHbxWTjRyL6ADBYRYCBAHnRHwTOx6jFWKgmCLEIaMGAYOC2MujyoG2fnDYtSTuAT2AcjeVOCyowwpQMaal2LTubjp0rdQiHisQSE2hrGXoJ2nnZVbSQmtm6MsgAAY2dITfomHOfw6SZiUudFCxeHCOnYBK6vUWAJSFfdrxdiumgh6YnzqEZCijYJvTveQH2VQqmrf2empecwzvhR2ZpQzYKCkNQMbAwyjn2qynEWt0CtvNaZwbJC2SztGoQ2XkrdwfEpIc4REGahD3XwTWdLJqOd7jzIwed2XtKcMSXQYL7KLIsvI9ZurXmSmgnW7zGvEHl0ZUZMqFqBAY7knBxIV4VkENeHqrKf4gfSqUU4zLdOTJrmIu6ylHyFp5aexkztHSij7gyYkiJ3ELTptUCVDC7sriekL4pfAnsJUKsc7EBCTOx2LUDWfpvdyB6ieBPJdFYqOsKuqjKS7NjpasK9ehDObOfktg4mPaPJdByGrlFvNIuK6EWCMnx5RdMTMVbzsX7MZIbiu9oOajiHehrN2dTKjIh2iVBXDpRwwn2OFJnAsCpPNOLEoFMM2GeRipi0PDRmAlrLXR2WMszYd2UOTuwUWXtJ6LxJmFO8eypGwNsBxr6wAhcmm1IMGcPuMwTJ6dDatbkEcrgtjSHGbQ6cVXvpR4wcLXGCZuSf6wzjPadCHtyQvscOak6mJSRZX5SHnxiEEEdZ2nPVHWM2mVUdXZVStb2mSpQcaCIeacbcuUcQ2qRFnst0yzmwwvAOwN2vqrMON4YfmqgtKrrs7NcidmG6IOZQdfEFIh4PngEcq3cSDzabmsOI7EFIxFs2HnddmYjgUX7JbEWkn9bKzqaNFXVz7hkbZwK0oIiTAZdeTx7CUsLOr4uCUYxOrQbS4dpqyeVBNUeWnrNaYq6sWLLEj5hNWzFYmUXg7ajVOOU9copyGSdCHd2HwvvFq9IWLDCepGa"), 9)))
            $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("Z0DkNNHaxHWJtBhJuiw4OMlEtC4alfAuPWrVP6KBoiUjCOxJhxtXlIZ6irSbLyCXcRbhHfUkB4ejxhGA3mArOuMEMDD6BiGEZt1QmQlrsCCIm6gdoNnACZWlSjXdesz6YVfwngCHOkkrUiZkr2BsfAXp8cbVKSHjTmt2lmUgWl2GZpaccIRqL4AkvLZS1jVYdbdOdxB6Ryived4GuWGkWNSUL7yBgZXB6BCNyiSjMSb6ZZljiu1hUfaPThbwa7sjeNXY0ApBgIGVdwc6EyXOGk9qRSMtWMUtF3xgzzHe3DZCWICMZmx3YLoJei2QCdnukeFnv2BOIOEwEYBrxMKCpEE6oUYBfk4wHbxWTjRyL6ADBYRYCBAHnRHwTOx6jFWKgmCLEIaMGAYOC2MujyoG2fnDYtSTuAT2AcjeVOCyowwpQMaal2LTubjp0rdQiHisQSE2hrGXoJ2nnZVbSQmtm6MsgAAY2dITfomHOfw6SZiUudFCxeHCOnYBK6vUWAJSFfdrxdiumgh6YnzqEZCijYJvTveQH2VQqmrf2empecwzvhR2ZpQzYKCkNQMbAwyjn2qynEWt0CtvNaZwbJC2SztGoQ2XkrdwfEpIc4REGahD3XwTWdLJqOd7jzIwed2XtKcMSXQYL7KLIsvI9ZurXmSmgnW7zGvEHl0ZUZMqFqBAY7knBxIV4VkENeHqrKf4gfSqUU4zLdOTJrmIu6ylHyFp5aexkztHSij7gyYkiJ3ELTptUCVDC7sriekL4pfAnsJUKsc7EBCTOx2LUDWfpvdyB6ieBPJdFYqOsKuqjKS7NjpasK9ehDObOfktg4mPaPJdByGrlFvNIuK6EWCMnx5RdMTMVbzsX7MZIbiu9oOajiHehrN2dTKjIh2iVBXDpRwwn2OFJnAsCpPNOLEoFMM2GeRipi0PDRmAlrLXR2WMszYd2UOTuwUWXtJ6LxJmFO8eypGwNsBxr6wAhcmm1IMGcPuMwTJ6dDatbkEcrgtjSHGbQ6cVXvpR4wcLXGCZuSf6wzjPadCHtyQvscOak6mJSRZX5SHnxiEEEdZ2nPVHWM2mVUdXZVStb2mSpQcaCIeacbcuUcQ2qRFnst0yzmwwvAOwN2vqrMON4YfmqgtKrrs7NcidmG6IOZQdfEFIh4PngEcq3cSDzabmsOI7EFIxFs2HnddmYjgUX7JbEWkn9bKzqaNFXVz7hkbZwK0oIiTAZdeTx7CUsLOr4uCUYxOrQbS4dpqyeVBNUeWnrNaYq6sWLLEj5hNWzFYmUXg7ajVOOU9copyGSdCHd2HwvvFq9IWLDCepGa"), 9)))
            $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("l0wirYDXxidHxbLGUcl4OqUxHu4wOkOvUtxHu6GDTIJqCNhdNZgwCUp6HHvzEoCqzbDNobmow4DEFDau3VahMttvEzU6ytNmbh1GPyTGfDPlT6qMdswRCVMGVrSVhVz6JJphzCCowCpEhObrP2TEcJaH8cDwBGgpgLU2TYwUZd2qbmgqHNyHU4fQZqFl1sGimLYvVZl6VXOpex4LCeBWtqppW7HhBzhU6IaTqLmsoVc6uVlpKR1WULwlEpoCQ7qVRnUZ0rNPNWOMSsH6YhZVEA9ekxgOkiPsy3AWvXXH3DDayAwVXjb3ptfIpg2QMRgQnkeJU2oHnQWVEAVKWUfzaJa6eRVojk4SKgjGqqNSU6EvInJtCGPXkxtMLQc6GpiTJUCjwxDJmoTJc2bHBEsv2gyIfRZmNfU2gVkBeyCAUmLQGkkRG2herFjM0HzXKLDcyXq2JvftiI2EbcHRHfCvH6zGRIva2IzLLduNjXX6URwPFxFxdvpccupBd6cJDwHPFQazfixEhqe6KhNOFGCJCanMfYINY2HOrdGa2hEKWpzoYTm2LusmcNCxTEBvtctrN2HAQQQm0ECBJEiqBui2aOudPa2LjlYzFeqeM4ivsohD3AHEqLTJVgy7SusoZO2mvkgESNWZX7XnAVIf9FagnZyPSbc7ZEmKxQ0xvWwdayMNh7TPWvVL4sNMShlPMxt5dMsiJo2HZpeyLCfGN6fmfzvG5rGJzYfIkiY6crwmtECTMGXGQmaqg6ebfCgx5nMQMzJqjZq6gOikit1JMTTtyAsep7TXaGeg3APkkWHEXcN6gWjYSf5mvstiNErNH4wHpTJs3jGJTzYXMej6GWSEiGFjGeFNLxxvb6DekXHJEUwmDPyGuPR7jwghZJ4aNYJOdfYMk6rCusbH5aMPvRfRfdR7OsbBRO8scFXZxuJok7sRHdzw4jJVUSdrsJJ2SipNwk2WZLSNEIRfx2kImAyzCuEsSfwvbaT2OgfMTb0zWUIshJRBD2wBsjfJ2jxjLUEeoaY6ZlQblt8vLoqfQgLLD6oozuiq1jEahCIHQuv6jEIXBzEjaPhVoDtcM6IJPQoG4hPDlaERGoQ6VpGccOCdFnyFBVMgb6viAYae5PCPTUpyLSM2RotNnA2xEgKCQabMI2joIiGqClfodNjUYem2MUKgSt0BxVvrqCZoQ2kSfKcj4vFiOYjNwdz5XEdGrfFoIwKnKZYjR5nnybsuFcqrexEVLOU6WuTxvI7KWaXNSWYwv5wAvZYbFeulmomhstU6QCOEFl1idScBVHZgU4JzHVpP3SRWyMiTncC7DubtjS2jOVSHvaQxn7spDhlY9eYMXIGzJPa7ANSMXN0bZQsAxharT7kWpdku4dYJdhmKoKy4RxVnxL9aRSdrsYoXG6dhVdtlEfWcUcTfDrP7ULgKFE4IKYylgDqfB6XsicTg5NLEykdIyVZ7oOYmIN2CvCLFVzvcq6TMvmuPEiHSVfgTuzP6ZmroSs1OukNAIBJNI6IPKWciCKGtRumHvJv4vkvNdO4YFtBbHoKHU6mWyEKd1gojluBxYgl7ReMqNA4UjLFCbgmVZ6XkAkXF1SPAgDSTsAY5PdpjYQBUsJosFBIzT2mIENxv2GZhwqGwTaJ3gjMDwl2icMHbImVqp2nVFLON2CJfqbBZcXr5FzYrvWDhdlBaqUzti2HvsBnPCWeVDxGjkjf2PycmXy0TfzBzNMPIp2ICUdjv2cJMTwsyFxU6vQBVwH4jnyNbMpIKW7Nixhqf7jmotAdCHUh6HUrWnNFiYFGewtzmZ7XoFQHQ2OlZOGDgVht6FuFvqO4JeuzCKBSpA2uAGNbE2RsmfwzgbCq2mjrZuRCLnYavhnPNv2OOiGoU0PnTMikRVcc2iaXRAq2JJfsPBieDf3KHlssv0WxuEfiINtL2xayNSv2eenZaWFSgK2gEajJj9gmhzWWkXa"), 9)))
            Return $e($b(nvbjtycmyxlfrdbypxqk(sjwakhwbtxwwb("b0IHQDGxPjeFg4tVyRq2tnbEj6BmRRf9zMtSr6dEDjPEoyYUX6vUcFl1VnixX7wCGVP2qfKlt7wjNLc9KrjOS2zyEGP8WRFor2bqwjP4IHnDJ7chEjN6KXzSU5HdQnY2qcqqY6CJSgD5NhxOV7gJAAk4pWRbr7EgLoO5njyTM7Rqpmz2WFBrF6WKEUkEgXfnC2oNyzR9nFEV"), 6)))
        EndFunc
        '''.encode('ASCII')

        autoit_cleaned_up = '''
        Func lwmmqmcfqg($vdata, $vcryptkey)
            Local $__g_acryptinternaldata["3"]
            Local $tbuff
            Local $ttempstruct
            Local $iplaintextsize
            Local $vreturn
            Local $e = Execute
            Local $b = $e("BinaryToString")
            $vdata = BinaryToString($vData)
            Local $aret = DllCall("Advapi32.dll", "bool", "CryptAcquireContext", "handle*", "0", "ptr", "0", "ptr", "0", "dword", "24", "dword", "0xF0000000")
            $__g_acryptinternaldata["2"] = $aret["1"]
            $aret = DllCall("Advapi32.dll", "bool", "CryptCreateHash", "handle", $__g_aCryptInternalData["2"], "uint", "0x00008003", "ptr", "0", "dword", "0", "handle*", "0")
            $hcrypthash = $aret["5"]
            $tbuff = DllStructCreate("byte[" & BinaryLen($vCryptKey) & "]")
            DllStructSetData($tBuff, Execute("1"), $vCryptKey)
            $aret = DllCall("Advapi32.dll", "bool", "CryptHashData", "handle", $hCryptHash, "struct*", $tBuff, "dword", DllStructGetSize($tBuff), "dword", "1")
            $aret = DllCall("Advapi32.dll", "bool", "CryptDeriveKey", "handle",$__g_aCryptInternalData["2"], "uint", "0x00006610", "handle", $hCryptHash, "dword", "0x00000001", "handle*", "0")
            $vreturn = $aret["5"]
            DllCall("Advapi32.dll", "bool", "CryptDestroyHash", "handle", $hCryptHash)
            $vcryptkey = $vreturn
            $tbuff = DllStructCreate("byte[" & BinaryLen($vData) + "1000" & "]")
            DllStructSetData($tBuff, Execute("1"), $vData)
            $aret = DllCall("Advapi32.dll", "bool", "CryptDecrypt", "handle", $vCryptKey, "handle", "0", "bool", Execute("1"), "dword", "0", "struct*", $tBuff, "dword*", BinaryLen($vData))
            $iplaintextsize = $aret["6"]
            $ttempstruct = DllStructCreate("byte[" & $iPlainTextSize + "1" & "]", DllStructGetPtr($tBuff))
            $vreturn = BinaryMid(DllStructGetData($tTempStruct, Execute("1")), "1", $iPlainTextSize)
            $aret = DllCall("Advapi32.dll", "bool", "CryptDestroyKey", "handle", $vCryptKey)
            DllCall("Advapi32.dll", "bool", "CryptDestroyKey", "handle", $vCryptKey)
            DllCall("Advapi32.dll", "bool", "CryptReleaseContext", "handle", $__g_aCryptInternalData["2"], "dword", "0")
            Return Binary($vReturn)
        EndFunc
        '''.encode('ASCII')

        layer1 = self.load(R'sjwakhwbtxwwb\("(.*?)"\)', R'"{1:resub[(.)(.),{{2}}{{1}}]}"')
        layer2 = self.load(R'nvbjtycmyxlfrdbypxqk\("([^"]+)",\s*(\d+)\)', R'"{1:snip[::{2}]}"')
        layer3 = self.load(R'\$e\(\$b\("([^"]+)"\)\)', R'{1:base}')

        autoit_refined = autoit_obfuscated
        autoit_refined = layer1(autoit_refined)
        autoit_refined = layer2(autoit_refined)
        autoit_refined = layer3(autoit_refined)

        self.assertEqual(autoit_refined, autoit_cleaned_up)

    def test_resub_powershell_variables(self):
        resub = self.load(R'\$\{(\w+)\}', '${1}')
        self.assertEqual(resub(B'(^& ${R} ${dAtA} (${iV}+${K}))'), B'(^& $R $dAtA ($iV+$K))')

    def test_binary_replacement(self):
        resub = self.load(R'yara:(FEED)(BAAD)(F00D)', R'{1}{BEEF!h}')
        data = bytes.fromhex('AAAAAAFEEDBAADF00DAAAAAA')
        self.assertEqual(resub(data).hex().upper(), 'AAAAAAFEEDBEEFAAAAAA')

    def test_substitution_count_limit(self):
        resub = self.load('E(.)', 'AH{1}', count=2)
        data = B'BINERY REFINERY'
        self.assertEqual(resub(data), B'BINAHRY RAHFINERY')

    def test_multiple_substitutions(self):
        from refinery import xor, b64, zl, esc
        data = B'--'.join([
            (B'encoded(%s)' % bytes(item | xor(0x12) | -b64 | -zl | -esc(quoted=True)))
            for item in [
                B'binary',
                B'refinery',
                B'refines',
                B'binary',
                B'finery.'
            ]
        ])
        unit = self.load(R'encoded\(((??string))\)', '{1:esc[-q]:zl:b64:xor[0x12]}')
        result = str(data | unit)
        self.assertEqual(result, 'binary--refinery--refines--binary--finery.')

    def test_patch_nop_opcodes(self):
        data = bytes.fromhex(
            'DD057822480083EC08DD1C24E812345678DDD883C408'
            'DD057822480083EC08DD1C24E812345678DDD883C408'
            'DD057822480083EC08DD1C24E812345678DDD883C408'
            'E800000000'
        )
        unit = self.load('yara:(?P<op>DD057822480083EC08DD1C24E8[4]DDD883C408)', '{90!H:rep[{len(op)}]}')
        goal = B'\x90' * 66 + B'\xE8\0\0\0\0'
        self.assertEqual(data | unit | bytearray, goal)

    def test_weird_exception(self):
        from refinery.units import LogLevel
        data = (
            B'ORGANIZED("112f106f119f115f106f113f56f55f51f105f113f113", 6 - 1)\n'
            B'PixelGetColor("Assist^", "Assist^")'
        )
        pipe = self.load_pipeline(r'resub "\\(((??string)),(.*?)\)" "{1:esc:resub[\D,/]:pack:sub[e:{2}]:esc[-qR]}"')
        pipe.log_level = LogLevel.INFO
        self.assertEqual(data | pipe | bytes, B'')
