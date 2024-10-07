#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib

from .. import TestUnitBase


class TestPCAP(TestUnitBase):

    def test_pe_extraction_from_pcap(self):
        data = self.download_sample('1baf0e669f38b94487b671fab59929129b5b1c2755bc00510812e8a96a53e10e')
        pipeline = self.ldu('pcap-http')
        test = {
            hashlib.sha256(chunk).hexdigest(): str(chunk['url'])
            for chunk in data | pipeline
        }
        goal = {
            'ad2b64410eb0d5a009d56583891e0ed36635d000044aeaaaf0003bb3e373ca2b': 'http:/''/163.fuckunion''.com/286//update.txt',
            '6494f132d23a9e1081150e954bbb11b577c260a7f4fc654044bf6ddb0793ea2a': 'http:/''/163.fuckunion''.com/286/soft/163.exe',
            'db604c662d8b659ef96558c8a572764e2479d911ae4a7e295a16bbf84aec5ab7': 'http:/''/www.tao168188''.com/mh.exe',
            '264dc5686bc2a6a75ae8f70692332042a73230f4159478711a32fe4dd4c5ec09': 'http:/''/163.fuckunion''.com/286/pop.asp?url=http://www.puma164.com/pu/39685867.htm?2',
            '78e42e7616421aa1f6a30aef6e6ef347e82d592992df7259fa94c550d9382767': 'http:/''/163.fuckunion''.com/286/count/count.asp?mac=00-0E-0C-33-1C-80&ver=2007051922&user=00&md5=258a993832e5f435cc3a7ba4791bc3de&pc=BOBTWO',
            '9972394d4d8d51abf15bfaf6c1ddfe9c8bf85ae0b9b0a561adfd9b4844c520b9': 'http:/''/www.tao168188''.com/12.exe',
            'e682dfcdde010f6e15bae0d843696f6ae8d5a85e75441660b782789ee747f075': 'http:/''/163.fuckunion''.com/favicon.ico',
            '302e8c6bb616ec55276915c6f2373bafa031970479ea9ab2e2e96f4e9d8b6730': 'http:/''/163.fuckunion''.com/286/pop.asp?url=http://59.34.197.164:81/804635/adx352133.asp',
        }
        self.assertDictEqual(test, goal)

    def test_get_request_summary(self):
        data = self.download_sample('1baf0e669f38b94487b671fab59929129b5b1c2755bc00510812e8a96a53e10e')
        pipeline = self.load_pipeline(R'pcap [| rex "^GET\s[^\s]+" | sep ]')
        result = str(data | pipeline)
        self.assertEqual(result, '\n'.join((
            'GET /286//update.txt',
            'GET /286/soft/163.exe',
            'GET /286/count/count.asp?mac=00-0E-0C-33-1C-80&ver=2007051922&user=00&md5=258a993832e5f435cc3a7ba4791bc3de&pc=BOBTWO',
            'GET /mh.exe',
            'GET /286/pop.asp?url=http://www.puma164.''com/pu/39685867.htm?2',
            'GET /favicon.ico',
            'GET /12.exe',
            'GET /286/pop.asp?url=http://59.34.197.''164:81/804635/adx352133.asp',
        )))

    def test_flaron11_challenge7(self):
        import base64
        import lzma
        data = lzma.decompress(base64.b85decode(
            '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;1V+i_+0=61K)#t#K}YG'
            'cgSLU?>dk6jYaLrYn;Eshef9Ha8#IyV~BO8IB{2Uq!*vd1uhp-'
            'C*2V*l#YiTUQL!~{Le9&arp^cG_azeEmev3iVMA93gTF+O^;IY'
            'H6j*ARay#M=l5iMDg-^8Rcf?xDTY^qoCVvJR$<ak1rlVGRE^bb'
            '^J`gmClb#1m84bGu<ts>okMZps+UY{i=C*nZtY9~I`pdKtnz{('
            '#N(=|P0F|9-Wh&_$JAL$z}6f&)C5!RNDy&d-<w_u<8G`FXN>zZ'
            '>O^oF!Inb*1T<W3VnomY=6h)B$}0k%Wv8aj*>&3&GBcaD+d(DS'
            '2JPmD6*LhF#LY7k-*FE<%`y32B^<6Dh4y7|FZOp~%kYBX!xYBE'
            'DNlj$$Rmu5C*7IIS?DebV&w?LbCNP&&|OYK*kBD3W~UPRUjc;0'
            't9v{-o}>}*@1*;*)%47FKW(XMj%lOQ6c|XHYIlG@vbJORGLm>L'
            '(@77YZkfP${a<aBAP3PS?+oqZPH&UFi9zqGTpG6zq^FjNohC$}'
            'HMdp^wY0wNWmH|H^PDp;W69O>A6*!*;{FOFIw|Vc>UZp-d~wZu'
            'm#ZDHE#cIW`IhS=dd=iGSYI^JDq*ERv`zy27;@(W<p?BG$j^k#'
            '9ZLK8om1R)RZf5fsbTa=F<J^lFkLtRd9WUE=dXkbVxFkW;4`l-'
            'VGe8m_JPKn?<39n26?VLkc>ZK&c9U%5hN9id~sfHp{9?=HYsUm'
            'h!nuIrI$E$g$3{8?z|FzloKV98NbAi-oCUAa*};*lZiXRiFG*l'
            'NNuz9&43+%t6S}&omi!jCnHXVjcM3muGjCTIqF@(0`$`qZ^BYa'
            'zZZ2%qs!Ik;Q}z&j6r8gzor$Ak@H}JqFny|K*nU?s>HXeq{6&Q'
            'uJNz+EobtS8>1=fX13FSLQxg+AX1S&Lo}@m(}IGe(PE4tC+Z|e'
            'EzJTasa`|j3?$N-MhF)Y=-9@Y`E6^IA%P0ekw=wFI5>;L8;&l+'
            'K|mKVnR@9Fp-A<RuK5Dnnr>FCi*{mFmTuDOFtD`<(n>OgpDt50'
            'MNQ@)J$bVe!Bff;^u6#Hc!|U6C5McbjT6$1G#M<+P|`WheIN^q'
            '7Za=G9bIUx{GXrl!9zMW@BFy5xVJ)c#L=&w7f%gv1yQbcV3b&P'
            'fH9D&Suy1%;ZHHaDFLgNhjK+@w=}nM=s&dQc-Ige?95k#+B}P}'
            'We0DX6;&ov3+3lgq9~_)T{^O<%PL^v(mJKLy<;i?;^JJb#gEe<'
            'FpFy2gsnl2q5r9)uk6x|z_-%QEE5)-<q26upo&4H&YyLV{-Q}k'
            'Hth9Xh<j`)e-D{L_)*shf`OqIR`$ET01b7~M&w6(n6y6b(7REH'
            'Fz1=Cgz=G|VL%8eQykCbx#{Lde}lG6L=0t9)zY^cy&Os%-a#&#'
            'y@Go;+b3h-)J<`OS48(S<pvisic*UwB}G7(B!^O8xY})m$iRH+'
            '{W+k;hhM0G4qk2G0$s{W<4D+A&vt-F3Wn3<3vDN9H6d100dm!-'
            'yj|8~lF*cfNf(fu^a+D5Ud0`m8cD_HwDxJvgU9H%cGw=LddIbm'
            'hJluW?nIOe9FlER2Edw>P&0#mE|8jr0+GL!#ohLgBvK`d_2BDz'
            '(>j)02D`=rRyIpu9B;sXWsJV(3rj{sRyQ&NRxC?tFGy>g(J^Rq'
            'DkVRG@LxEP{+pe#R(+A3p!pqf+6&+8T{TnWC+VZi8gdWf9gBX_'
            'WfB9PP>}7Rmf#FsMuizB@&1e;B$>WiFHuEXcic!P=k@_V2E&U+'
            'utsmCj)pkG2B~mx&d1Ol=ESsi$kFy`46e~q1BOl?-{xLJICROD'
            't@QC$b-@!kZTQbTtc-W51C~r*`hUbZhGTYDJYitd@!BXq86YAH'
            'ohy^xnzrO>!|o_XKEw;juu-_638DA+@a}-*%HL8JgLf&)&W7`%'
            '8XV<-ZQGg%94pBG5!QD}C#LQ<6+dobKo&4&%HPgVfbP>@Epmj$'
            'vq}r^;yK~aqZ!^lRYN}8mbX#=QrQxYws!T;jg$76+skh{ZB<jA'
            '?|^+LhLEr#lsx^VVJkr`J-ljjQXB!&GVE5nqn4zOcji_qN~`9m'
            ';DvhGJ-Oe9V^cwhTzc1~2k+$C%C?C@An=TE<!V)5{@Am|?MS-A'
            'J;?iEN9#~&sUvf;ElI{3PhZu8-y5G|U3l{RK{@u)l{xICUeXv`'
            '2B2LIPbyjfr50k65YKI6o_+%wKpwLE49jdg4f3ZZ)$mkb_R7Wd'
            '(V915xF0ycXMpXO>N8#BxTsd8hw?ra{u4Fxqw$C}P|eUJ^c$1X'
            '-x1*)bM|7EAOWuwW<dY|#{r$))skQ900EQ^v?Krk7zxH#vBYQl'
            '0ssI200dcD'))
        goal = [bytes.fromhex(p) for p in [
            '0a 6c 55 90 73 da 49 75  4e 9a d9 84 6a 72 95 47'
            '45 e4 f2 92 12 13 ec cd  a4 b1 42 2e 2f dd 64 6f'
            'c7 e2 83 89 c7 c2 e5 1a  59 1e 01 47 e2 eb e7 ae'
            '26 40 22 da f8 c7 67 6a  1b 27 20 91 7b 82 99 9d'
            '42 cd 18 78 d3 1b c5 7b  6d b1 7b 97 05 c7 ff 24'
            '04 cb bf 13 cb db 8c 09  66 21 63 40 45 29 39 22',
            # ------------------------------------------------
            'a0 d2 eb a8 17 e3 8b 03  cd 06 32 27 bd 32 e3 53'
            '88 08 18 89 3a b0 23 78  d7 db 3c 71 c5 c7 25 c6'
            'bb a0 93 4b 5d 5e 2d 3c  a6 fa 89 ff bb 37 4c 31'
            '96 a3 5e af 2a 5e 0b 43  00 21 de 36 1a a5 8f 80'
            '15 98 1f fd 0d 98 24 b5  0a f2 3b 5c cf 16 fa 4e'
            '32 34 83 60 2d 07 54 53  4d 2e 7a 8a af 81 74 dc'
            'f2 72 d5 4c 31 86 0f',
            # ------------------------------------------------
            '3f bd 43 da 3e e3 25',
            # ------------------------------------------------
            '86 df d7',
            # ------------------------------------------------
            'c5 0c ea 1c 4a a0 64 c3  5a 7f 6e 3a b0 25 84 41'
            'ac 15 85 c3 62 56 de a8  3c ac 93 00 7a 0c 3a 29'
            '86 4f 8e 28 5f fa 79 c8  eb 43 97 6d 5b 58 7f 8f'
            '35 e6 99 54 71 16',
            # ------------------------------------------------
            'fc b1 d2 cd bb a9 79 c9  89 99 8c',
            # ------------------------------------------------
            '61 49 0b',
            # ------------------------------------------------
            'ce 39 da',
            # ------------------------------------------------
            '57 70 11 e0 d7 6e c8 eb  0b 82 59 33 1d ef 13 ee'
            '6d 86 72 3e ac 9f 04 28  92 4e e7 f8 41 1d 4c 70'
            '1b 4d 9e 2b 37 93 f6 11  7d d3 0d ac ba',
            # ------------------------------------------------
            '2c ae 60 0b 5f 32 ce a1  93 e0 de 63 d7 09 83 8b'
            'd6',
            # ------------------------------------------------
            'a7 fd 35',
            # ------------------------------------------------
            'ed f0 fc',
            # ------------------------------------------------
            '80 2b 15 18 6c 7a 1b 1a  47 5d af 94 ae 40 f6 bb'
            '81 af ce dc 4a fb 15 8a  51 28 c2 8c 91 cd 7a 88'
            '57 d1 2a 66 1a ca ec',
            # ------------------------------------------------
            'ae c8 d2 7a 7c f2 6a 17  27 36 85',
            # ------------------------------------------------
            '35 a4 4e',
            # ------------------------------------------------
            '2f 39 17',
            # ------------------------------------------------
            'ed 09 44 7d ed 79 72 19  c9 66 ef 3d d5 70 5a 3c'
            '32 bd b1 71 0a e3 b8 7f  e6 66 69 e0 b4 64 6f c4'
            '16 c3 99 c3 a4 fe 1e dc  0a 3e c5 82 7b 84 db 5a'
            '79 b8 16 34 e7 c3 af e5  28 a4 da 15 45 7b 63 78'
            '15 37 3d 4e dc ac 21 59  d0 56',
            # ------------------------------------------------
            'f5 98 1f 71 c7 ea 1b 5d  8b 1e 5f 06 fc 83 b1 de'
            'f3 8c 6f 4e 69 4e 37 06  41 2e ab f5 4e 3b 6f 4d'
            '19 e8 ef 46 b0 4e 39 9f  2c 8e ce 84 17 fa',
            # ------------------------------------------------
            '40 08 bc',
            # ------------------------------------------------
            '54 e4 1e',
            # ------------------------------------------------
            'f7 01 fe e7 4e 80 e8 df  b5 4b 48 7f 9b 2e 3a 27'
            '7f a2 89 cf 6c b8 df 98  6c dd 38 7e 34 2a c9 f5'
            '28 6d a1 1c a2 78 40 84',
            # ------------------------------------------------
            '5c a6 8d 13 94 be 2a 4d  3d 4d 7c 82 e5',
            # ------------------------------------------------
            '31 b6 da c6 2e f1 ad 8d  c1 f6 0b 79 26 5e d0 de'
            'aa 31 dd d2 d5 3a a9 fd  93 43 46 38 10 f3 e2 23'
            '24 06 36 6b 48 41 53 33  d4 b8 ac 33 6d 40 86 ef'
            'a0 f1 5e 6e 59',
            # ------------------------------------------------
            '0d 1e c0 6f 36',
        ]]

        unit = self.load()
        test = data | unit | [bytes]
        self.assertEqual(test, goal)
