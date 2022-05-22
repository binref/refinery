#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import zlib
import base64

from .. import TestUnitBase


# The magic word is bananapalooza
class TestCommonMeta(TestUnitBase):

    def test_all_variables(self):
        pdf = zlib.decompress(base64.b64decode(
            'eNptUsFO4zAQvVvyPwyHSnAgtpukpRJCKtBuJbqkanxZbRAy1C2BkqDYRbv79YydRGm7WLJlv3me9zzj'
            '3uJ2ei4CQYkADuXTKyWXl0AJMPn3QwO7UVZty40DFmqjDfSRtqTk6ooSXaz8BUr6R3fv8pWB3xA6Ljw4'
            '5KbcFRbEXuY63XGmsMt0SK2TFFYX1kBUmwA2HoMnAkuaDbApnGY4xKgfiMFF0I8DkWVWG5tl63yrz2rW'
            'LfrjSM6tN4hICuxHKcuJOzlT9YLiFWq27wa21KbcVc/ovVGeoqtOXLTb1rwLN0C6e7IecxHRgNfKaJ+C'
            'zfT2U9v8WfmIV++MHJYpOir4XBcb+wKC85pJibGVVu+UXEtKmBSPHIsv19hmdxUPEZIDzjkM4zAYDQcg'
            'kYwItLPCpp8mSbJIT+AXvhju5fwnzMbpDF6UgdedsTDX6k2vggDOQKKZifQeW+nO7p9KozSHGJduwCCO'
            'wxjWe6BAbR8q9sDhN6CIov/BKBx1ICW2Utjvqv1Ly7J0P7BpY5r/0xDV1TJWVbb2OBCI9XqTZPoFx5+0'
            'nw=='
        ))
        meta = {
            'crc32'  : '8e9c7bea',
            'entropy': '60.00%',
            'ext'    : 'pdf',
            'ic'     : '0.0645',
            'md5'    : 'ee188312467228b061b430f7432de410',
            'mime'   : 'application/pdf',
            'sha1'   : '976c1f31b9d374078bc0093d837dbb5f58c7136d',
            'sha256' : '054dd1d7b1faaca9ee2296f1c62d2f5ab7d46d48b48784cbe843fa103c4fa61a',
            'size'   : '00.794 kB',
        }

        for name, value in meta.items():
            self.assertIn(value, {
                str(pdf | self.load(name) | self.ldu('cfmt', F'{{{name}}}')).strip(),
                str(pdf | self.load(name) | self.ldu('cfmt', F'{{{name}!r}}')).strip()
            })

        magic = str(pdf | self.load(name) | self.ldu('cfmt', '{magic}'))
        self.assertTrue(magic.startswith('PDF document'))
