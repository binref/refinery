import hashlib
import zlib
import base64

from .. import TestUnitBase
from refinery.lib.loader import load_pipeline as L


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
                str(pdf | self.load(name) | self.ldu('pf', F'{{{name}}}')).strip(),
                str(pdf | self.load(name) | self.ldu('pf', F'{{{name}!r}}')).strip()
            })

        magic = str(pdf | self.load(name) | self.ldu('pf', '{magic}'))
        self.assertTrue(magic.startswith('PDF'))

    def test_cm_sha512(self):
        data = b'Binary Refinery Test Data'
        expected = hashlib.sha512(data).hexdigest()
        result = str(data | self.load('sha512') | self.ldu('pf', '{sha512}'))
        self.assertEqual(result, expected)

    def test_cm_size(self):
        data = b'ABCDEF'
        result = str(data | self.load('size') | self.ldu('pf', '{size}'))
        self.assertEqual(result, '6')

    def test_cm_entropy(self):
        data = bytes(range(256))
        result = str(data | self.load('entropy') | self.ldu('pf', '{entropy!r}'))
        self.assertEqual(result, '100.00%')

    def test_cm_ic(self):
        data = b'A' * 100
        result = str(data | self.load('ic') | self.ldu('pf', '{ic}'))
        self.assertIn('1.0', result)

    def test_cm_md5(self):
        data = b'hello world'
        expected = hashlib.md5(data).hexdigest()
        result = str(data | self.load('md5') | self.ldu('pf', '{md5}'))
        self.assertEqual(result, expected)

    def test_cm_sha256(self):
        data = b'hello world'
        expected = hashlib.sha256(data).hexdigest()
        result = str(data | self.load('sha256') | self.ldu('pf', '{sha256}'))
        self.assertEqual(result, expected)

    def test_cm_sha1(self):
        data = b'hello world'
        expected = hashlib.sha1(data).hexdigest()
        result = str(data | self.load('sha1') | self.ldu('pf', '{sha1}'))
        self.assertEqual(result, expected)

    def test_cm_crc32(self):
        data = b'hello world'
        expected = '{:08x}'.format(zlib.crc32(data) & 0xFFFFFFFF)
        result = str(data | self.load('crc32') | self.ldu('pf', '{crc32}'))
        self.assertEqual(result, expected)

    def test_cm_size_for_empty_data(self):
        data = b''
        result = str(data | self.load('size') | self.ldu('pf', '{size}'))
        self.assertEqual(result, '0')

    def test_cm_entropy_all_same_bytes(self):
        data = b'\x00' * 256
        result = str(data | self.load('entropy') | self.ldu('pf', '{entropy!r}'))
        self.assertEqual(result, '00.00%')

    def test_cm_size_large_data(self):
        data = b'X' * 1024
        result = str(data | self.load('size') | self.ldu('pf', '{size}'))
        self.assertEqual(result, '1024')

    def test_cm_multiple_chunks_in_frame_size(self):
        pl = L('emit HELLO WORLD HI [| cm -S | pf {size} ]')
        result = pl()
        self.assertIn(b'5', result)

    def test_cm_multiple_chunks_in_frame_entropy(self):
        pl = L('emit AAAA ABCD [| cm -E | max entropy | pf {entropy!r} ]')
        result = pl()
        self.assertIn(b'25.00%', result)

    def test_cm_multiple_chunks_in_frame_md5(self):
        pl = L('emit HELLO [| cm -5 | pf {md5} ]')
        result = pl()
        expected = hashlib.md5(b'HELLO').hexdigest().encode()
        self.assertEqual(result, expected)

    def test_cm_hashes_flag(self):
        data = b'test data'
        unit = self.load('-H')
        result_md5 = str(data | unit | self.ldu('pf', '{md5}'))
        result_sha1 = str(data | unit | self.ldu('pf', '{sha1}'))
        result_sha256 = str(data | unit | self.ldu('pf', '{sha256}'))
        self.assertEqual(result_md5, hashlib.md5(data).hexdigest())
        self.assertEqual(result_sha1, hashlib.sha1(data).hexdigest())
        self.assertEqual(result_sha256, hashlib.sha256(data).hexdigest())

    def test_cm_default_populates_size(self):
        data = b'ABCDEF'
        result = str(data | self.load() | self.ldu('pf', '{size}'))
        self.assertEqual(result, '6')
