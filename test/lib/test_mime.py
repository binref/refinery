from refinery.lib.mime import FileMagicInfo

from .. import TestBase


class TestMIME(TestBase):

    def test_truncated_gzip_recognition(self):
        data = bytearray((31, 139, 8, 0, 0, 0, 0, 0, 4, 0, 212, 189, 121, 96, 91, 197, 241, 56, 190, 58, 109, 201, 167, 44, 91, 62, 99))
        self.assertEqual(FileMagicInfo(data).extension, 'gz')
