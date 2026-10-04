from refinery.lib.mime import FileMagicInfo

from .. import TestBase


class TestMIME(TestBase):

    def test_truncated_gzip_recognition(self):
        data = bytearray((31, 139, 8, 0, 0, 0, 0, 0, 4, 0, 212, 189, 121, 96, 91, 197, 241, 56, 190, 58, 109, 201, 167, 44, 91, 62, 99))
        self.assertEqual(FileMagicInfo(data).extension, 'gz')

    def test_file_type_check_runs_the_detector_once(self):
        from unittest import mock
        from refinery.lib import magic
        detector = mock.Mock(wraps=magic._db)
        with mock.patch.object(magic, '_db', detector):
            info = FileMagicInfo(B'The quick brown fox jumps over the lazy dog.')
        self.assertEqual(info.mime, 'text/plain')
        self.assertEqual(detector.best_magic_buffer.call_count, 1)
