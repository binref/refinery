import io
import tarfile

from .. import TestUnitBase


def _make_tar(name: str = 'test.txt', content: bytes = b'hello world') -> bytes:
    buf = io.BytesIO()
    with tarfile.open(mode='w', fileobj=buf) as t:
        info = tarfile.TarInfo(name=name)
        info.size = len(content)
        t.addfile(info, io.BytesIO(content))
    return buf.getvalue()


class TestCarveTar(TestUnitBase):

    def test_carve_single_tar(self):
        tar = _make_tar()
        # carve_tar uses data.find(b'ustar', offset) > 0 so tar must not start at byte 0
        data = b'\x00' * 32 + tar + b'\xFF' * 64
        unit = self.load()
        result = data | unit | []
        self.assertEqual(len(result), 1)
        # Verify the carved result is a valid tar
        with tarfile.open(mode='r', fileobj=io.BytesIO(bytes(result[0]))) as t:
            members = t.getnames()
        self.assertIn('test.txt', members)

    def test_carve_no_tar(self):
        data = b'\x00' + self.generate_random_buffer(512)
        unit = self.load()
        result = data | unit | []
        self.assertEqual(len(result), 0)
