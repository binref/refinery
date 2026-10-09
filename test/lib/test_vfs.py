from refinery.lib.vfs import VirtualFileSystem, VirtualFile
from .. import TestBase


class TestVFS(TestBase):

    def test_io_open(self):
        import io
        with VirtualFileSystem() as vfs:
            vf = VirtualFile(vfs, B'test')
            self.assertEqual(io.open(vf, 'rb').read(), B'test')

    def test_codecs_open(self):
        import codecs
        with VirtualFileSystem() as vfs:
            vf = VirtualFile(vfs, 'test'.encode('utf-16le'))
            self.assertEqual(codecs.open(vf, 'r', encoding='utf-16le').read(), 'test')

    def test_normal_open(self):
        with VirtualFileSystem() as vfs:
            vf = VirtualFile(vfs, B'test')
            self.assertEqual(open(vf, 'rb').read(), B'test')

    def test_stat(self):
        import os
        with VirtualFileSystem() as vfs:
            buffer = self.generate_random_buffer(2012)
            vf = VirtualFile(vfs, buffer)
            self.assertEqual(os.stat(vf).st_size, 2012)

    def test_mmap(self):
        import mmap
        with VirtualFileSystem() as vfs:
            buffer = b'finest refinery'
            vf = VirtualFile(vfs, buffer)
            mapping = mmap.mmap(open(vf, 'rb').fileno(), 0)
            mapping.seek(7)
            self.assertEqual(mapping.read(), B'refinery')
            self.assertEqual(mapping[:6], b'finest')

    def test_a_mapping_converts_to_the_bytes_it_maps(self):
        import mmap
        with VirtualFileSystem() as vfs:
            vf = VirtualFile(vfs, b'finest refinery')
            mapping = mmap.mmap(open(vf, 'rb').fileno(), 0)
            self.assertEqual(bytes(mapping), b'finest refinery')

    def test_a_mapping_to_the_end_of_the_file_starts_at_its_offset(self):
        import mmap
        data = bytes(self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73'))
        offset = mmap.ALLOCATIONGRANULARITY
        with VirtualFileSystem() as vfs:
            vf = VirtualFile(vfs, data)
            mapping = mmap.mmap(open(vf, 'rb').fileno(), 0, offset=offset)
            self.assertEqual(mapping[:16], data[offset:offset + 16])
            self.assertEqual(len(mapping), len(data) - offset)

    def test_read_and_write(self):
        with VirtualFileSystem() as vfs:
            vf1 = VirtualFile(vfs)
            with open(vf1, 'wb') as stream:
                stream.write(b'test')
            self.assertEqual(vf1.data, b'test')
            with open(vf1, 'rb') as stream:
                self.assertEqual(stream.read(), b'test')
            with open(vf1, 'wb') as stream:
                stream.write(b'refined')
            with open(vf1, 'rb') as stream:
                self.assertEqual(stream.read(), b'refined')

    def test_a_mapped_view_leaves_nothing_to_the_collector(self):
        import mmap
        data = bytes(self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73'))

        def view():
            with VirtualFileSystem() as vfs:
                vf = VirtualFile(vfs, bytearray(data))
                with open(vf, 'rb') as stream:
                    mapping = mmap.mmap(stream.fileno(), 0)
                    self.assertEqual(mapping[:2], B'MZ')

        self.assertCollectorFreesLessThan(0x40000, view)
