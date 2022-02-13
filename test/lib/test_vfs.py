#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
