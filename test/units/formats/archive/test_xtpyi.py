from ... import TestUnitBase


class TestPyInstallerExtractor(TestUnitBase):

    def test_regular_entry_point_extraction(self):
        data = self.download_sample('1edcad6274bc18804a87ca7e4e8d0ae86649ec3970f25c9323de7c5370f2d8d7')
        unit = self.load(user_code=True)
        carve = self.ldu('carve', 'b64', single=True, decode=True)
        result = str(data | unit | carve)
        self.assertIn("s.connect(('10.0.2.15',3334))", result)
        self.assertIn("uct.unpack('>I',s.recv(4))[0]", result)

    def test_password_protected_archive(self):
        data = self.download_sample('1edcad6274bc18804a87ca7e4e8d0ae86649ec3970f25c9323de7c5370f2d8d7')
        unit = self.load('*/unittest/case.py', unmarshal=2)
        result = str(data | unit)
        self.assertIn(R'difflib.ndiff(pprint.pformat(seq1).splitlines(), pprint.pformat(seq2).splitlines())', result)

    def test_plaintext_entry_point_extraction(self):
        data = self.download_sample('904df5d6b900fcdac44c002f03ab1fbc698b8d421a22639819b3b208aaa6ea2c')
        unit = self.load(user_code=True, decompile=True)
        result = str(data | unit)
        self.assertIn('AESCipher("RVX0WKdzfwd4ynICDqJL9YjUjly1ehv7")', result)

    def test_unprotected_library_extraction(self):
        data = self.download_sample('904df5d6b900fcdac44c002f03ab1fbc698b8d421a22639819b3b208aaa6ea2c')
        unit = self.load('out00-PYZ/uuid.py', unmarshal=2)
        result = str(data | unit)
        self.assertIn('6ba7b810-9dad-11d1-80b4-00c04fd430c8', result)

    _PLAIN = '904df5d6b900fcdac44c002f03ab1fbc698b8d421a22639819b3b208aaa6ea2c'
    _ENCRYPTED = '1edcad6274bc18804a87ca7e4e8d0ae86649ec3970f25c9323de7c5370f2d8d7'

    def _toc_entry(self, data: bytearray, name: str) -> int:
        """
        Returns the position of the table of contents entry with the given name. An entry holds the
        size of the entry, the position and both sizes of the data as big-endian 32-bit integers, a
        compression flag and a type byte, and then the name, padded with zeros.
        """
        encoded = F'{name}\0'.encode('utf8')
        candidates = []
        position = data.find(encoded)
        while position >= 0:
            size = int.from_bytes(data[position - 18:position - 14], 'big')
            if size % 16 == 0 and 18 + len(encoded) <= size <= 0x1000:
                candidates.append(position - 18)
            position = data.find(encoded, position + 1)
        self.assertEqual(len(candidates), 1)
        return candidates[0]

    def _rename(self, data: bytearray, name: str, new_name: str) -> bytearray:
        entry = self._toc_entry(data, name)
        size = int.from_bytes(data[entry:entry + 4], 'big')
        data[entry + 18:entry + size] = new_name.encode('utf8').ljust(size - 18, B'\0')
        return data

    def test_every_entry_of_an_archive_without_an_embedded_pyz_archive_is_extracted(self):
        data = bytearray(self.download_sample(self._PLAIN))
        original = data | self.load() | {'path': bytes}
        # the type of an entry is the byte after its compression flag; x stands for data
        data[self._toc_entry(data, 'out00-PYZ.pyz') + 17] = ord('x')
        files = data | self.load() | {'path': bytes}
        self.assertEqual(set(files), set(original))
        self.assertEqual(files['out00-PYZ.pyz'], original['out00-PYZ.pyz'])
        self.assertEqual(files['_ctypes.pyd'], original['_ctypes.pyd'])

    def test_an_entry_named_like_another_entry_is_extracted_next_to_it(self):
        data = bytearray(self.download_sample(self._PLAIN))
        original = data | self.load() | {'path': bytes}
        files = self._rename(data, '_socket.pyd', '_ctypes.pyd') | self.load() | {'path': bytes}
        self.assertEqual(files['_ctypes.pyd/1'], original['_ctypes.pyd'])
        self.assertEqual(files['_ctypes.pyd/2'], original['_socket.pyd'])
        self.assertEqual(len(files), len(original))

    def test_an_entry_named_like_the_compiled_user_script_is_extracted_next_to_it(self):
        data = bytearray(self.download_sample(self._PLAIN))
        original = data | self.load() | {'path': bytes}
        files = self._rename(data, 'pywintypes27.dll', 'wIJsD0zb6BV4.pyc') | self.load() | {'path': bytes}
        self.assertEqual(files['wIJsD0zb6BV4.pyc/1'], original['wIJsD0zb6BV4.pyc'])
        self.assertEqual(files['wIJsD0zb6BV4.pyc/2'], original['pywintypes27.dll'])

    def test_an_entry_named_like_the_decompiled_user_script_is_extracted_next_to_it(self):
        data = bytearray(self.download_sample(self._PLAIN))
        original = data | self.load(decompile=True) | {'path': bytes}
        data = self._rename(data, 'pywintypes27.dll', 'wIJsD0zb6BV4.py')
        files = data | self.load(decompile=True) | {'path': bytes}
        self.assertEqual(files['wIJsD0zb6BV4.py/1'], original['wIJsD0zb6BV4.py'])
        self.assertEqual(files['wIJsD0zb6BV4.py/2'], original['pywintypes27.dll'])

    def test_a_file_named_like_an_embedded_archive_is_extracted_next_to_it(self):
        data = bytearray(self.download_sample(self._PLAIN))
        original = data | self.load() | {'path': bytes}
        self._rename(data, 'out00-PYZ.pyz', 'out00-PYZ')
        files = self._rename(data, 'requests\\cacert.pem', 'out00-PYZ.pyz') | self.load() | {'path': bytes}
        self.assertEqual(files['out00-PYZ.pyz/1'], original['requests/cacert.pem'])
        self.assertEqual(files['out00-PYZ.pyz/2'], original['out00-PYZ.pyz'])

    def test_the_modules_of_two_embedded_archives_with_the_same_name_lie_in_numbered_folders(self):
        data = bytearray(self.download_sample(self._PLAIN))
        archive = self._toc_entry(data, 'out00-PYZ.pyz')
        entry = self._toc_entry(data, '_socket.pyd')
        # position, both sizes, compression flag and type of the archive's entry
        data[entry + 4:entry + 18] = data[archive + 4:archive + 18]
        self._rename(data, '_socket.pyd', 'out00-PYZ.pyz')
        modules = data | self.load('out00-PYZ/*/uuid.py', unmarshal=2) | {'path': bytes}
        self.assertEqual(set(modules), {'out00-PYZ/1/uuid.py', 'out00-PYZ/2/uuid.py'})
        for module in modules.values():
            self.assertIn(B'6ba7b810-9dad-11d1-80b4-00c04fd430c8', module)

    def test_the_key_of_the_last_key_module_decrypts_the_archive(self):
        data = bytearray(self.download_sample(self._ENCRYPTED))
        key_module = self._toc_entry(data, 'pyimod00_crypto_key')
        importers = self._toc_entry(data, 'pyimod03_importers')
        size = int.from_bytes(data[key_module:key_module + 4], 'big')
        self.assertEqual(size, int.from_bytes(data[importers:importers + 4], 'big'))
        # the key module and the module pyimod03_importers trade places; the latter, now first, gets
        # the name of the key module, so the real key module is the last one with that name
        moved = data[importers:importers + size]
        data[importers:importers + size] = data[key_module:key_module + size]
        data[key_module:key_module + size] = moved
        self._rename(data, 'pyimod03_importers', 'pyimod00_crypto_key')
        result = str(data | self.load('*/unittest/case.py', unmarshal=2))
        self.assertIn(R'difflib.ndiff(pprint.pformat(seq1).splitlines(), pprint.pformat(seq2).splitlines())', result)

    def test_an_archive_whose_last_key_module_holds_no_key_stays_encrypted(self):
        data = bytearray(self.download_sample(self._ENCRYPTED))
        self.assertTrue(data | self.load('*/unittest/case.py', unmarshal=2) | [])
        self._rename(data, 'pyimod01_os_path', 'pyimod00_crypto_key')
        self.assertEqual(data | self.load('*/unittest/case.py', unmarshal=2) | [], [])
