# flake8: noqa
import hashlib

from unittest import mock

from ... import TestUnitBase

from refinery.lib.inno.archive import InnoArchive, InvalidPassword


class TestInnoExtractor(TestUnitBase):

    def test_real_world_01_script(self):
        test = (
            self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73')
            | self.load('script.bin')
            | self.ldu('ifpsstr')
                [ self.ldu('rev')
                | self.ldu('vigenere', 'm')
                | self.ldu('iffp', 'url') ]
            | str
        )
        self.assertEqual(test, 'http''s:/''/t.''me/+r1hwDlb8VAI5ZTQy')

    def test_v_5_5_00_pwd(self):
        data = self.download_sample('aeac18c433de1a62b6b9106a9424028d4c2731d3f7b378088e7b305213432a42')
        test = data | self.load('HalfTime.dll') | self.ldu('sha256', text=True) | str
        self.assertEqual(test, 'e91b33814738947981595f529e6de370dae57623a67f3531ce238363d657e18e')

    def test_real_world_02_script(self):
        test = (
            self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73')
            | self.load('script.ps') | str
        )
        self.assertNotIn('LocalVar3 := Argument2', test)
        self.assertIn   ('LocalVar3 := Argument1', test) # noqa

    def test_real_world_01_file(self):
        test = (
            self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73')
            | self.load('idp.dll')
            | self.ldu('pemeta')
            | self.ldu('xtjson', 'ProductName')
            | str
        )
        self.assertEqual(test, 'Inno Download Plugin')

    def test_v_6_3_00(self):
        test = (
            self.download_sample('eeafd3fe2280e065aac87ca8b210be5873be5fe1f51ca4156d12bcf4f0d1eb1e')
            | self.load('script.bin')
            | self.ldu('ifpsstr')
                [ self.ldu('iffp', 'url')
                | self.ldu('urlfix')
                | self.ldu('dedup')
            ]| str
        )
        self.assertEqual(test, 'ht''tps:''//mealkittens''.''cfd/exte.php')

    def test_v_5_2_01(self):
        test = (
            self.download_sample('0c9ffd51196d71bba19a708bb64224be87c8fceb0b22b71262080c1055b5a642')
            | self.load('arrow.x')
            | str
        )
        self.assertIn('6f0d123b-bad2-4167-a0d0-80224f25fabb', test)

    def test_v_5_5_07(self):
        test = (
            self.download_sample('9271acdc528deb7d971f742c94d772b1f408b5db00ae949f79221a3545f41314')
            | self.load('History.txt')
            | str
        )
        self.assertIn('5, UltraISO 4.1 (July 28, 2002)', test)

    def test_proc_ptr_parsing(self):
        data = self.download_sample('cdbc92e0d280e54a66c347b0178d0b34a9ee8fc6c241ebfeb48bdcb31ddd774c')
        ifps = data | self.load('script.ps') | str
        self.assertIn('LocalVar3 := &RADIOBUTTONQUICKONCLICK', ifps)

    def test_the_archive_does_not_keep_the_uninstaller_after_reading_it(self):
        inno = InnoArchive(self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73'))
        uninstaller = inno.read_stream(inno.streams.Uninstaller)
        self.assertEqual(uninstaller[:2], B'MZ')
        self.assertIsNone(inno.streams.Uninstaller.data)

    def test_a_chunk_is_read_decompressed(self):
        inno = InnoArchive(self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73'))
        file = next(file for file in inno.files if file.size and not file.filtered)
        chunk = inno.read_chunk(file)
        self.assertEqual(chunk[file.offset:file.offset + file.size], inno.read_file(file))

    @staticmethod
    def _checked_digests_of_the_chunk(data: bytearray, chunk_offset: int) -> list[bytes | None]:
        """
        The digests of the files in the given chunk in the order of their data, where a file that
        cannot be read or fails its checksum has the digest `None`.
        """
        inno = InnoArchive(data)
        files = sorted((f for f in inno.files if f.chunk_offset == chunk_offset and f.size), key=lambda f: f.offset)
        extractors = [inno.extractor(file) for file in files]
        digests = []
        for file, extract in zip(files, extractors):
            try:
                digests.append(hashlib.sha256(inno.check_file(file, extract())).digest())
            except Exception:
                digests.append(None)
        return digests

    def test_damage_in_a_solid_bzip2_or_zlib_chunk_fails_only_the_files_from_the_damage_on(self):
        for sample in (
            'd1a18cc03c1ca8901a2521e448acb5074fca2511e51044a028989ecb116a332b',
            '0c05247e69030e6c1678d5c1a4cb05e6cc323b79e428d3fe014cb12adf8f502c',
        ):
            with self.subTest(sample=sample):
                data = bytearray(self.download_sample(sample))
                chunk = max(InnoArchive(data).files, key=lambda f: f.chunk_length)
                intact = self._checked_digests_of_the_chunk(data, chunk.chunk_offset)
                self.assertNotIn(None, intact)
                data[data.index(B'zlb\x1a') + 4 + chunk.chunk_offset + chunk.chunk_length * 3 // 10] ^= 0xFF
                damaged = self._checked_digests_of_the_chunk(data, chunk.chunk_offset)
                extracted = damaged.index(None)
                self.assertGreater(extracted, 0)
                self.assertEqual(damaged[:extracted], intact[:extracted])
                self.assertEqual(damaged[extracted:], [None] * (len(damaged) - extracted))

    DAMAGED_FILE = 'data/{app}/FBDF14B7-BF8D-A74F-A843-5F22543F7A88'

    def _installer_with_one_damaged_file(self) -> bytearray:
        """
        An installer whose largest LZMA chunk has one byte flipped in its middle. The decompressor
        does not notice; the file `DAMAGED_FILE` of that chunk fails its checksum.
        """
        data = bytearray(self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73'))
        chunk = max(InnoArchive(data).files, key=lambda f: f.chunk_length)
        data[data.index(B'zlb\x1a') + 4 + chunk.chunk_offset + chunk.chunk_length // 2] ^= 0xFF
        return data

    def test_a_file_that_fails_its_checksum_fails_with_a_hint_to_use_lenience(self):
        data = self._installer_with_one_damaged_file()
        with self.load_logged() as (unit, log):
            paths = [chunk['path'] for chunk in data | unit | [...]]
        self.assertIn('data/{tmp}/idp.dll', paths)
        self.assertNotIn(self.DAMAGED_FILE, paths)
        self.assertEqual(len(log), 1)
        self.assertIn(self.DAMAGED_FILE, log[0])
        self.assertTrue(log[0].endswith('(use -L to extract it anyway)'))

    def test_a_file_that_fails_its_checksum_comes_out_under_lenience_with_a_warning_unless_quiet(self):
        data = self._installer_with_one_damaged_file()
        with self.load_logged('-L') as (unit, log):
            paths = [chunk['path'] for chunk in data | unit | [...]]
        self.assertIn(self.DAMAGED_FILE, paths)
        self.assertEqual(len(log), 1)
        self.assertTrue(log[0].startswith(F'extracting {self.DAMAGED_FILE} despite an error: checksum error'))
        with self.load_logged('-L', '-Q') as (unit, log):
            paths = [chunk['path'] for chunk in data | unit | [...]]
        self.assertIn(self.DAMAGED_FILE, paths)
        self.assertEqual(log, [])

    PASSWORD_FOUND_BY_EMULATION = 'aeac18c433de1a62b6b9106a9424028d4c2731d3f7b378088e7b305213432a42'

    def test_a_read_before_the_password_is_known_does_not_fail_the_reads_after_it_was_guessed(self):
        inno = InnoArchive(self.download_sample(self.PASSWORD_FOUND_BY_EMULATION))
        first, second = (file for file in inno.files if file.encrypted and file.size)
        read_first, read_second = inno.extractor(first), inno.extractor(second)
        with self.assertRaises(InvalidPassword):
            read_first()
        self.assertTrue(inno.guess_password(10))
        data = read_second()
        self.assertIs(inno.check_file(second, data), data)

    def test_running_out_of_memory_in_an_encrypted_chunk_is_not_remembered_as_a_wrong_password(self):
        inno = InnoArchive(self.download_sample(self.PASSWORD_FOUND_BY_EMULATION))
        self.assertTrue(inno.guess_password(10))
        first, second = (file for file in inno.files if file.encrypted and file.size)
        read_first, read_second = inno.extractor(first), inno.extractor(second)
        with mock.patch('refinery.lib.inno.archive.decompress_pieces', side_effect=MemoryError):
            with self.assertRaises(MemoryError):
                read_first()
        data = read_second()
        self.assertIs(inno.check_file(second, data), data)

    def test_a_damaged_chunk_read_with_the_guessed_password_is_not_reported_as_missing_a_password(self):
        data = bytearray(self.download_sample(self.PASSWORD_FOUND_BY_EMULATION))
        chunk = max((file for file in InnoArchive(data).files if file.encrypted), key=lambda f: f.chunk_length)
        data[data.index(B'zlb\x1a') + 4 + chunk.chunk_offset + chunk.chunk_length // 2] ^= 0xFF
        inno = InnoArchive(data)
        self.assertTrue(inno.guess_password(10))
        file = next(file for file in inno.files if file.path == chunk.path)
        with self.assertRaises(InvalidPassword) as error:
            inno.read_file(file)
        self.assertNotEqual(str(error.exception), str(InvalidPassword()))
