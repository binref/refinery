from ... import TestUnitBase

import pytest

from refinery.lib.zip import ZipCompressionMethod


@pytest.mark.cythonized
class TestZipFileExtractor(TestUnitBase):

    def test_winzip_self_extracting_archive(self):
        data = self.download_sample('43db90bee13041cf0a53ca97f89054bc26465fe575ed40b1cb6476f3119cd8c1')
        self.assertEqual(
            str(data | self.load('1386431813jtun_streamset.zip') | self.load('stream.dis')),
            'MOVE([TempDir],%StreamDefDir%)')

    def test_password_protected_zip(self):
        data = bytes.fromhex(
            '504B03041400010000001505FA5496732F8E130000000700000008000000746573742E7478749C4E'
            '1F7FD879AA31F390F53CCD310BA615503F504B01023F001400010000001505FA5496732F8E130000'
            '0007000000080024000000000000002000000000000000746573742E7478740A0020000000000001'
            '0018000C83349177A0D8010C83349177A0D801EA64048F77A0D801504B050600000000010001005A'
            '000000390000000000'
        )
        put = self.ldu('put', 'p', 'refined')
        xtzip = self.load(pwd='var:p')
        self.assertEqual(str(data | put[xtzip]), 'foobar.')

    def test_empty_filename(self):
        data = bytes.fromhex(
            '504b0304140000080e00359eff54a5004e70a90000009400000000000000091405005d0000000100'
            '03008cc274baf7b3de2d96ead6a430098a4c88fdaddf5f4c29a3233472aedccfebda2bafb00162f0'
            '84cf660a7824199d6a3e1f68766e78dc5539561a8a1cfaba3192d7daee41449e4304188998b59f2a'
            'e06dc233c9e7164eef4055a129a79bc044c7eaab667314030b8dcc20535c0c003b681ae3a08c6f10'
            'cdc06d140dbe7a5c56d19085ce86d93feb2031a5a36e92cd085ceca38044f84eb0ec8d04f1800050'
            '4b01021400140000080e00359eff54a5004e70a90000009400000000000000000000000000000000'
            '0000000000504b050600000000010001002e000000c700000000000505050505'
        )
        unit = self.load()
        result, = data | unit
        self.assertEqual(result[:12], b'\x06\x02\0\0\0\xA4\0\0RSA1')

    def _flareon_zip(self) -> bytearray:
        data = self.download_sample('2c0d61aee8b3db82fb023fa5592c6dec996259129a0e9d4490da34517851b8cb')
        return bytearray(data | self.ldu('lzma') | self.ldu('carve_zip') | bytes)

    def _flareon_zip_with_method(self, method: int) -> bytearray:
        data = self._flareon_zip()
        for signature, offset in ((B'PK\x03\x04', 8), (B'PK\x01\x02', 10)):
            position = data.find(signature) + offset
            data[position:position + 2] = method.to_bytes(2, 'little')
        return data

    def test_reduce_factor_1_with_zipcrypto(self):
        data = self._flareon_zip()
        self.assertEqual(data | self.load(pwd='infected') | bytes, B'reduce_not_deflate')

    def test_lenient_extraction_of_unsupported_method_yields_decrypted_data(self):
        data = self._flareon_zip_with_method(ZipCompressionMethod.TOKENIZE)
        # 256 empty follower sets take 6 zero bits each, followed by the 18 plain bytes
        self.assertEqual(data | self.load(pwd='infected', lenient=1) | bytes, bytes(192) + B'reduce_not_deflate')

    def test_lenient_extraction_of_unknown_method_yields_decrypted_data(self):
        data = self._flareon_zip_with_method(0x4242)
        # 256 empty follower sets take 6 zero bits each, followed by the 18 plain bytes
        self.assertEqual(data | self.load(pwd='infected', lenient=1) | bytes, bytes(192) + B'reduce_not_deflate')

    def test_shrink_with_partial_clears_and_reduce_factor_4(self):
        data = self.download_sample('4e5967b2314677e10990ea64e4ef2b2a0050d884af4ca729db38a3497eac419c')
        chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | self.load()}
        self.assertEqual(len(chunks), 10)
        self.assertEqual(chunks['STAR.BAT'], '8ee7e11de572ee4c3c9eac3b1dd94a797a3fe57d5a3671274bdda3347675c3e8')
        self.assertEqual(chunks['STAR14.EXE'], '75ad32baf2bef37689feac82e62087aca7a6a9a533eaf2fc1c99fadb1e0c0a6c')
        # no independent Reduce decoder was available; the CRC-32 in the archive confirms this value
        self.assertEqual(chunks['STAR14.DOC'], 'ceeb302e3f10efaf65f06fa202f49573ddfaa7d575b5c7cb87b6eab0c8372961')

    def test_shrink_and_reduce_factor_2(self):
        data = self.download_sample('3fb198642cf2fd5d21fd3d49bed78e17b3bb2862f640bd19ff1e6c38fb0c22b0')
        chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | self.load()}
        self.assertEqual(len(chunks), 20)
        self.assertEqual(chunks['WININFO.TXT'], '5ce31098312df3aadb89506854092e8a5225ce4f244a3d5cd04aaaa9f0b4703d')
        # no independent Reduce decoder was available; the CRC-32 in the archive confirms this value
        self.assertEqual(chunks['APPLETS.TXT'], 'f4e5d21f5e39be15eeaa1140f39c8fbafa530062253151b864d4096b07bffe77')

    def test_reduce_factor_3(self):
        data = self.download_sample('9ce14fc9d6c2e1fcbaa2b37c64739169b2eafeea44365ce04ed20ac5f729dfcf')
        chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | self.load()}
        # no independent Reduce decoder was available; the CRC-32 in the archive confirms this value
        self.assertEqual(chunks, {'PLOTSORT.LSP': 'a302ab23e26e8e07ef41156d9a51d64d0f8ad617b761e217fb23223800c1155b'})

    def test_implode_with_all_window_sizes_and_literal_modes(self):
        data = self.download_sample('fae6599231c61f16f063d7ea93d6861decf2335f00ad1dd61b97295bb1c3412b')
        chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | self.load()}
        self.assertEqual(len(chunks), 18)
        self.assertEqual(chunks['REGISTRN.FRM'], '23f181a1879d8ffedd0d9802e489d43b103a44d815f55d0ad1806dbb83217a44')
        self.assertEqual(chunks['MYSTICIN.EXE'], 'f62bf13803b528b204e33b87d09fc5b0df1e61a9d18f57cd48fe2d8e82021f06')
        self.assertEqual(chunks['READ.ME'], '3457f9406fd8a9c990dc1cd3633d02ec32146cb3c18b8512c5d470eb687219ec')
        self.assertEqual(chunks['PAS3.DOC'], 'a4f201e6350be1a07dd4f9f140461cdef1f1d04f468398c995014dc4a8c9c891')

    def test_implode_with_minimum_match_length_of_pkzip_101(self):
        data = self.download_sample('f36d9551c1917a7990db2b4582191656d748179ea2bd15499294388e9c4fa458')
        chunks = {chunk['path']: repr(chunk['sha256']) for chunk in data | self.load()}
        chunks.pop('.0x00000.cave')
        self.assertEqual(len(chunks), 13)
        self.assertEqual(chunks['DEDICATE.DOC'], 'edc82bf30189cccb2c5ab3a18d212149ba82e3c14c700ea58433389a3d1e8f7e')
        # neither Info-ZIP UnZip nor 7-Zip extract these; the CRC-32 in the archive confirms these values
        self.assertEqual(chunks['README.DOC'], 'dcfed6f11652fe234c7c6228f0cc22990758e37b6bc4b09fae9f63a1788fae85')
        self.assertEqual(chunks['ORDER.DOC'], 'e68d15db0ea53209cfb4707accf1cff9f18ed8912974e009a39e77b45e130c9f')
        self.assertEqual(chunks['OMBUDSMN.ASP'], '890f95b60c8e93e6cfd468c7e42a246c6fb6adfb7f62fe3c79841cce2f432222')
