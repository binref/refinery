from ... import TestUnitBase
from .test_doctxt import PARAGRAPHS


class TestOfficeCrypt(TestUnitBase):

    def test_simple_samples(self):
        crypt = self.load('space-cowboy')
        doctxt = self.ldu('doctxt')
        data = self.download_sample('e12a6f21e62a300ee86a26d8a1f876113bebf1b52709421d4894f832dd54bcf1')
        output = str(data | crypt | doctxt)
        for p in PARAGRAPHS:
            self.assertIn(p, output)

    def test_shellcode_example(self):
        unit = self.load()
        data = self.download_sample('e850f3849ea82980cf23844ad3caadf73856b2d5b0c4179847d82ce4016e80ee')
        output = data | unit | bytes
        self.assertGreaterEqual(len(output), 500)

    def test_xls_rc4_cryptoapi(self):
        unit = self.load('test123')
        xlxtr = self.ldu('xlxtr')
        data = self.download_sample('4908a2b6b37f0c16ff3d7ce7b397623d7fcfaca4c4411905755ff512c39d9da5')
        cells = data | unit | bytearray | xlxtr | [bytes]
        self.assertIn(b'Encrypted XLS Test', cells)
        self.assertIn(b'This is a test document for RC4 CryptoAPI encryption.', cells)
        self.assertIn(b'42', cells)

    def test_xls_velvet_sweatshop(self):
        unit = self.load()
        xlxtr = self.ldu('xlxtr')
        data = self.download_sample('c98ed1b2cfb5c4ea5e532d5828097abf9db8d6e3c01e37771fb9dc6cc73cf80b')
        cells = data | unit | bytearray | xlxtr | [bytes]
        self.assertIn(b'VelvetSweatshop Test', cells)
        self.assertIn(b'Default Excel encryption password.', cells)

    def test_xlsx_agile(self):
        unit = self.load('test123')
        xlxtr = self.ldu('xlxtr')
        data = self.download_sample('c8cbea1bf23c50afb4f906b7de313dc34b6460d68d087e774825a9afbeecc300')
        cells = data | unit | bytearray | xlxtr | [bytes]
        self.assertIn(b'Encrypted XLSX Test', cells)
        self.assertIn(b'This tests ECMA-376 Agile encryption.', cells)

    def test_doc_rc4_cryptoapi(self):
        unit = self.load('test123')
        doctxt = self.ldu('doctxt')
        data = self.download_sample('e5dd0f4c6d0a972abdac1dd21b5dc4ea177e84273a6decf3997f6a49b7ec0bed')
        output = data | unit | doctxt | str
        self.assertIn('Encrypted DOC Test', output)
        self.assertIn('RC4 CryptoAPI encryption in Word 97-2003 format', output)

    def test_docx_agile(self):
        unit = self.load('test123')
        doctxt = self.ldu('doctxt')
        data = self.download_sample('cdcbbbd7676384514b280200a3deab7d69e57010353b7e1bf96956a07690e0ff')
        output = data | unit | doctxt | str
        self.assertIn('Encrypted DOCX Test', output)
        self.assertIn('ECMA-376 Agile encryption in modern Word format', output)

    def test_ppt_rc4_cryptoapi(self):
        unit = self.load('test123')
        data = self.download_sample('fd5de8e6396021bd604307d62c724d27f04d06b6aef2cf6450c749cfdd43acd0')
        output = data | unit | bytes
        self.assertIn(b'Encrypted PPT Test', output)
        self.assertIn(b'RC4 CryptoAPI encryption in PowerPoint 97-2003 format', output)
