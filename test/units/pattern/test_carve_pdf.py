from .. import TestUnitBase


class TestCarvePdf(TestUnitBase):

    def test_single_pdf(self):
        pdf = b'%PDF-1.4\n1 0 obj\n<< >>\nendobj\n%%EOF\n'
        data = b'junk' + pdf + b'more junk'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(bytes(results[0]), pdf)

    def test_multiple_pdfs(self):
        pdf1 = b'%PDF-1.4\nsome content\n%%EOF\n'
        pdf2 = b'%PDF-1.7\nother content\n%%EOF\n'
        data = b'header' + pdf1 + b'middle' + pdf2 + b'trailer'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 2)
        self.assertEqual(bytes(results[0]), pdf1)
        self.assertEqual(bytes(results[1]), pdf2)

    def test_no_pdf(self):
        data = b'This is not a PDF file at all.'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 0)

    def test_pdf_at_start(self):
        pdf = b'%PDF-1.5\ncontent here\n%%EOF'
        unit = self.load()
        results = pdf | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(bytes(results[0]), pdf)

    def test_pdf_without_eof(self):
        data = b'%PDF-1.4\nsome content without trailer'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 0)

    def test_offset_metadata(self):
        padding = b'X' * 100
        pdf = b'%PDF-1.4\ncontent\n%%EOF\n'
        data = padding + pdf
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['offset'], 100)

    def test_eof_with_crlf(self):
        pdf = b'%PDF-1.4\ncontent\n%%EOF\r\n'
        data = b'junk' + pdf + b'more'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(bytes(results[0]), pdf)
