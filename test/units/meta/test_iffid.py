from .. import TestUnitBase


class TestIffId(TestUnitBase):

    def test_filter_pdf(self):
        elf = self.download_sample('c5ba314fbf02989af9e2b5edb48626aede10f2d4569095a542ed0f2033068117')
        zip = self.download_sample('e90b970c5e5ddf821d6f9f4d7d710d6dc01d59b517e8fb39da726803dc52b5ad')
        pdf = self.download_sample('302c0d553c9e7f2561864d79022b780a53ec0a5927e8962d883b88dde249d044')
        exe = self.download_sample('ff4ef0ee0915af58ea1388f72730c63c746856a64760e17e4fcdfc559a8b4555')
        rb1 = self.generate_random_buffer(250)
        rb2 = self.generate_random_buffer(700)
        rb3 = self.generate_random_buffer(8)
        chunks: list[bytes | bytearray | memoryview] = [elf, rb1, zip, pdf, rb2, exe, rb3]
        self.assertEqual(chunks | self.load('pdf') | [], [pdf])
        self.assertEqual(chunks | self.load('zip') | [], [zip])
