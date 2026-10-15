import io

from refinery.lib.frame import Chunk
from refinery.units.formats.pdf import xtpdf

from .. import TestUnitBase


class TestPDF(TestUnitBase):

    def test_pdf_maldoc_with_embedded_flash(self):
        data = self.download_sample('76b19c1e705328cab4d98e546095eb5eb601d23d8102e6e0bfb0a8a6ab157366')

        test = data | self.load('raw/*', list=True) | {str}
        self.assertLessEqual({
            'raw/Root/Metadata',
            'raw/Root/OpenAction/JS',
            'raw/Root/Pages/Kids/0/Annots/0/NM',
            'raw/Root/Pages/Kids/0/Annots/0/RichMediaContent/Assets/Names/1/fqMBgzoMVutzNwk.swf',
        }, test)

        unit = self.load('Pages/*NM', 'Pages/*.swf')
        name, swf = data | unit
        self.assertEqual(name, B'fqMBgzoMVutzNwk.swf')
        self.assertEqual(swf[:3], B'CWS')

        unit = self.load('fqMBgzoMVutzNwk') | self.ldu('sha256', text=True)
        self.assertEqual(data | unit | str,
            'c2b666a3ef4c191b77b78c037656e50477b8ba3d35fd61ae843a3a1f4d41c5c1')

    def test_values_equal_to_values_found_earlier_are_extracted(self):
        data = self.download_sample('76b19c1e705328cab4d98e546095eb5eb601d23d8102e6e0bfb0a8a6ab157366')
        test = data | self.load('raw/ID/*', 'raw/Info/*Date') | {'path': bytes}
        self.assertEqual(test['raw/ID/1'], test['raw/ID/0'])
        self.assertEqual(test['raw/Info/ModDate'], test['raw/Info/CreationDate'])

    def _with_junk(self, junk) -> bytes:
        import pikepdf
        data = self.download_sample('76b19c1e705328cab4d98e546095eb5eb601d23d8102e6e0bfb0a8a6ab157366')
        pdf = pikepdf.open(io.BytesIO(data))
        pdf.Root.Junk = junk(pdf)
        output = io.BytesIO()
        pdf.save(output)
        return output.getvalue()

    def test_a_file_entry_that_points_at_its_own_container_ends(self):
        import pikepdf

        def junk(pdf):
            holder = pdf.make_indirect(pikepdf.Dictionary())
            holder.Spec = pikepdf.Dictionary(F=pikepdf.String('a.bin'), EF=pikepdf.Dictionary(F=holder))
            return holder

        data = self._with_junk(junk)
        test = data | self.load('fqMBgzoMVutzNwk') | self.ldu('sha256', text=True) | str
        self.assertEqual(test, 'c2b666a3ef4c191b77b78c037656e50477b8ba3d35fd61ae843a3a1f4d41c5c1')

    def test_a_stream_embedded_under_many_names_comes_out_under_each_name_decoded_once(self):
        import pikepdf

        def junk(pdf):
            spec = pdf.Root.Pages.Kids[0].Annots[0].RichMediaContent.Assets.Names[1]
            return pikepdf.Array([
                pikepdf.Dictionary(F=pikepdf.String(F'x{k}.swf'), EF=pikepdf.Dictionary(F=spec.EF.F))
                for k in range(20)
            ])

        original = self.download_sample('76b19c1e705328cab4d98e546095eb5eb601d23d8102e6e0bfb0a8a6ab157366')
        swf = original | self.load('fqMBgzoMVutzNwk') | bytes
        self.assertEqual(swf[:3], B'CWS')
        data = self._with_junk(junk)
        results = xtpdf().unpack(Chunk(data))
        names = {result.path: result.get_data() for result in results if 'Junk' in result.path}
        self.assertEqual(set(names), {F'raw/Root/Junk/{k}/x{k}.swf' for k in range(20)})
        self.assertTrue(all(embedded == swf for embedded in names.values()))
        self.assertEqual(len({id(embedded) for embedded in names.values()}), 1)
