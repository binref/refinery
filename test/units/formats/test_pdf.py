from __future__ import annotations

import io
import tracemalloc
import zlib

from refinery.lib.frame import Chunk
from refinery.lib.mime import FileMagicInfo
from refinery.lib.types import Callable
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

    def _with_a_stream_of_64_megabytes_of_zeros(self) -> bytes:
        import pikepdf

        def junk(pdf):
            stream = pdf.make_stream(zlib.compress(bytes(64 << 20)))
            stream.Filter = pikepdf.Name('/FlateDecode')
            return stream

        return self._with_junk(junk)

    def _peak_of_python_allocations(self, operation: Callable[[], object]) -> int:
        operation()
        tracemalloc.start()
        try:
            operation()
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    def test_listing_a_pdf_decodes_none_of_its_streams(self):
        data = self._with_a_stream_of_64_megabytes_of_zeros()
        paths: list[str] = []
        peak = self._peak_of_python_allocations(lambda: paths.extend(data | self.load(list=True) | [str]))
        self.assertIn('raw/Root/Junk', paths)
        self.assertLess(peak, 16 << 20)

    def test_extracting_some_outputs_of_a_pdf_decodes_no_other_stream(self):
        data = self._with_a_stream_of_64_megabytes_of_zeros()
        chunks: list[Chunk] = []
        peak = self._peak_of_python_allocations(lambda: chunks.extend(data | self.load('raw/Info/*Date') | []))
        self.assertEqual({str(chunk['path']) for chunk in chunks}, {'raw/Info/CreationDate', 'raw/Info/ModDate'})
        self.assertLess(peak, 16 << 20)

    def test_a_stream_is_decoded_when_it_is_extracted(self):
        data = self._with_a_stream_of_64_megabytes_of_zeros()
        self.assertEqual(data | self.load('raw/Root/Junk') | bytes, bytes(64 << 20))

    def _pdf_written_by_pillow(self, mode: str) -> bytes:
        from PIL import Image
        output = io.BytesIO()
        Image.new(mode, (64, 48)).save(output, 'PDF')
        return output.getvalue()

    def _with_flate_in_front_of_the_image_filter(self, data: bytes) -> bytes:
        import pikepdf
        pdf = pikepdf.open(io.BytesIO(data))
        for obj in list(pdf.objects):
            if isinstance(obj, pikepdf.Stream) and obj.get('/Subtype') == '/Image':
                filters = pikepdf.Array([pikepdf.Name('/FlateDecode'), obj['/Filter']])
                obj.write(zlib.compress(obj.read_raw_bytes()), filter=filters)
        output = io.BytesIO()
        pdf.save(output)
        return output.getvalue()

    def test_an_image_is_named_after_the_type_of_its_extracted_data(self):
        jpeg = self._pdf_written_by_pillow('RGB')
        for name, data, extension in (
            ('jpeg', jpeg, 'jpg'),
            ('jpeg behind flate', self._with_flate_in_front_of_the_image_filter(jpeg), 'jpg'),
            ('jpeg 2000', self._pdf_written_by_pillow('RGBA'), 'jp2'),
            ('fax', self._pdf_written_by_pillow('1'), 'png'),
        ):
            images = data | self.load('parsed/page0/img*') | {'path': bytes}
            self.assertEqual(list(images), [F'parsed/page0/img1.{extension}'], name)
            self.assertEqual(FileMagicInfo(images[F'parsed/page0/img1.{extension}']).extension, extension, name)
