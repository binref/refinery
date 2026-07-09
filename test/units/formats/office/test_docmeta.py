from __future__ import annotations

import inspect
import json

from refinery.lib.access import (
    VbaReference,
    _parse_import_export_spec,
    _parse_libid,
    _parse_vba_references,
)

from ... import TestUnitBase


_VBAPATH = 'VBAProfilePaths'


class TestDocMetaAccessObjects(TestUnitBase):
    def test_real_world_01(self):
        data = self.download_sample('05ab72c190dca23678705523e7fdcca163cf7f46a331ddec7cbb203130177b78')
        self.assertTrue(self.unit().handles(data))
        test = data | self.load() | json.loads
        self.assertEqual(test['Created'], '2015-05-11 15:04:09')
        self.assertEqual(test['Updated'], '2017-12-19 15:52:22')
        self.assertEqual(test['Engine'], 'Jet4')
        self.assertEqual(test[_VBAPATH], [
            R'C:\Users\amiranda\Documents\Embarcadero\Studio\Projects\IFUniversal\ifu.dll'])

    def test_real_world_02(self):
        data = self.download_sample('fed625c5a4b8c8d50334018921bd200c7b1eb7fcc3add5f842cbee20257720ac')
        self.assertTrue(self.unit().handles(data))
        test = data | self.load() | json.loads
        self.assertEqual(test['Created'], '2008-06-06 16:40:04')
        self.assertEqual(test['Updated'], '2021-06-10 16:44:30')
        self.assertEqual(test[_VBAPATH], [
            R'C:\Users\dyd_l\AppData\Local\Kingsoft\WPS Office\11.1.0.10495\office6\vbe6ext.olb'])

    def test_engine_reported(self):
        data = self.download_sample('afdf496b673b9db6f695ab79edfb7d7b59aae1e732470f6085f7954cfc86a744')
        self.assertTrue(self.unit().handles(data))
        test = data | self.load() | json.loads
        self.assertEqual(test['Created'], '2026-03-11 13:21:06')
        self.assertEqual(test['Updated'], '2026-03-11 13:21:06')
        self.assertEqual(test['Engine'], 'ACE12')
        self.assertEqual(len(test), 3)

    def test_does_not_handle_non_office(self):
        self.assertFalse(bool(self.unit().handles(b'\x7fELF' + b'\0' * 100)))


class TestDocMetaOOXML(TestUnitBase):

    def test_real_world_docx(self):
        data = self.download_sample('36c856d2bf531eb27745f04afe89b9a86035fb6808966001cec9fb751e3e90e3')
        test = data | self.load() | json.loads
        self.assertEqual(test['core']['creator'], 'Adobe')
        self.assertEqual(test['app']['Application'], 'Microsoft Office Word')


class TestVbaReferenceParser(TestUnitBase):

    def test_parse_libid_full(self):
        text = (
            '*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\system32\\stdole2.tlb#OLE Automation'
        )
        self.assertEqual(
            _parse_libid(text),
            VbaReference(
                guid='00020430-0000-0000-C000-000000000046',
                version='2.0',
                lcid='0',
                path='C:\\Windows\\system32\\stdole2.tlb',
                description='OLE Automation',
            ),
        )

    def test_parse_libid_without_description(self):
        text = '*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\a.tlb'
        self.assertEqual(
            _parse_libid(text),
            VbaReference(
                guid='00020430-0000-0000-C000-000000000046',
                version='2.0',
                lcid='0',
                path='C:\\a.tlb',
                description='',
            ),
        )

    def test_parse_libid_rejects_wrong_marker(self):
        self.assertIsNone(_parse_libid('G{123}#2.0#0#path'))

    def test_parse_libid_rejects_too_few_fields(self):
        self.assertIsNone(_parse_libid('*\\G{123}#2.0#0'))

    def test_parse_references_requires_header(self):
        libid = '*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\a.tlb#OLE Automation'.encode('utf-16-le')
        stream = b'\x00\x00' + len(libid).to_bytes(2, 'little') + libid
        self.assertEqual(_parse_vba_references(stream), [])

    def test_parse_references_reads_length_prefixed_record(self):
        libid = '*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\a.tlb#OLE Automation'.encode('utf-16-le')
        header = (0x61CC).to_bytes(2, 'little') + b'\x00' * 5
        stream = header + len(libid).to_bytes(2, 'little') + libid
        references = _parse_vba_references(stream)
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0].path, 'C:\\a.tlb')

    def test_parse_references_rejects_length_overrun(self):
        libid = '*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\a.tlb#OLE Automation'.encode('utf-16-le')
        header = (0x61CC).to_bytes(2, 'little') + b'\x00' * 5
        overrun = (len(libid) + 200).to_bytes(2, 'little')
        stream = header + overrun + libid
        self.assertEqual(_parse_vba_references(stream), [])

    def test_parse_references_rejects_odd_length_prefix(self):
        libid = '*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\a.tlb#OLE Automation'.encode('utf-16-le')
        header = (0x61CC).to_bytes(2, 'little') + b'\x00' * 5
        odd = (len(libid) + 1).to_bytes(2, 'little')
        stream = header + odd + libid
        self.assertEqual(_parse_vba_references(stream), [])


class TestImportExportSpecParser(TestUnitBase):
    _SPEC = inspect.cleandoc(
        """
        <?xml version="1.0" encoding="utf-8" ?>
        <ImportExportSpecification Path = "C:\\Users\\mctan\\Desktop\\New folder\\Digital Mil Contact Book.accdb" xmlns="urn:www.microsoft.com/office/access/imexspec">
        \t<ExportAccess StructureAndData="true">
        \t\t<AccessObject Source="Digital Mil Contact Book" ObjectType="Macro" Destination="Digital Mil Contact Book" />
        \t</ExportAccess>
        </ImportExportSpecification>
        """
    )

    def test_parses_path_from_utf16_blob(self):
        blob = self._SPEC.encode('utf-16-le')
        self.assertEqual(_parse_import_export_spec(blob), r'C:\Users\mctan\Desktop\New folder\Digital Mil Contact Book.accdb')

    def test_parses_despite_trailing_padding(self):
        blob = self._SPEC.encode('utf-16-le') + b'\xff\x00\x01'
        self.assertEqual(_parse_import_export_spec(blob), r'C:\Users\mctan\Desktop\New folder\Digital Mil Contact Book.accdb')

    def test_rejects_non_spec_xml(self):
        blob = '<?xml version="1.0"?><Other Path="C:\\x" />'.encode('utf-16-le')
        self.assertIsNone(_parse_import_export_spec(blob))

    def test_rejects_non_utf16(self):
        self.assertIsNone(_parse_import_export_spec(b'\x00'))
