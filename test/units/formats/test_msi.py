import json
import hashlib

import pytest

from refinery.lib.ole.file import OleFile
from refinery.units.formats.office.xtdoc import convert_msi_name

from .. import TestUnitBase

_MSI_NAME_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._'


def _rename_stream(data: bytes | bytearray, name: str, new_name: str) -> bytearray:
    """
    Writes a new name into the directory entry of the stream whose name decodes to the given one.
    """
    [old_name] = [item[-1] for item in OleFile(data).listdir() if convert_msi_name(item[-1]) == name]
    entry = F'{old_name}\0'.encode('utf-16le')
    renamed = bytearray(data)
    offsets = []
    offset = renamed.find(entry)
    while offset >= 0:
        if int.from_bytes(renamed[offset + 0x40:offset + 0x42], 'little') == len(entry):
            offsets.append(offset)
        offset = renamed.find(entry, offset + 1)
    [offset] = offsets
    entry = F'{new_name}\0'.encode('utf-16le')
    renamed[offset:offset + 0x40] = entry.ljust(0x40, B'\0')
    renamed[offset + 0x40:offset + 0x42] = len(entry).to_bytes(2, 'little')
    return renamed


@pytest.mark.cythonized
class TestMSI(TestUnitBase):

    def test_real_world_01(self):
        data = self.download_sample('5316330427de98c60661233369909132f6b838b5ff111f7f29efe3e90636a34a')
        msi = data | self.load() | {'path': ...}
        for path in (
            'MsiTables/ActionText.csv',
            'MsiTables/AdminExecuteSequence.csv',
            'MsiTables/AdminUISequence.csv',
            'MsiTables/AdvtExecuteSequence.csv',
            'MsiTables/Binary.csv',
            'MsiTables/CheckBox.csv',
            'MsiTables/Component.csv',
            'MsiTables/Control.csv',
            'MsiTables/ControlCondition.csv',
            'MsiTables/ControlEvent.csv',
            'MsiTables/CustomAction.csv',
            'MsiTables/Dialog.csv',
            'MsiTables/Directory.csv',
            'MsiTables/Error.csv',
            'MsiTables/EventMapping.csv',
            'MsiTables/Feature.csv',
            'MsiTables/FeatureComponents.csv',
            'MsiTables/InstallExecuteSequence.csv',
            'MsiTables/InstallUISequence.csv',
            'MsiTables/LaunchCondition.csv',
            'MsiTables/Property.csv',
            'MsiTables/RadioButton.csv',
            'MsiTables/Registry.csv',
            'MsiTables/TextStyle.csv',
            'MsiTables/UIText.csv',
            'MsiTables/Upgrade.csv',
            'MsiTables/Validation.csv',
        ):
            self.assertIn(path, msi)
        meta = json.loads(msi['MsiTables.json'])
        self.assertEqual(meta['Property'][19]['Value'], "Típica")
        self.assertContains(msi['Action/basicsmarch.js'], b'FDWPLOVWRX(PIENNNAXXI+ QRQHCMZIEY,NAXXIPIENN+ BJHZRJLZFX)')
        self.assertEqual(hashlib.sha256(msi['Binary/aicustact.dll']).hexdigest(),
            'f2f3ae8ca06f5cf320ca1d234a623bf55cf2b84c1d6dea3d85d5392e29aaf437')

    def test_cab_extraction(self):
        data = self.download_sample('5c698edeba5260b1eb170c375015273324b86bae82722d85d2f013b22ae52d0c')
        msi = data | self.load() | {'path': ...}
        cab = '_A43DCF057E5B03E2396812E1C2F1D349'
        for t in '123de':
            self.assertIn(F'{cab}/{t}', msi)
        self.assertEqual(msi[F'{cab}/1'], B'M')
        self.assertEqual(msi[F'{cab}/2'], B'Z')


@pytest.mark.cythonized
class TestMSIRepeatedNames(TestUnitBase):
    """
    The installers of these tests were built with the Windows Installer database engine and the
    Windows cabinet compressor through msilib of Python 3.12. Each of them installs two files named
    readme.txt into two different folders.
    """

    READMES = [B'readme of folder one\r\n', B'readme of folder two\r\n']

    def _readmes(self, data: bytes | bytearray) -> list[bytes]:
        return [bytes(chunk) for chunk in data | self.load('readme.txt')]

    def test_files_with_the_same_name_in_different_folders_are_all_extracted(self):
        data = self.download_sample('b963435f5bc9ddc70142637688a17ee16227f7c8171608b074c64fd92320e7da')
        self.assertCountEqual(self._readmes(data), self.READMES)

    def test_files_from_the_cabinet_are_extracted_at_their_install_path(self):
        data = self.download_sample('b963435f5bc9ddc70142637688a17ee16227f7c8171608b074c64fd92320e7da')
        self.assertEqual(data | self.load('files/*') | {'path': bytes}, {
            'files/one/readme.txt': B'readme of folder one\r\n',
            'files/two/readme.txt': B'readme of folder two\r\n',
        })

    def test_the_streams_of_the_tables_are_not_extracted_next_to_the_tables(self):
        data = self.download_sample('b963435f5bc9ddc70142637688a17ee16227f7c8171608b074c64fd92320e7da')
        paths = [str(path) for path in data | self.load(list=True)]
        self.assertIn('MsiTables/File.csv', paths)
        self.assertEqual([path for path in paths if path.startswith('!')], [])

    def test_a_stream_named_like_the_summary_stream_is_extracted_next_to_it(self):
        data = self.download_sample('e8ee8f4c88d7cf8fe652b20d66407ccb9fc0bc20ce4ccd13d8e13609116ec871')
        streams = [bytes(chunk) for chunk in data | self.load('Meta/SummaryInformation')]
        self.assertEqual(len(streams), 2)
        self.assertIn(B'stream named [5]SummaryInformation', streams)
        # a property set stream starts with the byte order mark FE FF
        self.assertTrue(any(stream.startswith(B'\xFE\xFF') for stream in streams))
        self.assertCountEqual(self._readmes(data), self.READMES)

    def test_streams_named_like_outputs_of_the_unit_are_extracted_next_to_them(self):
        data = self.download_sample('50f656e4311b8e28e15d0bad836a9a4ca9ec5b78dbe8b2b49e58465028e55859')
        cabinets = [bytes(chunk) for chunk in data | self.load('files.cab')]
        self.assertEqual(len(cabinets), 2)
        self.assertIn(B'stream named files.cab, not a cabinet', cabinets)
        self.assertTrue(any(cabinet.startswith(B'MSCF') for cabinet in cabinets))
        tables = [bytes(chunk) for chunk in data | self.load('MsiTables.json')]
        self.assertEqual(len(tables), 2)
        self.assertIn(B'stream named MsiTables.json', tables)
        tables.remove(B'stream named MsiTables.json')
        self.assertEqual(len(json.loads(tables[0])['File']), 2)
        self.assertCountEqual(self._readmes(data), self.READMES)

    def test_a_custom_table_named_like_the_folder_of_the_tables_leaves_the_table_file_its_name(self):
        data = self.download_sample('0a3d5e903e416b0c3624098e682a136234c77784cae99e17e217219b617404dd')
        msi = data | self.load() | {'path': ...}
        self.assertEqual(json.loads(msi['MsiTables.json'])['MsiTables'], [{'Key': 'row'}])
        self.assertIn('MsiTables/MsiTables.csv', msi)

    def test_a_stream_whose_name_decodes_like_a_table_does_not_replace_the_table(self):
        data = self.download_sample('50f656e4311b8e28e15d0bad836a9a4ca9ec5b78dbe8b2b49e58465028e55859')
        in_plain_text = '!Media'
        in_single_characters = chr(0x4840) + ''.join(chr(0x4800 + _MSI_NAME_ALPHABET.index(c)) for c in 'Media')
        for planted in (in_plain_text, in_single_characters):
            with self.subTest(planted=ascii(planted)):
                self.assertEqual(convert_msi_name(planted), '!Media')
                msi = _rename_stream(data, 'MsiTables.json', planted)
                self.assertCountEqual(self._readmes(msi), self.READMES)
                self.assertEqual(msi | self.load('!Media') | bytes, B'stream named MsiTables.json')

    def test_two_streams_with_the_same_name_each_hand_out_their_own_content(self):
        data = self.download_sample('e8ee8f4c88d7cf8fe652b20d66407ccb9fc0bc20ce4ccd13d8e13609116ec871')
        data = _rename_stream(data, '[5]SummaryInformation', '\x05SummaryInformation')
        streams = [bytes(chunk) for chunk in data | self.load('Meta/SummaryInformation')]
        self.assertEqual(len(streams), 2)
        self.assertIn(B'stream named [5]SummaryInformation', streams)
        # a property set stream starts with the byte order mark FE FF
        self.assertTrue(any(stream.startswith(B'\xFE\xFF') for stream in streams))


class TestMSIFormattedStrings(TestUnitBase):

    def test_files_and_components_are_looked_up_in_their_own_tables(self):
        import json
        from refinery.units.formats.msi import _formatting_tables
        data = self.download_sample('5c698edeba5260b1eb170c375015273324b86bae82722d85d2f013b22ae52d0c')
        tables = json.loads(data | self.load('MsiTables.json') | bytes)
        properties, files, components = _formatting_tables(tables)
        self.assertEqual(files['_524559CCC17A414796ED4E25309ABCED'], '1|1')
        self.assertEqual(components['C__524559CCC17A414796ED4E25309ABCED'], '%TARGETDIR%')
        self.assertFalse(properties.keys() & files.keys())
        self.assertFalse(properties.keys() & components.keys())

    def _format(self, string: str, **properties: str) -> str:
        from refinery.units.formats.msi import _format
        return _format(string, properties, {}, {})

    def test_a_property_value_that_names_a_property_is_not_formatted_again(self):
        self.assertEqual(self._format('[PropC]', PropA='a', PropB='[PropA]', PropC='[PropB]'), '[PropB]')

    def test_a_nested_property_is_formatted_from_the_inside_out(self):
        self.assertEqual(self._format('[[PropC]]', PropA='a', PropB='[PropA]', PropC='PropB'), '[PropA]')
        self.assertEqual(self._format('[[A]]', A='B', B='value'), 'value')

    def test_a_property_value_that_names_its_own_property_is_formatted_once(self):
        self.assertEqual(self._format('[P]', P='x[P]'), 'x[P]')
        self.assertEqual(self._format('[A]', A='[B]', B='[A]'), '[B]')

    def test_escaped_brackets_and_the_null_character(self):
        self.assertEqual(self._format('[\\[]P[\\]][~]', P='value'), '[P]\0')
