import json
import inspect

from .. import TestUnitBase


class TestWindowsRegistryExtractor(TestUnitBase):

    def test_duplicate_sections_winreg(self):
        data = self.download_sample('ff548cb8ff1e35ded07207b1488150571c81d5aed93758db11c60d362981a45b')
        test = data | self.load(list=True) | [str]
        self.assertEqual(len(test), 36)
        self.assertIn(R'HKEY_CURRENT_USER/Control Panel/Desktop/HungAppTimeout', test)

    def test_binary_values_in_uppercase_hex_keep_every_byte(self):
        data = self.download_sample('ff548cb8ff1e35ded07207b1488150571c81d5aed93758db11c60d362981a45b')
        items = data | self.load() | {'path': ...}
        self.assertEqual(items['HKEY_CURRENT_USER/Control Panel/Mouse/SmoothMouseXCurve'], bytes.fromhex(
            '0000000000000000'
            'C0CC0C0000000000'
            '8099190000000000'
            '4066260000000000'
            '0033330000000000'
        ))

    def test_registry_export(self):
        unit = self.load()
        data = inspect.cleandoc(
            R"""
            Windows Registry Editor Version 5.00

            [HKEY_CURRENT_USER\Test]
            "Bin"=hex:41,42,43,43,44,44,01,02
            "Str"="This is a \"string value\"."
            "u32"=dword:00000032
            "u64"=hex(b):64,00,00,00,00,00,00,00
            "Multi"=hex(7):4d,00,75,00,6c,00,74,00,69,00,00,00,22,00,53,00,74,00,72,00,69,\
                00,6e,00,67,00,22,00,00,00,56,00,61,00,6c,00,75,00,65,00,21,00,00,00,00,00
            "Exp"=hex(2):25,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,25,00,00,00
            @="Wookie"
            """
        ).encode(unit.codec)
        items = {chunk['path']: chunk for chunk in data | unit}
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/Bin'], B'ABCCDD\x01\x02')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/Str'], B'This is a "string value".')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/u32'], B'0x32')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/u64'], B'0x64')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/Multi.0'], B'Multi')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/Multi.1'], B'"String"')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/Multi.2'], B'Value!')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/Exp'], B'%AppData%')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test'], B'Wookie')

    def test_registry_export_negation(self):
        unit = self.load()
        data = inspect.cleandoc(
            R"""
            Windows Registry Editor Version 5.00

            [HKEY_CURRENT_USER\Test]
            "Bin"=hex:41,42,43,43,44,44,01,02
            "Str"="This is a \"string value\"."
            "u32"=dword:00000032
            @="Wookie"
            """
        ).encode(unit.codec)
        excluded = B'HKEY_CURRENT_USER/Test/Str'

        def paths(*patterns, **kw):
            return {chunk['path'] for chunk in data | self.load(*patterns, **kw)}

        everything = paths()
        self.assertIn(excluded, everything)
        self.assertEqual(paths(exclude=['*Str']), everything - {excluded})
        self.assertEqual(paths('*', exclude=['*Str']), everything - {excluded})
        self.assertEqual(paths(regex=True, exclude=['.*Str']), everything - {excluded})

        # The bare token Str excludes nothing at base fuzziness; it must be escalated to match.
        self.assertEqual(paths(exclude=['Str']), everything - {excluded})
        self.assertEqual(paths(exact=True, exclude=['Str']), everything)

    def test_commandline_in_registry_file(self):
        unit = self.load()
        data = inspect.cleandoc(
            R"""
            Windows Registry Editor Version 5.00

            [HKEY_USERS\COOPER-12\Software\Classes\ms-settings]

            [HKEY_USERS\COOPER-12\Software\Classes\ms-settings\Shell]

            [HKEY_USERS\COOPER-12\Software\Classes\ms-settings\Shell\Open]

            [HKEY_USERS\COOPER-12\Software\Classes\ms-settings\Shell\Open\command]
            @="pcalua -a C:\\d3str0y.exe"
            """
        ).encode(unit.codec)
        items = {chunk['path']: chunk for chunk in data | unit}
        self.assertEqual(items[B'HKEY_USERS/COOPER-12/Software/Classes/ms-settings/Shell/Open/command'], B'pcalua -a C:\\d3str0y.exe')

    def test_hive(self):
        data = self.download_sample('af0be95fd8aafc1ae2839995ad6350fe042c5ef1428c703fa9ff9824f15258e3')
        data = data | self.ldu('lzma') | bytearray
        test = data | self.load(
            'ROOT/SOFTWARE/Microsoft/Windows/CurrentVersion/CloudStore/'
            'Store/DefaultAccount/CloudCacheInvalidator/e883117a-be2c-87f4-4b6a-c7d3652038ac'
        ) | self.ldu('u16') | self.ldu('terminate') | json.loads
        self.assertEqual(test['activityStoreId'], 'E883117A-BE2C-87F4-4B6A-C7D3652038AC')

    def test_hive_excluded_pattern(self):
        token = 'CloudCacheInvalidator'
        excluded = (
            'ROOT/SOFTWARE/Microsoft/Windows/CurrentVersion/CloudStore/'
            'Store/DefaultAccount/CloudCacheInvalidator/e883117a-be2c-87f4-4b6a-c7d3652038ac')
        data = self.download_sample('af0be95fd8aafc1ae2839995ad6350fe042c5ef1428c703fa9ff9824f15258e3')
        data = data | self.ldu('lzma') | bytearray
        full = data | self.load(list=True) | [str]
        excl = data | self.load(exclude=[F'*{token}*'], list=True) | [str]
        self.assertIn(excluded, full)
        self.assertTrue(excl, 'exclusion pruned the entire hive')
        self.assertEqual(set(excl), {path for path in full if token not in path})

    def _export(self, export: str) -> dict[str, bytes]:
        unit = self.load()
        data = inspect.cleandoc(export).encode(unit.codec)
        return {str(chunk['path']): bytes(chunk) for chunk in data | unit | [...]}

    def test_a_value_assigned_twice_in_one_key_keeps_the_last_assignment(self):
        values = self._export(R"""
            Windows Registry Editor Version 5.00

            [HKEY_CURRENT_USER\Software\Run]
            "decoy"="calc.exe"
            "a"="first"
            "a"="second"
            """)
        self.assertEqual(values, {
            'HKEY_CURRENT_USER/Software/Run/decoy': B'calc.exe',
            'HKEY_CURRENT_USER/Software/Run/a': B'second',
        })

    def test_a_key_written_in_two_sections_keeps_the_last_assignment_of_each_value(self):
        values = self._export(R"""
            Windows Registry Editor Version 5.00

            [HKEY_CURRENT_USER\Software\Run]
            "a"="first"
            "b"="kept"

            [HKEY_CURRENT_USER\Software\Other]
            "c"="other"

            [HKEY_CURRENT_USER\Software\Run]
            "a"="second"
            """)
        self.assertEqual(values, {
            'HKEY_CURRENT_USER/Software/Run/a': B'second',
            'HKEY_CURRENT_USER/Software/Run/b': B'kept',
            'HKEY_CURRENT_USER/Software/Other/c': B'other',
        })

    def test_keys_and_value_names_that_differ_only_in_case_name_one_value(self):
        values = self._export(R"""
            Windows Registry Editor Version 5.00

            [HKEY_CURRENT_USER\Software\Run]
            "Updater"="C:\\Program Files\\Vendor\\update.exe"

            [HKEY_CURRENT_USER\SOFTWARE\RUN]
            "updater"="C:\\Users\\Public\\evil.exe"
            """)
        self.assertEqual(values, {
            'HKEY_CURRENT_USER/Software/Run/Updater': B'C:\\Users\\Public\\evil.exe',
        })

    def test_a_value_assigned_a_minus_sign_is_deleted(self):
        values = self._export(R"""
            Windows Registry Editor Version 5.00

            [HKEY_CURRENT_USER\Software\Run]
            "a"="evil"
            "b"="kept"
            "a"=-
            """)
        self.assertEqual(values, {'HKEY_CURRENT_USER/Software/Run/b': B'kept'})

    def test_a_key_with_a_leading_minus_sign_is_deleted_with_its_subkeys(self):
        values = self._export(R"""
            Windows Registry Editor Version 5.00

            [HKEY_CURRENT_USER\Software\Evil]
            "a"="evil"

            [HKEY_CURRENT_USER\Software\Evil\Sub]
            "b"="evil"

            [HKEY_CURRENT_USER\Software\EvilTwin]
            "c"="kept"

            [-HKEY_CURRENT_USER\Software\Evil]
            """)
        self.assertEqual(values, {'HKEY_CURRENT_USER/Software/EvilTwin/c': B'kept'})

    def test_a_value_with_a_percent_sign_comes_out_unchanged(self):
        values = self._export(R"""
            Windows Registry Editor Version 5.00

            [HKEY_CURRENT_USER\Software\Run]
            "p"="%AppData%\\evil.exe"
            """)
        self.assertEqual(values, {'HKEY_CURRENT_USER/Software/Run/p': B'%AppData%\\evil.exe'})

    def test_value_names_with_a_colon_or_an_equals_sign_are_read(self):
        values = self._export(R"""
            Windows Registry Editor Version 5.00

            [HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers]
            "C:\\Users\\x\\a.exe"="~ RUNASADMIN"

            [HKEY_CURRENT_USER\Software\X]
            "a=b"="c"
            """)
        self.assertEqual(values, {
            'HKEY_CURRENT_USER/Software/Microsoft/Windows NT/CurrentVersion/AppCompatFlags/Layers/C:/Users/x/a.exe': B'~ RUNASADMIN',
            'HKEY_CURRENT_USER/Software/X/a=b': B'c',
        })

    def test_a_string_value_holding_a_character_that_python_reads_as_a_line_break_is_kept_whole(self):
        for separator in ('\r', '\x0c', '\x1c', '\x85', '\N{LINE SEPARATOR}'):
            export = '\r\n'.join((
                'Windows Registry Editor Version 5.00',
                '',
                R'[HKEY_CURRENT_USER\Software\X]',
                F'"a"="one{separator}two"',
                '"b"="kept"',
                '',
            ))
            values = {str(chunk['path']): bytes(chunk) for chunk in export.encode('utf-16') | self.load() | [...]}
            self.assertEqual(values, {
                'HKEY_CURRENT_USER/Software/X/a': F'one{separator}two'.encode(self.load().codec),
                'HKEY_CURRENT_USER/Software/X/b': B'kept',
            }, repr(separator))
