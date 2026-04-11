from .. import TestUnitBase


class TestEscVB(TestUnitBase):

    def test_simple_string(self):
        unit = self.load()
        data = B'"This is ""a string""."'
        test = data | unit | bytes
        self.assertEqual(test, B'This is "a string".')
        self.assertEqual(test | -unit | bytes, data)

    def test_chr_decimal(self):
        unit = self.load()
        self.assertEqual(B'Chr(65)' | unit | bytes, B'A')

    def test_chr_hex(self):
        unit = self.load()
        self.assertEqual(B'Chr(&H41)' | unit | bytes, B'A')

    def test_chr_octal(self):
        unit = self.load()
        self.assertEqual(B'Chr(&O101)' | unit | bytes, B'A')

    def test_chr_binary(self):
        unit = self.load()
        self.assertEqual(B'Chr(&B1000001)' | unit | bytes, B'A')

    def test_chrw(self):
        unit = self.load()
        self.assertEqual(B'ChrW(8364)' | unit | bytes, '\u20AC'.encode('utf-8'))

    def test_chr_dollar(self):
        unit = self.load()
        self.assertEqual(B'Chr$(65)' | unit | bytes, B'A')

    def test_concatenation_with_ampersand(self):
        unit = self.load()
        self.assertEqual(B'"a" & Chr(13) & "b"' | unit | bytes, B'a\rb')

    def test_concatenation_with_plus(self):
        unit = self.load()
        self.assertEqual(B'"x" + ChrW(10) + "y"' | unit | bytes, B'x\ny')

    def test_multiple_chr_calls(self):
        unit = self.load()
        data = B'Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)'
        self.assertEqual(data | unit | bytes, B'Hello')

    def test_vbcrlf(self):
        unit = self.load()
        self.assertEqual(B'vbCrLf' | unit | bytes, B'\r\n')

    def test_vbtab(self):
        unit = self.load()
        self.assertEqual(B'vbTab' | unit | bytes, B'\t')

    def test_vbnullchar(self):
        unit = self.load()
        self.assertEqual(B'vbNullChar' | unit | bytes, B'\0')

    def test_mixed_constants_and_literals(self):
        unit = self.load()
        data = B'"line1" & vbCrLf & "line2"'
        self.assertEqual(data | unit | bytes, B'line1\r\nline2')

    def test_case_insensitive(self):
        unit = self.load()
        self.assertEqual(B'VBCRLF' | unit | bytes, B'\r\n')
        self.assertEqual(B'CHR(65)' | unit | bytes, B'A')

    def test_bare_string_passthrough(self):
        unit = self.load()
        self.assertEqual(B'not a vba expression' | unit | bytes, B'not a vba expression')

    def test_bare_quoted_string_fallback(self):
        unit = self.load()
        self.assertEqual(B'"hello"' | unit | bytes, B'hello')

    def test_reverse_printable(self):
        unit = self.load()
        self.assertEqual(unit.reverse(B'hello'), B'"hello"')

    def test_reverse_embedded_quote(self):
        unit = self.load()
        self.assertEqual(unit.reverse(B'say "hi"'), B'"say ""hi"""')

    def test_reverse_tab(self):
        unit = self.load()
        self.assertEqual(unit.reverse(B'a\tb'), B'"a" & vbTab & "b"')

    def test_reverse_crlf(self):
        unit = self.load()
        self.assertEqual(unit.reverse(B'a\r\nb'), B'"a" & vbCr & vbLf & "b"')

    def test_reverse_null(self):
        unit = self.load()
        self.assertEqual(unit.reverse(B'A\x00B'), B'"A" & vbNullChar & "B"')

    def test_reverse_nonprintable_fallback(self):
        unit = self.load()
        self.assertEqual(unit.reverse(B'\x01'), B'Chr(1)')

    def test_reverse_high_byte(self):
        unit = self.load()
        self.assertEqual(unit.reverse(B'\xFF'), B'Chr(255)')

    def test_roundtrip_printable(self):
        unit = self.load()
        original = B'Hello, World!'
        self.assertEqual(unit.reverse(original) | unit | bytes, original)

    def test_roundtrip_with_specials(self):
        unit = self.load()
        original = B'line1\r\nline2\ttab'
        self.assertEqual(unit.reverse(original) | unit | bytes, original)

    def test_roundtrip_with_nonprintable(self):
        unit = self.load()
        original = B'\x01\x02\x03'
        self.assertEqual(unit.reverse(original) | unit | bytes, original)

    def test_roundtrip_with_quotes(self):
        unit = self.load()
        original = B'She said "hello"'
        self.assertEqual(unit.reverse(original) | unit | bytes, original)
