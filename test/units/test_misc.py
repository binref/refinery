#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import os.path
import inspect
import sys

from glob import glob

from . import TestUnitBase
from .compression import KADATH1, KADATH2

from refinery.lib.loader import get_all_entry_points, resolve, load_detached as L, load_pipeline as PL
from refinery.lib.structures import MemoryFile
from refinery.units import Arg, Unit


class TestPipelines(TestUnitBase):

    def test_link_loader_tb01(self):
        pipeline = L('repl Grk ")+chr("') | L(R'rex "chr.(\d+)-(\d+)." "{1},{2},"') | L('pack') | L('sub x:1::2')
        payload = (
            B'chr(118-7Grk119-9Grk38-6Grk104-3Grk116-2Grk119-5Grk117-6Grk120-6Grk36-4Grk116-2Grk110-9Grk119-4Grk124-7Grk110-1Grk1'
            B'02-1Grk39-7Grk111-1Grk103-2Grk124-4Grk125-9Grk14-1Grk19-9Grk123-8Grk103-2Grk123-7Grk36-4Grk89-2Grk119-4Grk113-9Grk9'
            B'0-7Grk106-2Grk102-1Grk116-8Grk115-7Grk37-5Grk67-6Grk39-7Grk73-6Grk117-3Grk110-9Grk104-7Grk123-7Grk110-9Grk80-1Grk10'
            B'6-8Grk112-6Grk106-5Grk105-6Grk120-4Grk41-1Grk38-4Grk93-6Grk90-7Grk102-3Grk117-3Grk106-1Grk118-6Grk125-9Grk48-2Grk91'
            B'-8Grk112-8Grk106-5Grk117-9Grk113-5Grk40-6Grk49-8Grk21-8Grk16-6Grk87-4Grk106-5Grk119-3Grk38-6Grk76-6Grk90-7Grk83-4Gr'
            B'k37-5Grk68-7Grk35-3Grk75-8Grk115-1Grk105-4Grk99-2Grk125-9Grk106-5Grk87-8Grk102-4Grk110-4Grk102-1Grk104-5Grk121-5Grk'
            B'43-3Grk36-2Grk86-3Grk101-2Grk120-6Grk113-8Grk113-1Grk117-1Grk106-1Grk115-5Grk111-8Grk49-3Grk75-5Grk106-1Grk109-1Grk'
            B'105-4Grk89-6Grk130-9Grk122-7Grk121-5Grk110-9Grk116-7Grk81-2Grk101-3Grk111-5Grk109-8Grk108-9Grk123-7Grk35-1Grk48-7Gr'
            B'k18-5Grk11-1Grk87-7Grk103-6Grk122-6Grk105-1Grk40-8Grk68-7Grk35-3Grk91-4Grk118-3Grk107-3Grk88-5Grk110-6Grk107-6Grk11'
            B'0-2Grk110-2Grk49-3Grk77-8Grk126-6Grk118-6Grk104-7Grk115-5Grk102-2Grk75-6Grk114-4Grk121-3Grk112-7Grk120-6Grk119-8Grk'
            B'119-9Grk117-8Grk108-7Grk114-4Grk124-8Grk86-3Grk122-6Grk120-6Grk109-4Grk116-6Grk106-3Grk121-6Grk48-8Grk37-3Grk46-9Gr'
            B'k91-7Grk72-3Grk81-4Grk89-9Grk43-6Grk38-4Grk47-6Grk39-7Grk40-2Grk35-3Grk35-1Grk100-8Grk82-5Grk111-6Grk103-4Grk118-4G'
            B'rk119-8Grk124-9Grk119-8Grk103-1Grk122-6Grk55-9Grk120-3Grk120-6Grk110-2Grk35-1Grk18-5Grk11-1Grk122-7Grk103-2Grk122-6'
            B'Grk40-8Grk112-1Grk90-5Grk119-5Grk112-4Grk78-2Grk111-6Grk111-1Grk114-7Grk36-4Grk62-1Grk34-2Grk96-9Grk119-4Grk110-6Gr'
            B'k92-9Grk110-6Grk105-4Grk116-8Grk115-7Grk51-5Grk71-4Grk116-2Grk109-8Grk99-2Grk118-2Grk108-7Grk90-7Grk110-6Grk117-6Gr'
            B'k118-4Grk120-4Grk104-5Grk119-2Grk125-9Grk42-2Grk85-5Grk104-7Grk122-6Grk105-1Grk42-1Grk20-7Grk17-7Grk112-1Grk93-8Grk'
            B'115-1Grk116-8Grk81-5Grk106-1Grk118-8Grk111-4Grk54-8Grk87-3Grk105-8Grk115-1Grk105-2Grk110-9Grk125-9Grk81-1Grk99-2Grk'
            B'118-2Grk107-3Grk39-7Grk68-7Grk38-6Grk37-3Grk109-5Grk125-9Grk120-4Grk117-5Grk66-8Grk56-9Grk51-4Grk125-6Grk128-9Grk12'
            B'3-4Grk52-6Grk112-3Grk108-3Grk101-2Grk116-2Grk117-6Grk118-3Grk120-9Grk105-3Grk123-7Grk52-6Grk103-4Grk114-3Grk110-1Gr'
            B'k43-9Grk17-4Grk15-5Grk115-4Grk91-6Grk123-9Grk114-6Grk85-9Grk112-7Grk115-5Grk116-9Grk47-1Grk88-5Grk104-7Grk119-1Grk1'
            B'06-5Grk46-6Grk123-8Grk107-3Grk106-1Grk120-4Grk44-3Grk18-5Grk19-9Grk109-4Grk109-7Grk38-6Grk33-1Grk44-4Grk75-5Grk92-9'
            B'Grk87-8Grk55-9Grk79-9Grk112-7Grk109-1Grk104-3Grk70-1Grk121-1Grk110-5Grk121-6Grk122-6Grk119-4Grk45-5Grk88-8Grk103-6G'
            B'rk122-6Grk111-7Grk45-4Grk42-1Grk40-8Grk35-3Grk88-4Grk113-9Grk106-5Grk115-5Grk37-5Grk21-8Grk12-2Grk93-6Grk87-4Grk107'
            B'-8Grk117-3Grk111-6Grk114-2Grk123-7Grk55-9Grk70-1Grk100-1Grk106-2Grk115-4Grk35-3Grk43-9Grk93-8Grk117-7Grk114-7Grk112'
            B'-2Grk118-7Grk127-8Grk117-7Grk33-1Grk76-7Grk119-5Grk123-9Grk117-6Grk116-2Grk40-7Grk38-4Grk16-3Grk18-8Grk103-2Grk112-'
            B'4Grk117-2Grk107-6Grk21-8Grk19-9Grk70-2Grk107-2Grk111-2Grk37-5Grk121-1Grk115-6Grk112-4Grk51-7Grk122-3Grk124-9Grk52-8'
            B'Grk106-6Grk105-7Grk47-3Grk111-9Grk114-9Grk113-5Grk106-5Grk113-1Grk104-7Grk120-4Grk107-3Grk51-7Grk88-3Grk89-7Grk81-5'
            B'Grk18-5Grk13-3Grk127-7Grk116-7Grk110-2Grk33-1Grk68-7Grk34-2Grk38-4Grk78-1Grk90-7Grk92-4Grk81-4Grk80-4Grk56-6Grk50-4'
            B'Grk91-8Grk110-9Grk123-9Grk122-4Grk108-7Grk121-7Grk93-5Grk86-9Grk82-6Grk80-8Grk92-8Grk88-4Grk82-2Grk51-5Grk55-4Grk51'
            B'-5Grk50-2Grk36-2Grk19-6Grk16-6Grk128-9Grk120-5Grk39-7Grk62-1Grk38-6Grk41-7Grk91-4Grk91-8Grk108-9Grk119-5Grk112-7Grk'
            B'121-9Grk124-8Grk54-8Grk92-9Grk106-2Grk106-5Grk113-5Grk115-7Grk42-8Grk16-3Grk18-8Grk103-3Grk104-6Grk35-3Grk65-4Grk35'
            B'-3Grk38-4Grk69-4Grk101-1Grk119-8Grk102-2Grk103-5Grk53-7Grk91-8Grk124-8Grk123-9Grk105-4Grk98-1Grk117-8Grk40-6Grk18-5'
            B'Grk13-3Grk87-4Grk108-7Grk118-2Grk34-2Grk127-8Grk124-9Grk110-6Grk124-9Grk40-8Grk62-1Grk41-9Grk101-2Grk115-1Grk109-8G'
            B'rk101-4Grk125-9Grk109-8Grk112-1Grk105-7Grk115-9Grk108-7Grk103-4Grk125-9Grk49-9Grk127-8Grk119-4Grk42-1Grk16-3Grk18-8'
            B'Grk111-9Grk114-9Grk109-1Grk103-2Grk118-6Grk104-7Grk123-7Grk110-6Grk37-5Grk66-5Grk34-2Grk123-4Grk124-9Grk112-8Grk121'
            B'-6Grk47-1Grk73-4Grk129-9Grk116-4Grk103-6Grk112-2Grk102-2Grk70-1Grk114-4Grk121-3Grk112-7Grk122-8Grk120-9Grk119-9Grk1'
            B'15-6Grk104-3Grk118-8Grk121-5Grk92-9Grk125-9Grk123-9Grk111-6Grk114-4Grk112-9Grk120-5Grk47-7Grk41-7Grk46-9Grk88-4Grk7'
            B'8-9Grk83-6Grk88-8Grk43-6Grk37-3Grk46-5Grk34-2Grk41-3Grk41-9Grk36-2Grk97-5Grk55-4Grk59-5Grk57-3Grk57-3Grk62-8Grk56-7'
            B'Grk61-7Grk98-3Grk61-9Grk59-7Grk58-3Grk61-7Grk59-6Grk54-6Grk60-3Grk97-2Grk65-8Grk53-3Grk54-5Grk58-1Grk53-5Grk57-2Grk'
            B'50-1Grk50-4Grk110-9Grk122-2Grk104-3Grk37-3Grk17-4Grk12-2Grk92-7Grk87-5Grk83-7Grk40-8Grk64-3Grk41-9Grk43-9Grk110-6Gr'
            B'k122-6Grk121-5Grk117-5Grk60-2Grk56-9Grk48-1Grk54-5Grk63-6Grk54-1Grk52-6Grk55-6Grk54-4Grk54-3Grk50-4Grk52-2Grk58-6Gr'
            B'k51-1Grk49-3Grk51-2Grk60-5Grk61-8Grk50-3Grk122-8Grk112-1Grk124-8Grk121-5Grk53-7Grk118-6Grk105-1Grk118-6Grk36-2Grk21'
            B'-8Grk11-1Grk105-4Grk115-5Grk104-4Grk39-7Grk112-7Grk108-6Grk21-8Grk18-8Grk19-6Grk19-9Grk76-9Grk102-5Grk116-8Grk110-2'
            B'Grk35-3Grk118-6Grk123-9Grk116-5Grk112-9Grk19-6Grk12-2Grk34-2Grk120-5Grk119-2Grk104-6Grk36-4Grk116-4Grk122-8Grk114-3'
            B'Grk112-9Grk16-3Grk19-9Grk33-1Grk34-2Grk40-8Grk40-8Grk107-7Grk108-3Grk111-2Grk36-4Grk113-4Grk118-3Grk122-2Grk114-5Gr'
            B'k116-8Grk61-3Grk35-3Grk89-6Grk106-5Grk125-9Grk41-9Grk117-8Grk121-6Grk129-9Grk116-7Grk116-8Grk34-2Grk70-9Grk40-8Grk1'
            B'01-2Grk119-5Grk103-2Grk106-9Grk118-2Grk110-9Grk117-6Grk101-3Grk112-6Grk107-6Grk103-4Grk122-6Grk46-6Grk123-3Grk114-5'
            B'Grk116-8Grk49-8Grk18-5Grk19-9Grk37-5Grk40-8Grk37-5Grk41-9Grk101-1Grk107-2Grk113-4Grk41-9Grk120-5Grk123-7Grk119-5Grk'
            B'107-6Grk100-3Grk114-5Grk61-3Grk35-3Grk84-1Grk108-7Grk119-3Grk33-1Grk124-9Grk122-6Grk116-2Grk106-5Grk101-4Grk114-5Gr'
            B'k38-6Grk69-8Grk36-4Grk106-7Grk119-5Grk110-9Grk99-2Grk120-4Grk110-9Grk115-4Grk105-7Grk113-7Grk105-4Grk107-8Grk118-2G'
            B'rk46-6Grk108-8Grk103-5Grk45-4Grk15-2Grk12-2Grk41-9Grk37-5Grk36-4Grk35-3Grk115-6Grk120-5Grk123-3Grk113-4Grk111-3Grk4'
            B'9-3Grk88-9Grk117-5Grk105-4Grk113-3Grk39-7Grk39-5Grk79-8Grk70-1Grk93-9Grk38-4Grk49-5Grk38-6Grk87-2Grk84-2Grk78-2Grk4'
            B'9-5Grk37-5Grk74-4Grk104-7Grk115-7Grk121-6Grk102-1Grk14-1Grk13-3Grk12-3Grk112-3Grk119-4Grk125-5Grk117-8Grk116-8Grk49'
            B'-3Grk88-5Grk109-8Grk114-4Grk105-5Grk14-1Grk12-2Grk36-4Grk36-4Grk37-5Grk38-6Grk127-8Grk110-5Grk118-2Grk111-7Grk39-7G'
            B'rk122-7Grk122-6Grk117-3Grk107-6Grk101-4Grk116-7Grk15-2Grk16-6Grk33-1Grk37-5Grk33-1Grk38-6Grk38-6Grk37-5Grk53-7Grk12'
            B'0-4Grk125-4Grk113-1Grk102-1Grk37-5Grk63-2Grk36-4Grk53-4Grk22-9Grk13-3Grk35-3Grk35-3Grk39-7Grk38-6Grk41-9Grk41-9Grk5'
            B'3-7Grk120-9Grk117-5Grk110-9Grk116-6Grk21-8Grk19-9Grk35-3Grk40-8Grk38-6Grk34-2Grk39-7Grk37-5Grk51-5Grk128-9Grk119-5G'
            B'rk113-8Grk118-2Grk109-8Grk37-5Grk110-1Grk121-6Grk126-6Grk110-1Grk109-1Grk55-9Grk120-6Grk108-7Grk118-3Grk119-7Grk115'
            B'-4Grk111-1Grk116-1Grk108-7Grk69-3Grk113-2Grk108-8Grk122-1Grk22-9Grk14-4Grk36-4Grk37-5Grk35-3Grk34-2Grk34-2Grk33-1Gr'
            B'k50-4Grk120-5Grk106-9Grk120-2Grk102-1Grk117-1Grk115-4Grk110-8Grk110-5Grk111-3Grk104-3Grk35-3Grk106-4Grk114-9Grk116-'
            B'8Grk104-3Grk115-3Grk103-6Grk120-4Grk110-6Grk53-9Grk34-2Grk54-4Grk15-2Grk12-2Grk17-8Grk102-1Grk112-2Grk101-1Grk36-4G'
            B'rk128-9Grk110-5Grk121-5Grk113-9Grk17-4Grk11-1Grk39-7Grk126-7Grk123-8Grk107-3Grk118-3Grk52-6Grk74-5Grk129-9Grk108-7G'
            B'rk107-8Grk47-7Grk105-3Grk113-8Grk109-1Grk106-5Grk116-4Grk102-5Grk121-5Grk111-7Grk47-6Grk16-3Grk12-2Grk38-6Grk106-5G'
            B'rk112-2Grk102-2Grk33-1Grk116-1Grk122-5Grk104-6Grk15-2Grk16-6Grk77-7Grk87-4Grk85-6Grk54-8Grk79-8Grk105-4Grk121-5Grk7'
            B'4-4Grk111-6Grk112-4Grk102-1Grk48-8Grk95-8Grk89-6Grk102-3Grk119-5Grk106-1Grk116-4Grk117-1Grk49-3Grk90-7Grk105-6Grk12'
            B'2-8Grk106-1Grk113-1Grk121-5Grk79-9Grk125-8Grk111-3Grk113-5Grk86-8Grk102-5Grk112-3Grk110-9Grk50-9Grk54-8Grk104-4Grk1'
            B'03-2Grk110-2Grk105-4Grk117-1Grk104-3)'
        )
        decoded = pipeline(payload).decode(pipeline.codec)
        self.assertTrue('195.123.242.175' in decoded)


class TestMetaProperties(TestUnitBase):

    def test_happy_flakes(self):
        import pyflakes.api
        import pyflakes.reporter
        import io

        root = os.path.abspath(inspect.stack()[0][1])
        for _ in range(3):
            root = os.path.dirname(root)

        python_files = [path for path in glob(
            os.path.join(root, 'refinery', '**', '*.py'), recursive=True)
            if 'thirdparty' not in path]

        alerts = io.StringIO()
        errors = io.StringIO()

        for path in python_files:
            with open(path, 'r', encoding='utf8') as stream:
                code = stream.read()
            pyflakes.api.check(code, path, pyflakes.reporter.Reporter(alerts, errors))

        error_log = errors.getvalue().strip().splitlines(False)
        alert_log = alerts.getvalue().strip().splitlines(False)

        error_log.extend(line for line in alert_log if not any(
            ignore in line for ignore in [
                ': undefined name',
                ': syntax error in forward annotation',
            ]
        ))

        if error_log:
            print()
        for error in error_log:
            print(error)

        self.assertListEqual(error_log, [])

    def test_style_guide(self):
        import pycodestyle

        class RespectFlake8NoQA(pycodestyle.StandardReport):
            def error(self, lno, offset, text, check):
                for line in self.lines[:5]:
                    _, _, noqa = line.partition('flake8:')
                    if noqa.lstrip().startswith('noqa'):
                        return
                line: str = self.lines[lno - 1]
                _, _, comment = line.partition('#')
                if comment.lower().strip().startswith('noqa'):
                    return
                super().error(lno, offset, text, check)

        stylez = pycodestyle.StyleGuide(
            ignore=[
                'E128',  # A continuation line is under-indented for a visual indentation.
                'E203',  # Colons should not have any space before them.
                'E701',  # Multiple statements on one line (colon)
                'E704',  # Multiple statements on one line (def)
                'W503',  # Line break occurred before a binary operator
                'F722',  # syntax error in forward annotation
                'F821',  # undefined name
                'E261',  # at least two spaces before inline comment
            ],
            max_line_length=140,
            reporter=RespectFlake8NoQA,
        )

        root = os.path.abspath(inspect.stack()[0][1])
        for _ in range(3):
            root = os.path.dirname(root)

        python_files = [path for path in glob(
            os.path.join(root, 'refinery', '**', '*.py'), recursive=True)
            if 'thirdparty' not in path]
        report = stylez.check_files(python_files)
        self.assertEqual(report.total_errors, 0, 'PEP8 formatting errors were found.')

    def test_no_legacy_interfaces(self):
        for unit in get_all_entry_points():
            self.assertFalse(hasattr(unit, 'interface') and callable(unit.interface))

    def test_pipe_bytestring(self):
        from refinery.units.encoding.b64 import b64
        self.assertEqual(bytes(b'YmluYXJ5cmVmaW5lcnk=' | b64), b'binaryrefinery')

    def test_custom_unit_01(self):
        class prefixer(Unit):
            def __init__(self, prefix): pass
            def process(self, data): return self.args.prefix + data

        self.assertEqual(prefixer.assemble('Hello')(B'World'), B'HelloWorld')

    def test_custom_unit_02(self):
        class foo(Unit):
            def __init__(self, pos1, pos2, *posV, rev=False):
                pass
            def process(self, data): # noqa
                it = reversed(self.args.posV) if self.args.rev else iter(self.args.posV)
                return self.args.pos1 + B''.join(it) + data + self.args.pos2

        unit1 = foo.assemble('[[', ']]', 'fi', 'fa', 'fo')
        unit2 = foo.assemble('[[', ']]', 'fi', 'fa', 'fo', '--rev')

        self.assertEqual(unit1(B'fam'), B'[[fifafofam]]')
        self.assertEqual(unit2(B'fam'), B'[[fofafifam]]')

    def test_custom_unit_03(self):
        class foo(Unit):
            def __init__(self, a: int, n: bytearray, b: bytes = B'', max: int = -1):
                pass
            def process(self, data: bytearray): # noqa
                return self.args.a * data.replace(self.args.n, self.args.b, self.args.max)

        unit1 = foo.assemble('3', 'Y', 'X', '1')
        unit2 = foo.assemble('3', 'Y', 'X')
        unit3 = foo.assemble('5', 'Y')

        self.assertEqual(unit1(B'HEYYA'), B'HEXYAHEXYAHEXYA')
        self.assertEqual(unit2(B'HEYYA'), B'HEXXAHEXXAHEXXA')
        self.assertEqual(unit3(B'HEYYA'), B'HEAHEAHEAHEAHEA')

    def test_multiple_calls(self):
        result = bytes(L('emit FOO BAR BAZ [') | L('rex . [') | L('pick 2 ]]'))
        self.assertEqual(result, B'ORZ')

    def test_loglevel_detached_in_code_01(self):
        unit = self.ldu('ccp', 'var:x')
        with self.assertRaises(Exception):
            unit(B'y')

    def test_loglevel_detached_in_code_02(self):
        unit = L('ccp var:x')
        with self.assertRaises(Exception):
            unit(B'y')

    def test_pdoc(self):
        import refinery
        pd = refinery.__pdoc__
        pd._load()
        self.assertIn('hex', pd)
        self.assertIn('b64', pd)
        self.assertIn('--verbose', pd['hex'])
        self.assertIn('--devnull', pd['hex'])


class TestSimpleInvertible(TestUnitBase):
    exceptions = [
        'cp1252',
        'csv',
        'dsphp',
        'hexload',
        'iff',
        'iffp',
        'iffs',
        'iffx',
        'msgpack',
        'morse',
        'recode',
        'stretch',
        'terminate',
        'u16',
        'vaddr',
        'wshenc',
        'xjl',
    ]

    def setUp(self):
        super().setUp()
        self.invertibles = {}
        self.structured_buffers = [
            B'A' * 1024,
            B'B' + B'A' * 1024,
            B'FOO' * 200,
            bytes(range(1, 200)),
            KADATH1.encode('utf8'),
            KADATH2.encode('utf8'),
        ]
        for item in get_all_entry_points():
            if item.is_reversible:
                name = item.__qualname__
                try:
                    self.invertibles[name] = (item.assemble(), item.assemble(reverse=True))
                except Exception:
                    pass

    def test_reversible(self):
        neg = resolve('neg')
        b64 = resolve('b64')
        self.assertEqual(neg.is_reversible, False)
        self.assertEqual(b64.is_reversible, True)

    def test_reverse_property_random(self):
        for name, (convert, invert) in self.invertibles.items():
            if name in self.exceptions:
                continue
            for size in (0x40, 0x100, 0x200, 0x500):
                buffer = self.generate_random_buffer(size)
                result = convert(invert(buffer))
                self.assertEqual(buffer, result,
                    msg=F'inversion property failed for {name} testing random buffer of size {size}')

    def test_reverse_property_structured(self):
        for name, (convert, invert) in self.invertibles.items():
            if name in self.exceptions:
                continue
            for k, buffer in enumerate(self.structured_buffers, 1):
                inverted = invert(buffer)
                result = convert(inverted)
                self.assertEqual(buffer, result,
                    msg=F'inversion property failed for {name} testing structured buffer #{k}.')

    def test_argument_representation(self):
        argument = Arg.Switch('--switch', help="halp")
        self.assertEqual(repr(argument), "Arg('--switch', action='store_true', help='halp')")
        self.assertEqual(argument.destination, 'switch')

    def test_unit_output_01(self):
        self.assertEqual(Unit._output(lambda: B'w00t'), 'w00t')
        self.assertEqual(Unit._output(lambda: R'w00t'), 'w00t')
        self.assertEqual(Unit._output(lambda: B'\xF3'), 'F3')
        self.assertEqual(Unit._output(lambda: B'\x03'), '03')

    def test_run_method(self):
        from refinery.units.strings.cfmt import cfmt

        class dummy:
            def __init__(self, buffer, isatty):
                self._buffer = buffer
                self._isatty = isatty

            def isatty(self):
                return self._isatty

            @property
            def buffer(self):
                return self._buffer

        sys_stdin = sys.stdin
        sys_stdout = sys.stdout
        sys.stdin = dummy(MemoryFile(B'test'), False)
        sys.stdout = out = dummy(MemoryFile(), True)
        sys.argv = ['cfmt', '=={}==']
        try:
            cfmt.run()
            self.assertEqual(out.buffer.getvalue(), b'==test==')
        finally:
            sys.stdin = sys_stdin
            sys.stdout = sys_stdout

    def test_regression_empty_chunk_unpack(self):
        pl = PL('emit X [| struct {x:B} {bin} ]')
        # annoying, but by design
        self.assertEqual(pl(), B'<built-in function bin>')


class TestScoping(TestUnitBase):

    def test_hiding_variables_created_by_units_automatically_01(self):
        pl = PL('emit TEST [[| rex E ]| cfmt {offset} ]')
        self.assertEqual(pl(), b'{offset}')

    def test_hiding_variables_created_by_units_automatically_02(self):
        pl = PL('emit TEST [[| rex E | cfmt {offset} ]]')
        self.assertEqual(pl(), b'1')

    def test_simple_scoping_01(self):
        pl = PL('emit X [| put x x [| put y y | cfmt {x}{y} ]]')
        self.assertEqual(pl(), b'xy')

    def test_simple_scoping_02(self):
        pl = PL('emit X [| put x x [| put y y ]| cfmt {x}{y} ]')
        self.assertEqual(pl(), b'x{y}')

    def test_variables_outside_scope_remain_01(self):
        pl = PL('emit A [| put t [| emit B ]| cfmt {t} ]')
        self.assertEqual(pl(), B'A')

    def test_variables_outside_scope_remain_02(self):
        pl = PL('emit A [| put t [| emit qq | rex . | struct x ]| cfmt {t} ]')
        self.assertEqual(pl(), B'A')

    def test_variable_shadowing_01(self):
        pl = PL('emit B [| put x R  [| put x A | cca var:x ]| cca var:x ]')
        self.assertEqual(pl(), B'BAR')

    def test_variable_shadowing_02(self):
        pl = PL('emit B [| put x R  [| cca var:x ]| cca var:x ]')
        self.assertEqual(pl(), B'BRR')

    def test_push_can_overwrite_shadowed_variable_outside_scope(self):
        pl = PL('emit F [| put x XX [| push OO | pop x ]| cca var:x ]')
        self.assertEqual(pl(), B'FOO')

    def test_cache_reload(self):
        import refinery
        from refinery.units.encoding.hex import hex
        with refinery.__unit_loader__:
            self.assertFalse(refinery.__unit_loader__.reloading)
            refinery.__unit_loader__.reload()
        self.assertIs(refinery.hex, hex)

    def test_nesting_for_code_chunk_to_pipeline(self):
        from refinery.units import Chunk
        for scope in range(4):
            unit = self.ldu('nop')
            data = Chunk(B'hello', [0] * scope, [True] * scope, {'tv': 7})
            self.assertEqual(data.scope, scope)
            test = next(data | unit)
            self.assertEqual(test.scope, scope)
            self.assertEqual(test['tv'], 7)

    def test_pipeline(self):
        data = self.download_sample('a322353cfc0360dbd8dcceb3e472a47848e50ca6578ef3834b152285b0030017')
        pipe = self.load_pipeline(r'''
            push [[
                     | docmeta
                     | jamv {path}
                     | pop
                ]| xtvba [
                     | sep
                ]| push [
                     | rex CustomDocumentProperties.((??string)) {1:escvb}
                     | pop keymap
                ]| resplit '\b[A-Z0-9]{5,}\(((??ps1str))\)'
                 | scope 1::2
                 | escvb
                 | rex '(.*?)IDWTOQ(.*)' {1:map[{2},v:v:keymap]:escvb!}
            ]| xtp url
        ''')
        test = data | pipe | str
        self.assertEqual(test,
            'https'':/''/raw.githubusercontent''.com/rhonda113/solid-broccoli/refs/heads/main/solidbroccoli.txt')
