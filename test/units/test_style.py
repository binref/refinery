import os.path
import inspect
import pytest

from glob import glob

from refinery.lib.loader import get_all_entry_points

from . import TestUnitBase


class TestStyleGuides(TestUnitBase):

    @pytest.mark.cosmetics
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

    @pytest.mark.cosmetics
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

        for file in python_files:
            with open(file, 'rb') as code_lines:
                for k, line in enumerate(code_lines):
                    self.assertFalse(line.endswith(b'\r\n'), F'CRLF sequence on line {k} in {file}')

        report = stylez.check_files(python_files)
        self.assertEqual(report.total_errors, 0, 'PEP8 formatting errors were found.')
