from __future__ import annotations

import io
import re
import zipfile

from refinery.lib.scripts.xlm import XlmEngine, XlmView
from refinery.lib.scripts.xlm.trace import XlmStatus
from test import TestBase
from test.lib.excel.samples import XLM_MACRO_TEXT_XLSM
from test.lib.scripts.xlm.test_engine import _with_cell_formula

_MACROSHEET_PART = 'xl/macrosheets/intlsheet1.xml'


def _with_date_cell(data: bytes, cell: str, iso: str) -> bytes:
    """
    Turn one cell of the macrosheet of the XLSM sample into a date cell that stores the given
    moment as its cached value.
    """
    source = zipfile.ZipFile(io.BytesIO(data))
    buffer = io.BytesIO()
    pattern = re.compile(F'<c r="{cell}"[^>]*>.*?</c>'.encode(), re.DOTALL)
    with zipfile.ZipFile(buffer, 'w') as target:
        for info in source.infolist():
            content = source.read(info)
            if info.filename == _MACROSHEET_PART:
                content = pattern.sub(
                    F'<c r="{cell}" t="d"><v>{iso}</v></c>'.encode(),
                    content,
                    count=1,
                )
            target.writestr(info, content)
    return buffer.getvalue()


def _sample() -> bytes:
    """
    The XLSM sample with one cell turned into a date cell and the cell above the entry column
    made to spell one character whose code the day of the month decides: every day but the
    fourth spells a control character, so the day the guess keeps is the fourth.
    """
    data = _with_date_cell(XLM_MACRO_TEXT_XLSM, 'AZ113', '2026-10-01T00:00:00')
    return _with_cell_formula(data, 'AZ110', 'CHAR(DAY(AZ113)*8)')


class TestDayGuess(TestBase):

    def test_the_guess_keeps_the_day_whose_trace_spells_printable_text(self):
        engine = XlmEngine(XlmView(_sample()))
        steps = list(engine.run())
        self.assertEqual(engine.day, 4)
        self.assertEqual(steps[1].row, 110)
        self.assertEqual(steps[1].text, ' ')

    def test_a_preset_day_answers_directly_without_a_search(self):
        engine = XlmEngine(XlmView(_sample()), day=17)
        steps = list(engine.run())
        self.assertEqual(engine.day, 17)
        self.assertEqual(steps[1].text, '\x88')

    def test_every_trial_starts_from_the_cells_the_runs_have_written(self):
        view = XlmView(_sample())
        first = XlmEngine(view)
        list(first.run())
        trial = first.trial(4)
        reference = trial._find_cell('Doc1', 108, 56)
        assert reference is not None
        self.assertEqual(reference.value, 'URLMo')

    def test_a_serial_that_is_no_date_stays_unimplemented(self):
        data = _with_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ110', 'DAY(AZ109)')
        steps = list(XlmEngine(XlmView(data)).run())
        self.assertEqual(steps[1].status, XlmStatus.NotImplemented)
        self.assertEqual(steps[1].text, 'DAY(Serial Date)')
