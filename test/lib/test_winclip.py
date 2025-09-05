import os
import pyperclip
import time

from refinery.lib.winclip import get_any_data, ClipBoard, CF

from .. import clipboard, thread_group, TestBase


def work_around_pyperclip_data_races():
    time.sleep(0.1)


def onlywin(f):
    if os.name == 'nt':
        return f
    else:
        def dummy(*_):
            return
        return dummy


class TestWinClip(TestBase):

    @onlywin
    @thread_group('clipboard')
    @clipboard
    def test_copy_unicode(self):
        test = 'Refined Ünicode'
        with ClipBoard(CF.UNICODETEXT) as cb:
            cb.copy(test)
        work_around_pyperclip_data_races()
        self.assertEqual(pyperclip.paste(), test)

    @onlywin
    @thread_group('clipboard')
    @clipboard
    def test_copy_ansi(self):
        test = 'Refined ASCII'
        with ClipBoard(CF.TEXT) as cb:
            cb.copy(test)
        work_around_pyperclip_data_races()
        self.assertEqual(pyperclip.paste(), test)

    @onlywin
    @thread_group('clipboard')
    @clipboard
    def test_paste_text(self):
        test = 'Unrefined ASCII'
        pyperclip.copy(test)
        work_around_pyperclip_data_races()
        mode, data = get_any_data()
        self.assertEqual(test, data.decode())
        self.assertEqual(mode, CF.UNICODETEXT)
