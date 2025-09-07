import os
import pyperclip
import time
import pytest

from refinery.lib.winclip import get_any_data, ClipBoard, CF
from refinery.lib.loader import load_detached

from .. import TestBase


class TestWinClip(TestBase):

    @pytest.mark.clipboard
    def test_clipboard(self):
        def delay():
            time.sleep(0.1)

        dmp = self.ldu('dump')
        sep = self.ldu('sep', ' ')

        emit = load_detached('emit Too Much Technology')
        emit[dmp]()
        delay()
        self.assertEqual(pyperclip.paste(), 'TooMuchTechnology')

        emit = load_detached('emit Too Much Technology')
        emit[sep | dmp]()
        delay()
        self.assertEqual(pyperclip.paste(), 'Too Much Technology')

        data = 'Too much technology, in too little time.'
        dmp(data.encode(dmp.codec))
        delay()
        self.assertEqual(pyperclip.paste(), data)

        pyperclip.copy('baz')
        delay()
        pl = self.load_pipeline('emit a [| put foo bar | emit | pf {foo}{} ]')
        pl = bytes(pl())
        self.assertEqual(pl, b'barbaz')

        pyperclip.copy('baz')
        pl = self.load_pipeline('emit bort | push [| rex (?P<foo>...)t | pop | emit | pf {foo}{} ]')
        pl = bytes(pl())
        self.assertEqual(pl, b'borbaz')

        if os.name == 'nt':
            test = 'Refined Ünicode'
            with ClipBoard(CF.UNICODETEXT) as cb:
                cb.copy(test)
            self.assertEqual(pyperclip.paste(), test)
            mode, data = get_any_data()
            self.assertEqual(test, data.decode())
            self.assertEqual(mode, CF.UNICODETEXT)

            test = 'Refined ASCII'
            with ClipBoard(CF.TEXT) as cb:
                cb.copy(test)
            self.assertEqual(pyperclip.paste(), test)

            test = 'Unrefined ASCII'
            pyperclip.copy(test)
            mode, data = get_any_data()
            self.assertEqual(test, data.decode())
