import os
import pyperclip
import time

from refinery.lib.winclip import get_any_data, ClipBoard, CF
from refinery.lib.loader import load_detached

from .. import temporary_clipboard, TestBase


class TestWinClip(TestBase):

    def test_clipboard(self):
        def delay():
            time.sleep(0.1)

        dmp = self.ldu('dump')
        sep = self.ldu('sep', ' ')

        with temporary_clipboard():
            emit = load_detached('emit Too Much Technology')
            emit[dmp]()
            delay()
            self.assertEqual(pyperclip.paste(), 'TooMuchTechnology')

        with temporary_clipboard():
            emit = load_detached('emit Too Much Technology')
            emit[sep | dmp]()
            delay()
            self.assertEqual(pyperclip.paste(), 'Too Much Technology')

        with temporary_clipboard():
            data = 'Too much technology, in too little time.'
            dmp(data.encode(dmp.codec))
            delay()
            self.assertEqual(pyperclip.paste(), data)

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
