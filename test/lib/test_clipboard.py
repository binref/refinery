import os
import pyperclip

from refinery.lib.winclip import get_any_data, ClipBoard, CF
from refinery.lib.loader import load_detached

from .. import temporary_clipboard, TestBase


class TestWinClip(TestBase):

    def test_clipboard(self):
        dmp = self.ldu('dump')
        sep = self.ldu('sep', ' ')

        with temporary_clipboard():
            emit = load_detached('emit Too Much Technology')
            emit[dmp]()
            self.assertEqual(pyperclip.paste(), 'TooMuchTechnology')

        with temporary_clipboard():
            emit = load_detached('emit Too Much Technology')
            emit[sep | dmp]()
            self.assertEqual(pyperclip.paste(), 'Too Much Technology')

        with temporary_clipboard():
            data = 'Too much technology, in too little time.'
            dmp(data.encode(dmp.codec))
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
