#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import pyperclip

from refinery.lib.winclip import get_any_data, ClipBoard, CF

from .. import TestBase


def onlywin(f):
    if os.name == 'nt':
        return f
    else:
        def dummy(*_):
            return
        return dummy


class TestWinClip(TestBase):

    @onlywin
    def test_copy_unicode(self):
        test = 'Refined Ünicode'
        with ClipBoard(CF.UNICODETEXT) as cb:
            cb.copy(test)
        self.assertEqual(pyperclip.paste(), test)

    @onlywin
    def test_copy_ansi(self):
        test = 'Refined ASCII'
        with ClipBoard(CF.TEXT) as cb:
            cb.copy(test)
        self.assertEqual(pyperclip.paste(), test)

    @onlywin
    def test_paste_text(self):
        test = 'Unrefined ASCII'
        pyperclip.copy(test)
        mode, data = get_any_data()
        self.assertEqual(mode, CF.UNICODETEXT)
        self.assertEqual(test, data.decode())
