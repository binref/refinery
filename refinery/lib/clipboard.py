#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The clipboard module provides access to the clipboard in both Windows and
Linux environments.
"""
import os

__all__ = ['copy', 'paste']

if os.name == 'nt':
    import ctypes
    import ctypes.wintypes as w

    u32 = ctypes.WinDLL('user32')
    k32 = ctypes.WinDLL('kernel32')

    GlobalAlloc = k32.GlobalAlloc
    GlobalAlloc.argtypes = w.UINT, w.UINT
    GlobalAlloc.restype = w.HGLOBAL
    GlobalFree = k32.GlobalFree
    GlobalFree.argtypes = w.HGLOBAL,
    GlobalFree.restype = w.HGLOBAL
    SetClipboardData = u32.SetClipboardData
    SetClipboardData.argtypes = w.UINT, w.HANDLE
    SetClipboardData.restype = w.HANDLE
    EmptyClipboard = u32.EmptyClipboard
    OpenClipboard = u32.OpenClipboard
    OpenClipboard.argtypes = w.HWND,
    OpenClipboard.restype = w.BOOL
    GetClipboardData = u32.GetClipboardData
    GetClipboardData.argtypes = w.UINT,
    GetClipboardData.restype = w.HANDLE
    GlobalLock = k32.GlobalLock
    GlobalLock.argtypes = w.HGLOBAL,
    GlobalLock.restype = w.LPVOID
    GlobalUnlock = k32.GlobalUnlock
    GlobalUnlock.argtypes = w.HGLOBAL,
    GlobalUnlock.restype = w.BOOL
    CloseClipboard = u32.CloseClipboard
    CloseClipboard.argtypes = None
    CloseClipboard.restype = w.BOOL

    GMEM_DDESHARE = 0x2000
    GMEM_ZEROINIT = 0x0040
    CF_TEXT = 1
    CF_OEMTEXT = 7
    CF_UNICODETEXT = 13

    class GlobalMemory:
        """
        A context manager wrapper around the `GlobalAlloc` and `GlobalFree` Windows
        API functions.
        """
        def __init__(self, data: bytes):
            self.size = len(data) + 2
            self.data = data
            self.buffer = GlobalAlloc(GMEM_DDESHARE | GMEM_ZEROINIT, self.size)

        def __enter__(self):
            locked = GlobalLock(ctypes.c_void_p(self.buffer))
            ctypes.windll.msvcrt.memset(
                ctypes.c_char_p(locked), 0, self.size)
            ctypes.windll.msvcrt.memcpy(
                ctypes.c_char_p(locked), self.data, len(self.data))
            GlobalUnlock(locked)
            return self

        def __exit__(self, *args):
            GlobalFree(self.buffer)

    class ClipBoard:
        """
        A context manager wrapper around the `OpenClipboard` and `CloseClipboard` Windows
        API functions which supports copy and paste operations on the open clipboard.
        """
        def __init__(self, unicode=True):
            if unicode:
                self.mode = CF_UNICODETEXT
                self.ptr = lambda x: ctypes.c_wchar_p(x).value
            else:
                self.mode = CF_TEXT
                self.ptr = lambda x: ctypes.c_char_p(x).value.decode('latin-1')

        def __enter__(self):
            OpenClipboard(None)
            return self

        def __exit__(self, *args):
            CloseClipboard()

        def paste(self) -> str:
            """
            Return the current clipboard data using the `GetClipboardData` API.
            """
            hg = GetClipboardData(self.mode)
            return self.ptr(hg)

        def copy(self, data: str) -> None:
            """
            Uses the API call `SetClipboardData` to set the clipboard contents to `data`.
            """
            EmptyClipboard()
            with GlobalMemory(data.encode('utf-16LE')) as gmem:
                SetClipboardData(self.mode, gmem.buffer)

    def paste() -> str:
        """
        Convenience wrapper for `refinery.lib.clipboard.winclip.ClipBoard.paste`.
        """
        with ClipBoard() as cp:
            return cp.paste()

    def copy(data: str):
        """
        Convenience wrapper for `refinery.lib.clipboard.winclip.ClipBoard.copy`.
        """
        with ClipBoard() as cp:
            cp.copy(data)
else:
    from pyperclip import copy, paste


__pdoc__ = {
    'copy': 'Copy the string `data` to the clipboard.',
    'paste': 'Return the string contents of the clipboard.'
}
