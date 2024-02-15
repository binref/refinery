#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows-specific module to obtain data in different complex formats from the clipboard.
Primarily, this can retrieve image data from the clipboard.
"""
import os
import enum

if os.name == 'nt':
    import ctypes
    import ctypes.wintypes as w

    from ctypes import sizeof

    u32 = ctypes.WinDLL('user32')
    k32 = ctypes.WinDLL('kernel32')

    IsClipboardFormatAvailable = u32.IsClipboardFormatAvailable
    IsClipboardFormatAvailable.argtypes = w.UINT,
    IsClipboardFormatAvailable.restype = w.BOOL
    GlobalAlloc = k32.GlobalAlloc
    GlobalAlloc.argtypes = w.UINT, w.UINT
    GlobalAlloc.restype = w.HGLOBAL
    GlobalFree = k32.GlobalFree
    GlobalFree.argtypes = w.HGLOBAL,
    GlobalFree.restype = w.HGLOBAL
    GlobalSize = k32.GlobalSize
    GlobalSize.argtypes = w.HGLOBAL,
    GlobalSize.restype = w.UINT
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

    class FieldsFromTypeHints(type(ctypes.Structure)):

        def __new__(cls, name, bases, namespace):
            from typing import get_type_hints

            class AnnotationDummy:
                __annotations__ = namespace.get('__annotations__', {})

            annotations = get_type_hints(AnnotationDummy)
            namespace['_fields_'] = list(annotations.items())
            namespace['_pack_'] = 1

            return type(ctypes.Structure).__new__(cls, name, bases, namespace)

    class BITMAPINFOHEADER(ctypes.Structure, metaclass=FieldsFromTypeHints):
        biSize          : w.DWORD
        biWidth         : w.LONG
        biHeight        : w.LONG
        biPlanes        : w.WORD
        biBitCount      : w.WORD
        biCompression   : w.DWORD
        biSizeImage     : w.DWORD
        biXPelsPerMeter : w.LONG
        biYPelsPerMeter : w.LONG
        biClrUsed       : w.DWORD
        biClrImportant  : w.DWORD

    class BITMAPFILEHEADER(ctypes.Structure, metaclass=FieldsFromTypeHints):
        bfType          : w.WORD
        bfSize          : w.DWORD
        bfReserved1     : w.WORD
        bfReserved2     : w.WORD
        bfOffBits       : w.DWORD


GMEM_DDESHARE = 0x2000
GMEM_ZEROINIT = 0x0040


class CF(enum.IntEnum):
    TEXT = 1
    DIB = 8
    OEMTEXT = 7
    UNICODETEXT = 13


class GlobalMemory:

    def __init__(self, data, size=None):
        self.data = data
        self.size = size or (len(data) + 2)
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
        return None


class ClipBoard:

    def __init__(self, mode: CF):
        self.mode = mode

    def __enter__(self):
        OpenClipboard(None)
        return self

    def __exit__(self, *args):
        CloseClipboard()

    def paste(self):
        hg = GetClipboardData(self.mode.value)
        if self.mode is CF.TEXT or self.mode is CF.OEMTEXT:
            return ctypes.c_char_p(hg).value
        if self.mode is CF.UNICODETEXT:
            return ctypes.c_wchar_p(hg).value
        if self.mode is CF.DIB:
            def get_pixel_data_offset_for_packed_dib(header: BITMAPINFOHEADER) -> int:
                extra = 0
                if header.biSize == sizeof(BITMAPINFOHEADER):
                    if header.biBitCount > 8:
                        if header.biCompression == 3:  # BI_BITFIELDS
                            extra += 12
                        if header.biCompression == 6:
                            extra += 16
                if header.biClrUsed > 0:
                    extra += header.biClrUsed * 4
                else:
                    if header.biBitCount <= 8:
                        extra += 4 << header.biBitCount
                return header.biSize + extra
            bm_header = BITMAPINFOHEADER.from_address(hg)
            bm_stride = ((((bm_header.biWidth * bm_header.biBitCount) + 31) & ~31) >> 3)
            bm_size = abs(bm_header.biHeight) * bm_stride
            bm_offset = get_pixel_data_offset_for_packed_dib(bm_header)
            size = max(bm_offset + bm_size, GlobalSize(hg))
            data = ctypes.cast(hg, ctypes.POINTER(ctypes.c_ubyte * size))
            size += sizeof(BITMAPFILEHEADER)
            bfh = BITMAPFILEHEADER(0x4D42, size, 0, 0, sizeof(BITMAPFILEHEADER) + bm_offset)
            bitmap = bytes(data.contents)
            return bytes(bfh) + bitmap

    def copy(self, data):
        EmptyClipboard()
        size = len(data)
        if self.mode in (CF.TEXT, CF.OEMTEXT):
            size += 1
        if self.mode is CF.UNICODETEXT:
            size += 2
        glob = GlobalAlloc(GMEM_DDESHARE | GMEM_ZEROINIT, size)
        lock = GlobalLock(ctypes.c_void_p(glob))
        ctypes.windll.msvcrt.memset(ctypes.c_char_p(lock), 0, size)
        ctypes.windll.msvcrt.memcpy(ctypes.c_char_p(lock), data, len(data))
        GlobalUnlock(lock)
        SetClipboardData(self.mode.value, glob)


def get_any_data():
    for mode in CF:
        if not IsClipboardFormatAvailable(mode.value):
            continue
        with ClipBoard(mode) as cp:
            data = cp.paste()
            if not data:
                continue
            return mode, data
    return None, B''
