"""
Parser for VBA user form controls embedded in OLE compound files.

Implements parsing of the [MS-OFORMS][] specification for extracting variable names, values,
captions, and other metadata from embedded form controls.

[MS-OFORMS]: https://docs.microsoft.com/en-us/openspecs/
"""
from __future__ import annotations

import struct

from contextlib import contextmanager
from enum import IntFlag
from enum import auto as A
from typing import IO, TYPE_CHECKING, Generator, TypeVar

from refinery.lib.structures import FlagAccessMixin

if TYPE_CHECKING:
    from refinery.lib.ole.file import OleFile
    _T = TypeVar('_T', bound=IntFlag)


class OleFormParsingError(Exception):
    """
    Raised when an OLE form stream contains invalid or unexpected data.
    """
    pass


def consume(mask: _T, stream: ExtendedStream, props: dict[_T, int]) -> None:
    """
    For each flag in `props`, if that flag bit is set in `mask`, read and discard `size` bytes
    from `stream`.
    """
    for flag, size in props.items():
        if flag in mask:
            stream.read(size)


class FormPropMask(FlagAccessMixin, IntFlag):
    """
    FormPropMask: [MS-OFORMS] 2.2.10.2
    """
    _Unused1            = A() # noqa
    fBackColor          = A() # noqa
    fForeColor          = A() # noqa
    fNextAvailableID    = A() # noqa
    _Unused2_0          = A() # noqa
    _Unused2_1          = A() # noqa
    fBooleanProperties  = A() # noqa
    _Unused3            = A() # noqa
    fMousePointer       = A() # noqa
    fScrollBars         = A() # noqa
    fDisplayedSize      = A() # noqa
    fLogicalSize        = A() # noqa
    fScrollPosition     = A() # noqa
    fGroupCnt           = A() # noqa
    _Reserved           = A() # noqa
    fMouseIcon          = A() # noqa
    fCycle              = A() # noqa
    fSpecialEffect      = A() # noqa
    fBorderColor        = A() # noqa
    fCaption            = A() # noqa
    fFont               = A() # noqa
    fPicture            = A() # noqa
    fZoom               = A() # noqa
    fPictureAlignment   = A() # noqa
    fPictureTiling      = A() # noqa
    fPictureSizeMode    = A() # noqa
    fShapeCookie        = A() # noqa
    fDrawBuffer         = A() # noqa


class SitePropMask(FlagAccessMixin, IntFlag):
    """
    SitePropMask: [MS-OFORMS] 2.2.10.12.2
    """
    fName             = A() # noqa
    fTag              = A() # noqa
    fID               = A() # noqa
    fHelpContextID    = A() # noqa
    fBitFlags         = A() # noqa
    fObjectStreamSize = A() # noqa
    fTabIndex         = A() # noqa
    fClsidCacheIndex  = A() # noqa
    fPosition         = A() # noqa
    fGroupID          = A() # noqa
    _Unused1          = A() # noqa
    fControlTipText   = A() # noqa
    fRuntimeLicKey    = A() # noqa
    fControlSource    = A() # noqa
    fRowSource        = A() # noqa


class MorphDataPropMask(FlagAccessMixin, IntFlag):
    """
    MorphDataPropMask: [MS-OFORMS] 2.2.5.2
    """
    fVariousPropertyBits = A() # noqa
    fBackColor           = A() # noqa
    fForeColor           = A() # noqa
    fMaxLength           = A() # noqa
    fBorderStyle         = A() # noqa
    fScrollBars          = A() # noqa
    fDisplayStyle        = A() # noqa
    fMousePointer        = A() # noqa
    fSize                = A() # noqa
    fPasswordChar        = A() # noqa
    fListWidth           = A() # noqa
    fBoundColumn         = A() # noqa
    fTextColumn          = A() # noqa
    fColumnCount         = A() # noqa
    fListRows            = A() # noqa
    fcColumnInfo         = A() # noqa
    fMatchEntry          = A() # noqa
    fListStyle           = A() # noqa
    fShowDropButtonWhen  = A() # noqa
    _UnusedBits1         = A() # noqa
    fDropButtonStyle     = A() # noqa
    fMultiSelect         = A() # noqa
    fValue               = A() # noqa
    fCaption             = A() # noqa
    fPicturePosition     = A() # noqa
    fBorderColor         = A() # noqa
    fSpecialEffect       = A() # noqa
    fMouseIcon           = A() # noqa
    fPicture             = A() # noqa
    fAccelerator         = A() # noqa
    _UnusedBits2         = A() # noqa
    _Reserved            = A() # noqa
    fGroupName           = A() # noqa


class ImagePropMask(FlagAccessMixin, IntFlag):
    """
    ImagePropMask: [MS-OFORMS] 2.2.3.2
    """
    _UnusedBits1_1       = A() # noqa
    _UnusedBits1_2       = A() # noqa
    fAutoSize            = A() # noqa
    fBorderColor         = A() # noqa
    fBackColor           = A() # noqa
    fBorderStyle         = A() # noqa
    fMousePointer        = A() # noqa
    fPictureSizeMode     = A() # noqa
    fSpecialEffect       = A() # noqa
    fSize                = A() # noqa
    fPicture             = A() # noqa
    fPictureAlignment    = A() # noqa
    fPictureTiling       = A() # noqa
    fVariousPropertyBits = A() # noqa
    fMouseIcon           = A() # noqa


class CommandButtonPropMask(FlagAccessMixin, IntFlag):
    """
    CommandButtonPropMask: [MS-OFORMS] 2.2.1.2
    """
    fForeColor           = A() # noqa
    fBackColor           = A() # noqa
    fVariousPropertyBits = A() # noqa
    fCaption             = A() # noqa
    fPicturePosition     = A() # noqa
    fSize                = A() # noqa
    fMousePointer        = A() # noqa
    fPicture             = A() # noqa
    fAccelerator         = A() # noqa
    fTakeFocusOnClick    = A() # noqa
    fMouseIcon           = A() # noqa


class SpinButtonPropMask(FlagAccessMixin, IntFlag):
    """
    SpinButtonPropMask: [MS-OFORMS] 2.2.8.2
    """
    fForeColor           = A() # noqa
    fBackColor           = A() # noqa
    fVariousPropertyBits = A() # noqa
    fSize                = A() # noqa
    _UnusedBits1         = A() # noqa
    fMin                 = A() # noqa
    fMax                 = A() # noqa
    fPosition            = A() # noqa
    fPrevEnabled         = A() # noqa
    fNextEnabled         = A() # noqa
    fSmallChange         = A() # noqa
    fOrientation         = A() # noqa
    fDelay               = A() # noqa
    fMouseIcon           = A() # noqa
    fMousePointer        = A() # noqa


class TabStripPropMask(FlagAccessMixin, IntFlag):
    """
    TabStripPropMask: [MS-OFORMS] 2.2.9.2
    """
    fListIndex           = A() # noqa
    fBackColor           = A() # noqa
    fForeColor           = A() # noqa
    _Unused1             = A() # noqa
    fSize                = A() # noqa
    fItems               = A() # noqa
    fMousePointer        = A() # noqa
    _Unused2             = A() # noqa
    fTabOrientation      = A() # noqa
    fTabStyle            = A() # noqa
    fMultiRow            = A() # noqa
    fTabFixedWidth       = A() # noqa
    fTabFixedHeight      = A() # noqa
    fTooltips            = A() # noqa
    _Unused3             = A() # noqa
    fTipStrings          = A() # noqa
    _Unused4             = A() # noqa
    fNames               = A() # noqa
    fVariousPropertyBits = A() # noqa
    fNewVersion          = A() # noqa
    fTabsAllocated       = A() # noqa
    fTags                = A() # noqa
    fTabData             = A() # noqa
    fAccelerator         = A() # noqa
    fMouseIcon           = A() # noqa


class LabelPropMask(FlagAccessMixin, IntFlag):
    """
    LabelPropMask: [MS-OFORMS] 2.2.4.2
    """
    fForeColor           = A() # noqa
    fBackColor           = A() # noqa
    fVariousPropertyBits = A() # noqa
    fCaption             = A() # noqa
    fPicturePosition     = A() # noqa
    fSize                = A() # noqa
    fMousePointer        = A() # noqa
    fBorderColor         = A() # noqa
    fBorderStyle         = A() # noqa
    fSpecialEffect       = A() # noqa
    fPicture             = A() # noqa
    fAccelerator         = A() # noqa
    fMouseIcon           = A() # noqa


class ScrollBarPropMask(FlagAccessMixin, IntFlag):
    """
    ScrollBarPropMask: [MS-OFORMS] 2.2.7.2
    """
    fForeColor         = A() # noqa
    fBackColor         = A() # noqa
    fVariousPropertyBits = A() # noqa
    fSize              = A() # noqa
    fMousePointer      = A() # noqa
    fMin               = A() # noqa
    fMax               = A() # noqa
    fPosition          = A() # noqa
    _UnusedBits1       = A() # noqa
    fPrevEnabled       = A() # noqa
    fNextEnabled       = A() # noqa
    fSmallChange       = A() # noqa
    fLargeChange       = A() # noqa
    fOrientation       = A() # noqa
    fProportionalThumb = A() # noqa
    fDelay             = A() # noqa
    fMouseIcon         = A() # noqa


class ExtendedStream:
    """
    Wrapper around a raw byte stream with alignment-aware reads, padding support, and structured
    unpacking for parsing MS-OFORMS data.
    """

    def __init__(self, stream: IO[bytes], path: str):
        self._pos: int = 0
        self._jumps: list[tuple[str, object]] = []
        self._stream = stream
        self._path = path
        self._padding: bool = False
        self._pad_start: int = 0
        self._next_jump: tuple[str, object] | None = None

    @classmethod
    def open(cls, ole_file: OleFile, path: str) -> ExtendedStream:
        stream = ole_file.openstream(path)
        return cls(stream, path)

    def _read(self, size: int) -> bytes:
        self._pos += size
        return self._stream.read(size)

    def _pad(self, start: int, size: int = 4) -> None:
        offset = (self._pos - start) % size
        if offset:
            self._read(size - offset)

    def read(self, size: int) -> bytes:
        if self._padding:
            self._pad(self._pad_start, size)
        return self._read(size)

    @contextmanager
    def will_jump_to(self, size: int) -> Generator[None, None, None]:
        """
        Context manager that advances the stream to exactly `start + size` bytes after the block,
        where `start` is the position at entry.
        """
        start = self._pos
        try:
            yield
        finally:
            consumed = self._pos - start
            if consumed > size:
                self.raise_error(F'Bad jump: too much read ({consumed} > {size})')
            remaining = size - consumed
            if remaining > 0:
                self._read(remaining)

    @contextmanager
    def will_pad(self) -> Generator[None, None, None]:
        """
        Context manager that pads the stream to a 4-byte boundary after the enclosed block.
        """
        start = self._pos
        try:
            yield
        finally:
            self._pad(start)

    @contextmanager
    def padded_struct(self) -> Generator[None, None, None]:
        """
        Context manager that enables per-read padding mode; each read is padded to the read size's
        alignment boundary. Restores previous padding state on exit.
        """
        prev_padding = self._padding
        prev_pad_start = self._pad_start
        self._padding = True
        self._pad_start = self._pos
        try:
            yield
        finally:
            self._pad(self._pad_start)
            self._padding = prev_padding
            self._pad_start = prev_pad_start

    def unpacks(self, format: str, size: int) -> tuple:
        return struct.unpack(format, self.read(size))

    def unpack(self, format: str, size: int):
        return self.unpacks(format, size)[0]

    def raise_error(self, reason: str, back: int = 0) -> None:
        raise OleFormParsingError(F'{self._path}:{self._pos - back}: {reason}')

    def check_values(
        self, name: str, format: str, size: int, expected: tuple
    ) -> None:
        value = self.unpacks(format, size)
        if value != expected:
            self.raise_error(F'Invalid {name}: expected {expected!s} got {value!s}')

    def check_1value(self, name: str, format: str, size: int, expected) -> None:
        self.check_values(name, format, size, (expected,))


def consume_TextProps(stream: ExtendedStream) -> None:
    """
    TextProps: [MS-OFORMS] 2.3.1
    """
    stream.check_values('TextProps (versions)', '<BB', 2, (0, 2))
    cb = stream.unpack('<H', 2)
    stream.read(cb)


def consume_GuidAndFont(stream: ExtendedStream) -> None:
    """
    GuidAndFont: [MS-OFORMS] 2.4.7
    """
    uuids = stream.unpacks('<LHH', 8) + stream.unpacks('>Q', 8)
    if uuids == (199447043, 36753, 4558, 11376937813817407569):
        # UUID == {0BE35203-8F91-11CE-9DE300AA004BB851}
        # StdFont: [MS-OFORMS] 2.4.12
        stream.check_1value('StdFont (version)', '<B', 1, 1)
        stream.read(9)
        face_len = stream.unpack('<B', 1)
        stream.read(face_len)
    elif uuids == (2948729120, 55886, 4558, 13349514450607572916):
        # UUID == {AFC20920-DA4E-11CE-B94300AA006887B4}
        consume_TextProps(stream)
    else:
        stream.raise_error('Invalid GuidAndFont (UUID)', 16)


def consume_GuidAndPicture(stream: ExtendedStream) -> None:
    """
    GuidAndPicture: [MS-OFORMS] 2.4.8
    """
    # UUID == {0BE35204-8F91-11CE-9DE3-00AA004BB851}
    stream.check_values('GuidAndPicture (UUID part 1)', '<LHH', 8, (199447044, 36753, 4558))
    stream.check_1value('GuidAndPicture (UUID part 1)', '>Q', 8, 11376937813817407569)
    # StdPicture: [MS-OFORMS] 2.4.13
    stream.check_1value('StdPicture (Preamble)', '<L', 4, 0x0000746C)
    size = stream.unpack('<L', 4)
    stream.read(size)


def consume_CountOfBytesWithCompressionFlag(
    stream: ExtendedStream,
) -> int:
    """
    CountOfBytesWithCompressionFlag: [MS-OFORMS] 2.4.14.2 / 2.4.14.3
    """
    count = stream.unpack('<L', 4)
    return count & 0x7FFFFFFF


def consume_SiteClassInfo(stream: ExtendedStream) -> None:
    """
    SiteClassInfo: [MS-OFORMS] 2.2.10.10.1
    """
    stream.check_1value('SiteClassInfo (version)', '<H', 2, 0)
    cb = stream.unpack('<H', 2)
    stream.read(cb)


def consume_FormObjectDepthTypeCount(stream: ExtendedStream) -> int:
    """
    FormObjectDepthTypeCount: [MS-OFORMS] 2.2.10.7
    """
    _depth, mixed = stream.unpacks('<BB', 2)
    if mixed & 0x80:
        stream.check_1value('FormObjectDepthTypeCount (SITE_TYPE)', '<B', 1, 1)
        return mixed ^ 0x80
    if mixed != 1:
        stream.raise_error(
            F'Invalid FormObjectDepthTypeCount (SITE_TYPE):'
            F' expected 1 got {mixed!s}')
    return 1


def consume_OleSiteConcreteControl(
    stream: ExtendedStream,
) -> dict[str, object]:
    """
    OleSiteConcreteControl: [MS-OFORMS] 2.2.10.12.1
    """
    stream.check_1value('OleSiteConcreteControl (version)', '<H', 2, 0)
    cb_site = stream.unpack('<H', 2)
    with stream.will_jump_to(cb_site):
        propmask = SitePropMask(stream.unpack('<L', 4))
        with stream.padded_struct():
            name_len = tag_len = id_val = 0
            if propmask.fName:
                name_len = consume_CountOfBytesWithCompressionFlag(stream)
            if propmask.fTag:
                tag_len = consume_CountOfBytesWithCompressionFlag(stream)
            if propmask.fID:
                id_val = stream.unpack('<L', 4)
            consume(propmask, stream, {
                SitePropMask.fHelpContextID    : 4,
                SitePropMask.fBitFlags         : 4,
                SitePropMask.fObjectStreamSize : 4,
            })
            tabindex = clsid_cache_index = 0
            if propmask.fTabIndex:
                tabindex = stream.unpack('<H', 2)
            if propmask.fClsidCacheIndex:
                clsid_cache_index = stream.unpack('<H', 2)
            if propmask.fGroupID:
                stream.read(2)
            control_tip_text_len = 0
            if propmask.fControlTipText:
                control_tip_text_len = (consume_CountOfBytesWithCompressionFlag(stream))
            consume(propmask, stream, {
                SitePropMask.fRuntimeLicKey : 4,
                SitePropMask.fControlSource : 4,
                SitePropMask.fRowSource     : 4,
            })
        name = stream.read(name_len) if name_len > 0 else None
        tag = stream.read(tag_len) if tag_len > 0 else None
        if propmask.fPosition:
            stream.read(8)
        control_tip_text = stream.read(control_tip_text_len)
        if len(control_tip_text) == 0:
            control_tip_text = None
    return {
        'name': name,
        'tag': tag,
        'id': id_val,
        'tabindex': tabindex,
        'ClsidCacheIndex': clsid_cache_index,
        'value': None,
        'caption': None,
        'control_tip_text': control_tip_text,
    }


def consume_FormControl(
    stream: ExtendedStream,
) -> Generator[dict[str, object], None, None]:
    """
    FormControl: [MS-OFORMS] 2.2.10.1

    Generator that yields one site dict per embedded control.
    """
    stream.check_values('FormControl (versions)', '<BB', 2, (0, 4))
    cb_form = stream.unpack('<H', 2)
    with stream.will_jump_to(cb_form):
        propmask = FormPropMask(stream.unpack('<L', 4))
        consume(propmask, stream, {
            FormPropMask.fBackColor       : 4,
            FormPropMask.fForeColor       : 4,
            FormPropMask.fNextAvailableID : 4,
        })
        if propmask.fBooleanProperties:
            boolean_properties = stream.unpack('<L', 4)
            no_save_class_table = (boolean_properties & (1 << 15)) >> 15
        else:
            no_save_class_table = 0
    if propmask.fMouseIcon:
        consume_GuidAndPicture(stream)
    if propmask.fFont:
        consume_GuidAndFont(stream)
    if propmask.fPicture:
        consume_GuidAndPicture(stream)
    if not no_save_class_table:
        count_of_site_class_info = stream.unpack('<H', 2)
        for _ in range(count_of_site_class_info):
            consume_SiteClassInfo(stream)
    count_of_sites, count_of_bytes = stream.unpacks('<LL', 8)
    remaining = count_of_sites
    with stream.will_jump_to(count_of_bytes):
        with stream.will_pad():
            while remaining > 0:
                remaining -= consume_FormObjectDepthTypeCount(stream)
        for _ in range(count_of_sites):
            yield consume_OleSiteConcreteControl(stream)


def consume_MorphDataControl(
    stream: ExtendedStream,
) -> tuple[bytes, bytes | str, bytes | str]:
    """
    MorphDataControl: [MS-OFORMS] 2.2.5.1

    Returns (value, caption, group_name).
    """
    stream.check_values('MorphDataControl (versions)', '<BB', 2, (0, 2))
    cb = stream.unpack('<H', 2)
    with stream.will_jump_to(cb):
        propmask = MorphDataPropMask(stream.unpack('<Q', 8))
        with stream.padded_struct():
            consume(propmask, stream, {
                MorphDataPropMask.fVariousPropertyBits : 4,
                MorphDataPropMask.fBackColor           : 4,
                MorphDataPropMask.fForeColor           : 4,
                MorphDataPropMask.fMaxLength           : 4,
                MorphDataPropMask.fBorderStyle         : 1,
                MorphDataPropMask.fScrollBars          : 1,
                MorphDataPropMask.fDisplayStyle        : 1,
                MorphDataPropMask.fMousePointer        : 1,
                MorphDataPropMask.fPasswordChar        : 2,
                MorphDataPropMask.fListWidth           : 4,
                MorphDataPropMask.fBoundColumn         : 2,
                MorphDataPropMask.fTextColumn          : 2,
                MorphDataPropMask.fColumnCount         : 2,
                MorphDataPropMask.fListRows            : 2,
                MorphDataPropMask.fcColumnInfo         : 2,
                MorphDataPropMask.fMatchEntry          : 1,
                MorphDataPropMask.fListStyle           : 1,
                MorphDataPropMask.fShowDropButtonWhen  : 1,
                MorphDataPropMask.fDropButtonStyle     : 1,
                MorphDataPropMask.fMultiSelect         : 1,
            })
            value_size = (consume_CountOfBytesWithCompressionFlag(stream)
                if propmask.fValue else 0)
            caption_size = (consume_CountOfBytesWithCompressionFlag(stream)
                if propmask.fCaption else 0)
            consume(propmask, stream, {
                MorphDataPropMask.fPicturePosition : 4,
                MorphDataPropMask.fBorderColor     : 4,
                MorphDataPropMask.fSpecialEffect   : 4,
                MorphDataPropMask.fMouseIcon       : 2,
                MorphDataPropMask.fPicture         : 2,
                MorphDataPropMask.fAccelerator     : 2,
            })
            group_name_size = (consume_CountOfBytesWithCompressionFlag(stream)
                if propmask.fGroupName else 0)
        stream.read(8)
        value = stream.read(value_size)
        caption = stream.read(caption_size) if caption_size > 0 else ""
        group_name = stream.read(group_name_size) if group_name_size > 0 else ""
    if propmask.fMouseIcon:
        consume_GuidAndPicture(stream)
    if propmask.fPicture:
        consume_GuidAndPicture(stream)
    consume_TextProps(stream)
    return (value, caption, group_name)


def consume_ImageControl(stream: ExtendedStream) -> None:
    """
    ImageControl: [MS-OFORMS] 2.2.3.1
    """
    stream.check_values('ImageControl (versions)', '<BB', 2, (0, 2))
    cb = stream.unpack('<H', 2)
    with stream.will_jump_to(cb):
        propmask = ImagePropMask(stream.unpack('<L', 4))
    if propmask.fPicture:
        consume_GuidAndPicture(stream)
    if propmask.fMouseIcon:
        consume_GuidAndPicture(stream)


def consume_CommandButtonControl(stream: ExtendedStream) -> None:
    """
    CommandButtonControl: [MS-OFORMS] 2.2.1.1
    """
    stream.check_values('CommandButtonControl (versions)', '<BB', 2, (0, 2))
    cb = stream.unpack('<H', 2)
    with stream.will_jump_to(cb):
        propmask = CommandButtonPropMask(stream.unpack('<L', 4))
    if propmask.fPicture:
        consume_GuidAndPicture(stream)
    if propmask.fMouseIcon:
        consume_GuidAndPicture(stream)
    consume_TextProps(stream)


def consume_SpinButtonControl(stream: ExtendedStream) -> None:
    """
    SpinButtonControl: [MS-OFORMS] 2.2.8.1
    """
    stream.check_values('SpinButtonControl (versions)', '<BB', 2, (0, 2))
    cb = stream.unpack('<H', 2)
    with stream.will_jump_to(cb):
        propmask = SpinButtonPropMask(stream.unpack('<L', 4))
    if propmask.fMouseIcon:
        consume_GuidAndPicture(stream)


def consume_TabStripControl(stream: ExtendedStream) -> None:
    """
    TabStripControl: [MS-OFORMS] 2.2.9.1
    """
    stream.check_values('TabStripControl (versions)', '<BB', 2, (0, 2))
    cb = stream.unpack('<H', 2)
    with stream.will_jump_to(cb):
        propmask = TabStripPropMask(stream.unpack('<L', 4))
        consume(propmask, stream, {
            TabStripPropMask.fListIndex           : 4,
            TabStripPropMask.fBackColor           : 4,
            TabStripPropMask.fForeColor           : 4,
            TabStripPropMask.fSize                : 4,
            TabStripPropMask.fMousePointer        : 1,
            TabStripPropMask.fTabOrientation      : 4,
            TabStripPropMask.fTabStyle            : 4,
            TabStripPropMask.fTabFixedWidth       : 4,
            TabStripPropMask.fTabFixedHeight      : 4,
            TabStripPropMask.fTipStrings          : 4,
            TabStripPropMask.fNames               : 4,
            TabStripPropMask.fVariousPropertyBits : 4,
            TabStripPropMask.fTabsAllocated       : 4,
            TabStripPropMask.fTags                : 4,
        })
        tab_data = 0
        if propmask.fTabData:
            tab_data = stream.unpack('<L', 4)
    if propmask.fMouseIcon:
        consume_GuidAndPicture(stream)
    consume_TextProps(stream)
    for _ in range(tab_data):
        stream.read(4)


def consume_LabelControl(stream: ExtendedStream) -> bytes:
    """
    LabelControl: [MS-OFORMS] 2.2.4.1

    Returns the caption bytes.
    """
    stream.check_values('LabelControl (versions)', '<BB', 2, (0, 2))
    cb = stream.unpack('<H', 2)
    with stream.will_jump_to(cb):
        propmask = LabelPropMask(stream.unpack('<L', 4))
        with stream.padded_struct():
            consume(propmask, stream, {
                LabelPropMask.fForeColor           : 4,
                LabelPropMask.fBackColor           : 4,
                LabelPropMask.fVariousPropertyBits : 4,
            })
            caption_size = (consume_CountOfBytesWithCompressionFlag(stream)
                if propmask.fCaption else 0)
            consume(propmask, stream, {
                LabelPropMask.fPicturePosition : 4,
                LabelPropMask.fMousePointer    : 1,
                LabelPropMask.fBorderColor     : 4,
                LabelPropMask.fBorderStyle     : 2,
                LabelPropMask.fSpecialEffect   : 2,
                LabelPropMask.fPicture         : 2,
                LabelPropMask.fAccelerator     : 2,
                LabelPropMask.fMouseIcon       : 2,
            })
        caption = stream.read(caption_size)
        stream.read(8)
    if propmask.fPicture:
        consume_GuidAndPicture(stream)
    if propmask.fMouseIcon:
        consume_GuidAndPicture(stream)
    consume_TextProps(stream)
    return caption


def consume_ScrollBarControl(stream: ExtendedStream) -> None:
    """
    ScrollBarControl: [MS-OFORMS] 2.2.7.1
    """
    stream.check_values('LabelControl (versions)', '<BB', 2, (0, 2))
    cb = stream.unpack('<H', 2)
    with stream.will_jump_to(cb):
        propmask = ScrollBarPropMask(stream.unpack('<L', 4))
    if propmask.fMouseIcon:
        consume_GuidAndPicture(stream)


def extract_OleFormVariables(
    ole_file: OleFile,
    stream_dir: str,
) -> list[dict[str, object]]:
    """
    Extract OLE form control variables from an OLE compound file. Opens the 'f' (form) and 'o'
    (object data) streams under `stream_dir`, parses embedded controls, and returns a list of
    variable dicts with keys: name, tag, id, tabindex, ClsidCacheIndex, value, caption,
    control_tip_text, and optionally group_name.
    """
    control = ExtendedStream.open(ole_file, F'{stream_dir}/f')
    variables = list(consume_FormControl(control))
    data = ExtendedStream.open(ole_file, F'{stream_dir}/o')
    for var in variables:
        cci = var['ClsidCacheIndex']
        if cci == 7:
            consume_FormControl(data)
        elif cci == 12:
            consume_ImageControl(data)
        elif cci == 14:
            consume_FormControl(data)
        elif cci in (15, 23, 24, 25, 26, 27, 28):
            var['value'], var['caption'], var['group_name'] = (consume_MorphDataControl(data))
        elif cci == 16:
            consume_SpinButtonControl(data)
        elif cci == 17:
            consume_CommandButtonControl(data)
        elif cci == 18:
            consume_TabStripControl(data)
        elif cci == 21:
            var['caption'] = consume_LabelControl(data)
        elif cci == 47:
            consume_ScrollBarControl(data)
        elif cci == 57:
            consume_FormControl(data)
        else:
            break
    return variables
