"""
Data structures and methods for parsing Inno Setup installer archives. The design is based
on [innoextract][IE] source code and its Python port in [Malcat][MC]. The [Malcat][MC]
implementation served as the initial template but was re-written to work with refinery's
data structures.

[IE]: https://constexpr.org/innoextract/
[MC]: https://malcat.fr/
"""
from __future__ import annotations

import abc
import bz2
import codecs
import dataclasses
import enum
import functools
import lzma
import re
import struct
import weakref
import zlib

from functools import cached_property
from hashlib import md5, pbkdf2_hmac, sha1, sha256
from typing import TYPE_CHECKING, Callable, Iterator, NamedTuple

from refinery.lib.decompression import decompress_pieces, inflate_pieces, parse_lzma_properties
from refinery.lib.dt import filetime
from refinery.lib.inno.ifps import IFPSFile
from refinery.lib.inno.release import ReleaseRange, SetupRelease, next_release
from refinery.lib.lcid import DEFAULT_CODEPAGE, LCID
from refinery.lib.solid import SolidStream, SolidStreamTruncated
from refinery.lib.structures import Struct, StructReader, StructReaderBits
from refinery.lib.tools import copy_exception, exception_to_string, one
from refinery.lib.types import buf
from refinery.units import Unit

if TYPE_CHECKING:
    from typing import (
        ClassVar,
        TypeVar,
    )

    from refinery.lib.inno.host import SetupConstants
    _T = TypeVar('_T', bound=Struct)
    _E = TypeVar('_E', bound=enum.IntEnum)


class InvalidPassword(ValueError):
    def __init__(self, password: str | None = None):
        if password is None:
            super().__init__('A password is required and none was given.')
        else:
            super().__init__('The given password is not correct.')


class InnoChecksumMismatch(ValueError):
    """
    Raised when the data of a file does not match its checksum. The data is available as the
    attribute `data` of the exception.
    """
    def __init__(self, message: str, data: buf):
        super().__init__(message)
        self.data = data


class IncorrectVersion(RuntimeError):
    pass


class FileChunkOutOfBounds(LookupError):
    pass


class IVF(enum.IntFlag):
    NoFlag   = 0b0000 # noqa
    Legacy   = 0b0001 # noqa
    Bits16   = 0b0010 # noqa
    UTF_16   = 0b0100 # noqa
    InnoSX   = 0b1000 # noqa
    Legacy32 = 0b0001
    Legacy16 = 0b0011
    IsLegacy = 0b0011


def _enum(options: type[_E], value: int, default: _E):
    try:
        return options(value)
    except ValueError:
        return default


class InnoVersion(NamedTuple):
    major: int
    minor: int
    patch: int
    build: int = 0
    flags: IVF = IVF.NoFlag

    @property
    def semver(self):
        return (self.major, self.minor, self.patch, self.build)

    @property
    def unicode(self):
        return self.flags & IVF.UTF_16 == IVF.UTF_16

    @property
    def legacy(self):
        return self.flags & IVF.Legacy

    @property
    def ascii(self):
        return self.flags & IVF.UTF_16 == IVF.NoFlag

    @property
    def isx(self):
        return bool(self.flags & IVF.InnoSX)

    @property
    def bits(self):
        return 0x10 if self.flags & IVF.Bits16 else 0x20

    @classmethod
    def ParseLegacy(cls, dfn: bytes):
        v, s, _ = dfn.partition(B'\x1A')
        if s and (m := re.fullmatch(BR'i(\d+)\.(\d+)\.(\d+)--(16|32)', v)):
            major = int(m[1])
            minor = int(m[2])
            build = int(m[3])
            flags = IVF.Legacy16 if m[3] == B'16' else IVF.Legacy32
            return cls(major, minor, build, 0, flags)
        raise ValueError(dfn)

    @classmethod
    def Parse(cls, dfn: bytes):
        versions: list[InnoVersion] = []
        for match in [m.groups() for m in re.finditer(rb'(.*?)\((\d+(?:\.\d+){2,3})(?:.*?\(([uU])\))?', dfn)]:
            sv = tuple(map(int, match[1].split(B'.')))
            sv = (sv + (0,))[:4]
            vf = IVF.NoFlag
            if sv >= (6, 3, 0) or match[2]:
                vf |= IVF.UTF_16
            if any(isx in match[0] for isx in (B'My Inno Setup Extensions', B'with ISX')):
                vf |= IVF.InnoSX
            minor, major, patch, build = sv
            versions.append(InnoVersion(minor, major, patch, build, vf))
        if len(versions) == 1:
            return versions[0]
        if len(versions) == 2:
            a, b = versions
            return InnoVersion(*max(a.semver, b.semver), a.flags | b.flags)
        raise ValueError(dfn)

    def __str__(self):
        v = F'v{self.major}.{self.minor}.{self.patch:02d}.{self.build}'
        a = R'a'
        u = R'u'
        if self.flags & IVF.InnoSX:
            a = R''
            v = F'{v}x'
        t = u if self.flags & IVF.UTF_16 else a
        v = F'{v}{t}'
        if b := {
            IVF.Legacy16: '16',
            IVF.Legacy32: '32',
        }.get(self.flags & IVF.IsLegacy):
            v = F'{v}/{b}'
        return v

    def __repr__(self):
        return str(self)

    def is_ambiguous(self):
        try:
            return _IS_AMBIGUOUS[self]
        except KeyError:
            return True


_I = InnoVersion

_DEFAULT_INNO_VERSION = _I(5, 0, 0, 0, IVF.UTF_16)

_IS_AMBIGUOUS = {
    _I(1, 2, 10, 0, IVF.Legacy16): False,
    _I(1, 2, 10, 0, IVF.Legacy32): False,
    _I(1, 3,  3, 0, IVF.NoFlag): False, # noqa
    _I(1, 3,  9, 0, IVF.NoFlag): False, # noqa
    _I(1, 3, 10, 0, IVF.NoFlag): False, # noqa
    _I(1, 3, 10, 0, IVF.InnoSX): False, # noqa
    _I(1, 3, 12, 1, IVF.InnoSX): False, # noqa
    _I(1, 3, 21, 0, IVF.NoFlag): True,  # noqa
    _I(1, 3, 21, 0, IVF.InnoSX): True,  # noqa
    _I(1, 3, 24, 0, IVF.NoFlag): False, # noqa
    _I(1, 3, 24, 0, IVF.InnoSX): False, # noqa
    _I(1, 3, 25, 0, IVF.NoFlag): False, # noqa
    _I(1, 3, 25, 0, IVF.InnoSX): False, # noqa
    _I(2, 0,  0, 0, IVF.NoFlag): False, # noqa
    _I(2, 0,  1, 0, IVF.NoFlag): True,  # noqa
    _I(2, 0,  2, 0, IVF.NoFlag): False, # noqa
    _I(2, 0,  5, 0, IVF.NoFlag): False, # noqa
    _I(2, 0,  6, 0, IVF.NoFlag): False, # noqa
    _I(2, 0,  6, 0, IVF.InnoSX): False, # noqa
    _I(2, 0,  7, 0, IVF.NoFlag): False, # noqa
    _I(2, 0,  8, 0, IVF.NoFlag): False, # noqa
    _I(2, 0,  8, 0, IVF.InnoSX): False, # noqa
    _I(2, 0, 10, 0, IVF.InnoSX): False, # noqa
    _I(2, 0, 11, 0, IVF.NoFlag): False, # noqa
    _I(2, 0, 11, 0, IVF.InnoSX): False, # noqa
    _I(2, 0, 17, 0, IVF.NoFlag): False, # noqa
    _I(2, 0, 17, 0, IVF.InnoSX): False, # noqa
    _I(2, 0, 18, 0, IVF.NoFlag): False, # noqa
    _I(2, 0, 18, 0, IVF.InnoSX): False, # noqa
    _I(3, 0,  0, 0, IVF.NoFlag): False, # noqa
    _I(3, 0,  1, 0, IVF.NoFlag): False, # noqa
    _I(3, 0,  1, 0, IVF.InnoSX): False, # noqa
    _I(3, 0,  3, 0, IVF.NoFlag): True,  # noqa
    _I(3, 0,  3, 0, IVF.InnoSX): True,  # noqa
    _I(3, 0,  4, 0, IVF.NoFlag): False, # noqa
    _I(3, 0,  4, 0, IVF.InnoSX): False, # noqa
    _I(3, 0,  5, 0, IVF.NoFlag): False, # noqa
    _I(3, 0,  6, 1, IVF.InnoSX): False, # noqa
    _I(4, 0,  0, 0, IVF.NoFlag): False, # noqa
    _I(4, 0,  1, 0, IVF.NoFlag): False, # noqa
    _I(4, 0,  3, 0, IVF.NoFlag): False, # noqa
    _I(4, 0,  5, 0, IVF.NoFlag): False, # noqa
    _I(4, 0,  9, 0, IVF.NoFlag): False, # noqa
    _I(4, 0, 10, 0, IVF.NoFlag): False, # noqa
    _I(4, 0, 11, 0, IVF.NoFlag): False, # noqa
    _I(4, 1,  0, 0, IVF.NoFlag): False, # noqa
    _I(4, 1,  2, 0, IVF.NoFlag): False, # noqa
    _I(4, 1,  3, 0, IVF.NoFlag): False, # noqa
    _I(4, 1,  4, 0, IVF.NoFlag): False, # noqa
    _I(4, 1,  5, 0, IVF.NoFlag): False, # noqa
    _I(4, 1,  6, 0, IVF.NoFlag): False, # noqa
    _I(4, 1,  8, 0, IVF.NoFlag): False, # noqa
    _I(4, 2,  0, 0, IVF.NoFlag): False, # noqa
    _I(4, 2,  1, 0, IVF.NoFlag): False, # noqa
    _I(4, 2,  2, 0, IVF.NoFlag): False, # noqa
    _I(4, 2,  3, 0, IVF.NoFlag): True,  # noqa
    _I(4, 2,  4, 0, IVF.NoFlag): False, # noqa
    _I(4, 2,  5, 0, IVF.NoFlag): False, # noqa
    _I(4, 2,  6, 0, IVF.NoFlag): False, # noqa
    _I(5, 0,  0, 0, IVF.NoFlag): False, # noqa
    _I(5, 0,  1, 0, IVF.NoFlag): False, # noqa
    _I(5, 0,  3, 0, IVF.NoFlag): False, # noqa
    _I(5, 0,  4, 0, IVF.NoFlag): False, # noqa
    _I(5, 1,  0, 0, IVF.NoFlag): False, # noqa
    _I(5, 1,  2, 0, IVF.NoFlag): False, # noqa
    _I(5, 1,  7, 0, IVF.NoFlag): False, # noqa
    _I(5, 1, 10, 0, IVF.NoFlag): False, # noqa
    _I(5, 1, 13, 0, IVF.NoFlag): False, # noqa
    _I(5, 2,  0, 0, IVF.NoFlag): False, # noqa
    _I(5, 2,  1, 0, IVF.NoFlag): False, # noqa
    _I(5, 2,  3, 0, IVF.NoFlag): False, # noqa
    _I(5, 2,  5, 0, IVF.NoFlag): False, # noqa
    _I(5, 2,  5, 0, IVF.UTF_16): False, # noqa
    _I(5, 3,  0, 0, IVF.NoFlag): False, # noqa
    _I(5, 3,  0, 0, IVF.UTF_16): False, # noqa
    _I(5, 3,  3, 0, IVF.NoFlag): False, # noqa
    _I(5, 3,  3, 0, IVF.UTF_16): False, # noqa
    _I(5, 3,  5, 0, IVF.NoFlag): False, # noqa
    _I(5, 3,  5, 0, IVF.UTF_16): False, # noqa
    _I(5, 3,  6, 0, IVF.NoFlag): False, # noqa
    _I(5, 3,  6, 0, IVF.UTF_16): False, # noqa
    _I(5, 3,  7, 0, IVF.NoFlag): False, # noqa
    _I(5, 3,  7, 0, IVF.UTF_16): False, # noqa
    _I(5, 3,  8, 0, IVF.NoFlag): False, # noqa
    _I(5, 3,  8, 0, IVF.UTF_16): False, # noqa
    _I(5, 3,  9, 0, IVF.NoFlag): False, # noqa
    _I(5, 3,  9, 0, IVF.UTF_16): False, # noqa
    _I(5, 3, 10, 0, IVF.NoFlag): True,  # noqa
    _I(5, 3, 10, 0, IVF.UTF_16): True,  # noqa
    _I(5, 3, 10, 1, IVF.NoFlag): False, # noqa
    _I(5, 3, 10, 1, IVF.UTF_16): False, # noqa
    _I(5, 4,  2, 0, IVF.NoFlag): True,  # noqa
    _I(5, 4,  2, 0, IVF.UTF_16): True,  # noqa
    _I(5, 4,  2, 1, IVF.NoFlag): False, # noqa
    _I(5, 4,  2, 1, IVF.UTF_16): False, # noqa
    _I(5, 5,  0, 0, IVF.NoFlag): True,  # noqa
    _I(5, 5,  0, 0, IVF.UTF_16): True,  # noqa
    _I(5, 5,  0, 1, IVF.NoFlag): False, # noqa
    _I(5, 5,  0, 1, IVF.UTF_16): False, # noqa
    _I(5, 5,  6, 0, IVF.NoFlag): False, # noqa
    _I(5, 5,  6, 0, IVF.UTF_16): False, # noqa
    _I(5, 5,  7, 0, IVF.NoFlag): True,  # noqa
    _I(5, 5,  7, 0, IVF.UTF_16): True,  # noqa
    _I(5, 5,  7, 1, IVF.NoFlag): True,  # noqa
    _I(5, 5,  7, 1, IVF.UTF_16): True,  # noqa
    _I(5, 6,  0, 0, IVF.NoFlag): False, # noqa
    _I(5, 6,  0, 0, IVF.UTF_16): False, # noqa
    _I(5, 6,  2, 0, IVF.NoFlag): False, # noqa
    _I(5, 6,  2, 0, IVF.UTF_16): False, # noqa
    _I(6, 0,  0, 0, IVF.UTF_16): False, # noqa
    _I(6, 1,  0, 0, IVF.UTF_16): False, # noqa
    _I(6, 3,  0, 0, IVF.UTF_16): False, # noqa
    _I(6, 4,  0, 0, IVF.UTF_16): False, # noqa
    _I(6, 4,  0, 1, IVF.UTF_16): False, # noqa
    _I(6, 4,  1, 0, IVF.UTF_16): False, # noqa
    _I(6, 4,  2, 0, IVF.UTF_16): False, # noqa f80c9ea
    _I(6, 4,  3, 0, IVF.UTF_16): False, # noqa 
    _I(6, 5,  0, 0, IVF.UTF_16): False, # noqa
    _I(6, 5,  1, 0, IVF.UTF_16): False, # noqa 99c1859
    _I(6, 5,  2, 0, IVF.UTF_16): False, # noqa
    _I(6, 5,  3, 0, IVF.UTF_16): False, # noqa
    _I(6, 5,  4, 0, IVF.UTF_16): False, # noqa 9610981
    _I(6, 6,  0, 0, IVF.UTF_16): False, # noqa
    _I(6, 6,  1, 0, IVF.UTF_16): False, # noqa
    _I(6, 7,  0, 0, IVF.UTF_16): False, # noqa
    _I(6, 7,  1, 0, IVF.UTF_16): False, # noqa
    _I(6, 7,  2, 0, IVF.UTF_16): False, # noqa
    _I(6, 7,  3, 0, IVF.UTF_16): False, # noqa
    _I(7, 0,  0, 1, IVF.UTF_16): False, # noqa
    _I(7, 0,  0, 3, IVF.UTF_16): False, # noqa
    _I(7, 0,  1, 0, IVF.UTF_16): False, # noqa
}

_VERSIONS = sorted(_IS_AMBIGUOUS)

_TEXT_DIRECTIVE_FIELDS = {
    'AppName'               : 'AppName',
    'AppVerName'            : 'AppVersionedName',
    'AppVersion'            : 'AppVersion',
    'AppCopyright'          : 'AppCopyright',
    'AppMutex'              : 'AppMutex',
    'SetupMutex'            : 'SetupMutex',
    'AppId'                 : 'AppId',
    'DefaultUserInfoName'   : 'DefaultUsername',
    'DefaultUserInfoOrg'    : 'DefaultOrganisation',
    'DefaultUserInfoSerial' : 'DefaultSerial',
    'DefaultDirName'        : 'DefaultDirName',
    'DefaultGroupName'      : 'DefaultGroupName',
    'UninstallFilesDir'     : 'UninstallFilesDir',
    'UninstallDisplayName'  : 'UninstallName',
    'UninstallDisplayIcon'  : 'UninstallIcon',
    'AppPublisher'          : 'AppPublisher',
    'AppPublisherURL'       : 'AppPublisherUrl',
    'AppSupportPhone'       : 'AppSupportPhone',
    'AppSupportURL'         : 'AppSupportUrl',
    'AppUpdatesURL'         : 'AppUpdatesUrl',
    'AppReadmeFile'         : 'AppReadmeFile',
    'AppContact'            : 'AppContact',
    'AppComments'           : 'AppComment',
    'AppModifyPath'         : 'AppModifyPath',
}
"""
The fields of the setup header that hold the texts of `TextDirective`, by directive.
"""

_SETUP_PROGRAM_RELEASE = [
    re.compile(BR'Inno Setup version (\d+)\.(\d+)\.(\d+)'),
    re.compile(BR'I\0n\0n\0o\0 \0S\0e\0t\0u\0p\0 \0v\0e\0r\0s\0i\0o\0n\0 \0((?:\d\0)+)\.\0((?:\d\0)+)\.\0((?:\d\0)+)'),
]
"""
The text in which the setup program of an installer names its release, in ANSI and in Unicode
builds.
"""


class InnoStruct(Struct):
    def __init__(self, reader: StructReader[memoryview], version: InnoVersion, codec: str = 'latin1'):
        if version.unicode:
            self._read_string = functools.partial(
                reader.read_length_prefixed_utf16, bytecount=True)
            self._decode = functools.partial(codecs.decode, encoding='utf-16le', errors='replace')
        else:
            def _decode(data: bytes | bytearray | memoryview) -> str:
                try:
                    return codecs.decode(data, codec)
                except (LookupError, UnicodeDecodeError):
                    # TODO
                    return codecs.decode(data, 'latin1')

            def _read():
                return _decode(reader.read_length_prefixed())
            self._read_string = _read
            self._decode = _decode


class CheckSumType(enum.IntEnum):
    Missing = 0 # noqa
    Adler32 = 1 # noqa
    CRC32   = 2 # noqa
    MD5     = 3 # noqa
    SHA1    = 4 # noqa
    SHA256  = 5 # noqa

    def strong(self):
        return self.value >= 3


class Flags(enum.IntFlag):
    Empty                       = 0           # noqa
    DisableStartupPrompt        = enum.auto() # noqa
    Uninstallable               = enum.auto() # noqa
    CreateAppDir                = enum.auto() # noqa
    DisableDirPage              = enum.auto() # noqa
    DisableDirExistsWarning     = enum.auto() # noqa
    DisableProgramGroupPage     = enum.auto() # noqa
    AllowNoIcons                = enum.auto() # noqa
    AlwaysRestart               = enum.auto() # noqa
    BackSolid                   = enum.auto() # noqa
    AlwaysUsePersonalGroup      = enum.auto() # noqa
    WindowVisible               = enum.auto() # noqa
    WindowShowCaption           = enum.auto() # noqa
    WindowResizable             = enum.auto() # noqa
    WindowStartMaximized        = enum.auto() # noqa
    EnableDirDoesntExistWarning = enum.auto() # noqa
    DisableAppendDir            = enum.auto() # noqa
    Password                    = enum.auto() # noqa
    AllowRootDirectory          = enum.auto() # noqa
    DisableFinishedPage         = enum.auto() # noqa
    AdminPrivilegesRequired     = enum.auto() # noqa
    AlwaysCreateUninstallIcon   = enum.auto() # noqa
    OverwriteUninstRegEntries   = enum.auto() # noqa
    ChangesAssociations         = enum.auto() # noqa
    CreateUninstallRegKey       = enum.auto() # noqa
    UsePreviousAppDir           = enum.auto() # noqa
    BackColorHorizontal         = enum.auto() # noqa
    UsePreviousGroup            = enum.auto() # noqa
    UpdateUninstallLogAppName   = enum.auto() # noqa
    UsePreviousSetupType        = enum.auto() # noqa
    DisableReadyMemo            = enum.auto() # noqa
    AlwaysShowComponentsList    = enum.auto() # noqa
    FlatComponentsList          = enum.auto() # noqa
    ShowComponentSizes          = enum.auto() # noqa
    UsePreviousTasks            = enum.auto() # noqa
    DisableReadyPage            = enum.auto() # noqa
    AlwaysShowDirOnReadyPage    = enum.auto() # noqa
    AlwaysShowGroupOnReadyPage  = enum.auto() # noqa
    BzipUsed                    = enum.auto() # noqa
    AllowUNCPath                = enum.auto() # noqa
    UserInfoPage                = enum.auto() # noqa
    UsePreviousUserInfo         = enum.auto() # noqa
    UninstallRestartComputer    = enum.auto() # noqa
    RestartIfNeededByRun        = enum.auto() # noqa
    ShowTasksTreeLines          = enum.auto() # noqa
    ShowLanguageDialog          = enum.auto() # noqa
    DetectLanguageUsingLocale   = enum.auto() # noqa
    AllowCancelDuringInstall    = enum.auto() # noqa
    WizardImageStretch          = enum.auto() # noqa
    AppendDefaultDirName        = enum.auto() # noqa
    AppendDefaultGroupName      = enum.auto() # noqa
    EncryptionUsed              = enum.auto() # noqa
    ChangesEnvironment          = enum.auto() # noqa
    ShowUndisplayableLanguages  = enum.auto() # noqa
    SetupLogging                = enum.auto() # noqa
    SignedUninstaller           = enum.auto() # noqa
    UsePreviousLanguage         = enum.auto() # noqa
    DisableWelcomePage          = enum.auto() # noqa
    CloseApplications           = enum.auto() # noqa
    RestartApplications         = enum.auto() # noqa
    AllowNetworkDrive           = enum.auto() # noqa
    ForceCloseApplications      = enum.auto() # noqa
    AppNameHasConsts            = enum.auto() # noqa
    UsePreviousPrivileges       = enum.auto() # noqa
    WizardResizable             = enum.auto() # noqa
    UninstallLogging            = enum.auto() # noqa
    WizardModern                = enum.auto() # noqa
    WizardBorderStyled          = enum.auto() # noqa
    WizardKeepAspectRatio       = enum.auto() # noqa
    WizardLightButtonsUnstyled  = enum.auto() # noqa
    RedirectionGuard            = enum.auto() # noqa
    WizardBevelsHidden          = enum.auto() # noqa


class AutoBool(enum.IntEnum):
    Auto = 0
    No = 1
    Yes = 2

    @classmethod
    def From(cls, b):
        return AutoBool.Yes if b else AutoBool.No


class WizardStyle(enum.IntEnum):
    Classic = 0
    Modern = 1


class WizardDarkStyle(enum.IntEnum):
    Light = 0
    Dark = 1
    Dynamic = 2


class WizardLightControlStyling(enum.IntEnum):
    All = 0
    AllButButtons = 1
    OnlyRequired = 2


class StoredAlphaFormat(enum.IntEnum):
    AlphaIgnored = 0
    AlphaDefined = 1
    AlphaPremultiplied = 2


class UninstallLogMode(enum.IntEnum):
    Append = 0
    New = 1
    Overwrite = 2


class SetupStyle(enum.IntEnum):
    Classic = 0
    Modern = 1


class PrivilegesRequired(enum.IntEnum):
    Nothing = 0
    PowerUser = 1
    Admin = 2
    Lowest = 3


class PrivilegesRequiredOverrideAllowed(enum.IntFlag):
    Empty = 0
    CommandLine = 1
    Dialog = 2


class LanguageDetection(enum.IntEnum):
    UI = 0
    Locale = 1
    Nothing = 2


class CompressionMethod(enum.IntEnum):
    Store = 0
    Flate = 1
    BZip2 = 2
    LZMA1 = 3
    LZMA2 = 4

    def legacy_check(self, max: int, ver: str):
        if self.value > max:
            raise ValueError(F'Compression method {self.value} cannot be represented before version {ver}.')
        return self

    def legacy_conversion_pre_4_2_5(self):
        return self.legacy_check(2, '4.2.5').__class__(self.value + 1)

    def legacy_conversion_pre_4_2_6(self):
        if self == CompressionMethod.Store:
            return self
        return self.legacy_check(2, '4.2.6').__class__(self.value + 1)

    def legacy_conversion_pre_5_3_9(self):
        return self.legacy_check(3, '5.3.9')


class Architecture(enum.IntFlag):
    """
    A set of processor architectures as Setup stores the architecture directives before 6.3.0:
    Delphi's `set of TSetupProcessorArchitecture`, where bit k stands for the architecture with
    ordinal k of `(paUnknown, paX86, paX64, paIA64, paARM64)`.
    """
    Unknown = 0b00001 # noqa
    X86     = 0b00010 # noqa
    X64     = 0b00100 # noqa
    IA64    = 0b01000 # noqa
    ARM64   = 0b10000 # noqa


class SetupEntryBitness(enum.IntEnum):
    InstallDefault    = 0           # noqa
    Bits32            = enum.auto() # noqa
    Bits64            = enum.auto() # noqa
    NativeBit         = enum.auto() # noqa
    CurrentProcessBit = enum.auto() # noqa


class PasswordType(enum.IntEnum):
    CRC32     = 0           # noqa
    Nothing   = 0           # noqa
    MD5       = enum.auto() # noqa
    SHA1      = enum.auto() # noqa
    XChaCha20 = enum.auto() # noqa


class SetupTypeEnum(enum.IntEnum):
    User = 0
    DefaultFull = 1
    DefaultCompact = 2
    DefaultCustom = 3


class SetupFlags(enum.IntFlag):
    Fixed                     = 0b00001 # noqa
    Restart                   = 0b00010 # noqa
    DisableNoUninstallWarning = 0b00100 # noqa
    Exclusive                 = 0b01000 # noqa
    DontInheritCheck          = 0b10000 # noqa


class StreamCompressionMethod(enum.IntEnum):
    Store = 0
    Flate = 1
    LZMA1 = 2


class StreamHeader(InnoStruct):
    def __init__(self, reader: StructReader[memoryview], version: InnoVersion):
        super().__init__(reader, version)
        self.HeaderCrc = reader.u32()
        if version >= (6, 7, 0):
            self.CompressedSize = size = reader.u64()
        else:
            self.CompressedSize = size = reader.u32()
        if version >= (4, 0, 9):
            self.StoredSize = self.CompressedSize
            if not reader.u8():
                self.Compression = StreamCompressionMethod.Store
            elif version >= (4, 1, 6):
                self.Compression = StreamCompressionMethod.LZMA1
            else:
                self.Compression = StreamCompressionMethod.Flate
        else:
            self.UncompresedSize = reader.u32()
            if size == 0xFFFFFFFF:
                self.StoredSize = self.UncompresedSize
                self.Compression = StreamCompressionMethod.Store
            else:
                self.StoredSize = size
                self.Compression = StreamCompressionMethod.Flate
            # Add the size of a CRC32 checksum for each 4KiB subblock
            block_count, _r = divmod(self.StoredSize, 4096)
            block_count += int(bool(_r))
            self.StoredSize += 4 * block_count


class CrcCompressedBlock(Struct):
    def __init__(self, reader: StructReader[memoryview], size: int):
        self.BlockCrc = reader.u32()
        self.BlockData = reader.read(size)


SetupMagicToVersion = {
    B'rDlPtS\x30\x32\x87\x65\x56\x78' : _I(1, 2, 10), # noqa
    B'rDlPtS\x30\x34\x87\x65\x56\x78' : _I(4, 0,  0), # noqa
    B'rDlPtS\x30\x35\x87\x65\x56\x78' : _I(4, 0,  3), # noqa
    B'rDlPtS\x30\x36\x87\x65\x56\x78' : _I(4, 0, 10), # noqa
    B'rDlPtS\x30\x37\x87\x65\x56\x78' : _I(4, 1,  6), # noqa
    B'rDlPtS\xcd\xe6\xd7\x7b\x0b\x2a' : _I(5, 1,  5), # noqa
    B'nS5W7d\x54\x83\xaa\x1b\x0f\x6a' : _I(5, 1,  5), # noqa
}


class TSetupLdrOffsetTable(Struct):
    def __init__(self, reader: StructReader[memoryview], version: InnoVersion = min(SetupMagicToVersion.values())):
        start = reader.tell()
        check = reader.peek()
        self.id = bytes(reader.read(12))
        self.iv = iv = SetupMagicToVersion.get(self.id)
        # version: 6.5.0  5.1.5  4.1.6  4.0.0  1.0.0
        # offsets: 0x00C  0x00C  0x00C  0x00C  0x00C
        if iv is None:
            iv = version
        if iv >= (5, 1, 5):
            self.revision = reader.u32()
        else:
            self.revision = 0
        # offsets: 0x010  0x010  0x00C  0x00C  0x00C
        if self.revision >= 2:
            self.iv = iv = _I(6, 5, 0)
            integer = reader.u64
            crc_pad = 4
        else:
            integer = reader.u32
            crc_pad = 0
        self.total_size = integer()
        # offsets: 0x018  0x014  0x010  0x010  0x010
        self.exe_offset = integer()
        # offsets: 0x020  0x018  0x014  0x014  0x014
        self.exe_compressed_size = None if iv >= (4, 1, 6) else reader.u32()
        # offsets: 0x020  0x018  0x014  0x018  0x018
        self.exe_uncompressed_size = reader.u32()
        # offsets: 0x024  0x01C  0x018  0x01C  0x01C
        if iv >= (4, 0, 3):
            self.exe_checksum_type = CheckSumType.CRC32
        else:
            self.exe_checksum_type = CheckSumType.Adler32
        self.exe_checksum = bytes(reader.read(4))
        # offsets: 0x028  0x020  0x01C  0x020  0x020
        self.messages = reader.u32() if iv < (4, 0, 0) else None
        # offsets: 0x028  0x020  0x01C  0x020  0x024
        self.info_abs_offset = integer()
        # offsets: 0x030  0x024  0x020  0x024  0x028
        self.data_abs_offset = integer()
        # version: 6.5.0  5.1.5  4.1.6  4.0.0  1.0.0
        # offsets: 0x038  0x028  0x024  0x028  0x02C

        self.crc_padding = reader.read(crc_pad)
        check = check[:reader.tell() - start]
        self.computed_checksum = zlib.crc32(check)
        self.expected_checksum = reader.u32() if (
            iv >= (4, 0, 10)
        ) else self.computed_checksum

        self.base = min(
            self.exe_offset,
            self.info_abs_offset,
            self.data_abs_offset,
        )

        self.info_offset = self.info_abs_offset - self.base
        self.data_offset = self.data_abs_offset - self.base

    def Checked(self):
        if (_c := self.computed_checksum) != (_e := self.expected_checksum):
            raise ValueError(F'Invalid checksum; computed {_c:08X}, header value is {_e:08X}.')
        if self.exe_uncompressed_size < 0x100:
            raise ValueError(R'The EXE uncompressed size value is too low.')
        if self.info_offset < self.data_offset:
            raise ValueError(R'TData offset is beyond TSetup offset.')
        return self

    @classmethod
    def Try(cls, view: memoryview):
        try:
            return cls.Parse(view).Checked()
        except ValueError:
            return None

    @classmethod
    def FindInBinary(cls, data):
        issd = B'Inno Setup Setup Data'
        view = memoryview(data)
        if len(view) < 0x1000:
            return None
        for magic in SetupMagicToVersion:
            for match in re.finditer(re.escape(magic), view):
                if self := cls.Try(view[match.start():]):
                    ip = self.base + self.info_offset
                    if view[ip:][:len(issd)] == issd:
                        return self
        for im in re.finditer(B'%s.{20}' % issd, view):
            iv = InnoVersion.Parse(im[0])
            ip = im.start()
            if iv >= (6, 5, 0):
                delta = 0x38
            elif iv >= (5, 1, 5):
                delta = 0x28
            elif iv >= (4, 1, 6):
                delta = 0x24
            elif iv >= (4, 0, 0):
                delta = 0x28
            else:
                delta = 0x2C
            for dm in re.finditer(re.escape(InnoArchive.ChunkPrefix), view):
                dp = dm.start()
                rx = re.escape(dp.to_bytes(4, 'little'))
                for match in re.finditer(rx, view):
                    offset = match.start() - delta
                    if self := cls.Try(view[offset:]):
                        _ip = self.base + self.info_offset
                        if view[_ip:][:len(issd)] == issd:
                            return self


@dataclasses.dataclass
class InnoFile:
    reader: StructReader[memoryview]
    version: InnoVersion
    meta: SetupDataEntry
    path: str = ""
    dupe: bool = False
    setup: SetupFile | None = None
    compression_method: CompressionMethod | None = None
    crypto: SetupEncryptionHeader | None = None

    @property
    def tags(self):
        if s := self.setup:
            return s.Flags
        else:
            return SetupFileFlags.Empty

    @property
    def unicode(self):
        return self.version.unicode

    @property
    def compression(self):
        if self.meta.Flags & SetupDataEntryFlags.ChunkCompressed:
            return self.compression_method
        return CompressionMethod.Store

    @property
    def offset(self):
        return self.meta.Offset

    @property
    def size(self):
        return self.meta.FileSize

    @property
    def date(self):
        return self.meta.FileTime

    @property
    def first_slice(self):
        return self.meta.FirstSlice

    @property
    def chunk_offset(self):
        return self.meta.ChunkOffset

    @property
    def chunk_length(self):
        return self.meta.ChunkSize

    @property
    def checksum(self):
        return self.meta.Checksum

    @property
    def checksum_type(self):
        return self.meta.ChecksumType

    @property
    def encrypted(self):
        return bool(self.meta.Flags & SetupDataEntryFlags.ChunkEncrypted)

    @property
    def filtered(self):
        return bool(self.meta.Flags & SetupDataEntryFlags.CallInstructionOptimized)

    def check(self, data: buf):
        t = self.checksum_type
        if t == CheckSumType.Missing:
            return None
        if t == CheckSumType.Adler32:
            return (zlib.adler32(data) & 0xFFFFFFFF).to_bytes(4, 'little')
        if t == CheckSumType.CRC32:
            return (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, 'little')
        if t == CheckSumType.MD5:
            return md5(data).digest()
        if t == CheckSumType.SHA1:
            return sha1(data).digest()
        if t == CheckSumType.SHA256:
            return sha256(data).digest()
        raise ValueError(F'Unknown checksum type: {t!r}')


@dataclasses.dataclass
class InnoStream:
    header: StreamHeader
    blocks: list[CrcCompressedBlock] = dataclasses.field(default_factory=list)
    data: bytearray | None = None

    @property
    def compression(self):
        return self.header.Compression


class InstallMode(enum.IntEnum):
    Normal     = 0           # noqa
    Silent     = enum.auto() # noqa
    VerySilent = enum.auto() # noqa


class SetupHeader(InnoStruct):

    def __init__(self, reader: StructReaderBits[memoryview], version: InnoVersion, HeaderEncryption: SetupEncryptionHeaderV3 | None):
        super().__init__(reader, version)

        def read_string():
            return reader.read_length_prefixed()

        if version < (1, 3, 0):
            # skip uncompressed size
            reader.u32()

        self.AppId = self.AppPublisher = self.AppPublisherUrl = self.AppSupportPhone = None
        self.AppSupportUrl = self.AppUpdatesUrl = self.AppVersion = self.UninstallFilesDir = None
        self.UninstallName = self.UninstallIcon = self.AppMutex = self.DefaultUsername = None
        self.DefaultOrganisation = self.DefaultSerial = self.AppReadmeFile = self.AppContact = None
        self.AppComment = self.AppModifyPath = self.SetupMutex = None

        if True:
            self.AppName = read_string()
            self.AppVersionedName = read_string()
        if version >= (1, 3, 0):
            self.AppId = read_string()
        if True:
            self.AppCopyright = read_string()
        if version >= (1, 3, 0):
            self.AppPublisher = read_string()
            self.AppPublisherUrl = read_string()
        if version >= (5, 1, 13):
            self.AppSupportPhone = read_string()
        if version >= (1, 3, 0):
            self.AppSupportUrl = read_string()
            self.AppUpdatesUrl = read_string()
            self.AppVersion = read_string()
        if True:
            self.DefaultDirName = read_string()
            self.DefaultGroupName = read_string()
        if version < (3, 0, 0):
            self.UninstallIconName = reader.read_length_prefixed(encoding='cp1252')
        if True:
            self.BaseFilename = read_string()
        if (1, 3, 0) <= version < (5, 2, 5):
            self._license = reader.read_length_prefixed_ascii()
            self.InfoHead = reader.read_length_prefixed_ascii()
            self.InfoTail = reader.read_length_prefixed_ascii()
        if version >= (1, 3, 3):
            self.UninstallFilesDir = read_string()
        if version >= (1, 3, 6):
            self.UninstallName = read_string()
            self.UninstallIcon = read_string()
        if version >= (1, 3, 14):
            self.AppMutex = read_string()
        if version >= (3, 0, 0):
            self.DefaultUsername = read_string()
            self.DefaultOrganisation = read_string()
        if version >= (4, 0, 0) or version.isx and version >= (3, 0, 6, 1):
            self.DefaultSerial = read_string()
        if (4, 0, 0) <= version < (5, 2, 5) or version.isx and version >= (1, 3, 24):
            self._CompiledCode = read_string()
        if version >= (4, 2, 4):
            self.AppReadmeFile = read_string()
            self.AppContact = read_string()
            self.AppComment = read_string()
            self.AppModifyPath = read_string()
        self.CreateUninstallRegistryKey = read_string() if version >= (5, 3, 8) else None
        self.Uninstallable = read_string() if version >= (5, 3, 10) else None
        if version >= (5, 5, 0):
            self.CloseApplicationsFilter = read_string()
        if version >= (5, 5, 6):
            self.SetupMutex = read_string()
        if version >= (5, 6, 1):
            self.ChangesEnvironment = read_string()
            self.ChangesAssociations = read_string()
        else:
            self.ChangesEnvironment = None
            self.ChangesAssociations = None
        if version >= (6, 3, 0):
            self.ArchitecturesAllowed = self._read_string()
            self.ArchitecturesInstallIn64BitMode = self._read_string()
        if version >= (6, 4, 2):
            self.CloseApplicationsFilterExcludes = read_string()
        if version >= (6, 5, 0):
            self.SevenZipLibraryName = read_string()
        else:
            self.SevenZipLibraryName = None
        if version >= (6, 7, 0):
            self.UsePreviousAppDir = read_string()
            self.UsePreviousGroup = read_string()
            self.UsePreviousSetupType = read_string()
            self.UsePreviousTasks = read_string()
            self.UsePreviousUserInfo = read_string()
        if version >= (5, 2, 5):
            self._license = reader.read_length_prefixed_ascii()
            self.InfoHead = reader.read_length_prefixed_ascii()
            self.InfoTail = reader.read_length_prefixed_ascii()
        if version >= (5, 2, 1) and version < (5, 3, 10):
            self.UninstallerSignature = read_string()
        if version >= (5, 2, 5):
            self._CompiledCode = read_string()

        if self._CompiledCode and self._CompiledCode[:4] != B'IFPS':
            raise ValueError('Invalid signature in compiled code.')

        if version >= (2, 0, 6) and version.ascii:
            self.Charset = bytes(reader.read(0x20))
        else:
            self.Charset = 0

        if version >= (4, 0, 0):
            self.LanguageCount = reader.u32()
        elif version >= (2, 0, 1):
            self.LanguageCount = 1
        else:
            self.LanguageCount = 0

        if version >= (4, 2, 1):
            self.MessageCount = reader.u32()
        else:
            self.MessageCount = 0

        if version >= (4, 1, 0):
            self.PermissionCount = reader.u32()
        else:
            self.PermissionCount = 0

        if version >= (2, 0, 0) or version.isx:
            self.TypeCount = reader.u32()
            self.ComponentCount = reader.u32()
        else:
            self.TypeCount = 0
            self.ComponentCount = 0

        if version >= (2, 0, 0) or version.isx and version >= (1, 3, 17):
            self.TaskCount = reader.u32()
        else:
            self.TaskCount = 0

        self.DirectoryCount = reader.u32()

        if version >= (6, 5, 0):
            self.ISSigCount = reader.u32()
        else:
            self.ISSigCount = 0

        self.FileCount = reader.u32()
        self.DataEntryCount = reader.u32()
        self.IconCount = reader.u32()
        self.IniEntryCount = reader.u32()
        self.RegistryCount = reader.u32()
        self.DeleteCount = reader.u32()
        self.UninstallDeleteCount = reader.u32()
        self.RunCount = reader.u32()
        self.UninstallRunCount = reader.u32()

        if version < (1, 3, 0):
            _license_len = reader.u32()
            _infhead_len = reader.u32()
            _inftail_len = reader.u32()
        else:
            _license_len = 0
            _infhead_len = 0
            _inftail_len = 0

        if version >= (7, 0, 0, 3):
            self.CompiledCodeVersion = reader.u32()
        else:
            self.CompiledCodeVersion = 0

        self.WindowsVersion = WinVerRange(reader, version)

        self.BackColor1 = reader.u32() if (0, 0, 0) <= version < (6, 4, 0, 1) else 0
        self.BackColor2 = reader.u32() if (1, 3, 3) <= version < (6, 4, 0, 1) else 0

        if version < (5, 5, 7):
            self.LargeImageBackColor = reader.u32()
        if (2, 0, 0) <= version < (5, 0, 4) or version.isx:
            self.SmallImageBackColor = reader.u32()
        if version >= (6, 0, 0):
            if version < (6, 6, 0):
                self.WizardStyle = WizardStyle(reader.u8())
            else:
                self.WizardStyle = None
            self.WizardResizePercentX = reader.u32()
            self.WizardResizePercentY = reader.u32()
        else:
            self.WizardStyle = WizardStyle.Classic
            self.WizardResizePercentX = 0
            self.WizardResizePercentY = 0

        if version >= (6, 6, 0):
            self.WizardDarkStyle = WizardDarkStyle(reader.u8())
        else:
            self.WizardDarkStyle = None

        if version >= (5, 5, 7):
            self.StoredAlphaFormat = StoredAlphaFormat(reader.u8())
        else:
            self.StoredAlphaFormat = StoredAlphaFormat.AlphaIgnored

        if version >= (6, 5, 2):
            self.LargeImageBackColor = reader.u32()
            self.SmallImageBackColor = reader.u32()
        if version >= (6, 7, 0):
            self.WizardBackColor = reader.u32()
        if version >= (6, 6, 0):
            self.LargeImageBackColorDynamicDark = reader.u32()
            self.SmallImageBackColorDynamicDark = reader.u32()
        else:
            self.LargeImageBackColorDynamicDark = None
            self.SmallImageBackColorDynamicDark = None
        if version >= (6, 7, 0):
            self.WizardBackColorDynamicDark = reader.u32()
        if version >= (6, 6, 1):
            self.WizardImageOpacity = reader.u8()
        else:
            self.WizardImageOpacity = 0
        if version >= (6, 7, 0):
            self.WizardBackImageOpacity = reader.u8()
            self.WizardLightControlStyling = WizardLightControlStyling(reader.u8())

        if version >= (6, 5, 0):
            assert HeaderEncryption
            self.Encryption = HeaderEncryption
        elif version >= (6, 4, 0):
            self.Encryption = SetupEncryptionHeaderV2(reader)
        else:
            self.Encryption = SetupEncryptionHeaderV1(reader, version)

        if version >= (4, 0, 0):
            self.ExtraDiskSpace = reader.i64()
            self.SlicesPerDisk = reader.u32()
        else:
            self.ExtraDiskSpace = reader.u32()
            self.SlicesPerDisk = 1

        if (2, 0, 0) <= version < (5, 0, 0):
            self.InstallMode = _enum(InstallMode, reader.u8(), InstallMode.Normal)
        else:
            self.InstallMode = InstallMode.Normal
        if version >= (1, 3, 0):
            self.UninstallLogMode = UninstallLogMode(reader.u8())
        else:
            self.UninstallLogMode = UninstallLogMode.New

        if version >= (5, 0, 0):
            self.SetupStyle = SetupStyle.Modern
        elif (2, 0, 0) <= version or version.isx and version >= (1, 3, 13):
            self.SetupStyle = SetupStyle(reader.u8())
        else:
            self.SetupStyle = SetupStyle.Classic

        if version >= (1, 3, 6):
            self.DirExistsWarning = AutoBool(reader.u8())
        else:
            self.DirExistsWarning = AutoBool.Auto
        if version.isx and (2, 0, 10) <= version < (3, 0, 0):
            self.CodeLineOffset = reader.u32()

        self.Flags = Flags.Empty

        if (3, 0, 0) <= version < (3, 0, 3):
            val = AutoBool(reader.u8())
            if val == AutoBool.Auto:
                self.Flags |= Flags.RestartIfNeededByRun
            elif val == AutoBool.Yes:
                self.Flags |= Flags.AlwaysRestart

        if version >= (3, 0, 4) or version.isx and version >= (3, 0, 3):
            self.PrivilegesRequired = PrivilegesRequired(reader.u8())
        if version >= (5, 7, 0):
            self.PrivilegesRequiredOverrideAllowed = PrivilegesRequiredOverrideAllowed(reader.u8())
        if version >= (4, 0, 10):
            self.ShowLanguageDialog = AutoBool(reader.u8())
            self.LanguageDetection = LanguageDetection(reader.u8())

        if version >= (4, 1, 5):
            method = CompressionMethod(reader.u8())
            if version < (4, 2, 5):
                method = method.legacy_conversion_pre_4_2_5()
            elif version < (4, 2, 6):
                method = method.legacy_conversion_pre_4_2_5()
            elif version < (5, 3, 9):
                method = method.legacy_conversion_pre_5_3_9()
            self.CompressionMethod = method

        if (5, 1, 0) <= version < (6, 3, 0):
            self.ArchitecturesAllowed = Architecture(reader.u8())
            self.ArchitecturesInstallIn64BitMode = Architecture(reader.u8())
        elif version < (5, 1, 0):
            self.ArchitecturesAllowed = Architecture(0)
            self.ArchitecturesInstallIn64BitMode = Architecture(0)

        if (5, 2, 1) <= version < (5, 3, 10):
            self.UninstallerOriginalSize = reader.u32()
            self.UninstallheaderCrc = reader.u32()
        if version >= (5, 3, 3):
            self.DisableDirPage = AutoBool(reader.u8())
            self.DisableProgramGroupPage = AutoBool(reader.u8())
        if version >= (5, 5, 0):
            self.UninstallDisplaySize = reader.u64()
        elif version >= (5, 3, 6):
            self.UninstallDisplaySize = reader.u32()
        else:
            self.UninstallDisplaySize = 0

        flags = []
        flags.append(Flags.DisableStartupPrompt)
        if version < (5, 3, 10):
            flags.append(Flags.Uninstallable)
        flags.append(Flags.CreateAppDir)
        if version < (5, 3, 3):
            flags.append(Flags.DisableDirPage)
        if version < (1, 3, 6):
            flags.append(Flags.DisableDirExistsWarning)
        if version < (5, 3, 3):
            flags.append(Flags.DisableProgramGroupPage)
        flags.append(Flags.AllowNoIcons)
        if version < (3, 0, 0) or version >= (3, 0, 3):
            flags.append(Flags.AlwaysRestart)
        if version < (1, 3, 3):
            flags.append(Flags.BackSolid)
        flags.append(Flags.AlwaysUsePersonalGroup)
        if version < (6, 4, 0):
            flags.append(Flags.WindowVisible)
            flags.append(Flags.WindowShowCaption)
            flags.append(Flags.WindowResizable)
            flags.append(Flags.WindowStartMaximized)
        flags.append(Flags.EnableDirDoesntExistWarning)
        if version < (4, 1, 2):
            flags.append(Flags.DisableAppendDir)
        flags.append(Flags.Password)
        flags.append(Flags.AllowRootDirectory)
        flags.append(Flags.DisableFinishedPage)

        if version.bits > 16:
            if version < (3, 0, 4):
                flags.append(Flags.AdminPrivilegesRequired)
            if version < (3, 0, 0):
                flags.append(Flags.AlwaysCreateUninstallIcon)
            if version < (1, 3, 6):
                flags.append(Flags.OverwriteUninstRegEntries)
            if version < (5, 6, 1):
                flags.append(Flags.ChangesAssociations)

        if version < (5, 3, 8):
            flags.append(Flags.CreateUninstallRegKey)

        if version < (6, 7, 0):
            flags.append(Flags.UsePreviousAppDir)
        if version < (6, 4, 0):
            flags.append(Flags.BackColorHorizontal)
        if version < (6, 7, 0):
            flags.append(Flags.UsePreviousGroup)
        flags.append(Flags.UpdateUninstallLogAppName)
        if version < (6, 7, 0):
            flags.append(Flags.UsePreviousSetupType)
        flags.append(Flags.DisableReadyMemo)
        flags.append(Flags.AlwaysShowComponentsList)
        flags.append(Flags.FlatComponentsList)
        flags.append(Flags.ShowComponentSizes)
        if version < (6, 7, 0):
            flags.append(Flags.UsePreviousTasks)
        flags.append(Flags.DisableReadyPage)
        flags.append(Flags.AlwaysShowDirOnReadyPage)
        flags.append(Flags.AlwaysShowGroupOnReadyPage)
        if version < (4, 1, 5):
            flags.append(Flags.BzipUsed)
        flags.append(Flags.AllowUNCPath)
        flags.append(Flags.UserInfoPage)
        if version < (6, 7, 0):
            flags.append(Flags.UsePreviousUserInfo)
        flags.append(Flags.UninstallRestartComputer)
        flags.append(Flags.RestartIfNeededByRun)
        flags.append(Flags.ShowTasksTreeLines)
        if version < (4, 0, 10):
            flags.append(Flags.ShowLanguageDialog)
        if version >= (4, 0, 1) and version < (4, 0, 10):
            flags.append(Flags.DetectLanguageUsingLocale)
        if version >= (4, 0, 9):
            flags.append(Flags.AllowCancelDuringInstall)
        if version >= (4, 1, 3):
            flags.append(Flags.WizardImageStretch)
        if version >= (4, 1, 8):
            flags.append(Flags.AppendDefaultDirName)
            flags.append(Flags.AppendDefaultGroupName)
        if (6, 5, 0) > version >= (4, 2, 2):
            flags.append(Flags.EncryptionUsed)
        if version >= (5, 0, 4) and version < (5, 6, 1):
            flags.append(Flags.ChangesEnvironment)
        if version >= (5, 1, 7) and version.ascii:
            flags.append(Flags.ShowUndisplayableLanguages)
        if version >= (5, 1, 13):
            flags.append(Flags.SetupLogging)
        if version >= (5, 2, 1):
            flags.append(Flags.SignedUninstaller)
        if version >= (5, 3, 8):
            flags.append(Flags.UsePreviousLanguage)
        if version >= (5, 3, 9):
            flags.append(Flags.DisableWelcomePage)
        if version >= (5, 5, 0):
            flags.append(Flags.CloseApplications)
            flags.append(Flags.RestartApplications)
            flags.append(Flags.AllowNetworkDrive)
        if version >= (5, 5, 7):
            flags.append(Flags.ForceCloseApplications)
        if version >= (6, 0, 0):
            flags.append(Flags.AppNameHasConsts)
            flags.append(Flags.UsePreviousPrivileges)
            flags.append(Flags.WizardResizable)
        if version >= (6, 3, 0):
            flags.append(Flags.UninstallLogging)
        if version >= (6, 6, 0):
            flags.append(Flags.WizardModern)
            flags.append(Flags.WizardBorderStyled)
            flags.append(Flags.WizardKeepAspectRatio)
            if version < (6, 7, 0):
                flags.append(Flags.WizardLightButtonsUnstyled)
        if version >= (6, 7, 0):
            flags.append(Flags.RedirectionGuard)
            flags.append(Flags.WizardBevelsHidden)

        if version >= (6, 7, 0):
            flag_offset = reader.tell()
            for flag in flags:
                if reader.read_bit():
                    self.Flags |= flag
            reader.byte_align()
            reader.seekset(flag_offset + 8)
            flagsize = 0
        else:
            flagsize, _r = divmod(len(flags), 8)
            flagsize += int(bool(_r))
            bytecheck = bytes(reader.peek(flagsize + 1 + 4 + 1))

            if bytecheck[0] == 0:
                if bytecheck[~0] != 0 or bytecheck[~3:~0] == B'\0\0\0':
                    reader.u8()

            for flag in flags:
                if reader.read_bit():
                    self.Flags |= flag

        if version < (3, 0, 4):
            self.PrivilegesRequired = PrivilegesRequired.Admin if (
                self.Flags & Flags.AdminPrivilegesRequired
            ) else PrivilegesRequired.Nothing

        if version < (4, 0, 10):
            self.ShowLanguageDialog = AutoBool.From(
                self.Flags & Flags.ShowLanguageDialog)
            self.LanguageDetection = LanguageDetection.Locale if (
                self.Flags & Flags.DetectLanguageUsingLocale
            ) else LanguageDetection.UI

        if version < (4, 1, 5):
            self.CompressionMethod = CompressionMethod.BZip2 if (
                self.Flags & Flags.BzipUsed
            ) else CompressionMethod.Flate

        if version < (5, 3, 3):
            self.DisableDirPage = AutoBool.From(self.Flags & Flags.DisableDirPage)
            self.DisableProgramGroupPage = AutoBool.From(self.Flags & Flags.DisableProgramGroupPage)

        if version < (1, 3, 0):
            def _read_ascii(n: int):
                return codecs.decode(reader.read(_license_len), 'cp1252')
            self._license = _read_ascii(_license_len)
            self.InfoHead = _read_ascii(_infhead_len)
            self.InfoTail = _read_ascii(_inftail_len)

        if version < (6, 7, 0):
            reader.byte_align()

            if flagsize == 3:
                reader.u8()

    def get_license(self):
        return self._license

    def text(self, directive: TextDirective) -> str | None:
        """
        The text of a directive that Setup expands, `None` when the version of the installer does
        not have the directive.
        """
        return getattr(self, _TEXT_DIRECTIVE_FIELDS[directive])

    def directive(self, name: YesNoDirective) -> SetupDirective:
        """
        A yes-or-no directive as Setup reads it: the text of the directive, or the flag that older
        versions keep instead of a text.
        """
        text, flag = {
            YesNoDirective.Uninstallable         : (self.Uninstallable, Flags.Uninstallable),
            YesNoDirective.CreateUninstallRegKey : (self.CreateUninstallRegistryKey, Flags.CreateUninstallRegKey),
            YesNoDirective.ChangesEnvironment    : (self.ChangesEnvironment, Flags.ChangesEnvironment),
            YesNoDirective.ChangesAssociations   : (self.ChangesAssociations, Flags.ChangesAssociations),
        }[name]
        if TYPE_CHECKING:
            assert isinstance(text, str | None)
        return SetupDirective.read(text, bool(self.Flags & flag))

    def get_script(self):
        return self._CompiledCode

    @property
    def is_64bit(self):
        """
        Whether the embedded compiled code was compiled for a 64-bit `Exec`. This is encoded as the
        high bit of `CompiledCodeVersion`, which is only present since version 7.0.0.3.
        """
        return bool(self.CompiledCodeVersion & 0x80000000)

    def recode_strings(self, codec: str):
        for coded_string_attribute in [
            'AppComment',
            'AppContact',
            'AppCopyright',
            'AppId',
            'AppModifyPath',
            'AppMutex',
            'AppName',
            'AppPublisher',
            'AppPublisherUrl',
            'AppReadmeFile',
            'AppSupportPhone',
            'AppSupportUrl',
            'AppUpdatesUrl',
            'AppVersion',
            'AppVersionedName',
            'BaseFilename',
            'ChangesAssociations',
            'ChangesEnvironment',
            'CloseApplicationsFilter',
            'CreateUninstallRegistryKey',
            'DefaultDirName',
            'DefaultGroupName',
            'DefaultOrganisation',
            'DefaultSerial',
            'DefaultUsername',
            'SetupMutex',
            'Uninstallable',
            'UninstallFilesDir',
            'UninstallIcon',
            'UninstallName',
        ]:
            try:
                value: bytes | None = getattr(self, coded_string_attribute)
            except AttributeError:
                continue
            if value is None:
                continue
            if not isinstance(value, (bytes, bytearray, memoryview)):
                raise RuntimeError(F'Attempting to decode {coded_string_attribute} which was already decoded.')
            setattr(self, coded_string_attribute, codecs.decode(value, codec))


class Version(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: InnoVersion):
        super().__init__(reader, version)
        self.Build = reader.u16() if version >= (1, 3, 19) else 0
        self.Minor = reader.u8()
        self.Major = reader.u8()

    def __json__(self):
        return F'{self.Major:d}.{self.Minor:d}.{self.Build:04d}'


class WindowsVersion(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: InnoVersion):
        super().__init__(reader, version)
        self.OS = Version(reader, version)
        self.NT = Version(reader, version)
        (
            self.ServicePackMinor,
            self.ServicePackMajor,
        ) = reader.read_struct('BB') if version >= (1, 3, 19) else (0, 0)


class WinVerRange(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: InnoVersion):
        super().__init__(reader, version)
        self.Min = WindowsVersion(reader, version)
        self.Max = WindowsVersion(reader, version)


class LanguageId(Struct):
    def __init__(self, reader: StructReader[memoryview], version: InnoVersion):
        if version < (6, 6, 0):
            self.Value = reader.i32()
        else:
            self.Value = reader.u16()
        self.Name = LCID.get(self.Value, None)


class SetupLanguage(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: InnoVersion, _: TSetup):
        super().__init__(reader, version)
        read_string = self._read_string

        self.Name = read_string()
        LanguageName = reader.read_length_prefixed()

        self.DialogFont = read_string()
        self.TitleFont = read_string() if version < (6, 6, 0) else None
        self.WelcomeFont = read_string()
        self.CopyrightFont = read_string() if version < (6, 6, 0) else None
        self._compiled_messages = reader.read_length_prefixed()

        if version >= (4, 0, 1):
            self.LicenseText = reader.read_length_prefixed_ascii()
            self.InfoBefore = reader.read_length_prefixed_ascii()
            self.InfoAfter = reader.read_length_prefixed_ascii()
        else:
            self.LicenseText = self.InfoBefore = self.InfoAfter = ''

        self.LanguageId = LanguageId(reader, version)

        if version < (4, 2, 2):
            self.Codepage = DEFAULT_CODEPAGE.get(self.LanguageId.Value, 'cp1252')
        elif version.ascii:
            cp = reader.u32()
            cp = cp or 1252
            self.Codepage = F'cp{cp}'
        else:
            if version < (5, 3, 0):
                reader.u32()
            self.Codepage = 'utf-16le'

        if version >= (4, 2, 2):
            self.LanguageName = codecs.decode(LanguageName, 'utf-16le')
        else:
            self.LanguageName = codecs.decode(LanguageName, self.Codepage)

        self.DialogFontSize = reader.u32()

        if version < (4, 1, 0):
            self.DialogFontStandardHeight = reader.u32()
        if version < (6, 6, 0):
            self.TitleFontSize = reader.u32()
            self.DialogFontBaseScaleHeight = None
            self.DialogFontBaseScaleWidth = None
        else:
            self.TitleFontSize = None
            self.DialogFontBaseScaleHeight = reader.u32()
            self.DialogFontBaseScaleWidth = reader.u32()

        self.WelcomeFontSize = reader.u32()

        if version < (6, 6, 0):
            self.CopyrightFontSize = reader.u32()
        else:
            self.CopyrightFontSize = None

        if version >= (5, 2, 3):
            self.RightToLeft = reader.u8()


class SetupEncryptionScope(enum.IntEnum):
    NoEncryption = 0
    Files = 1
    Full = 2


class SpecialCryptContext(enum.IntEnum):
    PasswordTest = 0xFFFFFFFF
    CompressedBlocks1 = 0xFFFFFFFE
    CompressedBlocks2 = 0xFFFFFFFD


class SetupEncryptionNonce(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        self.RandomXorChunkStart = reader.u64()
        self.RandomXorFirstSlice = reader.u32()
        self.RemainignBytes = reader.peek(12)
        self.RemainingWords = [reader.u32() for _ in range(3)]

    def compile(self, chunk_start: int = 0, fist_slice: int | SpecialCryptContext = 0):
        return struct.pack('<Q4I',
            self.RandomXorChunkStart ^ chunk_start,
            self.RandomXorFirstSlice ^ fist_slice,
            *self.RemainingWords)

    def __repr__(self):
        return F'{self.RandomXorChunkStart:016X}-{self.RandomXorFirstSlice:08X}-{self.RemainignBytes.hex().upper()}'


class XChaChaParams(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        self.KDFSalt = bytes(reader.read_exactly(16))
        self.KDFIterations = reader.u32()
        self.BaseNonce = SetupEncryptionNonce(reader)

    def __repr__(self):
        return (
            F'PBKDF2[salt:{self.KDFSalt.hex().upper()}/iter:{self.KDFIterations}/'
            F'nonce:{self.BaseNonce!r}]')


class SetupEncryptionHeader(abc.ABC):
    SaltLength: int
    Scope: SetupEncryptionScope
    PasswordTest: bytes
    PasswordType: PasswordType
    PasswordSeed: XChaChaParams | bytes

    @abc.abstractmethod
    def test(self, password_bytes: buf) -> bool:
        ...

    @abc.abstractmethod
    def decrypt(self, password_bytes: buf, data: buf, chunk_start: int, first_slice: int) -> bytes:
        ...


class XChaChaMixin(SetupEncryptionHeader):
    SaltLength = 0
    Derivation: XChaChaParams

    def _derive(self, password_bytes: buf) -> buf:
        return pbkdf2_hmac(
            'sha256',
            password_bytes,
            self.Derivation.KDFSalt,
            self.Derivation.KDFIterations,
            dklen=32,
        )

    def test(self, password_bytes: buf) -> bool:
        return self.PasswordTest == self.decrypt(
            password_bytes, bytes(4), 0, SpecialCryptContext.PasswordTest)

    def decrypt(self, password_bytes: buf, data: buf, chunk_start: int, first_slice: int) -> bytes:
        key = self._derive(password_bytes)
        from Crypto.Cipher import ChaCha20
        seed = self.PasswordSeed
        assert isinstance(seed, XChaChaParams)
        nonce = seed.BaseNonce.compile(chunk_start, first_slice)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return cipher.decrypt(data)


class SetupEncryptionHeaderV1(Struct, SetupEncryptionHeader):
    SaltLength = 8

    def __init__(self, reader: StructReader[memoryview], version: InnoVersion):
        self.Scope = SetupEncryptionScope.Files
        if version >= (6, 4, 0):
            raise ValueError(F'Invalid version {version} for V1 encryption header!')
        elif version >= (5, 3, 9):
            self.PasswordType = PasswordType.SHA1
            self.PasswordTest = bytes(reader.read(20))
        elif version >= (4, 2, 0):
            self.PasswordType = PasswordType.MD5
            self.PasswordTest = bytes(reader.read(16))
        else:
            self.PasswordType = PasswordType.CRC32
            self.PasswordTest = bytes(reader.read(4))
        if version >= (4, 2, 2):
            self.PasswordSalt = bytes(reader.read(8))
        else:
            self.PasswordSalt = B''
        self.PasswordSeed = self.PasswordSalt

    @property
    def _algorithm(self):
        if self.PasswordType == PasswordType.MD5:
            return md5
        if self.PasswordType == PasswordType.SHA1:
            return sha1
        raise NotImplementedError(F'Password type {self.PasswordType.name} is not implemented.')

    def test(self, password_bytes: buf) -> bool:
        hash = self._algorithm(b'PasswordCheckHash')
        hash.update(self.PasswordSalt)
        hash.update(password_bytes)
        return self.PasswordTest == hash.digest()

    def decrypt(self, password_bytes: buf, data: buf, chunk_start: int, first_slice: int) -> buf:
        slen = self.SaltLength
        view = memoryview(data)
        hash = self._algorithm(view[:slen])
        hash.update(password_bytes)
        from refinery.units.crypto.cipher.rc4 import rc4
        return view[slen:] | rc4(hash.digest(), discard=1000) | bytes


class SetupEncryptionHeaderV2(Struct, XChaChaMixin):
    def __init__(self, reader: StructReader[memoryview]):
        self.Scope = SetupEncryptionScope.Files
        self.PasswordType = PasswordType.XChaCha20
        self.PasswordTest = bytes(reader.read(4))
        self.PasswordSeed = self.Derivation = XChaChaParams(reader)


class SetupEncryptionHeaderV3(Struct, XChaChaMixin):
    def __init__(self, reader: StructReader[memoryview]):
        self.Scope = SetupEncryptionScope(reader.u8())
        self.PasswordType = PasswordType.XChaCha20
        self.PasswordSeed = self.Derivation = XChaChaParams(reader)
        self.PasswordTest = bytes(reader.read(4))


class SetupISSignature(InnoStruct):
    def __init__(self, reader: StructReader[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)
        read_string = self._read_string
        self.PublicX = read_string()
        self.PublicY = read_string()
        self.RuntimeID = read_string()


class SetupCustomMessage(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)
        self.EncodedName = self._read_string()
        self._raw_value = reader.read_length_prefixed()
        self._language_index = reader.i32()
        try:
            self._language_value = parent.Languages[self._language_index]
        except IndexError:
            self._language_value = None
            codec = 'latin1'
        else:
            codec = self._language_value.Codepage
        try:
            self.Value = codecs.decode(self._raw_value, codec)
        except (LookupError, UnicodeDecodeError):
            # TODO: This is a fallback
            self.Value = codecs.decode(self._raw_value, 'latin1')

    def get_raw_value(self):
        return self._raw_value

    def get_language_index(self):
        return self._language_index

    def get_language_value(self):
        return self._language_value


class SetupType(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)
        read_string = self._read_string
        self.Name = read_string()
        self.Description = read_string()
        self.Languages = read_string() if version >= (4, 0, 1) else None
        self.Check = read_string() if version >= (4, 0, 0) or version.isx and version >= (1, 3, 24) else None
        self.WindowsVersion = WinVerRange(reader, version)
        self.CustsomTypeCode = reader.u8()
        if version >= (4, 0, 3):
            self.SetupType = SetupTypeEnum(reader.u8())
        else:
            self.SetupType = SetupTypeEnum.User
        if version >= (4, 0, 0):
            self.Size = reader.u64()
        else:
            self.Size = reader.u32()


class SetupComponent(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)
        read_string = self._read_string
        self.Name = read_string()
        self.Description = read_string()
        self.Types = read_string()
        self.Languages = read_string() if version >= (4, 0, 1) else None
        self.Check = read_string() if version >= (4, 0, 0) or version.isx and version >= (1, 3, 24) else None
        self.ExtraDiskSpace = reader.u64() if version >= (4, 0, 0) else None
        if version >= (6, 7, 0):
            self.Level = reader.u8()
        elif version >= (4, 0, 0) or version.isx and version >= (3, 0, 3):
            self.Level = reader.u32()
        else:
            self.Level = 0
        if version >= (4, 0, 0) or version.isx and version >= (3, 0, 4):
            self.Used = bool(reader.u8())
        else:
            self.Used = True
        if True:
            self.WindowsVersion = WinVerRange(reader, version)
            self.Flags = SetupFlags(reader.u8())
        if version >= (4, 0, 0):
            self.Size = reader.u64()
        elif version >= (2, 0, 0) or version.isx and version >= (1, 3, 24):
            self.Size = reader.u32()
        else:
            self.Size = None


class SetupTaskFlags(enum.IntFlag):
    Empty            = 0           # noqa
    Exclusive        = enum.auto() # noqa
    Unchecked        = enum.auto() # noqa
    Restart          = enum.auto() # noqa
    CheckedOne       = enum.auto() # noqa
    DontInheritCheck = enum.auto() # noqa


class SetupTask(InnoStruct):

    def __init__(self, reader: StructReaderBits[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)
        read_string = self._read_string

        self.Name = read_string()
        self.Description = read_string()
        self.GroupDescription = read_string()
        self.Components = read_string()
        self.Languages = read_string() if version >= (4, 0, 1) else None
        self.Check = read_string() if version >= (4, 0, 0) or version.isx and version >= (1, 3, 24) else None
        if version >= (6, 7, 0):
            self.Level = reader.u8()
        elif version >= (4, 0, 0) or version.isx and version >= (3, 0, 3):
            self.Level = reader.u32()
        else:
            self.Level = 0
        if version >= (4, 0, 0) or version.isx and version >= (3, 0, 4):
            self.Used = bool(reader.u8())
        else:
            self.Used = True
        if True:
            self.WindowsVersion = WinVerRange(reader, version)

        self.Flags = SetupTaskFlags.Empty

        def flagbit(f):
            self.Flags |= f if reader.read_bit() else 0

        if True:
            flagbit(SetupTaskFlags.Exclusive)
            flagbit(SetupTaskFlags.Unchecked)
        if version >= (2, 0, 5):
            flagbit(SetupTaskFlags.Restart)
        if version >= (2, 0, 6):
            flagbit(SetupTaskFlags.CheckedOne)
        if version >= (4, 2, 3):
            flagbit(SetupTaskFlags.DontInheritCheck)

        reader.byte_align()


class SetupCondition(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)
        read_string = self._read_string
        self.Components = read_string() if version >= (2, 0, 0) or version.isx and version >= (1, 3, 8) else None
        self.Tasks = read_string() if version >= (2, 0, 0) or version.isx and version >= (1, 3, 17) else None
        self.Languages = read_string() if version >= (4, 0, 1) else None
        self.Check = read_string() if version >= (4, 0, 0) or version.isx and version >= (1, 3, 24) else None
        if version >= (4, 1, 0):
            self.AfterInstall = read_string()
            self.BeforeInstall = read_string()
        else:
            self.AfterInstall = None
            self.BeforeInstall = None


class SetupDirectoryFlags(enum.IntFlag):
    Empty                = 0           # noqa
    NeverUninstall       = enum.auto() # noqa
    DeleteAfterInstall   = enum.auto() # noqa
    AlwaysUninstall      = enum.auto() # noqa
    SetNtfsCompression   = enum.auto() # noqa
    UnsetNtfsCompression = enum.auto() # noqa


class SetupDirectory(InnoStruct):

    def __init__(self, reader: StructReaderBits[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)
        read_string = self._read_string

        if version < (1, 3, 0):
            self.UncompressedSize = reader.u32()
        if True:
            self.Name = read_string()
            self.Condition = SetupCondition(reader, version, parent)

        if (4, 0, 11) <= version < (4, 1, 0):
            self.Permissions = read_string()
        if version >= (2, 0, 11):
            self.Attributes = reader.u32()

        self.WindowsVersion = WinVerRange(reader, version)

        if version >= (4, 1, 0):
            self.Permissions = reader.u16()

        self.Flags = SetupDirectoryFlags.Empty

        def flagbit(f):
            self.Flags |= f if reader.read_bit() else 0
        flagbit(SetupDirectoryFlags.NeverUninstall)
        flagbit(SetupDirectoryFlags.DeleteAfterInstall)
        flagbit(SetupDirectoryFlags.AlwaysUninstall)
        flagbit(SetupDirectoryFlags.SetNtfsCompression)
        flagbit(SetupDirectoryFlags.UnsetNtfsCompression)
        reader.byte_align()


class SetupPermission(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)
        self.Permission = reader.read_length_prefixed()


class SetupFileFlags(enum.IntFlag):
    Empty                              = 0           # noqa
    ConfirmOverwrite                   = enum.auto() # noqa
    NeverUninstall                     = enum.auto() # noqa
    RestartReplace                     = enum.auto() # noqa
    DeleteAfterInstall                 = enum.auto() # noqa
    RegisterServer                     = enum.auto() # noqa
    RegisterTypeLib                    = enum.auto() # noqa
    SharedFile                         = enum.auto() # noqa
    IsReadmeFile                       = enum.auto() # noqa
    CompareTimeStamp                   = enum.auto() # noqa
    FontIsNotTrueType                  = enum.auto() # noqa
    SkipIfSourceDoesntExist            = enum.auto() # noqa
    OverwriteReadOnly                  = enum.auto() # noqa
    OverwriteSameVersion               = enum.auto() # noqa
    CustomDestName                     = enum.auto() # noqa
    OnlyIfDestFileExists               = enum.auto() # noqa
    NoRegError                         = enum.auto() # noqa
    UninsRestartDelete                 = enum.auto() # noqa
    OnlyIfDoesntExist                  = enum.auto() # noqa
    IgnoreVersion                      = enum.auto() # noqa
    PromptIfOlder                      = enum.auto() # noqa
    DontCopy                           = enum.auto() # noqa
    UninsRemoveReadOnly                = enum.auto() # noqa
    RecurseSubDirsExternal             = enum.auto() # noqa
    ReplaceSameVersionIfContentsDiffer = enum.auto() # noqa
    DontVerifyChecksum                 = enum.auto() # noqa
    UninsNoSharedFilePrompt            = enum.auto() # noqa
    CreateAllSubDirs                   = enum.auto() # noqa
    Bits32                             = enum.auto() # noqa
    Bits64                             = enum.auto() # noqa
    ExternalSizePreset                 = enum.auto() # noqa
    SetNtfsCompression                 = enum.auto() # noqa
    UnsetNtfsCompression               = enum.auto() # noqa
    GacInstall                         = enum.auto() # noqa
    Download                           = enum.auto() # noqa
    ExtractArchive                     = enum.auto() # noqa


class SetupFileType(enum.IntEnum):
    UserFile = 0
    UninstExe = 1
    RegSvrExe = 2


class SetupFileCopyMode(enum.IntEnum):
    Normal                  = 0           # noqa
    IfDoesntExist           = enum.auto() # noqa
    AlwaysOverwrite         = enum.auto() # noqa
    AlwaysSkipIfSameOrOlder = enum.auto() # noqa


class SetupFileVerificationType(enum.IntEnum):
    Nothing  = 0           # noqa
    Hash     = enum.auto() # noqa
    ISSig    = enum.auto() # noqa


class SetupFileVerification(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: InnoVersion):
        super().__init__(reader, version)
        self.ISSigAllowedKeys = reader.read_length_prefixed_ascii()
        self.Hash = reader.read_exactly(32)
        self.Type = _enum(SetupFileVerificationType, reader.u8(), SetupFileVerificationType.Nothing)


_EXTERNAL_LOCATION = 0xFFFFFFFF
"""
The location of a file entry that is not in the installer.
"""


class SetupFile(InnoStruct):

    def __init__(self, reader: StructReaderBits[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)
        read_string = self._read_string

        if version < (1, 3, 0):
            self.UncompressedSize = reader.u32()
        else:
            self.UncompressedSize = None
        if True:
            self.Source = read_string()
            self.Destination = read_string()
            self.InstallFontName = read_string()
        if version >= (5, 2, 5):
            self.StrongAssemblyName = read_string()
        else:
            self.StrongAssemblyName = None

        self.Condition = SetupCondition(reader, version, parent)

        if version >= (6, 5, 0):
            self.Excludes = read_string()
            self.DownloadISSigSource = read_string()
            self.DownloadUserName = read_string()
            self.DownloadPassword = read_string()
            self.ExtractArchivePassword = read_string()
            self.Verification = SetupFileVerification(reader, version)
        else:
            self.Excludes = None
            self.DownloadISSigSource = None
            self.DownloadUserName = None
            self.DownloadPassword = None
            self.ExtractArchivePassword = None
            self.Verification = None

        self.WindowsVersion = WinVerRange(reader, version)

        self.Location = reader.u32()
        self.Attributes = reader.u32()
        self.ExternalSize = reader.u64() if version >= (4, 0, 0) else reader.u32()

        self.Flags = SetupFileFlags.Empty

        if version < (3, 0, 5):
            copy = _enum(SetupFileCopyMode, reader.u8(), SetupFileCopyMode.Normal)
            if copy == SetupFileCopyMode.AlwaysSkipIfSameOrOlder:
                pass
            elif copy == SetupFileCopyMode.Normal:
                self.Flags |= SetupFileFlags.PromptIfOlder
            elif copy == SetupFileCopyMode.IfDoesntExist:
                self.Flags |= SetupFileFlags.OnlyIfDoesntExist | SetupFileFlags.PromptIfOlder
            elif copy == SetupFileCopyMode.AlwaysOverwrite:
                self.Flags |= SetupFileFlags.IgnoreVersion | SetupFileFlags.PromptIfOlder

        if version >= (4, 1, 0):
            self.Permissions = reader.u16()
        else:
            self.Permissions = None

        if version >= (7, 0, 0, 3):
            self.Bitness = SetupEntryBitness(reader.u8())
        else:
            self.Bitness = None

        def flagbit(f):
            self.Flags |= f if reader.read_bit() else 0

        flagstart = reader.tell()

        if True:
            flagbit(SetupFileFlags.ConfirmOverwrite)
            flagbit(SetupFileFlags.NeverUninstall)
            flagbit(SetupFileFlags.RestartReplace)
            flagbit(SetupFileFlags.DeleteAfterInstall)
        if version.bits > 16:
            flagbit(SetupFileFlags.RegisterServer)
            flagbit(SetupFileFlags.RegisterTypeLib)
            flagbit(SetupFileFlags.SharedFile)
        if version < (2, 0, 0) and not version.isx:
            flagbit(SetupFileFlags.IsReadmeFile)
        if True:
            flagbit(SetupFileFlags.CompareTimeStamp)
            flagbit(SetupFileFlags.FontIsNotTrueType)
        if version >= (1, 2, 5):
            flagbit(SetupFileFlags.SkipIfSourceDoesntExist)
        if version >= (1, 2, 6):
            flagbit(SetupFileFlags.OverwriteReadOnly)
        if version >= (1, 3, 21):
            flagbit(SetupFileFlags.OverwriteSameVersion)
            flagbit(SetupFileFlags.CustomDestName)
        if version >= (1, 3, 25):
            flagbit(SetupFileFlags.OnlyIfDestFileExists)
        if version >= (2, 0, 5):
            flagbit(SetupFileFlags.NoRegError)
        if version >= (3, 0, 1):
            flagbit(SetupFileFlags.UninsRestartDelete)
        if version >= (3, 0, 5):
            flagbit(SetupFileFlags.OnlyIfDoesntExist)
            flagbit(SetupFileFlags.IgnoreVersion)
            flagbit(SetupFileFlags.PromptIfOlder)
        if version >= (4, 0, 0) or version.isx and version >= (3, 0, 6, 1):
            flagbit(SetupFileFlags.DontCopy)
        if version >= (4, 0, 5):
            flagbit(SetupFileFlags.UninsRemoveReadOnly)
        if version >= (4, 1, 8):
            flagbit(SetupFileFlags.RecurseSubDirsExternal)
        if version >= (4, 2, 1):
            flagbit(SetupFileFlags.ReplaceSameVersionIfContentsDiffer)
        if version >= (4, 2, 5):
            flagbit(SetupFileFlags.DontVerifyChecksum)
        if version >= (5, 0, 3):
            flagbit(SetupFileFlags.UninsNoSharedFilePrompt)
        if version >= (5, 1, 0):
            flagbit(SetupFileFlags.CreateAllSubDirs)
        if (5, 1, 2) <= version < (7, 0, 0, 3):
            flagbit(SetupFileFlags.Bits32)
            flagbit(SetupFileFlags.Bits64)
        if version >= (5, 2, 0):
            flagbit(SetupFileFlags.ExternalSizePreset)
            flagbit(SetupFileFlags.SetNtfsCompression)
            flagbit(SetupFileFlags.UnsetNtfsCompression)
        if version >= (5, 2, 5):
            flagbit(SetupFileFlags.GacInstall)
        if version >= (6, 5, 0):
            flagbit(SetupFileFlags.Download)
            flagbit(SetupFileFlags.ExtractArchive)

        reader.byte_align()

        if version >= (6, 7, 0):
            consumed = reader.tell() - flagstart
            remaining = 8 - consumed
            if remaining > 0:
                reader.seekrel(remaining)
        elif reader.tell() - flagstart == 3:
            reader.u8()

        self.Type = SetupFileType(reader.u8())

    @property
    def external(self) -> bool:
        """
        Whether the data of the file is not in the installer: Setup takes it from its source on the
        machine or downloads it. The entry of the uninstaller, which Setup writes from itself, is
        external too.
        """
        return self.Location == _EXTERNAL_LOCATION


class SetupIconCloseSetting(enum.IntEnum):
    NoSetting       = 0           # noqa
    CloseOnExit     = enum.auto() # noqa
    DontCloseOnExit = enum.auto() # noqa


class SetupIconFlags(enum.IntFlag):
    Empty                              = 0           # noqa
    NeverUninstall                     = enum.auto() # noqa
    RunMinimized                       = enum.auto() # noqa
    CreateOnlyIfFileExists             = enum.auto() # noqa
    UseAppPaths                        = enum.auto() # noqa
    FolderShortcut                     = enum.auto() # noqa
    ExcludeFromShowInNewInstall        = enum.auto() # noqa
    PreventPinning                     = enum.auto() # noqa
    HasAppUserModelToastActivatorCLSID = enum.auto() # noqa


class SetupIcon(InnoStruct):

    def __init__(self, reader: StructReaderBits[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)

        if version < (1, 3, 0):
            reader.u32()

        self.Name = self._read_string()
        self.FileName = self._read_string()
        self.Parameters = self._read_string()
        self.WorkingDir = self._read_string()
        self.IconFile = self._read_string()
        self.Comment = self._read_string()

        self.Condition = SetupCondition(reader, version, parent)

        self.AppUserModelId = self._read_string() if version >= (5, 3, 5) else None
        self.AppUserModelToastActivatorCLSID = str(reader.read_guid()) if version >= (6, 1, 0) else None

        self.WindowsVersion = WinVerRange(reader, version)
        self.IconIndex = reader.i32()

        if version >= (1, 3, 24):
            self.ShowCommand = reader.i32()
        else:
            self.ShowCommand = 1

        if version >= (1, 3, 15):
            self.CloseOnExit = _enum(SetupIconCloseSetting, reader.u8(), SetupIconCloseSetting.NoSetting)
        else:
            self.CloseOnExit = SetupIconCloseSetting.NoSetting

        self.HotKey = reader.u16() if version >= (2, 0, 7) else 0

        self.Flags = SetupIconFlags.Empty

        def flagbit(f):
            self.Flags |= f if reader.read_bit() else 0
        if True:
            flagbit(SetupIconFlags.NeverUninstall)
        if version < (1, 3, 26):
            flagbit(SetupIconFlags.RunMinimized)
        if True:
            flagbit(SetupIconFlags.CreateOnlyIfFileExists)
        if version.bits > 16:
            flagbit(SetupIconFlags.UseAppPaths)
        if version >= (5, 0, 3) and version < (6, 3, 0):
            flagbit(SetupIconFlags.FolderShortcut)
        if version >= (5, 4, 2):
            flagbit(SetupIconFlags.ExcludeFromShowInNewInstall)
        if version >= (5, 5, 0):
            flagbit(SetupIconFlags.PreventPinning)
        if version >= (6, 1, 0):
            flagbit(SetupIconFlags.HasAppUserModelToastActivatorCLSID)
        reader.byte_align()


class SetupIniFlags(enum.IntFlag):
    Empty                     = 0           # noqa
    CreateKeyIfDoesntExist    = enum.auto() # noqa
    UninsDeleteEntry          = enum.auto() # noqa
    UninsDeleteEntireSection  = enum.auto() # noqa
    UninsDeleteSectionIfEmpty = enum.auto() # noqa
    HasValue                  = enum.auto() # noqa


class SetupIniEntry(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)

        if version < (1, 3, 0):
            reader.u8()

        if not (IniFile := self._read_string()):
            IniFile = '{windows}/WIN.INI'
        self.IniFile = IniFile

        self.Section = self._read_string()
        self.Key = self._read_string()
        self.Value = self._read_string()
        self.Condition = SetupCondition(reader, version, parent)
        self.WindowsVersion = WinVerRange(reader, version)
        self.Flags = SetupIniFlags(reader.u8())


class SetupRegistryType(enum.IntEnum):
    Unset        = 0           # noqa
    String       = enum.auto() # noqa
    ExpandString = enum.auto() # noqa
    DWord        = enum.auto() # noqa
    Binary       = enum.auto() # noqa
    MultiString  = enum.auto() # noqa
    QWord        = enum.auto() # noqa


class SetupRegistryFlags(enum.IntFlag):
    Empty                       = 0           # noqa
    CreateValueIfDoesntExist    = enum.auto() # noqa
    UninsDeleteValue            = enum.auto() # noqa
    UninsClearValue             = enum.auto() # noqa
    UninsDeleteEntireKey        = enum.auto() # noqa
    UninsDeleteEntireKeyIfEmpty = enum.auto() # noqa
    PreserveStringType          = enum.auto() # noqa
    DeleteKey                   = enum.auto() # noqa
    DeleteValue                 = enum.auto() # noqa
    NoError                     = enum.auto() # noqa
    DontCreateKey               = enum.auto() # noqa
    Bits32                      = enum.auto() # noqa
    Bits64                      = enum.auto() # noqa


class SetupRegistryEntry(InnoStruct):

    def __init__(self, reader: StructReaderBits[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)

        if version < (1, 3, 0):
            reader.u32()

        if True:
            self.Key = self._read_string()
        self.Name = self._read_string() if version.bits > 16 else None
        if True:
            self.Value = reader.read_length_prefixed()
            self.Condition = SetupCondition(reader, version, parent)
        if (4, 0, 11) <= version < (4, 1, 0):
            self.Permissions = reader.read_length_prefixed()

        self.WindowsVersion = WinVerRange(reader, version)
        self.Hive = reader.u32() & 0x7FFFFFFF if version.bits > 16 else None
        self.Permissions = reader.u16() if version >= (4, 1, 0) else None
        self.Type = SetupRegistryType(reader.u8())
        if self.Type in (SetupRegistryType.Unset, SetupRegistryType.Binary):
            self.ValueText = None
        else:
            self.ValueText = self._decode(self.Value)

        if version >= (7, 0, 0, 3):
            self.Bitness = SetupEntryBitness(reader.u8())
        else:
            self.Bitness = None

        self.Flags = SetupRegistryFlags.Empty

        def flagbit(f):
            self.Flags |= f if reader.read_bit() else 0

        if version.bits > 16:
            flagbit(SetupRegistryFlags.CreateValueIfDoesntExist)
            flagbit(SetupRegistryFlags.UninsDeleteValue)
        if True:
            flagbit(SetupRegistryFlags.UninsClearValue)
            flagbit(SetupRegistryFlags.UninsDeleteEntireKey)
            flagbit(SetupRegistryFlags.UninsDeleteEntireKeyIfEmpty)
        if version >= (1, 2, 6):
            flagbit(SetupRegistryFlags.PreserveStringType)
        if version >= (1, 3, 9):
            flagbit(SetupRegistryFlags.DeleteKey)
            flagbit(SetupRegistryFlags.DeleteValue)
        if version >= (1, 3, 12):
            flagbit(SetupRegistryFlags.NoError)
        if version >= (1, 3, 16):
            flagbit(SetupRegistryFlags.DontCreateKey)
        if (5, 1, 0) <= version < (7, 0, 0, 3):
            flagbit(SetupRegistryFlags.Bits32)
            flagbit(SetupRegistryFlags.Bits64)

        reader.byte_align()


class SetupDeleteType(enum.IntEnum):
    Files           = 0           # noqa
    FilesAndSubdirs = enum.auto() # noqa
    DirIfEmpty      = enum.auto() # noqa


class SetupDeleteEntry(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)
        if version < (1, 3, 0):
            reader.u32()
        self.Name = self._read_string()
        self.Condition = SetupCondition(reader, version, parent)
        self.WindowsVersion = WinVerRange(reader, version)
        self.Type = SetupDeleteType(reader.u8())


class SetupRunWait(enum.IntEnum):
    UntilTerminated = 0 # noqa
    NoWait          = 1 # noqa
    UntilIdle       = 2 # noqa


class SetupRunFlags(enum.IntFlag):
    Empty             = 0           # noqa
    ShellExec         = enum.auto() # noqa
    SkipIfDoesntExist = enum.auto() # noqa
    PostInstall       = enum.auto() # noqa
    Unchecked         = enum.auto() # noqa
    SkipIfSilent      = enum.auto() # noqa
    SkipIfNotSilent   = enum.auto() # noqa
    HideWizard        = enum.auto() # noqa
    Bits32            = enum.auto() # noqa
    Bits64            = enum.auto() # noqa
    RunAsOriginalUser = enum.auto() # noqa
    DontLogParameters = enum.auto() # noqa
    LogOutput         = enum.auto() # noqa


class SetupRunEntry(InnoStruct):

    def __init__(self, reader: StructReaderBits[memoryview], version: InnoVersion, parent: TSetup):
        super().__init__(reader, version, parent.Codec)
        if version < (1, 3, 0):
            reader.u8()
        self.Name = self._read_string()
        self.Parameters = self._read_string()
        self.WorkingDir = self._read_string()

        self.RunOnceId = self._read_string() if version >= (1, 3, 9) else None
        self.StatusMessage = self._read_string() if version >= (2, 0, 2) else None
        self.Verb = self._read_string() if version >= (5, 1, 13) else None
        self.Description = self._read_string() if version >= (2, 0, 0) or version.isx else None

        self.Condition = SetupCondition(reader, version, parent)

        if version >= (7, 0, 0, 1):
            self.OnLog = self._read_string()
        else:
            self.OnLog = None

        self.WindowsVersion = WinVerRange(reader, version)
        self.ShowCommand = reader.u32() if version >= (1, 3, 24) else 0
        self.Wait = SetupRunWait(reader.u8())

        if version >= (7, 0, 0, 3):
            self.Bitness = SetupEntryBitness(reader.u8())
        else:
            self.Bitness = None

        self.Flags = SetupRunFlags.Empty

        def flagbit(f):
            self.Flags |= f if reader.read_bit() else 0

        if version >= (1, 2, 3):
            flagbit(SetupRunFlags.ShellExec)
        if version >= (1, 3, 9) or version.isx and version >= (1, 3, 8):
            flagbit(SetupRunFlags.SkipIfDoesntExist)
        if version >= (2, 0, 0):
            flagbit(SetupRunFlags.PostInstall)
            flagbit(SetupRunFlags.Unchecked)
            flagbit(SetupRunFlags.SkipIfSilent)
            flagbit(SetupRunFlags.SkipIfNotSilent)
        if version >= (2, 0, 8):
            flagbit(SetupRunFlags.HideWizard)
        if (5, 1, 10) <= version < (7, 0, 0, 3):
            flagbit(SetupRunFlags.Bits32)
            flagbit(SetupRunFlags.Bits64)
        if version >= (5, 2, 0):
            flagbit(SetupRunFlags.RunAsOriginalUser)
        if version >= (6, 1, 0):
            flagbit(SetupRunFlags.DontLogParameters)
        if version >= (6, 3, 0):
            flagbit(SetupRunFlags.LogOutput)

        reader.byte_align()


class TextDirective(enum.StrEnum):
    """
    The directives of the setup header whose texts Setup expands, by their names in the script of
    the installer.
    """
    AppName = 'AppName'
    AppVerName = 'AppVerName'
    AppVersion = 'AppVersion'
    AppCopyright = 'AppCopyright'
    AppMutex = 'AppMutex'
    SetupMutex = 'SetupMutex'
    AppId = 'AppId'
    DefaultUserInfoName = 'DefaultUserInfoName'
    DefaultUserInfoOrg = 'DefaultUserInfoOrg'
    DefaultUserInfoSerial = 'DefaultUserInfoSerial'
    DefaultDirName = 'DefaultDirName'
    DefaultGroupName = 'DefaultGroupName'
    UninstallFilesDir = 'UninstallFilesDir'
    UninstallDisplayName = 'UninstallDisplayName'
    UninstallDisplayIcon = 'UninstallDisplayIcon'
    AppPublisher = 'AppPublisher'
    AppPublisherURL = 'AppPublisherURL'
    AppSupportPhone = 'AppSupportPhone'
    AppSupportURL = 'AppSupportURL'
    AppUpdatesURL = 'AppUpdatesURL'
    AppReadmeFile = 'AppReadmeFile'
    AppContact = 'AppContact'
    AppComments = 'AppComments'
    AppModifyPath = 'AppModifyPath'


class SetupMessageName(enum.StrEnum):
    """
    The messages that Setup uses by name where the emulator follows it.
    """
    ButtonBack = 'ButtonBack'
    ButtonNext = 'ButtonNext'
    FullInstallation = 'FullInstallation'
    CompactInstallation = 'CompactInstallation'
    CustomInstallation = 'CustomInstallation'
    ReadyMemoComponents = 'ReadyMemoComponents'
    ReadyMemoDir = 'ReadyMemoDir'
    ReadyMemoGroup = 'ReadyMemoGroup'
    ReadyMemoTasks = 'ReadyMemoTasks'
    ReadyMemoType = 'ReadyMemoType'
    ReadyMemoUserInfo = 'ReadyMemoUserInfo'
    ErrorInternal2 = 'ErrorInternal2'


class _MessageList(NamedTuple):
    lowest: tuple[int, int, int]
    below: tuple[int, int, int] | None
    positions: tuple[int, ...]


_MESSAGE_LISTS: dict[tuple[tuple[int, ...], int], _MessageList] = {
    ((5, 1, 11), 207) : _MessageList((5, 1, 11), (5, 5, 0), (10, 16, 83, 27, 35, 124, 125, 126, 127, 128, 129, 54)),
    ((5, 5, 0), 220)  : _MessageList((5, 5, 0), (5, 5, 3), (12, 18, 89, 32, 40, 131, 132, 133, 134, 135, 136, 60)),
    ((5, 5, 3), 221)  : _MessageList((5, 5, 3), (6, 0, 0), (12, 18, 90, 32, 40, 132, 133, 134, 135, 136, 137, 61)),
    ((6, 0, 0), 240)  : _MessageList((6, 0, 0), (6, 0, 3), (16, 22, 95, 36, 44, 145, 146, 147, 148, 149, 150, 64)),
    ((6, 0, 0), 243)  : _MessageList((6, 0, 3), (6, 1, 0), (16, 22, 97, 36, 45, 148, 149, 150, 151, 152, 153, 66)),
    ((6, 0, 0), 261)  : _MessageList((6, 1, 0), (6, 4, 0), (16, 22, 114, 37, 46, 165, 166, 167, 168, 169, 170, 74)),
    ((6, 4, 0), 266)  : _MessageList((6, 4, 0), (6, 5, 0), (16, 22, 118, 38, 47, 169, 170, 171, 172, 173, 174, 77)),
    ((6, 5, 0), 281)  : _MessageList((6, 5, 0), None, (19, 25, 121, 41, 50, 172, 173, 174, 175, 176, 177, 80)),
}
"""
The lists of Setup's messages, by the version in their identifier and their count: the releases of
Inno Setup that use the list, and the positions of the messages of `SetupMessageName` in it, in the
order of that enumeration. The identifier alone does not tell a list: 6.0.0 names three.
"""


class SetupMessages:
    """
    The compiled messages of one language as Setup's `AssignSetupMessages` checks and reads them: a
    64-byte identifier `Inno Setup Messages (X.Y.Z)`, followed by ` (u)` in Unicode builds, the
    count of the messages, their total size and its complement, the CRC-32 of the strings, and the
    strings, each ended by a NUL character. The strings are UTF-16 in Unicode builds and decoded
    with the codec of the script's strings otherwise, so that a message and a literal of the script
    that Setup holds as the same bytes are equal. A block that fails a check raises `ValueError`.
    """
    def __init__(self, data: buf, unicode: bool, codec: str):
        view = memoryview(data)
        if len(view) <= 80:
            raise ValueError('The messages are cut short.')
        identifier = codecs.decode(bytes(view[:64]).partition(B'\0')[0], 'latin1')
        match = re.fullmatch(r'Inno Setup Messages \((\d+)\.(\d+)\.(\d+)\)( \(u\))?', identifier)
        if match is None or bool(match[4]) != unicode:
            raise ValueError(F'The messages have the identifier {identifier!r}, which this Setup does not read.')
        count, total, inverse, crc = struct.unpack_from('<IIIi', view, 64)
        if total != ~inverse & 0xFFFFFFFF or total != len(view):
            raise ValueError('The size of the messages does not match.')
        strings = view[80:]
        width = 2 if unicode else 1
        if zlib.crc32(strings) != crc & 0xFFFFFFFF or len(strings) < width or any(strings[-width:]):
            raise ValueError('The messages fail their CRC check.')
        try:
            texts = codecs.decode(strings, 'utf-16le' if unicode else codec).split('\0')
        except (LookupError, UnicodeDecodeError) as error:
            raise ValueError(F'The messages cannot be decoded: {error}') from error
        if len(texts) - 1 < count:
            raise ValueError('The messages are fewer than their count.')
        self.identifier = identifier
        self.version = (int(match[1]), int(match[2]), int(match[3]))
        self.texts = texts[:count]
        self.list = _MESSAGE_LISTS.get((self.version, count))

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, index: int) -> str:
        return self.texts[index]

    def named(self, name: SetupMessageName) -> str | None:
        """
        The message with the given name, `None` when the list of these messages is not known.
        """
        if (known := self.list) is None:
            return None
        return self.texts[known.positions[list(SetupMessageName).index(name)]]


class YesNoDirective(enum.StrEnum):
    """
    The directives of the setup header that are yes or no, or an expression of functions of the
    script.
    """
    Uninstallable = 'Uninstallable'
    CreateUninstallRegKey = 'CreateUninstallRegKey'
    ChangesEnvironment = 'ChangesEnvironment'
    ChangesAssociations = 'ChangesAssociations'


class SetupDirective(NamedTuple):
    """
    A yes-or-no directive of the setup header: its answer when the directive is yes or no, else the
    expression of functions of the script that Setup evaluates when it needs the value.
    """
    answer: bool | None
    expression: str = ''

    @classmethod
    def read(cls, text: str | None, flag: bool) -> SetupDirective:
        """
        Reads a directive as Setup does. Older versions keep it as the given flag and write no text.
        A text is yes or no, spelled `yes`, `true` or `1` and `no`, `false` or `0` in any case; any
        other text is an expression.
        """
        if not text:
            return cls(flag)
        folded = text.lower() if text.isascii() else text
        if folded in ('1', 'yes', 'true'):
            return cls(True)
        if folded in ('0', 'no', 'false'):
            return cls(False)
        return cls(None, text)


class WizardTexts(NamedTuple):
    """
    The license and the information texts that the wizard shows before and after the installation.
    An empty text means that the wizard skips its page.
    """
    license: str
    info_before: str
    info_after: str


class TSetup(InnoStruct):

    def __init__(self, reader: StructReaderBits[memoryview], version: InnoVersion, encryption: SetupEncryptionHeaderV3 | None):
        super().__init__(reader, version)
        self.Header = h = SetupHeader(reader, version, encryption)

        def _array(count: int, parser: type[_T]) -> list[_T]:
            return [parser.Parse(reader, version, self) for _ in range(count)]

        self.Languages = _array(h.LanguageCount, SetupLanguage)
        self._unicode = version.unicode
        self._messages: dict[int, SetupMessages | str] = {}
        _default_codec = 'cp1252'

        if version.unicode:
            self.Codec = 'utf-16le'
        elif not self.Languages:
            self.Codec = _default_codec
        else:
            self.Codec = self.Languages[0].Codepage
            if any(language.Codepage == _default_codec for language in self.Languages):
                self.Codec = _default_codec

        if version.ascii:
            h.recode_strings(self.Codec)
        else:
            h.recode_strings('utf-16le')

        if h.directive(YesNoDirective.Uninstallable).answer is True:
            h.Flags |= Flags.Uninstallable

        if version < (4, 0, 0):
            self._load_wizard_and_decompressor(reader, version)

        self.CustomMessages         = _array(h.MessageCount,         SetupCustomMessage) # noqa
        self.Permissions            = _array(h.PermissionCount,      SetupPermission)    # noqa
        self.Types                  = _array(h.TypeCount,            SetupType)          # noqa
        self.Components             = _array(h.ComponentCount,       SetupComponent)     # noqa
        self.Tasks                  = _array(h.TaskCount,            SetupTask)          # noqa
        self.Directories            = _array(h.DirectoryCount,       SetupDirectory)     # noqa
        self.ISSignatures           = _array(h.ISSigCount,           SetupISSignature)   # noqa
        self.Files                  = _array(h.FileCount,            SetupFile)          # noqa

        self._DecompressDLL = None
        self._DecryptionDLL = None

        self.Icons                  = _array(h.IconCount,            SetupIcon)          # noqa
        self.IniEntries             = _array(h.IniEntryCount,        SetupIniEntry)      # noqa
        self.RegistryEntries        = _array(h.RegistryCount,        SetupRegistryEntry) # noqa
        self.DeleteEntries          = _array(h.DeleteCount,          SetupDeleteEntry)   # noqa
        self.UninstallDeleteEntries = _array(h.UninstallDeleteCount, SetupDeleteEntry)   # noqa
        self.RunEntries             = _array(h.RunCount,             SetupRunEntry)      # noqa
        self.UninstallRunEntries    = _array(h.UninstallRunCount,    SetupRunEntry)      # noqa

        if version >= (4, 0, 0):
            self._load_wizard_and_decompressor(reader, version)

    def wizard_texts(self, language: int | None) -> WizardTexts:
        """
        The texts that the wizard shows in the language with the given index: each one is that of
        the language, or that of the setup header when the language has none.
        """
        header = self.Header
        texts = WizardTexts(header.get_license(), header.InfoHead, header.InfoTail)
        if language is None or not 0 <= language < len(self.Languages):
            return texts
        entry = self.Languages[language]
        own = WizardTexts(entry.LicenseText, entry.InfoBefore, entry.InfoAfter)
        return WizardTexts(*(text or fallback for text, fallback in zip(own, texts)))

    def get_wizard_images_large(self):
        return self._WizardImagesLarge

    def get_wizard_images_small(self):
        return self._WizardImagesSmall

    def messages(self, language: int) -> SetupMessages:
        """
        The compiled messages of the language with the given index, read when first asked for; a
        block that fails Setup's checks raises `ValueError` with the reason, every time it is asked
        for.
        """
        if isinstance(known := self._messages.get(language), SetupMessages):
            return known
        if known is not None:
            raise ValueError(known)
        try:
            messages = SetupMessages(self.Languages[language]._compiled_messages, self._unicode, self.Codec)
        except ValueError as error:
            self._messages[language] = str(error)
            raise
        self._messages[language] = messages
        return messages

    def get_decompress_dll(self):
        return self._DecompressDLL

    def get_7zip_dll(self):
        return self._SevenZipDLL

    def get_decryption_dll(self):
        return self._DecryptionDLL

    def _load_wizard_and_decompressor(self, reader: StructReader[memoryview], version: InnoVersion):
        if True:
            self._WizardImagesLarge = self._load_wizard_images(reader, version)
        if version >= (2, 0, 0) or version.isx:
            self._WizardImagesSmall = self._load_wizard_images(reader, version)
        method = self.Header.CompressionMethod
        crypto = self.Header.Flags & Flags.EncryptionUsed and version < (6, 4, 0)
        has7zip = bool(self.Header.SevenZipLibraryName)
        hasDLL = (False
            or method == CompressionMethod.BZip2
            or method == CompressionMethod.LZMA1 and version == (4, 1, 5)
            or method == CompressionMethod.Flate and version >= (4, 2, 6))
        self._DecompressDLL = reader.read_length_prefixed() if hasDLL else None
        self._SevenZipDLL = reader.read_length_prefixed() if has7zip else None
        self._DecryptionDLL = reader.read_length_prefixed() if crypto else None

    def _load_wizard_images(self, reader: StructReader[memoryview], version: InnoVersion):
        count = reader.u32() if version >= (5, 6, 0) else 1
        img = [reader.read_length_prefixed() for _ in range(count)]
        if version < (5, 6, 0) and img and not img[0]:
            img.clear()
        return img


class SetupDataEntryFlags(enum.IntFlag):
    Empty                    = 0           # noqa    
    VersionInfoValid         = enum.auto() # noqa
    VersionInfoNotValid      = enum.auto() # noqa
    BZipped                  = enum.auto() # noqa
    TimeStampInUTC           = enum.auto() # noqa
    IsUninstallerExe         = enum.auto() # noqa
    CallInstructionOptimized = enum.auto() # noqa
    ApplyTouchDateTime       = enum.auto() # noqa
    ChunkEncrypted           = enum.auto() # noqa
    ChunkCompressed          = enum.auto() # noqa
    SolidBreak               = enum.auto() # noqa
    Sign                     = enum.auto() # noqa
    SignOnce                 = enum.auto() # noqa


class SetupSignMode(enum.IntEnum):
    NoSetting  = 0  # noqa
    Yes        = 1  # noqa
    Once       = 2  # noqa
    Check      = 3  # noqa


class SetupDataEntry(InnoStruct):

    def __init__(self, reader: StructReaderBits[memoryview], version: InnoVersion):
        super().__init__(reader, version)
        self.FirstSlice = reader.u32()
        self.LastSlice = reader.u32()
        if version < (6, 5, 2):
            self.ChunkOffset = reader.u32()
        else:
            self.ChunkOffset = reader.u64()
        if version < (4, 0, 0):
            if self.FirstSlice < 1 or self.LastSlice < 1:
                raise ValueError(F'Unexpected slice {self.FirstSlice}:{self.LastSlice}')
        if version >= (4, 0, 1):
            self.Offset = reader.u64()
        if version >= (4, 0, 0):
            self.FileSize = reader.u64()
            self.ChunkSize = reader.u64()
        else:
            self.FileSize = reader.u32()
            self.ChunkSize = reader.u32()

        if version >= (6, 4, 0):
            self.ChecksumType = CheckSumType.SHA256
            self.Checksum = bytes(reader.read(32))
        elif version >= (5, 3, 9):
            self.ChecksumType = CheckSumType.SHA1
            self.Checksum = bytes(reader.read(20))
        elif version >= (4, 2, 0):
            self.ChecksumType = CheckSumType.MD5
            self.Checksum = bytes(reader.read(16))
        elif version >= (4, 0, 1):
            self.ChecksumType = CheckSumType.CRC32
            self.Checksum = bytes(reader.read(4))
        else:
            self.ChecksumType = CheckSumType.Adler32
            self.Checksum = bytes(reader.read(4))

        if version.bits == 16:
            from refinery.lib.dt import dostime
            ts = dostime(reader.u32())
        else:
            ts = filetime(reader.u64())

        self.FileTime = ts

        self.FileVersionMs = reader.u32()
        self.FileVersionLs = reader.u32()

        self.Flags = 0

        def flagbit(f):
            self.Flags |= f if reader.read_bit() else 0

        flag_start = reader.tell()
        flagbit(SetupDataEntryFlags.VersionInfoValid)

        if version < (6, 4, 3):
            flagbit(SetupDataEntryFlags.VersionInfoNotValid)
        if version < (4, 0, 1):
            flagbit(SetupDataEntryFlags.BZipped)
        if (4, 0, 10) <= version:
            flagbit(SetupDataEntryFlags.TimeStampInUTC)
        if (4, 1, 0) <= version < (6, 4, 3):
            flagbit(SetupDataEntryFlags.IsUninstallerExe)
        if (4, 1, 8) <= version:
            flagbit(SetupDataEntryFlags.CallInstructionOptimized)
        if (4, 2, 0) <= version < (6, 4, 3):
            flagbit(SetupDataEntryFlags.ApplyTouchDateTime)
        if (4, 2, 2) <= version:
            flagbit(SetupDataEntryFlags.ChunkEncrypted)
        if (4, 2, 5) <= version:
            flagbit(SetupDataEntryFlags.ChunkCompressed)
        if (5, 1, 13) <= version < (6, 4, 3):
            flagbit(SetupDataEntryFlags.SolidBreak)
        if (5, 5, 7) <= version < (6, 3, 0):
            flagbit(SetupDataEntryFlags.Sign)
            flagbit(SetupDataEntryFlags.SignOnce)

        reader.byte_align()

        if (6, 3, 0) <= version < (6, 4, 3):
            if (reader.tell() - flag_start) % 2:
                reader.u8()
            self.SignMode = SetupSignMode(reader.u8())
        elif self.Flags & SetupDataEntryFlags.SignOnce:
            self.SignMode = SetupSignMode.Once
        elif self.Flags & SetupDataEntryFlags.Sign:
            self.SignMode = SetupSignMode.Yes
        else:
            self.SignMode = SetupSignMode.NoSetting


class TData(InnoStruct):

    def __init__(self, reader: StructReaderBits[memoryview], version: InnoVersion):
        super().__init__(reader, version)
        self.DataEntries: list[SetupDataEntry] = []
        while not reader.eof:
            self.DataEntries.append(SetupDataEntry(reader, version))


class InnoParseResult(NamedTuple):
    version: InnoVersion
    streams: list[InnoStream]
    files: list[InnoFile]
    warnings: int
    failures: list[str]
    setup_info: None | TSetup
    setup_data: None | TData
    encryption: None | SetupEncryptionHeaderV3

    def ok(self):
        return self.warnings == 0 and not self.failures


class _Stored:
    """
    The decompressor of a stream that is stored without compression.
    """
    def decompress(self, data: buf) -> buf:
        return data


class InnoStreams(NamedTuple):
    TSetup: InnoStream
    TData: InnoStream
    Uninstaller: InnoStream


def _archive_config():
    """
    The configuration of the machine that an archive assumes when it names its files: the folders
    and names are the constants that stand for them.
    """
    from refinery.lib.inno.emulator import IFPSEmulatorConfig
    return IFPSEmulatorConfig(
        temp_path='{tmp}',
        user_name='{user}',
        host_name='{host}',
        inno_name='{name}',
        executable='{exe}',
        install_to='{app}',
        log_mutexes=False,
        log_opcodes=False,
        log_passwords=True,
    )


def _setup_program_release(view: memoryview, offset: int, version: InnoVersion) -> tuple[int, int, int] | None:
    """
    The release that the setup program at the given offset of an installer names in its text
    `Inno Setup version`; `None` when the program cannot be read or names no single release.
    """
    if version < (4, 1, 6):
        return None
    try:
        reader = StructReader(view[offset:])
        stream = InnoStream(StreamHeader(reader, version))
        to_read = stream.header.StoredSize
        while to_read > 4:
            block = CrcCompressedBlock(reader, min(to_read - 4, 0x1000))
            stream.blocks.append(block)
            to_read -= len(block)
        program = InnoArchive.read_stream(stream)
    except Exception:
        return None
    releases = {
        (int(major.replace(B'\0', B'')), int(minor.replace(B'\0', B'')), int(patch.replace(B'\0', B'')))
        for pattern in _SETUP_PROGRAM_RELEASE
        for major, minor, patch in pattern.findall(program)
    }
    if len(releases) != 1:
        return None
    return releases.pop()


def _message_list_releases(setup_info: TSetup) -> ReleaseRange | None:
    """
    The releases of Inno Setup that use the list of messages of the first language.
    """
    if not setup_info.Languages:
        return None
    try:
        known = setup_info.messages(0).list
    except ValueError:
        return None
    if known is None:
        return None
    return known.lowest, known.below


def _setup_program_releases(view: memoryview, offset: int, version: InnoVersion) -> ReleaseRange | None:
    """
    The release that the setup program names, as a range of releases for `SetupRelease`.
    """
    if (release := _setup_program_release(view, offset, version)) is None:
        return None
    return release, next_release(release)


class InnoArchive:
    """
    This class represents an InnoSetup archive. Optionally, a `refinery.units.Unit` can be
    passed to the class as a parameter to use its logger.
    """
    OffsetsPath: ClassVar[str] = 'RCDATA/11111'
    ChunkPrefix: ClassVar[bytes] = b'zlb\x1a'

    def __init__(
        self,
        data: bytearray,
        unit: Unit | None = None,
    ):
        if not (meta := TSetupLdrOffsetTable.FindInBinary(data)):
            try:
                from refinery.units.formats.pe.perc import perc
                with data | perc(self.OffsetsPath) as resources:
                    _meta = one(resources)
            except Exception as E:
                raise ValueError(F'Could not find TSetupOffsets PE resource at {self.OffsetsPath}') from E
            else:
                meta = TSetupLdrOffsetTable.Parse(_meta)

        self._password = None
        self._password_guessed = False

        leniency = unit.leniency if unit else 0
        self._log_verbose = (lambda *_: None) if unit is None else unit.log_debug
        self._log_comment = (lambda *_: None) if unit is None else unit.log_info
        self._log_warning = (lambda *_: None) if unit is None else unit.log_warn

        self.meta = meta
        self.view = view = memoryview(data)

        base = meta.base
        inno = StructReader(view[base:base + meta.total_size])

        self._chunks: weakref.WeakValueDictionary[tuple[int, int, str | None], SolidStream] = (
            weakref.WeakValueDictionary())

        blobsize = meta.info_offset - meta.data_offset
        inno.seek(meta.data_offset)
        self.blobs = blobs = StructReader(inno.read(blobsize))

        header = bytes(inno.read(16))

        try:
            version = InnoVersion.ParseLegacy(header)
        except ValueError:
            header += bytes(inno.read(64 - 16))
            try:
                version = InnoVersion.Parse(header)
            except ValueError:
                if version := meta.iv:
                    method = 'magic'
                else:
                    name, _, _rest = header.partition(b'\0')
                    method = 'broken'
                    if any(_rest):
                        header = name.hex()
                    else:
                        header = name.decode('latin1')
                    if leniency < 1:
                        raise ValueError(F'unable to parse header identifier "{header}"')
                    version = _DEFAULT_INNO_VERSION
            else:
                header, _, _ = header.partition(B'\0')
                header = header.decode('latin1')
                method = 'modern'
        else:
            header, _, _ = header.partition(B'\x1A')
            header = header.decode('latin1')
            method = 'legacy'

        self._log_comment(F'inno {version!s} via {method} header: {header}')

        inno_start = inno.tell()
        best_parse = None
        best_score = 0
        first_error = None
        success = False
        results: dict[InnoVersion, InnoParseResult] = {}
        result = None

        VER = _VERSIONS
        AMB = _IS_AMBIGUOUS

        if not version.is_ambiguous():
            index = VER.index(version)
        else:
            try:
                index = max(k for k, v in enumerate(VER) if v <= version)
            except Exception:
                index = 0

        lower = index
        upper = index + 1
        while lower > 0 and AMB[VER[lower - 1]] or VER[lower - 1].semver == VER[lower].semver:
            lower -= 1

        versions = [version] + VER[lower:upper] + VER[upper:] + VER[:lower]

        try:
            for v in versions:
                inno.seekset(inno_start)
                if inno.eof:
                    raise EOFError
                try:
                    if v.legacy:
                        inno.seekrel(-48)
                    result = self._try_parse_as(inno, blobs, v)
                except Exception as e:
                    first_error = first_error or e
                    self._log_comment(F'exception while parsing as {v!s}: {exception_to_string(e)}')
                    result = InnoParseResult(v, [], [], 1, [str(e)], None, None, None)
                else:
                    results[v] = result
                if success := result.ok():
                    if v != version:
                        self._log_comment(F'inno {v!s} via closest match: {header}')
                    break
                if not result.failures and (best_parse is None or result.warnings < best_score):
                    best_score = result.warnings
                    best_parse = result

            if not success:
                if best_parse is not None:
                    result = best_parse
                    self._log_warning(F'using parse result for {result.version!s} with {result.warnings} warnings')
                else:
                    if not results:
                        raise first_error or ValueError('no parser for any known Inno version worked')
                    result = min(results.values(), key=lambda result: len(result.failures))
                    self._log_warning(F'using parse result for {result.version!s} with {len(result.failures)} failures')
                    for k, failure in enumerate(result.failures, 1):
                        self._log_comment(F'failure {k}: {failure}')
        finally:
            del first_error

        if TYPE_CHECKING:
            assert result
            assert result.setup_data
            assert result.setup_info

        self.version = version = result.version
        self.codec = codec = result.setup_info.Codec
        self.setup_info = result.setup_info
        self.setup_data = result.setup_data
        self.files = result.files
        self.streams = InnoStreams(*result.streams)
        self.script_codec = 'latin1' if version.unicode else codec

        for file in self.files:
            try:
                path = self.expand_constants(file.path)
            except Exception as error:
                self._log_warning(F'keeping the constants of {file.path}: {exception_to_string(error)}')
                path = file.path
            path = path.replace('\\', '/')
            drive, colon, path = path.rpartition(':/')
            if colon and len(drive) == 1:
                path = F'{drive}/{path}'
            file.path = F'data/{path}'

    def expand_constants(self, text: str) -> str:
        """
        Expands the constants in a text of the installer as Setup would on the machine that the
        archive assumes, whose folders and names are the constants that stand for them. A code
        constant runs the script when the emulator can run it and fails otherwise.
        """
        if (emulator := self._script_emulator) is not None:
            return emulator.reset().expand_constant(text)
        if isinstance(host := self._constants_without_script, Exception):
            raise copy_exception(host)
        expansion = host.expand(text)
        try:
            while True:
                next(expansion)
        except StopIteration as done:
            return done.value

    @cached_property
    def _script_emulator(self):
        try:
            return self.emulator
        except Exception as error:
            self._log_comment(F'the script cannot be emulated: {exception_to_string(error)}')
            return None

    @cached_property
    def _constants_without_script(self) -> SetupConstants | Exception:
        """
        The constants of Setup on the machine that the archive assumes, without the script; the
        error that keeps them from being built, which every expansion then raises.
        """
        from refinery.lib.inno.host import HostSetup, SetupConstants
        from refinery.lib.inno.wizard import StandIns, WizardForm
        config = _archive_config()
        try:
            setup = HostSetup.of_installer(self, config)
        except Exception as error:
            return copy_exception(error)
        form = WizardForm(StandIns.of(config), uninstallable=setup.uninstallable.answer is not False)
        return SetupConstants(setup, config, form)

    @cached_property
    def emulator(self):
        """
        An `refinery.lib.inno.emulator.InnoSetupEmulator` for the embedded IFPS script, if it exists.
        """
        if self.ifps is None:
            return None
        from refinery.lib.inno.emulator import InnoSetupEmulator
        return InnoSetupEmulator(self, _archive_config())

    @cached_property
    def release(self) -> SetupRelease:
        """
        The release of Inno Setup that built the installer: the one that Inno Setup 7 writes into
        the header, else the releases from the version of the installer's data up to the next
        version of the data, which the list of Setup's messages and then the setup program narrow
        when asked.
        """
        if code := self.setup_info.Header.CompiledCodeVersion:
            return SetupRelease.of_compiled_code(code)
        lowest = self.version.semver[:3]
        below = next((v.semver[:3] for v in _VERSIONS if v.semver[:3] > lowest), None)
        return SetupRelease(
            lowest,
            below,
            functools.partial(_message_list_releases, self.setup_info),
            functools.partial(_setup_program_releases, self.view, self.meta.exe_offset, self.version),
        )

    @property
    def setup_program_release(self) -> tuple[int, int, int] | None:
        """
        The release that the setup program of the installer names in its text `Inno Setup version`,
        which Setup writes into its log; `None` when the program cannot be read or names no single
        release.
        """
        return _setup_program_release(self.view, self.meta.exe_offset, self.version)

    @cached_property
    def ifps(self):
        """
        An `refinery.lib.inno.ifps.IFPSFile` representing the embedded IFPS script, if it exists.
        Inno Setup 5.2.0 and later write two load flags into the declaration of a DLL import; for
        older versions, the calls of the script decide.
        """
        if script := self.setup_info.Header.get_script():
            version = self.version
            return IFPSFile.Parse(
                script,
                self.script_codec,
                version.unicode,
                2 if version >= (5, 2, 0) else None,
            )

    def guess_password(self, timeout: int) -> bool:
        """
        Attempt to guess the password by emulating the setup script.
        """
        if self._password_guessed:
            return self._password is not None
        self._password_guessed = True
        if file := self.get_encrypted_sample():
            from refinery.lib.inno.emulation import NewEmulationError, NewPassword, NewScriptError
            self._log_verbose('attempting to automatically determine password from the embedded script')
            try:
                if (emulator := self.emulator) is None:
                    self._log_comment('the archive has no script to determine the password from')
                    return False
                password_test = functools.partial(self.check_password, file)
                for p in emulator.emulate_installation(max_seconds=timeout, password_test=password_test):
                    if isinstance(p, (NewScriptError, NewEmulationError)):
                        self._log_comment(str(p))
                        continue
                    if not isinstance(p, NewPassword):
                        continue
                    if password_test(p):
                        self._log_comment('found password via emulation:', p)
                        self._password = p
                        return True
                else:
                    self._log_comment('no valid password found via emulation')
                    return False
            except Exception as error:
                self._log_comment('emuluation failed:', error)
                return False
        else:
            self._password = ''
            return True

    def get_encrypted_sample(self) -> InnoFile | None:
        """
        If the archive has a password, this function returns the smallest encrypted file record.
        """
        file = min(self.files, key=lambda f: (not f.encrypted, f.size))
        return file if file.encrypted else None

    def _try_parse_as(
        self,
        inno: StructReader[memoryview],
        blobs: StructReader[memoryview],
        version: InnoVersion,
        max_failures: int = 5
    ):
        streams: list[InnoStream] = []
        files: list[InnoFile] = []
        warnings = 0

        if version >= (6, 5, 0):
            expected_checksum = inno.u32()
            encryption = SetupEncryptionHeaderV3(inno)
            computed_checksum = zlib.crc32(encryption.__buffer__(0)) & 0xFFFFFFFF
            if expected_checksum != computed_checksum:
                raise ValueError('Encryption header failed the CRC check.')
            if encryption.Scope == SetupEncryptionScope.Full:
                raise NotImplementedError('This archive uses full encryption, support has not yet been added.')
        else:
            encryption = None

        for _ in range(3):
            stream = InnoStream(StreamHeader(inno, version))
            streams.append(stream)
            to_read = stream.header.StoredSize
            while to_read > 4:
                block = CrcCompressedBlock(inno, min(to_read - 4, 0x1000))
                stream.blocks.append(block)
                to_read -= len(block)

        self._log_verbose(F'{version!s} parsing stream 1 (TData)')
        streams[1].data = self.read_stream(streams[1])
        stream1 = TData.Parse(memoryview(streams[1].data), version)

        for meta in stream1.DataEntries:
            file = InnoFile(blobs, version, meta)
            files.append(file)

        self._log_verbose(F'{version!s} parsing stream 0 (TSetup)')
        streams[0].data = self.read_stream(streams[0])
        stream0 = TSetup.Parse(memoryview(streams[0].data), version, encryption)
        path_dedup: dict[str, list[SetupFile]] = {}

        for file in files:
            file.compression_method = stream0.Header.CompressionMethod
            file.crypto = stream0.Header.Encryption

        for sf in stream0.Files:
            sf: SetupFile
            location = sf.Location
            if sf.external or sf.Type != SetupFileType.UserFile or sf.Source:
                msg = F'skipping file: offset=0x{location:08X} type={sf.Type.name}'
                if sf.Source:
                    msg = F'{msg} src={sf.Source}'
                self._log_verbose(msg)
                continue
            if location >= len(files):
                self._log_warning(F'parsed {len(files)} entries, ignoring invalid setup reference to entry {location + 1}')
                continue
            path = sf.Destination.replace('\\', '/')
            path_dedup.setdefault(path, []).append(sf)
            files[location].setup = sf
            files[location].path = path

        for path, infos in list(path_dedup.items()):
            if len(infos) == 1:
                continue
            del path_dedup[path]
            for sf in infos:
                if condition := sf.Condition.Check:
                    condition = re.sub('\\s+', '-', condition)
                    np = F'{condition}/{path}'
                    path_dedup.setdefault(np, []).append(sf)

        for path, infos in path_dedup.items():
            if len(infos) == 1:
                files[infos[0].Location].path = path
                continue
            bycheck = {}
            onefile = None
            for info in infos:
                file = files[info.Location]
                if not file.checksum_type.strong():
                    bycheck.clear()
                    break
                dkey = (file.checksum, file.size)
                if dkey in bycheck:
                    self._log_verbose(F'skipping exact duplicate: {path}')
                    file.dupe = True
                    continue
                bycheck[dkey] = info
                onefile = file
            if bycheck:
                if len(bycheck) == 1:
                    assert onefile
                    onefile.path = path
                    continue
                infos = list(bycheck.values())
            for k, info in enumerate(infos):
                files[info.Location].path = F'{path}[{k}]'

        _width = len(str(len(files)))

        for k, file in enumerate(files):
            if file.dupe:
                continue
            if not file.path:
                self._log_verbose(F'file {k} does not have a path')
                file.path = F'raw/FileData{k:0{_width}d}'

        warnings = sum(1 for file in files if file.setup is None)
        failures = []
        nonempty = [f for f in files if f.size > 0]

        for file in nonempty:
            if len(failures) >= max_failures:
                break
            if file.setup is None:
                failures.append(F'file {file.path} had no associated metadata')
                continue

        return InnoParseResult(
            version,
            streams,
            files,
            warnings,
            failures,
            stream0,
            stream1,
            encryption,
        )

    @staticmethod
    def read_stream(stream: InnoStream):
        """
        Decompress and read the input stream.
        """
        result = bytearray()
        it = iter(stream.blocks)
        if stream.compression == StreamCompressionMethod.Store:
            dec = _Stored()
        elif stream.compression == StreamCompressionMethod.LZMA1:
            import lzma
            first = next(it).BlockData
            prop, first = first[:5], first[5:]
            filter = parse_lzma_properties(prop, 1)
            dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[filter])
            result.extend(dec.decompress(first))
        elif stream.compression == StreamCompressionMethod.Flate:
            import zlib
            dec = zlib.decompressobj()
        else:
            raise ValueError(F'Invalid compression value {stream.compression}')
        for block in it:
            result.extend(dec.decompress(block.BlockData))
        return result

    def check_password(self, file: InnoFile, password: str):
        """
        Returns `True` if the given password correctly decrypts the given file.
        """
        try:
            self.read_chunk(file, password, check_only=True)
        except InvalidPassword:
            return False
        else:
            return True

    def read_chunk(
        self,
        file: InnoFile,
        password: str | None = None,
        check_only: bool = False,
    ) -> buf:
        """
        Decompress and read the chunk containing the given file. If the chunk is encrypted, the
        function requires the correct password. If the `check_only` parameter is set, then only a
        password check is performed, but the chunk is not actually decompressed.
        """
        if check_only:
            return self._read_stored_chunk(file, password, check_only=True)
        chunk = bytearray()
        for _, piece in self._chunk_pieces(file, password):
            chunk.extend(piece)
        return chunk

    def _read_stored_chunk(
        self,
        file: InnoFile,
        password: str | None = None,
        check_only: bool = False,
    ) -> buf:
        """
        Read the compressed chunk containing the given file and decrypt it if it is encrypted. If
        the `check_only` parameter is set, then only a password check is performed.
        """
        reader = file.reader
        offset = file.chunk_offset
        length = file.chunk_length

        if password is None:
            password = self._password

        if offset + length > len(reader):
            span = F'0x{offset:X}-0x{offset + length:X}'
            raise LookupError(
                F'Chunk spans 0x{len(file.reader):X} bytes; data is located at {span}.')

        reader.seek(offset)
        prefix = reader.read(4)

        if prefix != self.ChunkPrefix:
            raise ValueError(F'Error reading chunk at offset 0x{offset:X}; invalid magic {prefix.hex()}.')

        if file.encrypted:
            if file.crypto is None:
                raise RuntimeError(F'File {file.path} is encrypted, but no password type was set.')
            if password is None:
                raise InvalidPassword
            password_bytes = password.encode(
                'utf-16le' if file.unicode else self.script_codec)
            if not file.crypto.test(password_bytes):
                raise InvalidPassword(password)
            length += file.crypto.SaltLength
        else:
            password_bytes = None

        if check_only:
            return B''

        data = reader.read_exactly(length)

        if file.encrypted:
            assert password_bytes
            assert file.crypto
            data = file.crypto.decrypt(password_bytes, data, file.chunk_offset, file.first_slice)

        return data

    def extractor(self, file: InnoFile, password: str | None = None) -> Callable[[], buf]:
        """
        Return a function that returns the contents of the given file record without performing
        any checks. The chunk that holds the file is decompressed when the function is first called;
        it keeps the data of other files only while the functions returned for them are alive.
        Without a password, the function uses the password that the archive has when it is called.
        """
        key = file.chunk_offset, file.chunk_length, password
        if (stream := self._chunks.get(key)) is None:
            stream = self._chunks[key] = SolidStream(lambda _: self._chunk_pieces(file, password))
        claim = stream.claim(file.offset, file.size)

        def extract() -> buf:
            if file.encrypted and password is None and self._password is None:
                raise InvalidPassword
            try:
                data = claim()
            except SolidStreamTruncated as truncated:
                data = truncated.partial
            if file.filtered:
                if file.version >= (5, 2, 0):
                    flip = (file.version >= (5, 3, 9))
                    data = self._filter_new(data, flip_high_byte=flip)
                else:
                    data = self._filter_old(data)
            return data

        return extract

    def _chunk_pieces(self, file: InnoFile, password: str | None) -> Iterator[tuple[int, buf]]:
        if password is None:
            password = self._password
        data = memoryview(self._read_stored_chunk(file, password))
        method = file.compression
        self._log_verbose(F'decompressing chunk at {file.chunk_offset:#010x} using {method.name}')
        try:
            if method is None or method == CompressionMethod.Store:
                pieces = iter((data,))
            elif method == CompressionMethod.LZMA1:
                props = parse_lzma_properties(data[0:5], 1)
                lzma1 = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[props])
                pieces = decompress_pieces(lzma1, data[5:])
            elif method == CompressionMethod.LZMA2:
                props = parse_lzma_properties(data[0:1], 2)
                lzma2 = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[props])
                pieces = decompress_pieces(lzma2, data[1:])
            elif method == CompressionMethod.BZip2:
                pieces = decompress_pieces(bz2.BZ2Decompressor(), data)
            elif method == CompressionMethod.Flate:
                pieces = inflate_pieces(data)
            else:
                pieces = iter((data,))
            position = 0
            for piece in pieces:
                yield position, piece
                position += len(piece)
        except MemoryError:
            raise
        except Exception as E:
            if not file.encrypted:
                raise
            raise InvalidPassword(password) from E

    def read_file(
        self,
        file: InnoFile,
        password: str | None = None,
    ):
        """
        Read the contents of the given file record from the archive without performing any checks.
        See also `refinery.lib.inno.InnoArchive.read_file_and_check`.
        """
        return self.extractor(file, password)()

    def read_file_and_check(
        self,
        file: InnoFile,
        password: str | None = None,
    ):
        """
        Read the contents of the given file record from the archive. Raises a `ValueError` if the
        checksum is invalid.
        """
        return self.check_file(file, self.read_file(file, password))

    def check_file(self, file: InnoFile, data: buf) -> buf:
        """
        Return the given contents of the file record, or raise `InnoChecksumMismatch` if they do
        not match its checksum.
        """
        if (cs := file.check(data)) is not None and cs != file.checksum:
            if isinstance(cs, int):
                computed = F'{cs:08X}'
                expected = F'{file.checksum:08X}'
            else:
                computed = cs.hex().upper()
                expected = file.checksum.hex().upper()
            raise InnoChecksumMismatch(F'checksum error; computed:{computed} expected:{expected}', data)

        return data

    def _filter_new(self, data: buf, flip_high_byte=False):
        try:
            import numpy as np
        except ImportError:
            return self._filter_new_fallback(data, flip_high_byte)
        u08 = np.uint8
        u32 = np.uint32
        ab0 = bytearray()
        ab1 = bytearray()
        ab2 = bytearray()
        ab3 = bytearray()
        positions = []
        if isinstance(data, bytearray):
            out = data
        else:
            out = bytearray(data)
        mem = memoryview(out)
        for k in range(0, len(mem), 0x10000):
            for match in re.finditer(B'(?s)[\xE8\xE9]....', mem[k:k + 0x10000], flags=re.DOTALL):
                a = match.start() + k
                if 0 < (top := mem[a + 4]) < 0xFF:
                    continue
                ab0.append(mem[a + 1])
                ab1.append(mem[a + 2])
                ab2.append(mem[a + 3])
                ab3.append(top)
                positions.append(a + 5)
        ab0 = np.frombuffer(ab0, dtype=u08)
        ab1 = np.frombuffer(ab1, dtype=u08)
        low = np.frombuffer(ab2, dtype=u08).astype(u32)
        msb = np.frombuffer(ab3, dtype=u08)
        sub = np.fromiter(positions, dtype=u32)
        low <<= 8
        low += ab1
        low <<= 8
        low += ab0
        low -= sub
        low &= 0xFFFFFF
        if flip_high_byte:
            flips = low >> 23
            keeps = 1 - flips
            keeps *= msb
            msb ^= 0xFF
            msb *= flips
            msb += keeps
        low += (msb.astype(u32) << 24)
        ab = low.tobytes()
        am = memoryview(ab)
        for k, offset in enumerate(positions):
            out[offset - 4:offset] = am[k * 4:(k + 1) * 4]
        return out

    def _filter_new_fallback(self, data: buf, flip_high_byte=False):
        block_size = 0x10000
        out = bytearray(data)
        i = 0
        while len(data) - i >= 5:
            c = out[i]
            block_size_left = block_size - (i % block_size)
            i += 1
            if (c == 0xE8 or c == 0xE9) and block_size_left >= 5:
                address = out[i:i + 4]
                i += 4
                if address[3] == 0 or address[3] == 0xFF:
                    rel = address[0] | address[1] << 8 | address[2] << 16
                    rel -= i & 0xFFFFFF
                    out[i - 4] = rel & 0xFF
                    out[i - 3] = (rel >> 8) & 0xFF
                    out[i - 2] = (rel >> 16) & 0xFF
                    if flip_high_byte and (rel & 0x800000) != 0:
                        out[i - 1] = (~out[i - 1]) & 0xFF
        return out

    @staticmethod
    def _filter_old(data: buf):
        if not isinstance(data, bytearray):
            data = bytearray(data)
        addr_bytes_left = 0
        addr_offset = 5
        addr = 0
        for i, c in enumerate(data):
            if addr_bytes_left == 0:
                if c == 0xE8 or c == 0xE9:
                    addr = (~addr_offset + 1) & 0xFFFFFFFF
                    addr_bytes_left = 4
            else:
                addr = (addr + c) & 0xFFFFFFFF
                c = addr & 0xFF
                addr = addr >> 8
                addr_bytes_left -= 1
            data[i] = c
        return data


def is_inno_setup(data: buf):
    """
    Test whether the input data is likely an Inno Setup executable.
    """
    if data[:2] != B'MZ':
        return False
    if re.search(re.escape(InnoArchive.ChunkPrefix), data) is None:
        return False
    for marker in [
        B'Inno Setup Setup Data',
        B'Inno Setup Messages',
        B'<description>Inno Setup</description>',
        B'InnoSetupLdrWindow',
        B'This installation was built with Inno Setup',
    ]:
        if re.search(re.escape(marker), data):
            return True
    for marker in SetupMagicToVersion.keys():
        if re.search(re.escape(marker), data) is not None:
            return True
    return False
