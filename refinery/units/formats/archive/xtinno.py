#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
InnoSetup parsing based on [innoextract][IE] source code and its Python port in [Malcat][MC].
The [Malcat][MC] implementation served as the initial template but was re-written to work
with refinery's data structures.

[IE]: https://constexpr.org/innoextract/
[MC]: https://malcat.fr/
"""
from __future__ import annotations

import enum
import re
import struct
import functools
import dataclasses
import codecs

import lzma
import zlib
import bz2

from datetime import datetime, timezone
from hashlib import sha256, sha1, md5

from refinery.units.formats.archive import ArchiveUnit
from refinery.units.formats.pe.perc import perc
from refinery.lib.structures import Struct, StructReader

from refinery.lib.tools import exception_to_string, one
from refinery.lib.lcid import LCID, DEFAULT_CODEPAGE
from refinery.lib.types import ByteStr
from refinery.lib.json import BytesAsStringEncoder

from refinery.units.crypto.cipher.rc4 import rc4
from refinery.units.crypto.cipher.chacha import xchacha
from refinery.units.crypto.keyderive.pbkdf2 import pbkdf2

from typing import (
    List,
    Optional,
    Type,
    TypeVar,
)


_DEFAULT_INNO_VERSION = (5, 0, 0)
_FILE_TIME_1970_01_01 = 116444736000000000

_T = TypeVar('_T')


class InvalidPassword(ValueError):
    def __init__(self, password: Optional[str] = None):
        if password is None:
            super().__init__('A password is required and none was given.')
        else:
            super().__init__('The given password is not correct.')


class FileChunkOutOfBounds(LookupError):
    pass


class JsonStruct(Struct):
    def json(self):
        def _json(v):
            if isinstance(v, list):
                return [_json(x) for x in v]
            if isinstance(v, dict):
                return {x: _json(y) for x, y in v.items()}
            if isinstance(v, JsonStruct):
                return v.json()
            if isinstance(v, enum.IntFlag):
                return [option.name for option in v.__class__ if v & option == option]
            if isinstance(v, enum.IntEnum):
                return v.name
            return v
        return {
            k: _json(v) for k, v in self.__dict__.items()
            if not k.startswith('_')
        }


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
    DisableProgramGroupPage     = enum.auto() # noqa
    AllowNoIcons                = enum.auto() # noqa
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


class AutoBool(enum.IntEnum):
    Auto = 0
    No = 1
    Yes = 2


class WizardStyle(enum.IntEnum):
    Classic = 0
    Modern = 1


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
    NoPrivileges = 0
    PowerUserPrivileges = 1
    AdminPriviliges = 2
    LowestPrivileges = 3


class PrivilegesRequiredOverrideAllowed(enum.IntEnum):
    CommandLine = 0
    Dialog = 1


class LanguageDetection(enum.IntEnum):
    UI = 0
    Locale = 1
    Nothing = 2


class CompressionMethod(enum.IntEnum):
    Store = 0
    ZLib = 1
    Bzip2 = 2
    Lzma1 = 3
    Lzma2 = 4

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
    Unknown = 0b00000 # noqa
    X86     = 0b00001 # noqa
    AMD64   = 0b00010 # noqa
    IA64    = 0b00100 # noqa
    ARM64   = 0b01000 # noqa
    All     = 0b01111 # noqa


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
    ZLib = 1
    LZMA1 = 2


class StreamHeader(JsonStruct):
    def __init__(self, reader: StructReader[memoryview], name: str, version: tuple[int, int, int]):
        self.Name = name
        self.HeaderCrc = reader.u32()
        self.CompressedSize = size = reader.u32()
        if version >= (4, 0, 9):
            self.StoredSize = self.CompressedSize
            if not reader.u8():
                self.Compression = StreamCompressionMethod.Store
            elif version >= (4, 1, 6):
                self.Compression = StreamCompressionMethod.LZMA1
            else:
                self.Compression = StreamCompressionMethod.ZLib
        else:
            self.UncompresedSize = reader.u32()
            if size == 0xFFFFFFFF:
                self.StoredSize = self.UncompresedSize
                self.Compression = StreamCompressionMethod.Store
            else:
                self.StoredSize = size
                self.Compression = StreamCompressionMethod.ZLib
            # Add the size of a CRC32 checksum for each 4KiB subblock
            block_count, _r = divmod(self.StoredSize, 4096)
            block_count += int(bool(_r))
            self.StoredSize += 4 * block_count


class CrcCompressedBlock(JsonStruct):
    def __init__(self, reader: StructReader[memoryview], size: int):
        self.BlockCrc = reader.u32()
        self.BlockData = reader.read(size)


class TSetupOffsets(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        self.id = reader.read(12)
        self.version = reader.u32()
        self.total_size = reader.u32()
        self.exe_offset = reader.u32()
        self.exe_uncompressed_size = reader.u32()
        self.exe_crc = reader.u32()
        self.setup0_offset = reader.u32()
        self.setup1_offset = reader.u32()
        self.offsets_crc = reader.u32()
        self.base = min(
            self.exe_offset,
            self.setup0_offset,
            self.setup1_offset,
        )
        self.setup0 = self.setup0_offset - self.base
        self.setup1 = self.setup1_offset - self.base


@dataclasses.dataclass
class InnoFile:
    reader: StructReader[ByteStr]
    version: tuple[int, int, int]
    unicode: bool
    meta: SetupDataEntry
    path: str = ""
    dupe: bool = False
    tags: SetupFileFlags = 0
    compression_method: Optional[CompressionMethod] = None
    password_hash: bytes = B''
    password_salt: bytes = B''
    password_type: PasswordType = PasswordType.Nothing

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

    def check(self, data: ByteStr):
        t = self.checksum_type
        if t == CheckSumType.Missing:
            return True
        if t == CheckSumType.Adler32:
            return self.checksum == zlib.adler32(data) & 0xFFFFFFFF
        if t == CheckSumType.CRC32:
            return self.checksum == zlib.crc32(data) & 0xFFFFFFFF
        if t == CheckSumType.MD5:
            return self.checksum == md5(data).digest()
        if t == CheckSumType.SHA1:
            return self.checksum == sha1(data).digest()
        if t == CheckSumType.SHA256:
            return self.checksum == sha256(data).digest()
        raise ValueError(F'Unknown checksum type: {t!r}')


@dataclasses.dataclass
class InnoStream:
    header: StreamHeader
    blocks: list[CrcCompressedBlock] = dataclasses.field(default_factory=list)

    @property
    def compression(self):
        return self.header.Compression

    @property
    def name(self):
        return self.header.Name


class InnoStruct(JsonStruct):
    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        if version < (4, 0, 0):
            a, b, c = version
            raise ValueError(F'Unsupported version {a}.{b}.{c}')
        if unicode:
            self._read_string = functools.partial(
                reader.read_length_prefixed_utf16, bytecount=True)
        else:
            self._read_string = reader.read_length_prefixed_ascii


class SetupAllowedArchitectures(str, enum.Enum):
    Unknown = 'Unknown'
    x86 = 'x86'
    x64 = 'x64'
    Arm32 = 'Arm32'
    Arm64 = 'Arm64'


class SetupHeader(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        super().__init__(reader, version, unicode)
        read_string = self._read_string

        self.AppName = read_string()
        self.AppVersionedName = read_string()
        self.AppId = read_string()
        self.AppCopyright = read_string()
        self.AppPublisher = read_string()
        self.AppPublisherUrl = read_string()
        if version >= (5, 1, 13):
            self.AppSupportPhone = read_string()
        self.AppSupportUrl = read_string()
        self.AppUpdatesUrl = read_string()
        self.AppVersion = read_string()
        self.DefaultDirName = read_string()
        self.DefaultGroupName = read_string()
        self.BaseFilename = read_string()
        if version < (5, 2, 5):
            self._license = read_string()
            self.InfoBefore = read_string()
            self.InfoAfter = read_string()
        self.UninstallFilesDir = read_string()
        self.UninstallName = read_string()
        self.UninstallIcon = read_string()
        self.AppMutex = read_string()
        if version >= (3, 0, 0):
            self.DefaultUsername = read_string()
            self.DefaultOrganisation = read_string()
        self.DefaultSerial = read_string()
        if version < (5, 2, 5):
            self.CompiledCode = reader.read_length_prefixed()
        if version >= (4, 2, 4):
            self.AppReadmeFile = read_string()
            self.AppContact = read_string()
            self.AppComment = read_string()
            self.AppModifyPath = read_string()
        if version >= (5, 3, 8):
            self.CreateUninstallRegistryKey = read_string()
        if version >= (5, 3, 10):
            self.Uninstallable = read_string()
        if version >= (5, 5, 0):
            self.CloseApplicationsFilter = read_string()
        if version >= (5, 5, 6):
            self.SetupMutex = read_string()
        if version >= (5, 6, 1):
            self.ChangesEnvironment = read_string()
            self.ChangesAssociations = read_string()
        if version >= (6, 3, 0):
            self.ArchitecturesAllowed32 = SetupAllowedArchitectures(read_string())
            self.ArchitecturesAllowed64 = SetupAllowedArchitectures(read_string())
        if version >= (5, 2, 5):
            self._license = reader.read_length_prefixed_ascii()
            self.InfoBefore = reader.read_length_prefixed_ascii()
            self.InfoAfter = reader.read_length_prefixed_ascii()
        if version >= (5, 2, 1) and version < (5, 3, 10):
            self.UninstallerSignature = reader.read_length_prefixed_ascii()
        if version >= (5, 2, 5):
            self.CompiledCode = reader.read_length_prefixed()
            if self.CompiledCode and self.CompiledCode[:4] != B'IFPS':
                raise ValueError('Invalid signature in compiled code.')
        if not unicode:
            self.Charset = reader.read(256 // 8)

        self.LanguageCount = reader.u32()

        if version >= (4, 2, 1):
            self.MessageCount = reader.u32()

        if version >= (4, 1, 0):
            self.PermissionCount = reader.u32()

        self.TypeCount = reader.u32()
        self.ComponentCount = reader.u32()
        self.TaskCount = reader.u32()
        self.DirectoryCount = reader.u32()
        self.FileCount = reader.u32()
        self.DataEntryCount = reader.u32()
        self.IconCount = reader.u32()
        self.IniEntryCount = reader.u32()
        self.RegistryEntryCount = reader.u32()
        self.DeleteEntryCount = reader.u32()
        self.UninstallDeleteEntryCount = reader.u32()
        self.RunEntryCount = reader.u32()
        self.UninstallRunEntryCount = reader.u32()

        self.MinimumWindowsVersion = WindowsVersion(reader)
        self.MaximumWindowsVersion = WindowsVersion(reader)

        self.BackColor1 = reader.u32()
        self.BackColor2 = reader.u32()
        if version < (5, 5, 7):
            self.ImageBackColor = reader.u32()
        if version < (5, 0, 4):
            self.SmallImageBackColor = reader.u32()
        if version >= (6, 0, 0):
            self.WizardStyle = WizardStyle(reader.u8())
            self.WizardResizePercentX = reader.u32()
            self.WizardResizePercentY = reader.u32()
        else:
            self.WizardStyle = WizardStyle.Classic
            self.WizardResizePercentX = 0
            self.WizardResizePercentY = 0

        if version >= (5, 5, 7):
            self.StoredAlphaFormat = StoredAlphaFormat(reader.u8())
        else:
            self.StoredAlphaFormat = StoredAlphaFormat.AlphaIgnored

        if version >= (6, 4, 0):
            self.PasswordType = PasswordType.XChaCha20
            self.PasswordHash = reader.read(4)
        elif version >= (5, 3, 9):
            self.PasswordType = PasswordType.SHA1
            self.PasswordHash = reader.read(20)
        elif version >= (4, 2, 0):
            self.PasswordType = PasswordType.MD5
            self.PasswordHash = reader.read(16)
        else:
            self.PasswordType = PasswordType.CRC32
            self.PasswordHash = reader.u32()

        if version >= (6, 4, 0):
            self.PasswordSalt = reader.read(44)
        elif version >= (4, 2, 2):
            self.PasswordSalt = reader.read(8)
        else:
            self.PasswordSalt = None

        self.ExtraDiskSpace = reader.i64()
        self.SlicesPerDisk = reader.u32()
        if version < (5, 0, 0):
            self.InstallVerbosity = reader.u8()
        self.UninstallLogMode = UninstallLogMode(reader.u8())
        if version < (5, 0, 0):
            self.SetupStyle = SetupStyle(reader.u8())
        self.DirExistsWarning = AutoBool(reader.u8())
        self.PrivilegesRequired = PrivilegesRequired(reader.u8())
        if version >= (5, 7, 0):
            self.PriilegesRequiredOverrideAllowed = PrivilegesRequiredOverrideAllowed(reader.u8())
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

        if version >= (6, 3, 0):
            self.ArchitecturesAllowed = Architecture.Unknown
            self.ArchitecturesInstalled64 = Architecture.Unknown
        elif version >= (5, 1, 0):
            self.ArchitecturesAllowed = Architecture(reader.u8())
            self.ArchitecturesInstalled64 = Architecture(reader.u8())
        else:
            self.ArchitecturesAllowed = Architecture.All
            self.ArchitecturesInstalled64 = Architecture.All

        if version >= (5, 2, 1) and version < (5, 3, 10):
            self.UninstallerOriginalSize = reader.u32()
            self.UninstallheaderCrc = reader.u32()
        if version >= (5, 3, 3):
            self.DisableDirPage = AutoBool(reader.u8())
            self.DisableProgramGroupPage = AutoBool(reader.u8())
        if version >= (5, 5, 0):
            self.UninstallDisplaySize = reader.u64()
        elif version >= (5, 3, 6):
            self.UninstallDisplaySize = reader.u32()
        flags = []
        flags.append(Flags.DisableStartupPrompt)
        if version < (5, 3, 10):
            flags.append(Flags.Uninstallable)
        flags.append(Flags.CreateAppDir)
        if version < (5, 3, 3):
            flags.append(Flags.DisableDirPage)
            flags.append(Flags.DisableProgramGroupPage)
        flags.append(Flags.AllowNoIcons)
        flags.append(Flags.AlwaysUsePersonalGroup)
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
        if version < (5, 6, 1):
            flags.append(Flags.ChangesAssociations)
        if version < (5, 3, 8):
            flags.append(Flags.CreateUninstallRegKey)
        flags.append(Flags.UsePreviousAppDir)
        flags.append(Flags.BackColorHorizontal)
        flags.append(Flags.UsePreviousGroup)
        flags.append(Flags.UpdateUninstallLogAppName)
        flags.append(Flags.UsePreviousSetupType)
        flags.append(Flags.DisableReadyMemo)
        flags.append(Flags.AlwaysShowComponentsList)
        flags.append(Flags.FlatComponentsList)
        flags.append(Flags.ShowComponentSizes)
        flags.append(Flags.UsePreviousTasks)
        flags.append(Flags.DisableReadyPage)
        flags.append(Flags.AlwaysShowDirOnReadyPage)
        flags.append(Flags.AlwaysShowGroupOnReadyPage)
        if version < (4, 1, 5):
            flags.append(Flags.BzipUsed)
        flags.append(Flags.AllowUNCPath)
        flags.append(Flags.UserInfoPage)
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
        if version >= (4, 2, 2):
            flags.append(Flags.EncryptionUsed)
        if version >= (5, 0, 4) and version < (5, 6, 1):
            flags.append(Flags.ChangesEnvironment)
        if version >= (5, 1, 7) and not unicode:
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

        flagsize, _r = divmod(len(flags), 8)
        flagsize += int(bool(_r))
        bytecheck = reader.peek(flagsize + 1 + 4 + 1)

        if bytecheck[0] == 0:
            if bytecheck[~0] != 0 or bytecheck[~3:~0] == B'\0\0\0':
                reader.u8()

        self.Flags = Flags.Empty

        for flag in flags:
            if reader.read_bit():
                self.Flags |= flag

        if version < (4, 1, 5):
            if self.Flags & Flags.BzipUsed:
                self.CompressionMethod = CompressionMethod.Bzip2
            else:
                self.CompressionMethod = CompressionMethod.ZLib

        reader.byte_align()

    def get_license(self):
        return self._license

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
                old: str = getattr(self, coded_string_attribute)
            except AttributeError:
                continue
            else:
                new = old.encode('latin1').decode(codec)
                setattr(self, coded_string_attribute, new)


class Version(JsonStruct):
    def __init__(self, reader: StructReader[memoryview]):
        self.Build = reader.u16()
        self.Minor = reader.u8()
        self.Major = reader.u8()


class WindowsVersion(JsonStruct):
    def __init__(self, reader: StructReader[memoryview]):
        self.WindowsVersion = Version(reader)
        self.NtVersion = Version(reader)
        self.ServicePackMinor = reader.u8()
        self.ServicePackMajor = reader.u8()


class LanguageId(JsonStruct):
    def __init__(self, reader: StructReader[memoryview]):
        self.Value = reader.u32()
        self.Name = LCID.get(self.Value, None)


class SetupLanguage(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        super().__init__(reader, version, unicode)
        read_string = self._read_string

        self.Name = read_string()
        LanguageName = reader.read_length_prefixed()

        self.DialogFont = read_string()
        self.TitleFont = read_string()
        self.WelcomeFont = read_string()
        self.CopyrightFont = read_string()
        self.Data = reader.read_length_prefixed()

        if version >= (4, 0, 1):
            self.LicenseText = reader.read_length_prefixed_ascii()
            self.InfoBefore = reader.read_length_prefixed_ascii()
            self.InfoAfter = reader.read_length_prefixed_ascii()

        self.LanguageId = LanguageId(reader)

        if version < (4, 2, 2):
            self.Codepage = DEFAULT_CODEPAGE.get(self.LanguageId.Value, 'cp1252')
        elif not unicode:
            cp = reader.u32() or 1252
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

        self.TitleFontSize = reader.u32()
        self.WelcomeFontSize = reader.u32()
        self.CopyrightFontSize = reader.u32()

        if version >= (5, 2, 3):
            self.RightToLeft = reader.u8()


class SetupMessage(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        super().__init__(reader, version, unicode)
        read_string = self._read_string
        self.EncodedName = read_string()
        self.Value = read_string()
        self.LanguageId = LanguageId(reader)


class SetupType(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        super().__init__(reader, version, unicode)
        read_string = self._read_string
        self.Name = read_string()
        self.Description = read_string()
        if version >= (4, 0, 1):
            self.Languages = read_string()
        self.Check = read_string()
        self.MinimumWindowsVersion = WindowsVersion(reader)
        self.MaximumWindowsVersion = WindowsVersion(reader)
        self.TypeCode = reader.u8()
        if version >= (4, 0, 1):
            self.SetupType = SetupTypeEnum(reader.u8())
        self.Size = reader.u64()


class SetupComponent(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        super().__init__(reader, version, unicode)
        read_string = self._read_string
        self.Name = read_string()
        self.Description = read_string()
        self.Types = read_string()
        if version >= (4, 0, 1):
            self.Languages = read_string()
        self.Check = read_string()
        self.ExtraDiskSpace = reader.u64()
        self.Level = reader.u32()
        self.Used = reader.u8()
        self.MinimumWindowsVersion = WindowsVersion(reader)
        self.MaximumWindowsVersion = WindowsVersion(reader)
        if version >= (4, 2, 3):
            self.Flags = SetupFlags(reader.u8())
        self.Size = reader.u64()


class SetupTaskFlags(enum.IntFlag):
    Empty            = 0           # noqa
    Exclusive        = enum.auto() # noqa
    Unchecked        = enum.auto() # noqa
    Restart          = enum.auto() # noqa
    CheckedOne       = enum.auto() # noqa
    DontInheritCheck = enum.auto() # noqa


class SetupTask(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        super().__init__(reader, version, unicode)
        read_string = self._read_string

        self.Name = read_string()
        self.Description = read_string()
        self.GroupDescription = read_string()
        self.Components = read_string()
        if version >= (4, 0, 1):
            self.Languages = read_string()
        self.Check = read_string()
        self.Level = reader.u32()
        self.Used = reader.u8()
        self.MinimumWindowsVersion = WindowsVersion(reader)
        self.MaximumWindowsVersion = WindowsVersion(reader)

        self.Flags = SetupTaskFlags.Empty

        def flagbit(f):
            self.Flags |= f if reader.read_bit() else 0

        flagbit(SetupTaskFlags.Exclusive)
        flagbit(SetupTaskFlags.Unchecked)
        flagbit(SetupTaskFlags.Restart)
        flagbit(SetupTaskFlags.CheckedOne)

        if version >= (4, 2, 3):
            flagbit(SetupTaskFlags.DontInheritCheck)

        reader.byte_align()


class SetupCondition(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        super().__init__(reader, version, unicode)
        read_string = self._read_string

        self.Components = read_string()
        self.Tasks = read_string()
        if version >= (4, 0, 1):
            self.Languages = read_string()
        self.Check = read_string()
        if version >= (4, 1, 0):
            self.AfterInstall = read_string()
            self.BeforeInstall = read_string()


class SetupDirectoryFlags(enum.IntFlag):
    Empty                = 0           # noqa
    NeverUninstall       = enum.auto() # noqa
    DeleteAfterInstall   = enum.auto() # noqa
    AlwaysUninstall      = enum.auto() # noqa
    SetNtfsCompression   = enum.auto() # noqa
    UnsetNtfsCompression = enum.auto() # noqa


class SetupDirectory(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        super().__init__(reader, version, unicode)
        read_string = self._read_string

        self.Name = read_string()
        self.Condition = SetupCondition(reader, version, unicode)
        if version >= (4, 0, 11) and version < (4, 1, 0):
            self.Permissions = read_string()
        self.Attributes = reader.u32()
        self.MinimumWindowsVersion = WindowsVersion(reader)
        self.MaximumWindowsVersion = WindowsVersion(reader)
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

    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        super().__init__(reader, version, unicode)
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


class SetupFileType(enum.IntEnum):
    UserFile = 0
    UninstExe = 1
    RegSvrExe = 2


class SetupFile(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        super().__init__(reader, version, unicode)
        read_string = self._read_string

        self.Source = read_string()
        self.Destination = read_string()
        self.InstallFontName = read_string()
        if version >= (5, 2, 5):
            self.StrongAssemblyName = read_string()
        self.Condition = SetupCondition(reader, version, unicode)
        self.MinimumWindowsVersion = WindowsVersion(reader)
        self.MaximumWindowsVersion = WindowsVersion(reader)
        self.Location = reader.u32()
        self.Attributes = reader.u32()
        self.ExternalSize = reader.u64()
        if version >= (4, 1, 0):
            self.Permissions = reader.u16()

        self.Flags = SetupFileFlags.Empty

        def flagbit(f):
            self.Flags |= f if reader.read_bit() else 0

        flagbit(SetupFileFlags.ConfirmOverwrite)
        flagbit(SetupFileFlags.NeverUninstall)
        flagbit(SetupFileFlags.RestartReplace)
        flagbit(SetupFileFlags.DeleteAfterInstall)
        flagbit(SetupFileFlags.RegisterServer)
        flagbit(SetupFileFlags.RegisterTypeLib)
        flagbit(SetupFileFlags.SharedFile)
        flagbit(SetupFileFlags.CompareTimeStamp)
        flagbit(SetupFileFlags.FontIsNotTrueType)
        flagbit(SetupFileFlags.SkipIfSourceDoesntExist)
        flagbit(SetupFileFlags.OverwriteReadOnly)
        flagbit(SetupFileFlags.OverwriteSameVersion)
        flagbit(SetupFileFlags.CustomDestName)
        flagbit(SetupFileFlags.OnlyIfDestFileExists)
        flagbit(SetupFileFlags.NoRegError)
        flagbit(SetupFileFlags.UninsRestartDelete)
        flagbit(SetupFileFlags.OnlyIfDoesntExist)
        flagbit(SetupFileFlags.IgnoreVersion)
        flagbit(SetupFileFlags.PromptIfOlder)
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
        if version >= (5, 1, 2):
            flagbit(SetupFileFlags.Bits32)
            flagbit(SetupFileFlags.Bits64)
        if version >= (5, 2, 0):
            flagbit(SetupFileFlags.ExternalSizePreset)
            flagbit(SetupFileFlags.SetNtfsCompression)
            flagbit(SetupFileFlags.UnsetNtfsCompression)
        if version >= (5, 2, 5):
            flagbit(SetupFileFlags.GacInstall)

        reader.byte_align()
        self.Type = SetupFileType(reader.u8())


class TSetup(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        super().__init__(reader, version, unicode)
        self.Header = h = SetupHeader(reader, version, unicode)

        def _array(count: int, parser: Type[_T]) -> List[_T]:
            return [parser(reader, version, unicode) for _ in range(count)]

        self.Languages = _array(h.LanguageCount, SetupLanguage)

        if not unicode:
            h.recode_strings(self.Languages[0].Codepage)

        # if version < INNO_VERSION(4, 0, 0):
        #  load_wizard_and_decompressor

        self.Messages    = _array(h.MessageCount,    SetupMessage)     # noqa
        self.Permissions = _array(h.PermissionCount, SetupPermission)  # noqa
        self.Types       = _array(h.TypeCount,       SetupType)        # noqa
        self.Components  = _array(h.ComponentCount,  SetupComponent)   # noqa
        self.Tasks       = _array(h.TaskCount,       SetupTask)        # noqa
        self.Directories = _array(h.DirectoryCount,  SetupDirectory)   # noqa
        self.Files       = _array(h.FileCount,       SetupFile)        # noqa

        # self.Icons                  = _array(h.IconCount,                 SetupIcon)
        # self.IniEntries             = _array(h.IniEntryCount,             SetupIniEntry)
        # self.RegistryEntries        = _array(h.RegistryEntryCount,        SetupRegistryEntry)
        # self.DeleteEntries          = _array(h.DeleteEntryCount,          SetupDeleteEntry)
        # self.UninstallDeleteEntries = _array(h.UninstallDeleteEntryCount, SetupUninstallDeleteEntry)
        # self.RunEntries             = _array(h.RunEntryCount,             SetupRunEntry)
        # self.UninstallRunEntries    = _array(h.UninstallRunEntryCount,    SetupUninstallRunEntry)

        # if version >= INNO_VERSION(4, 0, 0):
        #  load_wizard_and_decompressor


class SetupDataEntryFlags(enum.IntFlag):
    Empty                    = 0           # noqa    
    VersionInfoValid         = enum.auto() # noqa
    VersionInfoNotValid      = enum.auto() # noqa
    BZipped                  = enum.auto() # noqa
    TimeStampInUTC           = enum.auto() # noqa
    IsUninstallerExe         = enum.auto() # noqa
    CallInstructionOptimized = enum.auto() # noqa
    Touch                    = enum.auto() # noqa
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

    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        super().__init__(reader, version, unicode)
        self.FirstSlice = reader.u32()
        self.LastSlice = reader.u32()
        self.ChunkOffset = reader.u32()
        if version >= (4, 0, 1):
            self.Offset = reader.u64()
        self.FileSize = reader.u64()
        self.ChunkSize = reader.u64()

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
            self.Checksum = reader.u32()
        else:
            self.ChecksumType = CheckSumType.Adler32
            self.Checksum = reader.u32()

        ft = reader.u64()
        ts = datetime.fromtimestamp(
            (ft - _FILE_TIME_1970_01_01) / 10000000, timezone.utc)
        self.FileTime = ts

        self.FileVersionMs = reader.u32()
        self.FileVersionLs = reader.u32()

        self.Flags = 0

        def flagbit(f):
            self.Flags |= f if reader.read_bit() else 0

        flagbit(SetupDataEntryFlags.VersionInfoNotValid)
        flagbit(SetupDataEntryFlags.VersionInfoValid)

        if version < (4, 0, 1):
            flagbit(SetupDataEntryFlags.BZipped)
        if version >= (4, 0, 10):
            flagbit(SetupDataEntryFlags.TimeStampInUTC)
        if version >= (4, 1, 0):
            flagbit(SetupDataEntryFlags.IsUninstallerExe)
        if version >= (4, 1, 8):
            flagbit(SetupDataEntryFlags.CallInstructionOptimized)
        if version >= (4, 2, 0):
            flagbit(SetupDataEntryFlags.Touch)
        if version >= (4, 2, 2):
            flagbit(SetupDataEntryFlags.ChunkEncrypted)
        if version >= (4, 2, 5):
            flagbit(SetupDataEntryFlags.ChunkCompressed)
        if version >= (5, 1, 13):
            flagbit(SetupDataEntryFlags.SolidBreak)
        if version >= (5, 5, 7) and version < (6, 3, 0):
            flagbit(SetupDataEntryFlags.Sign)
            flagbit(SetupDataEntryFlags.SignOnce)

        reader.byte_align()

        if version >= (6, 3, 0):
            self.SignMode = SetupSignMode(reader.u8())
        elif self.Flags & SetupDataEntryFlags.SignOnce:
            self.SignMode = SetupSignMode.Once
        elif self.Flags & SetupDataEntryFlags.Sign:
            self.SignMode = SetupSignMode.Yes
        else:
            self.SignMode = SetupSignMode.NoSetting


class TData(InnoStruct):

    def __init__(self, reader: StructReader[memoryview], version: tuple[int, int, int], unicode: bool):
        super().__init__(reader, version, unicode)
        self.entries: list[SetupDataEntry] = []
        while not reader.eof:
            self.entries.append(SetupDataEntry(reader, version, unicode))


class xtinno(ArchiveUnit):
    """
    Extract files from InnoSetup archives.
    """

    _STREAM_NAMES = 'meta/TSetup', 'meta/TData', 'meta/Uninstaller'
    _ISCRIPT_NAME = 'meta/script'
    _LICENSE_NAME = 'meta/license.rtf'
    _OFFSETS_PATH = 'RCDATA/11111/0'
    _CHUNK_PREFIX = b'zlb\x1a'
    _MAX_ATTEMPTS = 1_000_000

    def unpack(self, data: bytearray):
        try:
            file_metadata = one(data | perc(self._OFFSETS_PATH))
        except Exception as E:
            raise ValueError(F'Could not find TSetupOffsets PE resource at {self._OFFSETS_PATH}') from E

        meta = TSetupOffsets(file_metadata)
        view = memoryview(data)
        base = meta.base
        inno = StructReader(view[base:base + meta.total_size])

        self._decompressed = {}
        streams: List[InnoStream] = []
        password = self.args.pwd or None

        files_len = meta.setup0 - meta.setup1
        inno.seek(meta.setup1)
        files_reader = StructReader(inno.read(files_len))

        header = bytes(inno.read(64))
        _magic = re.match(
            RB'^(.*?)\((\d+\.\d+\.\d+)\)(?:\s{0,32}\((u)\))?',
            header)
        if _magic is None:
            name, _, _rest = header.partition(b'\0')
            if any(_rest):
                name = header.hex()
            error = F'unable to parse header identifier "{name}"'
            if self.leniency < 1:
                raise ValueError(error)
            version = _DEFAULT_INNO_VERSION
            unicode = True
            _dotted = '.'.join(str(v) for v in version)
            self.log_warn(F'{error}; attempting to parse as v{_dotted}u')
        else:
            version = tuple(map(int, _magic.group(2).split(B'.')))
            unicode = bool(_magic.group(3))

        for name in self._STREAM_NAMES:
            stream = InnoStream(StreamHeader(inno, name, version))
            streams.append(stream)
            to_read = stream.header.StoredSize
            while to_read > 4:
                block = CrcCompressedBlock(inno, min(to_read - 4, 0x1000))
                stream.blocks.append(block)
                to_read -= len(block)

        encrypted_file = None
        files: list[InnoFile] = []

        yield self._pack(
            streams[2].name, None, lambda s=streams[2]: self.read_stream(s))

        self.log_debug('parsing stream 1 (TData)')
        stream1 = self.read_stream(streams[1])
        yield self._pack(streams[1].name, None, stream1)
        stream1 = TData(memoryview(stream1), version, unicode)
        with BytesAsStringEncoder as encoder:
            yield self._pack(F'{streams[1].name}.json', None,
                encoder.dumps(stream1.json()).encode(self.codec))

        for file_metadata in stream1.entries:
            file = InnoFile(files_reader, version, unicode, file_metadata)
            files.append(file)
            if password or not file.encrypted or not file.size:
                continue
            if encrypted_file is None or file.size < encrypted_file.size:
                encrypted_file = file

        self.log_debug('parsing stream 0 (TSetup)')
        stream0 = self.read_stream(streams[0])
        yield self._pack(streams[0].name, None, stream0)
        stream0 = TSetup(memoryview(stream0), version, unicode)
        with BytesAsStringEncoder as encoder:
            yield self._pack(F'{streams[0].name}.json', None,
                encoder.dumps(stream0.json()).encode(self.codec))
            yield self._pack(self._LICENSE_NAME, None,
                stream0.Header.get_license().encode(self.codec))

        path_dedup: dict[str, list[SetupFile]] = {}

        for sf in stream0.Files:
            sf: SetupFile
            location = sf.Location
            if location == 0xFFFFFFFF or sf.Type != SetupFileType.UserFile or sf.Source:
                msg = F'skipping file: offset=0x{location:08X} type={sf.Type.name}'
                if sf.Source:
                    msg = F'{msg} src={sf.Source}'
                self.log_debug(msg)
                continue
            if location >= len(files):
                self.log_warn(F'parsed {len(file)} entries, ignoring invalid setup reference to entry {location + 1}')
                continue
            path = sf.Destination.replace('\\', '/')
            if condition := sf.Condition.Check:
                condition = condition.replace(' ', '-')
                path = F'{condition}/{path}'
            path = F'data/{path}'
            path_dedup.setdefault(path, []).append(sf)
            files[location].tags = sf.Flags
            files[location].path = path

        for path, infos in path_dedup.items():
            if len(infos) == 1:
                files[infos[0].Location].path = path
                continue
            bycheck = {}
            for info in infos:
                file = files[info.Location]
                if not file.checksum_type.strong():
                    bycheck.clear()
                    break
                dkey = (file.checksum, file.size)
                if dkey in bycheck:
                    self.log_debug(F'skipping exact duplicate: {path}')
                    file.dupe = True
                    continue
                bycheck[dkey] = info
            if bycheck:
                if len(bycheck) == 1:
                    file.path = path
                    continue
                infos = list(bycheck.values())
            for k, info in enumerate(infos):
                files[info.Location].path = F'{path}[{k}]'

        codec = stream0.Languages[0].Codepage
        if unicode:
            codec = 'latin1'
        a, b, c, d = *version, ("u" if unicode else "a")
        self.log_info(
            F'inno v{a}.{b}.{c:02d}{d} '
            F'compression:{stream0.Header.CompressionMethod.name} '
            F'codepage:{codec} '
            F'password:{stream0.Header.PasswordType.name} '
        )

        for file in files:
            file.compression_method = stream0.Header.CompressionMethod
            file.password_hash = stream0.Header.PasswordHash
            file.password_type = stream0.Header.PasswordType
            file.password_salt = stream0.Header.PasswordSalt

        if stream0.Header.CompiledCode:
            from refinery.units.formats.ifps import ifps
            script = stream0.Header.CompiledCode
            yield self._pack(F'{self._ISCRIPT_NAME}.ps', None, script | ifps(codec) | bytes)
            yield self._pack(F'{self._ISCRIPT_NAME}.bin', None, script)

        if encrypted_file is not None:
            assert password is None, (
                F'An encrypted test file was chosen even though a password was provided: {password!r}')
            self.log_info(F'guessing password using encrypted file: {encrypted_file.path}')
            try:
                def _pwd(s: str):
                    if not s:
                        return False
                    if re.search(r'\{\w+\}', s):
                        return False
                    if re.search(R'^\w{2,12}://', s):
                        return False
                    return True
                from refinery.units.formats.ifpsstr import ifpsstr
                from itertools import combinations
                strings = script | ifpsstr(codec) | {str}
                strings = [s for s in strings if _pwd(s)]
                total = 0
                for k in range(1, 10):
                    for parts in combinations(strings, k):
                        if total > self._MAX_ATTEMPTS:
                            break
                        total += 1
                        string = ''.join(parts)
                        try:
                            plaintext = self._read_file(encrypted_file, password=string)
                            if not encrypted_file.check(plaintext):
                                continue
                            password = string
                            break
                        except Exception:
                            continue
                    if total > self._MAX_ATTEMPTS:
                        break
            except Exception as e:
                self.log_info(F'failed to extract strings from IFPS: {exception_to_string(e)}')

        for file in files:
            if file.dupe:
                continue
            yield self._pack(
                file.path,
                file.date,
                lambda f=file: self._read_file(f, password=password),
                tags=[t.name for t in SetupFileFlags if t & file.tags],
            )

    def read_stream(self, stream: InnoStream):
        result = bytearray()
        it = iter(stream.blocks)
        if stream.compression == StreamCompressionMethod.Store:
            class _dummy(self):
                def decompress(self, b):
                    return b
            dec = _dummy()
        elif stream.compression == StreamCompressionMethod.LZMA1:
            import lzma
            first = next(it).BlockData
            prop, first = first[:5], first[5:]
            filter = lzma._decode_filter_properties(lzma.FILTER_LZMA1, prop)
            dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[filter])
            result.extend(dec.decompress(first))
        elif stream.compression == StreamCompressionMethod.ZLib:
            import zlib
            dec = zlib.decompressobj()
        for block in it:
            result.extend(dec.decompress(block.BlockData))
        return result

    def _read_chunk(self, file: InnoFile, password: Optional[str] = None):
        reader = file.reader
        offset = file.chunk_offset
        length = file.chunk_length
        method = file.compression

        if offset + length > len(reader):
            span = F'0x{offset:X}-0x{offset + length:X}'
            raise LookupError(
                F'File data spans 0x{len(file.reader):X} bytes, but the file {file.path} is located at {span}.')

        reader.seek(offset)
        prefix = reader.read(4)

        if prefix != self._CHUNK_PREFIX:
            raise ValueError(F'Error reading chunk at offset 0x{offset:X}; invalid magic {prefix.hex()}.')

        if file.encrypted:
            if file.password_type == PasswordType.Nothing:
                raise RuntimeError(F'File {file.path} is encrypted, but no password type was set.')
            if password is None:
                raise InvalidPassword
            if file.password_type == PasswordType.XChaCha20:
                salt, iterations, nonce = struct.unpack('=16sI24s', file.password_salt)
                key = password.encode('utf8') | pbkdf2(32, salt, iterations, 'SHA256') | bytes
                test_nonce = list(struct.unpack('6I', nonce))
                test_nonce[2] = ~test_nonce[2]
                test_nonce = struct.pack('6I', test_nonce)
                if B'\0\0\0\0' | xchacha(key, nonce=test_nonce) | bytes != file.password_hash:
                    raise InvalidPassword(password)
                decryptor = xchacha(key, nonce=nonce)
            else:
                password_bytes = password.encode(
                    'utf-16le' if file.unicode else 'utf8')
                algorithm = {
                    PasswordType.SHA1: sha1,
                    PasswordType.MD5 : md5,
                }[file.password_type]
                hash = algorithm(b'PasswordCheckHash' + file.password_salt)
                hash.update(password_bytes)
                if hash.digest() != file.password_hash:
                    raise InvalidPassword(password)
                hash = algorithm(reader.read(8))
                hash.update(password_bytes)
                decryptor = rc4(hash.digest(), discard=1000)

        data = reader.read_exactly(length)

        if file.encrypted:
            data = data | decryptor | bytearray

        try:
            if method == CompressionMethod.Store:
                chunk = data
            elif method == CompressionMethod.Lzma1:
                props = lzma._decode_filter_properties(lzma.FILTER_LZMA1, data[0:5])
                dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[props])
                chunk = dec.decompress(data[5:])
            elif method == CompressionMethod.Lzma2:
                props = lzma._decode_filter_properties(lzma.FILTER_LZMA2, data[0:1])
                dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[props])
                chunk = dec.decompress(data[1:])
            elif method == CompressionMethod.Bzip2:
                chunk = bz2.decompress(data)
            elif method == CompressionMethod.ZLib:
                chunk = zlib.decompress(data)
        except Exception as E:
            if not file.encrypted:
                raise
            raise InvalidPassword(password) from E

        return chunk

    def _read_file(
        self,
        file: InnoFile,
        password: Optional[str] = None,
    ):
        offset = file.chunk_offset
        length = file.chunk_length

        try:
            chunk = self._decompressed[offset, length]
        except KeyError:
            chunk = self._decompressed[offset, length] = self._read_chunk(file, password)

        view = memoryview(chunk)
        data = view[file.offset:file.offset + file.size]

        if file.filtered:
            if file.version >= (5, 2, 0):
                flip = (file.version >= (5, 3, 9))
                data = self._filter_new(data, flip_high_byte=flip)
            else:
                data = self._filter_old(data)

        if not self.leniency and not file.check(data):
            raise ValueError('Invalid checksum. You can ignore this check with the -L flag.')

        return data

    @ArchiveUnit.Requires('numpy', 'speed', 'default', 'extended')
    def _numpy():
        import numpy
        return numpy

    def _filter_new(self, data: ByteStr, flip_high_byte=False):
        try:
            np = self._numpy
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
                top = mem[a + 4]
                if top != 0x00 and top != 0xFF:
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
        addresses = low.tobytes()
        for k, offset in enumerate(positions):
            out[offset - 4:offset] = addresses[k * 4:(k + 1) * 4]
        return out

    def _filter_new_fallback(self, data: ByteStr, flip_high_byte=False):
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
    def _filter_old(data: ByteStr):
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

    @classmethod
    def handles(self, data):
        if data[:2] != B'MZ':
            return False
        if re.search(re.escape(self._CHUNK_PREFIX), data) is None:
            return False
        return bool(
            re.search(BR'Inno Setup Setup Data \(\d+\.\d+\.', data))
