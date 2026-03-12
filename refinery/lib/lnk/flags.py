from __future__ import annotations

import enum

from refinery.lib.structures import FlagAccessMixin


class LinkFlags(FlagAccessMixin, enum.IntFlag):
    HasTargetIDList = 0x00000001
    HasLinkInfo = 0x00000002
    HasName = 0x00000004
    HasRelativePath = 0x00000008
    HasWorkingDir = 0x00000010
    HasArguments = 0x00000020
    HasIconLocation = 0x00000040
    IsUnicode = 0x00000080
    ForceNoLinkInfo = 0x00000100
    HasExpString = 0x00000200
    RunInSeparateProcess = 0x00000400
    Unused1 = 0x00000800
    HasDarwinID = 0x00001000
    RunAsUser = 0x00002000
    HasExpIcon = 0x00004000
    NoPidlAlias = 0x00008000
    Unused2 = 0x00010000
    RunWithShimLayer = 0x00020000
    ForceNoLinkTrack = 0x00040000
    EnableTargetMetadata = 0x00080000
    DisableLinkPathTracking = 0x00100000
    DisableKnownFolderTracking = 0x00200000
    DisableKnownFolderAlias = 0x00400000
    AllowLinkToLink = 0x00800000
    UnaliasOnSave = 0x01000000
    PreferEnvironmentPath = 0x02000000
    KeepLocalIDListForUNCTarget = 0x04000000


class FileAttributeFlags(FlagAccessMixin, enum.IntFlag):
    ReadOnly = 0x0001
    Hidden = 0x0002
    System = 0x0004
    Reserved1 = 0x0008
    Directory = 0x0010
    Archive = 0x0020
    Reserved2 = 0x0040
    Normal = 0x0080
    Temporary = 0x0100
    SparseFile = 0x0200
    ReparsePoint = 0x0400
    Compressed = 0x0800
    Offline = 0x1000
    NotContentIndexed = 0x2000
    Encrypted = 0x4000


class ShowCommand(enum.IntEnum):
    Normal = 0x01
    Maximized = 0x03
    MinimizedNoActive = 0x07


class DriveType(enum.IntEnum):
    Unknown = 0
    NoRootDir = 1
    Removable = 2
    Fixed = 3
    Remote = 4
    CdRom = 5
    RamDisk = 6


class LinkInfoFlags(FlagAccessMixin, enum.IntFlag):
    VolumeIDAndLocalBasePath = 0x01
    CommonNetworkRelativeLinkAndPathSuffix = 0x02


class CommonNetworkRelativeLinkFlags(FlagAccessMixin, enum.IntFlag):
    ValidDevice = 0x01
    ValidNetType = 0x02


class NetworkProviderType(enum.IntEnum):
    WNNC_NET_AVID = 0x001A0000
    WNNC_NET_DOCUSPACE = 0x001B0000
    WNNC_NET_MANAGEPC = 0x001C0000
    WNNC_NET_NET6 = 0x001D0000
    WNNC_NET_ADASTA = 0x001E0000
    WNNC_NET_RELATIVITY = 0x001F0000
    WNNC_NET_CLEARCASE = 0x00210000
    WNNC_NET_FRONTIER = 0x00220000
    WNNC_NET_BMC = 0x00230000
    WNNC_NET_DCE = 0x00240000
    WNNC_NET_DECORB = 0x00260000
    WNNC_NET_PROTSTOR = 0x00270000
    WNNC_NET_FJ_REDIR = 0x00280000
    WNNC_NET_DISTINCT = 0x00290000
    WNNC_NET_TWINS = 0x002A0000
    WNNC_NET_RDR2SAMPLE = 0x002B0000
    WNNC_NET_CSC = 0x002C0000
    WNNC_NET_3IN1 = 0x002D0000
    WNNC_NET_EXTENDNET = 0x002F0000
    WNNC_NET_STAC = 0x00300000
    WNNC_NET_FOXBAT = 0x00320000
    WNNC_NET_YAHOO = 0x00330000
    WNNC_NET_EXIFS = 0x00340000
    WNNC_NET_DAV = 0x00360000
    WNNC_NET_KNOWARE = 0x00370000
    WNNC_NET_OBJECT_DIRE = 0x00380000
    WNNC_NET_MASFAX = 0x00390000
    WNNC_NET_HOB_NFS = 0x003A0000
    WNNC_NET_SHIVA = 0x003B0000
    WNNC_NET_IBMAL = 0x003C0000
    WNNC_NET_LOCK = 0x003D0000
    WNNC_NET_TERMSRV = 0x003E0000
    WNNC_NET_SRT = 0x003F0000
    WNNC_NET_QUINCY = 0x00400000
    WNNC_NET_OPENAFS = 0x00410000
    WNNC_NET_AVID1 = 0x00420000
    WNNC_NET_DFS = 0x00430000
    WNNC_NET_KWNP = 0x00440000
    WNNC_NET_ZENWORKS = 0x00450000
    WNNC_NET_DRIVEONWEB = 0x00460000
    WNNC_NET_VMWARE = 0x00470000
    WNNC_NET_RSFX = 0x00480000
    WNNC_NET_MFILES = 0x00490000
    WNNC_NET_MS_NFS = 0x004A0000
    WNNC_NET_GOOGLE = 0x004B0000


class HotKeyLow(enum.IntEnum):
    Unset = 0x00
    Num0 = 0x30
    Num1 = 0x31
    Num2 = 0x32
    Num3 = 0x33
    Num4 = 0x34
    Num5 = 0x35
    Num6 = 0x36
    Num7 = 0x37
    Num8 = 0x38
    Num9 = 0x39
    KeyA = 0x41
    KeyB = 0x42
    KeyC = 0x43
    KeyD = 0x44
    KeyE = 0x45
    KeyF = 0x46
    KeyG = 0x47
    KeyH = 0x48
    KeyI = 0x49
    KeyJ = 0x4A
    KeyK = 0x4B
    KeyL = 0x4C
    KeyM = 0x4D
    KeyN = 0x4E
    KeyO = 0x4F
    KeyP = 0x50
    KeyQ = 0x51
    KeyR = 0x52
    KeyS = 0x53
    KeyT = 0x54
    KeyU = 0x55
    KeyV = 0x56
    KeyW = 0x57
    KeyX = 0x58
    KeyY = 0x59
    KeyZ = 0x5A
    F01 = 0x70
    F02 = 0x71
    F03 = 0x72
    F04 = 0x73
    F05 = 0x74
    F06 = 0x75
    F07 = 0x76
    F08 = 0x77
    F09 = 0x78
    F10 = 0x79
    F11 = 0x7A
    F12 = 0x7B
    F13 = 0x7C
    F14 = 0x7D
    F15 = 0x7E
    F16 = 0x7F
    F17 = 0x80
    F18 = 0x81
    F19 = 0x82
    F20 = 0x83
    F21 = 0x84
    F22 = 0x85
    F23 = 0x86
    F24 = 0x87
    NumLock = 0x90
    Scroll = 0x91


class HotKeyHigh(FlagAccessMixin, enum.IntFlag):
    Shift = 0x01
    Control = 0x02
    Alt = 0x04
