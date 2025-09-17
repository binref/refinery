# flake8: noqa
"""
Contains a library of known external function symbols for the IFPS runtime in InnoSetup installers.
"""
from __future__ import annotations

import inspect
import re

from typing import NamedTuple

from refinery.lib.inno import CaseInsensitiveDict


class IFPSParam(NamedTuple):
    name: str
    type: str | None
    const: bool


class IFPSSignature(NamedTuple):
    name: str
    kind: str
    parameters: tuple[IFPSParam]
    return_type: str | None
    void: bool
    readable: bool | None = None
    writable: bool | None = None

    def is_property(self):
        return self.kind == 'property'

    @property
    def argc(self):
        return len(self.parameters)


class IFPSClass(NamedTuple):
    name: str
    members: dict[str, IFPSSignature]


class IFPSClassReference(NamedTuple):
    Types: dict[str, str]
    Classes: dict[str, IFPSClass]



class ParsingError(RuntimeError):
    def __init__(self, symbol: str, what: str):
        super().__init__(F'{what}: {symbol}')


def parse_decl(decl: str, kind: str, void: bool | None = None, **kwargs):
    def try_type(type: str):
        if not type:
            return None
        type = type.strip().split()
        if not type:
            return None
        elif len(type) == 1:
            return type[0]
        elif type[0] == 'array':
            return 'TArray'
        elif len(t := set(type)) == 1:
            t = next(iter(t))
            return F'TStaticArray[{t}]'
        else:
            return F'TRecord[{",".join(type)}]'

    bo, bc = '[]' if kind == 'property' else '()'
    parts = re.fullmatch(r'''(?x)
                  (?P<name>\w+)
            (?:{o}(?P<args>.*?){c})?
            (?::\s(?P<type>[\w\s]+))?;?
    '''.format(o=re.escape(bo), c=re.escape(bc)), decl.strip())

    if void is None:
        void = kind == 'procedure'

    if parts is None:
        raise ParsingError(decl, 'Failed to parse')

    parts = parts.groupdict()
    name = parts['name']
    type = parts['type']
    type = try_type(type)
    args = []

    if a := parts['args']:
        for group in a.split(';'):
            group, _, at = group.strip().partition(': ')
            kind, _, tmp = group.strip().partition(' ')
            if kind in {'var', 'const'}:
                group = tmp
            for part in group.split(','):
                args.append(IFPSParam(part.strip(), try_type(at), kind != 'var'))

    return IFPSSignature(name, kind, tuple(args), type, void, **kwargs)


def parse_function(symbol: str) -> IFPSSignature:
    kind, _, decl = symbol.strip().partition(' ')
    sig = parse_decl(decl, kind)
    if (sig.return_type is None) != sig.void:
        raise ParsingError(symbol,
            F'Voidness ({sig.void}) of {kind} conflicts with return type {sig.return_type}')
    return sig


def _parse_api_functions(cls):
    sym: dict[str, IFPSSignature] = CaseInsensitiveDict()
    for line in inspect.cleandoc(inspect.getdoc(cls)).splitlines(False):
        if not line.strip():
            continue
        sig = parse_function(line)
        sym[sig.name] = sig
    return sym


@_parse_api_functions
class IFPSAPI:
    """
    procedure Inc(var P: Pointer);
    procedure Dec(var P: Pointer);
    function SizeOf(var P: Variant): Integer;

    property WizardForm:  TWizardForm;
    property UninstallProgressForm:  TUninstallProgressForm;
    function GetCmdTail: String;
    function ParamCount: Integer;
    function ParamStr(Index: Integer): String;
    function ActiveLanguage: String;
    function CustomMessage(const MsgName: String): String;
    function FmtMessage(const S: String; const Args: array of String): String;
    function SetupMessage(const ID: TSetupMessageID): String;
    function WizardDirValue: String;
    function WizardGroupValue: String;
    function WizardNoIcons: Boolean;
    function WizardSetupType(const Description: Boolean): String;
    function WizardSelectedComponents(const Descriptions: Boolean): String;
    function WizardIsComponentSelected(const Components: String): Boolean;
    function WizardSelectedTasks(const Descriptions: Boolean): String;
    function WizardIsTaskSelected(const Tasks: String): Boolean;
    function WizardSilent: Boolean;
    function IsUninstaller: Boolean;
    function UninstallSilent: Boolean;
    function CurrentFilename: String;
    function CurrentSourceFilename: String;
    function ExpandConstant(const S: String): String;
    function ExpandConstantEx(const S: String; const CustomConst, CustomValue: String): String;
    function GetPreviousData(const ValueName, DefaultValueData: String): String;
    function SetPreviousData(const PreviousDataKey: Integer; const ValueName, ValueData: String): Boolean;
    function Terminated: Boolean;
    function Debugging: Boolean;
    function RegisterExtraCloseApplicationsResource(const DisableFsRedir: Boolean; const AFilename: String): Boolean;
    function RmSessionStarted: Boolean;
    function GetWizardForm: TWizardForm;
    function GetUninstallProgressForm: TUninstallProgressForm;
    function GetExceptionMessage: String;
    function IsAdmin: Boolean;
    function IsAdminInstallMode: Boolean;
    function GetWindowsVersion: Cardinal;
    function GetWindowsVersionString: String;
    function IsWin64: Boolean;
    function Is64BitInstallMode: Boolean;
    function ProcessorArchitecture: TSetupProcessorArchitecture;
    function IsArm32Compatible: Boolean;
    function IsArm64: Boolean;
    function IsX64Compatible: Boolean;
    function IsX64OS: Boolean;
    function IsX86Compatible: Boolean;
    function IsX86OS: Boolean;
    function InstallOnThisVersion(const MinVersion, OnlyBelowVersion: String): Boolean;
    function IsDotNetInstalled(const MinVersion: TDotNetVersion; const MinServicePack: Cardinal): Boolean;
    function IsMsiProductInstalled(const UpgradeCode: String; const PackedMinVersion: Int64): Boolean;
    function GetEnv(const EnvVar: String): String;
    function GetUserNameString: String;
    function GetComputerNameString: String;
    function GetUILanguage: Integer;
    function FontExists(const FaceName: String): Boolean;
    function FindWindowByClassName(const ClassName: String): HWND;
    function FindWindowByWindowName(const WindowName: String): HWND;
    function SendMessage(const Wnd: HWND; const Msg, WParam, LParam: LongInt): LongInt;
    function PostMessage(const Wnd: HWND; const Msg, WParam, LParam: LongInt): Boolean;
    function SendNotifyMessage(const Wnd: HWND; const Msg, WParam, LParam: LongInt): Boolean;
    function RegisterWindowMessage(const Name: String): LongInt;
    function SendBroadcastMessage(const Msg, WParam, LParam: LongInt): LongInt;
    function PostBroadcastMessage(const Msg, WParam, LParam: LongInt): Boolean;
    function SendBroadcastNotifyMessage(const Msg, WParam, LParam: LongInt): Boolean;
    function CheckForMutexes(Mutexes: String): Boolean;
    function CreateCallback(Method: AnyMethod): Longword;
    function DLLGetLastError(): LongInt;
    function Chr(B: Byte): Char;
    function Ord(C: Char): Byte;
    function Copy(S: AnyString; Index, Count: Integer): String;
    function Length(S: AnyString): LongInt;
    function Lowercase(S: AnyString): String;
    function Uppercase(S: AnyString): String;
    function AnsiLowercase(S: AnyString): String;
    function AnsiUppercase(S: AnyString): String;
    function StringOfChar(C: Char; I : LongInt): String;
    function StringChange(var S: String; const FromStr, ToStr: String): Integer;
    function StringChangeEx(var S: String; const FromStr, ToStr: String; const SupportDBCS: Boolean): Integer;
    function Pos(SubStr, S: AnyString): Integer;
    function AddQuotes(const S: String): String;
    function RemoveQuotes(const S: String): String;
    function ConvertPercentStr(var S: String): Boolean;
    function CompareText(const S1, S2: String): Integer;
    function CompareStr(const S1, S2: String): Integer;
    function SameText(const S1, S2: String): Boolean;
    function SameStr(const S1, S2: String): Boolean;
    function IsWildcard(const Pattern: String): Boolean;
    function WildcardMatch(const Text, Pattern: String): Boolean;
    function Format(const Format: String; const Args: array of const): String;
    function Trim(const S: AnyString): AnyString;
    function TrimLeft(const S: String): String;
    function TrimRight(const S: String): String;
    function StringJoin(const Separator: String; const Values: TArrayOfString): String;
    function StringSplit(const S: String; const Separators: TArrayOfString; const Typ: TSplitType): TArrayOfString;
    function StringSplitEx(const S: String; const Separators: TArrayOfString; const Quote: Char; const Typ: TSplitType): TArrayOfString;
    function StrToIntDef(S: String; Def: LongInt): LongInt;
    function StrToInt(S: String): LongInt;
    function StrToInt64Def(S: String; Def: Int64): Int64;
    function StrToInt64(S: String): Int64;
    function StrToFloat(S: String): Extended;
    function IntToStr(I: Int64): String;
    function FloatToStr(E: Extended): String;
    function CharLength(const S: String; const Index: Integer): Integer;
    function AddBackslash(const S: String): String;
    function RemoveBackslashUnlessRoot(const S: String): String;
    function RemoveBackslash(const S: String): String;
    function AddPeriod(const S: String): String;
    function ChangeFileExt(const FileName, Extension: String): String;
    function ExtractFileExt(const FileName: String): String;
    function ExtractFileDir(const FileName: String): String;
    function ExtractFilePath(const FileName: String): String;
    function ExtractFileName(const FileName: String): String;
    function ExtractFileDrive(const FileName: String): String;
    function ExtractRelativePath(const BaseName, DestName: String): String;
    function ExpandFileName(const FileName: String): String;
    function ExpandUNCFileName(const FileName: String): String;
    function GetDateTimeString(const DateTimeFormat: String; const DateSeparator, TimeSeparator: Char): String;
    function Utf8Encode(const S: String): AnsiString;
    function Utf8Decode(const S: AnsiString): String;
    function GetMD5OfString(const S: AnsiString): String;
    function GetMD5OfUnicodeString(const S: String): String;
    function GetSHA1OfString(const S: AnsiString): String;
    function GetSHA1OfUnicodeString(const S: String): String;
    function GetSHA256OfString(const S: AnsiString): String;
    function GetSHA256OfUnicodeString(const S: String): String;
    function SysErrorMessage(ErrorCode: Integer): String;
    function MinimizePathName(const Filename: String; const Font: TFont; MaxLen: Integer): String;
    function GetArrayLength(var Arr: Array): LongInt;
    function Null: Variant;
    function Unassigned: Variant;
    function VarIsEmpty(const V: Variant): Boolean;
    function VarIsClear(const V: Variant): Boolean;
    function VarIsNull(const V: Variant): Boolean;
    function VarType(const V: Variant): TVarType;
    function VarArrayGet(var S: Variant; I: Integer): Variant;
    function DirExists(const Name: String): Boolean;
    function FileExists(const Name: String): Boolean;
    function FileOrDirExists(const Name: String): Boolean;
    function FileSize(const Name: String; var Size: Integer): Boolean;
    function FileSize64(const Name: String; var Size: Int64): Boolean;
    function GetSpaceOnDisk(const Path: String; const InMegabytes: Boolean; var Free, Total: Cardinal): Boolean;
    function GetSpaceOnDisk64(const Path: String; var Free, Total: Int64): Boolean;
    function FileSearch(const Name, DirList: String): String;
    function FindFirst(const FileName: String; var FindRec: TFindRec): Boolean;
    function FindNext(var FindRec: TFindRec): Boolean;
    function GetCurrentDir: String;
    function SetCurrentDir(const Dir: String): Boolean;
    function GetWinDir: String;
    function GetSystemDir: String;
    function GetSysWow64Dir: String;
    function GetTempDir: String;
    function GetShellFolderByCSIDL(const Folder: Integer; const Create: Boolean): String;
    function GetShortName(const LongName: String): String;
    function GenerateUniqueName(Path: String; const Extension: String): String;
    function IsProtectedSystemFile(const Filename: String): Boolean;
    function GetMD5OfFile(const Filename: String): String;
    function GetSHA1OfFile(const Filename: String): String;
    function GetSHA256OfFile(const Filename: String): String;
    function EnableFsRedirection(const Enable: Boolean): Boolean;
    function Exec(const Filename, Params, WorkingDir: String; const ShowCmd: Integer; const Wait: TExecWait; var ResultCode: Integer): Boolean;
    function ExecAsOriginalUser(const Filename, Params, WorkingDir: String; const ShowCmd: Integer; const Wait: TExecWait; var ResultCode: Integer): Boolean;
    function ShellExec(const Verb, Filename, Params, WorkingDir: String; const ShowCmd: Integer; const Wait: TExecWait; var ErrorCode: Integer): Boolean;
    function ShellExecAsOriginalUser(const Verb, Filename, Params, WorkingDir: String; const ShowCmd: Integer; const Wait: TExecWait; var ErrorCode: Integer): Boolean;
    function ExtractTemporaryFiles(const Pattern: String): Integer;
    function DownloadTemporaryFile(const Url, FileName, RequiredSHA256OfFile: String; const OnDownloadProgress: TOnDownloadProgress): Int64;
    function DownloadTemporaryFileSize(const Url): Int64;
    function DownloadTemporaryFileDate(const Url): String;
    function RenameFile(const OldName, NewName: String): Boolean;
    function CopyFile(const ExistingFile, NewFile: String; const FailIfExists: Boolean): Boolean;
    function DeleteFile(const FileName: String): Boolean;
    function SetNTFSCompression(const FileOrDir: String; Compress: Boolean): Boolean;
    function LoadStringFromFile(const FileName: String; var S: AnsiString): Boolean;
    function LoadStringFromLockedFile(const FileName: String; var S: AnsiString): Boolean;
    function LoadStringsFromFile(const FileName: String; var S: TArrayOfString): Boolean;
    function LoadStringsFromLockedFile(const FileName: String; var S: TArrayOfString): Boolean;
    function SaveStringToFile(const FileName: String; const S: AnsiString; const Append: Boolean): Boolean;
    function SaveStringsToFile(const FileName: String; const S: TArrayOfString; const Append: Boolean): Boolean;
    function SaveStringsToUTF8File(const FileName: String; const S: TArrayOfString; const Append: Boolean): Boolean;
    function SaveStringsToUTF8FileWithoutBOM(const FileName: String; const S: TArrayOfString; const Append: Boolean): Boolean;
    function CreateDir(const Dir: String): Boolean;
    function ForceDirectories(Dir: String): Boolean;
    function RemoveDir(const Dir: String): Boolean;
    function DelTree(const Path: String; const IsDir, DeleteFiles, DeleteSubdirsAlso: Boolean): Boolean;
    function CreateShellLink(const Filename, Description, ShortcutTo, Parameters, WorkingDir, IconFilename: String; const IconIndex, ShowCmd: Integer): String;
    function UnpinShellLink(const Filename: String): Boolean;
    function UnregisterServer(const Is64Bit: Boolean; const Filename: String; const FailCriticalErrors: Boolean): Boolean;
    function UnregisterTypeLibrary(const Is64Bit: Boolean; const Filename: String): Boolean;
    function DecrementSharedCount(const Is64Bit: Boolean; const Filename: String): Boolean;
    function ModifyPifFile(const Filename: String; const CloseOnExit: Boolean): Boolean;
    function GetVersionNumbers(const Filename: String; var VersionMS, VersionLS: Cardinal): Boolean;
    function GetVersionComponents(const Filename: String; var Major, Minor, Revision, Build: Word): Boolean;
    function GetVersionNumbersString(const Filename: String; var Version: String): Boolean;
    function GetPackedVersion(const Filename: String; var Version: Int64): Boolean;
    function PackVersionNumbers(const VersionMS, VersionLS: Cardinal): Int64;
    function PackVersionComponents(const Major, Minor, Revision, Build: Word): Int64;
    function ComparePackedVersion(const Version1, Version2: Int64): Integer;
    function SamePackedVersion(const Version1, Version2: Int64): Boolean;
    function VersionToStr(const Version: Int64): String;
    function StrToVersion(const Version: String; var Version: Int64): Boolean;
    function RegKeyExists(const RootKey: Integer; const SubKeyName: String): Boolean;
    function RegValueExists(const RootKey: Integer; const SubKeyName, ValueName: String): Boolean;
    function RegGetSubkeyNames(const RootKey: Integer; const SubKeyName: String; var Names: TArrayOfString): Boolean;
    function RegGetValueNames(const RootKey: Integer; const SubKeyName: String; var Names: TArrayOfString): Boolean;
    function RegQueryStringValue(const RootKey: Integer; const SubKeyName, ValueName: String; var ResultStr: String): Boolean;
    function RegQueryMultiStringValue(const RootKey: Integer; const SubKeyName, ValueName: String; var ResultStr: String): Boolean;
    function RegQueryDWordValue(const RootKey: Integer; const SubKeyName, ValueName: String; var ResultDWord: Cardinal): Boolean;
    function RegQueryBinaryValue(const RootKey: Integer; const SubKeyName, ValueName: String; var ResultStr: AnsiString): Boolean;
    function RegWriteStringValue(const RootKey: Integer; const SubKeyName, ValueName, Data: String): Boolean;
    function RegWriteExpandStringValue(const RootKey: Integer; const SubKeyName, ValueName, Data: String): Boolean;
    function RegWriteMultiStringValue(const RootKey: Integer; const SubKeyName, ValueName, Data: String): Boolean;
    function RegWriteDWordValue(const RootKey: Integer; const SubKeyName, ValueName: String; const Data: Cardinal): Boolean;
    function RegWriteBinaryValue(const RootKey: Integer; const SubKeyName, ValueName: String; const Data: AnsiString): Boolean;
    function RegDeleteKeyIncludingSubkeys(const RootKey: Integer; const SubkeyName: String): Boolean;
    function RegDeleteKeyIfEmpty(const RootKey: Integer; const SubkeyName: String): Boolean;
    function RegDeleteValue(const RootKey: Integer; const SubKeyName, ValueName: String): Boolean;
    function IniKeyExists(const Section, Key, Filename: String): Boolean;
    function IsIniSectionEmpty(const Section, Filename: String): Boolean;
    function GetIniBool(const Section, Key: String; const Default: Boolean; const Filename: String): Boolean;
    function GetIniInt(const Section, Key: String; const Default, Min, Max: LongInt; const Filename: String): LongInt;
    function GetIniString(const Section, Key, Default, Filename: String): String;
    function SetIniBool(const Section, Key: String; const Value: Boolean; const Filename: String): Boolean;
    function SetIniInt(const Section, Key: String; const Value: LongInt; const Filename: String): Boolean;
    function SetIniString(const Section, Key, Value, Filename: String): Boolean;
    function CreateInputQueryPage(const AfterID: Integer; const ACaption, ADescription, ASubCaption: String): TInputQueryWizardPage;
    function CreateInputOptionPage(const AfterID: Integer; const ACaption, ADescription, ASubCaption: String; Exclusive, ListBox: Boolean): TInputOptionWizardPage;
    function CreateInputDirPage(const AfterID: Integer; const ACaption, ADescription, ASubCaption: String; AAppendDir: Boolean; ANewFolderName: String): TInputDirWizardPage;
    function CreateInputFilePage(const AfterID: Integer; const ACaption, ADescription, ASubCaption: String): TInputFileWizardPage;
    function CreateOutputMsgPage(const AfterID: Integer; const ACaption, ADescription, AMsg: String): TOutputMsgWizardPage;
    function CreateOutputMsgMemoPage(const AfterID: Integer; const ACaption, ADescription, ASubCaption: String; const AMsg: AnsiString): TOutputMsgMemoWizardPage;
    function CreateOutputProgressPage(const ACaption, ADescription: String): TOutputProgressWizardPage;
    function CreateOutputMarqueeProgressPage(const ACaption, ADescription: String): TOutputMarqueeProgressWizardPage;
    function CreateDownloadPage(const ACaption, ADescription: String; const OnDownloadProgress: TOnDownloadProgress): TDownloadWizardPage;
    function CreateExtractionPage(const ACaption, ADescription: String; const OnExtractionProgress: TOnExtractionProgress): ExtractionWizardPage;
    function CreateCustomPage(const AfterID: Integer; const ACaption, ADescription: String): TWizardPage;
    function CreateCustomForm: TSetupForm;
    function PageFromID(const ID: Integer): TWizardPage;
    function PageIndexFromID(const ID: Integer): Integer;
    function ScaleX(X: Integer): Integer;
    function ScaleY(Y: Integer): Integer;
    function InitializeBitmapImageFromIcon(const BitmapImage: TBitmapImage; const IconFilename: String; const BkColor: TColor; const AscendingTrySizes: TArrayOfInteger): Boolean;
    function MsgBox(const Text: String; const Typ: TMsgBoxType; const Buttons: Integer): Integer;
    function SuppressibleMsgBox(const Text: String; const Typ: TMsgBoxType; const Buttons, Default: Integer): Integer;
    function TaskDialogMsgBox(const Instruction, Text: String; const Typ: TMsgBoxType; const Buttons: Cardinal; const ButtonLabels: TArrayOfString; const ShieldButton: Integer): Integer;
    function SuppressibleTaskDialogMsgBox(const Instruction, Text: String; const Typ: TMsgBoxType; const Buttons: Cardinal; const ButtonLabels: TArrayOfString; const ShieldButton: Integer; const Default: Integer): Integer;
    function GetOpenFileName(const Prompt: String; var FileName: String; const InitialDirectory, Filter, DefaultExtension: String): Boolean;
    function GetOpenFileNameMulti(const Prompt: String; var FileNameList: TStrings; const InitialDirectory, Filter, DefaultExtension: String): Boolean;
    function GetSaveFileName(const Prompt: String; var FileName: String; const InitialDirectory, Filter, DefaultExtension: String): Boolean;
    function BrowseForFolder(const Prompt: String; var Directory: String; const NewFolderButton: Boolean): Boolean;
    function ExitSetupMsgBox: Boolean;
    function SelectDisk(const DiskNumber: Integer; const AFilename: String; var Path: String): Boolean;
    function CreateOleObject(const ClassName: String): Variant;
    function GetActiveOleObject(const ClassName: String): Variant;
    function IDispatchInvoke(Self: IDispatch; PropertySet: Boolean; const Name: String; Par: array of Variant): Variant;
    function CreateComObject(const ClassID: TGUID): IUnknown;
    function StringToGUID(const S: String): TGUID;
    function ExecAndCaptureOutput(const Filename, Params, WorkingDir: String; const ShowCmd: Integer; const Wait: TExecWait; var ResultCode: Integer; var Output: TExecOutput): Boolean;
    function ExecAndLogOutput(const Filename, Params, WorkingDir: String; const ShowCmd: Integer; const Wait: TExecWait; var ResultCode: Integer; const OnLog: TOnLog): Boolean;
    function Random(const Range: Integer): Integer;
    function Get8087CW: Word;
    function LoadDLL(const DLLName: String; var ErrorCode: Integer): LongInt;
    function CallDLLProc(const DLLHandle: LongInt; const ProcName: String; const Param1, Param2: LongInt; var Result: LongInt): Boolean;
    function FreeDLL(const DLLHandle: LongInt): Boolean;
    function CastStringToInteger(var S: String): LongInt;
    function CastIntegerToString(const L: LongInt): String;
    function MakePendingFileRenameOperationsChecksum: String;
    procedure WizardSelectComponents(const Components: String);
    procedure WizardSelectTasks(const Tasks: String);
    procedure Abort;
    procedure RaiseException(const Msg: String);
    procedure ShowExceptionMessage;
    procedure GetWindowsVersionEx(var Version: TWindowsVersion);
    procedure CreateMutex(const Name: String);
    procedure UnloadDLL(Filename: String);
    procedure Delete(var S: AnyString; Index, Count: Integer);
    procedure Insert(Source: AnyString; var Dest: AnyString; Index: Integer);
    procedure SetLength(var S: AnyString; L: LongInt);
    procedure CharToOemBuff(var S: AnsiString);
    procedure OemToCharBuff(var S: AnsiString);
    procedure SetArrayLength(var Arr: Array; I: LongInt);
    procedure VarArraySet(C: Variant; I: Integer; var S: Variant);
    procedure FindClose(var FindRec: TFindRec);
    procedure ExtractTemporaryFile(const FileName: String);
    procedure SetDownloadCredentials(const User, Pass: String);
    procedure Extract7ZipArchive(const ArchiveFileName, DestDir: String; const FullPaths: Boolean; const OnExtractionProgress: TOnExtractionProgress);
    procedure DelayDeleteFile(const Filename: String; const Tries: Integer);
    procedure RegisterServer(const Is64Bit: Boolean; const Filename: String; const FailCriticalErrors: Boolean);
    procedure RegisterTypeLibrary(const Is64Bit: Boolean; const Filename: String);
    procedure IncrementSharedCount(const Is64Bit: Boolean; const Filename: String; const AlreadyExisted: Boolean);
    procedure RestartReplace(const TempFile, DestFile: String);
    procedure UnregisterFont(const FontName, FontFilename: String; const PerUserFont: Boolean);
    procedure UnpackVersionNumbers(const Version: Int64; var VersionMS, VersionLS: Cardinal);
    procedure UnpackVersionComponents(const Version: Int64; var Major, Minor, Revision, Build: Word);
    procedure DeleteIniSection(const Section, Filename: String);
    procedure DeleteIniEntry(const Section, Key, Filename: String);
    procedure OleCheck(Result: HResult);
    procedure CoFreeUnusedLibraries;
    procedure Log(const S: String);
    procedure Sleep(const Milliseconds: LongInt);
    procedure Beep;
    procedure Set8087CW(NewCW: Word);
    procedure BringToFrontAndRestore;
    """


def _parse_class_reference(cls) -> IFPSClassReference:
    def add_types(spec: tuple[IFPSParam]):
        for p in spec:
            if p.type is not None:
                types[p.type.casefold()] = p.type

    classes: dict[str, IFPSClass] = CaseInsensitiveDict()
    types: dict[str, str] = {}

    for function in IFPSAPI.values():
        add_types(function.parameters)

    for chunk in inspect.cleandoc(inspect.getdoc(cls)).split('\n\n'):
        name, _, rest = chunk.partition('=')
        name = name.strip()
        rest = rest.strip()
        types[name.casefold()] = name
        cm = re.fullmatch(r'(?s)class(?:\(\w+\))?\n\s*(.*?)\s*end;', rest)
        if cm is None:
            continue
        body = cm.group(1).strip().splitlines(False)
        members = CaseInsensitiveDict()
        for member in body:
            kind, _, decl = member.lstrip().rstrip(';').partition(' ')
            kwargs = {}
            if kind == 'property':
                decl, _, attributes = decl.partition(';')
                attributes = attributes.strip().split()
                kwargs.update(
                    writable=('write' in attributes),
                    readable=('read' in attributes))
            sig = parse_decl(decl, kind, **kwargs)

            if kind == 'property':
                parameters = sig.parameters
                this = IFPSParam('This', name, True)
                if kwargs['writable']:
                    setter_name = F'Set{sig.name}'
                    setter_args = (this, *parameters, IFPSParam('Value', sig.return_type, True))
                    setter = IFPSSignature(setter_name, 'setter', setter_args, None, True)
                    members[setter_name] = setter
                if kwargs['readable']:
                    if not sig.return_type or sig.void:
                        raise RuntimeError(F'Readable property {sig.name} had no type.')
                    getter_name = F'Get{sig.name}'
                    getter_args = (this, *parameters)
                    rt = sig.return_type
                    getter = IFPSSignature(getter_name, 'getter', getter_args, rt, False)
                    members[getter_name] = getter

            members[sig.name] = sig
            add_types(sig.parameters)

        classes[name] = IFPSClass(name, members)

    return IFPSClassReference(types, classes)


@_parse_class_reference
class IFPSClasses:
    """
    TObject = class
      constructor Create;
      procedure Free;
    end;

    TPersistent = class(TObject)
      procedure Assign(Source: TPersistent);
    end;

    TComponent = class(TPersistent)
      function FindComponent(AName: String): TComponent;
      constructor Create(AOwner: TComponent);
      property Owner: TComponent; read write;
      procedure DestroyComponents;
      procedure Destroying;
      procedure FreeNotification(AComponent: TComponent);
      procedure InsertComponent(AComponent: TComponent);
      procedure RemoveComponent(AComponent: TComponent);
      property Components[Index: Integer]: TComponent; read;
      property ComponentCount: Integer; read;
      property ComponentIndex: Integer; read write;
      property ComponentState: Byte; read;
      property DesignInfo: Longint; read write;
      property Name: String; read write;
      property Tag: Longint; read write;
    end;

    TStrings = class(TPersistent)
      function Add(S: String): Integer;
      procedure Append(S: String);
      procedure AddStrings(Strings: TStrings);
      procedure Clear;
      procedure Delete(Index: Integer);
      function IndexOf(const S: String): Integer;
      procedure Insert(Index: Integer; S: String);
      property Count: Integer; read;
      property Text: String; read write;
      property CommaText: String; read write;
      procedure LoadFromFile(FileName: String);
      procedure SaveToFile(FileName: String);
      property Strings[Index: Integer]: String; read write;
      property Objects[Index: Integer]: TObject; read write;
    end;

    TNotifyEvent = procedure(Sender: TObject);

    TDuplicates = (dupIgnore, dupAccept, dupError);

    TStringList = class(TStrings)
      function Find(S: String; var Index: Integer): Boolean;
      procedure Sort;
      property Duplicates: TDuplicates; read write;
      property Sorted: Boolean; read write;
      property OnChange: TNotifyEvent; read write;
      property OnChanging: TNotifyEvent; read write;
    end;

    { Seek Origin values: soFromBeginning, soFromCurrent, soFromEnd }

    TStream = class(TObject)
      function Read(var Buffer: AnyString; ByteCount: Longint): Longint;
      function Write(const Buffer: AnyString; ByteCount: Longint): Longint;
      function Seek(Offset: Int64; Origin: Word): Int64;
      procedure ReadBuffer(var Buffer: AnyString; ByteCount: Longint);
      procedure WriteBuffer(const Buffer: AnyString; ByteCount: Longint);
      function CopyFrom(Source: TStream; ByteCount: Int64; BufferSize: Integer): Int64;
      property Position: Longint; read write;
      property Size: Longint; read write;
    end;

    THandleStream = class(TStream)
      constructor Create(AHandle: Integer);
      property Handle: Integer; read;
    end;

    TFileStream = class(THandleStream)
      constructor Create(Filename: String; Mode: Word);
    end;

    TStringStream = class(TStream)
      constructor Create(AString: String);
    end;

    TGraphicsObject = class(TPersistent)
      property OnChange: TNotifyEvent; read write;
    end;

    TBrushStyle = (bsSolid, bsClear, bsHorizontal, bsVertical, bsFDiagonal, bsBDiagonal, bsCross, bsDiagCross);

    TBrush = class(TGraphicsObject)
      constructor Create;
      property Color: TColor; read write;
      property Style: TBrushStyle; read write;
    end;

    TFontStyle = (fsBold, fsItalic, fsUnderline, fsStrikeOut);

    TFontStyles = set of TFontStyle;

    TColor = Integer;

    { TColor values: clBlack, clMaroon, clGreen, clOlive, clNavy, clPurple, clTeal, clGray, clSilver, clRed, clLime, clYellow, clBlue, clFuchsia, clAqua, clLtGray, clDkGray, clWhite, clNone, clDefault, clScrollBar, clBackground, clActiveCaption, clInactiveCaption, clMenu, clWindow, clWindowFrame, clMenuText, clWindowText, clCaptionText, clActiveBorder, clInactiveBorder, clAppWorkSpace, clHighlight, clHighlightText, clBtnFace, clBtnShadow, clGrayText, clBtnText, clInactiveCaptionText, clBtnHighlight, cl3DDkShadow, cl3DLight, clInfoText, clInfoBk, clHotLight }

    TFont = class(TGraphicsObject)
      constructor Create;
      property Handle: Integer; read;
      property Color: TColor; read write;
      property Height: Integer; read write;
      property Name: String; read write;
      property Pitch: Byte; read write;
      property Size: Integer; read write;
      property PixelsPerInch: Integer; read write;
      property Style: TFontStyles; read write;
    end;

    TPenMode = (pmBlack, pmWhite, pmNop, pmNot, pmCopy, pmNotCopy, pmMergePenNot, pmMaskPenNot, pmMergeNotPen, pmMaskNotPen, pmMerge, pmNotMerge, pmMask, pmNotMask, pmXor, pmNotXor);

    TPenStyle = (psSolid, psDash, psDot, psDashDot, psDashDotDot, psClear, psInsideFrame);

    TPen = class(TGraphicsObject)
      constructor Create;
      property Color: TColor; read write;
      property Mode: TPenMode; read write;
      property Style: TPenStyle; read write;
      property Width: Integer; read write;
    end;

    TCanvas = class(TPersistent)
      procedure Arc(X1, Y1, X2, Y2, X3, Y3, X4, Y4: Integer);
      procedure Chord(X1, Y1, X2, Y2, X3, Y3, X4, Y4: Integer);
      procedure Draw(X, Y: Integer; Graphic: TGraphic);
      procedure Ellipse(X1, Y1, X2, Y2: Integer);
      procedure FloodFill(X, Y: Integer; Color: TColor; FillStyle: Byte);
      procedure LineTo(X, Y: Integer);
      procedure MoveTo(X, Y: Integer);
      procedure Pie(X1, Y1, X2, Y2, X3, Y3, X4, Y4: Integer);
      procedure Rectangle(X1, Y1, X2, Y2: Integer);
      procedure Refresh;
      procedure RoundRect(X1, Y1, X2, Y2, X3, Y3: Integer);
      function TextHeight(Text: String): Integer;
      procedure TextOut(X, Y: Integer; Text: String);
      function TextWidth(Text: String): Integer;
      property Handle: Integer; read write;
      property Pixels: Integer Integer Integer; read write;
      property Brush: TBrush; read;
      property CopyMode: Byte; read write;
      property Font: TFont; read;
      property Pen: TPen; read;
    end;

    TGraphic = class(TPersistent)
      procedure LoadFromFile(const Filename: String);
      procedure SaveToFile(const Filename: String);
      property Empty: Boolean; read write;
      property Height: Integer; read write;
      property Modified: Boolean; read write;
      property Width: Integer; read write;
      property OnChange: TNotifyEvent; read write;
    end;

    TAlphaFormat = (afIgnored, afDefined, afPremultiplied);

    HBITMAP = Integer;

    TBitmap = class(TGraphic)
      procedure LoadFromStream(Stream: TStream);
      procedure SaveToStream(Stream: TStream);
      property AlphaFormat: TAlphaFormat; read write;
      property Canvas: TCanvas; read write;
      property Handle: HBITMAP; read write;
    end;

    TAlign = (alNone, alTop, alBottom, alLeft, alRight, alClient);

    TAnchorKind = (akLeft, akTop, akRight, akBottom);

    TAnchors = set of TAnchorKind;

    TCursor = Integer;

    { TCursor values: crDefault, crNone, crArrow, crCross, crIBeam, crSizeNESW, crSizeNS, crSizeNWSE, crSizeWE, crUpArrow, crHourGlass, crDrag, crNoDrop, crHSplit, crVSplit, crMultiDrag, crSQLWait, crNo, crAppStart, crHelp, crHandPoint, crSizeAll, crHand }

    TControl = class(TComponent)
      constructor Create(AOwner: TComponent);
      procedure BringToFront;
      procedure Hide;
      procedure Invalidate;
      procedure Refresh;
      procedure Repaint;
      procedure SendToBack;
      procedure Show;
      procedure Update;
      procedure SetBounds(ALeft, ATop, AWidth, AHeight: Integer);
      property Left: Integer; read write;
      property Top: Integer; read write;
      property Width: Integer; read write;
      property Height: Integer; read write;
      property Hint: String; read write;
      property Align: TAlign; read write;
      property ClientHeight: Longint; read write;
      property ClientWidth: Longint; read write;
      property ShowHint: Boolean; read write;
      property Visible: Boolean; read write;
      property Enabled: Boolean; read write;
      property Cursor: TCursor; read write;
    end;

    TWinControl = class(TControl)
      property Parent: TWinControl; read write;
      property ParentBackground: Boolean; read write;
      property Handle: Longint; read write;
      property Showing: Boolean; read;
      property TabOrder: Integer; read write;
      property TabStop: Boolean; read write;
      function CanFocus: Boolean;
      function Focused: Boolean;
      property Controls[Index: Integer]: TControl; read;
      property ControlCount: Integer; read;
    end;

    TGraphicControl = class(TControl)
    end;

    TCustomControl = class(TWinControl)
    end;

    TScrollingWinControl = class(TWinControl)
      procedure ScrollInView(AControl: TControl);
    end;

    TFormBorderStyle = (bsNone, bsSingle, bsSizeable, bsDialog, bsToolWindow, bsSizeToolWin);

    TBorderIcon = (biSystemMenu, biMinimize, biMaximize, biHelp);

    TBorderIcons = set of TBorderIcon;

    TConstraintSize = 0..MaxInt;

    TSizeConstraints = class(TPersistent);
      property MaxHeight: TConstraintSize; read write;
      property MaxWidth: TConstraintSize; read write;
      property MinHeight: TConstraintSize; read write;
      property MinWidth: TConstraintSize; read write;
    end;

    TFormStyle = (fsNormal, fsMDIChild, fsMDIForm, fsStayOnTop);

    TPopupMode = (pmNone, pmAuto, pmExplicit);

    TPosition = (poDesigned, poDefault, poDefaultPosOnly, poDefaultSizeOnly, poScreenCenter, poDesktopCenter, poMainFormCenter, poOwnerFormCenter);

    TCloseAction = (caNone, caHide, caFree, caMinimize);

    TCloseEvent = procedure(Sender: TObject; var Action: TCloseAction);

    TCloseQueryEvent = procedure(Sender: TObject; var CanClose: Boolean);

    TEShiftState = (ssShift, ssAlt, ssCtrl, ssLeft, ssRight, ssMiddle, ssDouble);

    TShiftState = set of TEShiftState;

    TKeyEvent = procedure(Sender: TObject; var Key: Word; Shift: TShiftState);

    TKeyPressEvent = procedure(Sender: TObject; var Key: Char);

    TForm = class(TScrollingWinControl)
      constructor CreateNew(AOwner: TComponent);
      procedure Close;
      procedure Hide;
      procedure Show;
      function ShowModal: Integer;
      procedure Release;
      property Active: Boolean; read;
      property ActiveControl: TWinControl; read write;
      property Anchors: TAnchors; read write;
      property AutoScroll: Boolean; read write;
      property BorderIcons: TBorderIcons; read write;
      property BorderStyle: TFormBorderStyle; read write;
      property Caption: String; read write;
      property Color: TColor; read write;
      property Constraints: TSizeConstraints; read write;
      property Font: TFont; read write;
      property FormStyle: TFormStyle; read write;
      property KeyPreview: Boolean; read write;
      property PopupMode: TPopupMode; read write;
      property PopupParent: TForm; read write;
      property Position: TPosition; read write;
      property OnActivate: TNotifyEvent; read write;
      property OnClick: TNotifyEvent; read write;
      property OnDblClick: TNotifyEvent; read write;
      property OnClose: TCloseEvent; read write;
      property OnCloseQuery: TCloseQueryEvent; read write;
      property OnCreate: TNotifyEvent; read write;
      property OnDestroy: TNotifyEvent; read write;
      property OnDeactivate: TNotifyEvent; read write;
      property OnHide: TNotifyEvent; read write;
      property OnKeyDown: TKeyEvent; read write;
      property OnKeyPress: TKeyPressEvent; read write;
      property OnKeyUp: TKeyEvent; read write;
      property OnResize: TNotifyEvent; read write;
      property OnShow: TNotifyEvent; read write;
    end;

    TCustomLabel = class(TGraphicControl)
    end;

    TAlignment = (taLeftJustify, taRightJustify, taCenter);

    TLabel = class(TCustomLabel)
      property Alignment: TAlignment; read write;
      property Anchors: TAnchors; read write;
      property AutoSize: Boolean; read write;
      property Caption: String; read write;
      property Color: TColor; read write;
      property FocusControl: TWinControl; read write;
      property Font: TFont; read write;
      property WordWrap: Boolean; read write;
      property OnClick: TNotifyEvent; read write;
      property OnDblClick: TNotifyEvent; read write;
    end;

    TCustomEdit = class(TWinControl)
      procedure Clear;
      procedure ClearSelection;
      procedure SelectAll;
      property Modified: Boolean; read write;
      property SelLength: Integer; read write;
      property SelStart: Integer; read write;
      property SelText: String; read write;
      property Text: String; read write;
    end;

    TBorderStyle = TFormBorderStyle;

    TEditCharCase = (ecNormal, ecUpperCase, ecLowerCase);

    TEdit = class(TCustomEdit)
      property Anchors: TAnchors; read write;
      property AutoSelect: Boolean; read write;
      property AutoSize: Boolean; read write;
      property BorderStyle: TBorderStyle; read write;
      property CharCase: TEditCharCase; read write;
      property Color: TColor; read write;
      property Font: TFont; read write;
      property HideSelection: Boolean; read write;
      property MaxLength: Integer; read write;
      property PasswordChar: Char; read write;
      property ReadOnly: Boolean; read write;
      property Text: String; read write;
      property OnChange: TNotifyEvent; read write;
      property OnClick: TNotifyEvent; read write;
      property OnDblClick: TNotifyEvent; read write;
      property OnKeyDown: TKeyEvent; read write;
      property OnKeyPress: TKeyPressEvent; read write;
      property OnKeyUp: TKeyEvent; read write;
    end;

    TNewEdit = class(TEdit)
    end;

    TCustomMemo = class(TCustomEdit)
      property Lines: TStrings; read write;
    end;

    TScrollStyle = (ssNone, ssHorizontal, ssVertical, ssBoth);

    TMemo = class(TCustomMemo)
      property Alignment: TAlignment; read write;
      property Anchors: TAnchors; read write;
      property BorderStyle: TBorderStyle; read write;
      property Color: TColor; read write;
      property Font: TFont; read write;
      property HideSelection: Boolean; read write;
      property Lines: TStrings; read write;
      property MaxLength: Integer; read write;
      property ReadOnly: Boolean; read write;
      property ScrollBars: TScrollStyle; read write;
      property WantReturns: Boolean; read write;
      property WantTabs: Boolean; read write;
      property WordWrap: Boolean; read write;
      property OnChange: TNotifyEvent; read write;
      property OnClick: TNotifyEvent; read write;
      property OnDblClick: TNotifyEvent; read write;
      property OnKeyDown: TKeyEvent; read write;
      property OnKeyPress: TKeyPressEvent; read write;
      property OnKeyUp: TKeyEvent; read write;
    end;

    TNewMemo = class(TMemo)
    end;

    TCustomComboBox = class(TWinControl)
      property DroppedDown: Boolean; read write;
      property Items: TStrings; read write;
      property ItemIndex: Integer; read write;
    end;

    TComboBoxStyle = (csDropDown, csSimple, csDropDownList, csOwnerDrawFixed, csOwnerDrawVariable);

    TComboBox = class(TCustomComboBox)
      property Anchors: TAnchors; read write;
      property Color: TColor; read write;
      property DropDownCount: Integer; read write;
      property Font: TFont; read write;
      property MaxLength: Integer; read write;
      property Sorted: Boolean; read write;
      property Style: TComboBoxStyle; read write;
      property Text: String; read write;
      property OnChange: TNotifyEvent; read write;
      property OnClick: TNotifyEvent; read write;
      property OnDblClick: TNotifyEvent; read write;
      property OnDropDown: TNotifyEvent; read write;
      property OnKeyDown: TKeyEvent; read write;
      property OnKeyPress: TKeyPressEvent; read write;
      property OnKeyUp: TKeyEvent; read write;
    end;

    TNewComboBox = class(TComboBox)
    end;

    TButtonControl = class(TWinControl)
    end;

    TButton = class(TButtonControl)
      property Anchors: TAnchors; read write;
      property Cancel: Boolean; read write;
      property Caption: String; read write;
      property Default: Boolean; read write;
      property Font: TFont; read write;
      property ModalResult: Longint; read write;
      property OnClick: TNotifyEvent; read write;
    end;

    TNewButton = class(TButton)
    end;

    TCustomCheckBox = class(TButtonControl)
    end;

    TCheckBoxState = (cbUnchecked, cbChecked, cbGrayed);

    TCheckBox = class(TCustomCheckBox)
      property Alignment: TAlignment; read write;
      property AllowGrayed: Boolean; read write;
      property Anchors: TAnchors; read write;
      property Caption: String; read write;
      property Checked: Boolean; read write;
      property Color: TColor; read write;
      property Font: TFont; read write;
      property State: TCheckBoxState; read write;
      property OnClick: TNotifyEvent; read write;
    end;

    TNewCheckBox = class(TCheckBox)
    end;

    TRadioButton = class(TButtonControl)
      property Alignment: TAlignment; read write;
      property Anchors: TAnchors; read write;
      property Caption: String; read write;
      property Checked: Boolean; read write;
      property Color: TColor; read write;
      property Font: TFont; read write;
      property OnClick: TNotifyEvent; read write;
      property OnDblClick: TNotifyEvent; read write;
    end;

    TNewRadioButton = class(TRadioButton)
    end;

    TSysLinkType = (sltURL, sltID);

    TSysLinkEvent = procedure(Sender: TObject; const Link: string; LinkType: TSysLinkType);

    TCustomLinkLabel = class(TWinControl)
      property Alignment: TAlignment; read write;
      property AutoSize: Boolean; read write;
      property UseVisualStyle: Boolean; read write;
      property OnLinkClick: TSysLinkEvent; read write;
    end;

    TLinkLabel = class(TCustomLinkLabel)
      property Anchors: TAnchors; read write;
      property Caption: String; read write;
      property Color: TColor; read write;
      property Font: TFont; read write;
    end;

    TNewLinkLabel = class(TLinkLabel)
      function AdjustHeight: Integer;
    end;

    TCustomListBox = class(TWinControl)
      property Items: TStrings; read write;
      property ItemIndex: Integer; read write;
      property SelCount: Integer; read;
      property Selected[Index: Integer]: Boolean; read write;
    end;

    TListBoxStyle = (lbStandard, lbOwnerDrawFixed, lbOwnerDrawVariable);

    TListBox = class(TCustomListBox)
      property Anchors: TAnchors; read write;
      property BorderStyle: TBorderStyle; read write;
      property Color: TColor; read write;
      property Font: TFont; read write;
      property MultiSelect: Boolean; read write;
      property Sorted: Boolean; read write;
      property Style: TListBoxStyle; read write;
      property OnClick: TNotifyEvent; read write;
      property OnDblClick: TNotifyEvent; read write;
      property OnKeyDown: TKeyEvent; read write;
      property OnKeyPress: TKeyPressEvent; read write;
      property OnKeyUp: TKeyEvent; read write;
    end;

    TNewListBox = class(TListBox)
    end;

    TBevelKind = (bkNone, bkTile, bkSoft, bkFlat);

    TBevelShape = (bsBox, bsFrame, bsTopLine, bsBottomLine, bsLeftLine, bsRightLine, bsSpacer);

    TBevelStyle = (bsLowered, bsRaised);

    TBevel = class(TGraphicControl)
      property Anchors: TAnchors; read write;
      property Shape: TBevelShape; read write;
      property Style: TBevelStyle; read write;
    end;

    TCustomPanel = class(TCustomControl)
    end;

    TPanelBevel = (bvNone, bvLowered, bvRaised, bvSpace);

    TBevelWidth = Longint;

    TBorderWidth = Longint;

    TPanel = class(TCustomPanel)
      property Alignment: TAlignment; read write;
      property Anchors: TAnchors; read write;
      property BevelInner: TPanelBevel; read write;
      property BevelKind: TBevelKind; read write;
      property BevelOuter: TPanelBevel; read write;
      property BevelWidth: TBevelWidth; read write;
      property BorderWidth: TBorderWidth; read write;
      property BorderStyle: TBorderStyle; read write;
      property Caption: String; read write;
      property Color: TColor; read write;
      property Font: TFont; read write;
      property OnClick: TNotifyEvent; read write;
      property OnDblClick: TNotifyEvent; read write;
    end;

    TNewStaticText = class(TWinControl)
      function AdjustHeight: Integer;
      property Anchors: TAnchors; read write;
      property AutoSize: Boolean; read write;
      property Caption: String; read write;
      property Color: TColor; read write;
      property FocusControl: TWinControl; read write;
      property Font: TFont; read write;
      property ForceLTRReading: Boolean; read write;
      property ShowAccelChar: Boolean; read write;
      property WordWrap: Boolean; read write;
      property OnClick: TNotifyEvent; read write;
      property OnDblClick: TNotifyEvent; read write;
    end;

    TCheckItemOperation = (coUncheck, coCheck, coCheckWithChildren);

    TNewCheckListBox = class(TCustomListBox)
      function AddCheckBox(const ACaption, ASubItem: String; ALevel: Byte; AChecked, AEnabled, AHasInternalChildren, ACheckWhenParentChecked: Boolean; AObject: TObject): Integer;
      function AddGroup(ACaption, ASubItem: String; ALevel: Byte; AObject: TObject): Integer;
      function AddRadioButton(const ACaption, ASubItem: String; ALevel: Byte; AChecked, AEnabled: Boolean; AObject: TObject): Integer;
      function CheckItem(const Index: Integer; const AOperation: TCheckItemOperation): Boolean;
      property Anchors: TAnchors; read write;
      property Checked[Index: Integer]: Boolean; read write;
      property State[Index: Integer]: TCheckBoxState; read write;
      property ItemCaption[Index: Integer]: String; read write;
      property ItemEnabled[Index: Integer]: Boolean; read write;
      property ItemFontStyle[Index: Integer]: TFontStyles; read write;
      property ItemLevel[Index: Integer]: Byte; read;
      property ItemObject[Index: Integer]: TObject; read write;
      property ItemSubItem[Index: Integer]: String; read write;
      property SubItemFontStyle[Index: Integer]: TFontStyles; read write;
      property Flat: Boolean; read write;
      property MinItemHeight: Integer; read write;
      property Offset: Integer; read write;
      property OnClickCheck: TNotifyEvent; read write;
      property BorderStyle: TBorderStyle; read write;
      property Color: TColor; read write;
      property Font: TFont; read write;
      property Sorted: Boolean; read write;
      property OnClick: TNotifyEvent; read write;
      property OnDblClick: TNotifyEvent; read write;
      property OnKeyDown: TKeyEvent; read write;
      property OnKeyPress: TKeyPressEvent; read write;
      property OnKeyUp: TKeyEvent; read write;
      property ShowLines: Boolean; read write;
      property WantTabs: Boolean; read write;
      property RequireRadioSelection: Boolean; read write;
    end;

    TNewProgressBarState = (npbsNormal, npbsError, npbsPaused);

    TNewProgressBarStyle = (npbstNormal, npbstMarquee);

    TNewProgressBar = class(TWinControl)
      property Anchors: TAnchors; read write;
      property Min: Longint; read write;
      property Max: Longint; read write;
      property Position: Longint; read write;
      property State: TNewProgressBarState; read write;
      property Style: TNewProgressBarStyle; read write;
      property Visible: Boolean; read write;
    end;

    TRichEditViewer = class(TMemo)
      property Anchors: TAnchors; read write;
      property BevelKind: TBevelKind; read write;
      property BorderStyle: TBorderStyle; read write;
      property RTFText: AnsiString; write;
      property UseRichEdit: Boolean; read write;
    end;

    TPasswordEdit = class(TCustomEdit)
      property Anchors: TAnchors; read write;
      property AutoSelect: Boolean; read write;
      property AutoSize: Boolean; read write;
      property BorderStyle: TBorderStyle; read write;
      property Color: TColor; read write;
      property Font: TFont; read write;
      property HideSelection: Boolean; read write;
      property MaxLength: Integer; read write;
      property Password: Boolean; read write;
      property ReadOnly: Boolean; read write;
      property Text: String; read write;
      property OnChange: TNotifyEvent; read write;
      property OnClick: TNotifyEvent; read write;
      property OnDblClick: TNotifyEvent; read write;
      property OnKeyDown: TKeyEvent; read write;
      property OnKeyPress: TKeyPressEvent; read write;
      property OnKeyUp: TKeyEvent; read write;
    end;

    TCustomFolderTreeView = class(TWinControl)
      procedure ChangeDirectory(const Value: String; const CreateNewItems: Boolean);
      procedure CreateNewDirectory(const ADefaultName: String);
      property Directory: String; read write;
    end;

    TFolderRenameEvent = procedure(Sender: TCustomFolderTreeView; var NewName: String; var Accept: Boolean);

    TFolderTreeView = class(TCustomFolderTreeView)
      property Anchors: TAnchors; read write;
      property OnChange: TNotifyEvent; read write;
      property OnRename: TFolderRenameEvent; read write;
    end;

    TStartMenuFolderTreeView = class(TCustomFolderTreeView)
      procedure SetPaths(const AUserPrograms, ACommonPrograms, AUserStartup, ACommonStartup: String);
      property Anchors: TAnchors; read write;
      property OnChange: TNotifyEvent; read write;
      property OnRename: TFolderRenameEvent; read write;
    end;

    TBitmapImage = class(TGraphicControl)
      property Anchors: TAnchors; read write;
      property AutoSize: Boolean; read write;
      property BackColor: TColor; read write;
      property Center: Boolean; read write;
      property Bitmap: TBitmap; read write;
      property ReplaceColor: TColor; read write;
      property ReplaceWithColor: TColor; read write;
      property Stretch: Boolean; read write;
      property OnClick: TNotifyEvent; read write;
      property OnDblClick: TNotifyEvent; read write;
    end;

    TNewNotebook = class(TWinControl)
      function FindNextPage(CurPage: TNewNotebookPage; GoForward: Boolean): TNewNotebookPage;
      property Anchors: TAnchors; read write;
      property PageCount: Integer; read write;
      property Pages[Index: Integer]: TNewNotebookPage; read;
      property ActivePage: TNewNotebookPage; read write;
    end;

    TNewNotebookPage = class(TCustomControl)
      property Color: TColor; read write;
      property Notebook: TNewNotebook; read write;
      property PageIndex: Integer; read write;
    end;

    TWizardPageNotifyEvent = procedure(Sender: TWizardPage);
    TWizardPageButtonEvent = function(Sender: TWizardPage): Boolean;
    TWizardPageCancelEvent = procedure(Sender: TWizardPage; var ACancel, AConfirm: Boolean);
    TWizardPageShouldSkipEvent = function(Sender: TWizardPage): Boolean;

    TWizardPage = class(TComponent)
      property ID: Integer; read;
      property Caption: String; read write;
      property Description: String; read write;
      property Surface: TNewNotebookPage; read;
      property SurfaceColor: TColor; read;
      property SurfaceHeight: Integer; read;
      property SurfaceWidth: Integer; read;
      property OnActivate: TWizardPageNotifyEvent; read write;
      property OnBackButtonClick: TWizardPageButtonEvent; read write;
      property OnCancelButtonClick: TWizardPageCancelEvent; read write;
      property OnNextButtonClick: TWizardPageButtonEvent; read write;
      property OnShouldSkipPage: TWizardPageShouldSkipEvent; read write;
    end;

    TInputQueryWizardPage = class(TWizardPage)
      function Add(const APrompt: String; const APassword: Boolean): Integer;
      property Edits[Index: Integer]: TPasswordEdit; read;
      property PromptLabels[Index: Integer]: TNewStaticText; read;
      property SubCaptionLabel: TNewStaticText; read;
      property Values[Index: Integer]: String; read write;
    end;

    TInputOptionWizardPage = class(TWizardPage)
      function Add(const ACaption: String): Integer;
      function AddEx(const ACaption: String; const ALevel: Byte; const AExclusive: Boolean): Integer;
      property CheckListBox: TNewCheckListBox; read;
      property SelectedValueIndex: Integer; read write;
      property SubCaptionLabel: TNewStaticText; read;
      property Values[Index: Integer]: Boolean; read write;
    end;

    TInputDirWizardPage = class(TWizardPage)
      function Add(const APrompt: String): Integer;
      property Buttons[Index: Integer]: TNewButton; read;
      property Edits[Index: Integer]: TEdit; read;
      property NewFolderName: String; read write;
      property PromptLabels[Index: Integer]: TNewStaticText; read;
      property SubCaptionLabel: TNewStaticText; read;
      property Values[Index: Integer]: String; read write;
    end;

    TInputFileWizardPage = class(TWizardPage)
      function Add(const APrompt, AFilter, ADefaultExtension: String): Integer;
      property Buttons[Index: Integer]: TNewButton; read;
      property Edits[Index: Integer]: TEdit; read;
      property PromptLabels[Index: Integer]: TNewStaticText; read;
      property SubCaptionLabel: TNewStaticText; read;
      property Values[Index: Integer]: String; read write;
      property IsSaveButton[Index: Integer]: Boolean; read write;
    end;

    TOutputMsgWizardPage = class(TWizardPage)
      property MsgLabel: TNewStaticText; read;
    end;

    TOutputMsgMemoWizardPage = class(TWizardPage)
      property RichEditViewer: TRichEditViewer; read;
      property SubCaptionLabel: TNewStaticText; read;
    end;

    TOutputProgressWizardPage = class(TWizardPage)
      procedure Hide;
      property Msg1Label: TNewStaticText; read;
      property Msg2Label: TNewStaticText; read;
      property ProgressBar: TNewProgressBar; read;
      procedure SetProgress(const Position, Max: Longint);
      procedure SetText(const Msg1, Msg2: String);
      procedure Show;
    end;

    TOutputMarqueeProgressWizardPage = class(TOutputProgressWizardPage)
      procedure Animate;
    end;

    TDownloadWizardPage = class(TOutputProgressWizardPage)
      property AbortButton: TNewButton; read;
      property AbortedByUser: Boolean; read;
      procedure Add(const Url, BaseName, RequiredSHA256OfFile: String);
      procedure AddEx(const Url, BaseName, RequiredSHA256OfFile, UserName, Password: String);
      procedure Clear;
      function Download: Int64;
      property ShowBaseNameInsteadOfUrl: Boolean; read write;
    end;

    TExtractionWizardPage = class(TOutputProgressWizardPage)
      property AbortButton: TNewButton; read;
      property AbortedByUser: Boolean; read;
      procedure Add(const ArchiveFileName, DestDir: String; const FullPaths: Boolean);
      procedure Clear;
      procedure Extract;
      property ShowArchiveInsteadOfFile: Boolean; read write;
    end;

    TUIStateForm = class(TForm)
    end;

    TSetupForm = class(TUIStateForm)
      function CalculateButtonWidth(const ButtonCaptions: array of String): Integer;
      function ShouldSizeX: Boolean;
      function ShouldSizeY: Boolean;
      procedure FlipSizeAndCenterIfNeeded(const ACenterInsideControl: Boolean; const CenterInsideControlCtl: TWinControl; const CenterInsideControlInsideClientArea: Boolean);
      property ControlsFlipped: Boolean; read;
      property FlipControlsOnShow: Boolean; read write;
      property KeepSizeY: Boolean; read; write;
      property RightToLeft: Boolean; read;
      property SizeAndCenterOnShow: Boolean; read write;
    end;

    TWizardForm = class(TSetupForm)
      property CancelButton: TNewButton; read;
      property NextButton: TNewButton; read;
      property BackButton: TNewButton; read;
      property OuterNotebook: TNotebook; read;
      property InnerNotebook: TNotebook; read;
      property WelcomePage: TNewNotebookPage; read;
      property InnerPage: TNewNotebookPage; read;
      property FinishedPage: TNewNotebookPage; read;
      property LicensePage: TNewNotebookPage; read;
      property PasswordPage: TNewNotebookPage; read;
      property InfoBeforePage: TNewNotebookPage; read;
      property UserInfoPage: TNewNotebookPage; read;
      property SelectDirPage: TNewNotebookPage; read;
      property SelectComponentsPage: TNewNotebookPage; read;
      property SelectProgramGroupPage: TNewNotebookPage; read;
      property SelectTasksPage: TNewNotebookPage; read;
      property ReadyPage: TNewNotebookPage; read;
      property PreparingPage: TNewNotebookPage; read;
      property InstallingPage: TNewNotebookPage; read;
      property InfoAfterPage: TNewNotebookPage; read;
      property DiskSpaceLabel: TNewStaticText; read;
      property DirEdit: TEdit; read;
      property GroupEdit: TNewEdit; read;
      property NoIconsCheck: TNewCheckBox; read;
      property PasswordLabel: TNewStaticText; read;
      property PasswordEdit: TPasswordEdit; read;
      property PasswordEditLabel: TNewStaticText; read;
      property ReadyMemo: TNewMemo; read;
      property TypesCombo: TNewComboBox; read;
      property Bevel: TBevel; read;
      property WizardBitmapImage: TBitmapImage; read;
      property WelcomeLabel1: TNewStaticText; read;
      property InfoBeforeMemo: TRichEditViewer; read;
      property InfoBeforeClickLabel: TNewStaticText; read;
      property MainPanel: TPanel; read;
      property Bevel1: TBevel; read;
      property PageNameLabel: TNewStaticText; read;
      property PageDescriptionLabel: TNewStaticText; read;
      property WizardSmallBitmapImage: TBitmapImage; read;
      property ReadyLabel: TNewStaticText; read;
      property FinishedLabel: TNewStaticText; read;
      property YesRadio: TNewRadioButton; read;
      property NoRadio: TNewRadioButton; read;
      property WizardBitmapImage2: TBitmapImage; read;
      property WelcomeLabel2: TNewStaticText; read;
      property LicenseLabel1: TNewStaticText; read;
      property LicenseMemo: TRichEditViewer; read;
      property InfoAfterMemo: TRichEditViewer; read;
      property InfoAfterClickLabel: TNewStaticText; read;
      property ComponentsList: TNewCheckListBox; read;
      property ComponentsDiskSpaceLabel: TNewStaticText; read;
      property BeveledLabel: TNewStaticText; read;
      property StatusLabel: TNewStaticText; read;
      property FilenameLabel: TNewStaticText; read;
      property ProgressGauge: TNewProgressBar; read;
      property SelectDirLabel: TNewStaticText; read;
      property SelectStartMenuFolderLabel: TNewStaticText; read;
      property SelectComponentsLabel: TNewStaticText; read;
      property SelectTasksLabel: TNewStaticText; read;
      property LicenseAcceptedRadio: TNewRadioButton; read;
      property LicenseNotAcceptedRadio: TNewRadioButton; read;
      property UserInfoNameLabel: TNewStaticText; read;
      property UserInfoNameEdit: TNewEdit; read;
      property UserInfoOrgLabel: TNewStaticText; read;
      property UserInfoOrgEdit: TNewEdit; read;
      property PreparingErrorBitmapImage: TBitmapImage; read;
      property PreparingLabel: TNewStaticText; read;
      property FinishedHeadingLabel: TNewStaticText; read;
      property UserInfoSerialLabel: TNewStaticText; read;
      property UserInfoSerialEdit: TNewEdit; read;
      property TasksList: TNewCheckListBox; read;
      property RunList: TNewCheckListBox; read;
      property DirBrowseButton: TNewButton; read;
      property GroupBrowseButton: TNewButton; read;
      property SelectDirBitmapImage: TBitmapImage; read;
      property SelectGroupBitmapImage: TBitmapImage; read;
      property SelectDirBrowseLabel: TNewStaticText; read;
      property SelectStartMenuFolderBrowseLabel: TNewStaticText; read;
      property PreparingYesRadio: TNewRadioButton; read;
      property PreparingNoRadio: TNewRadioButton; read;
      property PreparingMemo: TNewMemo; read;
      property CurPageID: Integer; read;
      function AdjustLabelHeight(ALabel: TNewStaticText): Integer;
      function AdjustLinkLabelHeight(ALinkLabel: TNewLinkLabel): Integer;
      procedure IncTopDecHeight(AControl: TControl; Amount: Integer);
      property PrevAppDir: String; read;
    end;

    TUninstallProgressForm = class(TSetupForm)
      property OuterNotebook: TNewNotebook; read;
      property InnerPage: TNewNotebookPage; read;
      property InnerNotebook: TNewNotebook; read;
      property InstallingPage: TNewNotebookPage; read;
      property MainPanel: TPanel; read;
      property PageNameLabel: TNewStaticText; read;
      property PageDescriptionLabel: TNewStaticText; read;
      property WizardSmallBitmapImage: TBitmapImage; read;
      property Bevel1: TBevel; read;
      property StatusLabel: TNewStaticText; read;
      property ProgressBar: TNewProgressBar; read;
      property BeveledLabel: TNewStaticText; read;
      property Bevel: TBevel; read;
      property CancelButton: TNewButton; read;
    end;
    """


IFPSEventDescriptions = {
    parse_function('function InitializeSetup(): Boolean'): (
        'Called during Setup initialization. Return False to abort Setup, True otherwise.'
    ),
    parse_function('procedure InitializeWizard()'): (
        'Initial changes to the wizard or wizard pages at startup.'
    ),
    parse_function('procedure DeinitializeSetup()'): (
        'Called just before Setup terminates.'
    ),
    parse_function('procedure CurStepChanged(CurStep: TSetupStep)'): (
        'Used for pre-install and post-install tasks.'
    ),
    parse_function('procedure CurInstallProgressChanged(CurProgress, MaxProgress: Integer)'): (
        'Event function to monitor progress while Setup is extracting files.'
    ),
    parse_function('function NextButtonClick(PageID: Integer): Boolean'): (
        'Triggered when the setup step is advanced.'
    ),
    parse_function('function BackButtonClick(PageID: Integer): Boolean'): (
        'Called when the user navigates to the previous installation step.'
    ),
    parse_function('procedure CancelButtonClick(PageID: Integer; var Cancel, Confirm: Boolean)'): (
        'Called when the user clicks the Cancel button or closes the installer window.'
    ),
    parse_function('function ShouldSkipPage(PageID: Integer): Boolean'): (
        'The wizard calls this event function to determine whether or not a particular page should '
        'be shown at all.'
    ),
    parse_function('procedure CurPageChanged(PageID: Integer)'): (
        'Called after a new wizard page (specified by PageID) is shown.'
    ),
    parse_function('function CheckPassword(Password: String): Boolean'): (
        'If Setup finds the CheckPassword event function in the Pascal script, it automatically '
        'displays the Password page and calls CheckPassword to check passwords. Returns True to '
        'accept the password and False to reject it.'
    ),
    parse_function('function NeedRestart(): Boolean'): (
        'Returns True to instruct Setup to prompt the user to restart the system at the end of a'
        ' successful installation, False otherwise.'
    ),
    parse_function(
        'function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,'
        ' MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String'
    ): (
        'If Setup finds this event function in the Pascal script, it is called automatically when '
        'the Ready to Install wizard page becomes the active page. It should return the text to '
        'be displayed in the settings memo on the Ready to Install wizard page as a single string '
        'with lines separated by the NewLine parameter. Parameter Space contains a string with '
        'spaces.'
    ),
    parse_function('procedure RegisterPreviousData(PreviousDataKey: Integer)'): (
        'Used to store user settings entered on custom wizard pages.'
    ),
    parse_function('function CheckSerial(Serial: String): Boolean'): (
        'Returns True to accept a serial number and False to reject it.'
    ),
    parse_function('function GetCustomSetupExitCode: Integer'): (
        'Returns a number to instruct Setup to return a custom exit code.'
    ),
    parse_function('function PrepareToInstall(var NeedsRestart: Boolean): String'): (
        'Event function which detects and installs missing prerequisites and/or to shutdown any '
        'application which is about to be updated.'
    ),
    parse_function('procedure RegisterExtraCloseApplicationsResources'): (
        'Used to register extra files which Setup should check for being in-use.'
    ),
    parse_function('function InitializeUninstall(): Boolean'): (
        'Returns False to abort Uninstall, True otherwise.'
    ),
    parse_function('procedure InitializeUninstallProgressForm()'): (
        'Event function to make changes to the progress form at startup.'
    ),
    parse_function('procedure DeinitializeUninstall()'): (
        'Called just before uninstall terminates.'
    ),
    parse_function('procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep)'): (
        'Used for pre-uninstall and post-uninstall tasks.'
    ),
    parse_function('function UninstallNeedRestart(): Boolean'): (
        'Returns True to instruct Uninstall to prompt the user to restart the system at the end of'
        ' a successful uninstallation, False otherwise.'
    )
}

IFPSEvents = CaseInsensitiveDict()

for sig in IFPSEventDescriptions:
    IFPSEvents[sig.name] = sig
