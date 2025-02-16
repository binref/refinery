#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Contains a library of known external function symbols for the IFPS runtime in InnoSetup installers.
"""
from __future__ import annotations

from typing import NamedTuple, Optional

import dataclasses
import inspect
import re


class IFPSParam(NamedTuple):
    name: str
    type: Optional[str]
    const: bool


@dataclasses.dataclass
class IFPSSignature:
    name: str
    parameters: list[IFPSParam]
    return_type: Optional[str]
    void: bool


class ParsingError(RuntimeError):
    def __init__(self, symbol: str, what: str):
        super().__init__(F'{what}: {symbol}')


def _parse(cls):
    symbols: dict[str, IFPSSignature] = {}
    for symbol in inspect.cleandoc(inspect.getdoc(cls)).splitlines(False):
        parts = re.fullmatch(r'''(?x)
            (?P<void>function|procedure)
              \s(?P<name>\w+)
           (?:\((?P<args>.*?)\))?
          (?::\s(?P<type>\w+))?;
        ''', symbol)
        if parts is None:
            raise ParsingError(symbol, 'Failed to parse')
        parts = parts.groupdict()
        name = parts['name']
        void = parts['void'] == 'procedure'
        type = parts['type']
        args = []
        if a := parts['args']:
            for group in a.split(';'):
                group, _, at = group.strip().partition(': ')
                kind, _, tmp = group.strip().partition(' ')
                if kind in {'var', 'const'}:
                    group = tmp
                for part in group.split(','):
                    args.append(IFPSParam(part.strip(), at.strip() or None, kind != 'var'))
        if (type is None) != (void is True):
            raise ParsingError(symbol, 'Conflicting voidness')
        symbols[name.casefold()] = IFPSSignature(name, args, type, void)
    return symbols


@_parse
class IFPS_SYMBOLS:
    """
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
