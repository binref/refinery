"""
Shared utilities for PowerShell deobfuscation transforms.
"""
from __future__ import annotations

import io
import re

from refinery.lib.scripts import Block, Node
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AccessKind,
    Ps1ArrayLiteral,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1HereString,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1ParenExpression,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1TypeExpression,
    Ps1Variable,
)

_KNOWN_ALIAS = {
    'ac'      : 'Add-Content',
    'cat'     : 'Get-Content',
    'cd'      : 'Set-Location',
    'chdir'   : 'Set-Location',
    'childitem': 'Get-ChildItem',
    'clc'     : 'Clear-Content',
    'clear'   : 'Clear-Host',
    'clhy'    : 'Clear-History',
    'cli'     : 'Clear-Item',
    'clp'     : 'Clear-ItemProperty',
    'cls'     : 'Clear-Host',
    'clv'     : 'Clear-Variable',
    'cnsn'    : 'Connect-PSSession',
    'compare' : 'Compare-Object',
    'copy'    : 'Copy-Item',
    'cp'      : 'Copy-Item',
    'cpi'     : 'Copy-Item',
    'cpp'     : 'Copy-ItemProperty',
    'cvpa'    : 'Convert-Path',
    'dbp'     : 'Disable-PSBreakpoint',
    'del'     : 'Remove-Item',
    'diff'    : 'Compare-Object',
    'dir'     : 'Get-ChildItem',
    'dnsn'    : 'Disconnect-PSSession',
    'ebp'     : 'Enable-PSBreakpoint',
    'echo'    : 'Write-Output',
    'epal'    : 'Export-Alias',
    'epcsv'   : 'Export-Csv',
    'erase'   : 'Remove-Item',
    'etsn'    : 'Enter-PSSession',
    'exsn'    : 'Exit-PSSession',
    'fc'      : 'Format-Custom',
    'fhx'     : 'Format-Hex',
    'fl'      : 'Format-List',
    'foreach' : 'ForEach-Object',
    'ft'      : 'Format-Table',
    'fw'      : 'Format-Wide',
    'gal'     : 'Get-Alias',
    'gbp'     : 'Get-PSBreakpoint',
    'gc'      : 'Get-Content',
    'gci'     : 'Get-ChildItem',
    'gcm'     : 'Get-Command',
    'gcs'     : 'Get-PSCallStack',
    'gdr'     : 'Get-PSDrive',
    'gerr'    : 'Get-Error',
    'ghy'     : 'Get-History',
    'gi'      : 'Get-Item',
    'gjb'     : 'Get-Job',
    'gl'      : 'Get-Location',
    'gm'      : 'Get-Member',
    'gmo'     : 'Get-Module',
    'gp'      : 'Get-ItemProperty',
    'gps'     : 'Get-Process',
    'gpv'     : 'Get-ItemPropertyValue',
    'group'   : 'Group-Object',
    'gsn'     : 'Get-PSSession',
    'gsv'     : 'Get-Service',
    'gu'      : 'Get-Unique',
    'gv'      : 'Get-Variable',
    'h'       : 'Get-History',
    'history' : 'Get-History',
    'icm'     : 'Invoke-Command',
    'iex'     : 'Invoke-Expression',
    'ihy'     : 'Invoke-History',
    'ii'      : 'Invoke-Item',
    'ipal'    : 'Import-Alias',
    'ipcsv'   : 'Import-Csv',
    'ipmo'    : 'Import-Module',
    'irm'     : 'Invoke-RestMethod',
    'iwr'     : 'Invoke-WebRequest',
    'item'    : 'Get-Item',
    'kill'    : 'Stop-Process',
    'ls'      : 'Get-ChildItem',
    'man'     : 'help',
    'md'      : 'mkdir',
    'measure' : 'Measure-Object',
    'member'  : 'Get-Member',
    'mi'      : 'Move-Item',
    'mount'   : 'New-PSDrive',
    'move'    : 'Move-Item',
    'mp'      : 'Move-ItemProperty',
    'mv'      : 'Move-Item',
    'nal'     : 'New-Alias',
    'ndr'     : 'New-PSDrive',
    'ni'      : 'New-Item',
    'nmo'     : 'New-Module',
    'nsn'     : 'New-PSSession',
    'nv'      : 'New-Variable',
    'ogv'     : 'Out-GridView',
    'oh'      : 'Out-Host',
    'popd'    : 'Pop-Location',
    'ps'      : 'Get-Process',
    'pushd'   : 'Push-Location',
    'pwd'     : 'Get-Location',
    'r'       : 'Invoke-History',
    'rbp'     : 'Remove-PSBreakpoint',
    'rcjb'    : 'Receive-Job',
    'rcsn'    : 'Receive-PSSession',
    'rd'      : 'Remove-Item',
    'rdr'     : 'Remove-PSDrive',
    'ren'     : 'Rename-Item',
    'ri'      : 'Remove-Item',
    'rjb'     : 'Remove-Job',
    'rm'      : 'Remove-Item',
    'rmdir'   : 'Remove-Item',
    'rmo'     : 'Remove-Module',
    'rni'     : 'Rename-Item',
    'rnp'     : 'Rename-ItemProperty',
    'rp'      : 'Remove-ItemProperty',
    'rsn'     : 'Remove-PSSession',
    'rv'      : 'Remove-Variable',
    'rvpa'    : 'Resolve-Path',
    'sajb'    : 'Start-Job',
    'sal'     : 'Set-Alias',
    'saps'    : 'Start-Process',
    'sasv'    : 'Start-Service',
    'sbp'     : 'Set-PSBreakpoint',
    'select'  : 'Select-Object',
    'set'     : 'Set-Variable',
    'shcm'    : 'Show-Command',
    'si'      : 'Set-Item',
    'sl'      : 'Set-Location',
    'sleep'   : 'Start-Sleep',
    'sls'     : 'Select-String',
    'sort'    : 'Sort-Object',
    'sp'      : 'Set-ItemProperty',
    'spjb'    : 'Stop-Job',
    'spps'    : 'Stop-Process',
    'spsv'    : 'Stop-Service',
    'start'   : 'Start-Process',
    'sv'      : 'Set-Variable',
    'tee'     : 'Tee-Object',
    'type'    : 'Get-Content',
    'variable': 'Get-Variable',
    'where'   : 'Where-Object',
    'wjb'     : 'Wait-Job',
    'write'   : 'Write-Output',
}

_KNOWN_NAMES = {name.lower(): name for name in [
    # powershell.exe command-line parameters
    '-Command',
    '-EncodedCommand',
    '-Exec Bypass',
    '-ExecutionPolicy',
    '-File',
    '-InputFormat',
    '-NoExit',
    '-NoLogo',
    '-NoProfile',
    '-NonInter',
    '-OutputFormat',
    '-Sta',
    '-Version',
    '-Windows Hidden',
    '-WindowStyle',
    # operators
    '-As',
    '-BAnd',
    '-BNot',
    '-BOr',
    '-BXor',
    '-Contains',
    '-CReplace',
    '-Eq',
    '-GE',
    '-GT',
    '-IReplace',
    '-In',
    '-Is',
    '-IsNot',
    '-Join',
    '-LE',
    '-Like',
    '-LT',
    '-Match',
    '-NE',
    '-Not',
    '-NotContains',
    '-NotIn',
    '-NotLike',
    '-NotMatch',
    '-Replace',
    '-Shl',
    '-Shr',
    '-Split',
    '-XOr',
    # cmdlets
    'Add-Member',
    'Add-Type',
    'ConvertFrom-Base64',
    'ConvertFrom-Json',
    'ConvertFrom-SecureString',
    'ConvertFrom-StringData',
    'ConvertTo-Html',
    'ConvertTo-Json',
    'ConvertTo-SecureString',
    'Disable-PSRemoting',
    'Enable-PSRemoting',
    'Export-Clixml',
    'Get-Acl',
    'Get-CimInstance',
    'Get-Clipboard',
    'Get-Credential',
    'Get-Culture',
    'Get-Date',
    'Get-EventLog',
    'Get-ExecutionPolicy',
    'Get-Host',
    'Get-NetAdapter',
    'Get-NetIPAddress',
    'Get-Random',
    'Get-WinEvent',
    'Get-WmiObject',
    'Import-Clixml',
    'Invoke-CimMethod',
    'Invoke-WmiMethod',
    'Join-Path',
    'Measure-Command',
    'New-Object',
    'New-ScheduledTask',
    'New-Service',
    'New-TimeSpan',
    'Out-File',
    'Out-Null',
    'Out-String',
    'Read-Host',
    'Register-ObjectEvent',
    'Register-ScheduledTask',
    'Resolve-DnsName',
    'Restart-Computer',
    'Restart-Service',
    'Send-MailMessage',
    'Set-Acl',
    'Set-Clipboard',
    'Set-Content',
    'Set-ExecutionPolicy',
    'Set-StrictMode',
    'Split-Path',
    'Start-BitsTransfer',
    'Start-Transcript',
    'Stop-Computer',
    'Stop-Transcript',
    'Test-Connection',
    'Test-NetConnection',
    'Test-Path',
    'Unblock-File',
    'Unregister-ScheduledTask',
    'Update-Help',
    'Wait-Process',
    'Write-Debug',
    'Write-Error',
    'Write-Host',
    'Write-Progress',
    'Write-Verbose',
    'Write-Warning',
    # WMI class names
    'Win32_BaseBoard',
    'Win32_BIOS',
    'Win32_ComputerSystem',
    'Win32_ComputerSystemProduct',
    'Win32_DiskDrive',
    'Win32_LogicalDisk',
    'Win32_NetworkAdapter',
    'Win32_NetworkAdapterConfiguration',
    'Win32_OperatingSystem',
    'Win32_PhysicalMemory',
    'Win32_Process',
    'Win32_Processor',
    'Win32_Product',
    'Win32_Service',
    'Win32_Share',
    'Win32_SystemEnclosure',
    'Win32_UserAccount',
    'Win32_VideoController',
    # .NET type names (short)
    'Array',
    'BitConverter',
    'Boolean',
    'Byte',
    'Char',
    'Console',
    'Convert',
    'DateTime',
    'Decimal',
    'Double',
    'Enum',
    'Environment',
    'EventArgs',
    'Exception',
    'ExecutionContext',
    'Guid',
    'Hashtable',
    'Int16',
    'Int32',
    'Int64',
    'IntPtr',
    'Math',
    'Object',
    'Random',
    'Regex',
    'SByte',
    'Single',
    'String',
    'TimeSpan',
    'UInt16',
    'UInt32',
    'UInt64',
    'UIntPtr',
    'Uri',
    'Version',
    'Void',
    # .NET type names (namespace-qualified)
    'Collections.ArrayList',
    'Collections.Generic.Dictionary',
    'Collections.Generic.HashSet',
    'Collections.Generic.List',
    'Collections.Hashtable',
    'Collections.ObjectModel.Collection',
    'Collections.Queue',
    'Collections.SortedList',
    'Collections.Specialized.OrderedDictionary',
    'Collections.Stack',
    'ComponentModel.Win32Exception',
    'Diagnostics.Process',
    'Diagnostics.ProcessStartInfo',
    'Drawing.Bitmap',
    'Drawing.Graphics',
    'Drawing.Image',
    'Globalization.CultureInfo',
    'IO.BinaryReader',
    'IO.BinaryWriter',
    'IO.Compression.CompressionMode',
    'IO.Compression.DeflateStream',
    'IO.Compression.GZipStream',
    'IO.Compression.ZipFile',
    'IO.Directory',
    'IO.DirectoryInfo',
    'IO.File',
    'IO.FileInfo',
    'IO.FileMode',
    'IO.FileStream',
    'IO.MemoryStream',
    'IO.Path',
    'IO.Stream',
    'IO.StreamReader',
    'IO.StreamWriter',
    'IO.StringReader',
    'IO.StringWriter',
    'Management.Automation.PSCredential',
    'Management.Automation.ScriptBlock',
    'Management.Automation.SessionStateInternal',
    'Management.ManagementObject',
    'Management.ManagementObjectSearcher',
    'Net.CredentialCache',
    'Net.Dns',
    'Net.HttpWebRequest',
    'Net.HttpWebResponse',
    'Net.IPAddress',
    'Net.IPEndPoint',
    'Net.Mail.MailMessage',
    'Net.Mail.SmtpClient',
    'Net.NetworkCredential',
    'Net.Security.SslStream',
    'Net.SecurityProtocolType',
    'Net.ServicePointManager',
    'Net.Sockets.NetworkStream',
    'Net.Sockets.TcpClient',
    'Net.Sockets.TcpListener',
    'Net.Sockets.UdpClient',
    'Net.WebClient',
    'Net.WebProxy',
    'Net.WebRequest',
    'Reflection.Assembly',
    'Reflection.AssemblyName',
    'Reflection.BindingFlags',
    'Reflection.Emit.AssemblyBuilderAccess',
    'Runtime.InteropServices.DllImportAttribute',
    'Runtime.InteropServices.Marshal',
    'Runtime.InteropServices.RuntimeEnvironment',
    'Security.AccessControl.FileSystemAccessRule',
    'Security.Cryptography.AesCryptoServiceProvider',
    'Security.Cryptography.AesManaged',
    'Security.Cryptography.CipherMode',
    'Security.Cryptography.CryptoStream',
    'Security.Cryptography.CryptoStreamMode',
    'Security.Cryptography.DESCryptoServiceProvider',
    'Security.Cryptography.HMACMD5',
    'Security.Cryptography.HMACSHA1',
    'Security.Cryptography.HMACSHA256',
    'Security.Cryptography.ICryptoTransform',
    'Security.Cryptography.MD5',
    'Security.Cryptography.MD5CryptoServiceProvider',
    'Security.Cryptography.PaddingMode',
    'Security.Cryptography.RNGCryptoServiceProvider',
    'Security.Cryptography.RSA',
    'Security.Cryptography.RSACryptoServiceProvider',
    'Security.Cryptography.RijndaelManaged',
    'Security.Cryptography.SHA1',
    'Security.Cryptography.SHA1Managed',
    'Security.Cryptography.SHA256',
    'Security.Cryptography.SHA256Managed',
    'Security.Cryptography.SHA384',
    'Security.Cryptography.SHA512',
    'Security.Cryptography.SymmetricAlgorithm',
    'Security.Cryptography.TripleDESCryptoServiceProvider',
    'Security.Cryptography.X509Certificates.X509Certificate2',
    'Security.Principal.WindowsBuiltInRole',
    'Security.Principal.WindowsIdentity',
    'Security.Principal.WindowsPrincipal',
    'Security.SecureString',
    'ServiceProcess.ServiceController',
    'Text.ASCIIEncoding',
    'Text.Encoding',
    'Text.RegularExpressions.Regex',
    'Text.RegularExpressions.RegexOptions',
    'Text.StringBuilder',
    'Text.UTF8Encoding',
    'Threading.Mutex',
    'Threading.Thread',
    'Threading.Timer',
    'Xml.XmlDocument',
    'Add',
    'AddArgument',
    'AddScript',
    'AppendText',
    'Clone',
    'Close',
    'CompareTo',
    'ComputeHash',
    'Contains',
    'ConvertAll',
    'Copy',
    'CopyTo',
    'Create',
    'CreateDecryptor',
    'CreateEncryptor',
    'CreateInstance',
    'CreateSubKey',
    'Decompress',
    'Decrypt',
    'DefineDynamicAssembly',
    'DefineDynamicModule',
    'DefineEnum',
    'DefineLiteral',
    'DefinePInvokeMethod',
    'DefineType',
    'Delete',
    'DeleteSubKey',
    'DeleteValue',
    'Dispose',
    'DownloadData',
    'DownloadFile',
    'DownloadString',
    'Encrypt',
    'EndsWith',
    'Equals',
    'Exists',
    'Flush',
    'Format',
    'FromBase64String',
    'GetBytes',
    'GetBuffer',
    'GetChars',
    'GetConstructor',
    'GetCurrentProcess',
    'GetDomain',
    'GetEnumerator',
    'GetEnvironmentVariable',
    'GetField',
    'GetFolderPath',
    'GetHashCode',
    'GetHostAddresses',
    'GetHostByName',
    'GetHostEntry',
    'GetHostName',
    'GetKeyNames',
    'GetMethod',
    'GetMethods',
    'GetModuleHandle',
    'GetProcAddress',
    'GetProcesses',
    'GetProcessesByName',
    'GetProperties',
    'GetProperty',
    'GetResponse',
    'GetResponseStream',
    'GetStream',
    'GetString',
    'GetTempFileName',
    'GetTempPath',
    'GetType',
    'GetTypeFromCLSID',
    'GetTypes',
    'GetValue',
    'GetValueNames',
    'IndexOf',
    'Insert',
    'InvokeCommand',
    'Invoke',
    'IsMatch',
    'IsNullOrEmpty',
    'IsNullOrWhiteSpace',
    'Join',
    'Kill',
    'Load',
    'LoadFile',
    'LoadFrom',
    'LoadLibrary',
    'LoadWithPartialName',
    'Match',
    'Matches',
    'Move',
    'Open',
    'OpenKey',
    'OpenRead',
    'OpenSubKey',
    'OpenText',
    'PadLeft',
    'PadRight',
    'Parse',
    'PSObject',
    'Methods',
    'Peek',
    'Pop',
    'Push',
    'Read',
    'ReadAllBytes',
    'ReadAllLines',
    'ReadAllText',
    'ReadByte',
    'ReadLine',
    'ReadToEnd',
    'Remove',
    'Replace',
    'Reverse',
    'Seek',
    'SecurityProtocol',
    'ServerCertificateValidationCallback',
    'SetEnvironmentVariable',
    'SetValue',
    'ShellExecute',
    'Sleep',
    'Sort',
    'Split',
    'Start',
    'StartsWith',
    'Stop',
    'Substring',
    'ToArray',
    'ToBase64String',
    'ToBoolean',
    'ToByte',
    'ToChar',
    'ToCharArray',
    'ToDouble',
    'ToInt16',
    'ToInt32',
    'ToInt64',
    'ToLower',
    'ToSingle',
    'ToString',
    'ToUInt16',
    'ToUInt32',
    'ToUInt64',
    'ToUpper',
    'TransformBlock',
    'TransformFinalBlock',
    'Trim',
    'TrimEnd',
    'TrimStart',
    'TryParse',
    'UploadData',
    'UploadFile',
    'UploadString',
    'UploadValues',
    'Write',
    'WriteAllBytes',
    'WriteAllLines',
    'WriteAllText',
    'WriteByte',
    'WriteLine',
    # properties
    'ASCII',
    'Address',
    'Application',
    'Assembly',
    'BaseObject',
    'BaseStream',
    'BlockSize',
    'CanRead',
    'CanSeek',
    'CanWrite',
    'ChildItem',
    'Command',
    'ContentType',
    'Count',
    'Credentials',
    'Current',
    'CurrentDomain',
    'Data',
    'DefaultCredentials',
    'Definition',
    'DirectoryName',
    'Document',
    'EntryPoint',
    'ExitCode',
    'Extension',
    'FullName',
    'HasExited',
    'Headers',
    'Id',
    'Instance',
    'IsPresent',
    'Item',
    'IV',
    'Key',
    'Keys',
    'KeySize',
    'Length',
    'Location',
    'MainModule',
    'Members',
    'Message',
    'Method',
    'Mode',
    'Modules',
    'Name',
    'NonPublic',
    'OperatingSystem',
    'OsArchitecture',
    'Padding',
    'Parent',
    'Path',
    'Position',
    'PowerShell',
    'ProcessName',
    'ProcessorArchitecture',
    'Protocol',
    'Proxy',
    'PSVersionTable',
    'Public',
    'ResponseUri',
    'Result',
    'Size',
    'StandardOutput',
    'Ssl3',
    'Static',
    'StatusCode',
    'Text',
    'Tls',
    'Tls11',
    'Tls12',
    'Tls13',
    'UserAgent',
    'Value',
    'Values',
]}

for _name in list(_KNOWN_NAMES.values()):
    if '.' in _name:
        _full = F'System.{_name}'
        _KNOWN_NAMES[_full.lower()] = _full

for _a, _n in _KNOWN_ALIAS.items():
    _KNOWN_NAMES[_n.lower()] = _n

KEYWORD_SPELLING: dict[str, str] = {
    'param': 'Param',
}

SIMPLE_IDENTIFIER = re.compile(r'^[a-zA-Z_]\w*$')


def _string_value(node: Expression | None) -> str | None:
    if isinstance(node, Ps1StringLiteral):
        return node.value
    if isinstance(node, Ps1HereString):
        return node.value
    if isinstance(node, Ps1ExpandableString):
        out = io.StringIO()
        for p in node.parts:
            if not isinstance(p, Ps1StringLiteral):
                break
            out.write(p.value)
        else:
            return out.getvalue()
    if isinstance(node, Ps1SubExpression) and len(node.body) == 1:
        stmt = node.body[0]
        if isinstance(stmt, Ps1ExpressionStatement) and stmt.expression is not None:
            return _string_value(stmt.expression)
    return None


_BACKTICK_ENCODE = {
    '\x00': '`0',
    '\x07': '`a',
    '\x08': '`b',
    '\x09': '`t',
    '\x0A': '`n',
    '\x0B': '`v',
    '\x0C': '`f',
    '\x0D': '`r',
    '\x1B': '`e',
}
_NONPRINT_CONTROL = frozenset(_BACKTICK_ENCODE) - {'\n'}


def _make_string_literal(value: str) -> Ps1StringLiteral | Ps1HereString:
    has_newline = '\n' in value
    has_nonprint = any(c in value for c in _NONPRINT_CONTROL)
    if has_newline and not has_nonprint:
        raw = F"@'\n{value}\n'@"
        return Ps1HereString(value=value, raw=raw)
    if has_nonprint or has_newline:
        escaped = value.replace('`', '``').replace('"', '`"').replace('$', '`$')
        for ch, esc in _BACKTICK_ENCODE.items():
            escaped = escaped.replace(ch, esc)
        raw = F'"{escaped}"'
        return Ps1StringLiteral(value=value, raw=raw)
    if "'" not in value:
        raw = F"'{value}'"
    elif '"' not in value and '$' not in value and '`' not in value:
        raw = F'"{value}"'
    else:
        raw = "'" + value.replace("'", "''") + "'"
    return Ps1StringLiteral(value=value, raw=raw)


def _collect_string_arguments(node: Expression) -> list[str] | None:
    if isinstance(node, Ps1ArrayLiteral):
        result = []
        for elem in node.elements:
            sv = _string_value(elem)
            if sv is None:
                return None
            result.append(sv)
        return result
    sv = _string_value(node)
    if sv is not None:
        return [sv]
    return None


def _collect_int_arguments(node: Expression) -> list[int] | None:
    if isinstance(node, Ps1ArrayLiteral):
        result = []
        for elem in node.elements:
            if not isinstance(elem, Ps1IntegerLiteral):
                return None
            result.append(elem.value)
        return result
    if isinstance(node, Ps1ParenExpression) and node.expression is not None:
        return _collect_int_arguments(node.expression)
    if isinstance(node, Ps1IntegerLiteral):
        return [node.value]
    return None


def _unwrap_paren_to_array(node: Expression) -> Expression:
    if isinstance(node, Ps1ParenExpression) and node.expression is not None:
        return node.expression
    return node


def _case_normalize_name(name: str) -> str:
    lower = name.lower()
    canonical = _KNOWN_NAMES.get(lower)
    if canonical is not None:
        return canonical
    return name


def _strip_backtick_noop(name: str) -> str:
    result: list[str] = []
    i = 0
    while i < len(name):
        if name[i] == '`' and i + 1 < len(name):
            result.append(name[i + 1])
            i += 2
            continue
        result.append(name[i])
        i += 1
    return ''.join(result)


def _get_command_name(cmd: Ps1CommandInvocation) -> str | None:
    if isinstance(cmd.name, Ps1StringLiteral):
        return cmd.name.value
    return None


def _get_body(node) -> list | None:
    if isinstance(node, (Ps1Script, Block, Ps1ScriptBlock, Ps1SubExpression)):
        return node.body
    return None


def _replace_in_parent(old: Node, new: Node):
    parent = old.parent
    if parent is None:
        return
    new.parent = parent
    for attr_name in vars(parent):
        if attr_name in ('parent', 'offset'):
            continue
        value = getattr(parent, attr_name)
        if value is old:
            setattr(parent, attr_name, new)
            return
        if isinstance(value, list):
            for i, item in enumerate(value):
                if item is old:
                    value[i] = new
                    return
                if isinstance(item, tuple):
                    lst = list(item)
                    for j, elem in enumerate(lst):
                        if elem is old:
                            lst[j] = new
                            value[i] = tuple(lst)
                            return


_FOREACH_ALIASES = frozenset({'%', 'foreach', 'foreach-object'})

_ENCODING_MAP = {
    'ascii'            : 'ascii',
    'bigendianunicode' : 'utf-16-be',
    'default'          : 'latin-1',
    'unicode'          : 'utf-16-le',
    'utf7'             : 'utf-7',
    'utf8'             : 'utf-8',
    'utf32'            : 'utf-32-le',
}


def _normalize_dotnet_type_name(name: str) -> str:
    result = name.lower().replace(' ', '')
    if result.startswith('system.'):
        result = result[7:]
    return result


def _extract_foreach_scriptblock(expr: Expression) -> Ps1ScriptBlock | None:
    if not isinstance(expr, Ps1CommandInvocation):
        return None
    if not isinstance(expr.name, Ps1StringLiteral):
        return None
    if expr.name.value.lower() not in _FOREACH_ALIASES:
        return None
    if len(expr.arguments) != 1:
        return None
    arg = expr.arguments[0]
    if isinstance(arg, Ps1CommandArgument):
        if arg.kind != Ps1CommandArgumentKind.POSITIONAL:
            return None
        arg = arg.value
    if isinstance(arg, Ps1ScriptBlock):
        return arg
    return None


_ARRAY_TYPE_NAMES = frozenset({'array', 'system.array'})


def _is_array_reverse_call(node: Ps1ExpressionStatement) -> Ps1Variable | None:
    """
    If the statement is `[Array]::Reverse($var)`, return the variable node.
    """
    expr = node.expression
    if not isinstance(expr, Ps1InvokeMember):
        return None
    if expr.access != Ps1AccessKind.STATIC:
        return None
    if not isinstance(expr.object, Ps1TypeExpression):
        return None
    if expr.object.name.lower().replace(' ', '') not in _ARRAY_TYPE_NAMES:
        return None
    member = expr.member if isinstance(expr.member, str) else None
    if member is None or member.lower() != 'reverse':
        return None
    if len(expr.arguments) != 1:
        return None
    arg = expr.arguments[0]
    if isinstance(arg, Ps1Variable):
        return arg
    return None
