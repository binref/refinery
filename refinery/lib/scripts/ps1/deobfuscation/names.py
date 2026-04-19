"""
PowerShell name constants, alias tables, and string-only utility functions
used by multiple deobfuscation transforms.
"""
from __future__ import annotations

import re

KNOWN_ALIAS = {
    'ac'      : 'Add-Content',       # noqa
    'cat'     : 'Get-Content',       # noqa
    'cd'      : 'Set-Location',      # noqa
    'chdir'   : 'Set-Location',      # noqa
    'childitem': 'Get-ChildItem',    # noqa
    'clc'     : 'Clear-Content',     # noqa
    'clear'   : 'Clear-Host',        # noqa
    'clhy'    : 'Clear-History',     # noqa
    'cli'     : 'Clear-Item',        # noqa
    'clp'     : 'Clear-ItemProperty',# noqa
    'cls'     : 'Clear-Host',        # noqa
    'clv'     : 'Clear-Variable',    # noqa
    'cnsn'    : 'Connect-PSSession', # noqa
    'compare' : 'Compare-Object',    # noqa
    'copy'    : 'Copy-Item',         # noqa
    'cp'      : 'Copy-Item',         # noqa
    'cpi'     : 'Copy-Item',         # noqa
    'cpp'     : 'Copy-ItemProperty', # noqa
    'cvpa'    : 'Convert-Path',      # noqa
    'dbp'     : 'Disable-PSBreakpoint', # noqa
    'del'     : 'Remove-Item',       # noqa
    'diff'    : 'Compare-Object',    # noqa
    'dir'     : 'Get-ChildItem',     # noqa
    'dnsn'    : 'Disconnect-PSSession', # noqa
    'ebp'     : 'Enable-PSBreakpoint', # noqa
    'echo'    : 'Write-Output',      # noqa
    'epal'    : 'Export-Alias',      # noqa
    'epcsv'   : 'Export-Csv',        # noqa
    'erase'   : 'Remove-Item',       # noqa
    'etsn'    : 'Enter-PSSession',   # noqa
    'exsn'    : 'Exit-PSSession',    # noqa
    'fc'      : 'Format-Custom',     # noqa
    'fhx'     : 'Format-Hex',        # noqa
    'fl'      : 'Format-List',       # noqa
    'foreach' : 'ForEach-Object',    # noqa
    'ft'      : 'Format-Table',      # noqa
    'fw'      : 'Format-Wide',       # noqa
    'gal'     : 'Get-Alias',         # noqa
    'gbp'     : 'Get-PSBreakpoint',  # noqa
    'gc'      : 'Get-Content',       # noqa
    'gci'     : 'Get-ChildItem',     # noqa
    'gcm'     : 'Get-Command',       # noqa
    'gcs'     : 'Get-PSCallStack',   # noqa
    'gdr'     : 'Get-PSDrive',       # noqa
    'gerr'    : 'Get-Error',         # noqa
    'ghy'     : 'Get-History',       # noqa
    'gi'      : 'Get-Item',          # noqa
    'gjb'     : 'Get-Job',           # noqa
    'gl'      : 'Get-Location',      # noqa
    'gm'      : 'Get-Member',        # noqa
    'gmo'     : 'Get-Module',        # noqa
    'gp'      : 'Get-ItemProperty',  # noqa
    'gps'     : 'Get-Process',       # noqa
    'gpv'     : 'Get-ItemPropertyValue', # noqa
    'group'   : 'Group-Object',      # noqa
    'gsn'     : 'Get-PSSession',     # noqa
    'gsv'     : 'Get-Service',       # noqa
    'gu'      : 'Get-Unique',        # noqa
    'gv'      : 'Get-Variable',      # noqa
    'h'       : 'Get-History',       # noqa
    'history' : 'Get-History',       # noqa
    'icm'     : 'Invoke-Command',    # noqa
    'iex'     : 'Invoke-Expression', # noqa
    'ihy'     : 'Invoke-History',    # noqa
    'ii'      : 'Invoke-Item',       # noqa
    'ipal'    : 'Import-Alias',      # noqa
    'ipcsv'   : 'Import-Csv',        # noqa
    'ipmo'    : 'Import-Module',     # noqa
    'irm'     : 'Invoke-RestMethod', # noqa
    'iwr'     : 'Invoke-WebRequest', # noqa
    'item'    : 'Get-Item',          # noqa
    'kill'    : 'Stop-Process',      # noqa
    'ls'      : 'Get-ChildItem',     # noqa
    'man'     : 'help',              # noqa
    'md'      : 'mkdir',             # noqa
    'measure' : 'Measure-Object',    # noqa
    'member'  : 'Get-Member',        # noqa
    'mi'      : 'Move-Item',         # noqa
    'mount'   : 'New-PSDrive',       # noqa
    'move'    : 'Move-Item',         # noqa
    'mp'      : 'Move-ItemProperty', # noqa
    'mv'      : 'Move-Item',         # noqa
    'nal'     : 'New-Alias',         # noqa
    'ndr'     : 'New-PSDrive',       # noqa
    'ni'      : 'New-Item',          # noqa
    'nmo'     : 'New-Module',        # noqa
    'nsn'     : 'New-PSSession',     # noqa
    'nv'      : 'New-Variable',      # noqa
    'ogv'     : 'Out-GridView',      # noqa
    'oh'      : 'Out-Host',          # noqa
    'popd'    : 'Pop-Location',      # noqa
    'ps'      : 'Get-Process',       # noqa
    'pushd'   : 'Push-Location',     # noqa
    'pwd'     : 'Get-Location',      # noqa
    'r'       : 'Invoke-History',    # noqa
    'rbp'     : 'Remove-PSBreakpoint', # noqa
    'rcjb'    : 'Receive-Job',       # noqa
    'rcsn'    : 'Receive-PSSession', # noqa
    'rd'      : 'Remove-Item',       # noqa
    'rdr'     : 'Remove-PSDrive',    # noqa
    'ren'     : 'Rename-Item',       # noqa
    'ri'      : 'Remove-Item',       # noqa
    'rjb'     : 'Remove-Job',        # noqa
    'rm'      : 'Remove-Item',       # noqa
    'rmdir'   : 'Remove-Item',       # noqa
    'rmo'     : 'Remove-Module',     # noqa
    'rni'     : 'Rename-Item',       # noqa
    'rnp'     : 'Rename-ItemProperty', # noqa
    'rp'      : 'Remove-ItemProperty', # noqa
    'rsn'     : 'Remove-PSSession',  # noqa
    'rv'      : 'Remove-Variable',   # noqa
    'rvpa'    : 'Resolve-Path',      # noqa
    'sajb'    : 'Start-Job',         # noqa
    'sal'     : 'Set-Alias',         # noqa
    'saps'    : 'Start-Process',     # noqa
    'sasv'    : 'Start-Service',     # noqa
    'sbp'     : 'Set-PSBreakpoint',  # noqa
    'select'  : 'Select-Object',     # noqa
    'set'     : 'Set-Variable',      # noqa
    'shcm'    : 'Show-Command',      # noqa
    'si'      : 'Set-Item',          # noqa
    'sl'      : 'Set-Location',      # noqa
    'sleep'   : 'Start-Sleep',       # noqa
    'sls'     : 'Select-String',     # noqa
    'sort'    : 'Sort-Object',       # noqa
    'sp'      : 'Set-ItemProperty',  # noqa
    'spjb'    : 'Stop-Job',          # noqa
    'spps'    : 'Stop-Process',      # noqa
    'spsv'    : 'Stop-Service',      # noqa
    'start'   : 'Start-Process',     # noqa
    'sv'      : 'Set-Variable',      # noqa
    'tee'     : 'Tee-Object',        # noqa
    'type'    : 'Get-Content',       # noqa
    'variable': 'Get-Variable',      # noqa
    'where'   : 'Where-Object',      # noqa
    'wjb'     : 'Wait-Job',          # noqa
    'write'   : 'Write-Output',      # noqa
}

KNOWN_NAMES = {name.lower(): name for name in [
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

for _name in list(KNOWN_NAMES.values()):
    if '.' in _name:
        _full = F'System.{_name}'
        KNOWN_NAMES[_full.lower()] = _full

for _a, _n in KNOWN_ALIAS.items():
    KNOWN_NAMES[_n.lower()] = _n

SIMPLE_IDENTIFIER = re.compile(r'^[a-zA-Z_]\w*$')

GET_MEMBER_ALIASES = frozenset({'get-member', 'gm'})
GET_COMMAND_ALIASES = frozenset({'get-command', 'gcm'})

FOREACH_ALIASES = frozenset({'%', 'foreach', 'foreach-object'})

COMPARISON_OPS = {
    '-eq': int.__eq__,
    '-ne': int.__ne__,
    '-lt': int.__lt__,
    '-le': int.__le__,
    '-gt': int.__gt__,
    '-ge': int.__ge__,
}

ENCODING_MAP = {
    'ascii'            : 'ascii',            # noqa
    'bigendianunicode' : 'utf-16-be',        # noqa
    'default'          : 'latin-1',          # noqa
    'unicode'          : 'utf-16-le',        # noqa
    'utf7'             : 'utf-7',            # noqa
    'utf8'             : 'utf-8',            # noqa
    'utf32'            : 'utf-32-le',        # noqa
}

BUILTIN_VARIABLES = frozenset({'null', 'true', 'false'})

PS1_KNOWN_VARIABLES: dict[str, str] = {
    name.lower(): name for name in [
        'ConfirmPreference',
        'ConsoleFileName',
        'DebugPreference',
        'Error',
        'ErrorActionPreference',
        'ExecutionContext',
        'ForEach',
        'FormatEnumerationLimit',
        'HOME',
        'Host',
        'InformationPreference',
        'Input',
        'Matches',
        'MaximumAliasCount',
        'MaximumDriveCount',
        'MaximumErrorCount',
        'MaximumFunctionCount',
        'MaximumHistoryCount',
        'MaximumVariableCount',
        'MyInvocation',
        'NestedPromptLevel',
        'OutputEncoding',
        'PID',
        'PROFILE',
        'ProgressPreference',
        'PSCommandPath',
        'PSCulture',
        'PSDefaultParameterValues',
        'PSEmailServer',
        'PSHome',
        'PSScriptRoot',
        'PSSessionApplicationName',
        'PSSessionConfigurationName',
        'PSSessionOption',
        'PSUICulture',
        'PSVersionTable',
        'PWD',
        'ShellID',
        'StackTrace',
        'This',
        'VerbosePreference',
        'WarningPreference',
        'WhatIfPreference',
    ]
}

FORMAT_PATTERN = re.compile(r'\{\{|\}\}|\{(\d+)\}')


def normalize_type_expression(name: str) -> str:
    return name.lower().replace(' ', '')


def normalize_dotnet_type_name(name: str) -> str:
    result = normalize_type_expression(name)
    if result.startswith('system.'):
        result = result[7:]
    return result


def case_normalize_name(name: str) -> str:
    lower = name.lower()
    canonical = KNOWN_NAMES.get(lower)
    if canonical is not None:
        return canonical
    return name


def apply_format_string(fmt: str, args: list[str]) -> str | None:
    """
    Apply a PowerShell-style format string to a list of string arguments.
    Returns the formatted string, or ``None`` on index/value errors.
    """
    try:
        def replacer(m: re.Match) -> str:
            full = m.group(0)
            if full == '{{':
                return '{'
            if full == '}}':
                return '}'
            idx = int(m.group(1))
            return args[idx]
        return FORMAT_PATTERN.sub(replacer, fmt)
    except (IndexError, ValueError):
        return None
