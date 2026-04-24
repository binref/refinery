$ErrorActionPreference = 'SilentlyContinue'

# =============================================================================
# Type reflection — mirrors .NET types visible from PowerShell 5.1
# =============================================================================

$ShortTypes = @(
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
    'Void'
)

$QualifiedTypes = @(
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
    'Xml.XmlDocument'
)

$MicrosoftTypes = @(
    'Microsoft.Win32.Registry',
    'Microsoft.Win32.RegistryKey'
)

$WinFormsTypes = @(
    'Windows.Forms.Clipboard',
    'Windows.Forms.TextBox',
    'Windows.Forms.TextDataFormat'
)

$PSTypes = @(
    'System.AppDomain',
    'System.Management.Automation.AliasInfo',
    'System.Management.Automation.CmdletInfo',
    'System.Management.Automation.CommandInfo',
    'System.Management.Automation.CommandInvocationIntrinsics',
    'System.Management.Automation.EngineIntrinsics',
    'System.Management.Automation.FunctionInfo',
    'System.Management.Automation.Host.PSHost',
    'System.Management.Automation.Internal.Host.InternalHost',
    'System.Management.Automation.PathIntrinsics',
    'System.Management.Automation.PowerShell',
    'System.Management.Automation.PSMemberInfo',
    'System.Management.Automation.PSObject',
    'System.Management.Automation.PSVariable',
    'System.Management.Automation.PSVariableIntrinsics',
    'System.Management.Automation.ProviderIntrinsics',
    'System.Management.Automation.SessionState',
    'System.Management.Automation.SwitchParameter',
    'System.Reflection.Emit.AssemblyBuilder',
    'System.Reflection.Emit.EnumBuilder',
    'System.Reflection.Emit.ModuleBuilder',
    'System.Reflection.Emit.TypeBuilder',
    'System.Type'
)

$typeResult = @{}
$typeAliases = @{}

function Reflect-Type {
    param([System.Type]$Type)
    if ($null -eq $Type) { return }
    $fullName = $Type.FullName
    if ($null -eq $fullName) { return }
    if ($typeResult.ContainsKey($fullName)) { return }

    $isEnum = $Type.IsEnum
    $methods = @()
    $properties = @{}

    if (-not $isEnum) {
        $allMethods = $Type.GetMethods(
            [System.Reflection.BindingFlags]::Public -bor
            [System.Reflection.BindingFlags]::Instance -bor
            [System.Reflection.BindingFlags]::Static)
        $methodNames = @{}
        foreach ($m in $allMethods) {
            if (-not $m.IsSpecialName) {
                $methodNames[$m.Name] = $true
            }
        }

        $allProps = $Type.GetProperties(
            [System.Reflection.BindingFlags]::Public -bor
            [System.Reflection.BindingFlags]::Instance -bor
            [System.Reflection.BindingFlags]::Static)
        foreach ($p in $allProps) {
            $retType = $p.PropertyType.FullName
            if ($null -eq $retType) { $retType = $p.PropertyType.Name }
            $properties[$p.Name] = $retType
        }

        foreach ($iface in $Type.GetInterfaces()) {
            foreach ($im in $iface.GetMethods()) {
                if (-not $im.IsSpecialName) {
                    $methodNames[$im.Name] = $true
                }
            }
            foreach ($ip in $iface.GetProperties()) {
                if (-not $properties.ContainsKey($ip.Name)) {
                    $retType = $ip.PropertyType.FullName
                    if ($null -eq $retType) { $retType = $ip.PropertyType.Name }
                    $properties[$ip.Name] = $retType
                }
            }
        }

        $methods = @($methodNames.Keys | Sort-Object)
    } else {
        $methods = @([System.Enum]::GetNames($Type) | Sort-Object)
    }

    $typeResult[$fullName] = @{
        methods = $methods
        properties = $properties
        is_enum = $isEnum
    }
}

foreach ($name in $ShortTypes) {
    try {
        $t = [Type]"System.$name"
        if ($null -ne $t) {
            Reflect-Type $t
            $typeAliases[$name] = $t.FullName
        }
    } catch {}
    try {
        $t = [Type]$name
        if ($null -ne $t -and -not $typeAliases.ContainsKey($name)) {
            Reflect-Type $t
            $typeAliases[$name] = $t.FullName
        }
    } catch {}
}

foreach ($name in $QualifiedTypes) {
    try {
        $t = [Type]"System.$name"
        if ($null -ne $t) {
            Reflect-Type $t
            $typeAliases[$name] = $t.FullName
        }
    } catch {}
}

Add-Type -AssemblyName 'System.Windows.Forms' -ea SilentlyContinue
foreach ($name in $WinFormsTypes) {
    try {
        $t = [Type]"System.$name"
        if ($null -ne $t) {
            Reflect-Type $t
            $typeAliases[$name] = $t.FullName
        }
    } catch {}
}

foreach ($name in $MicrosoftTypes) {
    try {
        $t = [Type]$name
        if ($null -ne $t) {
            Reflect-Type $t
        }
    } catch {}
}

foreach ($name in $PSTypes) {
    try {
        $t = [Type]$name
        if ($null -ne $t) {
            Reflect-Type $t
        }
    } catch {}
}

$variableTypes = @{}
try { $variableTypes['ExecutionContext'] = $ExecutionContext.GetType().FullName } catch {}
try { $variableTypes['Host'] = $Host.GetType().FullName } catch {}
try { $variableTypes['PSVersionTable'] = $PSVersionTable.GetType().FullName } catch {}
try { $variableTypes['PSCmdlet'] = 'System.Management.Automation.PSScriptCmdlet' } catch {}
try { $variableTypes['MyInvocation'] = $MyInvocation.GetType().FullName } catch {}
try { $variableTypes['Error'] = $Error.GetType().FullName } catch {}
try { $variableTypes['PID'] = $PID.GetType().FullName } catch {}
try { $variableTypes['PWD'] = $PWD.GetType().FullName } catch {}
try { $variableTypes['ShellId'] = $ShellId.GetType().FullName } catch {}

# =============================================================================
# WMI class names and properties — for display-name normalization
# =============================================================================

$wmiClasses = @(Get-CimClass -Namespace root/cimv2 -ClassName Win32_* |
    ForEach-Object { $_.CimClassName } | Sort-Object)

$wmiProperties = @{}
foreach ($cls in Get-CimClass -Namespace root/cimv2 -ClassName Win32_*) {
    $props = @($cls.CimClassProperties | ForEach-Object { $_.Name } | Sort-Object)
    if ($props.Count -gt 0) {
        $wmiProperties[$cls.CimClassName] = $props
    }
}

# =============================================================================
# Command reflection — mirrors cmdlets, aliases, parameters
# =============================================================================

$CommonParameters = @(
    'Confirm',
    'Debug',
    'ErrorAction',
    'ErrorVariable',
    'InformationAction',
    'InformationVariable',
    'OutBuffer',
    'OutVariable',
    'PipelineVariable',
    'Verbose',
    'WarningAction',
    'WarningVariable',
    'WhatIf'
)
$CommonSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]$CommonParameters,
    [System.StringComparer]::OrdinalIgnoreCase
)

$commandAliases = [ordered]@{}
foreach ($a in Get-Alias | Sort-Object Name) {
    $commandAliases[$a.Name] = $a.Definition
}

$commands = Get-Command -CommandType Cmdlet, Function | Sort-Object Name
$cmdletNames = [System.Collections.Generic.List[string]]::new()
$cmdletParameters = [ordered]@{}

foreach ($cmd in $commands) {
    if ($cmd.Name -match '^[A-Z]:$') { continue }
    $cmdletNames.Add($cmd.Name)
    $params = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $cmd.Parameters) {
        foreach ($key in $cmd.Parameters.Keys | Sort-Object) {
            if (-not $CommonSet.Contains($key)) {
                $params.Add($key)
            }
        }
    }
    if ($params.Count -gt 0) {
        $cmdletParameters[$cmd.Name] = $params.ToArray()
    }
}

# =============================================================================
# Write combined output
# =============================================================================

$output = [ordered]@{
    types            = $typeResult
    type_aliases     = $typeAliases
    variable_types   = $variableTypes
    wmi_classes      = $wmiClasses
    wmi_properties   = $wmiProperties
    command_aliases   = $commandAliases
    cmdlets          = $cmdletNames.ToArray()
    parameters       = $cmdletParameters
}

$outPath = Join-Path (Join-Path $PSScriptRoot 'data') 'pwsh.json'
$json = $output | ConvertTo-Json -Depth 5
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($outPath, $json, $utf8NoBom)

Write-Host ("{0,5} Types"            -f $typeResult.Count)
Write-Host ("{0,5} Type aliases"     -f $typeAliases.Count)
Write-Host ("{0,5} Variable types"   -f $variableTypes.Count)
Write-Host ("{0,5} WMI classes"      -f $wmiClasses.Count)
Write-Host ("{0,5} WMI properties"   -f $wmiProperties.Count)
Write-Host ("{0,5} Commands"         -f $cmdletNames.Count)
Write-Host ("{0,5} Command aliases"  -f $commandAliases.Count)
Write-Host ("{0,5} Parameter sets"   -f $cmdletParameters.Count)

python -c @"
import json, sys
def sort_lists(obj):
    if isinstance(obj, dict):
        return {k: sort_lists(v) for k, v in obj.items()}
    if isinstance(obj, list) and obj and isinstance(obj[0], str):
        return sorted(obj)
    if isinstance(obj, list):
        return [sort_lists(v) for v in obj]
    return obj
path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
data = sort_lists(data)
with open(path, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)
    f.write('\n')
"@ $outPath

Write-Host "`nWritten to: $outPath"
