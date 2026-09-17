<#
.SYNOPSIS
Collect the PowerShell and .NET metadata that the ps1 deobfuscator reasons about.

.DESCRIPTION
Writes pwsh-meta.json, pwsh-types.json, pwsh-commands.json, pwsh-variables.json and pwsh-wmi.json
into the output directory. The names to collect are read from pwsh-seeds.json, which is a reviewed
input rather than a discovered one: closing over every type reachable from a root like System.Type
reaches most of the base class library within two steps.

Run this with -NoProfile. Type resolution sees whatever assemblies the session has loaded, and a
profile that loads one would put types into the data that are not on a clean machine.

Three oracles answer three different questions, and none of them substitutes for another.
Reflection reports signatures. Get-TypeData reports the Extended Type System members that
types.ps1xml adds and that reflection cannot see. A pristine runspace, created from a default
InitialSessionState rather than from this session, reports commands, aliases, automatic variables
and Get-Member ordering. The pristine runspace is what keeps this script's own definitions out of
the data it writes: the previous generator ran Get-Command in its own session and shipped its own
helper function as a known cmdlet. Each pristine query gets a new session and returns plain data,
so no query can observe what an earlier one defined.

Failure has two kinds and they are not interchangeable. A structural failure means the run cannot
be trusted at all: an unmet floor, a host that is not what was asked for, a document that
serialized past its depth. It writes no data and exits non-zero. An item-level degradation means
one name could not be collected; it is recorded in the problems list and the run continues.
Recording everything as fatal trains the operator to ignore the exit code, which is how the
previous generator came to run under SilentlyContinue.

.PARAMETER Unauthoritative
Collect on a host that cannot produce authoritative data, stamping the result accordingly and
writing to a temporary directory instead of the data directory. Every floor is demoted to an
item-level problem. This is what allows the code paths to be exercised on PowerShell 7 on Linux
before the real run.

.PARAMETER ClosureDepth
How many steps to follow out of the seed set through member, parameter and return types. Zero
collects the seeds alone.
#>
[CmdletBinding()]
param(
    [switch] $Unauthoritative,
    [ValidateRange(0, 3)]
    [int] $ClosureDepth = 1,
    [string] $SeedFile,
    [string] $OutputDirectory
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$ScriptDir =
    if ($PSScriptRoot) { $PSScriptRoot }
    elseif ($PSCommandPath) { Split-Path -Parent $PSCommandPath }
    else { (Get-Location).Path }
if (-not $SeedFile) { $SeedFile = Join-Path $ScriptDir 'pwsh-seeds.json' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $ScriptDir 'data' }

$SchemaVersion = 1
$GeneratorVersion = 2
$JsonDepth = 64

$Problems = [System.Collections.Generic.List[object]]::new()

function Add-Problem {
    param(
        [Parameter(Mandatory)] [string] $Stage,
        [Parameter(Mandatory)] [string] $Item,
        [Parameter(Mandatory)] [object] $Reason
    )
    $kind = 'Rejected'
    $message = [string]$Reason
    if ($Reason -is [System.Management.Automation.ErrorRecord]) {
        $kind = $Reason.Exception.GetType().FullName
        $message = $Reason.Exception.Message
    } elseif ($Reason -is [Exception]) {
        $kind = $Reason.GetType().FullName
        $message = $Reason.Message
    }
    $Problems.Add([ordered]@{
        stage   = $Stage
        item    = $Item
        kind    = $kind
        message = $message
    })
}

function Assert-Floor {
    param(
        [Parameter(Mandatory)] [string] $Stage,
        [Parameter(Mandatory)] [string] $Item,
        [Parameter(Mandatory)] [string] $Message
    )
    if ($Unauthoritative) {
        Add-Problem -Stage $Stage -Item $Item -Reason "floor not met: $Message"
        return
    }
    throw "$Stage floor not met for '$Item': $Message"
}

function Get-MaxDepth {
    <#
    The deepest chain of nested containers in an object graph, so a document can be checked against
    the serializer's depth limit before it is written. ConvertTo-Json replaces a container it may
    not descend into with that container's ToString(), turning a nested object into a bare type-name
    string with no warning. A type-name string is indistinguishable from a legitimate value once
    written, so the only sound check is on the structure, not the text. Recursion is bounded by
    Limit so that a live object accidentally left in the graph terminates instead of looping.
    #>
    param(
        [object] $Value,
        [int] $Limit
    )
    if ($Limit -le 0) { return 1 }
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return 0 }
    $deepest = 0
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($item in $Value.PSBase.Values) {
            $depth = Get-MaxDepth -Value $item -Limit ($Limit - 1)
            if ($depth -gt $deepest) { $deepest = $depth }
        }
        return $deepest + 1
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($item in $Value) {
            $depth = Get-MaxDepth -Value $item -Limit ($Limit - 1)
            if ($depth -gt $deepest) { $deepest = $depth }
        }
        return $deepest + 1
    }
    return 0
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [object] $Value
    )
    $depth = Get-MaxDepth -Value $Value -Limit ($JsonDepth + 2)
    if ($depth -gt $JsonDepth) {
        throw "$Path nests $depth levels, past the -Depth $JsonDepth serializer limit."
    }
    #: Compressed because these files are read by a program and shipped through gzip, and the
    #: indentation is most of what would be written: the operator grid was 86% whitespace before the
    #: same flag reached it. It also settles the line endings the surrounding pipeline used to
    #: normalize, because there are none left to normalize.
    $json = $Value | ConvertTo-Json -Depth $JsonDepth -Compress
    $encoding = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $json + "`n", $encoding)
    return $json.Length
}

function Invoke-Pristine {
    <#
    Run a script in a session built from a default InitialSessionState, and return what it wrote.
    The session is created and disposed per call, so one query can never see what another defined,
    and the script must therefore reduce everything it needs to plain data before returning.
    #>
    param(
        [Parameter(Mandatory)] [string] $Label,
        [Parameter(Mandatory)] [string] $Script
    )
    $initial = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $shell = [PowerShell]::Create($initial)
    try {
        $null = $shell.AddScript("`$ErrorActionPreference = 'Stop'`n" + $Script)
        $result = $shell.Invoke()
        foreach ($record in $shell.Streams.Error) {
            Add-Problem -Stage 'pristine' -Item $Label -Reason $record
        }
        return $result
    } finally {
        $shell.Dispose()
    }
}

function Get-TypeKind {
    param([Type] $Type)
    if ($Type.IsEnum) { return 'enum' }
    if ($Type.IsInterface) { return 'interface' }
    if ([System.Delegate].IsAssignableFrom($Type)) { return 'delegate' }
    if ($Type.IsValueType) { return 'struct' }
    return 'class'
}

function Get-TypeText {
    param([Type] $Type)
    if ($null -eq $Type) { return $null }
    if ($null -ne $Type.FullName) { return $Type.FullName }
    return $Type.Name
}

function Get-TypeDefinition {
    <#
    Reduce a type to the definition the type table is keyed by: an array, pointer or by-reference
    type reduces to its element type, and a constructed generic to its open definition. Returns
    null for anything PowerShell source cannot name.
    #>
    param([Type] $Type)
    $cursor = $Type
    while ($null -ne $cursor -and ($cursor.IsArray -or $cursor.IsByRef -or $cursor.IsPointer)) {
        $cursor = $cursor.GetElementType()
    }
    if ($null -eq $cursor) { return $null }
    if ($cursor.IsGenericType -and -not $cursor.IsGenericTypeDefinition) {
        $cursor = $cursor.GetGenericTypeDefinition()
    }
    if ($cursor.IsGenericParameter) { return $null }
    if (-not ($cursor.IsPublic -or $cursor.IsNestedPublic)) { return $null }
    return $cursor
}

$MemberFlags = [System.Reflection.BindingFlags]::Public -bor
               [System.Reflection.BindingFlags]::Instance -bor
               [System.Reflection.BindingFlags]::Static

function Get-PublicMethods {
    param([Type] $Type)
    return @($Type.GetMethods($MemberFlags) | Where-Object { -not $_.IsSpecialName })
}

function Get-PublicProperties {
    param([Type] $Type)
    return @($Type.GetProperties($MemberFlags))
}

function Get-PublicFields {
    param([Type] $Type)
    return @($Type.GetFields($MemberFlags))
}

function ConvertTo-ParameterRecord {
    param([System.Reflection.ParameterInfo] $Parameter)
    return [ordered]@{
        name     = $Parameter.Name
        type     = Get-TypeText $Parameter.ParameterType
        byref    = [bool]$Parameter.ParameterType.IsByRef
        out      = [bool]$Parameter.IsOut
        optional = [bool]$Parameter.IsOptional
        position = [int]$Parameter.Position
    }
}

function Get-SignatureKey {
    <#
    A stable ordering key for a parameter list, so overloads and constructors serialize in the same
    order on every box. Reflection returns them in an order the CLR leaves unspecified, which would
    otherwise show up as a spurious difference when two machines' output is compared. The
    zero-padded arity sorts a shorter signature ahead of a longer one; the parameter types break the
    remaining ties, and no two overloads of one method can share both.
    #>
    param([object] $Parameters)
    $list = @($Parameters)
    $types = @($list | ForEach-Object { [string]$_.type })
    return ('{0:0000}|{1}' -f $list.Count, ($types -join ','))
}

function Add-MethodMember {
    param(
        [System.Collections.Specialized.OrderedDictionary] $Members,
        [System.Reflection.MethodInfo] $Method
    )
    $parameters = @()
    foreach ($parameter in $Method.GetParameters()) {
        $parameters += ConvertTo-ParameterRecord $parameter
    }
    $overload = [ordered]@{
        static     = [bool]$Method.IsStatic
        generic    = [bool]$Method.IsGenericMethodDefinition
        returns    = Get-TypeText $Method.ReturnType
        parameters = @($parameters)
    }
    if ($Members.PSBase.Contains($Method.Name)) {
        if ($Members[$Method.Name].kind -eq 'method') {
            $Members[$Method.Name].overloads += $overload
        }
    } else {
        $Members[$Method.Name] = [ordered]@{
            kind      = 'method'
            source    = 'reflection'
            overloads = @($overload)
        }
    }
}

function Add-PropertyMember {
    param(
        [System.Collections.Specialized.OrderedDictionary] $Members,
        [System.Reflection.PropertyInfo] $Property
    )
    if ($Members.PSBase.Contains($Property.Name)) { return }
    $accessor = @($Property.GetAccessors($false)) | Select-Object -First 1
    $Members[$Property.Name] = [ordered]@{
        kind     = 'property'
        source   = 'reflection'
        type     = Get-TypeText $Property.PropertyType
        static   = [bool]($null -ne $accessor -and $accessor.IsStatic)
        readable = [bool]$Property.CanRead
        writable = [bool]$Property.CanWrite
    }
}

function ConvertTo-TypeRecord {
    param(
        [Parameter(Mandatory)] [Type] $Type,
        [Parameter(Mandatory)] [bool] $Seeded,
        [object] $EtsMembers
    )
    $members = [ordered]@{}

    foreach ($method in (Get-PublicMethods $Type)) {
        Add-MethodMember $members $method
    }

    foreach ($property in (Get-PublicProperties $Type)) {
        Add-PropertyMember $members $property
    }

    # Explicitly-implemented interface members — System.Array's Count from ICollection is the
    # canonical case — are not returned by GetProperties/GetMethods on the type itself, only by
    # reflecting the interfaces it implements. A member the type already declares wins; the
    # interface only fills what is otherwise invisible.
    foreach ($interface in $Type.GetInterfaces()) {
        foreach ($method in (Get-PublicMethods $interface)) {
            if ($members.PSBase.Contains($method.Name)) { continue }
            Add-MethodMember $members $method
        }
        foreach ($property in (Get-PublicProperties $interface)) {
            Add-PropertyMember $members $property
        }
    }

    foreach ($field in (Get-PublicFields $Type)) {
        if ($members.PSBase.Contains($field.Name)) { continue }
        $members[$field.Name] = [ordered]@{
            kind     = 'field'
            source   = 'reflection'
            type     = Get-TypeText $field.FieldType
            static   = [bool]$field.IsStatic
            readable = $true
            writable = [bool](-not ($field.IsInitOnly -or $field.IsLiteral))
        }
    }

    # The Extended Type System fills only what reflection cannot see. A member reflection already
    # reported keeps its reflection kind and — the load-bearing part — its return type: Get-Member
    # presents System.Array's Count as an alias property, but ICollection.Count is a real Int32
    # property, and dropping that type would break every consumer that resolves what `.Count` yields.
    # The members that exist only in the ETS, like Process.Path and Process.CPU, are the ones this
    # captures, and they are exactly the ScriptProperties a later purity gate must not mistake for
    # inert reads.
    foreach ($member in @($EtsMembers)) {
        if ($null -eq $member) { continue }
        if ($members.PSBase.Contains($member.Name)) { continue }
        $members[$member.Name] = [ordered]@{
            kind   = $member.Kind
            source = 'ets'
        }
    }

    foreach ($name in @($members.PSBase.Keys)) {
        $member = $members[$name]
        if ($member.kind -eq 'method') {
            $member.overloads = @($member.overloads | Sort-Object {
                '{0}|{1}|{2}' -f [int][bool]$_.static, (Get-SignatureKey $_.parameters), [string]$_.returns
            })
        }
    }

    $sorted = [ordered]@{}
    foreach ($name in ($members.PSBase.Keys | Sort-Object)) { $sorted[$name] = $members[$name] }

    $constructors = @()
    if (-not $Type.IsInterface -and -not $Type.IsGenericTypeDefinition) {
        foreach ($constructor in $Type.GetConstructors()) {
            $parameters = @()
            foreach ($parameter in $constructor.GetParameters()) {
                $parameters += ConvertTo-ParameterRecord $parameter
            }
            $constructors += [ordered]@{ parameters = @($parameters) }
        }
        $constructors = @($constructors | Sort-Object { Get-SignatureKey $_.parameters })
    }

    $enumValues = $null
    if ($Type.IsEnum) {
        $enumValues = [ordered]@{}
        foreach ($name in ([System.Enum]::GetNames($Type) | Sort-Object)) {
            $value = [System.Enum]::Parse($Type, $name)
            $enumValues[$name] = [string][System.Enum]::Format($Type, $value, 'd')
        }
    }

    return [ordered]@{
        kind         = Get-TypeKind $Type
        base         = Get-TypeText $Type.BaseType
        sealed       = [bool]$Type.IsSealed
        abstract     = [bool]$Type.IsAbstract
        interfaces   = @($Type.GetInterfaces() | ForEach-Object { Get-TypeText $_ } | Sort-Object)
        enum_values  = $enumValues
        seeded       = $Seeded
        member_order = $null
        constructors = @($constructors)
        members      = $sorted
    }
}

function Get-ClosureCandidates {
    param([Type] $Type)
    $candidates = [System.Collections.Generic.List[Type]]::new()
    $add = {
        param([Type] $Candidate)
        $definition = Get-TypeDefinition $Candidate
        if ($null -ne $definition) { $candidates.Add($definition) }
    }
    & $add $Type.BaseType
    foreach ($interface in $Type.GetInterfaces()) { & $add $interface }
    if ($Type.IsGenericType) {
        foreach ($argument in $Type.GetGenericArguments()) { & $add $argument }
    }
    foreach ($property in (Get-PublicProperties $Type)) { & $add $property.PropertyType }
    foreach ($field in (Get-PublicFields $Type)) { & $add $field.FieldType }
    foreach ($method in (Get-PublicMethods $Type)) {
        & $add $method.ReturnType
        foreach ($parameter in $method.GetParameters()) { & $add $parameter.ParameterType }
    }
    if (-not $Type.IsInterface -and -not $Type.IsGenericTypeDefinition) {
        foreach ($constructor in $Type.GetConstructors()) {
            foreach ($parameter in $constructor.GetParameters()) { & $add $parameter.ParameterType }
        }
    }
    return , $candidates.ToArray()
}

<#
Expressions that produce a benign instance whose Get-Member output is the display order the
deobfuscator resolves ($X | Get-Member)[N].Name against. The order cannot be derived: it is what
the engine emits for a real object, including the members the Extended Type System contributes.
Every entry is a base class library constructor or a read of existing state, and the set is
deliberately small — a type with no entry gets no member_order, and the reader must then decline to
answer rather than guess. Collections are absent on purpose, because the pipeline enumerates them
and Get-Member then reports the element type instead.
#>
$InstanceExpressions = [ordered]@{
    'Microsoft.Win32.RegistryKey'                   = '[Microsoft.Win32.Registry]::LocalMachine'
    'System.Boolean'                                = '$true'
    'System.Byte'                                   = '[byte]0'
    'System.Char'                                   = '[char]65'
    'System.DateTime'                               = '[datetime]::MinValue'
    'System.Diagnostics.Process'                    = 'Get-Process -Id $PID'
    'System.Diagnostics.ProcessStartInfo'           = 'New-Object System.Diagnostics.ProcessStartInfo'
    'System.Double'                                 = '[double]0'
    'System.Exception'                              = 'New-Object System.Exception'
    'System.Guid'                                   = '[guid]::Empty'
    'System.IO.DirectoryInfo'                       = "New-Object System.IO.DirectoryInfo 'C:\'"
    'System.IO.FileInfo'                            = "New-Object System.IO.FileInfo 'C:\x'"
    'System.IO.MemoryStream'                        = 'New-Object System.IO.MemoryStream'
    'System.Int32'                                  = '[int]0'
    'System.Int64'                                  = '[int64]0'
    'System.Management.Automation.EngineIntrinsics' = '$ExecutionContext'
    'System.Management.Automation.PSObject'         = 'New-Object System.Management.Automation.PSObject'
    'System.Net.IPAddress'                          = "[ipaddress]'127.0.0.1'"
    'System.Net.WebClient'                          = 'New-Object System.Net.WebClient'
    'System.Object'                                 = 'New-Object System.Object'
    'System.Random'                                 = 'New-Object System.Random'
    'System.Security.SecureString'                  = 'New-Object System.Security.SecureString'
    'System.String'                                 = "''"
    'System.Text.RegularExpressions.Regex'          = "New-Object System.Text.RegularExpressions.Regex 'x'"
    'System.Text.StringBuilder'                     = 'New-Object System.Text.StringBuilder'
    'System.TimeSpan'                               = '[timespan]::Zero'
    'System.Uri'                                    = "[uri]'http://localhost/'"
    'System.Version'                                = "[version]'1.0'"
}

if (-not (Test-Path -LiteralPath $SeedFile)) {
    throw "Seed file not found: $SeedFile"
}
$Seeds = Get-Content -LiteralPath $SeedFile -Raw | ConvertFrom-Json

if (-not $Unauthoritative -and $PSVersionTable.PSEdition -ne 'Desktop') {
    throw (
        'Authoritative collection requires Windows PowerShell 5.1. ' +
        'Run with -Unauthoritative to exercise the collection on this host instead.'
    )
}
if ($Unauthoritative) {
    $OutputDirectory = Join-Path ([System.IO.Path]::GetTempPath()) 'pwsh-unauthoritative'
}
if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    $null = New-Item -ItemType Directory -Path $OutputDirectory
}

$outputSizes = [ordered]@{}

try {

    foreach ($assembly in $Seeds.assemblies) {
        try {
            Add-Type -AssemblyName $assembly
        } catch {
            Add-Problem -Stage 'assembly' -Item $assembly -Reason $_
        }
    }

    $accelerators = [ordered]@{}
    $acceleratorType = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
    $acceleratorTable = $acceleratorType::Get
    foreach ($name in ($acceleratorTable.Keys | Sort-Object)) {
        $accelerators[$name] = Get-TypeText $acceleratorTable[$name]
    }
    foreach ($name in $Seeds.accelerators.required) {
        if (-not $accelerators.Contains($name)) {
            Assert-Floor -Stage 'accelerators' -Item $name -Message 'not in the accelerator table'
        }
    }
    Write-Host ('{0,8} accelerators' -f $accelerators.Count)

    $etsMembers = @{}
    $etsRecords = Invoke-Pristine -Label 'Get-TypeData' -Script @'
Get-TypeData -TypeName * | ForEach-Object {
    $typeName = $_.TypeName
    $_.Members.GetEnumerator() | ForEach-Object {
        [pscustomobject]@{
            TypeName = $typeName
            Name     = $_.Key
            Kind     = $_.Value.GetType().Name
        }
    }
}
'@
    foreach ($record in $etsRecords) {
        $kind = switch ($record.Kind) {
            'AliasPropertyData'  { 'ets_alias_property' }
            'CodeMethodData'     { 'ets_code_method' }
            'CodePropertyData'   { 'ets_code_property' }
            'MemberSetData'      { 'ets_member_set' }
            'NotePropertyData'   { 'ets_note_property' }
            'PropertySetData'    { 'ets_property_set' }
            'ScriptMethodData'   { 'ets_script_method' }
            'ScriptPropertyData' { 'ets_script_property' }
            default              { 'ets_unknown' }
        }
        if (-not $etsMembers.ContainsKey($record.TypeName)) { $etsMembers[$record.TypeName] = @() }
        $etsMembers[$record.TypeName] += [pscustomobject]@{ Name = $record.Name; Kind = $kind }
    }
    Write-Host ('{0,8} types carry extended members' -f $etsMembers.Count)

    $resolved = [ordered]@{}
    $frontier = [System.Collections.Generic.List[Type]]::new()
    $seededNames = @{}
    foreach ($group in @('required', 'optional')) {
        foreach ($name in $Seeds.types.$group) {
            $seededNames[$name] = $true
            $type = $name -as [type]
            if ($null -eq $type) {
                if ($group -eq 'required') {
                    Assert-Floor -Stage 'types' -Item $name -Message 'did not resolve'
                } else {
                    Add-Problem -Stage 'types' -Item $name -Reason 'did not resolve'
                }
                continue
            }
            $definition = Get-TypeDefinition $type
            if ($null -eq $definition) {
                Add-Problem -Stage 'types' -Item $name -Reason 'not a public named type'
                continue
            }
            if (-not $resolved.Contains($definition.FullName)) {
                $resolved[$definition.FullName] = $definition
                $frontier.Add($definition)
            }
        }
    }
    foreach ($name in $accelerators.Keys) {
        $type = $accelerators[$name] -as [type]
        if ($null -eq $type) { continue }
        $definition = Get-TypeDefinition $type
        if ($null -eq $definition -or $resolved.Contains($definition.FullName)) { continue }
        $resolved[$definition.FullName] = $definition
        $frontier.Add($definition)
    }
    Write-Host ('{0,8} seed types resolved' -f $resolved.Count)

    for ($step = 0; $step -lt $ClosureDepth; $step++) {
        $next = [System.Collections.Generic.List[Type]]::new()
        foreach ($type in $frontier) {
            try {
                $candidates = Get-ClosureCandidates $type
            } catch {
                Add-Problem -Stage 'closure' -Item $type.FullName -Reason $_
                continue
            }
            foreach ($candidate in $candidates) {
                if ($resolved.Contains($candidate.FullName)) { continue }
                $resolved[$candidate.FullName] = $candidate
                $next.Add($candidate)
            }
        }
        $frontier = $next
        Write-Host ('{0,8} types added by closure step {1}' -f $next.Count, ($step + 1))
    }

    $types = [ordered]@{}
    foreach ($key in ($resolved.Keys | Sort-Object)) {
        try {
            $ets = $null
            if ($etsMembers.ContainsKey($key)) { $ets = $etsMembers[$key] }
            $types[$key] = ConvertTo-TypeRecord `
                -Type $resolved[$key] `
                -Seeded ([bool]$seededNames.ContainsKey($key)) `
                -EtsMembers $ets
        } catch {
            Add-Problem -Stage 'reflection' -Item $key -Reason $_
        }
    }
    foreach ($name in $Seeds.types.required) {
        if (-not $types.Contains($name)) {
            Assert-Floor -Stage 'types' -Item $name -Message 'resolved but was not reflected'
        } elseif ($types[$name].members.PSBase.Count -eq 0) {
            Assert-Floor -Stage 'types' -Item $name -Message 'reflected but yielded no members'
        }
    }

    $orderTemplate = @'
try {
    [pscustomobject]@{
        Type  = '__NAME__'
        Error = $null
        Order = @((__EXPR__) | Get-Member | ForEach-Object { $_.Name })
    }
} catch {
    [pscustomobject]@{ Type = '__NAME__'; Error = $_.Exception.Message; Order = $null }
}
'@
    $orderScript = [System.Text.StringBuilder]::new()
    foreach ($name in $InstanceExpressions.Keys) {
        $piece = $orderTemplate.Replace('__NAME__', $name).Replace('__EXPR__', $InstanceExpressions[$name])
        $null = $orderScript.AppendLine($piece)
    }
    foreach ($record in (Invoke-Pristine -Label 'Get-Member order' -Script $orderScript.ToString())) {
        if ($null -ne $record.Error) {
            Add-Problem -Stage 'member_order' -Item $record.Type -Reason $record.Error
            continue
        }
        if (-not $types.Contains($record.Type)) {
            Add-Problem -Stage 'member_order' -Item $record.Type -Reason 'instance type is not collected'
            continue
        }
        $types[$record.Type].member_order = @($record.Order)
    }
    Write-Host ('{0,8} types reflected' -f $types.Count)

    <#
    A command's parameters are the same however its module is loaded, so importing every available
    module before enumerating is pure lookup gain: it takes the commands whose module is present but
    not auto-loaded — Defender, scheduled tasks, BITS, Appx, and the rest — from a null parameter
    list to a complete one. This is safe against the leak the pristine session exists to prevent:
    the generator's own functions live only in the main runspace and are absent here regardless of
    what modules import. It does make the set of command names depend on which modules the box
    carries; narrowing that set to a stable universe for wildcard resolution is a reader policy
    (each command records its module for exactly that), not something to decide by omission here.
    #>
    $commandRecords = Invoke-Pristine -Label 'Get-Command' -Script @'
# Continue, not the prepended Stop: introspecting a script function's parameters can raise a
# non-terminating error that Stop would escalate into a blank parameter list. Real failures still
# reach the error stream and become recorded problems, and the command floor catches the rest.
$WarningPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'
foreach ($available in Get-Module -ListAvailable) {
    try { Import-Module $available.Name -ErrorAction Stop -WarningAction SilentlyContinue }
    catch { Write-Error ("import {0}: {1}" -f $available.Name, $_.Exception.Message) }
}
Get-Command -CommandType Cmdlet, Function | ForEach-Object {
    $command = $_
    # A proxy function's parameters are not realized by bulk enumeration: Format-Hex, the Archive
    # cmdlets and other CmdletBinding wrappers report an empty parameter list until the command is
    # resolved by name, which forces the wrapper to be built. Cmdlets are never affected. Genuinely
    # parameterless functions simply re-resolve to empty again, so this is safe to do for all of them.
    if ($command -is [System.Management.Automation.FunctionInfo] -and
        (($null -eq $command.Parameters) -or ($command.Parameters.PSBase.Count -eq 0))) {
        $byName = @(Get-Command -Name $command.Name -CommandType Function -ErrorAction SilentlyContinue)
        if ($byName.Count -gt 0) { $command = $byName[0] }
    }
    $file = $null
    if ($command -is [System.Management.Automation.FunctionInfo]) { $file = $command.ScriptBlock.File }
    $parameters = @()
    try {
        $values = if ($null -eq $command.Parameters) { @() } else { $command.Parameters.PSBase.Values }
        $parameters = @($values | ForEach-Object {
            [pscustomobject]@{
                Name    = $_.Name
                Type    = $_.ParameterType.FullName
                Switch  = [bool]$_.SwitchParameter
                Aliases = @($_.Aliases)
                Sets    = @($_.ParameterSets.GetEnumerator() | ForEach-Object {
                    [pscustomobject]@{
                        Set            = $_.Key
                        Position       = [int]$_.Value.Position
                        Mandatory      = [bool]$_.Value.IsMandatory
                        Pipeline       = [bool]$_.Value.ValueFromPipeline
                        PipelineByName = [bool]$_.Value.ValueFromPipelineByPropertyName
                        Remaining      = [bool]$_.Value.ValueFromRemainingArguments
                    }
                })
            }
        })
        $parseError = $null
    } catch {
        $parseError = $_.Exception.Message
    }
    [pscustomobject]@{
        Name        = $command.Name
        Kind        = [string]$command.CommandType
        Module      = [string]$command.ModuleName
        File        = $file
        OutputTypes = @($command.OutputType | ForEach-Object { $_.Name })
        Parameters  = $parameters
        Error       = $parseError
    }
}
'@

    $commonParameters = @(
        @([System.Management.Automation.Cmdlet]::CommonParameters) +
        @([System.Management.Automation.Cmdlet]::OptionalCommonParameters) | Sort-Object -Unique
    )
    $commonSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$commonParameters, [System.StringComparer]::OrdinalIgnoreCase)

    $collected = [ordered]@{}
    $duplicates = @{}
    foreach ($record in $commandRecords) {
        $name = $record.Name
        if ($name -match '^[A-Za-z]:$') { continue }
        if ($null -ne $record.File -and $record.File -eq $PSCommandPath) {
            throw "the pristine session resolved '$name' to this generator script"
        }
        if ($collected.Contains($name)) {
            if (-not $duplicates.ContainsKey($name)) { $duplicates[$name] = @() }
            $duplicates[$name] += $record.Module
            continue
        }
        if ($null -ne $record.Error) {
            Add-Problem -Stage 'commands' -Item $name -Reason $record.Error
        }
        $parameters = [ordered]@{}
        foreach ($parameter in ($record.Parameters | Sort-Object Name)) {
            $sets = @()
            foreach ($set in ($parameter.Sets | Sort-Object Set)) {
                $sets += [ordered]@{
                    set              = $set.Set
                    position         = $set.Position
                    mandatory        = $set.Mandatory
                    pipeline         = $set.Pipeline
                    pipeline_by_name = $set.PipelineByName
                    remaining        = $set.Remaining
                }
            }
            $parameters[$parameter.Name] = [ordered]@{
                type    = $parameter.Type
                switch  = $parameter.Switch
                common  = [bool]$commonSet.Contains($parameter.Name)
                aliases = @($parameter.Aliases | Sort-Object)
                sets    = @($sets)
            }
        }
        $outputTypes = @($record.OutputTypes | Sort-Object -Unique)
        $collected[$name] = [ordered]@{
            kind                 = $record.Kind
            module               = $record.Module
            output_types         = $outputTypes
            output_type_declared = [bool]($outputTypes.Count -gt 0)
            parameters           = $parameters
        }
    }

    $commands = [ordered]@{}
    foreach ($name in ($collected.Keys | Sort-Object)) { $commands[$name] = $collected[$name] }

    foreach ($name in ($duplicates.Keys | Sort-Object)) {
        Add-Problem -Stage 'commands' -Item $name -Reason (
            'shadowed by further definitions from: ' + (($duplicates[$name] | Sort-Object) -join ', '))
    }
    foreach ($name in $Seeds.commands.required) {
        if (-not $commands.Contains($name)) {
            Assert-Floor -Stage 'commands' -Item $name -Message 'not present'
        } elseif ($commands[$name].parameters.PSBase.Count -eq 0) {
            Assert-Floor -Stage 'commands' -Item $name -Message 'present but carries no parameters'
        }
    }
    $modulesSeen = @{}
    foreach ($name in $commands.PSBase.Keys) {
        if ($commands[$name].parameters.PSBase.Count -gt 0) { $modulesSeen[$commands[$name].module] = $true }
    }
    foreach ($module in $Seeds.modules.required) {
        if (-not $modulesSeen.ContainsKey($module)) {
            Assert-Floor -Stage 'modules' -Item $module -Message 'contributed no command with parameters'
        }
    }
    Write-Host ('{0,8} commands' -f $commands.Count)

    $aliases = [ordered]@{}
    $aliasRecords = Invoke-Pristine -Label 'Get-Alias' -Script @'
# Aliases are module-contributed the same way commands are, so the alias table has to be built
# against the same imported surface Get-Command uses. A bare pristine session lists only the core
# aliases and drops every module-provided short form, the CimCmdlets ones (gcim, icim, ...) among
# them. The Continue preference and per-import catch mirror the command query for the same reason.
$WarningPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'
foreach ($available in Get-Module -ListAvailable) {
    try { Import-Module $available.Name -ErrorAction Stop -WarningAction SilentlyContinue }
    catch { Write-Error ("import {0}: {1}" -f $available.Name, $_.Exception.Message) }
}
Get-Alias | Sort-Object Name | ForEach-Object {
    [pscustomobject]@{ Name = $_.Name; Definition = $_.Definition }
}
'@
    foreach ($record in $aliasRecords) { $aliases[$record.Name] = $record.Definition }

    $variables = [ordered]@{}
    $variableRecords = Invoke-Pristine -Label 'Get-Variable' -Script @'
Get-Variable | Sort-Object Name | ForEach-Object {
    $type = $null
    try { if ($null -ne $_.Value) { $type = $_.Value.GetType().FullName } } catch { }
    [pscustomobject]@{ Name = $_.Name; Type = $type; Options = [string]$_.Options }
}
'@
    foreach ($record in $variableRecords) {
        $variables[$record.Name] = [ordered]@{
            type    = $record.Type
            options = $record.Options
        }
    }
    Write-Host ('{0,8} aliases, {1} variables' -f $aliases.Count, $variables.Count)

    $namespaces = [ordered]@{}
    foreach ($namespace in $Seeds.wmi.namespaces) {
        $classes = [ordered]@{}
        try {
            $cimClasses = @(Get-CimClass -Namespace $namespace | Sort-Object CimClassName)
        } catch {
            Add-Problem -Stage 'wmi' -Item $namespace -Reason $_
            $namespaces[$namespace] = $classes
            continue
        }
        foreach ($cimClass in $cimClasses) {
            $className = $cimClass.CimClassName
            try {
                $properties = [ordered]@{}
                foreach ($property in ($cimClass.CimClassProperties | Sort-Object Name)) {
                    $properties[$property.Name] = [string]$property.CimType
                }
                $methods = [ordered]@{}
                foreach ($method in ($cimClass.CimClassMethods | Sort-Object Name)) {
                    $methods[$method.Name] = @(
                        $method.Parameters | Sort-Object Name | ForEach-Object { $_.Name })
                }
                $classes[$className] = [ordered]@{
                    superclass = [string]$cimClass.CimSuperClassName
                    properties = $properties
                    methods    = $methods
                }
            } catch {
                Add-Problem -Stage 'wmi' -Item "$namespace/$className" -Reason $_
            }
        }
        $namespaces[$namespace] = $classes
        Write-Host ('{0,8} classes in {1}' -f $classes.Count, $namespace)
    }
    foreach ($namespace in $Seeds.wmi.required) {
        if (-not $namespaces.Contains($namespace) -or $namespaces[$namespace].PSBase.Count -eq 0) {
            Assert-Floor -Stage 'wmi' -Item $namespace -Message 'yielded no classes'
        }
    }

    $memberCount = 0
    $overloadCount = 0
    foreach ($key in $types.PSBase.Keys) {
        $memberCount += $types[$key].members.PSBase.Count
        foreach ($member in $types[$key].members.PSBase.Values) {
            if ($member.kind -eq 'method') { $overloadCount += $member.overloads.Count }
        }
    }
    $wmiClassCount = 0
    foreach ($namespace in $namespaces.PSBase.Keys) { $wmiClassCount += $namespaces[$namespace].PSBase.Count }

    $meta = [ordered]@{
        schema        = [ordered]@{ version = $SchemaVersion }
        generator     = [ordered]@{
            version       = $GeneratorVersion
            closure_depth = $ClosureDepth
            seed_file     = [System.IO.Path]::GetFileName($SeedFile)
        }
        authoritative = [bool](-not $Unauthoritative)
        host          = [ordered]@{
            ps_version = [string]$PSVersionTable.PSVersion
            ps_edition = [string]$PSVersionTable.PSEdition
            platform   = [string][System.Environment]::OSVersion.Platform
            os         = [string][System.Environment]::OSVersion.VersionString
            culture    = [string](Get-Culture).Name
            bits       = [int]([IntPtr]::Size * 8)
        }
        counts        = [ordered]@{
            accelerators = $accelerators.Count
            types        = $types.Count
            members      = $memberCount
            overloads    = $overloadCount
            commands     = $commands.Count
            aliases      = $aliases.Count
            variables    = $variables.Count
            wmi_classes  = $wmiClassCount
        }
        problems      = @($Problems)
    }

    $files = [ordered]@{
        'pwsh-types.json'     = [ordered]@{ accelerators = $accelerators; types = $types }
        'pwsh-commands.json'  = [ordered]@{
            common_parameters = @($commonParameters)
            commands          = $commands
            aliases           = $aliases
        }
        'pwsh-variables.json' = [ordered]@{ variables = $variables }
        'pwsh-wmi.json'       = [ordered]@{ namespaces = $namespaces }
        'pwsh-meta.json'      = $meta
    }
    foreach ($name in $files.Keys) {
        $outputSizes[$name] = Write-JsonFile -Path (Join-Path $OutputDirectory $name) -Value $files[$name]
    }

} catch {
    $failure = [ordered]@{
        structural_failure = [string]$_.Exception.Message
        position           = [string]$_.InvocationInfo.PositionMessage
        problems           = @($Problems)
    }
    $diagnostics = Join-Path $OutputDirectory 'pwsh-meta.failed.json'
    try {
        $null = Write-JsonFile -Path $diagnostics -Value $failure
        Write-Host "`nSTRUCTURAL FAILURE. No data written. Diagnostics: $diagnostics"
    } catch {
        Write-Host "`nSTRUCTURAL FAILURE, and the diagnostics could not be written either."
    }
    Write-Host $failure.structural_failure
    exit 1
}

Write-Host ''
if ($Unauthoritative) {
    Write-Host "-Unauthoritative: this is not shippable data. Written to $OutputDirectory"
}
foreach ($name in $outputSizes.Keys) {
    Write-Host ('{0,8} KB {1}' -f [math]::Round($outputSizes[$name] / 1024), $name)
}
Write-Host ''
Write-Host ('{0,8} problems' -f $Problems.Count)
foreach ($problem in ($Problems | Select-Object -First 25)) {
    Write-Host ('         {0}/{1}: {2}' -f $problem.stage, $problem.item, $problem.message)
}
if ($Problems.Count -gt 25) {
    Write-Host ('         ... and {0} more, all recorded in pwsh-meta.json' -f ($Problems.Count - 25))
}
