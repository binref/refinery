"""
The .NET type and PowerShell command database that the PowerShell analysis and deobfuscation
subsystems share: type accelerators and members, command names, aliases and parameters, WMI classes,
and the small lookup tables built from them. The data is collected by run-pwsh.ps1 on genuine
Windows PowerShell 5.1 and shipped as the compressed `pwsh-*.json.xz` resources.

Every question about a *type* is asked of the query API at the end — `resolve_type` and the
functions built on it. `resolve_type` is the only thing that mints a canonical `Ps1TypeName`, and
every table below is keyed by one, which is what makes two spellings of a type comparable at all:
`char[]`, `System.Char[]` and `[Char[]]` are one name, and none of them is `System.Char`.

The remaining `*` tables (`KNOWN_CMDLETS`, `CANONICAL_TYPE_NAMES`, ...) are about *commands* and
*display*, not about type identity.
"""
from __future__ import annotations

import copy
import enum
import functools
import lzma
import operator
import re
import typing
from collections import defaultdict

from refinery.lib.json import loads
from refinery.lib.resources import datapath
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName, parse_type_name

SCHEMA_VERSION = 1


def _load(name: str) -> dict:
    """
    One captured table, as it ships: LZMA over compact JSON.

    LZMA rather than gzip because these tables are long stretches of repeated key names and type
    names, which a large compression window roughly halves where gzip and a binary encoding both do
    worse. Reading them through `refinery.lib.json` more than repays the extra decompression cost
    where its preferred backend is present; where that backend is absent the standard-library
    fallback is a few percent slower to load.
    """
    with datapath(name).open('rb') as fp:
        return loads(lzma.decompress(fp.read()))


_META = _load('pwsh-meta.json.xz')
_schema = _META['schema']['version']
if _schema != SCHEMA_VERSION:
    raise ValueError(
        F'pwsh metadata schema version {_schema} is not the expected {SCHEMA_VERSION}; '
        F'the reader and the collected data are out of step.'
    )

_TYPES = _load('pwsh-types.json.xz')
_COMMANDS = _load('pwsh-commands.json.xz')
_VARIABLES = _load('pwsh-variables.json.xz')
_WMI = _load('pwsh-wmi.json.xz')

#: Type names PowerShell's *parser* understands that are not registered type accelerators, so a
#: collection run on a real host does not report them however authoritative it is — `[ordered]` is
#: recognized in a cast position and denotes an `OrderedDictionary`, but it is absent from the 94
#: accelerators our capture reports because it never was one. Kept beside the collected table rather
#: than injected into it: the data describes a host's .NET surface and this describes the language,
#: and blurring the two would cost the collected table the provenance that makes it trustworthy.
_PARSER_TYPE_KEYWORDS: dict[str, str] = {
    'ordered': 'System.Collections.Specialized.OrderedDictionary',
}

_ACCELERATORS: dict[str, str] = {
    **_PARSER_TYPE_KEYWORDS,
    **{_alias.lower(): _full for _alias, _full in _TYPES['accelerators'].items()},
}


def _engine_enum(name: str, members: dict[str, int]) -> dict:
    """
    A record for an enum the engine defines, shaped as the capture shapes one so that the one
    resolver answers for it: reflection gives every enum the instance surface of `System.Enum`, an
    Int32 `value__` and one static field per member, which is the record the capture holds for
    `ConfirmImpact` and what is composed here for a sibling it does not hold. The inherited records
    are copied, as the capture gives every enum records of its own, so that nothing reached through
    this record can write into `System.Enum`'s.
    """
    inherited = {
        member: copy.deepcopy(record)
        for member, record in _TYPES['types']['System.Enum']['members'].items()
        if record['kind'] == 'method'
        and not any(overload['static'] for overload in record['overloads'])
    }
    fields = {
        member: {
            'kind': 'field',
            'source': 'reflection',
            'type': name,
            'static': True,
            'readable': True,
            'writable': False,
        }
        for member in members
    }
    ordinal = {
        'kind': 'field',
        'source': 'reflection',
        'type': 'System.Int32',
        'static': False,
        'readable': True,
        'writable': True,
    }
    return {
        'kind': 'enum',
        'base': 'System.Enum',
        'sealed': True,
        'abstract': False,
        'interfaces': ['System.IComparable', 'System.IConvertible', 'System.IFormattable'],
        'enum_values': {member: str(value) for member, value in members.items()},
        'seeded': False,
        'member_order': None,
        'constructors': [],
        'members': {**inherited, **fields, 'value__': ordinal},
    }


#: The members of the enums the engine defines that the capture does not report, kept beside the
#: collected table for the reason `_PARSER_TYPE_KEYWORDS` is: a record written by hand must not
#: borrow the provenance of the collected ones. `ActionPreference` is the type of six of the seven
#: `$…Preference` variables — the capture does report `ConfirmImpact`, the seventh's — and its
#: members are those of Windows PowerShell 5.1, measured on one, where a later engine adds `Break`.
#: The record composed from an entry here wins over a captured one, so a recapture on a later host
#: cannot move an answer; what says an entry may go is
#: `test_the_captured_type_table_is_not_where_the_engine_enum_is_supplied`, which fails the moment
#: a capture reports the type.
_ENGINE_ENUMS: dict[str, dict[str, int]] = {
    'System.Management.Automation.ActionPreference': {
        'SilentlyContinue': 0,
        'Stop': 1,
        'Continue': 2,
        'Inquire': 3,
        'Ignore': 4,
        'Suspend': 5,
    },
}

_ENGINE_TYPES: dict[str, dict] = {
    _name: _engine_enum(_name, _members) for _name, _members in _ENGINE_ENUMS.items()
}

#: The .NET types the resolver answers for: the collected table and, beside it, the engine's own.
_TYPE_TABLE: dict[str, dict] = {**_TYPES['types'], **_ENGINE_TYPES}


class _EnumTable(typing.NamedTuple):
    """
    What is read off an enum record: each member's ordinal under the lowercased name 5.1 matches
    it by, the member each ordinal spells where exactly one holds it, and the integer type the
    ordinals are stored in.
    """
    ordinals: dict[str, int]
    names: dict[int, str]
    storage: str | None


def _enum_table(record: dict) -> _EnumTable:
    """
    The `_EnumTable` of one enum record. The capture records an ordinal as a string, read here as
    the number that selects the member, so a malformed one stops the module from loading rather than
    the first question asked of it. A name is keyed lowercased and the first spelling of a name
    wins, which is the case-insensitive first match PowerShell resolves a member by; an ordinal that
    several members hold spells none of them, because .NET does not say which name it writes for
    one and a spelling this cannot settle is refused rather than picked.
    """
    values = {
        member: int(ordinal) for member, ordinal in (record.get('enum_values') or {}).items()
    }
    ordinals: dict[str, int] = {}
    holders: defaultdict[int, list[str]] = defaultdict(list)
    for member, ordinal in values.items():
        ordinals.setdefault(member.lower(), ordinal)
        holders[ordinal].append(member)
    names = {ordinal: members[0] for ordinal, members in holders.items() if len(members) == 1}
    field = record['members'].get('value__')
    storage = None if field is None else field.get('type')
    return _EnumTable(ordinals, names, storage)


#: Every enum the resolver answers for, read once beside the type table it is built from, so that
#: a question about a member is a dictionary read wherever a value is converted or spelled.
_ENUM_TABLES: dict[str, _EnumTable] = {
    _key: _enum_table(_record)
    for _key, _record in _TYPE_TABLE.items()
    if _record.get('kind') == 'enum'
}

#: Commands the capture reports that the host does not have. `Format-Hex` leaked in from a shadowing
#: PowerShell 7.0 `Microsoft.PowerShell.Utility` module; a 5.1 host cannot run it.
#:
#: A record for a command the host cannot run is not inert: the wildcard resolver draws its
#: candidate universe from `KNOWN_CMDLETS`, so `Get-Command Format-H*` would have a unique match and
#: be rewritten into a call to a command 5.1 reports as not found. Withheld from the derived table
#: rather than deleted from the capture, which stays as collected.
_MISCOLLECTED_COMMANDS = frozenset({'format-hex'})

#: The bare nouns that name a program Windows itself ships, so that 5.1 runs the program rather than
#: retrying the name with a `Get-` prefix — the Application tier, which sits above that retry and
#: which no capture of the session's tables can describe. `tpm` opens `C:\Windows\system32\tpm.msc`,
#: and `Get-Tpm` is what we answered for it.
#:
#: Derived by intersecting every PATHEXT-matching file in `System32` and `Windows` with the 523 bare
#: nouns `refinery.lib.scripts.ps1.ast.implicit_get_retry` rewrites; `tpm` is the whole intersection.
#: A program the analyst installed cannot be here and is the declared residual: `date` resolves to
#: Git's `date.exe` on the development box and to `Get-Date` on one without it, and nothing readable
#: from a script says which. This is a floor under that residual rather than a fix for it.
PROGRAM_NAMES = frozenset({'tpm'})

_COMMAND_TABLE: dict[str, dict] = {
    _name: _record for _name, _record in _COMMANDS['commands'].items()
    if _name.lower() not in _MISCOLLECTED_COMMANDS
}

#: The member kinds these views expose. Fields and every Extended Type System member (`ets_*`) are
#: collected but withheld from them; the query API exposes those separately.
_VIEW_MEMBER_KINDS = frozenset({'method', 'property'})

#: The members whose value the receiver's shape decides rather than anything it holds — the count of
#: a collection and the dimension of an array. They are pure by construction, which is why the folder
#: computes them off a literal receiver and the trap-removal reader may treat a bare read of one as
#: droppable where it keeps a read of any other member, whose getter it cannot prove pure.
SHAPE_MEMBERS = frozenset({'length', 'count', 'rank'})


def _view_members(record: dict) -> dict[str, dict]:
    return {
        name: member
        for name, member in record['members'].items()
        if member['source'] in ('reflection', 'wmi') and member['kind'] in _VIEW_MEMBER_KINDS
    }


VARIABLE_TYPES: dict[str, str] = {
    _name.lower(): _info['type'].lower()
    for _name, _info in _VARIABLES['variables'].items()
    if _info['type'] is not None
}
#: `$PSCmdlet` exists only inside an advanced function's scope, so the pristine `Get-Variable` the
#: generator runs never sees it. It is supplied here because it cannot be collected rather than
#: because it is absent.
VARIABLE_TYPES.setdefault('pscmdlet', 'system.management.automation.psscriptcmdlet')

#: The set of type-accelerator spellings, lowercased. An accelerator is already the shortest
#: readable name for its type, so display normalization leaves it as written rather than expanding
#: it to the verbose full name: `[ref]` and `[int]` stay, where `[System.Int32]` folds to `[Int32]`.
TYPE_ACCELERATORS: frozenset[str] = frozenset(_alias.lower() for _alias in _ACCELERATORS)

CANONICAL_TYPE_NAMES: dict[str, str] = {}

for _alias, _full in _ACCELERATORS.items():
    _display = _full.removeprefix('System.')
    CANONICAL_TYPE_NAMES[_alias.lower()] = _display
    CANONICAL_TYPE_NAMES[_full.lower()] = _display
for _full in _TYPE_TABLE:
    _display = _full.removeprefix('System.')
    CANONICAL_TYPE_NAMES.setdefault(_full.lower(), _display)
    CANONICAL_TYPE_NAMES.setdefault(_full.lower().removeprefix('system.'), _display)

WMI_CLASS_NAMES: dict[str, str] = {}

for _classes in _WMI['namespaces'].values():
    for _cls in _classes:
        WMI_CLASS_NAMES.setdefault(_cls.lower(), _cls)
        CANONICAL_TYPE_NAMES.setdefault(_cls.lower(), _cls)

CANONICAL_TYPE_NAMES.setdefault(
    'management.automation.sessionstateinternal',
    'Management.Automation.SessionStateInternal',
)


def is_type(name: str, target: str) -> bool:
    """
    Whether a type name as written in PowerShell source names the same type as `target`. Both sides
    go through `resolve_type`, so no difference of spelling can make two names for one type answer
    `False`: an accelerator, an omitted `System.` prefix, a difference of case, whitespace inside the
    name, an assembly qualification and a generic argument list are all understood.
    """
    resolved = resolve_type(name)
    return resolved is not None and resolved == resolve_type(target)


#: The aliases the host binds, and nothing else. An entry here is not a harmless surplus: nothing in
#: ordinary name lookup beats an alias, so a name added here is taken away from whatever 5.1 would
#: have given it. The engine's implicit `Get-` retry (`childitem`, `item`, ...) is not an alias — it
#: is a *last resort* reached only once the alias, function and cmdlet tables have missed, so
#: `function item { }` beats it — and lives in `refinery.lib.scripts.ps1.ast.implicit_get_retry`.
#:
#: A wrong record in either table is not merely surplus: two things read them in a direction it
#: corrupts. `refinery.lib.scripts.ps1.deobfuscation.wildcards` matches a wildcard against
#: `KNOWN_CMDLETS` and emits the unique hit as a command, and
#: `refinery.lib.scripts.ps1.ast.implicit_get_retry` refuses a retry for any name a table claims, so
#: a record for a command the host does not have suppresses a retry 5.1 performs.
#:
#: Anything added to either table has to be measured on a host first, and the ps1 oracle corpus is
#: where such a measurement is recorded.
KNOWN_ALIAS: dict[str, str] = {
    _name.lower(): _definition for _name, _definition in _COMMANDS['aliases'].items()
}

#: The CimCmdlets short forms are module-provided aliases, and a bare pristine `Get-Alias` does not
#: list them even though their target cmdlets are collected. `run-pwsh.ps1` now imports the modules
#: before enumerating aliases, but the shipped data predates that fix, so they are restored here
#: until the next regeneration; each target is a canonical name already in `KNOWN_CMDLETS`.
for _cim_alias, _cim_command in {
    'gcai' : 'Get-CimAssociatedInstance',
    'gcim' : 'Get-CimInstance',
    'gcls' : 'Get-CimClass',
    'gcms' : 'Get-CimSession',
    'icim' : 'Invoke-CimMethod',
    'ncim' : 'New-CimInstance',
    'ncms' : 'New-CimSession',
    'ncso' : 'New-CimSessionOption',
    'rcie' : 'Register-CimIndicationEvent',
    'rcim' : 'Remove-CimInstance',
    'rcms' : 'Remove-CimSession',
    'scim' : 'Set-CimInstance',
}.items():
    KNOWN_ALIAS.setdefault(_cim_alias, _cim_command)

KNOWN_PS_OPERATORS: dict[str, str] = {name.lower(): name for name in [
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
    '-In',
    '-IReplace',
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
]}

KNOWN_PS_SWITCHES: dict[str, str] = {name.lower(): name for name in [
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
]}

KNOWN_CMDLETS: dict[str, str] = {name.lower(): name for name in _COMMAND_TABLE}
KNOWN_CMDLETS.setdefault('convertfrom-base64', 'ConvertFrom-Base64')
KNOWN_CMDLETS.setdefault('powershell', 'PowerShell')

for _n in KNOWN_ALIAS.values():
    KNOWN_CMDLETS.setdefault(_n.lower(), _n)

CMDLET_PARAMETERS: dict[str, list[str]] = {
    _name.lower(): [
        _param for _param, _info in _record['parameters'].items() if not _info['common']
    ]
    for _name, _record in _COMMAND_TABLE.items()
}

ALL_PARAMETER_NAMES: dict[str, str] = {}

for _params in CMDLET_PARAMETERS.values():
    for _p in _params:
        ALL_PARAMETER_NAMES.setdefault(_p.lower(), _p)

#: The PowerShell common parameters, keyed by lowercased name and mapped to their lowercased
#: aliases. These are the parameters every advanced command shares (`-ErrorAction`, `-OutVariable`,
#: `-Verbose`, ...), which `CMDLET_PARAMETERS` and the views built from it deliberately exclude.
#: This is the one place they are surfaced, so a consumer reasoning about them — the out-variable
#: purity check does — reads them from the collected data rather than hardcoding the set. They are
#: identical on every command, so a single advanced command already determines the whole set; the
#: union is taken regardless so the first command that happens to lack one does not drop it.
COMMON_PARAMETERS: dict[str, tuple[str, ...]] = {}

for _record in _COMMAND_TABLE.values():
    for _param, _info in _record['parameters'].items():
        if _info['common']:
            COMMON_PARAMETERS.setdefault(
                _param.lower(),
                tuple(_alias.lower() for _alias in _info['aliases']),
            )

#: The common parameters that bind their argument as the *name* of a variable the command fills:
#: `-OutVariable`, `-ErrorVariable` and the rest, with their aliases (`ov`, `ev`, ...). A common
#: parameter names a variable exactly when its name ends in `Variable`, the convention the engine
#: defines them under, which `-OutBuffer` (a count) is the one common parameter to fail.
#:
#: These are the names a caller means when it asks which parameters address a variable by string,
#: and they are deliberately *not* the same set as the parameters that make a command impure:
#: `refinery.lib.scripts.ps1.analysis.effects` adds `-SetSeed` to that one, a `Get-Random` switch
#: that rewrites the generator state and names no variable at all. A consumer reading the impurity
#: set for names would take the `5` of `Get-Random -SetSeed 5` for a variable called `5`.
#: The out-variable parameters the derivation below must produce. Each is a fixed engine contract
#: whose loss silences a real write, so a collected surface that no longer carries one fails the
#: load rather than letting the set shrink silently.
REQUIRED_OUT_VARIABLE_PARAMETERS = frozenset({
    'errorvariable',
    'informationvariable',
    'outvariable',
    'pipelinevariable',
    'warningvariable',
})


def _derive_out_variable_parameters(common: dict[str, tuple[str, ...]]) -> frozenset[str]:
    """
    The out-variable parameters and their aliases, from a collected common-parameter surface.

    Taken as an argument rather than read from the module so the floor below can be exercised
    against a surface that has lost one; a check that only ever runs on the real data, at import,
    cannot be shown to work.
    """
    names: set[str] = set()
    for parameter, aliases in common.items():
        if parameter.endswith('variable'):
            names.add(parameter)
            names.update(aliases)
    if missing := REQUIRED_OUT_VARIABLE_PARAMETERS - names:
        raise ValueError(
            F'the collected common parameters no longer surface the out-variable parameters '
            F'{sorted(missing)!r}; every view built on them would silently stop treating those '
            F'parameters as naming a variable, so the data and this module are out of step.'
        )
    return frozenset(names)


OUT_VARIABLE_PARAMETERS = _derive_out_variable_parameters(COMMON_PARAMETERS)

_VALUE_PARAMETERS: dict[str, frozenset[str]] = {}
_SCRIPTBLOCK_PARAMETERS: dict[str, frozenset[str]] = {}
_PARAMETER_SETS: dict[str, dict[str, frozenset[str]]] = {}
_POSITIONAL_SCRIPTBLOCK_SETS: dict[str, frozenset[str]] = {}

_COMMAND_RECORDS: dict[str, dict] = {
    _name.lower(): _record for _name, _record in _COMMAND_TABLE.items()
}


def value_parameters(command: str) -> frozenset[str]:
    """
    The lowercased parameter names and aliases of *command* that take a value, as opposed to the
    switches that stand alone. Empty for a command the collected surface does not carry.

    A caller reading a command's arguments needs this to tell `-Name x`, where `x` is the value of
    `-Name`, from `-Recurse C:\\`, where the path is a positional argument of its own. The parser
    renders both as a switch followed by a positional because it has no parameter metadata; this is
    that metadata.

    Looked up and memoized per command rather than built for every command at import: the table
    carries thousands of commands and a caller asks about a handful.
    """
    command = command.lower()
    found = _VALUE_PARAMETERS.get(command)
    if found is None:
        names: set[str] = set()
        for _parameter, _info in _COMMAND_RECORDS.get(command, {}).get('parameters', {}).items():
            if _info['switch']:
                continue
            names.add(_parameter.lower())
            names.update(_alias.lower() for _alias in _info['aliases'])
        found = _VALUE_PARAMETERS[command] = frozenset(names)
    return found


_ABBREVIATION_POOLS: dict[str, tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]] = {}


def _abbreviation_pools(command: str):
    """
    The two pools *command* binds a parameter out of: its own parameter names and aliases, and its
    per-cmdlet common ones, each entry the lowercased spelling paired with the full-cased parameter
    it names. `None` for a command the collected surface does not carry.

    Memoized for the same reason `value_parameters` is: the table carries thousands of commands and
    a caller asks about a handful.
    """
    command = command.lower()
    found = _ABBREVIATION_POOLS.get(command)
    if found is not None:
        return found
    record = _COMMAND_RECORDS.get(command)
    if record is None:
        return None
    own: list[tuple[str, str]] = []
    common: list[tuple[str, str]] = []
    for _parameter, _info in record['parameters'].items():
        _pool = common if _info['common'] else own
        _pool.append((_parameter.lower(), _parameter))
        _pool.extend((_alias.lower(), _parameter) for _alias in _info['aliases'])
    found = _ABBREVIATION_POOLS[command] = (tuple(own), tuple(common))
    return found


def abbreviated_parameter(command: str, written: str) -> str | None:
    """
    The full parameter name *written* binds on *command*, or `None` where it binds none, is
    ambiguous, or the collected surface carries no record for the command.

    PowerShell binds a parameter by its full name or by any alias, and by any prefix that names one
    parameter unambiguously; a cmdlet's own parameters win over the common ones where a prefix
    matches both pools — measured on 5.1, `Set-Alias q -V Write-Output` binds `-Value` although
    the common `Verbose` also matches `v`. An exact hit on an alias is taken before any prefix is
    considered, which is the discriminating case for `Add-Member -Type`: the alias names
    `MemberType` and no prefix question is asked.

    A prefix that names two or more of the cmdlet's own parameters binds nothing — 5.1 reports it
    ambiguous rather than reaching past them to a common parameter — so the common pool is consulted
    only where no own parameter is a prefix at all. Reading own ambiguity as a licence to expand a
    common name would rewrite `Copy-Item x y -p`, which 5.1 rejects between `Path` and `PassThru`,
    into a `-PipelineVariable` bind the script never had.

    The pools are the command's own record and never the union tables, because the common
    parameters are per-cmdlet on 5.1 — measured, `Get-Date -c` is `NamedParameterNotFound` where
    `Remove-Item -c` asks whether to confirm. The residual of reading a collected surface rather
    than the cmdlet itself is stated where the rewrite is done: a prefix unique here but ambiguous
    on the real cmdlet would be expanded, and closing it means re-collecting the surface from 5.1.
    """
    pools = _abbreviation_pools(command)
    if pools is None:
        return None
    written = written.lower().lstrip('-')
    if not written:
        return None
    own, common = pools
    for pool in (own, common):
        for spelling, parameter in pool:
            if spelling == written:
                return parameter
    own_prefixed = {parameter for spelling, parameter in own if spelling.startswith(written)}
    if len(own_prefixed) == 1:
        return next(iter(own_prefixed))
    if own_prefixed:
        return None
    common_prefixed = {parameter for spelling, parameter in common if spelling.startswith(written)}
    if len(common_prefixed) == 1:
        return next(iter(common_prefixed))
    return None


def scriptblock_parameters(command: str) -> frozenset[str]:
    """
    The lowercased parameter names and aliases of *command* that are declared to take a script
    block, as opposed to the ones that take a value of any other kind. Empty for a command the
    collected surface does not carry.

    A caller asking where a block written as an argument ends up needs this to tell
    `ForEach-Object -Process { ... }`, which the command runs, from `ForEach-Object -InputObject
    { ... }`, which hands the block on as data and never runs it.

    An array element type counts: `-Process` is declared `ScriptBlock[]` and `-Begin` is declared
    `ScriptBlock`, and both are run.

    Looked up and memoized per command for the reason `value_parameters` gives.
    """
    command = command.lower()
    found = _SCRIPTBLOCK_PARAMETERS.get(command)
    if found is None:
        names: set[str] = set()
        for _parameter, _info in _COMMAND_RECORDS.get(command, {}).get('parameters', {}).items():
            if _info['type'].rstrip('[]') != 'System.Management.Automation.ScriptBlock':
                continue
            names.add(_parameter.lower())
            names.update(_alias.lower() for _alias in _info['aliases'])
        found = _SCRIPTBLOCK_PARAMETERS[command] = frozenset(names)
    return found


#: The set name the engine records for a parameter that belongs to every parameter set of its
#: command, rather than to any one of them. Every common parameter carries it.
EVERY_PARAMETER_SET = '__AllParameterSets'


def parameter_sets(command: str) -> dict[str, frozenset[str]]:
    """
    The parameter sets each parameter of *command* belongs to, keyed by lowercased parameter name
    and by each of its aliases. Empty for a command the collected surface does not carry.

    5.1 chooses one set from the arguments a call writes, and the same position can mean a different
    thing in each: `ForEach-Object` has a script block at position 0 of its `ScriptBlockSet` and a
    member name at position 0 of its `PropertyAndMethodSet`. A caller reading what a positional
    argument binds needs this to know which set the call is in.

    Looked up and memoized per command for the reason `value_parameters` gives.
    """
    command = command.lower()
    found = _PARAMETER_SETS.get(command)
    if found is None:
        table: dict[str, frozenset[str]] = {}
        for _parameter, _info in _COMMAND_RECORDS.get(command, {}).get('parameters', {}).items():
            names = frozenset(_set['set'] for _set in _info['sets'])
            table[_parameter.lower()] = names
            for _alias in _info['aliases']:
                table[_alias.lower()] = names
        found = _PARAMETER_SETS[command] = table
    return found


def positional_scriptblock_sets(command: str) -> frozenset[str]:
    """
    The parameter sets of *command* in which the first positional argument binds a parameter
    declared to take a script block. Empty where the command has no such parameter at all, and a
    positional block then binds nothing this can name.
    """
    command = command.lower()
    found = _POSITIONAL_SCRIPTBLOCK_SETS.get(command)
    if found is None:
        names: set[str] = set()
        for _parameter, _info in _COMMAND_RECORDS.get(command, {}).get('parameters', {}).items():
            if _info['type'].rstrip('[]') != 'System.Management.Automation.ScriptBlock':
                continue
            names.update(_set['set'] for _set in _info['sets'] if _set['position'] == 0)
        found = _POSITIONAL_SCRIPTBLOCK_SETS[command] = frozenset(names)
    return found


SIMPLE_IDENTIFIER = re.compile(r'^[a-zA-Z_]\w*$')

OBJ_COMMANDS = frozenset({
    'new-object',
})

WMI_COMMANDS = frozenset({
    'get-ciminstance',
    'get-wmiobject',
})

TYPE_ARG_COMMANDS = frozenset(OBJ_COMMANDS | WMI_COMMANDS)

GET_MEMBER_ALIASES = frozenset({'get-member', 'gm'})
GET_COMMAND_ALIASES = frozenset({'get-command', 'gcm'})

FOREACH_ALIASES = frozenset({'%', 'foreach', 'foreach-object'})

COMPARISON_OPS = {
    '-eq': operator.eq,
    '-ne': operator.ne,
    '-lt': operator.lt,
    '-le': operator.le,
    '-gt': operator.gt,
    '-ge': operator.ge,
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
        'False',
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
        'Null',
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
        'True',
        'VerbosePreference',
        'WarningPreference',
        'WhatIfPreference',
    ]
}

FORMAT_PATTERN = re.compile(r'\{\{|\}\}|\{(\d+)(?:,(-?\d+))?(?::([^}]+))?\}')


def resolve_type(name: str | Ps1TypeName) -> Ps1TypeName | None:
    """
    Resolve a .NET type name as written in PowerShell source to the one canonical `Ps1TypeName` the
    collected metadata is keyed by, or `None` when the name is syntactically not a type or names a
    type that was not collected. This understands the whole type-name grammar — accelerators, an
    omitted `System.` prefix, generic arity, arrays — and it is the **only** thing that mints a
    canonical name, which is what makes a canonical name comparable to another one.

    A parsed name is not canonical: `System.Int32`, `system.int32` and `System.Int32, mscorlib` parse
    to three unequal, differently hashing tuples, as do the two spellings of a list type. So the
    result is *rebuilt* rather than returned — the collected record's own casing for the name, the
    assembly qualification dropped because it does not distinguish a type here, and the arguments
    resolved in turn. An argument that does not resolve makes the whole name unresolved, since a
    name is only as understood as its least understood part.

    The array suffixes are carried rather than dropped, so `char[]` resolves to a name distinct from
    `System.Char`; what an array's members actually are is `_member_surface`'s question, asked of the
    name this returns.
    """
    parsed = parse_type_name(name) if isinstance(name, str) else name
    if parsed is None:
        return None
    return _canonical_type_name(parsed)


def named_type(name: str) -> Ps1TypeName:
    """
    A type a *module* names, rather than one a script did: `resolve_type` with the unresolved case
    treated as the defect it is. A module that writes a type name out and gets `None` back does not
    receive a weaker answer, it receives a comparison that is silently false forever after, so this
    raises at import instead of letting one through. Anything read out of a script goes through
    `resolve_type`, where not being a type is an ordinary answer.
    """
    resolved = resolve_type(name)
    if resolved is None:
        raise ValueError(F'the collected type table does not resolve {name}')
    return resolved


def _canonical_type_name(parsed: Ps1TypeName) -> Ps1TypeName | None:
    for candidate in _definition_candidates(parsed.definition):
        if candidate not in _TYPE_TABLE and candidate not in _WMI_TYPES:
            continue
        arguments: list[Ps1TypeName] = []
        for argument in parsed.arguments:
            resolved = _canonical_type_name(argument)
            if resolved is None:
                return None
            arguments.append(resolved)
        base, _, arity = candidate.partition('`')
        return Ps1TypeName(
            name=base,
            arity=int(arity) if arity else 0,
            arguments=tuple(arguments),
            ranks=parsed.ranks,
            pointers=parsed.pointers,
            byref=parsed.byref,
        )
    return None


def _definition_candidates(definition: str):
    lower = definition.lower()
    accel = _ACCELERATORS.get(lower)
    if accel is not None:
        yield accel
    for key in _TYPE_LOOKUP.get(lower, ()):
        yield key


_TYPE_LOOKUP: dict[str, list[str]] = {}

for _full in _TYPE_TABLE:
    _TYPE_LOOKUP.setdefault(_full.lower(), []).append(_full)
    _bare = _full.removeprefix('System.').lower()
    if _bare != _full.lower():
        _TYPE_LOOKUP.setdefault(_bare, []).append(_full)

#: The WMI classes, shaped like a collected type record so that one resolver answers for them too. A
#: WMI class is a type a PowerShell expression can have — `Get-WmiObject Win32_Process` yields one.
#:
#: The capture records a class's property *names* and not their types, so each member says so with a
#: `type` of `None`: a chain through a WMI property stops resolving there, which is the honest
#: answer rather than a guess. `source` is its own tier for the same reason `engine` is — a caller
#: deciding about purity must be able to tell a WMI property from a reflected one.
_WMI_TYPES: dict[str, dict] = {}

for _classes in _WMI['namespaces'].values():
    for _cls, _cls_info in _classes.items():
        _WMI_TYPES.setdefault(_cls, {
            'kind': 'wmi',
            'sealed': False,
            'members': {
                _prop: {'kind': 'property', 'source': 'wmi', 'type': None}
                for _prop in _cls_info['properties']
            },
        })

for _cls in _WMI_TYPES:
    _TYPE_LOOKUP.setdefault(_cls.lower(), []).append(_cls)


def canonical_type(name: str) -> Ps1TypeName | None:
    """
    An alias for `resolve_type`.
    """
    return resolve_type(name)


def required_type_key(name: str) -> Ps1TypeName:
    """
    Resolve a hand-kept table's type spelling to the lowercased canonical .NET `FullName` that table
    keys on, raising when the collected metadata carries no such type. Building a table through this
    at import time is a fail-loud floor: an entry naming a type the current data cannot resolve
    stops the module from loading rather than going silently unmatched. A generic type is named by
    its arity-marked generic definition (the CLR's backtick-arity form), the only spelling
    `resolve_type` resolves without its type arguments.
    """
    resolved = resolve_type(name)
    if resolved is None:
        raise ValueError(
            F'a PowerShell analysis table names {name!r}, which the collected metadata does not '
            F'resolve to a type; the data and the table are out of step.'
        )
    return resolved.generic_definition


def required_type_keys(names: set[str]) -> frozenset[Ps1TypeName]:
    """
    A frozenset of canonical type keys built from readable source spellings through
    `required_type_key`. Spellings that name the same type collapse to one entry, retiring the
    dual-spelling entries (`int` beside `int32`) the allow-lists carried before the data could
    resolve them.
    """
    return frozenset(required_type_key(name) for name in names)


def required_member_keys(
    entries: set[tuple[str, str]],
) -> frozenset[tuple[Ps1TypeName, str]]:
    """
    A frozenset of `(canonical type key, lowercased member)` pairs, the form a member-keyed table
    looks up. Only the type half is resolved through the data and floored by it; the member name is
    matched against a `refinery.lib.scripts.ps1.model.Ps1InvokeMember.member` at its own casing.
    """
    return frozenset(
        (required_type_key(type_name), member.lower())
        for type_name, member in entries
    )


#: Where an array type's members come from. .NET gives every array the surface of `System.Array`
#: rather than one of its own, so `char[]` answers member questions off this and not off `Char`.
_ARRAY_SURFACE = 'System.Array'


def _type_record(key: str) -> dict | None:
    """
    The collected record a canonical definition key names, from either the .NET type capture or the
    WMI class capture. The two are separate captures of the same thing — what members a value of a
    type has — so they are read through one accessor and every query below is written once.
    """
    record = _TYPE_TABLE.get(key)
    if record is None:
        record = _WMI_TYPES.get(key)
    return record


def _member_surface(name: str | Ps1TypeName) -> str | None:
    """
    The key of the collected record whose members a value of this type carries, or `None` when the
    type does not resolve. This is the one place the array rule lives: an array carries the members
    of `System.Array` whatever it is an array *of*, so every member query — the table, the display
    order, one record, a property's type, the static overloads — reaches the same surface through
    here rather than each deciding for itself.

    Sealedness is deliberately not asked here, because it is not a question about the member
    surface: `System.Array` is not sealed, and every array type is.
    """
    resolved = resolve_type(name)
    if resolved is None:
        return None
    if resolved.ranks:
        return _ARRAY_SURFACE
    return resolved.definition


def type_members(name: str | Ps1TypeName) -> dict[str, dict] | None:
    """
    The full member table of a type, keyed by member name, including the fields and Extended Type
    System members the view functions omit. Each value carries at least `kind` and `source`.
    Returns `None` when the type is not collected.
    """
    key = _member_surface(name)
    if key is None:
        return None
    record = _type_record(key)
    return None if record is None else record['members']


def collected_type_names() -> tuple[str, ...]:
    """
    The reflection `FullName` spellings the .NET type capture holds, sorted, and none of the WMI
    class names it does not.
    """
    return tuple(sorted(_TYPE_TABLE))


def member_order(name: str | Ps1TypeName) -> list[str] | None:
    """
    The order `Get-Member` displays a type's members in, as observed on a real instance, or `None`
    when it was not collected for this type. This is the authentic display order, not a synthesis
    from the member table, and is only present for the types the generator has an instance for.
    """
    key = _member_surface(name)
    if key is None:
        return None
    record = _type_record(key)
    return None if record is None else record.get('member_order')


def type_is_sealed(name: str | Ps1TypeName) -> bool:
    """
    Whether the named type is sealed — no subtype of it exists, so a value of the type carries
    exactly the members reflection reports and nothing a subtype could add. `False` when the type
    is not collected or is not sealed, so a caller that needs sealedness to justify a grant fails
    closed on an unknown type rather than assuming it. The flag is read from the collected metadata,
    which is what retires the hand-asserted sealedness the effect layer's pure-read allow-list used
    to rest on.

    An array type is sealed whatever its element type is — .NET derives no type from one — so it is
    answered from the array rather than through `_member_surface`, which would answer it off
    `System.Array` and call it unsealed.
    """
    resolved = resolve_type(name)
    if resolved is None:
        return False
    if resolved.ranks:
        return True
    record = _type_record(resolved.definition)
    return record is not None and bool(record.get('sealed'))


def type_is_value_type(name: str | Ps1TypeName) -> bool:
    """
    Whether the named type is a value type — a struct or an enum, so a value of it is never
    `$null` — or `False` where it is not collected, so a caller that grants on the value it holds
    fails closed. Read from the collected `kind` the way `type_is_sealed` reads `sealed`. An
    array is `False` whatever its element is, and it is answered before the member surface is
    consulted, which would read the element type's record and call the array a struct.
    """
    resolved = resolve_type(name)
    if resolved is None or resolved.ranks:
        return False
    record = _type_record(resolved.definition)
    return record is not None and record.get('kind') in ('struct', 'enum')


#: Read as an exact spelling against the collected interface set rather than through
#: `resolve_type`, because the capture renders `System.Collections.Generic` interfaces in several
#: spellings while it renders this one the same way everywhere.
_ENUMERABLE_INTERFACE = 'System.Collections.IEnumerable'


def is_enumerable(name: str | Ps1TypeName) -> bool | None:
    """
    Whether the pipeline enumerates a value of the type — whether `@($x)` collects one element per
    item the value yields rather than one element holding it — or `None` where the type is not
    collected. `System.String` is the one measured exception: it implements the interface and is
    enumerated by nothing, so it is answered on the measurement rather than the interface set. A
    value type is not exempt by being one: `System.ArraySegment`1` is a struct an `@()` flattens.
    An array is always enumerated, whatever its element is.
    """
    resolved = resolve_type(name)
    if resolved is None:
        return None
    if resolved.ranks:
        return True
    if resolved.definition == 'System.String':
        return False
    record = _type_record(resolved.definition)
    if record is None:
        return None
    return _ENUMERABLE_INTERFACE in (record.get('interfaces') or ())


class MemberLookup(enum.Enum):
    """
    The two non-record outcomes of `member_record`. A member query has three outcomes a purity gate
    must keep apart: the type was never collected, so nothing is known about its members; the type is
    collected but carries no member of that name; or the member is present and its record is returned.
    Collapsing the first two into a single `None` conflates an unknown surface with a known absence,
    which a sound gate must treat oppositely — an unknown surface is unsafe, a known-absent read
    yields `$null`.
    """
    UNCOLLECTED = 'uncollected'
    ABSENT = 'absent'


#: The members PowerShell's object adapter puts on every value, whatever its type. `Get-Member
#: -Force` reports them per instance rather than per type, so the capture — which walks types —
#: cannot hold them.
#:
#: Each is measured on a 5.1 host rather than reasoned about; see `TYPE_TRANSCRIPTS` in
#: `test.lib.scripts.ps1.test_oracle`. `Count` is 1 for a scalar, `PSTypeNames` is the type's own
#: name followed by its bases, and `PSObject` wraps the value.
#:
#: `Length` is deliberately absent even though a scalar answers 1 for it. Every type that carries a
#: real `Length` has it collected — `System.String`, `System.Array`, `System.IO.FileStream` — so the
#: tier would never be reached for one; putting it here would only add a way for the *next* type
#: whose capture is incomplete to have a live getter vouched for. The scalar case is left to the
#: value domain, which knows what a scalar is.
#:
#: `source` is neither `reflection` nor `ets`. Filing these as `ets` would make every read of one
#: impure and delete nothing that is deleted today; filing them as `reflection` would claim the
#: capture saw them. They are their own tier so that a gate can decide about them on purpose.
_ENGINE_MEMBERS: dict[str, dict] = {
    'count': {'kind': 'property', 'source': 'engine', 'type': 'System.Int32'},
    'pstypenames': {'kind': 'property', 'source': 'engine', 'type': 'System.String[]'},
    'psobject': {
        'kind': 'property',
        'source': 'engine',
        'type': 'System.Management.Automation.PSObject',
    },
}


def engine_member(member: str) -> dict | None:
    """
    The record for a member the object adapter adds to every value, or `None` for a name that is not
    one. Callers consult this only where `member_record` answered `MemberLookup.ABSENT`: a collected
    record is what the type really carries and is never overridden by this.
    """
    return _ENGINE_MEMBERS.get(member.lower())


def type_names(name: str | Ps1TypeName) -> list[str] | None:
    """
    The value a type's `PSTypeNames` enumerates: its own reflection `FullName` followed by the
    `FullName` of every type it derives from, ending at `System.Object`. Measured on a 5.1 host; see
    `TYPE_TRANSCRIPTS` in `test.lib.scripts.ps1.test_oracle`.

    Returns `None` when the type does not resolve, is an array — whose chain is `System.Array` and
    not that of its element type — or reaches a base that was not collected, so a caller folds a
    chain that is known whole and never a truncated one.
    """
    resolved = resolve_type(name)
    if resolved is None or resolved.is_array:
        return None
    names: list[str] = []
    current: str | None = resolved.definition
    while current is not None:
        record = _type_record(current)
        if record is None:
            return None
        names.append(current)
        current = record.get('base')
    return names


def _unmodelled_for_type_test(kind: Ps1TypeName) -> bool:
    """
    Whether a type carries a shape the assignability model below does not settle: a generic, a
    pointer or a by-reference type. An array is modelled and is deliberately not one of these.
    """
    return bool(kind.arity or kind.arguments or kind.pointers or kind.byref)


def _array_interfaces() -> frozenset[str]:
    """
    The interfaces `System.Array` is recorded to implement, which every array type implements too.
    Read on demand rather than at import so it does not depend on the type table's load order.
    """
    record = _type_record('System.Array')
    return frozenset(record['interfaces']) if record is not None else frozenset()


def _array_is_assignable_to(target: Ps1TypeName) -> bool | None:
    """
    Whether an array satisfies `-is target`. An array derives only `System.Array` and `System.Object`
    and implements the interfaces `System.Array` carries, so a concrete target that is neither is a
    definite `False`. The two the model does not settle are covariance — a different array type — and
    the generic collection interfaces an array implements beyond `System.Array`'s own; both are
    declined rather than denied so a fold never answers one the way 5.1 would not.
    """
    if target.is_array:
        return None
    if target.definition in ('System.Array', 'System.Object'):
        return True
    record = _type_record(target.definition)
    if record is None:
        return None
    if record.get('kind') == 'interface':
        return True if target.definition in _array_interfaces() else None
    return False


def is_assignable_to(
    value_type: str | Ps1TypeName,
    target_type: str | Ps1TypeName,
) -> bool | None:
    """
    Whether a value whose runtime type is `value_type` satisfies `value_type -is target_type`, the
    test PowerShell's `-is` and `-isnot` operators perform. `True` when the runtime type is the
    target, derives from it, or implements it; `False` when the collected model settles that it is
    none of those; and `None` where the model does not settle it — an unresolved or generic type, an
    array against a different array type, or an array against an interface `System.Array` is not
    recorded to carry. A `None` is a fold declined, never a `False` guessed, so a caller never
    answers a test 5.1 would answer the other way.

    For a non-array value the class relation is read whole: the base chain `type_names` returns and
    the interface set the collected record carries are both what reflection reports for the value's
    own type, so a target that is neither an ancestor class nor a listed interface is a definite
    `False`.
    """
    value = resolve_type(value_type)
    target = resolve_type(target_type)
    if value is None or target is None:
        return None
    if _unmodelled_for_type_test(value) or _unmodelled_for_type_test(target):
        return None
    if value.is_array:
        return True if value == target else _array_is_assignable_to(target)
    if target.is_array:
        return False
    chain = type_names(value)
    if chain is None:
        return None
    if target.definition in chain:
        return True
    record = _type_record(value.definition)
    if record is None:
        return None
    return target.definition in record.get('interfaces', ())


def member_record(name: str | Ps1TypeName, member: str) -> dict | MemberLookup:
    """
    The collected record for a single member of a type, or a `MemberLookup` sentinel explaining why
    there is none. `MemberLookup.UNCOLLECTED` means the type has no member table at all;
    `MemberLookup.ABSENT` means the type is collected and carries no member of that name. The member
    is matched case-insensitively, as PowerShell resolves it, and the first match wins. The record
    carries at least `kind` and `source`, which distinguish a plain reflection property or field from
    a code-running Extended Type System member.

    A member the capture holds wins over `engine_member`, which is why the adapter tier is consulted
    here on the way out rather than by each caller: a caller that asked the tier first would answer
    `Count` off it for `System.Array`, which carries a real one.
    """
    members = type_members(name)
    if members is None:
        return MemberLookup.UNCOLLECTED
    lower = member.lower()
    for stored, record in members.items():
        if stored.lower() == lower:
            return record
    engine = engine_member(member)
    if engine is not None:
        return engine
    return MemberLookup.ABSENT


def view_members(name: str | Ps1TypeName) -> dict[str, dict] | None:
    """
    The members of a type that `Get-Member` reports without `-Force`: the reflected methods and
    properties, and for a WMI class its properties. Fields and Extended Type System members are
    withheld. The type is resolved through `resolve_type`, so an array answers off `System.Array`
    and a spelling that is not already the lowercased `FullName` resolves instead of missing.

    An enum has no members in this sense and its named values stand in for them, which is what the
    view has always done and what a caller listing what may follow a dot needs.
    """
    key = _member_surface(name)
    if key is None:
        return None
    record = _type_record(key)
    if record is None:
        return None
    if record.get('kind') == 'enum':
        return {value: {'kind': 'property', 'source': 'enum'} for value in record['enum_values'] or {}}
    return _view_members(record)


def member_names(name: str | Ps1TypeName) -> list[str] | None:
    """
    The names `view_members` reports, sorted, or `None` when the type does not resolve.
    """
    members = view_members(name)
    return None if members is None else sorted(members)


def _enum_of(name: str | Ps1TypeName) -> _EnumTable | None:
    """
    The `_EnumTable` of a type, or `None` when the type does not resolve or is not an enum.
    """
    key = _member_surface(name)
    return None if key is None else _ENUM_TABLES.get(key)


def is_enum(name: str | Ps1TypeName) -> bool:
    """
    Whether the type resolves and is an enum.
    """
    return _enum_of(name) is not None


def enum_ordinal(name: str | Ps1TypeName, member: str) -> int | None:
    """
    The integer an enum member denotes, matched case-insensitively as 5.1 resolves it, or `None`
    when the type is not an enum or names no such member.
    """
    table = _enum_of(name)
    return None if table is None else table.ordinals.get(member.lower())


def enum_name(name: str | Ps1TypeName, ordinal: int) -> str | None:
    """
    The member an enum ordinal spells, or `None` when the type is not an enum, no member holds that
    ordinal, or more than one does. A value carrying an ordinal no member names has no spelling,
    exactly as 5.1 writes the number itself for it. A Python `bool` is refused rather than read as
    the integer it compares equal to: `True == 1` would spell the member holding 1 for a Boolean
    5.1 does not convert to an enum at all.
    """
    table = _enum_of(name)
    if table is None or isinstance(ordinal, bool):
        return None
    return table.names.get(ordinal)


def enum_storage(name: str | Ps1TypeName) -> str | None:
    """
    The integer type an enum stores its ordinals in, which reflection reports as the type of its
    `value__` field, or `None` when the type is not an enum or its record carries no such field. It
    is the width an integer is truncated to on its way into the enum and read at on its way out.
    """
    table = _enum_of(name)
    return None if table is None else table.storage


def canonical_member(name: str | Ps1TypeName, member: str) -> str | None:
    """
    The casing the metadata records for a member, matched case-insensitively as PowerShell resolves
    it, or `None` when the type or the member does not resolve.
    """
    members = view_members(name)
    if members is None:
        return None
    lower = member.lower()
    for stored in members:
        if stored.lower() == lower:
            return stored
    return None


def resolve_member_type(name: str | Ps1TypeName, member: str) -> Ps1TypeName | None:
    """
    The type a property of a type holds, or `None` when the type does not resolve, carries no such
    member, or the member is not a property. The answer is a canonical `Ps1TypeName`, so a chain of
    reads composes: what `$x.Prop.Length` resolves to is this asked twice.
    """
    record = member_record(name, member)
    if isinstance(record, MemberLookup):
        return None
    if record.get('kind') != 'property':
        return None
    declared = record.get('type')
    if not declared:
        return None
    return resolve_type(declared)


def static_overloads(name: str | Ps1TypeName, member: str) -> list[dict]:
    """
    The static overloads of a method on a type, each a record carrying its `returns` and its
    `parameters`, where every parameter records its `byref`/`out` direction, its `type` and its
    `position`. Returns an empty list when the type is not collected or carries no static method of
    that name. A caller asks this to reason about a `[Type]::Member(...)` call, whose reachable
    surface is the static one.
    """
    return _overloads(name, member, static=True)


def instance_overloads(name: str | Ps1TypeName, member: str) -> list[dict]:
    """
    The overloads of a method that a *value* of the type carries, in the same shape
    `static_overloads` returns. Returns an empty list when the type is not collected or carries no
    instance method of that name, which is what says a call on a value of it cannot be made at all:
    `System.Char` has a `ToUpper`, every overload of it is static, and `([char]65).ToUpper()`
    reports `MethodNotFound` on 5.1 while `[char]::ToUpper('a')` answers.
    """
    return _overloads(name, member, static=False)


def _overloads(name: str | Ps1TypeName, member: str, *, static: bool) -> list[dict]:
    """
    One side of a method's collected surface. The member is matched case-insensitively, as
    PowerShell resolves it, and the first match wins. A non-method member that case-collides with
    the method name is skipped, not taken as the answer, so a real method behind it is still found.
    """
    members = type_members(name)
    if members is None:
        return []
    for stored, record in members.items():
        if stored.lower() != member.lower():
            continue
        if record.get('kind') != 'method':
            continue
        return [
            overload for overload in record.get('overloads') or ()
            if bool(overload.get('static')) is static
        ]
    return []


def _required_reflection_method_keys(
    entries: set[tuple[str, str]],
) -> frozenset[tuple[Ps1TypeName, str]]:
    """
    A frozenset of `(canonical type key, lowercased member)` pairs — the form
    `required_member_keys` builds — floored against the collected metadata: the member must be a
    reflection method of the type the key names. An entry naming anything else is a table
    speaking about a method the data cannot see, which fails the load rather than silently
    granting or denying a fold around it.
    """
    keys = required_member_keys(entries)
    for type_key, member in keys:
        record = member_record(type_key, member)
        if (
            isinstance(record, MemberLookup)
            or record.get('kind') != 'method'
            or record.get('source') != 'reflection'
        ):
            raise ValueError(
                F'a curated method table names {type_key}.{member}, which the collected metadata '
                F'does not carry as a reflection method; the data and the table are out of step.'
            )
    return keys


def _required_non_null_returns(
    entries: set[tuple[str, str]],
) -> dict[tuple[Ps1TypeName, str], Ps1TypeName]:
    """
    The non-null vouch table, floored on top of `_required_reflection_method_keys`: the type
    must be sealed — a subtype could override the member to return `$null` — and the member's
    instance overloads must agree on one return type, which is the return the table records for
    the vouch, so that answering one is a lookup on the table rather than a re-derivation of the
    agreement. An entry that fails a floor fails the load.
    """
    table: dict[tuple[Ps1TypeName, str], Ps1TypeName] = {}
    for type_key, member in _required_reflection_method_keys(entries):
        if not type_is_sealed(type_key):
            raise ValueError(
                F'the non-null return table names {type_key!r}, which the collected metadata does '
                F'not mark sealed; a subtype could override {member} to return $null, so the data '
                F'and the table are out of step.'
            )
        returns = {
            resolve_type(overload['returns'])
            for overload in instance_overloads(type_key, member)
            if overload.get('returns')
        }
        if None in returns or len(returns) != 1:
            raise ValueError(
                F'the non-null return table names {type_key!r}.{member}, whose instance overloads '
                F'do not agree on one return type; the value the vouch answers with would be a '
                F'guess, so the data and the table are out of step.'
            )
        table[(type_key, member)] = next(iter(returns))
    return table


#: The instance methods whose call on a value of the type always returns a non-null value of the
#: one return type its overloads agree on, measured on 5.1 — `StringBuilder.ToString` first: an
#: emptied `StringBuilder` still answers a String. The table records the agreed return beside the
#: key, so a vouch is one lookup. This is what lets an origin judgment follow a member call rather
#: than stopping at a name it cannot type; see
#: `refinery.lib.scripts.ps1.analysis.values.non_null_type`.
NON_NULL_RETURNS: dict[tuple[Ps1TypeName, str], Ps1TypeName] = _required_non_null_returns({
    ('text.stringbuilder', 'tostring'),
})

#: The generic methods on the collected static surface whose signatures are fully concrete, so
#: no spelling-based guard can see their genericity: `Invoke` on the definition throws
#: `InvalidOperationException` where the direct spelling throws a bare `MethodException` —
#: measured on 5.1, over the three `Marshal` methods a live scan of the collected surface
#: found. The ps1 oracle re-runs the scan, so a regeneration that adds one fails the pin. The
#: capture records genericity at the source — `run-pwsh.ps1` writes an
#: `IsGenericMethodDefinition` flag — and when the shipped tables carry it, this table is
#: retired in favour of the guard reading it.
CONCRETE_GENERIC_METHODS: frozenset[tuple[Ps1TypeName, str]] = _required_reflection_method_keys({
    ('runtime.interopservices.marshal', 'destroystructure'),
    ('runtime.interopservices.marshal', 'offsetof'),
    ('runtime.interopservices.marshal', 'sizeof'),
})


_COMMAND_LOOKUP: dict[str, dict] = {
    _name.lower(): _record for _name, _record in _COMMAND_TABLE.items()
}


#: The operator grid's own version, which is what "its own version" below has to mean if it is to
#: mean anything: the two resources change for different reasons and are written by different
#: scripts, so a table added to the grid must not declare five host tables out of date when nothing
#: about them moved. Sharing `SCHEMA_VERSION` made exactly that the price of adding `unary` and
#: `type_tests`.
OPERATOR_SCHEMA_VERSION = 2

#: What the operator and conversion grids were captured from. Its own resource and its own version,
#: because its subject is different from the rest of this module: the five host tables describe what
#: one installation *has*, and this describes what the language *does*, which is fixed for a version
#: of PowerShell. They are regenerated by different scripts and adjudicated separately.
_OPERATORS = _load('pwsh-operators.json.xz')
_operator_schema = _OPERATORS['schema']['version']
if _operator_schema != OPERATOR_SCHEMA_VERSION:
    raise ValueError(
        F'pwsh operator grid schema version {_operator_schema} is not the expected '
        F'{OPERATOR_SCHEMA_VERSION}; the reader and the collected data are out of step.'
    )

#: The two outcomes the capture records that are not a type. A cell that threw for some pair of
#: operands is one the domain must be able to model as throwing, and a cell that yielded `$null` has
#: no type to report at all — `$null.GetType()` throws, so naming one would put a type in the grid
#: that no value has.
_THREW = 'throw'
_WAS_NULL = 'null'


class OperatorOutcome(typing.NamedTuple):
    """
    Everything one grid cell was observed to produce, over several witness values per operand type.

    A cell is deliberately not a type. `(operator, left type, right type)` does not determine one:
    `512MB * 512MB` is a `Double` out of the same Int32-by-Int32 cell that gives an `Int32`
    elsewhere, and `12 + '0xabc'` is `2760` where `16 + 'file'` throws. So `types` is a set, and a
    caller may read a single type out of it only when there is exactly one and neither `may_throw`
    nor `may_be_null` is set. Anything wider is decided by the values, and answering it needs a
    kernel rather than the grid.

    `may_throw` is on its own axis rather than being a member of `types` because throwing is not an
    alternative to having a type: `[int]$x` over a string is *an Int32, or it throws*, which is the
    commonest shape in a byte-decoder loader, and a sum would have to answer that it knows nothing.
    """
    types: frozenset[Ps1TypeName]
    may_throw: bool
    may_be_null: bool

    @property
    def single_type(self) -> Ps1TypeName | None:
        """
        The one type this cell always produces, or `None` when it does not always produce one.
        """
        if self.may_throw or self.may_be_null or len(self.types) != 1:
            return None
        return next(iter(self.types))

    @property
    def always_throws(self) -> bool:
        """
        Whether every witnessed pair in this cell threw, so that no value was observed to come out
        of it at all.

        It names no cause and must not be read as one. Many `True` cells are a *value* reason rather
        than a missing method: `2 / $null` is a divide-by-zero, and division has a perfectly good
        method for an Int32. `Int32 / Boolean` is the control — same operator, same value reason, not
        selected, because `$true` divides fine and leaves `types` non-empty. A caller wanting to know
        *why* asks the host.

        `may_throw` answers a different question, and reading it as this one conflates them: `$true *
        2` throws with nothing witnessed, while `$true / 2` is 0.5 and throws only over a divisor the
        left operand has no part in. The claim is about the *cell*, never one operand; projecting it
        onto a side (`_NO_OPERATOR_METHOD_ON_BOOLEAN`) needs its own operand-wise evidence and is
        sound only because it is used to refuse, where a wrong projection costs a fold rather than
        inventing a value. A cell that produced `$null` did produce something, so `may_be_null`
        excludes it.
        """
        return self.may_throw and not self.may_be_null and not self.types


def _outcome(recorded: list[str] | None) -> OperatorOutcome | None:
    if recorded is None:
        return None
    types = set()
    for entry in recorded:
        if entry in (_THREW, _WAS_NULL):
            continue
        resolved = resolve_type(entry)
        if resolved is None:
            return None
        types.add(resolved)
    return OperatorOutcome(
        types=frozenset(types),
        may_throw=_THREW in recorded,
        may_be_null=_WAS_NULL in recorded,
    )


def operand_witnesses() -> dict[str, tuple[str, ...]]:
    """
    The expressions each grid cell was measured over, keyed by the type they produce. This is the
    capture's *method* rather than its result, and it is published because a cell is a lower bound:
    a caller deciding how far to trust one has to know what was tried, and a caller that recorded
    such a decision has to be able to tell that the ground under it moved.
    """
    return {
        name: tuple(texts) for name, texts in _OPERATORS['witnesses'].items()
    }


def binary_operators() -> frozenset[str]:
    """
    Every operator the binary grid has a table for, lower case as the capture wrote them. Published
    so that a caller quantifying over the measured operators reads the set rather than carrying one
    of its own, which would go stale the next time the capture is widened.

    A test that writes the set out *is* keeping a copy, and does so on purpose: it is the ratchet
    that makes a regeneration fail loudly instead of quietly covering more. This is for the other
    kind of caller, the one that wants to iterate and does not want to be told the answer.
    """
    return frozenset(_OPERATORS['binary'])


def binary_outcome(
    operator: str,
    left: str | Ps1TypeName,
    right: str | Ps1TypeName,
) -> OperatorOutcome | None:
    """
    What `left <operator> right` was observed to produce, or `None` when the grid does not cover the
    operator or either type. An uncovered cell is not an empty one: a caller must read `None` as
    *nothing is known here* and decline, never as *this produces nothing*.
    """
    rows = _OPERATORS['binary'].get(operator.lower())
    if rows is None:
        return None
    row = _axis_position(_operand_axis(), left)
    column = _axis_position(_operand_axis(), right)
    if row is None or column is None:
        return None
    return _outcomes()[rows[row][column]]


def unary_outcome(
    operator: str,
    operand: str | Ps1TypeName,
) -> OperatorOutcome | None:
    """
    What `<operator> operand` was observed to produce, for the operators that take one operand.
    Read the same way as `binary_outcome`.
    """
    row = _OPERATORS['unary'].get(operator.lower())
    if row is None:
        return None
    column = _axis_position(_operand_axis(), operand)
    return None if column is None else _outcomes()[row[column]]


def type_test_outcome(
    operator: str,
    source: str | Ps1TypeName,
    target: str | Ps1TypeName,
) -> OperatorOutcome | None:
    """
    What `source <operator> [target]` was observed to produce, for the operators whose right operand
    is a type rather than a value. Read the same way as `binary_outcome`.
    """
    rows = _OPERATORS['type_tests'].get(operator.lower())
    if rows is None:
        return None
    row = _axis_position(_operand_axis(), source)
    column = _axis_position(_target_axis(), target)
    if row is None or column is None:
        return None
    return _outcomes()[rows[row][column]]


def conversion_outcome(
    target: str | Ps1TypeName,
    source: str | Ps1TypeName,
) -> OperatorOutcome | None:
    """
    What casting a value of `source` to `target` was observed to produce, or `None` when the grid
    does not cover the cast. Read the same way as `binary_outcome`.
    """
    key = _grid_key(target)
    row = None if key is None else _conversions().get(key)
    if row is None:
        return None
    column = _axis_position(_operand_axis(), source)
    return None if column is None else _outcomes()[row[column]]


@functools.cache
def _outcomes() -> tuple[OperatorOutcome | None, ...]:
    """
    Every distinct outcome the capture recorded, in the order the cells index them by.

    A cell is a position in this table rather than a list of names, because the grids hold nine
    thousand cells between them and seventy-two answers. Reading it that way also means the type
    names are resolved seventy-two times when the module loads instead of once per lookup.
    """
    return tuple(_outcome(recorded) for recorded in _OPERATORS['outcomes'])


@functools.cache
def _operand_axis() -> dict[str, int]:
    """
    Where each operand type sits along the axis the cells are indexed by, keyed the way everything
    else here is keyed. The order is written into the capture rather than assumed from any other
    part of it, so that reading a cell never depends on two lists having stayed in step.
    """
    return _axis_index(_OPERATORS['types'], 'operand')


@functools.cache
def _target_axis() -> dict[str, int]:
    """
    Where each cast target sits along the axis the type-operator cells are indexed by.

    The capture writes this axis as the accelerator a cast is *written* with — `int`, `long`,
    `byte[]` — and the operand axis as the type a value *reported*. Those are two spellings of one
    thing, and a caller naming a type would otherwise have to know which axis it was about to index.
    """
    return _axis_index(_OPERATORS['targets'], 'cast target')


@functools.cache
def _conversions() -> dict[str, list[int]]:
    """
    The conversion grid keyed by the target a caller names rather than the accelerator the capture
    wrote, for the reason `_target_axis` re-keys the same spellings.
    """
    keyed = {}
    for target, row in _OPERATORS['conversions'].items():
        key = _grid_key(target)
        if key is None:
            raise ValueError(F'the conversion grid names a target that is not a type: {target}')
        keyed[key] = row
    return keyed


def _axis_position(axis: dict[str, int], name: str | Ps1TypeName) -> int | None:
    """
    Where a type sits along an axis, or `None` when the name resolves to no type at all or the axis
    has no place for it. Both are the same answer to a caller: the grid does not cover this.
    """
    key = _grid_key(name)
    return None if key is None else axis.get(key)


def _axis_index(names: list[str], what: str) -> dict[str, int]:
    """
    An axis as the position of each type along it. A spelling that does not resolve is an error
    rather than a missing entry: it would silently make every cell indexed through it unknown.
    """
    index = {}
    for position, name in enumerate(names):
        key = _grid_key(name)
        if key is None:
            raise ValueError(F'the {what} axis names something that is not a type: {name}')
        index[key] = position
    return index


def _grid_key(name: str | Ps1TypeName) -> str | None:
    """
    The spelling the grid is keyed by, which is a rendered canonical name rather than a definition:
    the grid has a row for `System.Object[]` and one for `System.Object`, and they are two types.
    """
    resolved = resolve_type(name)
    return None if resolved is None else str(resolved)


def command(name: str) -> dict | None:
    """
    The collected record for a command, or `None` when the name is not a known cmdlet or function.
    The record carries the command kind, its module, declared output types with an
    `output_type_declared` flag, and the full parameter table including the common parameters.
    Command names are matched case-insensitively, as PowerShell resolves them.
    """
    return _COMMAND_LOOKUP.get(name.lower())


def command_output_types(name: str) -> frozenset[str] | None:
    """
    The declared output types of a command, lowercased, or `None` when the command declares none. A
    set is returned only when the command carries an `[OutputType]` attribute — the
    `output_type_declared` flag — because an `output_types` list without it records what was observed,
    not what the author promised, and an empty one means the declaration was never made rather than
    that the command emits nothing. An unknown command is `None` for the same reason. Names are
    matched case-insensitively.
    """
    record = _COMMAND_LOOKUP.get(name.lower())
    if record is None or not record.get('output_type_declared'):
        return None
    return frozenset(_type.lower() for _type in record['output_types'])
