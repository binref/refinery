"""
Inno Setup constants as Setup expands them: how the end of a constant is found and its parameters
are split, which names each version of Setup knows, and how each kind of constant is expanded. The
values come from a `ConstantHost`, which stands for the machine and the Setup that run the script.
"""
from __future__ import annotations

import re

from typing import Any, Callable, Generator, Mapping, NamedTuple, Protocol

from refinery.lib.inno.emulation import InternalError
from refinery.lib.inno.release import SetupRelease

_HEX_DIGITS = frozenset('0123456789abcdefABCDEF')

_Version = tuple[int, ...]

CodeRunner = Callable[[str, str], Generator[Any, Any, str]]
"""
Runs the function of the script with the given name and argument for a code constant and returns
its text; the run of the script that asks for an expansion gives it.
"""


class _Name(NamedTuple):
    since: _Version = (0,)
    until: _Version | None = None


_NAMES: dict[str, _Name] = {
    'app'               : _Name(),
    'cmd'               : _Name(),
    'commonappdata'     : _Name(),
    'commoncf'          : _Name(since=(6, 0, 0)),
    'commoncf32'        : _Name(since=(6, 0, 0)),
    'commoncf64'        : _Name(since=(6, 0, 0)),
    'commondesktop'     : _Name(),
    'commondocs'        : _Name(),
    'commonfavorites'   : _Name(),
    'commonfonts'       : _Name(since=(6, 1, 0)),
    'commonpf'          : _Name(since=(6, 0, 0)),
    'commonpf32'        : _Name(since=(6, 0, 0)),
    'commonpf64'        : _Name(since=(6, 0, 0)),
    'commonprograms'    : _Name(),
    'commonstartmenu'   : _Name(),
    'commonstartup'     : _Name(),
    'commontemplates'   : _Name(),
    'computername'      : _Name(),
    'dao'               : _Name(),
    'dotnet11'          : _Name(),
    'dotnet20'          : _Name(),
    'dotnet2032'        : _Name(),
    'dotnet2064'        : _Name(),
    'dotnet40'          : _Name(),
    'dotnet4032'        : _Name(),
    'dotnet4064'        : _Name(),
    'group'             : _Name(),
    'groupname'         : _Name(),
    'hwnd'              : _Name(until=(6, 4, 0)),
    'language'          : _Name(),
    'localappdata'      : _Name(),
    'log'               : _Name(),
    'sd'                : _Name(),
    'src'               : _Name(),
    'srcexe'            : _Name(),
    'sys'               : _Name(),
    'sysnative'         : _Name(since=(6, 0, 2)),
    'sysuserinfoname'   : _Name(),
    'sysuserinfoorg'    : _Name(),
    'syswow64'          : _Name(),
    'tmp'               : _Name(),
    'uninstallexe'      : _Name(),
    'userappdata'       : _Name(),
    'usercf'            : _Name(since=(5, 5, 2)),
    'userdesktop'       : _Name(),
    'userdocs'          : _Name(),
    'userfavorites'     : _Name(),
    'userfonts'         : _Name(since=(6, 1, 0)),
    'userinfoname'      : _Name(),
    'userinfoorg'       : _Name(),
    'userinfoserial'    : _Name(),
    'username'          : _Name(),
    'userpf'            : _Name(since=(5, 5, 2)),
    'userprograms'      : _Name(),
    'usersavedgames'    : _Name(since=(6, 0, 4)),
    'usersendto'        : _Name(since=(5, 6, 1)),
    'userstartmenu'     : _Name(),
    'userstartup'       : _Name(),
    'usertemplates'     : _Name(),
    'win'               : _Name(),
    'wizardhwnd'        : _Name(),
}
"""
The names of the constants without parameters that Setup knows, with the first version that knows
each one and the first that no longer does. Versions before 5.4.3 are taken to know the names of
5.4.3.
"""


class _OldName(NamedTuple):
    name: str
    renamed: _Version
    until: _Version | None = None


_OLD_NAMES: dict[str, _OldName] = {
    'cf'     : _OldName('commoncf', renamed=(6, 0, 0)),
    'cf32'   : _OldName('commoncf32', renamed=(6, 0, 0)),
    'cf64'   : _OldName('commoncf64', renamed=(6, 0, 0)),
    'fonts'  : _OldName('commonfonts', renamed=(6, 1, 0)),
    'pf'     : _OldName('commonpf', renamed=(6, 0, 0)),
    'pf32'   : _OldName('commonpf32', renamed=(6, 0, 0)),
    'pf64'   : _OldName('commonpf64', renamed=(6, 0, 0)),
    'sendto' : _OldName('usersendto', renamed=(6, 0, 0), until=(5, 6, 1)),
}
"""
Names that older versions of Setup knew as their own and that newer versions read as another name.
Before Setup renamed it, each old name is a constant of its own with the value of the new name;
`sendto` is not known from 5.6.1 until Setup renamed it in 6.0.0.
"""

_AUTO_SINCE: _Version = (6, 0, 0)


class ConstantError(InternalError):
    """
    The internal error that Setup raises for a constant that it cannot expand.
    """


class ConstantHost(Protocol):
    """
    The machine and the Setup that a constant is expanded for. A method raises `ConstantError` for
    a value that Setup cannot give on this machine, and any other exception for a value that the
    host does not know.
    """
    release: SetupRelease
    """
    The release of Setup.
    """
    admin: bool
    """
    Whether Setup installs for all users, which decides what the `auto` constants stand for.
    """
    win64: bool
    """
    Whether the machine runs a 64-bit Windows.
    """

    def constant(self, name: str, original: str) -> str:
        """
        The value of a constant without parameters, given by the name that Setup reads it as and
        by the name that the script wrote.
        """
        ...

    def environment(self, name: str, has_default: bool) -> str:
        """
        The value of an environment variable, empty when it is not set. Setup uses the default of
        the constant when the value is empty; `has_default` tells whether the constant has one.
        """
        ...

    def registry(self, root: str, view: int | None, key: str) -> bool:
        """
        Whether the registry key opens; `view` is 32 or 64 for a forced registry view.
        """
        ...

    def registry_value(self, root: str, view: int | None, key: str, value: str, default: str) -> str:
        """
        The text of a value in a registry key that opens, or the default when it has none.
        """
        ...

    def ini_value(self, file: str, section: str, key: str, default: str) -> str:
        """
        The value of a key in an INI file, or the default.
        """
        ...

    def parameter(self, name: str, default: str) -> str:
        """
        The value of a command line parameter `/NAME=value`, or the default.
        """
        ...

    def custom_message(self, name: str) -> str | None:
        """
        The custom message of the active language with the given name, `None` when the setup has
        no such message.
        """
        ...

    def format_message(self, message: str, arguments: list[str]) -> str:
        """
        Puts the arguments into a message as Setup's `FmtMessage` does.
        """
        ...

    def drive(self, path: str) -> str:
        """
        The drive or network share at the start of a path.
        """
        ...


def _read_as(constant: str, host: ConstantHost) -> str:
    """
    The name that Setup reads the given constant as: since Setup renamed an old name, it reads
    it as the new name, and since 6.0.0 it reads `auto` as `common` when it installs for all users
    and as `user` otherwise.
    """
    release = host.release
    if (old := _OLD_NAMES.get(constant)) is not None and release.since(old.renamed):
        return old.name
    if constant.startswith('auto') and release.since(_AUTO_SINCE):
        constant = constant.replace('auto', 'common' if host.admin else 'user')
        if constant in ('userpf32', 'userpf64', 'usercf32', 'usercf64'):
            constant = constant[:-2]
    return constant


def _value_name(name: str, release: SetupRelease) -> str | None:
    """
    The name whose value a constant has when Setup knows it as a constant without parameters, or
    `None`. An old name that Setup has not renamed yet has the value of its new name.
    """
    if (entry := _NAMES.get(name)) is not None:
        if release.since(entry.since) and (entry.until is None or not release.since(entry.until)):
            return name
        return None
    if (old := _OLD_NAMES.get(name)) is not None and not release.since(old.renamed):
        if old.until is None or not release.since(old.until):
            return old.name
    return None


def skip_past_constant(string: str, start: int) -> int | None:
    """
    The index after the constant whose opening brace is at the given index, or `None` when the
    constant is not closed. Two opening braces are one escaped brace. Inside a constant, braces
    nest, and two opening braces in a row count as text.
    """
    end = len(string)
    cursor = start + 1
    if cursor >= end:
        return None
    if string[cursor] == '{':
        return cursor + 1
    level = 1
    last_open = -1
    while cursor < end:
        character = string[cursor]
        if character == '{':
            if last_open != cursor - 1:
                level += 1
                last_open = cursor
            else:
                level -= 1
        elif character == '}':
            level -= 1
            if level == 0:
                return cursor + 1
        cursor += 1
    return None


def constant_position(character: str, string: str) -> int:
    """
    The index of the first occurrence of the character in the string outside of any constant, or
    -1 when there is none.
    """
    cursor = 0
    while cursor < len(string):
        if string[cursor] == character:
            return cursor
        if string[cursor] != '{':
            cursor += 1
        elif (cursor := skip_past_constant(string, cursor)) is None:
            break
    return -1


def split_constant_parameter(string: str, character: str) -> tuple[str, str | None]:
    """
    Splits the string at the first occurrence of the character outside of any constant. The second
    part is `None` when the character does not occur.
    """
    if (index := constant_position(character, string)) < 0:
        return string, None
    return string[:index], string[index + 1:]


def decode_percent_escapes(string: str) -> str | None:
    """
    Decodes each percent sign followed by two hex digits into the character with that code, except
    inside constants. The result is `None` when a percent sign is not followed by two hex digits or
    a constant is not closed.
    """
    output: list[str] = []
    cursor = 0
    while cursor < len(string):
        character = string[cursor]
        if character == '{':
            if (end := skip_past_constant(string, cursor)) is None:
                return None
            output.append(string[cursor:end])
            cursor = end
        elif character == '%':
            digits = string[cursor + 1:cursor + 3]
            if len(digits) != 2 or not _HEX_DIGITS.issuperset(digits):
                return None
            output.append(chr(int(digits, 16)))
            cursor += 3
        else:
            output.append(character)
            cursor += 1
    return ''.join(output)


def _decoded(kind: str, *parameters: str) -> list[str]:
    decoded = []
    for parameter in parameters:
        if (value := decode_percent_escapes(parameter)) is None:
            raise ConstantError(F'Failed to parse "{kind}" constant')
        decoded.append(value)
    return decoded


def fmt_message(message: str, arguments: list[str]) -> str:
    """
    Setup's `FmtMessage`: `%1` to `%9` stand for the arguments and `%%` for a percent sign; a
    placeholder without its argument stays.
    """
    def substitute(match: re.Match[str]):
        if (spec := match[1]) == '%':
            return '%'
        if (k := int(spec) - 1) < len(arguments):
            return arguments[k]
        return match[0]
    return re.sub('%([1-9%])', substitute, message)


def expand_constants(
    string: str,
    host: ConstantHost,
    custom: Mapping[str, str] | None = None,
    run_code: CodeRunner | None = None,
) -> Generator[Any, Any, str]:
    """
    Expands the constants in the given string as Setup's `ExpandConstEx2` does, with the custom
    constants that Setup passes for the text, by their names, and the runner of code constants
    of the script that asks for the expansion. The value of a constant is not scanned again, and a
    backslash right after a value that ends in one is dropped. Without a runner, a code constant
    fails as a value that the emulator does not have.
    """
    output: list[str] = []
    cursor = 0
    end = len(string)
    while cursor < end:
        if (brace := string.find('{', cursor)) < 0:
            output.append(string[cursor:])
            break
        output.append(string[cursor:brace])
        if string.startswith('{', brace + 1):
            output.append('{')
            cursor = brace + 2
            continue
        if (after := skip_past_constant(string, brace)) is None:
            raise ConstantError('Unclosed constant')
        value = yield from _expand_constant(string[brace + 1:after - 1], host, custom, run_code)
        output.append(value)
        cursor = after
        if value.endswith('\\') and string.startswith('\\', cursor):
            cursor += 1
    return ''.join(output)


def _expand_constant(
    constant: str,
    host: ConstantHost,
    custom: Mapping[str, str] | None,
    run_code: CodeRunner | None,
) -> Generator[Any, Any, str]:
    """
    The value of one constant, given without its braces, as Setup's `ExpandIndividualConst`
    computes it: each part of a parameter is expanded only when Setup needs it.
    """
    original = constant
    if (constant := _read_as(constant, host)) == '\\':
        return '\\'
    if (name := _value_name(constant, host.release)) is not None:
        return host.constant(name, original)
    if constant.startswith('%'):
        variable, default = split_constant_parameter(constant[1:], '|')
        has_default = default is not None
        variable = decode_percent_escapes(variable)
        default = decode_percent_escapes(default or '')
        if variable is None or default is None:
            return ''
        value = host.environment((yield from expand_constants(variable, host, custom, run_code)), has_default)
        if not value:
            value = yield from expand_constants(default, host, custom, run_code)
        return value
    if constant.startswith('reg:'):
        return (yield from _expand_registry_constant(constant[4:], host, custom, run_code))
    if constant.startswith('ini:'):
        return (yield from _expand_ini_constant(constant[4:], host, custom, run_code))
    if constant.startswith('param:'):
        name, default = split_constant_parameter(constant[6:], '|')
        name, default = _decoded('param', name, default or '')
        name = yield from expand_constants(name, host, custom, run_code)
        default = yield from expand_constants(default, host, custom, run_code)
        return host.parameter(name, default)
    if constant.startswith('code:'):
        function, default = split_constant_parameter(constant[5:], '|')
        function, default = _decoded('code', function, default or '')
        default = yield from expand_constants(default, host, custom, run_code)
        if run_code is None:
            raise NotImplementedError(F'The emulator cannot run the function {function} of a code constant without the script.')
        return (yield from run_code(function, default))
    if constant.startswith('drive:'):
        path, = _decoded('drive', constant[6:])
        return host.drive((yield from expand_constants(path, host, custom, run_code)))
    if constant.startswith('cm:'):
        return (yield from _expand_message_constant(constant[3:], host, custom, run_code))
    if custom is not None and constant and (value := custom.get(constant)) is not None:
        return value
    raise ConstantError(F'Unknown constant "{original}"')


def _expand_registry_constant(
    parameter: str,
    host: ConstantHost,
    custom: Mapping[str, str] | None,
    run_code: CodeRunner | None,
) -> Generator[Any, Any, str]:
    """
    Expands `reg:HKxx\\Key,Value|Default`. The root may end in 32 or 64 for a registry view.
    Setup expands the default first, then the key, and the value name only when the key opens.
    """
    root, rest = split_constant_parameter(parameter, '\\')
    if rest is None or not root:
        raise ConstantError('Failed to parse "reg" constant')
    view = None
    if root.endswith('32'):
        root, view = root[:-2], 32
    elif root.endswith('64'):
        if not host.win64:
            raise ConstantError('Cannot access a 64-bit key in a "reg" constant on this version of Windows')
        root, view = root[:-2], 64
    if (root := root.upper()) not in ('HKA', 'HKCR', 'HKCU', 'HKLM', 'HKU', 'HKCC'):
        raise ConstantError('Failed to parse "reg" constant')
    rest, default = split_constant_parameter(rest, '|')
    key, value = split_constant_parameter(rest, ',')
    if value is None:
        raise ConstantError('Failed to parse "reg" constant')
    key, value, default = _decoded('reg', key, value, default or '')
    default = yield from expand_constants(default, host, custom, run_code)
    key = yield from expand_constants(key, host, custom, run_code)
    if not host.registry(root, view, key):
        return default
    value = yield from expand_constants(value, host, custom, run_code)
    return host.registry_value(root, view, key, value, default)


def _expand_ini_constant(
    parameter: str,
    host: ConstantHost,
    custom: Mapping[str, str] | None,
    run_code: CodeRunner | None,
) -> Generator[Any, Any, str]:
    """
    Expands `ini:File,Section,Key|Default`; Setup expands all four parts in this order.
    """
    file, rest = split_constant_parameter(parameter, ',')
    if rest is None or not file:
        raise ConstantError('Failed to parse "ini" constant')
    rest, default = split_constant_parameter(rest, '|')
    section, key = split_constant_parameter(rest, ',')
    if key is None:
        raise ConstantError('Failed to parse "ini" constant')
    parts = []
    for part in _decoded('ini', file, section, key, default or ''):
        parts.append((yield from expand_constants(part, host, custom, run_code)))
    file, section, key, default = parts
    return host.ini_value(file, section, key, default)


def _expand_message_constant(
    parameter: str,
    host: ConstantHost,
    custom: Mapping[str, str] | None,
    run_code: CodeRunner | None,
) -> Generator[Any, Any, str]:
    """
    Expands `cm:Name,Argument,...`: the name is taken as written, each of up to nine arguments is
    decoded and expanded, and the message of the active language receives them.
    """
    name, rest = split_constant_parameter(parameter, ',')
    arguments: list[str] = []
    while rest is not None and len(arguments) < 9:
        argument, rest = split_constant_parameter(rest, ',')
        argument, = _decoded('cm', argument)
        arguments.append((yield from expand_constants(argument, host, custom, run_code)))
    if (message := host.custom_message(name)) is None:
        raise ConstantError(F'Unknown custom message name "{name}" in "cm" constant')
    return host.format_message(message, arguments)
