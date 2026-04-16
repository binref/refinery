from __future__ import annotations

import dataclasses
import io
import struct

from typing import Callable

from refinery.lib.nsis.archive import (
    OP_PARAMETER_COUNT,
    NSArchive,
    NSHeader,
    NSHeaderFlags,
    NSMethod,
    NSScriptExtendedInstruction,
    NSScriptFlags,
    NSScriptInstruction,
    NSSection,
    NSSectionFlags,
    NSType,
    Op,
)

PAGE_LICENSE = 0
PAGE_SELCOM = 1
PAGE_DIR = 2
PAGE_INSTFILES = 3
PAGE_UNINST = 4
PAGE_COMPLETED = 5
PAGE_CUSTOM = 6

PAGE_TYPES = (
    'license',
    'components',
    'directory',
    'instfiles',
    'uninstConfirm',
    'COMPLETED',
    'custom',
)

PAGE_SIZE = 64

PF_CANCEL_ENABLE = 4
PF_LICENSE_FORCE_SELECTION = 32
PF_LICENSE_NO_FORCE_SELECTION = 64
PF_PAGE_EX = 512
PF_DIR_NO_BTN_DISABLE = 1024

IDD_LICENSE_FSRB = 108
IDD_LICENSE_FSCB = 109

DEL_DIR = 1
DEL_RECURSE = 2
DEL_REBOOT = 4

ON_FUNCS = (
    'Init',
    'InstSuccess',
    'InstFailed',
    'UserAbort',
    'GUIInit',
    'GUIEnd',
    'MouseOverSection',
    'VerifyInstDir',
    'SelChange',
    'RebootFailed',
)

CMD_REF_Goto = 1 << 0
CMD_REF_Call = 1 << 1
CMD_REF_Pre = 1 << 2
CMD_REF_Show = 1 << 3
CMD_REF_Leave = 1 << 4
CMD_REF_OnFunc = 1 << 5
CMD_REF_Section = 1 << 6
CMD_REF_InitPluginDir = 1 << 7
CMD_REF_OnFunc_NumShifts = 28
CMD_REF_OnFunc_Mask = 0xF0000000
CMD_REF_Page_NumShifts = 16
CMD_REF_Page_Mask = 0x0FFF0000

INITPLUGINDIR_OPCODES = (13, 26, 31, 13, 19, 21, 11, 14, 25, 31, 1, 22, 4, 1)

_MB_BUTTONS = (
    'OK',
    'OKCANCEL',
    'ABORTRETRYIGNORE',
    'YESNOCANCEL',
    'YESNO',
    'RETRYCANCEL',
    'CANCELTRYCONTINUE',
)

_MB_ICONS = (
    None,
    'ICONSTOP',
    'ICONQUESTION',
    'ICONEXCLAMATION',
    'ICONINFORMATION',
)

_MB_FLAGS = (
    'HELP',
    'NOFOCUS',
    'SETFOREGROUND',
    'DEFAULT_DESKTOP_ONLY',
    'TOPMOST',
    'RIGHT',
    'RTLREADING',
)

_BUTTON_IDS = (
    '0',
    'IDOK',
    'IDCANCEL',
    'IDABORT',
    'IDRETRY',
    'IDIGNORE',
    'IDYES',
    'IDNO',
    'IDCLOSE',
    'IDHELP',
    'IDTRYAGAIN',
    'IDCONTINUE',
)

_SHOWWINDOW_COMMANDS = (
    'HIDE',
    'SHOWNORMAL',
    'SHOWMINIMIZED',
    'SHOWMAXIMIZED',
    'SHOWNOACTIVATE',
    'SHOW',
    'MINIMIZE',
    'SHOWMINNOACTIVE',
    'SHOWNA',
    'RESTORE',
    'SHOWDEFAULT',
    'FORCEMINIMIZE',
)

_REG_ROOTS = {
    0x00000000: 'SHCTX',
    0x80000000: 'HKCR',
    0x80000001: 'HKCU',
    0x80000002: 'HKLM',
    0x80000003: 'HKU',
    0x80000004: 'HKPD',
    0x80000005: 'HKCC',
    0x80000006: 'HKDD',
    0x80000050: 'HKPT',
    0x80000060: 'HKPN',
}

_EXEC_FLAGS = (
    'AutoClose',
    'ShellVarContext',
    'Errors',
    'Abort',
    'RebootFlag',
    'reboot_called',
    'cur_insttype',
    'plugin_api_version',
    'Silent',
    'InstDirError',
    'rtl',
    'ErrorLevel',
    'RegView',
    'DetailsPrint',
)

_FLAG_VALUE_NAMES: dict[int, dict[int, str]] = {
    0 : {0: 'false', 1: 'true'},                              # AutoClose
    1 : {0: 'current', 1: 'all'},                             # ShellVarContext
    4 : {0: 'false', 1: 'true'},                              # RebootFlag
    8 : {0: 'normal', 1: 'silent'},                           # Silent
    12: {0: '32', 256: '64'},                                 # RegView
    13: {0: 'both', 2: 'textonly', 4: 'listonly', 6: 'none'}, # DetailsPrint
}

_SECTION_VARS = (
    'Text',
    'InstTypes',
    'Flags',
    'Code',
    'CodeSize',
    'Size',
)

_WIN_ATTRIBS = (
    'READONLY',
    'HIDDEN',
    'SYSTEM',
    None,
    'DIRECTORY',
    'ARCHIVE',
    'DEVICE',
    'NORMAL',
    'TEMPORARY',
    'SPARSE_FILE',
    'REPARSE_POINT',
    'COMPRESSED',
    'OFFLINE',
    'NOT_CONTENT_INDEXED',
    'ENCRYPTED',
    None,
    'VIRTUAL',
)

_OVERWRITE_MODES = (
    'on',
    'off',
    'try',
    'ifnewer',
    'ifdiff',
)

VK_F1 = 0x70

NSIS_MAX_INST_TYPES = 32

_POST_STRINGS = (
    'install_directory_auto_append',
    'uninstchild',
    'uninstcmd',
    'wininit',
)


def _decode_flag_value(flag_id: int, s: str) -> str | None:
    table = _FLAG_VALUE_NAMES.get(flag_id)
    if table is None:
        return None
    try:
        v = int(s, 0)
    except (ValueError, TypeError):
        return None
    return table.get(v)


def decode_messagebox(param: int) -> str:
    """
    Decode MB_* flags from a single uint32 into a pipe-delimited string.
    """
    parts: list[str] = []
    v = param & 0xF
    if v < len(_MB_BUTTONS):
        parts.append(F'MB_{_MB_BUTTONS[v]}')
    else:
        parts.append(F'MB_Buttons_{v}')
    icon = (param >> 4) & 0x7
    if icon != 0:
        if icon < len(_MB_ICONS) and _MB_ICONS[icon] is not None:
            parts.append(F'MB_{_MB_ICONS[icon]}')
        else:
            parts.append(F'MB_Icon_{icon}')
    if param & 0x80:
        parts.append('MB_USERICON')
    def_button = (param >> 8) & 0xF
    if def_button != 0:
        parts.append(F'MB_DEFBUTTON{def_button + 1}')
    modal = (param >> 12) & 0x3
    if modal == 1:
        parts.append('MB_SYSTEMMODAL')
    elif modal == 2:
        parts.append('MB_TASKMODAL')
    elif modal == 3:
        parts.append('0x3000')
    flags = param >> 14
    for i, name in enumerate(_MB_FLAGS):
        if flags & (1 << i):
            parts.append(F'MB_{name}')
    return '|'.join(parts)


def decode_button_id(button_id: int) -> str:
    """
    Map a button ID integer to its name (IDOK, IDCANCEL, ...).
    """
    if button_id < len(_BUTTON_IDS):
        return _BUTTON_IDS[button_id]
    return F'Button_{button_id}'


def decode_showwindow(cmd: int) -> str:
    """
    Map a SW_* command index to its name.
    """
    if cmd < len(_SHOWWINDOW_COMMANDS):
        return F'SW_{_SHOWWINDOW_COMMANDS[cmd]}'
    return str(cmd)


def decode_reg_root(val: int) -> str:
    """
    Map a registry root value to its name.
    """
    name = _REG_ROOTS.get(val)
    if name is not None:
        return name
    return F'0x{val:08X}'


def decode_exec_flags(flags_type: int) -> str:
    """
    Map an exec flag type index to its name.
    """
    if flags_type < len(_EXEC_FLAGS):
        return _EXEC_FLAGS[flags_type]
    return F'_{flags_type}'


def decode_sect_op(op_type: int) -> str:
    """
    Map a section operation type index to its name.
    """
    if op_type < len(_SECTION_VARS):
        return _SECTION_VARS[op_type]
    return F'_{op_type}'


def decode_file_attributes(flags: int) -> str:
    """
    Decode a file attribute bitmask into a pipe-delimited string.
    """
    parts: list[str] = []
    remaining = flags
    for i, name in enumerate(_WIN_ATTRIBS):
        bit = 1 << i
        if remaining & bit:
            if name is not None:
                parts.append(name)
                remaining &= ~bit
    if remaining:
        parts.append(F'0x{remaining:X}')
    return '|'.join(parts)


def decode_setoverwrite(mode: int) -> str:
    """
    Map an overwrite mode index to its name.
    """
    if mode < len(_OVERWRITE_MODES):
        return _OVERWRITE_MODES[mode]
    return str(mode)


def decode_shortcut_hotkey(spec: int) -> str:
    """
    Decode a CreateShortcut hotkey spec into a human-readable string. The high byte contains
    modifier flags, the next byte is the virtual key.
    """
    mod_key = (spec >> 24) & 0xFF
    key = (spec >> 16) & 0xFF
    if mod_key == 0 and key == 0:
        return ''
    parts: list[str] = []
    if mod_key & 1:
        parts.append('SHIFT')
    if mod_key & 2:
        parts.append('CONTROL')
    if mod_key & 4:
        parts.append('ALT')
    if mod_key & 8:
        parts.append('EXT')
    if VK_F1 <= key <= VK_F1 + 23:
        parts.append(F'F{key - VK_F1 + 1}')
    elif (0x41 <= key <= 0x5A) or (0x30 <= key <= 0x39):
        parts.append(chr(key))
    else:
        parts.append(F'Char_{key}')
    return '|'.join(parts)


class NSScriptWriter:
    """
    Thin wrapper around an output buffer providing NSIS script formatting helpers.
    """

    def __init__(self):
        self._buf = io.StringIO()
        self._indent = 0
        self._block_comment = False
        self._line_start = True

    def _emit_line_prefix(self):
        if self._line_start and self._block_comment:
            self._buf.write('; ')
        self._line_start = False

    def indent(self):
        self._indent += 1

    def dedent(self):
        if self._indent > 0:
            self._indent -= 1

    def write(self, s: str):
        self._emit_line_prefix()
        self._buf.write(s)

    def newline(self):
        self._buf.write('\n')
        self._line_start = True

    def space(self):
        self._buf.write(' ')

    def tab(self, commented: bool = False):
        self._emit_line_prefix()
        if commented and not self._block_comment:
            self._buf.write('    ; ')
        else:
            self._buf.write('  ' + '  ' * self._indent)

    def big_space_comment(self):
        self._buf.write('    ; ')

    def small_space_comment(self):
        self._buf.write(' ; ')

    def comment(self, s: str):
        self._emit_line_prefix()
        self._buf.write(F'; {s}')

    def separator(self):
        self.newline()
        self.comment(F'{"":-<72}')
        self.newline()

    def comment_open(self):
        self._block_comment = True
        self._line_start = True

    def comment_close(self):
        self._block_comment = False

    def add_uint(self, v: int):
        self._buf.write(str(v))

    def add_hex(self, v: int):
        self._buf.write(F'0x{v:08X}')

    def add_color(self, v: int):
        v = ((v & 0xFF) << 16) | (v & 0xFF00) | ((v >> 16) & 0xFF)
        self._buf.write(F'0x{v:06X}')

    def add_quoted(self, s: str):
        self._emit_line_prefix()
        if _is_bare_identifier(s) or _is_numeric(s):
            self._buf.write(s)
        else:
            self._buf.write(F'"{s}"')

    def space_quoted(self, s: str):
        self.space()
        self.add_quoted(s)

    def add_string_lf(self, s: str):
        self._emit_line_prefix()
        self._buf.write(s)
        self.newline()

    def tab_string(self, s: str):
        self.tab()
        self._buf.write(s)

    def add_quotes(self):
        self._buf.write('""')

    def getvalue(self) -> str:
        return self._buf.getvalue()


def nsis_escape(s: str) -> str:
    """
    Apply NSIS escape sequences to a string for decompiler output.
    """
    out: list[str] = []
    for c in s:
        if c == '\t':
            out.append('$\\t')
        elif c == '\n':
            out.append('$\\n')
        elif c == '\r':
            out.append('$\\r')
        elif c == '"':
            out.append('$\\"')
        else:
            out.append(c)
    return ''.join(out)


def _is_bare_identifier(s: str) -> bool:
    if len(s) < 2 or s[0] != '$':
        return False
    return all(c.isascii() and (c.isalnum() or c == '_') for c in s[1:])


def _is_numeric(s: str) -> bool:
    if not s:
        return False
    t = s
    if t[0] in '+-':
        t = t[1:]
    if not t:
        return False
    if t.startswith('0x') or t.startswith('0X'):
        t = t[2:]
        return len(t) > 0 and all(c in '0123456789abcdefABCDEF' for c in t)
    return t.isdigit()


def format_section_begin(
    writer: NSScriptWriter,
    section: NSSection,
    index: int,
    read_string: Callable[[int], str | None],
    is_installer: bool,
) -> bool:
    """
    Write Section/SectionGroup/SectionGroupEnd header. Returns True if the section is a group
    marker (no body to close with SectionEnd).
    """
    flags = NSSectionFlags(section.flags)
    name = read_string(section.name)
    if name is None:
        name = ''
    if not is_installer and name.lower() != 'uninstall':
        name = F'un.{name}'
    if flags & NSSectionFlags.BOLD:
        name = F'!{name}'

    if flags & NSSectionFlags.SECGRPEND:
        writer.add_string_lf('SectionGroupEnd')
        return True

    if flags & NSSectionFlags.SECGRP:
        writer.write('SectionGroup')
        if flags & NSSectionFlags.EXPAND:
            writer.write(' /e')
        writer.space_quoted(name)
        writer.small_space_comment()
        writer.write(F'Section_{index}')
        writer.newline()
        return True

    writer.write('Section')
    if not (flags & NSSectionFlags.SELECTED):
        writer.write(' /o')
    if name:
        writer.space_quoted(name)
    writer.small_space_comment()
    writer.write(F'Section_{index}')
    writer.newline()

    if section.size_kb != 0:
        writer.tab()
        writer.comment(F'AddSize {section.size_kb}')
        writer.newline()

    need_section_in = (
        (section.name != 0 and section.install_types != 0)
        or (section.name == 0 and section.install_types != 0xFFFFFFFF)
    )
    if need_section_in or (flags & NSSectionFlags.RO):
        writer.tab_string('SectionIn')
        inst_types = section.install_types
        for i in range(32):
            if inst_types & (1 << i):
                writer.write(F' {i + 1}')
        if flags & NSSectionFlags.RO:
            writer.write(' RO')
        writer.newline()

    return False


def format_section_end(writer: NSScriptWriter):
    """
    Write SectionEnd.
    """
    writer.add_string_lf('SectionEnd')
    writer.newline()


def _func_name(labels: list[int], index: int) -> str:
    """
    Generate a function name string from the label flags at the given index.
    """
    mask = labels[index]
    if mask & CMD_REF_OnFunc:
        func_id = (mask >> CMD_REF_OnFunc_NumShifts) & 0xF
        if func_id < len(ON_FUNCS):
            return F'.on{ON_FUNCS[func_id]}'
        return F'.onFunc_{func_id}'
    if mask & CMD_REF_InitPluginDir:
        return 'Initialize_____Plugins'
    return F'func_{index}'


def _add_param_func(
    writer: NSScriptWriter,
    labels: list[int],
    index: int,
):
    """
    Write a space followed by a function name or empty quotes.
    """
    writer.space()
    signed = index if index < 0x80000000 else index - 0x100000000
    if signed >= 0 and index < len(labels):
        writer.write(_func_name(labels, index))
    else:
        writer.add_quotes()


def emit_pages(
    writer: NSScriptWriter,
    header: NSHeader,
    labels: list[int],
    is_installer: bool,
) -> None:
    """
    Emit Page/UninstPage/PageEx blocks from the bh_pages data. Updates the labels array with
    CMD_REF_Pre/Show/Leave for page callbacks.
    """
    bh = header.bh_pages
    if bh.count == 0:
        return

    writer.separator()
    writer.comment(F'PAGES: {bh.count}')
    writer.newline()

    raw = bytes(header.raw_data)
    num_instructions = len(labels)

    if (
        bh.count > (1 << 12)
        or bh.offset > len(raw)
        or bh.count * PAGE_SIZE > len(raw) - bh.offset
    ):
        writer.big_space_comment()
        writer.write('!!! ERROR: Pages error')
        writer.newline()
        return

    writer.newline()

    for page_index in range(bh.count):
        base = bh.offset + page_index * PAGE_SIZE
        p = raw[base:base + PAGE_SIZE]
        if len(p) < PAGE_SIZE:
            break

        dlg_id = struct.unpack_from('<I', p, 0)[0]
        wnd_proc_id = struct.unpack_from('<I', p, 4)[0]
        pre_func = struct.unpack_from('<I', p, 8)[0]
        show_func = struct.unpack_from('<I', p, 12)[0]
        leave_func = struct.unpack_from('<I', p, 16)[0]
        flags = struct.unpack_from('<I', p, 20)[0]
        caption = struct.unpack_from('<I', p, 24)[0]
        next_param = struct.unpack_from('<I', p, 32)[0]
        params = [struct.unpack_from('<I', p, 44 + 4 * i)[0] for i in range(5)]

        def _set_func_ref(func_index: int, flag: int):
            signed = func_index if func_index < 0x80000000 else func_index - 0x100000000
            if signed >= 0 and func_index < num_instructions:
                labels[func_index] = (
                    (labels[func_index] & ~CMD_REF_Page_Mask)
                    | flag
                    | (page_index << CMD_REF_Page_NumShifts)
                )

        _set_func_ref(pre_func, CMD_REF_Pre)
        _set_func_ref(show_func, CMD_REF_Show)
        _set_func_ref(leave_func, CMD_REF_Leave)

        if wnd_proc_id == PAGE_COMPLETED:
            writer.comment_open()

        writer.comment(F'Page {page_index}')
        writer.newline()

        if flags & PF_PAGE_EX:
            writer.write('PageEx ')
            if not is_installer:
                writer.write('un.')
        else:
            writer.write('Page ' if is_installer else 'UninstPage ')

        if wnd_proc_id < len(PAGE_TYPES):
            writer.write(PAGE_TYPES[wnd_proc_id])
        else:
            writer.add_uint(wnd_proc_id)

        pre_signed = pre_func if pre_func < 0x80000000 else pre_func - 0x100000000
        show_signed = show_func if show_func < 0x80000000 else show_func - 0x100000000
        leave_signed = leave_func if leave_func < 0x80000000 else leave_func - 0x100000000
        need_callbacks = pre_signed >= 0 or show_signed >= 0 or leave_signed >= 0

        if flags & PF_PAGE_EX:
            writer.newline()
            if need_callbacks:
                writer.tab_string('PageCallbacks')

        if need_callbacks:
            _add_param_func(writer, labels, pre_func)
            if wnd_proc_id != PAGE_CUSTOM:
                _add_param_func(writer, labels, show_func)
            _add_param_func(writer, labels, leave_func)

        if not (flags & PF_PAGE_EX):
            if flags & PF_CANCEL_ENABLE:
                writer.write(' /ENABLECANCEL')
            writer.newline()
        else:
            writer.newline()
            if caption != 0:
                writer.tab_string('Caption')
                writer.space_quoted(header._read_string(caption) or '')
                writer.newline()

        if wnd_proc_id == PAGE_LICENSE:
            _emit_license_page(writer, header, flags, dlg_id, params, next_param)
        elif wnd_proc_id == PAGE_SELCOM:
            _emit_page_option(writer, header, params, 3, 'ComponentsText')
        elif wnd_proc_id == PAGE_DIR:
            _emit_page_option(writer, header, params, 4, 'DirText')
            if params[4] != 0:
                writer.tab_string('DirVar')
                writer.space()
                writer.write(header._string_code_variable(params[4] - 1))
                writer.newline()
            if flags & PF_DIR_NO_BTN_DISABLE:
                writer.tab_string('DirVerify leave')
                writer.newline()
        elif wnd_proc_id == PAGE_INSTFILES:
            if params[2] != 0:
                writer.tab_string('CompletedText')
                writer.space_quoted(header._read_string(params[2]) or '')
                writer.newline()
            if params[1] != 0:
                writer.tab_string('DetailsButtonText')
                writer.space_quoted(header._read_string(params[1]) or '')
                writer.newline()
        elif wnd_proc_id == PAGE_UNINST:
            if params[4] != 0:
                writer.tab_string('DirVar')
                writer.space()
                writer.write(header._string_code_variable(params[4] - 1))
                writer.newline()
            _emit_page_option(writer, header, params, 2, 'UninstallText')

        if flags & PF_PAGE_EX:
            writer.write('PageExEnd')
            writer.newline()
        if wnd_proc_id == PAGE_COMPLETED:
            writer.comment_close()
        writer.newline()


def _emit_license_page(
    writer: NSScriptWriter,
    header: NSHeader,
    flags: int,
    dlg_id: int,
    params: list[int],
    next_param: int,
) -> None:
    if (flags & PF_LICENSE_NO_FORCE_SELECTION) or (flags & PF_LICENSE_FORCE_SELECTION):
        writer.tab_string('LicenseForceSelection ')
        if flags & PF_LICENSE_NO_FORCE_SELECTION:
            writer.write('off')
        else:
            if dlg_id == IDD_LICENSE_FSCB:
                writer.write('checkbox')
            elif dlg_id == IDD_LICENSE_FSRB:
                writer.write('radiobuttons')
            else:
                writer.add_uint(dlg_id)
            for i in range(2, 4):
                if params[i] != 0:
                    writer.space_quoted(header._read_string(params[i]) or '')
        writer.newline()

    if params[0] != 0 or next_param != 0:
        writer.tab_string('LicenseText')
        writer.space_quoted(header._read_string(params[0]) or '')
        if next_param != 0:
            writer.space_quoted(header._read_string(next_param) or '')
        writer.newline()

    if params[1] != 0:
        writer.tab_string('LicenseData')
        signed = params[1] if params[1] < 0x80000000 else params[1] - 0x100000000
        if signed < 0:
            writer.space_quoted(header._read_string(params[1]) or '')
        else:
            writer.write(F' #{params[1]}')
        writer.newline()


def _emit_page_option(
    writer: NSScriptWriter,
    header: NSHeader,
    params: list[int],
    num: int,
    name: str,
) -> None:
    actual_num = num
    while actual_num > 0 and params[actual_num - 1] == 0:
        actual_num -= 1
    if actual_num == 0:
        return
    writer.tab_string(name)
    for i in range(actual_num):
        writer.space_quoted(header._read_string(params[i]) or '')
    writer.newline()


def _format_description(header: NSHeader) -> str:
    """
    Build the NSIS type description string (e.g. "NSIS-3", "NSIS-Park-1").
    """
    if header.type >= NSType.Park1:
        suffix = '1'
        if header.type is NSType.Park2:
            suffix = '2'
        elif header.type is NSType.Park3:
            suffix = '3'
        s = F'NSIS-Park-{suffix}'
    else:
        s = 'NSIS-2' if header.type is NSType.Nsis2 else 'NSIS-3'
    if header._is_nsis200:
        s += '.00'
    elif header._is_nsis225:
        s += '.25'
    if header.unicode:
        s += ' Unicode'
    if header._log_cmd_is_enabled:
        s += ' log'
    if header._bad_cmd >= 0:
        s += F' BadCmd={header._bad_cmd}'
    return s


def emit_header_info(
    writer: NSScriptWriter,
    header: NSHeader,
    archive: NSArchive | None,
    is_installer: bool,
) -> None:
    """
    Emit header metadata: NSIS type, compressor, flags, language tables, InstType list,
    InstallDir, and post-header strings.
    """
    writer.comment('NSIS script')
    if header.unicode:
        writer.write(' (UTF-8)')
    writer.space()
    writer.write(_format_description(header))
    writer.newline()

    writer.comment('Install' if is_installer else 'Uninstall')
    writer.newline()
    writer.newline()

    if header.unicode:
        writer.add_string_lf('Unicode true')

    if archive is not None and archive.method is not NSMethod.Copy:
        writer.write('SetCompressor')
        if archive.solid:
            writer.write(' /SOLID')
        method_name = {
            NSMethod.Deflate: 'zlib',
            NSMethod.NSGzip: 'zlib',
            NSMethod.BZip2: 'bzip2',
            NSMethod.LZMA: 'lzma',
        }.get(archive.method)
        if method_name:
            writer.space()
            writer.write(method_name)
        writer.newline()

    if archive is not None and archive.method is NSMethod.LZMA and archive.lzma_options is not None:
        writer.write('SetCompressorDictSize ')
        writer.add_uint(archive.lzma_options.dictionary_size >> 20)
        writer.newline()

    writer.separator()

    writer.comment(F'HEADER SIZE: {header.raw_size}')
    writer.newline()

    if header.bh_pages.offset != 0:
        writer.comment(F'START HEADER SIZE: {header.bh_pages.offset}')
        writer.newline()

    bh_sections = header.bh_sections
    bh_entries = header.bh_entries
    if bh_sections.count > 0 and bh_entries.offset > bh_sections.offset:
        section_size = (bh_entries.offset - bh_sections.offset) // bh_sections.count
        if section_size >= 24:
            max_string_len = section_size - 24
            if header.unicode:
                max_string_len >>= 1
            if max_string_len == 0:
                writer.comment(F'SECTION SIZE: {section_size}')
            else:
                writer.comment(F'MAX STRING LENGTH: {max_string_len}')
            writer.newline()

    num_string_chars = header.bh_langtbl.offset - header.bh_strings.offset
    if header.unicode:
        num_string_chars >>= 1
    writer.comment(F'STRING CHARS: {num_string_chars}')
    writer.newline()

    if header.bh_ctlcolors.offset > header.raw_size:
        writer.big_space_comment()
        writer.add_string_lf('Bad COLORS TABLE')

    if header.bh_ctlcolors.count != 0:
        writer.comment(F'COLORS Num: {header.bh_ctlcolors.count}')
        writer.newline()

    if header.bh_font.count != 0:
        writer.comment(F'FONTS Num: {header.bh_font.count}')
        writer.newline()

    if header.bh_data.count != 0:
        writer.comment(F'DATA NUM: {header.bh_data.count}')
        writer.newline()

    writer.newline()
    writer.add_string_lf('OutFile [NSIS].exe')
    writer.add_string_lf('!include WinMessages.nsh')
    writer.newline()

    raw = bytes(header.raw_data)
    if len(raw) < 4:
        return

    eh_flags = NSScriptFlags(struct.unpack_from('<I', raw, 0)[0])
    show_details = int(eh_flags) & 3
    if 1 <= show_details <= 2:
        writer.write('ShowInstDetails' if is_installer else 'ShowUninstDetails')
        writer.add_string_lf(' show' if show_details == 1 else ' nevershow')

    if eh_flags & NSScriptFlags.PROGRESS_COLORED:
        writer.add_string_lf('InstProgressFlags colored')
    if eh_flags & (NSScriptFlags.SILENT | NSScriptFlags.SILENT_LOG):
        writer.write('SilentInstall ' if is_installer else 'SilentUnInstall ')
        writer.add_string_lf('silentlog' if (eh_flags & NSScriptFlags.SILENT_LOG) else 'silent')
    if eh_flags & NSScriptFlags.AUTO_CLOSE:
        writer.add_string_lf('AutoCloseWindow true')
    if not (eh_flags & NSScriptFlags.NO_ROOT_DIR):
        writer.add_string_lf('AllowRootDirInstall true')
    if eh_flags & NSScriptFlags.NO_CUSTOM:
        writer.add_string_lf('InstType /NOCUSTOM')
    if eh_flags & NSScriptFlags.COMP_ONLY_ON_CUSTOM:
        writer.add_string_lf('InstType /COMPONENTSONLYONCUSTOM')

    bho_size = 12 if header.is64bit else 8
    params_offset = 4 + bho_size * 8
    if header.bh_pages.offset == 276:
        params_offset -= bho_size

    if params_offset + 40 > len(raw):
        return

    def _get32(off: int) -> int:
        return struct.unpack_from('<I', raw, off)[0]

    p2 = params_offset

    root_key = _get32(p2)
    sub_key = _get32(p2 + 4)
    value = _get32(p2 + 8)
    if (root_key != 0 and root_key != 0xFFFFFFFF) or sub_key != 0 or value != 0:
        writer.write('InstallDirRegKey')
        writer.space()
        writer.write(decode_reg_root(root_key))
        s = header._read_string(sub_key)
        if s:
            writer.space_quoted(s)
        s = header._read_string(value)
        if s:
            writer.space_quoted(s)
        writer.newline()

    bg_color1 = _get32(p2 + 12)
    bg_color2 = _get32(p2 + 16)
    bg_textcolor = _get32(p2 + 20)
    if bg_color1 != 0xFFFFFFFF or bg_color2 != 0xFFFFFFFF or bg_textcolor != 0xFFFFFFFF:
        writer.write('BGGradient')
        if bg_color1 != 0 or bg_color2 != 0xFF0000 or bg_textcolor != 0xFFFFFFFF:
            writer.space()
            writer.add_color(bg_color1)
            writer.space()
            writer.add_color(bg_color2)
            if bg_textcolor != 0xFFFFFFFF:
                writer.space()
                writer.add_color(bg_textcolor)
        writer.newline()

    lb_bg = _get32(p2 + 24)
    lb_fg = _get32(p2 + 28)
    if (lb_bg != 0xFFFFFFFF or lb_fg != 0xFFFFFFFF) and (lb_bg != 0 or lb_fg != 0xFF00):
        writer.write('InstallColors')
        writer.space()
        writer.add_color(lb_fg)
        writer.space()
        writer.add_color(lb_bg)
        writer.newline()

    license_bg = _get32(p2 + 36)
    signed_license_bg = license_bg if license_bg < 0x80000000 else license_bg - 0x100000000
    if license_bg != 0xFFFFFFFF and signed_license_bg != -15:
        writer.write('LicenseBkColor')
        if signed_license_bg == -5:
            writer.write(' /windows')
        else:
            writer.space()
            writer.add_color(license_bg)
        writer.newline()

    langtable_size = _get32(p2 + 32)
    bh_langtbl = header.bh_langtbl
    if bh_langtbl.count > 0 and langtable_size != 0xFFFFFFFF:
        if langtable_size >= 10:
            num_strings = (langtable_size - 10) // 4
        else:
            num_strings = 0

        writer.newline()
        writer.separator()
        writer.comment(F'LANG TABLES: {bh_langtbl.count}')
        writer.newline()
        writer.comment(F'LANG STRINGS: {num_strings}')
        writer.newline()
        writer.newline()

        license_lang_index = -1
        bh_pages = header.bh_pages
        if bh_pages.count > 0:
            for page_i in range(bh_pages.count):
                page_base = bh_pages.offset + page_i * PAGE_SIZE
                if page_base + PAGE_SIZE > len(raw):
                    break
                wnd_proc_id = struct.unpack_from('<I', raw, page_base + 4)[0]
                param1 = struct.unpack_from('<I', raw, page_base + 44 + 4)[0]
                if wnd_proc_id != PAGE_LICENSE or param1 == 0:
                    continue
                signed_param1 = param1 if param1 < 0x80000000 else param1 - 0x100000000
                if signed_param1 < 0:
                    license_lang_index = -(signed_param1 + 1)

        if license_lang_index >= 0:
            for i in range(bh_langtbl.count):
                lang_base = bh_langtbl.offset + langtable_size * i
                if lang_base + 10 + (license_lang_index + 1) * 4 > len(raw):
                    break
                lang_id = struct.unpack_from('<H', raw, lang_base)[0]
                val = struct.unpack_from('<I', raw, lang_base + 10 + license_lang_index * 4)[0]
                if val != 0:
                    writer.write(F'LicenseLangString LSTR_{license_lang_index}')
                    writer.write(F' {lang_id}')
                    s = header._read_string(val)
                    if s:
                        writer.space_quoted(nsis_escape(s))
                    writer.newline()
            writer.newline()

        branding_text = 0
        name_val = 0
        for i in range(bh_langtbl.count):
            lang_base = bh_langtbl.offset + langtable_size * i
            if lang_base + 10 + 3 * 4 > len(raw):
                break
            lang_id = struct.unpack_from('<H', raw, lang_base)[0]
            v0 = struct.unpack_from('<I', raw, lang_base + 10 + 0 * 4)[0]
            v2 = struct.unpack_from('<I', raw, lang_base + 10 + 2 * 4)[0]
            if v0 != 0 and (lang_id == 1033 or branding_text == 0):
                branding_text = v0
            if v2 != 0 and (lang_id == 1033 or name_val == 0):
                name_val = v2

        if name_val != 0:
            writer.write('Name')
            s = header._read_string(name_val)
            if s:
                writer.space_quoted(s)
            writer.newline()

        if branding_text != 0:
            writer.write('BrandingText')
            s = header._read_string(branding_text)
            if s:
                writer.space_quoted(s)
            writer.newline()

        for i in range(bh_langtbl.count):
            lang_base = bh_langtbl.offset + langtable_size * i
            if lang_base + 10 > len(raw):
                break
            lang_id = struct.unpack_from('<H', raw, lang_base)[0]
            writer.newline()
            writer.comment(F'LANG: {lang_id}')
            writer.newline()

            for j in range(num_strings):
                str_off = lang_base + 10 + j * 4
                if str_off + 4 > len(raw):
                    break
                val = struct.unpack_from('<I', raw, str_off)[0]
                if val != 0 and j != license_lang_index:
                    writer.write(F'LangString LSTR_{j} {lang_id}')
                    s = header._read_string(val)
                    if s:
                        writer.space_quoted(nsis_escape(s))
                    writer.newline()
            writer.newline()

    on_func_count = len(ON_FUNCS)
    if header.bh_pages.offset == 276:
        on_func_count -= 1

    p2_after = params_offset + 40 + on_func_count * 4
    writer.newline()

    for i in range(NSIS_MAX_INST_TYPES + 1):
        off = p2_after + i * 4
        if off + 4 > len(raw):
            break
        inst_type = _get32(off)
        if inst_type != 0:
            writer.write('InstType')
            s = ''
            if not is_installer:
                s = 'un.'
            resolved = header._read_string(inst_type)
            if resolved:
                s += resolved
            writer.space_quoted(s)
            writer.newline()

    install_dir_off = p2_after + (NSIS_MAX_INST_TYPES + 1) * 4
    if install_dir_off + 4 <= len(raw):
        install_dir = _get32(install_dir_off)
        if install_dir != 0:
            writer.write('InstallDir')
            s = header._read_string(install_dir)
            if s:
                writer.space_quoted(nsis_escape(s))
            writer.newline()

    if header.bh_pages.offset >= 288:
        post_off = install_dir_off + 4
        for i in range(4):
            if i != 0 and header.bh_pages.offset < 300:
                break
            if post_off + 4 > len(raw):
                break
            param = _get32(post_off + 4 * i)
            if param == 0 or param == 0xFFFFFFFF:
                continue
            writer.comment(F'{_POST_STRINGS[i]} =')
            s = header._read_string(param)
            if s:
                writer.space_quoted(nsis_escape(s))
            writer.newline()

    writer.newline()


SW_HIDE = 0
SW_SHOWNORMAL = 1
SW_SHOWMINIMIZED = 2
SW_SHOWMINNOACTIVE = 7
SW_SHOWNA = 8

GENERIC_READ = 1 << 31
GENERIC_WRITE = 1 << 30
GENERIC_EXECUTE = 1 << 29
GENERIC_ALL = 1 << 28

CREATE_NEW = 1
CREATE_ALWAYS = 2
OPEN_EXISTING = 3
OPEN_ALWAYS = 4
TRUNCATE_EXISTING = 5

TRANSPARENT = 1

COLORS_TEXT = 1
COLORS_TEXT_SYS = 2
COLORS_BK = 4
COLORS_BK_SYS = 8
COLORS_BKB = 16

CTL_COLORS_SIZE = 24

K_EXEC_FLAGS_ERRORS = 2
K_EXEC_FLAGS_DETAILS_PRINT = 13

K_INTOP_OPS = '+-*/|&^!|&%<>'


def _add_goto_var(writer: NSScriptWriter, header: NSHeader, param: int):
    writer.space()
    signed = param if param < 0x80000000 else param - 0x100000000
    if signed < 0:
        writer.write(header._string_code_variable(-(signed + 1)))
    else:
        writer.write(F'label_{param - 1}')


def _add_goto_var1(writer: NSScriptWriter, header: NSHeader, param: int):
    if param == 0:
        writer.write(' 0')
    else:
        _add_goto_var(writer, header, param)


def _add_goto_vars2(writer: NSScriptWriter, header: NSHeader, p0: int, p1: int):
    _add_goto_var1(writer, header, p0)
    if p1 != 0:
        _add_goto_var(writer, header, p1)


def _add_param(writer: NSScriptWriter, header: NSHeader, param: int):
    writer.space()
    s = header._read_string(param)
    if s is not None:
        writer.add_quoted(nsis_escape(s))
    else:
        writer.add_uint(param)


def _add_param_var(writer: NSScriptWriter, header: NSHeader, param: int):
    writer.space()
    writer.write(header._string_code_variable(param))


def _add_params(writer: NSScriptWriter, header: NSHeader, params: list[int], num: int):
    for i in range(num):
        _add_param(writer, header, params[i])


def _add_optional_param(writer: NSScriptWriter, header: NSHeader, param: int):
    if param != 0:
        _add_param(writer, header, param)


def _add_optional_params(
    writer: NSScriptWriter, header: NSHeader, params: list[int], num: int,
):
    actual = num
    while actual > 0 and params[actual - 1] == 0:
        actual -= 1
    _add_params(writer, header, params, actual)


def render_opcode(
    writer: NSScriptWriter,
    header: NSHeader,
    instruction: NSScriptInstruction | NSScriptExtendedInstruction,
    opcode: Op,
    labels: list[int],
    raw: bytes,
    overwrite_state: list[int],
    address: int,
    commented: bool,
) -> None:
    """
    Render a single NSIS opcode's arguments to the writer. Handles all opcodes except Ret and
    INVALID_OPCODE, which require structural context handled by the caller.
    """
    params = instruction.arguments

    if opcode is Op.Nop:
        if params[0] == 0:
            writer.write('Nop')
        else:
            writer.write('Goto')
            _add_goto_var(writer, header, params[0])

    elif opcode is Op.Abort:
        writer.write(opcode.name)
        _add_optional_param(writer, header, params[0])

    elif opcode is Op.Quit:
        writer.write(opcode.name)

    elif opcode is Op.Call:
        writer.write('Call ')
        signed_p0 = params[0] if params[0] < 0x80000000 else params[0] - 0x100000000
        if signed_p0 < 0:
            writer.write(header._string_code_variable(-(signed_p0 + 1)))
        elif params[0] == 0:
            writer.write('0')
        else:
            val = params[0] - 1
            if params[1] == 1:
                writer.write(F':label_{val}')
            else:
                writer.write(_func_name(labels, val))

    elif opcode is Op.DetailPrint or opcode is Op.Sleep:
        writer.write(opcode.name)
        _add_param(writer, header, params[0])

    elif opcode is Op.BringToFront:
        writer.write(opcode.name)

    elif opcode is Op.SetDetailsView:
        writer.write(opcode.name)
        if params[0] == SW_SHOWNA and params[1] == SW_HIDE:
            writer.write(' show')
        elif params[1] == SW_SHOWNA and params[0] == SW_HIDE:
            writer.write(' hide')
        else:
            for i in range(2):
                writer.space()
                writer.write(decode_showwindow(params[i]))

    elif opcode is Op.SetFileAttributes:
        writer.write(opcode.name)
        _add_param(writer, header, params[0])
        writer.space()
        writer.write(decode_file_attributes(params[1]))

    elif opcode is Op.CreateDirectory:
        is_set_out_path = params[1] != 0
        writer.write('SetOutPath' if is_set_out_path else 'CreateDirectory')
        _add_param(writer, header, params[0])
        if params[2] != 0:
            writer.small_space_comment()
            writer.write('CreateRestrictedDirectory')

    elif opcode is Op.IfFileExists:
        writer.write(opcode.name)
        _add_param(writer, header, params[0])
        _add_goto_vars2(writer, header, params[1], params[2])

    elif opcode is Op.SetFlag:
        s_val = header._read_string(params[1]) or ''
        if params[0] == K_EXEC_FLAGS_ERRORS and params[2] == 0:
            if s_val == '0':
                writer.write('ClearErrors')
            else:
                writer.write('SetErrors')
        else:
            writer.write('Set')
            writer.write(decode_exec_flags(params[0]))
            if params[2] != 0:
                writer.write(' lastused')
            else:
                decoded = _decode_flag_value(params[0], s_val)
                if decoded is not None:
                    writer.space()
                    writer.write(decoded)
                else:
                    writer.space_quoted(nsis_escape(s_val))

    elif opcode is Op.IfFlag:
        writer.write('If')
        writer.write(decode_exec_flags(params[2]))
        _add_goto_vars2(writer, header, params[0], params[1])

    elif opcode is Op.GetFlag:
        writer.write('Get')
        writer.write(decode_exec_flags(params[1]))
        _add_param_var(writer, header, params[0])

    elif opcode is Op.Rename:
        writer.write(opcode.name)
        if params[2] != 0:
            writer.write(' /REBOOTOK')
        _add_params(writer, header, params, 2)
        if params[3] != 0:
            writer.small_space_comment()
            _add_param(writer, header, params[3])

    elif opcode is Op.GetFullPathName:
        writer.write(opcode.name)
        if params[2] == 0:
            writer.write(' /SHORT')
        _add_param_var(writer, header, params[1])
        _add_param(writer, header, params[0])

    elif opcode is Op.SearchPath or opcode is Op.StrLen:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[0])
        _add_param(writer, header, params[1])

    elif opcode is Op.GetTempFileName:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[0])
        s = header._read_string(params[1])
        if s and s != '$TEMP':
            writer.space_quoted(nsis_escape(s))

    elif opcode is Op.ExtractFile:
        overwrite = params[0] & 0x7
        if overwrite != overwrite_state[0]:
            writer.write('SetOverwrite ')
            writer.write(decode_setoverwrite(overwrite))
            overwrite_state[0] = overwrite
            writer.newline()
            writer.tab(commented)
        writer.write('File')
        _add_param(writer, header, params[1])

    elif opcode is Op.Delete:
        writer.write(opcode.name)
        flag = params[1]
        if flag & DEL_REBOOT:
            writer.write(' /REBOOTOK')
        _add_param(writer, header, params[0])

    elif opcode is Op.MessageBox:
        writer.write(opcode.name)
        writer.space()
        writer.write(decode_messagebox(params[0]))
        _add_param(writer, header, params[1])
        button_id = params[0] >> 21
        if button_id != 0:
            writer.write(' /SD')
            writer.write(decode_button_id(button_id))
        for i in range(2, 6, 2):
            if params[i] != 0:
                writer.space()
                writer.write(decode_button_id(params[i]))
                _add_goto_var1(writer, header, params[i + 1])

    elif opcode is Op.RMDir:
        writer.write(opcode.name)
        flag = params[1]
        if flag & DEL_RECURSE:
            writer.write(' /r')
        if flag & DEL_REBOOT:
            writer.write(' /REBOOTOK')
        _add_param(writer, header, params[0])

    elif opcode is Op.AssignVar:
        writer.write('StrCpy')
        _add_param_var(writer, header, params[0])
        _add_param(writer, header, params[1])
        _add_optional_params(writer, header, params[2:4], 2)

    elif opcode is Op.StrCmp:
        writer.write('StrCmpS' if params[4] != 0 else 'StrCmp')
        _add_params(writer, header, params, 2)
        _add_goto_vars2(writer, header, params[2], params[3])

    elif opcode is Op.ReadEnvStr:
        writer.write('ReadEnvStr' if params[2] != 0 else 'ExpandEnvStrings')
        _add_param_var(writer, header, params[0])
        _add_param(writer, header, params[1])

    elif opcode is Op.IntCmp:
        writer.write('IntCmpU' if params[5] != 0 else 'IntCmp')
        _add_params(writer, header, params, 2)
        _add_goto_var1(writer, header, params[2])
        if params[3] != 0 or params[4] != 0:
            _add_goto_vars2(writer, header, params[3], params[4])

    elif opcode is Op.IntOp:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[0])
        op_index = params[3]
        c = K_INTOP_OPS[op_index] if op_index < 13 else '?'
        c2 = '' if (op_index < 8 or op_index == 10) else c
        num_ops = 1 if op_index == 7 else 2
        _add_param(writer, header, params[1])
        writer.space()
        writer.write(c)
        if num_ops != 1:
            if c2:
                writer.write(c2)
            _add_param(writer, header, params[2])

    elif opcode is Op.IntFmt:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[0])
        _add_params(writer, header, params[1:3], 2)

    elif opcode is Op.PushPop:
        if params[2] != 0:
            writer.write('Exch')
            if params[2] != 1:
                writer.write(F' {params[2]}')
        elif params[1] != 0:
            writer.write('Pop')
            _add_param_var(writer, header, params[0])
        else:
            writer.write('Push')
            _add_param(writer, header, params[0])

    elif opcode is Op.FindWindow:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[0])
        _add_param(writer, header, params[1])
        _add_optional_params(writer, header, params[2:5], 3)

    elif opcode is Op.SendMessage:
        writer.write(opcode.name)
        _add_param(writer, header, params[1])
        _add_param(writer, header, params[2])
        spec = params[5]
        for i in range(2):
            prefix = 'STR:' if (spec & (1 << i)) else ''
            s = header._read_string(params[3 + i])
            writer.space_quoted(prefix + nsis_escape(s or ''))
        signed_p0 = params[0] if params[0] < 0x80000000 else params[0] - 0x100000000
        if signed_p0 >= 0:
            _add_param_var(writer, header, params[0])
        timeout = spec >> 2
        if timeout != 0:
            writer.write(F' /TIMEOUT={timeout}')

    elif opcode is Op.IsWindow:
        writer.write(opcode.name)
        _add_param(writer, header, params[0])
        _add_goto_vars2(writer, header, params[1], params[2])

    elif opcode is Op.GetDlgItem:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[0])
        _add_params(writer, header, params[1:3], 2)

    elif opcode is Op.SetCtlColors:
        writer.write(opcode.name)
        _add_param(writer, header, params[0])
        offset = params[1]
        bh_cc = header.bh_ctlcolors
        if (
            header.raw_size < bh_cc.offset
            or header.raw_size - bh_cc.offset < offset
            or header.raw_size - bh_cc.offset - offset < CTL_COLORS_SIZE
        ):
            writer.write(' ; bad offset')
        else:
            p2 = bh_cc.offset + offset
            cc_text = struct.unpack_from('<I', raw, p2)[0]
            cc_bkc = struct.unpack_from('<I', raw, p2 + 4)[0]
            cc_bkmode = struct.unpack_from('<i', raw, p2 + 16)[0]
            cc_flags = struct.unpack_from('<i', raw, p2 + 20)[0]
            if (cc_flags & COLORS_BK_SYS) or (cc_flags & COLORS_TEXT_SYS):
                writer.write(' /BRANDING')
            bk = ''
            bkc_print = False
            if cc_bkmode == TRANSPARENT:
                bk = ' transparent'
            elif cc_flags & COLORS_BKB:
                if not (cc_flags & COLORS_BK_SYS) and (cc_flags & COLORS_BK):
                    bkc_print = True
            if (cc_flags & COLORS_TEXT) or bk or bkc_print:
                writer.space()
                if (cc_flags & COLORS_TEXT_SYS) or not (cc_flags & COLORS_TEXT):
                    writer.add_quotes()
                else:
                    writer.add_color(cc_text)
            writer.write(bk)
            if bkc_print:
                writer.space()
                writer.add_color(cc_bkc)

    elif opcode is Op.SetBrandingImage:
        writer.write(opcode.name)
        writer.write(F' /IMGID={params[1]}')
        if params[2] == 1:
            writer.write(' /RESIZETOFIT')
        _add_param(writer, header, params[0])

    elif opcode is Op.CreateFont:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[0])
        _add_param(writer, header, params[1])
        _add_optional_params(writer, header, params[2:4], 2)
        if params[4] & 1:
            writer.write(' /ITALIC')
        if params[4] & 2:
            writer.write(' /UNDERLINE')
        if params[4] & 4:
            writer.write(' /STRIKE')

    elif opcode is Op.ShowWindow:
        if params[3] != 0:
            writer.write('EnableWindow')
        else:
            writer.write('ShowWindow')
        _add_param(writer, header, params[0])
        _add_param(writer, header, params[1])

    elif opcode is Op.ExecShell:
        writer.write(opcode.name)
        _add_params(writer, header, params, 2)
        if params[2] != 0 or params[3] != SW_SHOWNORMAL:
            _add_param(writer, header, params[2])
            if params[3] != SW_SHOWNORMAL:
                writer.space()
                writer.write(decode_showwindow(params[3]))
        if params[5] != 0:
            writer.write('    ;')
            _add_param(writer, header, params[5])

    elif opcode is Op.Exec:
        writer.write('ExecWait' if params[2] != 0 else 'Exec')
        _add_param(writer, header, params[0])
        signed_p1 = params[1] if params[1] < 0x80000000 else params[1] - 0x100000000
        if params[2] != 0 and signed_p1 >= 0:
            _add_param_var(writer, header, params[1])

    elif opcode is Op.GetFileTime or opcode is Op.GetDLLVersion:
        writer.write(opcode.name)
        _add_param(writer, header, params[2])
        _add_param_var(writer, header, params[0])
        _add_param_var(writer, header, params[1])

    elif opcode is Op.RegisterDll:
        func_str = header._read_string(params[1]) or ''
        print_func = True
        if params[2] == 0:
            writer.write('CallInstDLL')
            _add_param(writer, header, params[0])
            if params[3] == 1:
                writer.write(' /NOUNLOAD')
        else:
            if func_str == 'DllUnregisterServer':
                writer.write('UnRegDLL')
                print_func = False
            else:
                writer.write('RegDLL')
                if func_str == 'DllRegisterServer':
                    print_func = False
            _add_param(writer, header, params[0])
        if print_func:
            writer.space_quoted(nsis_escape(func_str))

    elif opcode is Op.CreateShortCut:
        writer.write(opcode.name)
        num_params = 6
        while num_params > 2 and params[num_params - 1] == 0:
            num_params -= 1
        spec = params[4]
        if spec & 0x8000:
            writer.write(' /NoWorkingDir')
        _add_params(writer, header, params, min(num_params, 4))
        if num_params <= 4:
            pass
        else:
            icon = spec & 0xFF
            writer.space()
            if icon != 0:
                writer.add_uint(icon)
            else:
                writer.add_quotes()
            sw = (spec >> 8) & 0x7F
            if (spec >> 8) == 0 and num_params < 6:
                pass
            else:
                if sw == SW_SHOWMINNOACTIVE:
                    sw = SW_SHOWMINIMIZED
                writer.space()
                if sw == 0:
                    writer.add_quotes()
                else:
                    writer.write(decode_showwindow(sw))
                hotkey = decode_shortcut_hotkey(spec)
                if hotkey:
                    writer.space()
                    writer.write(hotkey)
                elif num_params >= 6:
                    writer.space()
                    writer.add_quotes()
                _add_optional_param(writer, header, params[5])

    elif opcode is Op.CopyFiles:
        writer.write(opcode.name)
        if params[2] & 0x04:
            writer.write(' /SILENT')
        if params[2] & 0x80:
            writer.write(' /FILESONLY')
        _add_params(writer, header, params, 2)
        if params[3] != 0:
            writer.write('    ;')
            _add_param(writer, header, params[3])

    elif opcode is Op.Reboot:
        writer.write(opcode.name)
        if params[0] != 0xBADF00D:
            writer.write(' ; Corrupted ???')

    elif opcode is Op.WriteINI:
        num_always = 0
        if params[0] == 0:
            writer.write('FlushINI')
        elif params[4] != 0:
            writer.write('WriteINIStr')
            num_always = 3
        else:
            writer.write('DeleteINI')
            writer.write('Sec' if params[1] == 0 else 'Str')
            num_always = 1
        _add_param(writer, header, params[3])
        _add_params(writer, header, params, num_always)
        _add_optional_params(writer, header, params[num_always:3], 3 - num_always)

    elif opcode is Op.ReadINIStr:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[0])
        _add_param(writer, header, params[3])
        _add_params(writer, header, params[1:3], 2)

    elif opcode is Op.DeleteReg:
        writer.write(opcode.name)
        if params[4] == 0:
            writer.write('Value')
        else:
            writer.write('Key')
            if params[4] & 2:
                writer.write(' /ifempty')
        writer.space()
        writer.write(decode_reg_root(params[1]))
        _add_param(writer, header, params[2])
        _add_optional_param(writer, header, params[3])

    elif opcode is Op.WriteReg:
        writer.write(opcode.name)
        reg_type_name = {1: 'Str', 2: 'ExpandStr', 3: 'Bin', 4: 'DWORD'}.get(params[4])
        if params[4] == 1 and params[5] == 2:
            reg_type_name = 'ExpandStr'
        if reg_type_name:
            writer.write(reg_type_name)
        else:
            writer.write(F'?{params[4]}')
        writer.space()
        writer.write(decode_reg_root(params[0]))
        _add_params(writer, header, params[1:3], 2)
        if params[4] != 3:
            _add_param(writer, header, params[3])
        else:
            writer.write(F' data[{params[3]} ... ]')

    elif opcode is Op.ReadReg:
        writer.write(opcode.name)
        writer.write('DWORD' if params[4] == 1 else 'Str')
        _add_param_var(writer, header, params[0])
        writer.space()
        writer.write(decode_reg_root(params[1]))
        _add_params(writer, header, params[2:4], 2)

    elif opcode is Op.EnumReg:
        writer.write(opcode.name)
        writer.write('Key' if params[4] != 0 else 'Value')
        _add_param_var(writer, header, params[0])
        writer.space()
        writer.write(decode_reg_root(params[1]))
        _add_params(writer, header, params[2:4], 2)

    elif opcode is Op.FileClose or opcode is Op.FindClose:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[0])

    elif opcode is Op.FileOpen:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[0])
        _add_param(writer, header, params[3])
        acc = params[1]
        creat = params[2]
        if acc != 0 or creat != 0:
            cc = ''
            if acc == GENERIC_READ and creat == OPEN_EXISTING:
                cc = 'r'
            elif creat == CREATE_ALWAYS and acc == GENERIC_WRITE:
                cc = 'w'
            elif creat == OPEN_ALWAYS and acc == (GENERIC_WRITE | GENERIC_READ):
                cc = 'a'
            if cc:
                writer.write(F' {cc}')
            else:
                if acc & GENERIC_READ:
                    writer.write(' GENERIC_READ')
                if acc & GENERIC_WRITE:
                    writer.write(' GENERIC_WRITE')
                if acc & GENERIC_EXECUTE:
                    writer.write(' GENERIC_EXECUTE')
                if acc & GENERIC_ALL:
                    writer.write(' GENERIC_ALL')
                creat_name = {
                    CREATE_NEW: 'CREATE_NEW',
                    CREATE_ALWAYS: 'CREATE_ALWAYS',
                    OPEN_EXISTING: 'OPEN_EXISTING',
                    OPEN_ALWAYS: 'OPEN_ALWAYS',
                    TRUNCATE_EXISTING: 'TRUNCATE_EXISTING',
                }.get(creat)
                writer.space()
                writer.write(creat_name or str(creat))

    elif opcode is Op.FileWrite or opcode is Op.FileWriteW:
        writer.write('FileWrite')
        if opcode is Op.FileWriteW:
            writer.write('UTF16LE' if params[2] == 0 else 'Word')
        elif params[2] != 0:
            writer.write('Byte')
        _add_param_var(writer, header, params[0])
        _add_param(writer, header, params[1])

    elif opcode is Op.FileRead or opcode is Op.FileReadW:
        writer.write('FileRead')
        if opcode is Op.FileReadW:
            writer.write('UTF16LE' if params[3] == 0 else 'Word')
        elif params[3] != 0:
            writer.write('Byte')
        _add_param_var(writer, header, params[0])
        _add_param_var(writer, header, params[1])
        _add_optional_param(writer, header, params[2])

    elif opcode is Op.FileSeek:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[0])
        _add_param(writer, header, params[2])
        if params[3] == 1:
            writer.write(' CUR')
        if params[3] == 2:
            writer.write(' END')
        signed_p1 = params[1] if params[1] < 0x80000000 else params[1] - 0x100000000
        if signed_p1 >= 0:
            if params[3] == 0:
                writer.write(' SET')
            _add_param_var(writer, header, params[1])

    elif opcode is Op.FindNext:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[1])
        _add_param_var(writer, header, params[0])

    elif opcode is Op.FindFirst:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[1])
        _add_param_var(writer, header, params[0])
        _add_param(writer, header, params[2])

    elif opcode is Op.WriteUninstaller:
        writer.write(opcode.name)
        _add_param(writer, header, params[0])
        if params[3] != 0:
            writer.small_space_comment()
            _add_param(writer, header, params[3])

    elif opcode is Op.SectionSet:
        writer.write('Section')
        signed_p2 = params[2] if params[2] < 0x80000000 else params[2] - 0x100000000
        if signed_p2 >= 0:
            writer.write('Get')
            writer.write(decode_sect_op(params[2]))
            _add_param(writer, header, params[0])
            _add_param_var(writer, header, params[1])
        else:
            writer.write('Set')
            t = -(signed_p2) - 1
            writer.write(decode_sect_op(t))
            _add_param(writer, header, params[0])
            _add_param(writer, header, params[4] if t == 0 else params[1])

    elif opcode is Op.InstTypeSet:
        if params[3] == 0:
            if params[2] == 0:
                writer.write('InstTypeGetText')
                _add_param(writer, header, params[0])
                _add_param_var(writer, header, params[1])
            else:
                writer.write('InstTypeSetText')
                _add_params(writer, header, params, 2)
        else:
            if params[2] == 0:
                writer.write('GetCurInstType')
                _add_param_var(writer, header, params[1])
            else:
                writer.write('SetCurInstType')
                _add_param(writer, header, params[0])

    elif opcode is Op.LockWindow:
        writer.write(opcode.name)
        writer.write(' on' if params[0] == 0 else ' off')

    elif opcode is Op.Log:
        if params[0] != 0:
            writer.write('LogSet ')
            writer.write('off' if params[1] == 0 else 'on')
        else:
            writer.write('LogText')
            _add_param(writer, header, params[1])

    elif opcode is Op.FindProc:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[0])
        _add_param(writer, header, params[1])

    elif opcode is Op.GetFontVersion or opcode is Op.GetFontName:
        writer.write(opcode.name)
        _add_param_var(writer, header, params[0])
        _add_param(writer, header, params[1])

    elif opcode is Op.GetOSInfo:
        writer.write(opcode.name)

    elif opcode is Op.ReservedOpcode:
        writer.write('GetFunctionAddress')

    else:
        writer.write(F'Command{int(opcode)}')


def emit_commands(
    writer: NSScriptWriter,
    header: NSHeader,
    label_info: LabelInfo,
    sections: list[NSSection],
    is_installer: bool,
) -> None:
    """
    Emit the main instruction body: per-opcode decompilation switch, section open/close, function
    open/close, and label markers. Function bodies are rendered using structural analysis to
    recover If/Else constructs with indentation.
    """
    from refinery.lib.nsis.controlflow import (
        build_cfg,
        eliminate_dead_code,
        linearize,
        reduce_if_else,
        reduce_loops,
        render_node,
    )

    labels = label_info.labels
    num_instructions = len(header.instructions)
    num_sections = len(sections)

    overwrite_state = [0]
    cur_section_index = 0
    section_is_open = False
    on_func_is_open = False
    end_comment_index = 0

    raw = bytes(header.raw_data)

    func_ranges: dict[int, int] = {}
    k = 0
    while k < num_instructions:
        flg = labels[k]
        if not is_func(flg):
            k += 1
            continue
        func_start = k
        k += 1
        while k < num_instructions:
            insn = header.instructions[k]
            opcode = header.opcode(insn)
            if opcode is Op.Ret:
                if k + 1 >= num_instructions or is_probably_end_of_func(labels[k + 1]):
                    func_ranges[func_start] = k + 1
                    k += 1
                    break
            k += 1
        else:
            func_ranges[func_start] = k

    writer.separator()

    kkk = 0
    while kkk < num_instructions:
        instruction = header.instructions[kkk]
        opcode = header.opcode(instruction)

        is_section_group = False
        while cur_section_index < num_sections:
            sect = sections[cur_section_index]
            if section_is_open:
                if sect.start_cmd_index + sect.num_commands + 1 != kkk:
                    break
                format_section_end(writer)
                section_is_open = False
                cur_section_index += 1
                continue
            if sect.start_cmd_index != kkk:
                break
            if format_section_begin(writer, sect, cur_section_index, header._read_string, is_installer):
                is_section_group = True
                cur_section_index += 1
            else:
                section_is_open = True

        if labels[kkk] != 0 and labels[kkk] != CMD_REF_Section:
            flg = labels[kkk]
            if is_func(flg):
                if kkk == label_info.init_plugins_dir_start:
                    writer.comment_open()
                on_func_is_open = True
                writer.write('Function ')
                writer.write(_func_name(labels, kkk))
                if is_page_func(flg):
                    writer.big_space_comment()
                    writer.write('Page ')
                    writer.add_uint((flg & CMD_REF_Page_Mask) >> CMD_REF_Page_NumShifts)
                    if flg & CMD_REF_Leave:
                        writer.write(', Leave')
                    if flg & CMD_REF_Pre:
                        writer.write(', Pre')
                    if flg & CMD_REF_Show:
                        writer.write(', Show')
                writer.newline()

                if kkk in func_ranges:
                    func_end = func_ranges[kkk]
                    body_end = func_end - 1
                    cfg = build_cfg(header, kkk, body_end)
                    root = linearize(header, cfg, labels, kkk, body_end)
                    reduced = reduce_loops(root, header)
                    reduced = reduce_if_else(reduced, header)
                    reduced = eliminate_dead_code(reduced)
                    render_node(
                        reduced, writer, header, labels, raw,
                        overwrite_state, end_comment_index,
                    )
                    if labels[body_end] & CMD_REF_Goto:
                        writer.write(F'label_{body_end}:')
                        writer.newline()
                    writer.add_string_lf('FunctionEnd')
                    if func_end == label_info.init_plugins_dir_end:
                        writer.comment_close()
                    writer.newline()
                    on_func_is_open = False
                    kkk = func_end
                    continue

            if flg & CMD_REF_Goto:
                writer.write(F'label_{kkk}:')
                writer.newline()

        commented = kkk < end_comment_index

        if opcode is Op.INVALID_OPCODE:
            writer.tab(commented)
            writer.write(F'Command{instruction.opcode}')
            writer.newline()

        elif opcode is Op.Ret:
            if on_func_is_open:
                if kkk == num_instructions - 1 or is_probably_end_of_func(labels[kkk + 1]):
                    writer.add_string_lf('FunctionEnd')
                    if kkk + 1 == label_info.init_plugins_dir_end:
                        writer.comment_close()
                    writer.newline()
                    on_func_is_open = False
                    kkk += 1
                    continue
            if is_section_group:
                kkk += 1
                continue
            if section_is_open:
                sect = sections[cur_section_index]
                if sect.start_cmd_index + sect.num_commands == kkk:
                    format_section_end(writer)
                    section_is_open = False
                    cur_section_index += 1
                    kkk += 1
                    continue
            writer.tab_string('Return')
            writer.newline()

        else:
            writer.tab(commented)
            render_opcode(writer, header, instruction, opcode, labels, raw, overwrite_state, kkk, commented)
            writer.newline()

        kkk += 1

    if section_is_open and cur_section_index < num_sections:
        sect = sections[cur_section_index]
        if sect.start_cmd_index + sect.num_commands + 1 == num_instructions:
            format_section_end(writer)
            cur_section_index += 1

    while cur_section_index < num_sections:
        sect = sections[cur_section_index]
        if section_is_open:
            if sect.start_cmd_index + sect.num_commands != num_instructions:
                break
            format_section_end(writer)
            section_is_open = False
            cur_section_index += 1
            continue
        if sect.start_cmd_index != num_instructions:
            break
        format_section_begin(writer, sect, cur_section_index, header._read_string, is_installer)
        cur_section_index += 1


_GOTO_MASKS: dict[Op, int] = {
    Op.Nop           : 1 << 0,
    Op.IfFileExists  : 3 << 1,
    Op.IfFlag        : 3 << 0,
    Op.MessageBox    : 5 << 3,
    Op.StrCmp        : 3 << 2,
    Op.IntCmp        : 7 << 2,
    Op.IsWindow      : 3 << 1,
}


def is_func(flag: int) -> bool:
    """
    Check whether a label flag indicates a function start.
    """
    return bool(flag & (CMD_REF_Call | CMD_REF_Pre | CMD_REF_Show | CMD_REF_Leave | CMD_REF_OnFunc))


def is_page_func(flag: int) -> bool:
    """
    Check whether a label flag indicates a page callback function.
    """
    return bool(flag & (CMD_REF_Pre | CMD_REF_Show | CMD_REF_Leave))


def is_probably_end_of_func(flag: int) -> bool:
    """
    Check whether a label flag likely ends a function body.
    """
    return flag != 0 and flag != CMD_REF_Goto


@dataclasses.dataclass
class LabelInfo:
    """
    Result of label analysis pass over NSIS instructions.
    """
    labels: list[int]
    init_plugins_dir_start: int = -1
    init_plugins_dir_end: int = -1


def build_labels(header: NSHeader, sections: list[NSSection]) -> LabelInfo:
    """
    Build the label array from an NSHeader. Each entry is a bitmask indicating whether the
    instruction at that index is a jump target, call target, function start, section start,
    onFunc entry, or InitPluginsDir.
    """
    num_instructions = len(header.instructions)
    labels = [0] * num_instructions
    raw = bytes(header.raw_data)

    bho_size = 12 if header.is64bit else 8
    params_offset = 4 + bho_size * 8
    if header.bh_pages.offset == 276:
        params_offset -= bho_size
    on_func_offset = params_offset + 40
    num_on_func = len(ON_FUNCS)
    if header.bh_pages.offset == 276:
        num_on_func -= 1

    for i in range(num_on_func):
        off = on_func_offset + 4 * i
        if off + 4 <= len(raw):
            func = struct.unpack_from('<I', raw, off)[0]
            if func < num_instructions:
                labels[func] = (labels[func] & ~CMD_REF_OnFunc_Mask) | (CMD_REF_OnFunc | (i << CMD_REF_OnFunc_NumShifts))

    for section in sections:
        if section.start_cmd_index < num_instructions:
            labels[section.start_cmd_index] |= CMD_REF_Section

    for instruction in header.instructions:
        opcode = header.opcode(instruction)
        args = instruction.arguments

        if opcode is Op.Call:
            if len(args) > 1 and args[1] == 1:
                param0 = args[0]
                if 0 < param0 <= num_instructions:
                    labels[param0 - 1] |= CMD_REF_Goto
            else:
                param0 = args[0]
                if param0 > 0 and param0 <= num_instructions:
                    labels[param0 - 1] |= CMD_REF_Call
            continue

        mask = _GOTO_MASKS.get(opcode)
        if mask is None:
            continue

        for i in range(6):
            if not mask:
                break
            if mask & 1:
                param = args[i] if i < len(args) else 0
                signed = param if param < 0x80000000 else param - 0x100000000
                if signed > 0 and param <= num_instructions:
                    labels[param - 1] |= CMD_REF_Goto
            mask >>= 1

    init_start = -1
    init_end = -1
    ipd_len = len(INITPLUGINDIR_OPCODES)
    for k in range(num_instructions):
        flg = labels[k]
        if not is_func(flg):
            continue
        if num_instructions - k < ipd_len:
            continue
        match = True
        for j in range(ipd_len):
            insn = header.instructions[k + j]
            cmd_id = header.opcode(insn)
            if cmd_id != INITPLUGINDIR_OPCODES[j]:
                match = False
                break
        if match:
            init_start = k
            init_end = k + ipd_len
            labels[k] |= CMD_REF_InitPluginDir
            break

    return LabelInfo(
        labels=labels,
        init_plugins_dir_start=init_start,
        init_plugins_dir_end=init_end,
    )


class NSDecompiler:
    """
    Produces NSIS script output from a parsed NSIS header, combining header info emission, page
    emission, and per-opcode command emission.
    """

    def __init__(self, header: NSHeader, archive: NSArchive | None = None):
        self.header = header
        self.archive = archive
        self.is_installer = True
        if archive is not None:
            self.is_installer = not bool(archive.flags & NSHeaderFlags.Uninstall)

    def decompile(self) -> str:
        header = self.header
        writer = NSScriptWriter()
        sections = header.sections
        label_info = build_labels(header, sections)
        emit_header_info(writer, header, self.archive, self.is_installer)
        emit_pages(writer, header, label_info.labels, self.is_installer)
        emit_commands(writer, header, label_info, sections, self.is_installer)
        return writer.getvalue()


class NSDisassembler:
    """
    Produces a flat opcode listing from an NSIS script header.
    """

    def __init__(self, header: NSHeader):
        self.header = header

    def disassemble(self) -> str:
        header = self.header
        script = io.StringIO()
        name_width = max(len(op.name) for op in Op)
        addr_width = len(F'{len(header.instructions):X}')
        for k, instruction in enumerate(header.instructions):
            if k > 0:
                script.write('\n')
            opcode = header.opcode(instruction)
            if opcode is Op.INVALID_OPCODE:
                name = F'Command{instruction.opcode}'
            else:
                name = opcode.name
            script.write(F'0x{k:0{addr_width}X}: {name:<{name_width}} ')
            for j, arg in enumerate(
                instruction.arguments[:OP_PARAMETER_COUNT.get(opcode, 6)]
            ):
                if j > 0:
                    script.write(', ')
                if arg > 20 and header._is_good_string(arg):
                    script.write(repr(header._read_string(arg)))
                elif arg < 0x100:
                    script.write(str(arg))
                elif arg < 0x10000:
                    script.write(F'0x{arg:04X}')
                else:
                    script.write(F'0x{arg:08X}')
        return script.getvalue()
