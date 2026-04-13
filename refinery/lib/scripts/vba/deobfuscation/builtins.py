"""
VBA built-in numeric constants.

Only numeric constants are included. String constants like vbCrLf or vbTab represent control
characters that cannot be expressed inside VBA string literals and are therefore not inlined.
"""
from __future__ import annotations

VBA_BUILTIN_CONSTANTS: dict[str, int] = {
    # miscellaneous
    'vbobjecterror': -2_147_221_504,
    # key codes: mouse / control
    'vbkeylbutton' : 0x01,
    'vbkeyrbutton' : 0x02,
    'vbkeycancel'  : 0x03,
    'vbkeymbutton' : 0x04,
    'vbkeyback'    : 0x08,
    'vbkeytab'     : 0x09,
    'vbkeyclear'   : 0x0C,
    'vbkeyreturn'  : 0x0D,
    'vbkeyshift'   : 0x10,
    'vbkeycontrol' : 0x11,
    'vbkeymenu'    : 0x12,
    'vbkeypause'   : 0x13,
    'vbkeycapital' : 0x14,
    'vbkeyescape'  : 0x1B,
    'vbkeyspace'   : 0x20,
    'vbkeypageup'  : 0x21,
    'vbkeypagedown': 0x22,
    'vbkeyend'     : 0x23,
    'vbkeyhome'    : 0x24,
    'vbkeyleft'    : 0x25,
    'vbkeyup'      : 0x26,
    'vbkeyright'   : 0x27,
    'vbkeydown'    : 0x28,
    'vbkeyselect'  : 0x29,
    'vbkeyprint'   : 0x2A,
    'vbkeyexecute' : 0x2B,
    'vbkeysnapshot': 0x2C,
    'vbkeyinsert'  : 0x2D,
    'vbkeydelete'  : 0x2E,
    'vbkeyhelp'    : 0x2F,
    # key codes: A-Z
    'vbkeya': 65, 'vbkeyb': 66, 'vbkeyc': 67, 'vbkeyd': 68, 'vbkeye': 69,
    'vbkeyf': 70, 'vbkeyg': 71, 'vbkeyh': 72, 'vbkeyi': 73, 'vbkeyj': 74,
    'vbkeyk': 75, 'vbkeyl': 76, 'vbkeym': 77, 'vbkeyn': 78, 'vbkeyo': 79,
    'vbkeyp': 80, 'vbkeyq': 81, 'vbkeyr': 82, 'vbkeys': 83, 'vbkeyt': 84,
    'vbkeyu': 85, 'vbkeyv': 86, 'vbkeyw': 87, 'vbkeyx': 88, 'vbkeyy': 89,
    'vbkeyz': 90,
    # key codes: 0-9
    'vbkey0': 48, 'vbkey1': 49, 'vbkey2': 50, 'vbkey3': 51, 'vbkey4': 52,
    'vbkey5': 53, 'vbkey6': 54, 'vbkey7': 55, 'vbkey8': 56, 'vbkey9': 57,
    # key codes: numpad
    'vbkeynumpad0'  : 0x60, 'vbkeynumpad1' : 0x61, 'vbkeynumpad2': 0x62,
    'vbkeynumpad3'  : 0x63, 'vbkeynumpad4' : 0x64, 'vbkeynumpad5': 0x65,
    'vbkeynumpad6'  : 0x66, 'vbkeynumpad7' : 0x67, 'vbkeynumpad8': 0x68,
    'vbkeynumpad9'  : 0x69,
    'vbkeymultiply' : 0x6A,
    'vbkeyadd'      : 0x6B,
    'vbkeyseparator': 0x6C,
    'vbkeysubtract' : 0x6D,
    'vbkeydecimal'  : 0x6E,
    'vbkeydivide'   : 0x6F,
    # key codes: function keys
    'vbkeyf1' : 0x70, 'vbkeyf2' : 0x71, 'vbkeyf3' : 0x72, 'vbkeyf4' : 0x73,
    'vbkeyf5' : 0x74, 'vbkeyf6' : 0x75, 'vbkeyf7' : 0x76, 'vbkeyf8' : 0x77,
    'vbkeyf9' : 0x78, 'vbkeyf10': 0x79, 'vbkeyf11': 0x7A, 'vbkeyf12': 0x7B,
    'vbkeyf13': 0x7C, 'vbkeyf14': 0x7D, 'vbkeyf15': 0x7E, 'vbkeyf16': 0x7F,
    # key codes: locks
    'vbkeynumlock': 0x90,
}
