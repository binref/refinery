"""
Library of regular expression patterns.
"""
from __future__ import annotations

import enum
import functools
import re

from typing import TYPE_CHECKING, Callable, Iterator, overload

from refinery.lib.patterns.tlds import tlds
from refinery.lib.tools import normalize_to_display, normalize_to_identifier
from refinery.lib.types import buf

if TYPE_CHECKING:
    from re import Match

    class PatternMethods:
        @overload
        def split(self, string: buf, maxsplit: int = 0) -> list[bytes]:
            ...

        @overload
        def split(self, string: str, maxsplit: int = 0) -> list[str]:
            ...

        def split(self, string, maxsplit=0) -> list:
            ...

        @overload
        def fullmatch(self, string: buf, pos: int = 0, endpos: int | None = None) -> Match[bytes]:
            ...

        @overload
        def fullmatch(self, string: str, pos: int = 0, endpos: int | None = None) -> Match[str]:
            ...

        def fullmatch(self, string, pos=0, endpos=None) -> Match:
            ...

        @overload
        def search(self, string: buf, pos: int = 0, endpos: int | None = None) -> Match[bytes]:
            ...

        @overload
        def search(self, string: str, pos: int = 0, endpos: int | None = None) -> Match[str]:
            ...

        def search(self, string, pos=0, endpos=None) -> Match:
            ...

        @overload
        def sub(self, repl: buf | Callable[[Match[bytes]], buf], string: buf, count: int = 0) -> bytes:
            ...

        @overload
        def sub(self, repl: str | Callable[[Match[str]], str], string: str, count: int = 0) -> str:
            ...

        def sub(self, repl, string, count=0) -> str | bytes:
            ...

        @overload
        def finditer(self, string: buf, pos: int = 0, endpos: int | None = None) -> Iterator[Match[bytes]]:
            ...

        @overload
        def finditer(self, string: str, pos: int = 0, endpos: int | None = None) -> Iterator[Match[str]]:
            ...

        def finditer(self, string, pos=0, endpos=None) -> Iterator[Match]:
            ...
else:
    PatternMethods = object


def _sized_suffix(lower: int, upper: int):
    if lower <= 0:
        if upper <= 0:
            return '*'
        else:
            return F'{{1,{upper}}}'
    elif upper <= 0:
        if lower == 1:
            return '+'
        else:
            return F'{{{lower},}}'
    else:
        return F'{{{lower},{upper}}}'


class pattern(PatternMethods):
    """
    A wrapper for regular expression pattern objects created from re.compile,
    allowing combination of several patterns into one via overloaded
    operators.
    """
    str_pattern: str
    bin_pattern: bytes

    def __init__(self, pattern: str, flags: int = 0):
        self.str_pattern = pattern
        self.bin_pattern = pattern.encode('ascii')
        self.flags = flags

    def __bytes__(self):
        return self.bin_pattern

    @functools.cached_property
    def bin(self):
        return re.compile(B'(%s)' % self.bin_pattern, flags=self.flags)

    @functools.cached_property
    def str(self):
        return re.compile(self.str_pattern, flags=self.flags)

    def __hash__(self):
        return hash((self.str_pattern, self.flags))

    def __eq__(self, other):
        if isinstance(other, str):
            return self.str_pattern == other and self.flags == 0
        if isinstance(other, pattern):
            return self.str_pattern == other.str_pattern and self.flags == other.flags
        return False

    def __str__(self):
        return self.str_pattern

    def __getattr__(self, verb):
        if not hasattr(re.Pattern, verb):
            raise AttributeError(verb)
        bin_attr = getattr(self.bin, verb)
        if not callable(bin_attr):
            return bin_attr
        str_attr = getattr(self.str, verb)

        def wrapper(*args, **kwargs):
            for argument in args:
                if isinstance(argument, str):
                    return str_attr(*args, **kwargs)
            else:
                return bin_attr(*args, **kwargs)

        functools.update_wrapper(wrapper, bin_attr)
        return wrapper


class alphabet(pattern):
    """
    A pattern object representing strings of letters from a given alphabet, with
    an optional prefix and suffix.
    """
    def __init__(
        self,
        repeat: str,
        prefix: str = '',
        suffix: str = '',
        lower: int = 1,
        upper: int = 0,
        prefix_min: int = 0,
        prefix_max: int = 0,
        suffix_min: int = 0,
        suffix_max: int = 0,
        token_size: int = 1,
        flags: int = 0,
        **kwargs
    ):
        self.repeat = repeat
        self.prefix = prefix
        self.suffix = suffix
        self.suffix_min = suffix_min
        self.suffix_max = suffix_max
        self.prefix_min = prefix_min
        self.prefix_max = prefix_max
        self.token_size = token_size
        lower = lower - suffix_max - prefix_max
        upper = upper - suffix_min - prefix_min
        if token_size > 1:
            lower, _r = divmod(lower, token_size)
            if _r and lower == 0:
                lower = _r
            upper, _r = divmod(upper, token_size)
            if _r and upper >= 0:
                upper += 1
        self.lower = lower
        self.upper = upper
        count = _sized_suffix(lower, upper)
        pattern.__init__(self,
            R'{b}(?:{r}){c}{a}'.format(
                r=repeat,
                b=prefix,
                c=count,
                a=suffix
            ),
            flags,
            **kwargs
        )


class tokenize(pattern):
    """
    A pattern representing a sequence of tokens matching the `token` pattern, separated
    by sequences matching the pattern `sep`. The optional parameter `bound` is required
    before and after each token, its default value is the regular expression zero length
    match for a word boundary.
    """
    def __init__(self, token, sep, bound='\\b', unique_sep=False, sep_ignores_whitespace=True, **kwargs):
        if unique_sep:
            if sep_ignores_whitespace:
                p = (
                    R'(?:{b}{t}{b}\s{{0,50}}(?P<__sep__>{s})\s{{0,50}})'
                    R'(?:(?:{b}{t}{b}\s{{0,50}}(?P=__sep__)\s{{0,50}})+{b}{t}{b}|{b}{t}{b})'
                )
            else:
                p = R'(?:{b}{t}{b}(?P<__sep__>{s}))(?:(?:{b}{t}{b}(?P=__sep__))+{b}{t}{b}|{b}{t}{b})'
        else:
            p = R'(?:{b}{t}{b}{s})+(?:{b}{t}{b})'
        pattern.__init__(self, p.format(s=sep, b=bound, t=token), **kwargs)


class _PatternEnum(enum.Enum):
    @classmethod
    def get(cls, name, default=None):
        try:
            return cls[name]
        except KeyError:
            return default

    def __str__(self):
        return str(self.value)

    def __bytes__(self):
        return bytes(self.value)

    def __repr__(self):
        return F'<pattern {self.name}: {self.value}>'

    def __getattr__(self, name):
        if name in dir(re.Pattern):
            return getattr(self.value, name)
        raise AttributeError

    @property
    def display(self):
        return normalize_to_display(self.name)


_TLDS = R'(?i:{possible_tld})(?!(?:{dealbreakers}))'.format(
    possible_tld='|'.join(tlds),
    dealbreakers='|'.join([
        R'[a-z]',
        R'[A-Za-z]{3}',
        R'\.\w\w',
        R'\([\'"\w)]'
    ])
)

# see https://tools.ietf.org/html/rfc2181#section-11
_format_serrated_domain = (
    R'(?:\w[a-zA-Z0-9\-\_]{{0,62}}?\.){repeat}'
    R'\w[a-zA-Z0-9\-\_]{{0,62}}\.{tlds}'
)
_format_defanged_domain = (
    R'(?:\w[a-zA-Z0-9\-\_]{{0,62}}?(?:\[\.\]|\.)){repeat}'
    R'\w[a-zA-Z0-9\-\_]{{0,62}}(?:\[\.\]|\.){tlds}'
)

_pattern_utf8 = R'(?:[\x00-\x7F]|[\xC0-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF7][\x80-\xBF]{3})+'
_pattern_b92 = R'~|(?:[!-_a-}]{2})+[!-_a-}]?'

_pattern_serrated_domain = _format_serrated_domain.format(repeat='{0,20}', tlds=_TLDS)
_pattern_defanged_domain = _format_defanged_domain.format(repeat='{0,20}', tlds=_TLDS)

_pattern_subdomain = _format_serrated_domain.format(repeat='{1,20}', tlds=_TLDS)

_pattern_octet = R'(?:1\d\d|2[0-4]\d|25[0-5]|[1-9]?\d)'
_pattern_serrated_ipv4 = R'(?<![0-9])(?:{o}\.){{3}}{o}(?![0-9])'.format(o=_pattern_octet)
_pattern_defanged_ipv4 = R'(?:{o}{d}){{3}}{o}'.format(o=_pattern_octet, d=R'(?:\[\.\]|\.)')

# Taken from: https://stackoverflow.com/a/17871737/9130824
_pattern_ipv6 = (
    R'('
    R'([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'          # 1:2:3:4:5:6:7:8
    R'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'       # 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
    R'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'  # 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
    R'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'  # 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
    R'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'  # 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
    R'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'  # 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
    R'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'         # 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
    R'([0-9a-fA-F]{1,4}:){1,7}:|'                         # 1::                              1:2:3:4:5:6:7::
    R':((:[0-9a-fA-F]{1,4}){1,7}|:)|'                     # ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::
    R'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'     # fe80::7:8%eth0   fe80::7:8%1     (link-local IPv6 addresses with zone index)
    R'::(ffff(:0{1,4}){0,1}:){0,1}'                       #
    R'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'  #
    R'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'          # ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255
    R'([0-9a-fA-F]{1,4}:){1,4}:'                          # (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
    R'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'  #
    R'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'           # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33
    R')'                                                  # (IPv4-Embedded IPv6 Address)
)

_pattern_serrated_socket = f'(?:{_pattern_serrated_ipv4}|{_pattern_serrated_domain})(?::\\d{{2,5}})'
_pattern_defanged_socket = f'(?:{_pattern_defanged_ipv4}|{_pattern_defanged_domain})(?::\\d{{2,5}})'

_pattern_serrated_hostname = _pattern_serrated_socket + '?'
_pattern_defanged_hostname = _pattern_defanged_socket + '?'


def _sized_pattern_integer(lower: int = 0, upper: int = 0):
    x = _sized_suffix(max(1, lower - 3), upper - 2)
    o = _sized_suffix(max(0, lower - 3), upper - 2)
    d = _sized_suffix(max(0, lower - 2), upper - 1)
    return (
        F'[-+]?(?:0[bB][01]{x}|0[xX][0-9a-fA-F]{x}|0[1-7][0-7]{o}|[1-9][0-9]{d}|0)'
        R'(?=[uU]?[iI]\d{1,2}|[LlHh]|[^a-zA-Z0-9]|$)'
    )


_pattern_integer = _sized_pattern_integer()
_pattern_float = R'[-+]?[0-9]*\.?[0-9]+(?:[eE][-+]?[0-9]+)?'
_pattern_number = F'(?:(?:{_pattern_integer})|(?:{_pattern_float}))'
_pattern_number = (
    '[-+]?(?:0[bB][01]+|0[xX][0-9a-fA-F]+|0[1-7][0-7]*|(?:[1-9][0-9]*|0)(?P<__fp1>\\.[0-9]*)?|(?P<__fp2>\\.[0-9]+))'
    '(?(__fp1)(?:[eE][-+]?[0-9]+)?|(?(__fp2)(?:[eE][-+]?[0-9]+)?|(?=[uU]?[iI]\\d{1,2}|[LlHh]|[^a-zA-Z0-9]|$)))'
)


_pattern_date_elements = {
    'A': '(?:{})'.format('|'.join([
        '[sS]un(?:day)?',
        '[mM]on(?:day)?',
        '[tT]ue(?:sday)?',
        '[wW]ed(?:nesday)?',
        '[tT]hu(?:rsday)?',
        '[fF]ri(?:day)?',
        '[sS]at(?:urday)?',
    ])),
    'B': '(?:{})'.format('|'.join([
        '[jJ]an(?:uary)?',
        '[fF]eb(?:ruary)?',
        '[mM]ar(?:ch)?',
        '[aA]pr(?:il)?',
        '[mM]ay',
        '[jJ]un(?:e)?',
        '[jJ]ul(?:y)?',
        '[aA]ug(?:ust)?',
        '[sS]ep(?:tember)?',
        '[oO]ct(?:ober)?',
        '[nN]ov(?:ember)?',
        '[dD]ec(?:ember)?',
    ])),
    'D': '(?:[23]?(?:1st|2nd|3rd|[4-9]th)|20th|30th)',
    'd': '(?:0?[1-9]|[12][0-9]|3[01])',
    'm': '(?:0[1-9]|1[012])',
    'I': '(?:0[1-9]|1[0-2])',
    'p': '(?:[ap]m|[AP]M)',
    'H': '(?:[01][0-9]|2[0-3])',
    'M': '(?:[0-5][0-9])',
    'S': '(?:[0-5][0-9])',
    'z': '(?:[-+](?:[0-9]{2}){1,3}(?:\\.[0-9]{6})?)',
    'y': '(?:[0-9]{2})',
    'Y': '(?:[0-9]{4})',
    'c': '(?:[,;]|\\s|[,;]\\s)',
    'gap': '\\s{1,3}'
}

_pattern_time = r'(?:{H}:{M}(?::{S})?|{I}:{M}(?::{S})?{c}?\(?{p}\)?)'.format_map(_pattern_date_elements)
_pattern_date_elements['T'] = _pattern_time

_pattern_date_list = [
    R'{A}{c}(?:{d}|{D}){gap}{B}{c}{Y}(?:\s{T})?',
    R'{B}\s(?:{d}|{D}){c}{Y}(?:\s{T})?',
    R'{Y}[-:]{m}[-:]{d}(?:[T\x20]{H}:{M}(?::{S})?(?:[Z.][0-9]{{6}})?{z}?)',
    R'{m}/{d}/{Y}(?:{c}{T})?',
    R'{A}{c}{B}{c}(?:{d}|{D}){c}{T}(?:\s\(?UTC\)?)?\s{Y}',
]

_pattern_date = '|'.join(
    _p.format_map(_pattern_date_elements) for _p in _pattern_date_list)


def _sized_pattern_string(lower: int = 0, upper: int = 0):
    ml = _sized_suffix((lower - 6) // 1, (upper - 6))
    sl = _sized_suffix((lower - 2) // 2, (upper - 2))
    str_dq = FR'"(?:[^"\\\r\n]|\\[^\r\n]){sl}"'
    str_sq = FR"'(?:[^'\\\r\n]|\\[^\r\n]){sl}'"
    str_js = FR'`(?:[^`\\]|\\.){sl}`'
    str_mul_dq = FR'"""(?:.(?!""")){ml}"""'
    str_mul_sq = FR"'''(?:.(?!''')){ml}'''"
    return '(?:{})'.format('|'.join((
        str_dq,
        str_sq,
        str_js,
        str_mul_dq,
        str_mul_sq,
    )))


def _sized_pattern_cmdstr(lower: int = 0, upper: int = 0):
    n = _sized_suffix((lower - 2) // 2, upper - 2)
    return FR'''(?:"(?:""|[^"]){n}"|'(?:''|[^']){n}')'''


_pattern_cmdstr = _sized_pattern_cmdstr()
_pattern_ps1str = R'''(?:(?:@"\s*?[\r\n].*?[\r\n]"@)|(?:@'\s*?[\r\n].*?[\r\n]'@)|(?:"(?:`.|""|[^"\n])*")|(?:'(?:''|[^'\n])*'))'''
_pattern_vbastr = R'''"(?:""|[^"])*"'''
_pattern_vbaint = R'(?:&[bB][01]+|&[hH][0-9a-fA-F]+|&[oO][0-7]*|[-+]?(?:[1-9][0-9]*|0))(?=\b|$)'
_pattern_string = _sized_pattern_string()

_pattern_urlenc = R'''(?:%[0-9a-fA-F]{2}|[0-9a-zA-Z\-\._~\?!$&=])+'''
_pattern_urlhex = R'''(?:%[0-9a-fA-F]{2})+'''

_pattern_json = (
    R'''\s{0,20}[\[\{](?:"(?:[^"\\\r\n]|\\[^\r\n])*'''
    R'''"(?:\s*[:,])?|(?:none|true|false|%s|%s|\]|\})(?:\s*,)?|[,\]\}\[\{\s]+)*[\]\}]'''
) % (_pattern_integer, _pattern_float)

_pattern_wshenc = R'''#@~\^[ -~]{6}==(?:.*?)[ -~]{6}==\^#~@'''

_part_url_credentials = (
    R'(?:([^"\'\s\x00-\x20\x7E-\xFF]{1,256})?'
    R'(?::([^"\'\s\x00-\x20\x7E-\xFF]{0,256})?)?@)?'
)
_prefix_serrated_url = R'(([a-zA-Z]{2,20}:)?\/\/)' + _part_url_credentials
_prefix_defanged_url = R'(([a-zA-Z]{2,20}(?:\[:\]|:))?\/\/)' + _part_url_credentials
_suffix_combined_url = R'([/?#](?:[#/=:;$!?&.,\w\+\%\-\*\'~@()](?![a-zA-Z]{2,20}://))*)?'

_pattern_serrated_url = F'{_prefix_serrated_url}({_pattern_serrated_hostname}){_suffix_combined_url}'
_pattern_defanged_url = F'{_prefix_defanged_url}({_pattern_defanged_hostname}){_suffix_combined_url}'

_pattern_email = fR'(?:[a-zA-Z0-9_\.\+\-]{{1,256}}?)@(?:{_pattern_serrated_domain})'
_pattern_guid = R'(?:\b|\{)[0-9A-Fa-f]{8}(?:\-[0-9A-Fa-f]{4}){3}\-[0-9A-Fa-f]{12}(?:\}|\b)'

_pattern_pathpart_nospace = R'[-\w+,.;@\]\[{}^`~]+'  # R'[^/\\:"<>|\s\x7E-\xFF\x00-\x1F\xAD]+'
_pattern_win_path_element = R'(?:{n} ){{0,4}}{n}'.format(n=_pattern_pathpart_nospace)
_pattern_nix_path_element = R'(?:{n} ){{0,1}}{n}'.format(n=_pattern_pathpart_nospace)
_pattern_win_env_variable = R'%[a-zA-Z][a-zA-Z0-9_\-\(\)]*%'

_pattern_win_path_template_abs = R'(?:{s})(?P<__pathsep__>[\\\/])(?:{p}(?P=__pathsep__))*{p}(?:(?P=__pathsep__)|\b)'
_pattern_win_path_template_rel = R'(?:{p}|)\\(?:{p}\\)*{p}(?:\\|\b)'
_pattern_win_path_template = F'(?:{_pattern_win_path_template_abs}|{_pattern_win_path_template_rel})'

_pattern_win_root = '|'.join([
    _pattern_win_env_variable,    # environment variable
    R'[A-Za-z]:',                 # drive letter with colon
    R'\\\\[a-zA-Z0-9_.$@]{1,50}', # UNC path
    R'HK[A-Z_]{1,30}',            # registry root key
])
_pattern_win_path = _pattern_win_path_template.format(
    s=_pattern_win_root,
    p=_pattern_win_path_element
)
_pattern_win_path_terse = _pattern_win_path_template.format(
    s=_pattern_win_root,
    p=_pattern_pathpart_nospace
)

_pattern_nix_path_template = R'(?:/(?:{n}/)+|(?:{n}/){{2,}}){n}'
_pattern_nix_path = _pattern_nix_path_template.format(
    n=_pattern_nix_path_element)
_pattern_nix_path_terse = _pattern_nix_path_template.format(
    n=_pattern_pathpart_nospace)

_pattern_any_path = R'(?:{nix})|(?:{win})'.format(
    nix=_pattern_nix_path,
    win=_pattern_win_path,
)
_pattern_any_path_terse = R'(?:{nix})|(?:{win})'.format(
    nix=_pattern_nix_path_terse,
    win=_pattern_win_path_terse,
)

_pattern_uuencode = R'begin\s+\d{3}\s+[\x20!-~]+?\r?\n(?:M[\x20-\x60]{60}\r?\n)*(?:.*?\r?\n)?`\r?\nend'


def make_hexline_pattern(blocksize: int) -> str:
    return R'(?:{s}+\s+)?\s*({h})(?:[ \t]+(.+?))?'.format(
        h=tokenize(
            RF'(?:0[xX])?[0-9a-fA-F]{{{2 * blocksize}}}h?',
            sep=R'[- \t\/:;,\\]{1,3}'
        ).str_pattern,
        s=R'[-\w:;,#\.\$\?!\/\\=\(\)\[\]\{\}]'
    )


_pattern_hexline = make_hexline_pattern(1)

_pattern_pem = (
    R'-----BEGIN(?:\s[A-Z0-9]+)+-----{n}'
    R'(?:{b}{{40,100}}{n})*{b}{{1,100}}={{0,3}}{n}'
    R'-----END(?:\s[A-Z0-9]+)+-----'
).format(n=R'(?:\r\n|\n\r|\n)', b=R'[0-9a-zA-Z\+\/]')


AnsiColor = pattern(R'\x1b\[(?:22|[34]\d|(?:9|10)[0-8]|[0-2])(?:;\d+)*m')


class checks(_PatternEnum):
    json = pattern(_pattern_json)
    "Data that consists of JSON-like tokens; cannot detect actual JSON data."


class formats(_PatternEnum):
    """
    An enumeration of patterns for certain formats.
    """
    int = pattern(_pattern_integer)
    "Integer expressions"
    flt = pattern(_pattern_float)
    "Floating point number expressions"
    num = pattern(_pattern_number)
    "Either an integer or a float"
    str = pattern(_pattern_string)
    "C syntax string literal"
    cmdstr = pattern(_pattern_cmdstr)
    "Windows command line escaped string literal"
    ps1str = pattern(_pattern_ps1str, flags=re.DOTALL)
    "PowerShell escaped string literal"
    vbastr = pattern(_pattern_vbastr)
    "VBS/VBA string literal"
    vbaint = pattern(_pattern_vbaint)
    "VBS/VBA integer literal"
    printable = alphabet(R'[\s!-~]')
    "Any sequence of printable characters"
    urlquote = pattern(_pattern_urlenc)
    "Any sequence of url-encoded characters, default char set"
    urlhex = pattern(_pattern_urlhex)
    "A hex-encoded buffer using URL escape sequences"
    intarray = tokenize(_pattern_integer, sep=R'[;,]', bound='', unique_sep=True)
    "Sequences of integers, separated by commas or semicolons"
    strarray = tokenize(_pattern_string, sep=R'[;,]', bound='', unique_sep=True)
    "Sequences of strings, separated by commas or semicolons"
    numarray = tokenize(_pattern_number, sep=R'[;,]', bound='', unique_sep=True)
    "Sequences of numbers, separated by commas or semicolons"
    hexarray = tokenize(R'[0-9A-Fa-f]{2}', sep=R'[;,]', bound='', unique_sep=True)
    "Arrays of hexadecimal strings, separated by commas or semicolons"
    word = alphabet(R'\\w')
    "Sequences of word characters"
    letters = alphabet(R'[a-zA-Z]')
    "Sequences of alphabetic characters"
    wshenc = pattern(_pattern_wshenc)
    "Encoded Windows Scripting Host Scripts (JS/VBS)"
    alnum = alphabet(R'[a-zA-Z0-9]')
    "Sequences of alpha-numeric characters"
    b32 = pattern('[A-Z2-7]+|[a-z2-7+]')
    "Base32 encoded strings"
    b58 = alphabet(R'(?:[1-9A-HJ-NP-Za-km-z]')
    "Base58 encoded strings"
    b62 = alphabet(R'(?:[0-9A-Za-z]')
    "Base62 encoded strings"
    b64 = alphabet(R'(?:[0-9a-zA-Z\+/]{4})', suffix=R'(?:(?:[0-9a-zA-Z\+/]{2,3})={0,3})?', suffix_max=6, token_size=4)
    "Base64 encoded strings"
    b85 = alphabet(R'[-!+*()#-&^-~0-9;-Z]')
    "Base85 encoded strings"
    a85 = alphabet(R'[!-u]')
    "Ascii85 encoded strings"
    z85 = alphabet(R'[-0-9a-zA-Z.:+=^!/*?&<>()\[\]{}@%$#]')
    "Z85 encoded strings"
    b92 = pattern(_pattern_b92)
    "Base92 encoded strings"
    b64u = alphabet(R'[-\w]{4}', suffix=R'(?:[-\w]{2,3}={0,3})?', suffix_max=6)
    "Base64 encoded strings using URL-safe alphabet"
    hex = alphabet(R'[0-9a-fA-F]{2}', token_size=2)
    "Hexadecimal strings"
    b16 = alphabet(R'[0-9A-F]{2}', token_size=2)
    "Uppercase hexadecimal strings"
    b16s = tokenize(R'[0-9a-fA-F]+', R'\s*', bound='')
    "Hexadecimal strings"
    b64s = alphabet(R'[-\s\w\+/]', suffix=R'(?:={0,3})?', suffix_max=3)
    "Base64 encoded strings, separated by whitespace"
    b85s = alphabet(R'[-!+*()#-&^-~0-9;-Z\s]')
    "Base85 encoded string, separated by whitespace"
    a85s = alphabet(R'[!-u\s]')
    "Ascii85 encoded string, separated by whitespace"
    z85s = alphabet(R'[-\s0-9a-zA-Z.:+=^!/*?&<>()\[\]{}@%$#]')
    "Z85 encoded string, separated by whitespace"
    utf8 = pattern(_pattern_utf8)
    "A sequence of bytes that can be decoded as UTF8."
    hexdump = tokenize(_pattern_hexline, bound='', sep=R'\s*\n')
    """
    This pattern matches a typical hexdump output where hexadecimally encoded
    bytes are followed by a string which contains dots or printable characters
    from the dump. For example:

        46 4F 4F 0A 42 41 52 0A  FOO.BAR.
        F0 0B AA BA F0 0B        ......
    """
    uuenc = pattern(_pattern_uuencode)
    "UUEncoded data"

    # shortcuts
    float = flt
    integer = int
    number = num
    string = str

    @classmethod
    def from_dashname(cls, key: str):
        if key.startswith('[') and key.endswith(']'):
            key = key[1:-1] + 'array'
        return getattr(cls, normalize_to_identifier(key))


class wallets(_PatternEnum):
    # https://gist.github.com/etherx-dev/76559d9e6d916917a960e33ceea91481
    ADA = pattern("addr1[a-z0-9]+")
    ATOM = pattern("cosmos[-\\w\\.]{10,}")
    BCH = pattern("(bitcoincash:)?(q|p)[a-z0-9]{41}|(BITCOINCASH:)?(Q|P)[A-Z0-9]{41}")
    BTC = pattern("(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,39})")
    BTCP = pattern("5[HJK][1-9A-Za-z][^A-HJ-NP-Za-km-z0-9]{48}")
    DASH = pattern("X[1-9A-HJ-NP-Za-km-z]{33}")
    DOGE = pattern("D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}")
    DOT = pattern("1[0-9a-zA-Z]{47}")
    ETH = pattern("0x[a-fA-F0-9]{40}")
    IOTA = pattern("iota[a-z0-9]{10,}")
    LSK = pattern("[0-9]{19}L")
    LTC = pattern("[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}")
    NEO = pattern("N[0-9a-zA-Z]{33}")
    ONE = pattern("(?:bnb|one)1[a-z0-9]{38}")
    ONT = pattern("A[0-9a-zA-Z]{33}")
    RONIN = pattern("ronin:[a-fA-F0-9]{40}")
    TERRA = pattern("terra1[a-z0-9]{38}")
    XEM = pattern("N[A-Za-z0-9]{4,7}-[A-Za-z0-9]{4,7}-[A-Za-z0-9]{4,7}-[A-Za-z0-9]{4,7}-[A-Za-z0-9]{4,7}-[A-Za-z0-9]{4,7}-[A-Za-z0-9]{4,7}")
    XLM = pattern("G[A-D][A-Z2-7]{54}")
    XMR = pattern("4[0-9AB][1-9A-HJ-NP-Za-km-z]{90,120}")
    XRP = pattern("r[0-9a-zA-Z]{24,34}")


class indicators(_PatternEnum):
    """
    An enumeration of patterns for indicators.
    """
    domain = pattern(_pattern_serrated_domain)
    "Domain names"
    email = pattern(_pattern_email)
    "Email addresses"
    guid = pattern(_pattern_guid)
    "Windows GUID strings"
    date = pattern(_pattern_date)
    "A date or timestamp value in a common format"
    ipv4 = pattern(_pattern_serrated_ipv4)
    "String representations of IPv4 addresses"
    ipv6 = pattern(_pattern_ipv6)
    "String representations of IPv6 addresses"
    md5 = alphabet('[0-9A-Fa-f]', lower=32, upper=32)
    "Hexadecimal strings of length 32"
    sha1 = alphabet('[0-9A-Fa-f]', lower=40, upper=40)
    "Hexadecimal strings of length 40"
    sha256 = alphabet('[0-9A-Fa-f]', lower=64, upper=64)
    "Hexadecimal strings of length 64"
    hostname = pattern(_pattern_serrated_hostname)
    "Any domain name or IPv4 address, optionally followed by a colon and a port number."
    socket = pattern(_pattern_serrated_socket)
    "Any domain name or IPv4 address followed by a colon and a (port) number"
    subdomain = pattern(_pattern_subdomain)
    "A domain which contains at least three parts, including the top level"
    url = pattern(_pattern_serrated_url)
    "Uniform resource locator addresses"
    pem = pattern(_pattern_pem)
    "A pattern matching PEM encoded cryptographic parameters"
    path = pattern(_pattern_any_path)
    "Windows and Linux path names"
    winpath = pattern(_pattern_win_path)
    "Windows path names"
    nixpath = pattern(_pattern_nix_path)
    "Posix path names"
    evar = pattern(_pattern_win_env_variable)
    "Windows environment variables, i.e. something like `%APPDATA%`"

    @classmethod
    def from_dashname(cls, key):
        return getattr(cls, normalize_to_identifier(key))


class defanged(_PatternEnum):
    """
    An enumeration of patterns for defanged indicators. Used only by the reverse
    operation of `refinery.defang`.
    """
    hostname = pattern(_pattern_defanged_hostname)
    "A defanged `refinery.lib.patterns.indicators.hostname`."
    url = pattern(_pattern_defanged_url)
    "A defanged `refinery.lib.patterns.indicators.url`."


def pattern_with_size_limits(p: pattern, lower: int | None, upper: int | None) -> pattern:
    """
    This attempts to construct a pattern from a given format that includes the given lower and
    upper bounds on total match size. This is not always possible.
    """
    lower = max(0, lower or 0)
    upper = max(0, upper or 0)
    handlers = {
        formats.int.value     : _sized_pattern_integer,
        formats.cmdstr.value  : _sized_pattern_cmdstr,
        formats.string.value  : _sized_pattern_string,
    }
    if isinstance(p, alphabet):
        return alphabet(
            p.repeat,
            p.prefix,
            p.suffix,
            lower,
            upper,
            p.prefix_min,
            p.prefix_max,
            p.suffix_min,
            p.suffix_max,
            p.token_size,
            flags=p.flags,
        )
    elif h := handlers.get(p):
        return pattern(h(lower, upper), formats.int.value.flags)
    return p
