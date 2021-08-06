#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Library of regular expression patterns.
"""
import enum
import functools
import re

from typing import Optional

from .tlds import tlds


class pattern:
    """
    A wrapper for regular expression pattern objects created from re.compile,
    allowing combination of several patterns into one via overloaded
    operators.
    """
    str_pattern: str
    bin_pattern: Optional[bytes]
    bin_compiled: re.Pattern
    str_compiled: re.Pattern

    def __init__(self, pattern: str):
        self.str_pattern = pattern
        self.bin_pattern = None
        self.bin_compiled = re.compile(B'(%s)' % self)
        self.str_compiled = re.compile(self.str_pattern)

    def __bytes__(self):
        bin_pattern = self.bin_pattern
        if bin_pattern is None:
            self.bin_pattern = bin_pattern = self.str_pattern.encode('ascii')
        return bin_pattern

    def __str__(self):
        return self.str_pattern

    def __getattr__(self, verb):
        bin_attr = getattr(self.bin_compiled, verb)
        if not callable(bin_attr):
            return bin_attr
        str_attr = getattr(self.str_compiled, verb)

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
    an optional prefix and postfix.
    """
    def __init__(self, repeat, prefix='', postfix='', at_least=1, at_most=None, **kwargs):
        if not at_most:
            count = '+' if at_least <= 1 else '{{{},}}'.format(at_least)
        else:
            count = '{{{},{}}}(?!{})'.format(at_least, at_most, repeat)

        pattern.__init__(self,
            R'{b}(?:{r}){c}{a}'.format(
                r=repeat,
                b=prefix,
                c=count,
                a=postfix
            ),
            **kwargs
        )


class tokenize(pattern):
    """
    A pattern representing a sequence of tokens matching the `token` pattern, separated
    by sequences matching the pattern `sep`. The optional parameter `bound` is required
    before and after each token, its default value is the regular expression zero length
    match for a word boundary.
    """
    def __init__(self, token, sep, bound='\\b', **kwargs):
        pattern.__init__(
            self,
            R'(?:{b}{t}{b}{s})+(?:{b}{t}{b})?'.format(
                s=sep, b=bound, t=token),
            **kwargs
        )


class PatternEnum(enum.Enum):
    @classmethod
    def get(cls, name, default):
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
    def dashname(self):
        return self.name.replace('_', '-')


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
    R'(?:[a-zA-Z0-9\_][a-zA-Z0-9\-\_]{{0,62}}?\.){repeat}'
    R'[a-zA-Z0-9\_][a-zA-Z0-9\-\_]{{1,62}}\.{tlds}'
)
_format_defanged_domain = (
    R'(?:[a-zA-Z0-9\_][a-zA-Z0-9\-\_]{{0,62}}?(?:\[\.\]|\.)){repeat}'
    R'[a-zA-Z0-9\_][a-zA-Z0-9\-\_]{{1,62}}(?:\[\.\]|\.){tlds}'
)

_pattern_utf8 = R'(?:[\x00-\x7F]|[\xC0-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF7][\x80-\xBF]{3})+'

_pattern_serrated_domain = _format_serrated_domain.format(repeat='{0,20}', tlds=_TLDS)
_pattern_defanged_domain = _format_defanged_domain.format(repeat='{0,20}', tlds=_TLDS)

_pattern_subdomain = _format_serrated_domain.format(repeat='{1,20}', tlds=_TLDS)

_pattern_octet = R'(?:1\d\d|2[0-4]\d|25[0-5]|[1-9]?\d)'
_pattern_serrated_ipv4 = R'(?<!\.|\d)(?:{o}\.){{3}}{o}(?![\d\.])'.format(o=_pattern_octet)
_pattern_defanged_ipv4 = R'(?:{o}{d}){{3}}{o}'.format(o=_pattern_octet, d=R'(?:\[\.\]|\.)')

# Taken from: https://stackoverflow.com/a/17871737/9130824
_pattern_ipv6 = (
    R'('
    R'([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'          # 1:2:3:4:5:6:7:8
    R'([0-9a-fA-F]{1,4}:){1,7}:|'                         # 1::                              1:2:3:4:5:6:7::
    R'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'         # 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
    R'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'  # 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
    R'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'  # 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
    R'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'  # 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
    R'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'  # 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
    R'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'       # 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
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

_pattern_serrated_socket = '(?:{ip}|{d})(?::\\d{{2,5}})'.format(ip=_pattern_serrated_ipv4, d=_pattern_serrated_domain)
_pattern_defanged_socket = '(?:{ip}|{d})(?::\\d{{2,5}})'.format(ip=_pattern_defanged_ipv4, d=_pattern_defanged_domain)

_pattern_serrated_hostname = _pattern_serrated_socket + '?'
_pattern_defanged_hostname = _pattern_defanged_socket + '?'

_pattern_integer = '[-+]?(?:0[bB][01]+|0[xX][0-9a-fA-F]+|0[1-7][0-7]*|[1-9][0-9]*|0)(?=[uU]?[iI]\\d{1,2}|[LlHh]|[^a-zA-Z0-9]|$)'
_pattern_float = R'[-+]?[0-9]*\.?[0-9]+(?:[eE][-+]?[0-9]+)?'
_pattern_cmdstr = R'''(?:"(?:""|[^"])*"|'(?:''|[^'])*')'''
_pattern_ps1str = R'''(?:@"\s*?[\r\n].*?[\r\n]"@|@'\s*?[\r\n].*?[\r\n]'@|"(?:`.|""|[^"])*"|'(?:''|[^'])*')'''

_pattern_string = R'''(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')'''
_pattern_urlenc_coarse = R'''(?:%[0-9a-fA-F]{2}|[0-9a-zA-Z\-\._~\?!$&=:\/#\[\]@'\(\)\*\+,;])+'''
_pattern_urlenc_narrow = R'''(?:%[0-9a-fA-F]{2}|[0-9a-zA-Z\-\._~\?!$&=])+'''
_pattern_urlenc_hex = R'''(?:%[0-9a-fA-F]{2})+'''

_pattern_vbe = R'''#@~\^[ -~]{6}==(?:.*?)[ -~]{6}==\^#~@'''

_part_url_credentials = (
    R'(?:(?P<url_username>[^"\'\s\x00-\x20\x7E-\xFF]{1,256})?'
    R'(?::(?P<url_password>[^"\'\s\x00-\x20\x7E-\xFF]{0,256})?)?@)?'
)
_prefix_serrated_url = R'(?P<url_scheme>(?P<url_protocol>[a-zA-Z]{2,20}:)?\/\/)' + _part_url_credentials
_prefix_defanged_url = R'(?P<url_scheme>(?P<url_protocol>[a-zA-Z]{2,20})?(?:\[:\]|:)\/\/)' + _part_url_credentials
_suffix_combined_url = R'(?P<url_path>[/?#](?:[#/=:;$!?&.,\w\+\%\-\*\'~@()](?![a-zA-Z]{2,20}://))*)?'

_pattern_serrated_url = F'{_prefix_serrated_url}(?P<url_host>{_pattern_serrated_hostname}){_suffix_combined_url}'
_pattern_defanged_url = F'{_prefix_defanged_url}(?P<url_host>{_pattern_defanged_hostname}){_suffix_combined_url}'

_pattern_email = R'(?:[a-zA-Z0-9_\.\+\-]{{1,256}}?)@(?:{})'.format(_pattern_serrated_domain)
_pattern_guid = R'(?:\b|\{)[0-9A-Fa-f]{8}(?:\-[0-9A-Fa-f]{4}){3}\-[0-9A-Fa-f]{12}(?:\}|\b)'

_pattern_pathpart_nospace = R'[-\w+,.;@\]\[{}^`~]+'  # R'[^/\\:"<>|\s\x7E-\xFF\x00-\x1F\xAD]+'
_pattern_win_path_element = R'(?:{n} ){{0,4}}{n}'.format(n=_pattern_pathpart_nospace)
_pattern_nix_path_element = R'(?:{n} ){{0,1}}{n}'.format(n=_pattern_pathpart_nospace)
_pattern_win_env_variable = R'%[a-zA-Z][a-zA-Z0-9_\-\(\)]*%'

_pattern_win_path = R'(?:{s})(?P<pathsep>[\\\/])(?:{p}(?P=pathsep))*{p}\b'.format(
    s='|'.join([
        _pattern_win_env_variable,     # environment variable
        R'[A-Za-z]:',                 # drive letter with colon
        R'\\\\[a-zA-Z0-9_.$]{1,50}',  # UNC path
        R'HK[A-Z_]{1,30}',            # registry root key
    ]),
    p=_pattern_win_path_element
)

_pattern_nix_path = R'\b/?(?:{n}/){{2,}}{n}\b'.format(n=_pattern_nix_path_element)
_pattern_any_path = R'(?:{nix})|(?:{win})'.format(
    nix=_pattern_nix_path,
    win=_pattern_win_path
)


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
    R'(?:{b}{{40,100}}{n})+{b}{{1,100}}={{0,3}}{n}'
    R'-----END(?:\s[A-Z0-9]+)+-----'
).format(n=R'(?:\r\n|\n\r|\n)', b=R'[0-9a-zA-Z\+\/]')

__all__ = [
    'pattern',
    'alphabet',
    'tokenize',
    'formats',
    'indicators',
    'defanged'
]


class formats(PatternEnum):
    """
    An enumeration of patterns for certain formats.
    """
    integer = pattern(_pattern_integer)
    "Integer expressions"
    float = pattern(_pattern_float)
    "Floating point number expressions"
    string = pattern(_pattern_string)
    "C syntax string literal"
    cmdstr = pattern(_pattern_cmdstr)
    "Windows command line escaped string literal"
    ps1str = pattern(_pattern_ps1str)
    "PowerShell escaped string literal"
    printable = alphabet(R'[\s!-~]')
    "Any sequence of printable characters"
    url_encoded_coarse = pattern(_pattern_urlenc_coarse)
    "Any sequence of url-encoded characters, coarse variant"
    url_encoded_narrow = pattern(_pattern_urlenc_narrow)
    "Any sequence of url-encoded characters, narrow variant"
    url_encoded_hex = pattern(_pattern_urlenc_hex)
    "A hex-encoded buffer using URL escape sequences"
    intarray = tokenize(_pattern_integer, sep=R'\s*[;,]\s*', bound='')
    "Sequences of integers, separated by commas or semicolons"
    word = alphabet(R'\\w')
    "Sequences of word characters"
    letters = alphabet(R'[a-zA-Z]')
    "Sequences of alphabetic characters"
    vbe = pattern(_pattern_vbe)
    "Encoded Visual Basic Scripts"
    alphanumeric = alphabet(R'[a-zA-Z0-9]')
    "Sequences of alpha-numeric characters"
    b32 = pattern('[A-Z2-7]+|[a-z2-7+]')
    "Base32 encoded strings"
    b64 = alphabet(R'[0-9a-zA-Z\+\/]', postfix=R'[0-9a-zA-Z\+\/]{0,3}={0,3}')
    "Base64 encoded strings"
    b64url = alphabet(R'[0-9a-zA-Z\_\-]', postfix=R'[0-9a-zA-Z\_\-]{0,3}={0,3}')
    "Base64 encoded strings using URL-safe alphabet"
    hex = alphabet(R'[0-9a-fA-F]')
    "Hexadecimal strings"
    uppercase_hex = alphabet(R'[0-9A-F]')
    "Uppercase hexadecimal strings"
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
    hexarray = tokenize(R'[0-9A-F]{2}', sep=R'\s*[;,]\s*', bound='')
    "Arrays of hexadecimal strings, separated by commas or semicolons"

    @classmethod
    def from_dashname(cls, key):
        return getattr(cls, key.replace('-', '_'))


class indicators(PatternEnum):
    """
    An enumeration of patterns for indicators.
    """
    domain = pattern(_pattern_serrated_domain)
    "Domain names"
    email = pattern(_pattern_email)
    "Email addresses"
    guid = pattern(_pattern_guid)
    "Windows GUID strings"
    ipv4 = pattern(_pattern_serrated_ipv4)
    "String representations of IPv4 addresses"
    ipv6 = pattern(_pattern_ipv6)
    "String representations of IPv6 addresses"
    md5 = alphabet('[0-9a-f]', at_least=32, at_most=32)
    "Hexadecimal strings of length 32"
    sha = alphabet('[0-9a-f]', at_least=40, at_most=40)
    "Hexadecimal strings of length 40"
    sha256 = alphabet('[0-9a-f]', at_least=64, at_most=64)
    "Hexadecimal strings of length 64"
    hostname = pattern(_pattern_serrated_hostname)
    "Any domain name or IPv4 address, optionally followd by a colon and a port number."
    socket = pattern(_pattern_serrated_socket)
    "Any domain name or IPv4 address followed by a colon and a (port) number"
    subdomain = pattern(_pattern_subdomain)
    "A domain which contains at least three parts, including the top level"
    url = pattern(_pattern_serrated_url)
    "Uniform resource locator addresses"
    btc = alphabet('[a-km-zA-HJ-NP-Z0-9]', prefix=R'(?<!\w)[13]', at_least=26, at_most=33)
    "Bitcoin addresses"
    pem = pattern(_pattern_pem)
    "A pattern matching PEM encoded cryptographic parameters"
    xmr = alphabet('[1-9A-HJ-NP-Za-km-z]', prefix='4[0-9AB]', at_least=90, at_most=120)
    "Monero addresses"
    path = pattern(_pattern_any_path)
    "Windows and Linux path names"
    environment_variable = pattern(_pattern_win_env_variable)
    "Windows environment variables, i.e. something like `%APPDATA%`"

    @classmethod
    def from_dashname(cls, key):
        return getattr(cls, key.replace('-', '_'))


class defanged(PatternEnum):
    """
    An enumeration of patterns for defanged indicators. Used only by the reverse
    operation of `refinery.defang`.
    """
    hostname = pattern(_pattern_defanged_hostname)
    "A defanged `refinery.lib.patterns.indicators.hostname`."
    url = pattern(_pattern_defanged_url)
    "A defanged `refinery.lib.patterns.indicators.url`."
