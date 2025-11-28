from __future__ import annotations

import re

from enum import Enum
from fnmatch import fnmatch
from ipaddress import ip_address
from pathlib import Path
from string import ascii_letters
from typing import AnyStr
from urllib.parse import urlparse

from refinery.lib.patterns import indicators
from refinery.lib.types import Param
from refinery.units import RefineryCriticalException
from refinery.units.pattern import Arg, PatternExtractor


class LetterWeight:
    def __init__(self, weight):
        try:
            self._weights = weight._weights
        except AttributeError:
            pass
        else:
            return
        self._weights = {
            letter: weight for letters, weight in weight.items() for letter in letters
        }
        for letter in range(0x100):
            self._weights.setdefault(letter, 0)

    def __call__(self, data: AnyStr) -> float:
        if isinstance(data, str):
            data = data.encode('latin1')
        return sum(self._weights[c] for c in data) / len(data) / max(self._weights.values())


class LetterWeights(LetterWeight, Enum):
    IOC = LetterWeight({
        B'^`': 1,
        B'!$%&()*+-<=>?[]{}~\t': 2,
        B'ABCDEFGHIJKLMNOPQRSTUVWXYZ': 4,
        B'.,:;#/\\|@_ ': 5,
        B'0123456789abcdefghijklmnopqrstuvwxyz': 8,
    })
    Path = LetterWeight({
        B'^`': 1,
        B'$%&()*+-<=>?[]{}~\t': 2,
        B'.,:;#/\\|@_ ': 4,
        B'0123456789': 4,
        B'ABCDEFGHIJKLMNOPQRSTUVWXYZ': 6,
        B'abcdefghijklmnopqrstuvwxyz': 8,
    })


class xtp(PatternExtractor):
    """
    Extract Patterns: Uses regular expressions to extract indicators from the input data and
    optionally filters these results heuristically. The unit is designed to extract indicators
    such as domain names and IP addresses, see below for a complete list. To extract data
    formats such as hex-encoded data, use `refinery.carve`.
    """

    def __init__(
        self,
        *pattern: Param[str, Arg.String('pattern',
            default=(
                indicators.hostname.name,
                indicators.url.name,
                indicators.email.name,
            ), help=(
                'Choose the pattern to extract. The unit uses {{default}} by default. Use an '
                'asterix character to select all available patterns. The available patterns '
                'are: {}'.format(', '.join(p.display for p in indicators))
            )
        )],
        filter: Param[int, Arg.Counts('-f', help=(
            'If this setting is enabled, the xtp unit will attempt to reduce the number '
            'of false positives by certain crude heuristics. Specify multiple times to '
            'make the filtering more aggressive.')
        )] = 0,
        min=1, max=0, len=0, stripspace=False, duplicates=False, longest=False, take=0
    ):
        self.superinit(super(), **vars(), ascii=True, utf16=True)

        patterns = {
            p for name in pattern for p in indicators if fnmatch(p.display, name)
        }
        # if indicators.hostname in patterns:
        #     patterns.remove(indicators.hostname)
        #     patterns.add(indicators.ipv4)
        #     patterns.add(indicators.domain)
        patterns = [F'(?P<{p.name}>{p.value})' for p in patterns]
        if not patterns:
            raise RefineryCriticalException('The given mask does not match any known indicator pattern.')
        joined = '|'.join(patterns)
        self.args.pattern = re.compile(joined.encode(self.codec), flags=re.DOTALL)
        self.args.filter = filter

    _ALPHABETIC = ascii_letters.encode('ASCII')

    _LEGITIMATE_HOSTS = {
        'acm.org'                 : 1,
        'adobe.com'               : 1,
        'aka.ms'                  : 1,
        'android.com'             : 1,
        'apache.org'              : 1,
        'apple.com'               : 1,
        'archive.org'             : 2,
        'azure.com'               : 1,
        'baidu.com'               : 2,
        'bootstrapcdn.com'        : 2,
        'cdnjs.cloudflare.com'    : 4,
        'comodo.net'              : 1,
        'comodoca.com'            : 1,
        'curl.haxx.se'            : 1,
        'curl.se'                 : 1,
        'digicert.com'            : 1,
        'dublincore.org'          : 1,
        'example.com'             : 1,
        'facebook.com'            : 4,
        'fontawesome.com'         : 1,
        'github.com'              : 3,
        'globalsign.com'          : 1,
        'globalsign.net'          : 1,
        'godaddy.com'             : 1,
        'golang.org'              : 1,
        'google.com'              : 4,
        'googleapis.com'          : 5,
        'googleusercontent.com'   : 5,
        'gov'                     : 2,
        'gstatic.com'             : 2,
        'iana.org'                : 1,
        'ietf.org'                : 1,
        'intel.com'               : 1,
        'jquery.com'              : 1,
        'jsdelivr.net'            : 2,
        'libssh.org'              : 1,
        'live.com'                : 1,
        'microsoft.com'           : 1,
        'mozilla.org'             : 1,
        'msdn.com'                : 1,
        'msn.com'                 : 1,
        'newtonsoft.com'          : 3, # json.net
        'nuget.org'               : 3,
        'office.com'              : 1,
        'office365.com'           : 2,
        'openssl.org'             : 1,
        'openssh.com'             : 1,
        'openxmlformats.org'      : 1,
        'oracle.com'              : 1,
        'purl.org'                : 1,
        'python.org'              : 1,
        'readthedocs.io'          : 1,
        'schema.org'              : 2,
        'sectigo.com'             : 1,
        'skype.com'               : 1,
        'sourceforge.net'         : 4,
        'stackoverflow.com'       : 1,
        'sun.com'                 : 1,
        'sway-cdn.com'            : 1,
        'sway-extensions.com'     : 1,
        'symantec.com'            : 1,
        'symauth.com'             : 1,
        'symcb.com'               : 1,
        'symcd.com'               : 1,
        'sysinternals.com'        : 3,
        'thawte.com'              : 1,
        'unicode.org'             : 2,
        'usertrust.com'           : 1,
        'verisign.com'            : 1,
        'w3.org'                  : 1,
        'wikipedia.org'           : 1,
        'wolfram.com'             : 1,
        'xml.org'                 : 1,
        'xmlsoap.org'             : 1,
        'yahoo.com'               : 1,
    }

    for _ext in [
        'build',
        'data',
        'do',
        'help',
        'java',
        'md',
        'mov',
        'name',
        'py',
        'so',
        'sys',
        'zip',
    ]:
        _LEGITIMATE_HOSTS[_ext] = 4

    _DOMAIN_WHITELIST = {
        'system.net',
        'wscript.shell',
    }

    _BRACKETING = {
        B"'"[0]: B"'",
        B'"'[0]: B'"',
        B'('[0]: B')',
        B'{'[0]: B'}',
        B'['[0]: B']',
        B'<'[0]: B'>',
    }

    def _check_host(self, host: str, text: str):
        hl = host.lower()
        if hl in self._DOMAIN_WHITELIST:
            self.log_info(F'excluding indicator because domain {hl} is forcefully ignored: {text}')
            return False
        for white, level in self._LEGITIMATE_HOSTS.items():
            if self.args.filter >= level and (hl == white or hl.endswith(F'.{white}')):
                self.log_info(F'excluding indicator because domain {hl} is whitelisted: {text}', clip=True)
                self.log_debug(F'reduce level below {level} to allow, current level is {self.args.filter}')
                return False
        return True

    def _check_match(self, data: memoryview | bytearray, pos: int, name: str, value: bytes):
        term = self._BRACKETING.get(data[pos - 1], None)
        text = value.decode(self.codec)
        if term:
            pos = value.find(term)
            if pos > 0:
                value = value[:pos]
        if not self.args.filter:
            return value
        if name == indicators.hostname.name:
            if all(part.isdigit() for part in value.split(B'.')):
                name = indicators.ipv4.name
            elif B'.' not in value:
                name = indicators.ipv6.name
            else:
                name = indicators.domain.name
        if name == indicators.ipv4.name:
            ocets = [int(x) for x in value.split(B'.')]
            if ocets.count(0) >= 3:
                self.log_info(F'excluding ipv4 because it contains many zeros: {text}')
                return None
            if self.args.filter > 2 and sum(ocets) < 10:
                self.log_info(F'excluding ipv4 because of low value ocets: {text}')
                return None
            if ocets[0] <= 5 * self.args.filter:
                for area in (
                    bytes(data[pos - 20 : pos + 20]),
                    bytes(data[pos * 2 - 40 : pos * 2 + 40 : 2]),
                    bytes(data[pos * 2 - 41 : pos * 2 + 39 : 2]),
                ):
                    check = area.lower()
                    if B'version' in check or b'build' in check:
                        self.log_info(F'excluding ipv4 because it might be a version: {text}')
                        return None
            small_ocet_count = sum(1 for ocet in ocets if ocet < 10)
            if small_ocet_count > max(0, 4 - self.args.filter):
                self.log_info(F'excluding ipv4 because it has too many small ocets: {text}')
                return None
            ip = ip_address(text)
            if not ip.is_global:
                if self.args.filter >= 3 or not ip.is_private:
                    self.log_info(F'excluding ipv4 because it is not global: {text}')
                    return None
        elif name in {
            indicators.url.name,
            indicators.socket.name,
            indicators.hostname.name,
            indicators.domain.name,
            indicators.subdomain.name
        }:
            if self.args.filter >= 2:
                if LetterWeights.IOC(value) < 0.6:
                    self.log_info(F'excluding indicator because with low score: {text}', clip=True)
                    return None
                if name != indicators.url.name and len(value) > 0x100:
                    self.log_info(F'excluding indicator because it is too long: {text}', clip=True)
                    return None
            ioc = text
            if '://' not in ioc:
                ioc = F'tcp://{ioc}'
            parts = urlparse(ioc)
            host, _, _ = parts.netloc.partition(':')
            if not self._check_host(host, text):
                return None
            if name == indicators.url.name:
                scheme = parts.scheme.lower()
                for p in ('http', 'https', 'ftp', 'file', 'mailto'):
                    if scheme.endswith(p):
                        pos = scheme.find(p)
                        value = value[pos:]
                        break
            if name in {
                indicators.hostname.name,
                indicators.domain.name,
                indicators.subdomain.name
            }:
                if data[pos - 1] in b'/\\' and self.args.filter >= 2:
                    return None
                hostparts = host.split('.')
                if self.args.filter >= 2:
                    if not all(p.isdigit() for p in hostparts) and all(len(p) < 4 for p in hostparts):
                        self.log_info(F'excluding host with too many short parts: {text}')
                        return None
                if self.args.filter >= 3:
                    if len(hostparts) <= sum(3 for p in hostparts if p != p.lower() and p != p.upper()):
                        self.log_info(F'excluding host with too many mixed case parts: {text}')
                        return None
                # These heuristics attempt to filter out member access to variables in
                # scripts which can be mistaken for domains because of the TLD inflation
                # we've had.
                uppercase = sum(1 for c in host if c.isalpha() and c.upper() == c)
                lowercase = sum(1 for c in host if c.isalpha() and c.lower() == c)
                if lowercase and uppercase:
                    caseratio = uppercase / lowercase
                    if 0.1 < caseratio < 0.9:
                        self.log_info(F'excluding indicator with too much uppercase letters: {text}')
                        return None
                if all(x.isidentifier() for x in hostparts):
                    if len(hostparts) == 2 and hostparts[0] in ('this', 'self'):
                        self.log_info(F'excluding host that looks like a code snippet: {text}')
                        return None
                    if len(hostparts[-2]) < 3:
                        self.log_info(F'excluding host with too short root domain name: {text}')
                        return None
                    if any(x.startswith('_') for x in hostparts):
                        self.log_info(F'excluding host with underscores: {text}')
                        return None
                    if len(hostparts[-1]) > 3:
                        prefix = '.'.join(hostparts[:-1])
                        seen_before = len(set(re.findall(
                            fR'{prefix}(?:\.\w+)+'.encode('ascii'), data)))
                        if seen_before > 2:
                            self.log_debug(F'excluding indicator that was already seen: {text}')
                            return None
        elif name == indicators.email.name:
            _, _, host = value.partition(B'@')
            host = host.decode(self.codec)
            if not self._check_host(host, text):
                return None
            at = value.find(B'@')
            ix = 0
            while value[ix] not in self._ALPHABETIC:
                ix += 1
            return None if at - ix < 3 else value[ix:]
        elif name in (
            indicators.path.name,
            indicators.winpath.name,
            indicators.nixpath.name,
        ):
            if len(value.split()) + min(self.args.filter, 4) >= 6:
                self.log_info(F'excluding path because it contains too many spaces: {text}')
                return None
            if len(value) < 8:
                self.log_info(F'excluding path because it is too short: {text}')
                return None
            if len(value) > 16 and len(re.findall(RB'\\x\d\d', value)) > len(value) // 10:
                self.log_info(F'excluding long path containign hex: {text}', clip=True)
                return None
            try:
                path_string = text
            except Exception:
                self.log_debug(F'excluding path which did not decode: {value!r}', clip=True)
                return None
            try:
                path = Path(path_string)
            except Exception as E:
                self.log_debug(F'error parsing path "{path}": {E!s}')
                return None
            path_likeness = sum(v for v, x in [
                (1, path.suffix),
                (1, path_string.startswith('/')),
                (2, path_string.startswith('%')),
                (2, path_string.startswith('\\\\')),
                (2, path_string[1:3] == ':\\'),
            ] if x)
            if 2 + path_likeness < min(self.args.filter, 2):
                self.log_info(F'excluding long path because it has no characteristic parts: {text}')
                return None
            bad_parts = 0
            all_parts = len(path.parts)
            if self.args.filter >= 1:
                date_likeness = sum(1
                    for t in ['yyyy', 'yy', 'mm', 'dd', 'hh', 'ss']
                    if t in path.parts or t.upper() in path.parts)
                if len(value) < 20 and date_likeness >= all_parts - 1:
                    self.log_info(F'excluding path that looks like a date format: {text}', clip=True)
                    return None
            if self.args.filter >= 2:
                for k, part in enumerate(path.parts):
                    if not k:
                        drive, colon, slash = part.partition(':')
                        if colon and len(drive) == 1 and len(slash) <= 1:
                            continue
                        if part[0] == part[~0] == '%':
                            continue
                        if len(part) == 1:
                            continue
                    if (
                        LetterWeights.Path(part) < 0.5 + (min(self.args.filter, 4) * 0.1)
                        or (self.args.filter >= 2 and LetterWeights.Path(part[:1]) < 0.5)
                    ):
                        bad_parts += 1
                        self.log_debug(F'bad part {k + 1} in path: {part}')
            for filter_limit in (2, 3, 4):
                bad_ratio = 2 ** (filter_limit - 1)
                if self.args.filter >= filter_limit and bad_parts * bad_ratio >= all_parts:
                    self.log_info(F'excluding path with bad parts: {text}', clip=True)
                    return None
        return value

    def process(self, data):
        whitelist = set()

        def check(match: re.Match):
            for name, value in match.groupdict().items():
                if value is not None:
                    break
            else:
                raise RefineryCriticalException('Received empty match.')
            if value in whitelist:
                return None
            result = self._check_match(match.string, match.start(), name, value)
            if result is not None:
                return self.labelled(result, pattern=name)
            whitelist.add(value)

        transforms = [check]
        yield from self.matches_filtered(memoryview(data), self.args.pattern, *transforms)
