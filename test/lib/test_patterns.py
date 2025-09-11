from __future__ import annotations

import re

from inspect import getdoc as multiline
from refinery.lib.patterns import indicators, formats

from .. import TestBase


class RegexTextBase(TestBase):

    def assertMatches(self, pattern: indicators | formats, _string: str):
        for conv, string in ((str, _string), (bytes, _string.encode('latin1'))):
            self.assertTrue(re.fullmatch(conv(pattern), string),
                msg=F'The string "{string}" did not match the pattern {pattern.name} as {conv.__name__}')
            self.assertListEqual([string], [match[0] for match in re.finditer(conv(pattern), string)],
                msg=F'The string "{string}" not recovered by pattern {pattern.name} as {conv.__name__}')


class TestIndicators(RegexTextBase):

    def test_ipv4_too_large_ocets(self):
        self.assertFalse(re.fullmatch(str(indicators.ipv4), '127.0.0.288'))

    def test_ipv4_almost_too_large_ocet(self):
        self.assertMatches(indicators.ipv4, '13.203.240.255')

    def test_ipv6_colon_colon_digit(self):
        self.assertMatches(indicators.ipv6, '2b14:301:126:3c::7')

    def test_ipv6_colon_colon_digit_digit(self):
        self.assertMatches(indicators.ipv6, '2b14:301:126:3c::2d4:25')

    def test_telegram_url(self):
        self.assertMatches(indicators.url, 'https://t.me/binaryrefinerytest')

    def test_telegram_domain(self):
        self.assertMatches(indicators.domain, 't.me')

    def test_date(self):
        self.assertMatches(indicators.date, '2030-01-01T09:00:00')
        self.assertMatches(indicators.date, '2020-01-01T12:07:00')
        self.assertMatches(indicators.date, 'Wed Mar 31 00:00:00 UTC 2027')


class TestFormats(RegexTextBase):

    def test_ps1str_here_string_match(self):
        @multiline
        class here_string:
            """
            $page = [XML] @"
            <command:command xmlns:maml="http://schemas.microsoft.com/maml/2004/10"
            xmlns:command="http://schemas.microsoft.com/maml/dev/command/2004/10"
            xmlns:dev="http://schemas.microsoft.com/maml/dev/2004/10">
            <command:details>
                    <command:name>
                        Format-Table
                    </command:name>
                    <maml:description>
                        <maml:para>Formats the output as a table.</maml:para>
                    </maml:description>
                    <command:verb>format</command:verb>
                    <command:noun>table</command:noun>
                    <dev:version></dev:version>
            </command:details>
            ...
            </command:command>
            "@
            """

        match = re.search(str(formats.ps1str), here_string, flags=re.DOTALL)
        data = match.group(0)[2:-2].strip()
        self.assertTrue(bool(match), 'string not found')
        self.assertTrue(data.startswith('<command:command'))
        self.assertTrue(data.endswith('</command:command>'))

    def test_guid_in_path(self):
        self.assertMatches(indicators.path,
            R'C:\Users\W10PRO~1\AppData\Local\Temp\{CAE44DB5-22DC-4A76-B334-E77C8D459505}\word_data.bin')

    def test_two_part_path(self):
        self.assertMatches(indicators.path,
            R'/root/something_something_in_the_root.txt')
