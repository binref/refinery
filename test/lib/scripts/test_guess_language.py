from __future__ import annotations

import inspect
import unittest

from test import TestBase

from refinery.lib.scripts.guess import guess_language
from refinery.lib.scripts.js.model import JsErrorNode
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.ps1.model import Ps1ErrorNode
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.vba.model import VbaErrorNode
from refinery.lib.scripts.vba.parser import VbaParser
from refinery.units.scripting.deobfuscate import defu


_JAVASCRIPT = inspect.cleandoc("""
    function decode(data) {
      return unescape(atob(data));
    }
    alert(decode(
      'aHR0cHM6Ly9leGFtcGxlLmNvbS91cGRhdGUvYWdlbnQucGhwP2lkPTQyJnRva2VuPWFiY2RlZmdoaWprbG1ub3A='
    ));
""") + '\n'

_FIRST_CUT_ONLY_JAVASCRIPT_READS = 55
"""
The length of the shortest prefix of `_JAVASCRIPT` that neither the PowerShell nor the VBA grammar
reads completely, counting what a grammar leaves unread the way the guess counts it. Every shorter
prefix is a script one of those two accepts, and for those nothing but the order in which the
backends are tried decides the answer.
"""

_CUT_INSIDE_TWO_OPEN_BLOCKS = inspect.cleandoc("""
    function f(s) {
      for (var i = 0; i < 3; i++) {
        out += s[i];
""") + '\n'

_UNTERMINATED_STRING_AT_THE_END = F'{_JAVASCRIPT}var x = "abc'

_POWERSHELL = inspect.cleandoc("""
    $hb = (New-Object Net.WebClient)
    $sK = Get-Culture | Format-List -Property * | Out-String -Stream
    if ($SK -Match 'ja') {
      Start-Process $hb
    } else {
      exit
    }
""") + '\n'

_VBA = inspect.cleandoc("""
    Attribute VB_Name = "Module1"
    Dim x As Long
    Sub Foo()
      MsgBox x
    End Sub
    Function Bar() As Long
      Bar = MsgBox(x)
    End Function
""") + '\n'

_PUNCTUATION = ')]);})|)&);)^)%)@)!)~)+)=)?)<)>);)'

_SOURCES = {
    'javascript'                  : _JAVASCRIPT,
    'javascript_cut_inside_blocks': _CUT_INSIDE_TWO_OPEN_BLOCKS,
    'javascript_cut_in_a_string'  : _UNTERMINATED_STRING_AT_THE_END,
    'powershell'                  : _POWERSHELL,
    'vba'                         : _VBA,
    'punctuation'                 : _PUNCTUATION,
}

_GRAMMARS = {
    'ps1' : (Ps1Parser, Ps1ErrorNode),
    'vba' : (VbaParser, VbaErrorNode),
    'js'  : (JsParser, JsErrorNode),
}


def _unread_characters(source: str, language: str) -> int:
    """
    The characters of *source* the grammar of *language* could not read, counted as the guess
    counts them: the text a grammar gave up on where the source stops is text every grammar gives
    up on alike, and says nothing about which language wrote the file.
    """
    parser, error = _GRAMMARS[language]
    tree = parser(source).parse()
    return sum(
        len(node.text)
        for node in tree.walk()
        if isinstance(node, error) and node.offset + len(node.text) < len(source)
    )


def _backend_of_the_unit(source: str) -> str | None:
    unit = defu()
    try:
        unit.parse(source)
    except ValueError:
        return None
    return unit._backend.name


class TestLanguageGuess(TestBase):

    def test_a_cut_javascript_file_is_javascript_at_every_cut_no_other_grammar_reads(self):
        for cut in range(_FIRST_CUT_ONLY_JAVASCRIPT_READS, len(_JAVASCRIPT) + 1):
            with self.subTest(cut=cut):
                self.assertEqual(guess_language(_JAVASCRIPT[:cut]), 'js')

    def test_javascript_alone_reads_the_stated_cut_completely(self):
        prefix = _JAVASCRIPT[:_FIRST_CUT_ONLY_JAVASCRIPT_READS]
        self.assertEqual(
            {name: _unread_characters(prefix, name) == 0 for name in _GRAMMARS},
            {'ps1': False, 'vba': False, 'js': True},
        )

    def test_every_shorter_cut_is_read_completely_by_powershell_or_by_vba(self):
        for cut in range(1, _FIRST_CUT_ONLY_JAVASCRIPT_READS):
            with self.subTest(cut=cut):
                prefix = _JAVASCRIPT[:cut]
                self.assertEqual(
                    _unread_characters(prefix, 'ps1') == 0
                    or _unread_characters(prefix, 'vba') == 0,
                    True,
                )

    def test_each_source_is_recognized(self):
        """
        The VBA module is answered with PowerShell because the PowerShell grammar reads every line
        of it without an error as well, and PowerShell is the backend that is asked first.
        """
        self.assertEqual(
            {name: guess_language(source) for name, source in _SOURCES.items()},
            {
                'javascript'                  : 'js',
                'javascript_cut_inside_blocks': 'js',
                'javascript_cut_in_a_string'  : 'js',
                'powershell'                  : 'ps1',
                'vba'                         : 'ps1',
                'punctuation'                 : None,
            },
        )

    def test_the_unit_selects_the_backend_that_the_guess_names(self):
        self.assertEqual(
            {name: _backend_of_the_unit(source) for name, source in _SOURCES.items()},
            {name: guess_language(source) for name, source in _SOURCES.items()},
        )

    def test_the_guess_answers_the_same_for_bytes_as_for_text(self):
        self.assertEqual(
            {name: guess_language(source.encode('utf8')) for name, source in _SOURCES.items()},
            {name: guess_language(source) for name, source in _SOURCES.items()},
        )


_CUT_INSIDE_A_FOR_HEAD = inspect.cleandoc("""
    function f(s) {
      for (var i = 0; i < s.length;
""")


class TestACutInsideAForHeadIsStillJavaScript(TestBase):
    """
    A `for` head the file ends inside is one unread statement reaching the end of the file, which
    the guess discounts for every grammar alike: the JavaScript grammar and the PowerShell grammar
    both read everything the file holds before it, and the order the backends are tried in decides
    for PowerShell. What tells the file apart is the head itself, `var i = 0; i < s.length;`,
    which only JavaScript reads, and the guess does not look inside a statement it could not read.
    """

    @unittest.expectedFailure
    def test_the_cut_file_is_javascript(self):
        self.assertEqual(guess_language(_CUT_INSIDE_A_FOR_HEAD), 'js')
