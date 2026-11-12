from __future__ import annotations

from test import TestBase, lines_executed

from refinery.lib.scripts.ps1.analysis import listing, model
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.listing import (
    Ps1CommandSelection,
    Ps1MemberSelection,
    Ps1NameNarrowing,
    get_command_selection,
    listed_command,
    listed_member,
    listed_variable,
    lookup_may_raise,
    lookup_selection,
    member_selection,
    name_narrowing,
    variable_listing_holds_at,
)
from refinery.lib.scripts.ps1.ast import get_command_name
from refinery.lib.scripts.ps1.data import Ps1MemberView
from refinery.lib.scripts.ps1.model import (
    Ps1CommandInvocation,
    Ps1InvokeMember,
    Ps1Pipeline,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _first(source: str, kind: type):
    for node in Ps1Parser(source).parse().walk():
        if isinstance(node, kind):
            return node
    raise LookupError(source)


def _named(source: str, name: str) -> Ps1CommandInvocation:
    for node in Ps1Parser(source).parse().walk():
        if isinstance(node, Ps1CommandInvocation) and get_command_name(node) == name:
            return node
    raise LookupError(source)


def _pattern(text: str) -> Ps1CommandSelection:
    return Ps1CommandSelection(text, True)


def _literal(text: str) -> Ps1CommandSelection:
    return Ps1CommandSelection(text, False)


def _everything() -> Ps1CommandSelection:
    return Ps1CommandSelection(None, False)


def _like(pattern: str) -> Ps1NameNarrowing:
    return Ps1NameNarrowing(pattern, False)


def _clike(pattern: str) -> Ps1NameNarrowing:
    return Ps1NameNarrowing(pattern, True)


class TestPs1ListedCommand(TestBase):

    def test_a_literal_lists_the_command_its_unescaped_name_names(self):
        for written, expected in (
            ('WRITE', 'write'),
            ('w`rite', 'write'),
            ('Get-Item', 'Get-Item'),
        ):
            with self.subTest(written):
                self.assertEqual(listed_command(_literal(written)), expected)

    def test_a_literal_no_command_of_the_session_bears_lists_nothing_one_can_name(self):
        for written in ('wr`?te', 'nosuch', 'where.exe'):
            with self.subTest(written):
                self.assertIsNone(listed_command(_literal(written)))

    def test_a_literal_is_looked_up_without_reading_the_whole_vocabulary(self):
        listed_command(_literal('Get-Item'))
        self.assertLess(lines_executed(lambda: listed_command(_literal('Get-Item')), listing), 50)

    def test_a_pattern_one_engine_command_matches_lists_it(self):
        for pattern, expected in (
            ('???t?', 'write'),
            ('mor?', 'more'),
            ('[v-x]rite', 'write'),
            ('mkdi?', 'mkdir'),
        ):
            with self.subTest(pattern):
                self.assertEqual(listed_command(_pattern(pattern)), expected)

    def test_a_pattern_the_session_lists_more_or_less_than_once_lists_nothing_one_can_name(self):
        for pattern in ('hel?*', 'gt?', 'Write-FileSystemCach?', 'a?', '[!x]rite', '*-Item', 'zzq*'):
            with self.subTest(pattern):
                self.assertIsNone(listed_command(_pattern(pattern)))

    def test_a_listing_without_a_name_leaves_the_aliases_no_module_defines_out(self):
        for narrowing, expected in (
            (_like('wr?te'), None),
            (_like('*w-*ct'), 'New-Object'),
            (_like('mkdi?'), 'mkdir'),
            (_like('A?'), 'A:'),
            (_clike('new-o*'), None),
            (_clike('New-O*'), 'New-Object'),
        ):
            with self.subTest(narrowing):
                self.assertEqual(listed_command(_everything(), narrowing), expected)

    def test_a_listing_without_a_name_and_without_a_narrowing_names_nothing(self):
        self.assertIsNone(listed_command(_everything()))

    def test_a_shaped_listing_names_nothing(self):
        self.assertIsNone(listed_command(Ps1CommandSelection('wr?te', True, shaped=True)))

    def test_a_listing_of_cmdlets_skips_every_alias_and_function(self):
        self.assertEqual(listed_command(Ps1CommandSelection('*w-*ct', True, cmdlets_only=True)), 'New-Object')
        self.assertIsNone(listed_command(Ps1CommandSelection('write', False, cmdlets_only=True)))
        self.assertIsNone(listed_command(Ps1CommandSelection('New-Obj*', False, cmdlets_only=True)))


class TestPs1GetCommandSelection(TestBase):

    def test_the_name_is_read_off_every_spelling_that_binds_it(self):
        for source in (
            "Get-Command 'wr?te'",
            "Get-Command -Name 'wr?te'",
            "Get-Command -Name:'wr?te'",
            "Get-Command -Na 'wr?te'",
        ):
            with self.subTest(source):
                self.assertEqual(
                    get_command_selection(_first(source, Ps1CommandInvocation)),
                    Ps1CommandSelection('wr?te', True),
                )

    def test_no_argument_selects_everything(self):
        self.assertEqual(get_command_selection(_first('Get-Command', Ps1CommandInvocation)), _everything())

    def test_another_entry_shapes_the_listing(self):
        for source in ("Get-Command 'wr?te' -CommandType Alias", 'Get-Command -All write'):
            with self.subTest(source):
                selection = get_command_selection(_first(source, Ps1CommandInvocation))
                assert selection is not None
                self.assertEqual(selection.shaped, True)

    def test_an_unreadable_selection_is_refused(self):
        for source in (
            'Get-Command x y',
            'Get-Command @a',
            "Get-Command -N 'wr?te'",
            'Get-Command $n',
        ):
            with self.subTest(source):
                self.assertIsNone(get_command_selection(_first(source, Ps1CommandInvocation)))

    def test_piped_input_binds_the_name_where_it_stands(self):
        self.assertIsNone(get_command_selection(_named("'v' | Get-Command 'x'", 'Get-Command')))


class TestPs1LookupSelection(TestBase):

    def _selection(self, call: str) -> Ps1CommandSelection | None:
        return lookup_selection(_first(F'$ExecutionContext.InvokeCommand.{call}', Ps1InvokeMember))

    def test_a_name_lookup_reads_its_second_argument_as_a_boolean(self):
        for argument, pattern in (
            ('$false', False),
            ('0', False),
            ("'0'", True),
            ('$true', True),
            ('1', True),
        ):
            with self.subTest(argument):
                self.assertEqual(
                    self._selection(F"GetCommandName('*w-*ct', {argument}, $true)"),
                    Ps1CommandSelection('*w-*ct', pattern),
                )

    def test_a_cmdlet_lookup_takes_a_literal_and_a_cmdlet_listing_a_pattern(self):
        self.assertEqual(
            self._selection("GetCmdlet('New-Obj*')"),
            Ps1CommandSelection('New-Obj*', False, cmdlets_only=True),
        )
        self.assertEqual(
            self._selection("GetCmdlets('*w-*ct')"),
            Ps1CommandSelection('*w-*ct', True, cmdlets_only=True),
        )

    def test_a_command_lookup_takes_a_literal_of_the_kind_it_names(self):
        self.assertEqual(self._selection("GetCommand('*w-*ct', 'All')"), Ps1CommandSelection('*w-*ct', False))
        self.assertEqual(
            self._selection("GetCommand('New-Object', 'Cmdlet')"),
            Ps1CommandSelection('New-Object', False, cmdlets_only=True),
        )

    def test_an_argument_nobody_can_read_is_refused(self):
        for call in ("GetCommandName('*w-*ct', $x, $true)", 'GetCmdlet($n)', "GetCommand('x', $t)"):
            with self.subTest(call):
                self.assertIsNone(self._selection(call))


class TestPs1LookupMayRaise(TestBase):

    def test_a_literal_and_a_malformed_pattern_may_raise(self):
        for selection in (_literal('nosuch'), _pattern('[zz'), _literal('wr`?te')):
            with self.subTest(selection):
                self.assertTrue(lookup_may_raise(selection))

    def test_a_well_formed_pattern_never_raises(self):
        for selection in (_pattern('zz]x'), _pattern('zzq*'), _everything()):
            with self.subTest(selection):
                self.assertFalse(lookup_may_raise(selection))


class TestPs1NameNarrowing(TestBase):

    def test_every_like_operator_narrows_with_its_case_rule(self):
        for operator, case_sensitive in (('-like', False), ('-ilike', False), ('-clike', True)):
            with self.subTest(operator):
                pipeline = _first(F"x | ? {{ $_.Name {operator} 'wr?te' }}", Ps1Pipeline)
                self.assertEqual(
                    name_narrowing(pipeline.elements[-1]),
                    Ps1NameNarrowing('wr?te', case_sensitive),
                )

    def test_a_filter_on_another_member_does_not_narrow_the_name(self):
        pipeline = _first("x | ? { $_.Source -like 'wr?te' }", Ps1Pipeline)
        self.assertIsNone(name_narrowing(pipeline.elements[-1]))

    def test_the_long_spelling_of_the_current_object_narrows(self):
        pipeline = _first("x | ? { $PSItem.Name -like 'wr?te' }", Ps1Pipeline)
        self.assertEqual(name_narrowing(pipeline.elements[-1]), _like('wr?te'))

    def test_a_qualified_or_static_read_off_the_current_object_does_not_narrow(self):
        for read in ('$global:_.Name', '$script:PSItem.Name', '$_::Name'):
            with self.subTest(read):
                pipeline = _first(F"x | ? {{ {read} -like 'wr?te' }}", Ps1Pipeline)
                self.assertIsNone(name_narrowing(pipeline.elements[-1]))


class TestPs1MemberSelection(TestBase):

    def _selection(self, source: str) -> Ps1MemberSelection | None:
        pipeline = _first(F"{source} | ? {{ $_.Name -like 'x' }}", Ps1Pipeline)
        return member_selection(pipeline.elements[:-1])

    def test_every_spelling_of_a_view_selects_it(self):
        for source, view in (
            ("'abc' | Get-Member", Ps1MemberView.INSTANCE),
            ("'abc' | Get-Member -Static:$false", Ps1MemberView.INSTANCE),
            ('[string] | Get-Member -Static', Ps1MemberView.STATIC),
            ("'abc' | Get-Member -MemberType Method", Ps1MemberView.METHOD),
            ("'abc' | Get-Member -M Method", Ps1MemberView.METHOD),
            ("'abc' | Get-Member -Type Property", Ps1MemberView.PROPERTY),
            ("'abc'.psobject.Methods", Ps1MemberView.METHODS),
            ("'abc'.psobject.Properties", Ps1MemberView.PROPERTIES),
        ):
            with self.subTest(source):
                self.assertEqual(self._selection(source), Ps1MemberSelection('System.String', view))

    def test_a_selection_nobody_can_answer_is_refused(self):
        for source in (
            "'abc' | Get-Member -MemberType 'Method, Property'",
            "'abc' | Get-Member -MemberType Methods",
            "'abc' | Get-Member -View Base",
            "'abc' | Get-Member -Force",
            "@('abc') | Get-Member",
            '$q | Get-Member',
        ):
            with self.subTest(source):
                self.assertIsNone(self._selection(source))


class TestPs1ListedMember(TestBase):

    def test_the_member_one_view_lists_once_is_named(self):
        for type_name, view, pattern, expected in (
            ('System.String', Ps1MemberView.INSTANCE, 'Conc?t', None),
            ('System.String', Ps1MemberView.INSTANCE, 'Char*', 'Chars'),
            ('System.String', Ps1MemberView.STATIC, 'Conc?t', 'Concat'),
            ('System.String', Ps1MemberView.STATIC, 'Emp*', 'Empty'),
            ('System.String', Ps1MemberView.STATIC, 'ne?', 'new'),
            ('System.DateTime', Ps1MemberView.STATIC, 'MaxV*', 'MaxValue'),
            ('System.String', Ps1MemberView.METHOD, 'Clo?e', 'Clone'),
            ('System.String', Ps1MemberView.PROPERTY, 'Clo?e', None),
            ('System.String', Ps1MemberView.METHODS, 'get_Len*', 'get_Length'),
            ('System.DateTime', Ps1MemberView.INSTANCE, 'Displ*', None),
        ):
            with self.subTest(view=view.value, pattern=pattern):
                self.assertEqual(
                    listed_member(Ps1MemberSelection(type_name, view), _like(pattern)),
                    expected,
                )


class TestPs1ListedVariable(TestBase):

    def test_the_session_variable_a_pattern_matches_once_is_named_as_the_session_spells_it(self):
        for pattern, expected in (
            ('E*t', 'ExecutionContext'),
            ('*mdr*', 'MaximumDriveCount'),
            ('PSHo*', 'PSHOME'),
            ('Shel*', 'ShellId'),
            ('tru?', 'true'),
        ):
            with self.subTest(pattern):
                self.assertEqual(listed_variable(pattern), expected)

    def test_a_pattern_matching_a_variable_the_engine_creates_while_running_names_nothing(self):
        for pattern in ('Matc*', 'fore*', 'Thi?', 'PSIt*', 'LASTE*', 'OF?'):
            with self.subTest(pattern):
                self.assertIsNone(listed_variable(pattern))


class TestPs1VariableListingHoldsAt(TestBase):

    @staticmethod
    def _site_and_cache(source: str) -> tuple[Ps1CommandInvocation, Ps1ModelCache]:
        script = Ps1Parser(source).parse()
        site = next(
            node for node in script.walk()
            if isinstance(node, Ps1CommandInvocation) and get_command_name(node) == 'Write-Output'
        )
        return site, Ps1ModelCache(script)

    def _holds(self, source: str, pattern: str) -> bool:
        site, cache = self._site_and_cache(source)
        return variable_listing_holds_at(pattern, site, cache)

    def test_a_variable_a_command_names_with_a_prefix_that_is_no_scope_is_listed(self):
        for writer in (
            "Set-Variable 'e:pathext' 5",
            "New-Variable 'e:pathext' 5",
            "Set-Item 'Variable:e:pathext' 5",
            "Set-Variable 'env:et' 5",
        ):
            with self.subTest(writer):
                self.assertFalse(self._holds(F"{writer}\nWrite-Output 'x'", 'E*t'))

    def test_an_environment_variable_is_not_listed(self):
        self.assertTrue(self._holds("$env:Et = 5\nWrite-Output 'x'", 'E*t'))

    def test_a_second_guard_on_one_tree_reads_nothing_of_the_tree_again(self):
        counts = []
        for size in (40, 80):
            assignments = '\n'.join(F'$a{index} = {index}' for index in range(size))
            site, cache = self._site_and_cache(F"{assignments}\nWrite-Output 'x'")
            variable_listing_holds_at('E*t', site, cache)
            counts.append(lines_executed(
                lambda: variable_listing_holds_at('E*t', site, cache), listing, model))
        self.assertEqual(counts[0], counts[1])
